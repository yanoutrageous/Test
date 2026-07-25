from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from .safety.context import (
    ContextError,
    DataClassification,
    validate_safe_id,
)
from .safety.external_source import (
    ExternalSourceError,
    RegisteredSourceEvidence,
    open_registered_external_source,
)
from .safety.workspace_io import (
    WorkspaceIOError,
    get_workspace_io,
)


COPY_PROVENANCE_SCHEMA_VERSION = "1.0"
COPY_PAYLOAD_NAME = "payload.bin"
COPY_PROVENANCE_NAME = "provenance.json"


class SourceCopyCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    SOURCE_REJECTED = "SOURCE_REJECTED"
    TARGET_CONFLICT = "TARGET_CONFLICT"
    PUBLICATION_FAILED = "PUBLICATION_FAILED"


class SourceCopyError(RuntimeError):
    def __init__(self, code: SourceCopyCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code.value}: {message}")

    def __repr__(self) -> str:
        return (
            f"SourceCopyError(code='{self.code.value}', "
            "source='<redacted>', target='<redacted>')"
        )


@dataclass(frozen=True, slots=True)
class SourceCopyReceipt:
    copy_id: str
    job_id: str
    logical_source_id: str
    classification: DataClassification
    target_relative_path: str
    payload_sha256: str
    payload_bytes: int
    provenance_sha256: str
    source_object_reference: str
    source_verification_sha256: str
    target_object_reference: str
    publish_receipt_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification.value,
            "copy_id": self.copy_id,
            "job_id": self.job_id,
            "logical_source_id": self.logical_source_id,
            "payload_bytes": self.payload_bytes,
            "payload_sha256": self.payload_sha256,
            "provenance_sha256": self.provenance_sha256,
            "publish_receipt_sha256": self.publish_receipt_sha256,
            "source_object_reference": self.source_object_reference,
            "source_verification_sha256": self.source_verification_sha256,
            "target_object_reference": self.target_object_reference,
            "target_relative_path": self.target_relative_path,
        }


@dataclass(frozen=True, slots=True)
class RegisteredExternalVerificationReceipt:
    logical_source_id: str
    payload_sha256: str
    payload_bytes: int
    verification_sha256: str


def _safe_id(value: str, *, field_name: str) -> str:
    try:
        return validate_safe_id(value, field_name=field_name)
    except ContextError as exc:
        raise SourceCopyError(
            SourceCopyCode.INVALID_REQUEST,
            f"{field_name} is not a canonical safe identifier",
        ) from exc


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def _isolated_workspace_prefix() -> Path:
    """Use the launcher's fixed synthetic project only during safe tests."""

    raw_run_root = os.environ.get("M0_TEST_LAB_ROOT")
    if not raw_run_root:
        return Path()
    workspace = get_workspace_io()
    try:
        run_root = workspace.validate_directory_path(Path(raw_run_root))
        relative = run_root.relative_to(workspace.project_root)
        marker = json.loads(
            workspace.read_bytes(
                relative / ".safety-marker.json",
                maximum_bytes=64 * 1024,
            ).decode("utf-8")
        )
    except (OSError, UnicodeError, ValueError, WorkspaceIOError) as exc:
        raise SourceCopyError(
            SourceCopyCode.INVALID_REQUEST,
            "safe-launcher Copy root could not be verified",
        ) from exc
    if (
        len(relative.parts) != 3
        or relative.parts[:2] != ("tmp", "test_lab")
        or relative.parts[2] != run_root.name
        or not run_root.name.startswith("RUN-")
        or type(marker) is not dict
        or marker.get("schema_version") != "1.0"
        or marker.get("run_id") != run_root.name
        or marker.get("purpose") != "M0-S1 WorkspaceGuard safety laboratory"
    ):
        raise SourceCopyError(
            SourceCopyCode.INVALID_REQUEST,
            "safe-launcher Copy root has an invalid fixed topology",
        )
    return relative / "project"


def _provenance(
    *,
    evidence: RegisteredSourceEvidence,
    verification_sha256: str,
    copy_id: str,
    job_id: str,
    purpose: str,
    target_relative_path: str,
) -> bytes:
    return _canonical_json(
        {
            "classification": evidence.classification.value,
            "copy_id": copy_id,
            "created_at": datetime.now(UTC).isoformat(),
            "job_id": job_id,
            "payload": {
                "bytes": evidence.size_bytes,
                "path": COPY_PAYLOAD_NAME,
                "sha256": evidence.sha256,
            },
            "purpose": purpose,
            "schema_version": COPY_PROVENANCE_SCHEMA_VERSION,
            "source": evidence.to_provenance_fields(),
            "source_verification_sha256": verification_sha256,
            "target_relative_path": target_relative_path,
        }
    )


def copy_registered_external_file(
    source_path: str | os.PathLike[str],
    *,
    logical_source_id: str,
    copy_id: str,
    job_id: str,
    purpose: str,
    classification: DataClassification = DataClassification.INTERNAL,
    verify_only: bool = False,
) -> SourceCopyReceipt | RegisteredExternalVerificationReceipt:
    """Publish one immutable, path-redacted Copy/source revision."""

    canonical_copy_id = _safe_id(copy_id, field_name="copy_id")
    canonical_job_id = _safe_id(job_id, field_name="job_id")
    canonical_purpose = _safe_id(purpose, field_name="purpose")
    if classification not in {
        DataClassification.INTERNAL,
        DataClassification.RESTRICTED,
    }:
        raise SourceCopyError(
            SourceCopyCode.INVALID_REQUEST,
            "source Copy classification must be INTERNAL or RESTRICTED",
        )

    workspace = get_workspace_io()
    isolated_prefix = _isolated_workspace_prefix()
    target_relative = (
        isolated_prefix / "Copy" / "source" / canonical_copy_id
    )
    staging_relative = (
        isolated_prefix
        / "tmp"
        / "jobs"
        / classification.value
        / canonical_job_id
        / f"source-copy-{canonical_copy_id}"
    )
    payload_stage = staging_relative / COPY_PAYLOAD_NAME
    provenance_stage = staging_relative / COPY_PROVENANCE_NAME

    try:
        with open_registered_external_source(
            source_path,
            logical_id=logical_source_id,
            classification=classification,
        ) as lease:
            material = lease.read_once()
            if verify_only:
                verification = lease.verify_unchanged(material.evidence)
                return RegisteredExternalVerificationReceipt(
                    logical_source_id=material.evidence.logical_id,
                    payload_sha256=material.evidence.sha256,
                    payload_bytes=material.evidence.size_bytes,
                    verification_sha256=verification.verification_digest,
                )
            workspace.ensure_directory(target_relative.parent)
            workspace.ensure_directory(staging_relative)
            payload_receipt = workspace.create_new_bytes(
                payload_stage,
                material.payload,
            )
            verification = lease.verify_unchanged(material.evidence)
            provenance_bytes = _provenance(
                evidence=material.evidence,
                verification_sha256=verification.verification_digest,
                copy_id=canonical_copy_id,
                job_id=canonical_job_id,
                purpose=canonical_purpose,
                target_relative_path=target_relative.as_posix(),
            )
            provenance_receipt = workspace.create_new_bytes(
                provenance_stage,
                provenance_bytes,
            )
            move_receipt = workspace.move_directory_no_replace(
                staging_relative,
                target_relative,
            )
            published_payload = workspace.read_bytes(
                target_relative / COPY_PAYLOAD_NAME,
                maximum_bytes=max(1, material.evidence.size_bytes),
            )
            published_provenance = workspace.read_bytes(
                target_relative / COPY_PROVENANCE_NAME,
                maximum_bytes=max(1, len(provenance_bytes)),
            )
    except ExternalSourceError as exc:
        raise SourceCopyError(
            SourceCopyCode.SOURCE_REJECTED,
            "registered source did not pass the read-only boundary",
        ) from exc
    except WorkspaceIOError as exc:
        code = (
            SourceCopyCode.TARGET_CONFLICT
            if exc.code.value == "TARGET_CONFLICT"
            else SourceCopyCode.PUBLICATION_FAILED
        )
        raise SourceCopyError(
            code,
            "fixed-root Copy publication was rejected",
        ) from exc

    if (
        published_payload != material.payload
        or published_provenance != provenance_bytes
        or payload_receipt.sha256 != material.evidence.sha256
        or provenance_receipt.sha256
        != hashlib.sha256(provenance_bytes).hexdigest()
    ):
        raise SourceCopyError(
            SourceCopyCode.PUBLICATION_FAILED,
            "published Copy bytes differ from the verified source revision",
        )
    return SourceCopyReceipt(
        copy_id=canonical_copy_id,
        job_id=canonical_job_id,
        logical_source_id=material.evidence.logical_id,
        classification=classification,
        target_relative_path=target_relative.as_posix(),
        payload_sha256=material.evidence.sha256,
        payload_bytes=material.evidence.size_bytes,
        provenance_sha256=provenance_receipt.sha256,
        source_object_reference=material.evidence.source_object_reference,
        source_verification_sha256=verification.verification_digest,
        target_object_reference=move_receipt.object_reference,
        publish_receipt_sha256=move_receipt.receipt_sha256,
    )
