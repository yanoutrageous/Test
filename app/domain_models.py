from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Mapping


DOMAIN_SCHEMA_ID = "LOCAL_EXAM_BANK_DOMAIN_REVISION"
DOMAIN_SCHEMA_VERSION = "1.0"

DOMAIN_OBJECT_TYPES = frozenset(
    {
        "source_file_revision",
        "source_page",
        "source_region",
        "question_revision",
        "solution_revision",
        "scoring_point_revision",
        "taxonomy_release",
        "tag_assertion",
        "figure_revision",
        "template_revision",
        "font_manifest",
        "blueprint_revision",
        "candidate_pool_snapshot",
        "paper_revision",
        "export_bundle",
        "backup_set",
        "active_state",
        "review_event",
        "audit_event",
    }
)
REVISION_STATES = frozenset(
    {"candidate", "reviewed", "approved", "superseded", "rejected"}
)

_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_id",
        "schema_version",
        "object_type",
        "object_id",
        "revision_id",
        "revision_no",
        "state",
        "created_at",
        "predecessor_revision_id",
        "payload",
        "extensions",
        "content_sha256",
    }
)
_ID_PATTERN = re.compile(r"[A-Z][A-Z0-9._-]{2,127}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z"
)
_EXTENSION_KEY_PATTERN = re.compile(r"x-[a-z0-9][a-z0-9._-]{0,62}")
_MEDIA_TYPE_PATTERN = re.compile(
    r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}"
)
_PAYLOAD_CONTRACTS: Mapping[str, tuple[frozenset[str], frozenset[str]]] = (
    MappingProxyType(
        {
            "source_file_revision": (
                frozenset(
                    {
                        "logical_source_id",
                        "source_sha256",
                        "bytes",
                        "media_type",
                        "project_relative_path",
                        "license_status",
                        "pii_classification",
                    }
                ),
                frozenset(),
            ),
            "source_page": (
                frozenset(
                    {
                        "source_file_revision_id",
                        "page_no",
                        "width_mm",
                        "height_mm",
                    }
                ),
                frozenset({"rotation_degrees"}),
            ),
            "source_region": (
                frozenset({"source_page_id", "coordinate_space", "bbox"}),
                frozenset({"transform_chain_id"}),
            ),
            "question_revision": (
                frozenset({"question_ir_revision_id"}),
                frozenset({"solution_revision_ids", "figure_revision_ids"}),
            ),
            "solution_revision": (
                frozenset({"question_revision_id", "solution_ir_revision_id"}),
                frozenset({"scoring_point_revision_ids"}),
            ),
            "scoring_point_revision": (
                frozenset({"solution_revision_id", "points", "criteria_blocks"}),
                frozenset(),
            ),
            "taxonomy_release": (
                frozenset({"taxonomy_id", "release_version", "terms_sha256"}),
                frozenset(),
            ),
            "tag_assertion": (
                frozenset(
                    {
                        "question_revision_id",
                        "taxonomy_release_id",
                        "tag_id",
                        "evidence_revision_ids",
                        "review_status",
                    }
                ),
                frozenset(),
            ),
            "figure_revision": (
                frozenset({"figure_ir_revision_id", "fallback_asset_ref"}),
                frozenset({"derived_asset_refs"}),
            ),
            "template_revision": (
                frozenset(
                    {
                        "template_family_id",
                        "token_contract_sha256",
                        "font_manifest_revision_id",
                    }
                ),
                frozenset(),
            ),
            "font_manifest": (
                frozenset({"fonts"}),
                frozenset({"fallback_policy"}),
            ),
            "blueprint_revision": (
                frozenset({"taxonomy_release_id", "constraints"}),
                frozenset(),
            ),
            "candidate_pool_snapshot": (
                frozenset({"question_revision_ids", "query_contract_sha256"}),
                frozenset(),
            ),
            "paper_revision": (
                frozenset(
                    {
                        "paper_ir_revision_id",
                        "blueprint_revision_id",
                        "candidate_pool_snapshot_id",
                    }
                ),
                frozenset(),
            ),
            "export_bundle": (
                frozenset(
                    {"paper_revision_id", "artifact_refs", "manifest_sha256"}
                ),
                frozenset(),
            ),
            "backup_set": (
                frozenset(
                    {
                        "state_id",
                        "database_backup_id",
                        "asset_manifest_sha256",
                    }
                ),
                frozenset(),
            ),
            "active_state": (
                frozenset({"pointers"}),
                frozenset(),
            ),
            "review_event": (
                frozenset(
                    {
                        "subject_revision_id",
                        "decision",
                        "actor_ref",
                        "evidence_revision_ids",
                    }
                ),
                frozenset(),
            ),
            "audit_event": (
                frozenset(
                    {
                        "action",
                        "subject_revision_id",
                        "result",
                        "evidence_sha256",
                    }
                ),
                frozenset(),
            ),
        }
    )
)


class DomainContractError(ValueError):
    pass


def _fail(message: str) -> None:
    raise DomainContractError(message)


def _require_exact_fields(
    value: Mapping[str, Any],
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
    context: str,
) -> None:
    actual = frozenset(value)
    missing = required - actual
    unknown = actual - required - optional
    if missing:
        _fail(f"{context} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        _fail(f"{context} has unknown fields: {', '.join(sorted(unknown))}")


def _require_identifier(value: Any, context: str) -> str:
    if type(value) is not str or not _ID_PATTERN.fullmatch(value):
        _fail(f"{context} must be a contracted identifier")
    if value.casefold() == "latest":
        _fail(f"{context} cannot use a latest-version alias")
    return value


def _require_nonempty_string(value: Any, context: str, *, limit: int = 4096) -> str:
    if type(value) is not str or not value or len(value) > limit:
        _fail(f"{context} must be a non-empty bounded string")
    return value


def _require_sha256(value: Any, context: str) -> str:
    if type(value) is not str or not _SHA256_PATTERN.fullmatch(value):
        _fail(f"{context} must be a lowercase SHA-256")
    return value


def _require_number(
    value: Any,
    context: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    if type(value) not in (int, float) or not math.isfinite(float(value)):
        _fail(f"{context} must be a finite number")
    converted = float(value)
    if minimum is not None and converted < minimum:
        _fail(f"{context} must be >= {minimum}")
    if maximum is not None and converted > maximum:
        _fail(f"{context} must be <= {maximum}")
    return converted


def _require_id_list(value: Any, context: str, *, unique: bool = True) -> list[str]:
    if type(value) is not list:
        _fail(f"{context} must be a list")
    result = [_require_identifier(item, f"{context} item") for item in value]
    if unique and len(set(result)) != len(result):
        _fail(f"{context} cannot contain duplicate identifiers")
    return result


def _require_relative_path_or_none(value: Any, context: str) -> None:
    if value is None:
        return
    if type(value) is not str or not value or "\\" in value or ":" in value:
        _fail(f"{context} must be a project-relative POSIX path or null")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        _fail(f"{context} must not be absolute or traverse parents")
    if path.as_posix() != value:
        _fail(f"{context} must be normalized")


def _validate_json_value(value: Any, context: str, depth: int = 0) -> None:
    if depth > 24:
        _fail(f"{context} exceeds the maximum JSON depth")
    if value is None or type(value) in (bool, int, str):
        return
    if type(value) is float:
        if not math.isfinite(value):
            _fail(f"{context} contains a non-finite number")
        return
    if type(value) is list:
        if len(value) > 4096:
            _fail(f"{context} contains too many list items")
        for index, item in enumerate(value):
            _validate_json_value(item, f"{context}[{index}]", depth + 1)
        return
    if type(value) is dict:
        if len(value) > 4096:
            _fail(f"{context} contains too many object fields")
        for key, item in value.items():
            if type(key) is not str or not key or len(key) > 128:
                _fail(f"{context} contains an invalid object key")
            _validate_json_value(item, f"{context}.{key}", depth + 1)
        return
    _fail(f"{context} contains a non-JSON value")


def _validate_extensions(value: Any, context: str) -> None:
    if type(value) is not dict:
        _fail(f"{context} must be an object")
    for key, item in value.items():
        if type(key) is not str or not _EXTENSION_KEY_PATTERN.fullmatch(key):
            _fail(f"{context} keys must use the x-* extension namespace")
        _validate_json_value(item, f"{context}.{key}")


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DomainContractError("document is not canonical JSON data") from exc


def _clone_json(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(_canonical_json_bytes(value).decode("utf-8"))


def _content_digest(document_without_digest: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json_bytes(document_without_digest)).hexdigest()


def _validate_payload_common(
    object_type: str,
    payload: Any,
) -> dict[str, Any]:
    if type(payload) is not dict:
        _fail("payload must be an object")
    required, optional = _PAYLOAD_CONTRACTS[object_type]
    _require_exact_fields(
        payload,
        required=required | frozenset({"extensions"}),
        optional=optional,
        context=f"{object_type} payload",
    )
    _validate_extensions(payload["extensions"], "payload.extensions")
    _validate_json_value(payload, "payload")
    return payload


def _validate_source_file(payload: Mapping[str, Any]) -> None:
    _require_identifier(payload["logical_source_id"], "logical_source_id")
    _require_sha256(payload["source_sha256"], "source_sha256")
    if type(payload["bytes"]) is not int or payload["bytes"] < 0:
        _fail("bytes must be a non-negative integer")
    if (
        type(payload["media_type"]) is not str
        or not _MEDIA_TYPE_PATTERN.fullmatch(payload["media_type"])
    ):
        _fail("media_type is invalid")
    _require_relative_path_or_none(
        payload["project_relative_path"], "project_relative_path"
    )
    if payload["license_status"] not in {
        "synthetic",
        "user-owned",
        "local-use-only",
        "redistributable",
        "unverified",
    }:
        _fail("license_status is invalid")
    if payload["pii_classification"] not in {
        "none",
        "internal",
        "restricted",
        "unknown",
    }:
        _fail("pii_classification is invalid")


def _validate_source_page(payload: Mapping[str, Any]) -> None:
    _require_identifier(
        payload["source_file_revision_id"], "source_file_revision_id"
    )
    if type(payload["page_no"]) is not int or payload["page_no"] < 1:
        _fail("page_no must be a positive integer")
    _require_number(payload["width_mm"], "width_mm", minimum=0.001)
    _require_number(payload["height_mm"], "height_mm", minimum=0.001)
    if "rotation_degrees" in payload and payload["rotation_degrees"] not in {
        0,
        90,
        180,
        270,
    }:
        _fail("rotation_degrees must be 0, 90, 180 or 270")


def _validate_source_region(payload: Mapping[str, Any]) -> None:
    _require_identifier(payload["source_page_id"], "source_page_id")
    if payload["coordinate_space"] not in {
        "pdf_points_top_left",
        "pixels_top_left",
        "millimetres_top_left",
    }:
        _fail("coordinate_space is invalid")
    bbox = payload["bbox"]
    if (
        type(bbox) is not list
        or len(bbox) != 4
        or any(type(item) not in (int, float) for item in bbox)
        or any(not math.isfinite(float(item)) for item in bbox)
    ):
        _fail("bbox must contain four finite numbers")
    x0, y0, x1, y1 = (float(item) for item in bbox)
    if x0 < 0 or y0 < 0 or x1 <= x0 or y1 <= y0:
        _fail("bbox must be a positive non-empty rectangle")
    if "transform_chain_id" in payload:
        _require_identifier(payload["transform_chain_id"], "transform_chain_id")


def _validate_font_manifest(payload: Mapping[str, Any]) -> None:
    fonts = payload["fonts"]
    if type(fonts) is not list or not fonts:
        _fail("fonts must be a non-empty list")
    seen: set[str] = set()
    required = frozenset(
        {
            "font_id",
            "family",
            "version",
            "sha256",
            "glyph_coverage",
            "license_status",
            "redistributable",
            "fallback_font_id",
        }
    )
    for index, font in enumerate(fonts):
        if type(font) is not dict:
            _fail(f"fonts[{index}] must be an object")
        _require_exact_fields(font, required=required, context=f"fonts[{index}]")
        font_id = _require_identifier(font["font_id"], f"fonts[{index}].font_id")
        if font_id in seen:
            _fail("fonts cannot contain duplicate font_id values")
        seen.add(font_id)
        _require_nonempty_string(font["family"], f"fonts[{index}].family")
        _require_nonempty_string(font["version"], f"fonts[{index}].version")
        if font["sha256"] is not None:
            _require_sha256(font["sha256"], f"fonts[{index}].sha256")
        if (
            type(font["glyph_coverage"]) is not list
            or not font["glyph_coverage"]
            or any(type(item) is not str or not item for item in font["glyph_coverage"])
        ):
            _fail(f"fonts[{index}].glyph_coverage is invalid")
        if font["license_status"] not in {
            "system",
            "user-provided",
            "redistributable",
            "unverified",
        }:
            _fail(f"fonts[{index}].license_status is invalid")
        if type(font["redistributable"]) is not bool:
            _fail(f"fonts[{index}].redistributable must be boolean")
        if font["fallback_font_id"] is not None:
            _require_identifier(
                font["fallback_font_id"], f"fonts[{index}].fallback_font_id"
            )


def _validate_payload(object_type: str, payload: Any) -> None:
    payload = _validate_payload_common(object_type, payload)
    if object_type == "source_file_revision":
        _validate_source_file(payload)
    elif object_type == "source_page":
        _validate_source_page(payload)
    elif object_type == "source_region":
        _validate_source_region(payload)
    elif object_type == "question_revision":
        _require_identifier(
            payload["question_ir_revision_id"], "question_ir_revision_id"
        )
        for field in ("solution_revision_ids", "figure_revision_ids"):
            if field in payload:
                _require_id_list(payload[field], field)
    elif object_type == "solution_revision":
        _require_identifier(payload["question_revision_id"], "question_revision_id")
        _require_identifier(
            payload["solution_ir_revision_id"], "solution_ir_revision_id"
        )
        if "scoring_point_revision_ids" in payload:
            _require_id_list(
                payload["scoring_point_revision_ids"],
                "scoring_point_revision_ids",
            )
    elif object_type == "scoring_point_revision":
        _require_identifier(payload["solution_revision_id"], "solution_revision_id")
        _require_number(payload["points"], "points", minimum=0)
        if type(payload["criteria_blocks"]) is not list:
            _fail("criteria_blocks must be a list")
    elif object_type == "taxonomy_release":
        _require_identifier(payload["taxonomy_id"], "taxonomy_id")
        _require_nonempty_string(payload["release_version"], "release_version")
        _require_sha256(payload["terms_sha256"], "terms_sha256")
    elif object_type == "tag_assertion":
        _require_identifier(payload["question_revision_id"], "question_revision_id")
        _require_identifier(payload["taxonomy_release_id"], "taxonomy_release_id")
        _require_identifier(payload["tag_id"], "tag_id")
        _require_id_list(payload["evidence_revision_ids"], "evidence_revision_ids")
        if payload["review_status"] not in {
            "candidate",
            "approved",
            "stale",
            "rejected",
        }:
            _fail("review_status is invalid")
    elif object_type == "figure_revision":
        _require_identifier(
            payload["figure_ir_revision_id"], "figure_ir_revision_id"
        )
        _require_relative_path_or_none(
            payload["fallback_asset_ref"], "fallback_asset_ref"
        )
        if "derived_asset_refs" in payload:
            if type(payload["derived_asset_refs"]) is not list:
                _fail("derived_asset_refs must be a list")
            for index, item in enumerate(payload["derived_asset_refs"]):
                _require_relative_path_or_none(item, f"derived_asset_refs[{index}]")
    elif object_type == "template_revision":
        _require_identifier(payload["template_family_id"], "template_family_id")
        _require_sha256(payload["token_contract_sha256"], "token_contract_sha256")
        _require_identifier(
            payload["font_manifest_revision_id"], "font_manifest_revision_id"
        )
    elif object_type == "font_manifest":
        _validate_font_manifest(payload)
        if "fallback_policy" in payload:
            _require_nonempty_string(payload["fallback_policy"], "fallback_policy")
    elif object_type == "blueprint_revision":
        _require_identifier(payload["taxonomy_release_id"], "taxonomy_release_id")
        if type(payload["constraints"]) is not list:
            _fail("constraints must be a list")
    elif object_type == "candidate_pool_snapshot":
        _require_id_list(
            payload["question_revision_ids"], "question_revision_ids"
        )
        _require_sha256(
            payload["query_contract_sha256"], "query_contract_sha256"
        )
    elif object_type == "paper_revision":
        _require_identifier(payload["paper_ir_revision_id"], "paper_ir_revision_id")
        _require_identifier(
            payload["blueprint_revision_id"], "blueprint_revision_id"
        )
        _require_identifier(
            payload["candidate_pool_snapshot_id"], "candidate_pool_snapshot_id"
        )
    elif object_type == "export_bundle":
        _require_identifier(payload["paper_revision_id"], "paper_revision_id")
        if type(payload["artifact_refs"]) is not list or not payload["artifact_refs"]:
            _fail("artifact_refs must be a non-empty list")
        for index, item in enumerate(payload["artifact_refs"]):
            _require_relative_path_or_none(item, f"artifact_refs[{index}]")
        _require_sha256(payload["manifest_sha256"], "manifest_sha256")
    elif object_type == "backup_set":
        _require_identifier(payload["state_id"], "state_id")
        _require_identifier(payload["database_backup_id"], "database_backup_id")
        _require_sha256(
            payload["asset_manifest_sha256"], "asset_manifest_sha256"
        )
    elif object_type == "active_state":
        pointers = payload["pointers"]
        if type(pointers) is not dict or not pointers:
            _fail("pointers must be a non-empty object")
        for key in sorted(pointers):
            value = pointers[key]
            if key not in DOMAIN_OBJECT_TYPES - {"active_state"}:
                _fail("pointers contains an unsupported domain object type")
            _require_identifier(value, f"pointers.{key}")
    elif object_type == "review_event":
        _require_identifier(payload["subject_revision_id"], "subject_revision_id")
        if payload["decision"] not in {
            "approve",
            "reject",
            "needs_revision",
            "supersede",
        }:
            _fail("decision is invalid")
        _require_identifier(payload["actor_ref"], "actor_ref")
        _require_id_list(
            payload["evidence_revision_ids"], "evidence_revision_ids"
        )
    elif object_type == "audit_event":
        _require_nonempty_string(payload["action"], "action")
        _require_identifier(payload["subject_revision_id"], "subject_revision_id")
        if payload["result"] not in {"success", "denied", "failed", "in_doubt"}:
            _fail("result is invalid")
        _require_sha256(payload["evidence_sha256"], "evidence_sha256")


def validate_domain_revision(document: Any) -> dict[str, Any]:
    if type(document) is not dict:
        _fail("domain revision must be an object")
    _require_exact_fields(
        document,
        required=_TOP_LEVEL_FIELDS,
        context="domain revision",
    )
    if document["schema_id"] != DOMAIN_SCHEMA_ID:
        _fail("domain revision schema_id is unsupported")
    if document["schema_version"] != DOMAIN_SCHEMA_VERSION:
        _fail("domain revision schema_version is unsupported")
    object_type = document["object_type"]
    if object_type not in DOMAIN_OBJECT_TYPES:
        _fail("domain revision object_type is unsupported")
    object_id = _require_identifier(document["object_id"], "object_id")
    revision_id = _require_identifier(document["revision_id"], "revision_id")
    if revision_id == object_id:
        _fail("revision_id must differ from object_id")
    if type(document["revision_no"]) is not int or document["revision_no"] < 1:
        _fail("revision_no must be a positive integer")
    if document["state"] not in REVISION_STATES:
        _fail("state is invalid")
    if (
        type(document["created_at"]) is not str
        or not _TIMESTAMP_PATTERN.fullmatch(document["created_at"])
    ):
        _fail("created_at must be an explicit UTC ISO-8601 timestamp")
    try:
        datetime.fromisoformat(document["created_at"][:-1] + "+00:00")
    except ValueError as exc:
        raise DomainContractError(
            "created_at must be a real UTC calendar timestamp"
        ) from exc
    predecessor = document["predecessor_revision_id"]
    if document["revision_no"] == 1:
        if predecessor is not None:
            _fail("first revision cannot have a predecessor")
    else:
        _require_identifier(predecessor, "predecessor_revision_id")
        if predecessor == revision_id:
            _fail("revision cannot be its own predecessor")
    _validate_payload(object_type, document["payload"])
    _validate_extensions(document["extensions"], "extensions")
    expected = _content_digest(
        {key: value for key, value in document.items() if key != "content_sha256"}
    )
    _require_sha256(document["content_sha256"], "content_sha256")
    if document["content_sha256"] != expected:
        _fail("content_sha256 does not match canonical revision content")
    return _clone_json(document)


def create_domain_revision(
    *,
    object_type: str,
    object_id: str,
    revision_id: str,
    revision_no: int,
    state: str,
    created_at: str,
    predecessor_revision_id: str | None,
    payload: Mapping[str, Any],
    extensions: Mapping[str, Any] | None = None,
) -> "DomainRevision":
    payload_copy = _clone_json(payload)
    payload_copy.setdefault("extensions", {})
    document: dict[str, Any] = {
        "schema_id": DOMAIN_SCHEMA_ID,
        "schema_version": DOMAIN_SCHEMA_VERSION,
        "object_type": object_type,
        "object_id": object_id,
        "revision_id": revision_id,
        "revision_no": revision_no,
        "state": state,
        "created_at": created_at,
        "predecessor_revision_id": predecessor_revision_id,
        "payload": payload_copy,
        "extensions": _clone_json(extensions or {}),
    }
    document["content_sha256"] = _content_digest(document)
    return DomainRevision.from_dict(document)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DomainContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class DomainRevision:
    _canonical: bytes

    @staticmethod
    def from_dict(document: Mapping[str, Any]) -> "DomainRevision":
        validated = validate_domain_revision(_clone_json(document))
        return DomainRevision(_canonical_json_bytes(validated))

    @staticmethod
    def from_json_bytes(payload: bytes) -> "DomainRevision":
        if type(payload) is not bytes:
            raise DomainContractError("domain revision JSON must be bytes")
        try:
            decoded = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DomainContractError("domain revision JSON must be UTF-8") from exc
        try:
            value = json.loads(decoded, object_pairs_hook=_reject_duplicate_pairs)
        except (json.JSONDecodeError, DomainContractError) as exc:
            if isinstance(exc, DomainContractError):
                raise
            raise DomainContractError("domain revision JSON is invalid") from exc
        return DomainRevision.from_dict(value)

    @property
    def document(self) -> dict[str, Any]:
        return json.loads(self._canonical.decode("utf-8"))

    @property
    def object_type(self) -> str:
        return str(self.document["object_type"])

    @property
    def object_id(self) -> str:
        return str(self.document["object_id"])

    @property
    def revision_id(self) -> str:
        return str(self.document["revision_id"])

    @property
    def content_sha256(self) -> str:
        return str(self.document["content_sha256"])

    def to_json_bytes(self, *, pretty: bool = False) -> bytes:
        if not pretty:
            return self._canonical
        return (
            json.dumps(
                self.document,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                indent=2,
            )
            + "\n"
        ).encode("utf-8")
