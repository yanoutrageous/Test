from __future__ import annotations

import base64
import hashlib
import hmac
import json
import ntpath
import re
import secrets
import threading
import unicodedata
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, NoReturn, Protocol

from .audit_events import (
    AuditAction,
    AuditDecision,
    AuditEvent,
    AuditReceipt,
    CapabilityKind,
    PairRole,
    RedactionMode,
    audit_hmac_key_id,
    audit_receipt,
)
from .context import DataClassification, validate_safe_id
from .namespace_policy import (
    POLICY_DIGEST,
    POLICY_ID,
    POLICY_VERSION,
    NamespaceId,
)
from .windows_handle_writer import (
    HandleDirectorySnapshot,
    HandleWriteReceipt,
    HandleWriterCode,
    HandleWriterError,
    RuntimeMutexLease,
)
from app.workspace_guard import ExpectedKind, PathIntent


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_KEY_FILE = re.compile(
    r"^(?P<sequence>[0-9]{8})-(?P<revision>[A-Z0-9][A-Z0-9_-]{0,63})-"
    r"(?P<digest>[0-9a-f]{64})\.json$"
)
_SEGMENT_FILE = re.compile(r"^(?P<sequence>[0-9]{20})-(?P<digest>[0-9a-f]{64})\.json$")
_UTC_SECONDS = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_KEY_ROOT = Path("logs") / "audit" / "keys"
_SEGMENT_ROOT = Path("logs") / "audit" / "segments"
_KEY_SCHEMA_FIELDS = frozenset({"body", "integrity"})
_KEY_BODY_FIELDS = frozenset(
    {
        "schema_id",
        "schema_version",
        "revision_sequence",
        "revision_id",
        "created_at_utc",
        "algorithm",
        "master_key_base64",
        "master_key_sha256",
        "audit_hmac_key_id",
        "segment_key_id",
    }
)
_KEY_INTEGRITY_FIELDS = frozenset({"revision_sha256"})
_SEGMENT_FIELDS = frozenset({"body", "integrity"})
_SEGMENT_BODY_FIELDS = frozenset(
    {
        "schema_id",
        "schema_version",
        "ledger_id",
        "epoch_id",
        "sequence",
        "previous_segment_sha256",
        "created_at_utc",
        "policy_id",
        "policy_version",
        "policy_digest",
        "key_revision_sequence",
        "key_revision_id",
        "key_revision_sha256",
        "key_id",
        "segment_kind",
        "batch",
        "classification_set",
        "redaction_mode_set",
        "transition",
        "records",
    }
)
_SEGMENT_INTEGRITY_FIELDS = frozenset(
    {"segment_sha256", "segment_hmac_sha256"}
)
_BATCH_FIELDS = frozenset(
    {
        "batch_id",
        "transaction_references",
        "record_ids",
        "record_count",
        "batch_sha256",
    }
)
_TRANSITION_FIELDS = frozenset(
    {
        "from_revision_sequence",
        "from_revision_id",
        "from_revision_sha256",
        "from_key_id",
        "to_revision_sequence",
        "to_revision_id",
        "to_revision_sha256",
        "to_key_id",
        "to_master_key_sha256",
    }
)
_ROTATION_RECORD_FIELDS = frozenset(
    {
        "record_id",
        "record_type",
        "from_revision_id",
        "to_revision_id",
        "to_revision_sha256",
        "to_key_id",
        "to_master_key_sha256",
    }
)
_GENESIS_RECORD_FIELDS = frozenset(
    {
        "record_id",
        "record_type",
        "epoch_id",
        "initial_revision_id",
        "initial_revision_sha256",
        "policy_digest",
    }
)
_AUDIT_EVENT_V21_FIELDS = frozenset(
    {
        "event_version",
        "event_id",
        "occurred_at_utc",
        "decision",
        "action",
        "capability_kind",
        "capability_state",
        "error_code",
        "classification",
        "redaction_mode",
        "context_digest",
        "context_hmac_sha256",
        "run_id",
        "job_id",
        "operation_id",
        "caller",
        "purpose",
        "policy_id",
        "policy_version",
        "policy_digest",
        "boundary_instance_id",
        "ticket_id",
        "pair_id",
        "pair_role",
        "namespace",
        "intent",
        "expected_kind",
        "safe_relative_path",
        "path_hmac_sha256",
        "path_depth",
        "hmac_key_id",
        "manifest_id",
        "manifest_sha256",
        "source_tree_sha256",
        "checkpoint_id",
        "topology_digest",
        "evidence_digest",
    }
)
_MAX_KEY_REVISIONS = 64
_MAX_KEY_FILE_BYTES = 16 * 1024
_MAX_SEGMENTS = 4096
_MAX_SEGMENT_BYTES = 2 * 1024 * 1024
_MAX_LEDGER_BYTES = 64 * 1024 * 1024
_MAX_BATCH_RECORDS = 256
_MAX_JSON_DEPTH = 12
_MAX_STRING_LENGTH = 16 * 1024
_MAX_DIAGNOSTIC_EVENTS = 4096
_LEDGER_CONSTRUCTOR = object()


class _LedgerStorage(Protocol):
    def acquire_runtime_mutex(self) -> RuntimeMutexLease: ...

    def read_flat_directory(
        self,
        relative_path: str | Path,
        *,
        maximum_entries: int,
        maximum_file_bytes: int,
        maximum_total_bytes: int,
    ) -> HandleDirectorySnapshot: ...

    def publish_new_file(
        self,
        staging_relative_path: str | Path,
        target_relative_path: str | Path,
        payload: bytes,
        *,
        expected_sha256: str,
    ) -> HandleWriteReceipt: ...

    def seal_after_indeterminate_mutation(self) -> None: ...


class LedgerCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    STORAGE_FAILURE = "STORAGE_FAILURE"
    KEY_STORE_CORRUPT = "KEY_STORE_CORRUPT"
    KEY_NOT_FOUND = "KEY_NOT_FOUND"
    KEY_CONFLICT = "KEY_CONFLICT"
    CHAIN_CORRUPT = "CHAIN_CORRUPT"
    UNKNOWN_ENTRY = "UNKNOWN_ENTRY"
    POLICY_MISMATCH = "POLICY_MISMATCH"
    REDACTION_FAILURE = "REDACTION_FAILURE"
    BATCH_CONFLICT = "BATCH_CONFLICT"
    RECORD_CONFLICT = "RECORD_CONFLICT"
    ROTATION_INVALID = "ROTATION_INVALID"
    MUTEX_BUSY = "MUTEX_BUSY"
    LEDGER_SEALED = "LEDGER_SEALED"
    CAPACITY_EXCEEDED = "CAPACITY_EXCEEDED"


class LedgerError(RuntimeError):
    def __init__(self, code: LedgerCode, message: str) -> None:
        self.code = code
        super().__init__(f"{code.value}: {message}")

    def __repr__(self) -> str:
        return f"LedgerError(code='{self.code.value}', path='<redacted>', key='<redacted>')"


def _raise_ledger_error(error: LedgerError) -> NoReturn:
    error.__traceback__ = None
    error.__context__ = None
    error.__cause__ = None
    error.__suppress_context__ = True
    raise error from None


class SegmentKind(StrEnum):
    GENESIS = "GENESIS"
    AUDIT_BATCH = "AUDIT_BATCH"
    KEY_ROTATION = "KEY_ROTATION"


@dataclass(frozen=True, slots=True)
class AuditKeyRevision:
    revision_sequence: int
    revision_id: str
    created_at_utc: str
    master_key_sha256: str
    audit_hmac_key_id: str
    segment_key_id: str
    revision_sha256: str
    _master_key: bytes = field(repr=False, compare=False)

    @property
    def audit_hmac_key(self) -> bytes:
        return _derive_key(self._master_key, b"AUDIT-REDACTION-V1\0")

    @property
    def segment_hmac_key(self) -> bytes:
        return _derive_key(self._master_key, b"AUDIT-SEGMENT-AUTH-V1\0")

    def __repr__(self) -> str:
        return (
            "AuditKeyRevision(revision_sequence="
            f"{self.revision_sequence}, revision_id='{self.revision_id}', "
            f"audit_hmac_key_id='{self.audit_hmac_key_id}', key='<redacted>')"
        )

    def __reduce__(self) -> Any:
        raise TypeError("audit key revisions cannot be serialized")


@dataclass(frozen=True, slots=True)
class LedgerHead:
    epoch_id: str
    last_sequence: int
    last_segment_sha256: str | None
    active_revision_sequence: int
    active_revision_id: str
    segment_count: int
    startup_observed_abandoned_mutex: bool = False


@dataclass(frozen=True, slots=True)
class SegmentReceipt:
    epoch_id: str
    sequence: int
    segment_sha256: str
    batch_sha256: str
    record_ids: tuple[str, ...]
    replayed: bool
    capability_state: str = "TEST_LOCAL_DURABLE_SEGMENT"


def _derive_key(master_key: bytes, domain: bytes) -> bytes:
    return hmac.new(master_key, domain, hashlib.sha256).digest()


def _domain_sha256(domain: bytes, payload: bytes) -> str:
    return hashlib.sha256(domain + payload).hexdigest()


def _domain_hmac(key: bytes, domain: bytes, payload: bytes) -> str:
    return hmac.new(key, domain + payload, hashlib.sha256).hexdigest()


def _prefixed_digest_id(prefix: str, digest: str) -> str:
    upper = digest.upper()
    return prefix + upper[:32]


def _validate_utc_seconds(value: str, *, field_name: str) -> str:
    if type(value) is not str or not _UTC_SECONDS.fullmatch(value):
        raise LedgerError(LedgerCode.INVALID_REQUEST, f"{field_name} must be canonical UTC seconds")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise LedgerError(LedgerCode.INVALID_REQUEST, f"{field_name} is not a real UTC instant") from None
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise LedgerError(LedgerCode.INVALID_REQUEST, f"{field_name} is not canonical")
    return value


def _now_utc_seconds() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_json_value(value: Any, *, depth: int = 0) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise LedgerError(LedgerCode.INVALID_REQUEST, "canonical JSON exceeds its depth bound")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if value < -(2**63) or value > 2**63 - 1:
            raise LedgerError(LedgerCode.INVALID_REQUEST, "canonical JSON integer is out of range")
        return
    if type(value) is str:
        if len(value) > _MAX_STRING_LENGTH or unicodedata.normalize("NFC", value) != value:
            raise LedgerError(LedgerCode.INVALID_REQUEST, "canonical JSON string is invalid")
        return
    if type(value) is list:
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str or not key or not key.isascii() or len(key) > 128:
                raise LedgerError(LedgerCode.INVALID_REQUEST, "canonical JSON object key is invalid")
            _validate_json_value(item, depth=depth + 1)
        return
    raise LedgerError(LedgerCode.INVALID_REQUEST, "canonical JSON contains an unsupported type")


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    if type(value) is not dict:
        raise LedgerError(LedgerCode.INVALID_REQUEST, "canonical JSON root must be an exact object")
    _validate_json_value(value)
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _reject_float(_value: str) -> NoReturn:
    raise LedgerError(LedgerCode.CHAIN_CORRUPT, "canonical JSON forbids floating-point values")


def _reject_constant(_value: str) -> NoReturn:
    raise LedgerError(LedgerCode.CHAIN_CORRUPT, "canonical JSON forbids non-finite values")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LedgerError(LedgerCode.CHAIN_CORRUPT, "canonical JSON contains a duplicate key")
        result[key] = value
    return result


def parse_canonical_json_bytes(payload: bytes, *, maximum_bytes: int) -> dict[str, Any]:
    if type(payload) is not bytes or not payload or len(payload) > maximum_bytes:
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "canonical JSON file has an invalid bounded size")
    if payload.startswith(b"\xef\xbb\xbf") or b"\r" in payload or not payload.endswith(b"\n"):
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "canonical JSON byte framing is invalid")
    if payload.endswith(b"\n\n"):
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "canonical JSON has extra trailing data")
    try:
        framed_json = payload[:-1]
        text = str(framed_json, "utf-8", "strict")
        decoded = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except LedgerError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
        OverflowError,
    ):
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "canonical JSON cannot be decoded") from None
    if type(decoded) is not dict:
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "canonical JSON root is not an object")
    try:
        canonical = canonical_json_bytes(decoded)
    except LedgerError:
        raise LedgerError(
            LedgerCode.CHAIN_CORRUPT,
            "canonical JSON schema value is invalid",
        ) from None
    except (RecursionError, ValueError, OverflowError):
        raise LedgerError(
            LedgerCode.CHAIN_CORRUPT,
            "canonical JSON structure exceeds its fixed bounds",
        ) from None
    if canonical != payload:
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "JSON bytes are semantically valid but non-canonical")
    return decoded


def _require_exact_fields(value: Any, expected: frozenset[str], *, label: str) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != expected:
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, f"{label} fields do not match the frozen schema")
    return value


def _require_sha256(value: Any, *, label: str) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, f"{label} is not canonical SHA-256")
    return value


def _key_body(
    *,
    revision_sequence: int,
    revision_id: str,
    created_at_utc: str,
    master_key: bytes,
) -> dict[str, Any]:
    audit_key = _derive_key(master_key, b"AUDIT-REDACTION-V1\0")
    segment_key = _derive_key(master_key, b"AUDIT-SEGMENT-AUTH-V1\0")
    return {
        "schema_id": "LOCAL_EXAM_BANK_AUDIT_KEY_REVISION",
        "schema_version": "1.0",
        "revision_sequence": revision_sequence,
        "revision_id": revision_id,
        "created_at_utc": created_at_utc,
        "algorithm": "HMAC-SHA256-DOMAIN-KDF-V1",
        "master_key_base64": base64.b64encode(master_key).decode("ascii"),
        "master_key_sha256": _domain_sha256(b"AUDIT-MASTER-KEY-V1\0", master_key),
        "audit_hmac_key_id": audit_hmac_key_id(audit_key),
        "segment_key_id": _domain_sha256(b"AUDIT-SEGMENT-KEY-ID-V1\0", segment_key),
    }


def build_key_revision_bytes(
    *,
    revision_sequence: int,
    revision_id: str,
    created_at_utc: str,
    master_key: bytes,
) -> tuple[bytes, AuditKeyRevision]:
    if type(revision_sequence) is not int or revision_sequence < 1 or revision_sequence > 99_999_999:
        raise LedgerError(LedgerCode.INVALID_REQUEST, "revision sequence is outside its fixed range")
    try:
        canonical_revision_id = validate_safe_id(revision_id, field_name="revision_id")
    except Exception:
        raise LedgerError(LedgerCode.INVALID_REQUEST, "revision ID is not canonical") from None
    if len(canonical_revision_id) > 64:
        raise LedgerError(LedgerCode.INVALID_REQUEST, "revision ID exceeds its filename bound")
    created = _validate_utc_seconds(created_at_utc, field_name="created_at_utc")
    if type(master_key) is not bytes or len(master_key) != 32:
        raise LedgerError(LedgerCode.INVALID_REQUEST, "master key must be exact 32-byte material")
    body = _key_body(
        revision_sequence=revision_sequence,
        revision_id=canonical_revision_id,
        created_at_utc=created,
        master_key=master_key,
    )
    body_bytes = canonical_json_bytes(body)[:-1]
    revision_sha256 = _domain_sha256(b"AUDIT-KEY-REVISION-V1\0", body_bytes)
    payload = canonical_json_bytes(
        {
            "body": body,
            "integrity": {"revision_sha256": revision_sha256},
        }
    )
    revision = AuditKeyRevision(
        revision_sequence=revision_sequence,
        revision_id=canonical_revision_id,
        created_at_utc=created,
        master_key_sha256=body["master_key_sha256"],
        audit_hmac_key_id=body["audit_hmac_key_id"],
        segment_key_id=body["segment_key_id"],
        revision_sha256=revision_sha256,
        _master_key=master_key,
    )
    return payload, revision


def _parse_key_revision(name: str, payload: bytes) -> AuditKeyRevision:
    match = _KEY_FILE.fullmatch(name)
    if match is None:
        raise LedgerError(LedgerCode.UNKNOWN_ENTRY, "key store contains an unknown or pending entry")
    envelope = parse_canonical_json_bytes(payload, maximum_bytes=_MAX_KEY_FILE_BYTES)
    _require_exact_fields(envelope, _KEY_SCHEMA_FIELDS, label="key revision envelope")
    body = _require_exact_fields(envelope["body"], _KEY_BODY_FIELDS, label="key revision body")
    integrity = _require_exact_fields(
        envelope["integrity"],
        _KEY_INTEGRITY_FIELDS,
        label="key revision integrity",
    )
    sequence = body["revision_sequence"]
    revision_id = body["revision_id"]
    created_at = body["created_at_utc"]
    if (
        type(sequence) is not int
        or sequence < 1
        or sequence > 99_999_999
        or f"{sequence:08d}" != match.group("sequence")
    ):
        raise LedgerError(LedgerCode.KEY_STORE_CORRUPT, "key revision sequence is invalid")
    try:
        canonical_revision_id = validate_safe_id(revision_id, field_name="revision_id")
    except Exception:
        raise LedgerError(LedgerCode.KEY_STORE_CORRUPT, "key revision ID is invalid") from None
    if canonical_revision_id != match.group("revision") or len(canonical_revision_id) > 64:
        raise LedgerError(LedgerCode.KEY_STORE_CORRUPT, "key revision filename binding is invalid")
    try:
        _validate_utc_seconds(created_at, field_name="created_at_utc")
    except LedgerError:
        raise LedgerError(LedgerCode.KEY_STORE_CORRUPT, "key revision timestamp is invalid") from None
    if body["schema_id"] != "LOCAL_EXAM_BANK_AUDIT_KEY_REVISION" or body["schema_version"] != "1.0":
        raise LedgerError(LedgerCode.KEY_STORE_CORRUPT, "key revision schema is unsupported")
    if body["algorithm"] != "HMAC-SHA256-DOMAIN-KDF-V1":
        raise LedgerError(LedgerCode.KEY_STORE_CORRUPT, "key revision algorithm is unsupported")
    encoded = body["master_key_base64"]
    if type(encoded) is not str:
        raise LedgerError(LedgerCode.KEY_STORE_CORRUPT, "key material encoding is invalid")
    try:
        encoded_bytes = bytes(encoded, "ascii", "strict")
        master_key = base64.b64decode(encoded_bytes, validate=True)
    except (ValueError, UnicodeEncodeError):
        raise LedgerError(LedgerCode.KEY_STORE_CORRUPT, "key material encoding is invalid") from None
    if len(master_key) != 32 or base64.b64encode(master_key).decode("ascii") != encoded:
        raise LedgerError(LedgerCode.KEY_STORE_CORRUPT, "key material length or encoding is invalid")
    expected_body = _key_body(
        revision_sequence=sequence,
        revision_id=canonical_revision_id,
        created_at_utc=created_at,
        master_key=master_key,
    )
    if body != expected_body:
        raise LedgerError(LedgerCode.KEY_STORE_CORRUPT, "key revision derived metadata differs")
    revision_sha = _domain_sha256(
        b"AUDIT-KEY-REVISION-V1\0",
        canonical_json_bytes(body)[:-1],
    )
    if (
        _require_sha256(integrity["revision_sha256"], label="revision SHA-256")
        != revision_sha
        or match.group("digest") != revision_sha
    ):
        raise LedgerError(LedgerCode.KEY_STORE_CORRUPT, "key revision integrity binding differs")
    return AuditKeyRevision(
        revision_sequence=sequence,
        revision_id=canonical_revision_id,
        created_at_utc=created_at,
        master_key_sha256=body["master_key_sha256"],
        audit_hmac_key_id=body["audit_hmac_key_id"],
        segment_key_id=body["segment_key_id"],
        revision_sha256=revision_sha,
        _master_key=master_key,
    )


class AuditKeyRevisionStore:
    def __init__(
        self,
        storage: _LedgerStorage,
        *,
        _constructor: object | None = None,
    ) -> None:
        if _constructor is not _LEDGER_CONSTRUCTOR:
            raise TypeError("key revision stores require the fixed ledger factory")
        self._storage = storage
        self._lock = threading.RLock()
        self._fresh_revision_ids: set[str] = set()

    def create_revision(
        self,
        *,
        revision_sequence: int,
        revision_id: str,
        master_key: bytes,
        created_at_utc: str | None = None,
    ) -> AuditKeyRevision:
        created = created_at_utc or _now_utc_seconds()
        request_error: LedgerError | None = None
        try:
            payload, expected = build_key_revision_bytes(
                revision_sequence=revision_sequence,
                revision_id=revision_id,
                created_at_utc=created,
                master_key=master_key,
            )
        except LedgerError as exc:
            request_error = LedgerError(exc.code, "key revision request is invalid")
        if request_error is not None:
            _raise_ledger_error(request_error)
        operation_error: LedgerError | None = None
        try:
            with self._storage.acquire_runtime_mutex():
                return self._create_revision_under_mutex(payload, expected)
        except LedgerError as exc:
            if exc.code not in {
                LedgerCode.INVALID_REQUEST,
                LedgerCode.KEY_CONFLICT,
                LedgerCode.CAPACITY_EXCEEDED,
            }:
                self._storage.seal_after_indeterminate_mutation()
            operation_error = LedgerError(
                exc.code,
                "key revision operation failed safely",
            )
        except HandleWriterError as exc:
            code = (
                LedgerCode.MUTEX_BUSY
                if exc.code is HandleWriterCode.MUTEX_BUSY
                else LedgerCode.STORAGE_FAILURE
            )
            operation_error = LedgerError(
                code,
                "key revision storage operation failed safely",
            )
        if operation_error is not None:
            _raise_ledger_error(operation_error)
        raise AssertionError("key revision operation completed without a result")

    def load_all(self) -> dict[str, AuditKeyRevision]:
        scan_error: LedgerError | None = None
        with self._lock:
            try:
                with self._storage.acquire_runtime_mutex():
                    return self._load_all_under_mutex()
            except LedgerError as exc:
                self._storage.seal_after_indeterminate_mutation()
                scan_error = LedgerError(exc.code, "key revision scan failed safely")
            except HandleWriterError as exc:
                code = (
                    LedgerCode.MUTEX_BUSY
                    if exc.code is HandleWriterCode.MUTEX_BUSY
                    else LedgerCode.STORAGE_FAILURE
                )
                scan_error = LedgerError(
                    code,
                    "key revision scan storage failed safely",
                )
        if scan_error is not None:
            _raise_ledger_error(scan_error)
        raise AssertionError("key revision scan completed without a result")

    def _consume_fresh_initial_revision(self, revision_id: str) -> bool:
        with self._lock:
            if revision_id not in self._fresh_revision_ids:
                return False
            self._fresh_revision_ids.remove(revision_id)
            return True

    def _create_revision_under_mutex(
        self,
        payload: bytes,
        expected: AuditKeyRevision,
    ) -> AuditKeyRevision:
        with self._lock:
            existing = self._load_all_under_mutex()
            if (
                expected.revision_id in existing
                or any(
                    revision.revision_sequence == expected.revision_sequence
                    or revision.master_key_sha256 == expected.master_key_sha256
                    for revision in existing.values()
                )
            ):
                raise LedgerError(LedgerCode.KEY_CONFLICT, "key revision already exists")
            if len(existing) >= _MAX_KEY_REVISIONS:
                raise LedgerError(
                    LedgerCode.CAPACITY_EXCEEDED,
                    "key revision store reached its fixed capacity",
                )
            final_name = (
                f"{expected.revision_sequence:08d}-{expected.revision_id}-"
                f"{expected.revision_sha256}.json"
            )
            staging_name = (
                f"PENDING-{expected.revision_sequence:08d}-"
                f"{expected.revision_sha256[:24]}-{secrets.token_hex(8).upper()}.json"
            )
            receipt = self._storage.publish_new_file(
                _KEY_ROOT / staging_name,
                _KEY_ROOT / final_name,
                payload,
                expected_sha256=hashlib.sha256(payload).hexdigest(),
            )
            if (
                receipt.size_bytes != len(payload)
                or receipt.sha256 != hashlib.sha256(payload).hexdigest()
            ):
                self._storage.seal_after_indeterminate_mutation()
                raise LedgerError(
                    LedgerCode.STORAGE_FAILURE,
                    "key revision publish receipt differs from exact bytes",
                )
            after = self._load_all_under_mutex()
            actual = after.get(expected.revision_id)
            if actual is None or actual.revision_sha256 != expected.revision_sha256:
                self._storage.seal_after_indeterminate_mutation()
                raise LedgerError(
                    LedgerCode.STORAGE_FAILURE,
                    "key revision is missing after verified publish",
                )
            self._fresh_revision_ids.add(actual.revision_id)
            return actual

    def _load_all_under_mutex(self) -> dict[str, AuditKeyRevision]:
        try:
            snapshot = self._storage.read_flat_directory(
                _KEY_ROOT,
                maximum_entries=_MAX_KEY_REVISIONS,
                maximum_file_bytes=_MAX_KEY_FILE_BYTES,
                maximum_total_bytes=_MAX_KEY_REVISIONS * _MAX_KEY_FILE_BYTES,
            )
        except HandleWriterError as exc:
            raise LedgerError(LedgerCode.STORAGE_FAILURE, "key store cannot be read") from exc
        revisions: dict[str, AuditKeyRevision] = {}
        sequences: set[int] = set()
        key_digests: set[str] = set()
        for entry in snapshot.entries:
            revision = _parse_key_revision(entry.name, entry.payload)
            if (
                revision.revision_id in revisions
                or revision.revision_sequence in sequences
                or revision.master_key_sha256 in key_digests
            ):
                raise LedgerError(LedgerCode.KEY_STORE_CORRUPT, "key store contains a duplicate revision")
            revisions[revision.revision_id] = revision
            sequences.add(revision.revision_sequence)
            key_digests.add(revision.master_key_sha256)
        return dict(
            sorted(
                revisions.items(),
                key=lambda item: item[1].revision_sequence,
            )
        )


def _audit_batch_payload(records: list[dict[str, Any]]) -> bytes:
    return json.dumps(
        records,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _audit_batch_sha256(records: list[dict[str, Any]]) -> str:
    return _domain_sha256(b"AUDIT-BATCH-V1\0", _audit_batch_payload(records))


def _rotation_batch_sha256(records: list[dict[str, Any]]) -> str:
    return _domain_sha256(
        b"AUDIT-KEY-ROTATION-BATCH-V1\0",
        _audit_batch_payload(records),
    )


def _genesis_batch_sha256(records: list[dict[str, Any]]) -> str:
    return _domain_sha256(
        b"AUDIT-GENESIS-BATCH-V1\0",
        _audit_batch_payload(records),
    )


def _segment_envelope(body: dict[str, Any], revision: AuditKeyRevision) -> tuple[bytes, str]:
    body_bytes = canonical_json_bytes(body)[:-1]
    segment_sha256 = _domain_sha256(b"LEDGER-SEGMENT-V1\0", body_bytes)
    segment_hmac_sha256 = _domain_hmac(
        revision.segment_hmac_key,
        b"LEDGER-SEGMENT-AUTH-V1\0",
        bytes.fromhex(segment_sha256),
    )
    envelope = {
        "body": body,
        "integrity": {
            "segment_sha256": segment_sha256,
            "segment_hmac_sha256": segment_hmac_sha256,
        },
    }
    payload = canonical_json_bytes(envelope)
    if len(payload) > _MAX_SEGMENT_BYTES:
        raise LedgerError(LedgerCode.CAPACITY_EXCEEDED, "segment exceeds its exact byte limit")
    return payload, segment_sha256


def _build_genesis_segment_bytes(
    *,
    epoch_id: str,
    created_at_utc: str,
    revision: AuditKeyRevision,
) -> tuple[bytes, str, str, tuple[str, ...]]:
    try:
        canonical_epoch = validate_safe_id(epoch_id, field_name="epoch_id")
    except Exception:
        raise LedgerError(LedgerCode.INVALID_REQUEST, "epoch ID is not canonical") from None
    created = _validate_utc_seconds(created_at_utc, field_name="created_at_utc")
    if type(revision) is not AuditKeyRevision:
        raise LedgerError(LedgerCode.INVALID_REQUEST, "genesis requires an exact key revision")
    record_id = f"GENESIS-{canonical_epoch}"
    record = {
        "record_id": record_id,
        "record_type": SegmentKind.GENESIS.value,
        "epoch_id": canonical_epoch,
        "initial_revision_id": revision.revision_id,
        "initial_revision_sha256": revision.revision_sha256,
        "policy_digest": POLICY_DIGEST,
    }
    records = [record]
    batch_sha = _genesis_batch_sha256(records)
    body = {
        "schema_id": "LOCAL_EXAM_BANK_IMMUTABLE_SEGMENT",
        "schema_version": "1.0",
        "ledger_id": "AUDIT",
        "epoch_id": canonical_epoch,
        "sequence": 0,
        "previous_segment_sha256": None,
        "created_at_utc": created,
        "policy_id": POLICY_ID,
        "policy_version": POLICY_VERSION,
        "policy_digest": POLICY_DIGEST,
        "key_revision_sequence": revision.revision_sequence,
        "key_revision_id": revision.revision_id,
        "key_revision_sha256": revision.revision_sha256,
        "key_id": revision.segment_key_id,
        "segment_kind": SegmentKind.GENESIS.value,
        "batch": {
            "batch_id": _prefixed_digest_id("GENESIS-", batch_sha),
            "transaction_references": [record_id],
            "record_ids": [record_id],
            "record_count": 1,
            "batch_sha256": batch_sha,
        },
        "classification_set": [DataClassification.INTERNAL.value],
        "redaction_mode_set": ["HMAC_ONLY"],
        "transition": None,
        "records": records,
    }
    payload, segment_sha = _segment_envelope(body, revision)
    return payload, segment_sha, batch_sha, (record_id,)


@dataclass(frozen=True, slots=True)
class _ParsedSegment:
    sequence: int
    segment_sha256: str
    previous_segment_sha256: str | None
    kind: SegmentKind
    batch_id: str
    batch_sha256: str
    record_ids: tuple[str, ...]
    revision: AuditKeyRevision
    transition_to: AuditKeyRevision | None


def _validate_audit_record(record: Any, revision: AuditKeyRevision) -> dict[str, Any]:
    row = _require_exact_fields(
        record,
        _AUDIT_EVENT_V21_FIELDS,
        label="audit event v2.1 record",
    )
    if row["event_version"] != "2.1" or type(row["event_id"]) is not str:
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "audit event version or ID is invalid")
    try:
        validate_safe_id(row["event_id"], field_name="event_id")
        _validate_utc_seconds(row["occurred_at_utc"], field_name="occurred_at_utc")
    except Exception:
        raise LedgerError(
            LedgerCode.CHAIN_CORRUPT,
            "audit event identity or timestamp is invalid",
        ) from None
    exact_enum_fields = {
        "decision": {item.value for item in AuditDecision},
        "action": {item.value for item in AuditAction},
        "capability_kind": {item.value for item in CapabilityKind},
        "classification": {item.value for item in DataClassification},
        "redaction_mode": {item.value for item in RedactionMode},
        "namespace": {item.value for item in NamespaceId},
        "intent": {item.value for item in PathIntent},
        "expected_kind": {item.value for item in ExpectedKind},
    }
    if any(
        type(row[field]) is not str or row[field] not in allowed
        for field, allowed in exact_enum_fields.items()
    ):
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "audit event enum field is invalid")
    is_denial = row["decision"] == AuditDecision.DENY.value
    if (
        (
            is_denial
            and (
                row["action"] != AuditAction.DENY.value
                or type(row["error_code"]) is not str
                or not row["error_code"]
            )
        )
        or (
            not is_denial
            and (
                row["action"]
                not in {AuditAction.ISSUE.value, AuditAction.REVALIDATE.value}
                or row["error_code"] is not None
            )
        )
    ):
        raise LedgerError(
            LedgerCode.CHAIN_CORRUPT,
            "audit decision, action, and error code are inconsistent",
        )
    if row["capability_state"] != "CANDIDATE_ONLY":
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "audit capability state is invalid")
    optional_strings = (
        "error_code",
        "context_digest",
        "context_hmac_sha256",
        "run_id",
        "job_id",
        "operation_id",
        "caller",
        "purpose",
        "ticket_id",
        "pair_id",
        "pair_role",
        "safe_relative_path",
        "path_hmac_sha256",
        "manifest_id",
        "manifest_sha256",
        "source_tree_sha256",
        "checkpoint_id",
        "topology_digest",
        "evidence_digest",
    )
    if any(
        value is not None
        and (type(value) is not str or not value or len(value) > _MAX_STRING_LENGTH)
        for value in (row[field] for field in optional_strings)
    ):
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "audit optional string field is invalid")
    if (
        type(row["boundary_instance_id"]) is not str
        or not row["boundary_instance_id"]
        or len(row["boundary_instance_id"]) > 128
        or type(row["hmac_key_id"]) is not str
        or not re.fullmatch(r"[0-9A-F]{16}", row["hmac_key_id"])
    ):
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "audit boundary or key identity is invalid")
    if row["policy_id"] != POLICY_ID or row["policy_version"] != POLICY_VERSION or row["policy_digest"] != POLICY_DIGEST:
        raise LedgerError(LedgerCode.POLICY_MISMATCH, "audit event policy binding differs")
    if row["hmac_key_id"] != revision.audit_hmac_key_id:
        raise LedgerError(LedgerCode.REDACTION_FAILURE, "audit event HMAC key binding differs")
    classification = row["classification"]
    redaction = row["redaction_mode"]
    pair_role = row["pair_role"]
    if pair_role is not None and pair_role not in {item.value for item in PairRole}:
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "audit pair role is invalid")
    is_single = row["capability_kind"] == CapabilityKind.SINGLE.value
    if (
        (is_denial and pair_role is not None)
        or (
            not is_denial
            and (
                (is_single and (pair_role is not None or row["pair_id"] is not None))
                or (not is_single and (pair_role is None or row["pair_id"] is None))
            )
        )
    ):
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "audit pair metadata is inconsistent")
    digest_fields = (
        "manifest_sha256",
        "source_tree_sha256",
        "topology_digest",
        "evidence_digest",
    )
    if any(
        row[field] is not None and not _SHA256.fullmatch(row[field])
        for field in digest_fields
    ):
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "audit evidence digest is invalid")
    context_hmac = row["context_hmac_sha256"]
    visible_context = (
        "run_id",
        "job_id",
        "operation_id",
        "caller",
        "purpose",
    )
    if context_hmac is not None:
        if (
            not _SHA256.fullmatch(context_hmac)
            or row["context_digest"] is not None
            or any(row[field] is not None for field in visible_context)
            or row["manifest_id"] is not None
        ):
            raise LedgerError(LedgerCode.REDACTION_FAILURE, "audit context HMAC mode is invalid")
    elif (
        type(row["context_digest"]) is not str
        or not _SHA256.fullmatch(row["context_digest"])
        or any(row[field] is None for field in visible_context)
    ):
        raise LedgerError(LedgerCode.REDACTION_FAILURE, "audit visible context mode is invalid")
    safe_path = row["safe_relative_path"]
    path_hmac = row["path_hmac_sha256"]
    path_depth = row["path_depth"]
    if redaction == RedactionMode.SAFE_RELATIVE.value:
        if (
            type(safe_path) is not str
            or path_hmac is not None
            or type(path_depth) is not int
            or path_depth < 1
        ):
            raise LedgerError(LedgerCode.REDACTION_FAILURE, "audit visible path mode is invalid")
        pure_path = PureWindowsPath(safe_path)
        canonical_path = ntpath.normcase(
            ntpath.normpath(str(pure_path))
        ).replace("\\", "/")
        if (
            pure_path.drive
            or pure_path.is_absolute()
            or any(part in {"", ".", ".."} for part in pure_path.parts)
            or canonical_path != safe_path
            or path_depth != len(pure_path.parts)
        ):
            raise LedgerError(LedgerCode.REDACTION_FAILURE, "audit visible path is not relative")
    elif (
        safe_path is not None
        or type(path_hmac) is not str
        or not _SHA256.fullmatch(path_hmac)
        or (path_depth is not None and (type(path_depth) is not int or path_depth < 1))
    ):
        raise LedgerError(LedgerCode.REDACTION_FAILURE, "audit HMAC path mode is invalid")
    if classification == DataClassification.RESTRICTED.value:
        forbidden_visible = (
            "context_digest",
            "run_id",
            "job_id",
            "operation_id",
            "caller",
            "purpose",
            "safe_relative_path",
            "path_depth",
            "manifest_id",
            "checkpoint_id",
        )
        if redaction != "HMAC_ONLY" or any(row[name] is not None for name in forbidden_visible):
            raise LedgerError(LedgerCode.REDACTION_FAILURE, "restricted audit record exposes visible context")
        if type(row["path_hmac_sha256"]) is not str or not _SHA256.fullmatch(row["path_hmac_sha256"]):
            raise LedgerError(LedgerCode.REDACTION_FAILURE, "restricted audit path HMAC is missing")
    return row


def _transaction_references(records: list[dict[str, Any]]) -> list[str]:
    references: set[str] = set()
    for record in records:
        candidate = record.get("operation_id") or record.get("context_hmac_sha256")
        if type(candidate) is str:
            references.add(candidate)
    return sorted(references)


def build_audit_segment_bytes(
    *,
    epoch_id: str,
    sequence: int,
    previous_segment_sha256: str | None,
    created_at_utc: str,
    revision: AuditKeyRevision,
    events: tuple[AuditEvent, ...],
) -> tuple[bytes, str, str, tuple[str, ...]]:
    try:
        canonical_epoch = validate_safe_id(epoch_id, field_name="epoch_id")
    except Exception:
        raise LedgerError(LedgerCode.INVALID_REQUEST, "epoch ID is not canonical") from None
    if type(sequence) is not int or sequence < 0 or sequence >= 10**20:
        raise LedgerError(LedgerCode.INVALID_REQUEST, "segment sequence is outside its fixed range")
    if (sequence == 0) is not (previous_segment_sha256 is None):
        raise LedgerError(LedgerCode.INVALID_REQUEST, "genesis previous hash contract is invalid")
    if previous_segment_sha256 is not None and not _SHA256.fullmatch(previous_segment_sha256):
        raise LedgerError(LedgerCode.INVALID_REQUEST, "previous segment hash is invalid")
    created = _validate_utc_seconds(created_at_utc, field_name="created_at_utc")
    if type(revision) is not AuditKeyRevision:
        raise LedgerError(LedgerCode.INVALID_REQUEST, "segment requires an exact key revision")
    if type(events) is not tuple or not events or len(events) > _MAX_BATCH_RECORDS:
        raise LedgerError(LedgerCode.INVALID_REQUEST, "audit batch has an invalid record count")
    if any(type(event) is not AuditEvent for event in events):
        raise LedgerError(LedgerCode.INVALID_REQUEST, "audit batch requires exact AuditEvent records")
    records = [event.to_dict() for event in events]
    for record in records:
        _validate_audit_record(record, revision)
    receipt = audit_receipt(events)
    if receipt.batch_sha256 != _audit_batch_sha256(records):
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "audit receipt algorithm drifted")
    record_ids = receipt.event_ids
    if len(set(record_ids)) != len(record_ids):
        raise LedgerError(LedgerCode.RECORD_CONFLICT, "audit batch contains duplicate event IDs")
    batch_id = _prefixed_digest_id("AUDIT-", receipt.batch_sha256)
    classifications = sorted({record["classification"] for record in records})
    redactions = sorted({record["redaction_mode"] for record in records})
    body = {
        "schema_id": "LOCAL_EXAM_BANK_IMMUTABLE_SEGMENT",
        "schema_version": "1.0",
        "ledger_id": "AUDIT",
        "epoch_id": canonical_epoch,
        "sequence": sequence,
        "previous_segment_sha256": previous_segment_sha256,
        "created_at_utc": created,
        "policy_id": POLICY_ID,
        "policy_version": POLICY_VERSION,
        "policy_digest": POLICY_DIGEST,
        "key_revision_sequence": revision.revision_sequence,
        "key_revision_id": revision.revision_id,
        "key_revision_sha256": revision.revision_sha256,
        "key_id": revision.segment_key_id,
        "segment_kind": SegmentKind.AUDIT_BATCH.value,
        "batch": {
            "batch_id": batch_id,
            "transaction_references": _transaction_references(records),
            "record_ids": list(record_ids),
            "record_count": len(records),
            "batch_sha256": receipt.batch_sha256,
        },
        "classification_set": classifications,
        "redaction_mode_set": redactions,
        "transition": None,
        "records": records,
    }
    payload, segment_sha = _segment_envelope(body, revision)
    return payload, segment_sha, receipt.batch_sha256, record_ids


def _build_rotation_segment_bytes(
    *,
    epoch_id: str,
    sequence: int,
    previous_segment_sha256: str | None,
    created_at_utc: str,
    current_revision: AuditKeyRevision,
    next_revision: AuditKeyRevision,
    rotation_id: str,
) -> tuple[bytes, str, str, tuple[str, ...]]:
    try:
        canonical_rotation_id = validate_safe_id(rotation_id, field_name="rotation_id")
    except Exception:
        raise LedgerError(LedgerCode.INVALID_REQUEST, "rotation ID is not canonical") from None
    if next_revision.revision_sequence != current_revision.revision_sequence + 1:
        raise LedgerError(LedgerCode.ROTATION_INVALID, "key rotation sequence is not contiguous")
    record = {
        "record_id": canonical_rotation_id,
        "record_type": SegmentKind.KEY_ROTATION.value,
        "from_revision_id": current_revision.revision_id,
        "to_revision_id": next_revision.revision_id,
        "to_revision_sha256": next_revision.revision_sha256,
        "to_key_id": next_revision.segment_key_id,
        "to_master_key_sha256": next_revision.master_key_sha256,
    }
    records = [record]
    batch_sha = _rotation_batch_sha256(records)
    transition = {
        "from_revision_sequence": current_revision.revision_sequence,
        "from_revision_id": current_revision.revision_id,
        "from_revision_sha256": current_revision.revision_sha256,
        "from_key_id": current_revision.segment_key_id,
        "to_revision_sequence": next_revision.revision_sequence,
        "to_revision_id": next_revision.revision_id,
        "to_revision_sha256": next_revision.revision_sha256,
        "to_key_id": next_revision.segment_key_id,
        "to_master_key_sha256": next_revision.master_key_sha256,
    }
    body = {
        "schema_id": "LOCAL_EXAM_BANK_IMMUTABLE_SEGMENT",
        "schema_version": "1.0",
        "ledger_id": "AUDIT",
        "epoch_id": epoch_id,
        "sequence": sequence,
        "previous_segment_sha256": previous_segment_sha256,
        "created_at_utc": _validate_utc_seconds(created_at_utc, field_name="created_at_utc"),
        "policy_id": POLICY_ID,
        "policy_version": POLICY_VERSION,
        "policy_digest": POLICY_DIGEST,
        "key_revision_sequence": current_revision.revision_sequence,
        "key_revision_id": current_revision.revision_id,
        "key_revision_sha256": current_revision.revision_sha256,
        "key_id": current_revision.segment_key_id,
        "segment_kind": SegmentKind.KEY_ROTATION.value,
        "batch": {
            "batch_id": _prefixed_digest_id("ROTATION-", batch_sha),
            "transaction_references": [canonical_rotation_id],
            "record_ids": [canonical_rotation_id],
            "record_count": 1,
            "batch_sha256": batch_sha,
        },
        "classification_set": [DataClassification.INTERNAL.value],
        "redaction_mode_set": ["HMAC_ONLY"],
        "transition": transition,
        "records": records,
    }
    payload, segment_sha = _segment_envelope(body, current_revision)
    return payload, segment_sha, batch_sha, (canonical_rotation_id,)


def _parse_segment(
    *,
    name: str,
    payload: bytes,
    epoch_id: str,
    expected_sequence: int,
    expected_previous: str | None,
    current_revision: AuditKeyRevision,
    revisions: dict[str, AuditKeyRevision],
) -> _ParsedSegment:
    match = _SEGMENT_FILE.fullmatch(name)
    if match is None:
        raise LedgerError(LedgerCode.UNKNOWN_ENTRY, "segment store contains an unknown or pending entry")
    envelope = parse_canonical_json_bytes(payload, maximum_bytes=_MAX_SEGMENT_BYTES)
    _require_exact_fields(envelope, _SEGMENT_FIELDS, label="segment envelope")
    body = _require_exact_fields(envelope["body"], _SEGMENT_BODY_FIELDS, label="segment body")
    integrity = _require_exact_fields(
        envelope["integrity"],
        _SEGMENT_INTEGRITY_FIELDS,
        label="segment integrity",
    )
    sequence = body["sequence"]
    if (
        type(sequence) is not int
        or sequence != expected_sequence
        or f"{sequence:020d}" != match.group("sequence")
    ):
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "segment sequence or filename is not contiguous")
    previous = body["previous_segment_sha256"]
    if previous != expected_previous:
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "segment previous-hash link differs")
    if body["schema_id"] != "LOCAL_EXAM_BANK_IMMUTABLE_SEGMENT" or body["schema_version"] != "1.0":
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "segment schema is unsupported")
    if body["ledger_id"] != "AUDIT" or body["epoch_id"] != epoch_id:
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "segment ledger or epoch binding differs")
    try:
        _validate_utc_seconds(body["created_at_utc"], field_name="created_at_utc")
    except LedgerError:
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "segment timestamp is invalid") from None
    if body["policy_id"] != POLICY_ID or body["policy_version"] != POLICY_VERSION or body["policy_digest"] != POLICY_DIGEST:
        raise LedgerError(LedgerCode.POLICY_MISMATCH, "segment policy binding differs")
    if (
        body["key_revision_sequence"] != current_revision.revision_sequence
        or body["key_revision_id"] != current_revision.revision_id
        or body["key_revision_sha256"] != current_revision.revision_sha256
        or body["key_id"] != current_revision.segment_key_id
    ):
        raise LedgerError(LedgerCode.ROTATION_INVALID, "segment used an inactive key revision")
    body_bytes = canonical_json_bytes(body)[:-1]
    segment_sha = _domain_sha256(b"LEDGER-SEGMENT-V1\0", body_bytes)
    segment_hmac = _domain_hmac(
        current_revision.segment_hmac_key,
        b"LEDGER-SEGMENT-AUTH-V1\0",
        bytes.fromhex(segment_sha),
    )
    if (
        _require_sha256(integrity["segment_sha256"], label="segment SHA-256") != segment_sha
        or _require_sha256(integrity["segment_hmac_sha256"], label="segment HMAC") != segment_hmac
        or match.group("digest") != segment_sha
    ):
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "segment hash, HMAC, or filename binding differs")
    batch = _require_exact_fields(body["batch"], _BATCH_FIELDS, label="segment batch")
    if (
        type(batch["batch_id"]) is not str
        or type(batch["transaction_references"]) is not list
        or any(type(item) is not str for item in batch["transaction_references"])
        or batch["transaction_references"] != sorted(set(batch["transaction_references"]))
        or type(batch["record_ids"]) is not list
        or any(type(item) is not str for item in batch["record_ids"])
        or len(set(batch["record_ids"])) != len(batch["record_ids"])
        or type(batch["record_count"]) is not int
        or batch["record_count"] != len(batch["record_ids"])
        or batch["record_count"] < 1
        or batch["record_count"] > _MAX_BATCH_RECORDS
    ):
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "segment batch metadata is invalid")
    records = body["records"]
    if type(records) is not list or len(records) != batch["record_count"]:
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "segment record count differs")
    if type(body["classification_set"]) is not list or type(body["redaction_mode_set"]) is not list:
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "segment classification metadata is invalid")
    try:
        kind = SegmentKind(body["segment_kind"])
    except (TypeError, ValueError):
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "segment kind is unsupported") from None
    transition_to: AuditKeyRevision | None = None
    if kind is SegmentKind.GENESIS:
        if sequence != 0 or body["transition"] is not None or len(records) != 1:
            raise LedgerError(LedgerCode.CHAIN_CORRUPT, "genesis placement or shape is invalid")
        record = _require_exact_fields(
            records[0],
            _GENESIS_RECORD_FIELDS,
            label="genesis record",
        )
        record_ids = (record["record_id"],)
        batch_sha = _genesis_batch_sha256([record])
        if (
            record["record_id"] != f"GENESIS-{epoch_id}"
            or record["record_type"] != SegmentKind.GENESIS.value
            or record["epoch_id"] != epoch_id
            or record["initial_revision_id"] != current_revision.revision_id
            or record["initial_revision_sha256"] != current_revision.revision_sha256
            or record["policy_digest"] != POLICY_DIGEST
            or batch["batch_id"] != _prefixed_digest_id("GENESIS-", batch_sha)
            or batch["transaction_references"] != [record["record_id"]]
            or body["classification_set"] != [DataClassification.INTERNAL.value]
            or body["redaction_mode_set"] != ["HMAC_ONLY"]
        ):
            raise LedgerError(LedgerCode.CHAIN_CORRUPT, "genesis binding differs")
    elif kind is SegmentKind.AUDIT_BATCH:
        if sequence == 0:
            raise LedgerError(LedgerCode.CHAIN_CORRUPT, "audit batch cannot replace genesis")
        if body["transition"] is not None:
            raise LedgerError(LedgerCode.CHAIN_CORRUPT, "audit batch unexpectedly contains a key transition")
        validated = [_validate_audit_record(record, current_revision) for record in records]
        record_ids = tuple(record["event_id"] for record in validated)
        batch_sha = _audit_batch_sha256(validated)
        if batch["batch_id"] != _prefixed_digest_id("AUDIT-", batch_sha):
            raise LedgerError(LedgerCode.CHAIN_CORRUPT, "audit batch ID differs from its canonical content")
        if body["classification_set"] != sorted({record["classification"] for record in validated}):
            raise LedgerError(LedgerCode.CHAIN_CORRUPT, "audit classification set differs")
        if body["redaction_mode_set"] != sorted({record["redaction_mode"] for record in validated}):
            raise LedgerError(LedgerCode.CHAIN_CORRUPT, "audit redaction set differs")
        if batch["transaction_references"] != _transaction_references(validated):
            raise LedgerError(LedgerCode.CHAIN_CORRUPT, "audit transaction references differ")
    else:
        if sequence == 0:
            raise LedgerError(LedgerCode.ROTATION_INVALID, "key rotation cannot replace genesis")
        transition = _require_exact_fields(body["transition"], _TRANSITION_FIELDS, label="key transition")
        if len(records) != 1:
            raise LedgerError(LedgerCode.ROTATION_INVALID, "key rotation segment record count differs")
        record = _require_exact_fields(records[0], _ROTATION_RECORD_FIELDS, label="key rotation record")
        record_ids = (record["record_id"],)
        batch_sha = _rotation_batch_sha256([record])
        if (
            record["record_type"] != SegmentKind.KEY_ROTATION.value
            or batch["batch_id"] != _prefixed_digest_id("ROTATION-", batch_sha)
            or batch["transaction_references"] != [record["record_id"]]
            or body["classification_set"] != [DataClassification.INTERNAL.value]
            or body["redaction_mode_set"] != ["HMAC_ONLY"]
            or transition["from_revision_sequence"] != current_revision.revision_sequence
            or transition["from_revision_id"] != current_revision.revision_id
            or transition["from_revision_sha256"] != current_revision.revision_sha256
            or transition["from_key_id"] != current_revision.segment_key_id
        ):
            raise LedgerError(LedgerCode.ROTATION_INVALID, "key rotation source binding differs")
        next_revision = revisions.get(transition["to_revision_id"])
        if (
            next_revision is None
            or next_revision.revision_sequence != current_revision.revision_sequence + 1
            or transition["to_revision_sequence"] != next_revision.revision_sequence
            or transition["to_revision_sha256"] != next_revision.revision_sha256
            or transition["to_key_id"] != next_revision.segment_key_id
            or transition["to_master_key_sha256"] != next_revision.master_key_sha256
            or record["from_revision_id"] != current_revision.revision_id
            or record["to_revision_id"] != next_revision.revision_id
            or record["to_revision_sha256"] != next_revision.revision_sha256
            or record["to_key_id"] != next_revision.segment_key_id
            or record["to_master_key_sha256"] != next_revision.master_key_sha256
        ):
            raise LedgerError(LedgerCode.ROTATION_INVALID, "key rotation target binding differs")
        transition_to = next_revision
    if tuple(batch["record_ids"]) != record_ids or batch["batch_sha256"] != batch_sha:
        raise LedgerError(LedgerCode.CHAIN_CORRUPT, "segment batch digest or record IDs differ")
    return _ParsedSegment(
        sequence=sequence,
        segment_sha256=segment_sha,
        previous_segment_sha256=previous,
        kind=kind,
        batch_id=batch["batch_id"],
        batch_sha256=batch_sha,
        record_ids=record_ids,
        revision=current_revision,
        transition_to=transition_to,
    )


class DurableAuditLedger:
    def __init__(
        self,
        storage: _LedgerStorage,
        key_store: AuditKeyRevisionStore,
        *,
        epoch_id: str,
        initial_revision_id: str,
        initialize: bool = False,
        initialized_at_utc: str | None = None,
        _runtime_mutex_lease: RuntimeMutexLease | None = None,
        _constructor: object | None = None,
    ) -> None:
        if _constructor is not _LEDGER_CONSTRUCTOR:
            raise TypeError("durable ledgers require the fixed ledger factory")
        if _runtime_mutex_lease is not None and (
            type(_runtime_mutex_lease) is not RuntimeMutexLease
            or _runtime_mutex_lease._writer is not storage
        ):
            raise LedgerError(
                LedgerCode.INVALID_REQUEST,
                "ledger runtime mutex lease is invalid",
            )
        if _runtime_mutex_lease is not None:
            _runtime_mutex_lease._assert_live_owner(storage)
        if type(initialize) is not bool or (
            not initialize and initialized_at_utc is not None
        ):
            raise LedgerError(
                LedgerCode.INVALID_REQUEST,
                "ledger initialization mode is invalid",
            )
        try:
            self._epoch_id = validate_safe_id(epoch_id, field_name="epoch_id")
            self._initial_revision_id = validate_safe_id(
                initial_revision_id,
                field_name="initial_revision_id",
            )
        except Exception:
            raise LedgerError(LedgerCode.INVALID_REQUEST, "ledger identity is not canonical") from None
        if key_store._storage is not storage:
            raise LedgerError(LedgerCode.INVALID_REQUEST, "ledger and key store authorities differ")
        if initialize and not key_store._consume_fresh_initial_revision(
            self._initial_revision_id
        ):
            raise LedgerError(
                LedgerCode.INVALID_REQUEST,
                "ledger initialization requires a freshly published initial key",
            )
        self._storage = storage
        self._key_store = key_store
        self._lock = threading.RLock()
        self._sealed_code: LedgerCode | None = None
        self._segments: tuple[_ParsedSegment, ...] = ()
        self._revisions: dict[str, AuditKeyRevision] = {}
        self._batches: dict[str, SegmentReceipt] = {}
        self._record_ids: set[str] = set()
        self._total_segment_bytes = 0
        self._head: LedgerHead | None = None
        startup_error: LedgerError | None = None
        try:
            if _runtime_mutex_lease is None:
                with self._storage.acquire_runtime_mutex() as lease:
                    self._startup_under_mutex(
                        lease,
                        initialize=initialize,
                        initialized_at_utc=initialized_at_utc,
                    )
            else:
                self._startup_under_mutex(
                    _runtime_mutex_lease,
                    initialize=initialize,
                    initialized_at_utc=initialized_at_utc,
                )
        except LedgerError as exc:
            self._sealed_code = exc.code
            self._storage.seal_after_indeterminate_mutation()
            startup_error = LedgerError(
                exc.code,
                "ledger startup validation failed safely",
            )
        except HandleWriterError as exc:
            self._sealed_code = (
                LedgerCode.MUTEX_BUSY if exc.code is HandleWriterCode.MUTEX_BUSY else LedgerCode.STORAGE_FAILURE
            )
            startup_error = LedgerError(
                self._sealed_code,
                "ledger startup storage failed safely",
            )
        if startup_error is not None:
            _raise_ledger_error(startup_error)

    def _startup_under_mutex(
        self,
        lease: RuntimeMutexLease,
        *,
        initialize: bool,
        initialized_at_utc: str | None,
    ) -> None:
        self._scan_under_mutex(
            startup_abandoned=lease.abandoned,
            allow_empty=initialize,
        )
        if not initialize:
            return
        active = self._active_revision()
        if (
            self._segments
            or len(self._revisions) != 1
            or active.revision_sequence != 1
        ):
            raise LedgerError(
                LedgerCode.INVALID_REQUEST,
                "ledger initialization roots are not exact and empty",
            )
        payload, segment_sha, _batch_sha, _record_ids = (
            _build_genesis_segment_bytes(
                epoch_id=self._epoch_id,
                created_at_utc=initialized_at_utc or _now_utc_seconds(),
                revision=active,
            )
        )
        self._publish_segment(
            sequence=0,
            segment_sha256=segment_sha,
            payload=payload,
        )
        self._scan_under_mutex(
            startup_abandoned=lease.abandoned,
            allow_empty=False,
        )

    @property
    def head(self) -> LedgerHead:
        with self._lock:
            self._require_open()
            if self._head is None:
                raise LedgerError(LedgerCode.LEDGER_SEALED, "ledger head is unavailable")
            return self._head

    @property
    def audit_hmac_key_id(self) -> str:
        with self._lock:
            self._require_open()
            return self._active_revision().audit_hmac_key_id

    def append_audit_batch(
        self,
        events: tuple[AuditEvent, ...],
        *,
        created_at_utc: str | None = None,
    ) -> SegmentReceipt:
        _events, receipt = self._append_with_factory(
            lambda _revision: events,
            created_at_utc=created_at_utc,
        )
        return receipt

    def append_built_audit_batch(
        self,
        builder: Callable[[bytes], tuple[AuditEvent, ...]],
        *,
        created_at_utc: str | None = None,
    ) -> tuple[tuple[AuditEvent, ...], SegmentReceipt]:
        if not callable(builder):
            raise LedgerError(
                LedgerCode.INVALID_REQUEST,
                "audit event builder must be callable",
            )
        return self._append_with_factory(
            lambda revision: builder(revision.audit_hmac_key),
            created_at_utc=created_at_utc,
        )

    def _append_with_factory(
        self,
        factory: Callable[[AuditKeyRevision], tuple[AuditEvent, ...]],
        *,
        created_at_utc: str | None,
    ) -> tuple[tuple[AuditEvent, ...], SegmentReceipt]:
        created = created_at_utc or _now_utc_seconds()
        append_error: LedgerError | None = None
        result: tuple[tuple[AuditEvent, ...], SegmentReceipt] | None = None
        with self._lock:
            self._require_open()
            try:
                with self._storage.acquire_runtime_mutex():
                    try:
                        self._scan_under_mutex(
                            startup_abandoned=False,
                            allow_empty=False,
                        )
                    except LedgerError as exc:
                        self._seal(exc.code)
                        raise
                    active = self._active_revision()
                    try:
                        events = factory(active)
                    except LedgerError:
                        raise
                    except Exception:
                        raise LedgerError(
                            LedgerCode.INVALID_REQUEST,
                            "audit event builder failed safely",
                        ) from None
                    committed = self._append_events_under_mutex(
                        events,
                        created_at_utc=created,
                        active=active,
                    )
                    result = (events, committed)
            except LedgerError as exc:
                append_error = LedgerError(
                    exc.code,
                    "audit segment append failed safely",
                )
            except HandleWriterError as exc:
                code = (
                    LedgerCode.MUTEX_BUSY
                    if exc.code is HandleWriterCode.MUTEX_BUSY
                    else LedgerCode.STORAGE_FAILURE
                )
                if code is not LedgerCode.MUTEX_BUSY:
                    self._seal(code)
                append_error = LedgerError(
                    code,
                    "audit segment storage failed safely",
                )
        if append_error is not None:
            _raise_ledger_error(append_error)
        if result is None:
            raise AssertionError("audit segment append completed without a result")
        return result

    def _append_events_under_mutex(
        self,
        events: tuple[AuditEvent, ...],
        *,
        created_at_utc: str,
        active: AuditKeyRevision,
    ) -> SegmentReceipt:
        if (
            type(events) is not tuple
            or not events
            or any(type(event) is not AuditEvent for event in events)
        ):
            raise LedgerError(
                LedgerCode.INVALID_REQUEST,
                "audit batch requires a non-empty exact event tuple",
            )
        try:
            expected = audit_receipt(events)
        except LedgerError:
            raise
        except Exception:
            raise LedgerError(
                LedgerCode.INVALID_REQUEST,
                "audit batch identity could not be computed safely",
            ) from None
        batch_id = _prefixed_digest_id("AUDIT-", expected.batch_sha256)
        replay = self._batches.get(batch_id)
        if replay is not None:
            if (
                replay.batch_sha256 == expected.batch_sha256
                and replay.record_ids == expected.event_ids
            ):
                return SegmentReceipt(
                    epoch_id=replay.epoch_id,
                    sequence=replay.sequence,
                    segment_sha256=replay.segment_sha256,
                    batch_sha256=replay.batch_sha256,
                    record_ids=replay.record_ids,
                    replayed=True,
                )
            self._seal(LedgerCode.BATCH_CONFLICT)
            raise LedgerError(
                LedgerCode.BATCH_CONFLICT,
                "batch ID replay differs from committed content",
            )
        if any(record_id in self._record_ids for record_id in expected.event_ids):
            self._seal(LedgerCode.RECORD_CONFLICT)
            raise LedgerError(
                LedgerCode.RECORD_CONFLICT,
                "audit event ID was already committed",
            )
        head = self._required_head()
        try:
            payload, segment_sha, batch_sha, record_ids = build_audit_segment_bytes(
                epoch_id=self._epoch_id,
                sequence=head.last_sequence + 1,
                previous_segment_sha256=head.last_segment_sha256,
                created_at_utc=created_at_utc,
                revision=active,
                events=events,
            )
        except LedgerError:
            raise
        except Exception:
            raise LedgerError(
                LedgerCode.INVALID_REQUEST,
                "audit segment construction failed before publication",
            ) from None
        if batch_sha != expected.batch_sha256 or record_ids != expected.event_ids:
            self._seal(LedgerCode.STORAGE_FAILURE)
            raise LedgerError(
                LedgerCode.STORAGE_FAILURE,
                "audit batch identity changed during exact segment construction",
            )
        receipt = self._publish_segment(
            sequence=head.last_sequence + 1,
            segment_sha256=segment_sha,
            payload=payload,
        )
        try:
            self._scan_under_mutex(
                startup_abandoned=False,
                allow_empty=False,
            )
        except LedgerError as exc:
            self._seal(exc.code)
            raise
        committed = self._batches.get(batch_id)
        if (
            committed is None
            or committed.segment_sha256 != segment_sha
            or receipt.sha256 != hashlib.sha256(payload).hexdigest()
        ):
            self._seal(LedgerCode.STORAGE_FAILURE)
            raise LedgerError(
                LedgerCode.STORAGE_FAILURE,
                "published segment is absent after full-chain rescan",
            )
        return committed

    def rotate_key(
        self,
        *,
        next_revision_id: str,
        rotation_id: str,
        created_at_utc: str | None = None,
    ) -> SegmentReceipt:
        created = created_at_utc or _now_utc_seconds()
        rotation_error: LedgerError | None = None
        with self._lock:
            self._require_open()
            try:
                with self._storage.acquire_runtime_mutex():
                    try:
                        self._scan_under_mutex(
                            startup_abandoned=False,
                            allow_empty=False,
                        )
                    except LedgerError as exc:
                        self._seal(exc.code)
                        raise
                    try:
                        canonical_rotation_id = validate_safe_id(
                            rotation_id,
                            field_name="rotation_id",
                        )
                        canonical_next_revision_id = validate_safe_id(
                            next_revision_id,
                            field_name="next_revision_id",
                        )
                    except Exception:
                        raise LedgerError(
                            LedgerCode.INVALID_REQUEST,
                            "key rotation identity is not canonical",
                        ) from None
                    prior = next(
                        (
                            segment
                            for segment in self._segments
                            if canonical_rotation_id in segment.record_ids
                        ),
                        None,
                    )
                    if prior is not None:
                        if (
                            prior.kind is not SegmentKind.KEY_ROTATION
                            or prior.transition_to is None
                            or prior.transition_to.revision_id
                            != canonical_next_revision_id
                        ):
                            self._seal(LedgerCode.RECORD_CONFLICT)
                            raise LedgerError(
                                LedgerCode.RECORD_CONFLICT,
                                "rotation ID replay differs from committed content",
                            )
                        replay = self._batches[prior.batch_id]
                        return SegmentReceipt(
                            epoch_id=replay.epoch_id,
                            sequence=replay.sequence,
                            segment_sha256=replay.segment_sha256,
                            batch_sha256=replay.batch_sha256,
                            record_ids=replay.record_ids,
                            replayed=True,
                        )
                    current = self._active_revision()
                    next_revision = self._revisions.get(canonical_next_revision_id)
                    if next_revision is None:
                        raise LedgerError(LedgerCode.KEY_NOT_FOUND, "rotation target key revision does not exist")
                    head = self._required_head()
                    payload, segment_sha, batch_sha, record_ids = _build_rotation_segment_bytes(
                        epoch_id=self._epoch_id,
                        sequence=head.last_sequence + 1,
                        previous_segment_sha256=head.last_segment_sha256,
                        created_at_utc=created,
                        current_revision=current,
                        next_revision=next_revision,
                        rotation_id=rotation_id,
                    )
                    batch_id = _prefixed_digest_id("ROTATION-", batch_sha)
                    replay = self._batches.get(batch_id)
                    if replay is not None:
                        return SegmentReceipt(
                            epoch_id=replay.epoch_id,
                            sequence=replay.sequence,
                            segment_sha256=replay.segment_sha256,
                            batch_sha256=replay.batch_sha256,
                            record_ids=replay.record_ids,
                            replayed=True,
                        )
                    if any(record_id in self._record_ids for record_id in record_ids):
                        self._seal(LedgerCode.RECORD_CONFLICT)
                        raise LedgerError(LedgerCode.RECORD_CONFLICT, "rotation record ID was already committed")
                    self._publish_segment(
                        sequence=head.last_sequence + 1,
                        segment_sha256=segment_sha,
                        payload=payload,
                    )
                    try:
                        self._scan_under_mutex(
                            startup_abandoned=False,
                            allow_empty=False,
                        )
                    except LedgerError as exc:
                        self._seal(exc.code)
                        raise
                    committed = self._batches.get(batch_id)
                    if committed is None or self._active_revision().revision_id != next_revision_id:
                        self._seal(LedgerCode.ROTATION_INVALID)
                        raise LedgerError(LedgerCode.ROTATION_INVALID, "rotation did not become active after rescan")
                    return committed
            except LedgerError as exc:
                rotation_error = LedgerError(
                    exc.code,
                    "key rotation failed safely",
                )
            except HandleWriterError as exc:
                code = (
                    LedgerCode.MUTEX_BUSY
                    if exc.code is HandleWriterCode.MUTEX_BUSY
                    else LedgerCode.STORAGE_FAILURE
                )
                if code is not LedgerCode.MUTEX_BUSY:
                    self._seal(code)
                rotation_error = LedgerError(
                    code,
                    "key rotation storage failed safely",
                )
        if rotation_error is not None:
            _raise_ledger_error(rotation_error)
        raise AssertionError("key rotation completed without a result")

    def _publish_segment(
        self,
        *,
        sequence: int,
        segment_sha256: str,
        payload: bytes,
    ) -> HandleWriteReceipt:
        if (
            len(self._segments) >= _MAX_SEGMENTS
            or self._total_segment_bytes + len(payload) > _MAX_LEDGER_BYTES
        ):
            raise LedgerError(
                LedgerCode.CAPACITY_EXCEEDED,
                "ledger reached its fixed segment or byte capacity",
            )
        directory = _SEGMENT_ROOT / self._epoch_id
        final_name = f"{sequence:020d}-{segment_sha256}.json"
        staging_name = (
            f"PENDING-{sequence:020d}-{segment_sha256[:24]}-"
            f"{secrets.token_hex(8).upper()}.json"
        )
        return self._storage.publish_new_file(
            directory / staging_name,
            directory / final_name,
            payload,
            expected_sha256=hashlib.sha256(payload).hexdigest(),
        )

    def _scan_under_mutex(
        self,
        *,
        startup_abandoned: bool,
        allow_empty: bool,
    ) -> None:
        revisions = self._key_store._load_all_under_mutex()
        initial = revisions.get(self._initial_revision_id)
        if initial is None:
            raise LedgerError(LedgerCode.KEY_NOT_FOUND, "initial key revision does not exist")
        try:
            snapshot = self._storage.read_flat_directory(
                _SEGMENT_ROOT / self._epoch_id,
                maximum_entries=_MAX_SEGMENTS,
                maximum_file_bytes=_MAX_SEGMENT_BYTES,
                maximum_total_bytes=_MAX_LEDGER_BYTES,
            )
        except HandleWriterError as exc:
            raise LedgerError(LedgerCode.STORAGE_FAILURE, "segment store cannot be read") from exc
        files: list[tuple[int, str, bytes]] = []
        for entry in snapshot.entries:
            match = _SEGMENT_FILE.fullmatch(entry.name)
            if match is None:
                raise LedgerError(LedgerCode.UNKNOWN_ENTRY, "segment store contains an unknown or pending entry")
            files.append((int(match.group("sequence")), entry.name, entry.payload))
        files.sort(key=lambda item: item[0])
        segments: list[_ParsedSegment] = []
        batches: dict[str, SegmentReceipt] = {}
        record_ids: set[str] = set()
        current = initial
        previous: str | None = None
        for expected_sequence, (_numeric, name, payload) in enumerate(files):
            segment = _parse_segment(
                name=name,
                payload=payload,
                epoch_id=self._epoch_id,
                expected_sequence=expected_sequence,
                expected_previous=previous,
                current_revision=current,
                revisions=revisions,
            )
            if segment.batch_id in batches:
                raise LedgerError(LedgerCode.BATCH_CONFLICT, "ledger chain repeats a batch ID")
            if any(record_id in record_ids for record_id in segment.record_ids):
                raise LedgerError(LedgerCode.RECORD_CONFLICT, "ledger chain repeats a record ID")
            receipt = SegmentReceipt(
                epoch_id=self._epoch_id,
                sequence=segment.sequence,
                segment_sha256=segment.segment_sha256,
                batch_sha256=segment.batch_sha256,
                record_ids=segment.record_ids,
                replayed=False,
            )
            batches[segment.batch_id] = receipt
            record_ids.update(segment.record_ids)
            segments.append(segment)
            previous = segment.segment_sha256
            if segment.transition_to is not None:
                current = segment.transition_to
        if not segments and not allow_empty:
            raise LedgerError(
                LedgerCode.CHAIN_CORRUPT,
                "initialized ledger is missing its immutable genesis",
            )
        if segments and (
            segments[0].kind is not SegmentKind.GENESIS
            or any(segment.kind is SegmentKind.GENESIS for segment in segments[1:])
        ):
            raise LedgerError(
                LedgerCode.CHAIN_CORRUPT,
                "ledger genesis placement is invalid",
            )
        self._revisions = revisions
        self._segments = tuple(segments)
        self._batches = batches
        self._record_ids = record_ids
        self._total_segment_bytes = sum(len(entry.payload) for entry in snapshot.entries)
        self._head = LedgerHead(
            epoch_id=self._epoch_id,
            last_sequence=len(segments) - 1,
            last_segment_sha256=previous,
            active_revision_sequence=current.revision_sequence,
            active_revision_id=current.revision_id,
            segment_count=len(segments),
            startup_observed_abandoned_mutex=startup_abandoned,
        )

    def _active_revision(self) -> AuditKeyRevision:
        head = self._required_head()
        revision = self._revisions.get(head.active_revision_id)
        if revision is None:
            raise LedgerError(LedgerCode.KEY_NOT_FOUND, "active key revision is missing")
        return revision

    def _required_head(self) -> LedgerHead:
        if self._head is None:
            raise LedgerError(LedgerCode.LEDGER_SEALED, "ledger head is unavailable")
        return self._head

    def _seal(self, code: LedgerCode) -> None:
        if self._sealed_code is None:
            self._sealed_code = code
        self._storage.seal_after_indeterminate_mutation()

    def _require_open(self) -> None:
        if self._sealed_code is not None:
            raise LedgerError(LedgerCode.LEDGER_SEALED, "ledger is sealed after an unsafe or indeterminate state")


class DurableAuditSink:
    def __init__(
        self,
        ledger: DurableAuditLedger,
        *,
        _constructor: object | None = None,
    ) -> None:
        if (
            _constructor is not _LEDGER_CONSTRUCTOR
            or type(ledger) is not DurableAuditLedger
        ):
            raise LedgerError(LedgerCode.INVALID_REQUEST, "durable audit sink requires an exact ledger")
        self._ledger = ledger
        self._events: deque[AuditEvent] = deque(maxlen=_MAX_DIAGNOSTIC_EVENTS)
        self._lock = threading.RLock()

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def record(self, event: AuditEvent) -> AuditReceipt:
        return self.record_batch((event,))

    def record_batch(self, events: tuple[AuditEvent, ...]) -> AuditReceipt:
        if type(events) is not tuple or not events or any(type(event) is not AuditEvent for event in events):
            raise LedgerError(LedgerCode.INVALID_REQUEST, "durable audit sink requires a non-empty exact event tuple")
        receipt_error: LedgerError | None = None
        expected: AuditReceipt | None = None
        try:
            expected = audit_receipt(events)
        except Exception:
            receipt_error = LedgerError(
                LedgerCode.INVALID_REQUEST,
                "durable audit receipt could not be computed safely",
            )
        if receipt_error is not None:
            _raise_ledger_error(receipt_error)
        if expected is None:
            raise AssertionError("durable audit receipt completed without a result")
        committed = self._ledger.append_audit_batch(events)
        self._accept_committed(events, expected, committed)
        return expected

    def record_factory(
        self,
        builder: Callable[[bytes], tuple[AuditEvent, ...]],
    ) -> AuditReceipt:
        events, committed = self._ledger.append_built_audit_batch(builder)
        receipt_error: LedgerError | None = None
        expected: AuditReceipt | None = None
        try:
            expected = audit_receipt(events)
        except Exception:
            self._ledger._seal(LedgerCode.STORAGE_FAILURE)
            receipt_error = LedgerError(
                LedgerCode.STORAGE_FAILURE,
                "committed durable audit receipt could not be recomputed safely",
            )
        if receipt_error is not None:
            _raise_ledger_error(receipt_error)
        if expected is None:
            raise AssertionError("committed durable audit receipt completed without a result")
        self._accept_committed(events, expected, committed)
        return expected

    def _accept_committed(
        self,
        events: tuple[AuditEvent, ...],
        expected: AuditReceipt,
        committed: SegmentReceipt,
    ) -> None:
        if committed.batch_sha256 != expected.batch_sha256 or committed.record_ids != expected.event_ids:
            self._ledger._seal(LedgerCode.STORAGE_FAILURE)
            raise LedgerError(LedgerCode.STORAGE_FAILURE, "durable audit receipt differs from the audit contract")
        with self._lock:
            if not committed.replayed:
                self._events.extend(events)
