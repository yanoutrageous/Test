from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import ntpath
import os
import re
import stat
import sys
import threading
import traceback
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PureWindowsPath
from types import CodeType, FunctionType
from typing import Any, Callable, NoReturn, ParamSpec, TypeVar

from app.project_root import PROJECT_ROOT as _VERIFIED_PROJECT_ROOT
from app.safety.context import ContextError, DataClassification, validate_safe_id
from app.workspace_guard import PathIntent


def _contract_project_root(_root: Path = _VERIFIED_PROJECT_ROOT) -> Path:
    return _root


CONTRACT_PROJECT_ROOT = _contract_project_root()
SYNTHETIC_REFERENCE_POLICY_ID = "SYNTHETIC-REFERENCE-EXISTING-READ-V1"
REGISTERED_EXTERNAL_POLICY_ID = "REGISTERED-EXTERNAL-EXISTING-READ-V1"
SYNTHETIC_REFERENCE_MAX_BYTES = 64 * 1024 * 1024
SYNTHETIC_REFERENCE_PAYLOAD_NAME = "payload.bin"

_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_SQLITE_HEADER = b"SQLite format 3\0"
_MARKER_MAX_BYTES = 64 * 1024
_READ_API_CONSTRUCTOR = object()
_POLICY_CONSTRUCTOR = object()
_LEASE_CONSTRUCTOR = object()
_REGISTERED_LEASE_CONSTRUCTOR = object()
_COPY_EXECUTION_PERMIT_CONSTRUCTOR = object()
_SHA256_HEX = frozenset("0123456789abcdef")
_LOGICAL_REFERENCE_ID = re.compile(r"REF-[A-Z0-9][A-Z0-9._-]{2,127}")
_P = ParamSpec("_P")
_T = TypeVar("_T")
_POLICY_DOCUMENT = {
    "authority": "SYNTHETIC_REFERENCE_EXISTING_READ",
    "default_stream_only": True,
    "fixed_layout": "<run>/external/REFERENCE/<single-file>",
    "maximum_bytes": SYNTHETIC_REFERENCE_MAX_BYTES,
    "mutation_authority": False,
    "policy_id": SYNTHETIC_REFERENCE_POLICY_ID,
    "schema_version": "1.0",
    "sqlite_generic_copy": "DENY",
}
SYNTHETIC_REFERENCE_POLICY_DIGEST = hashlib.sha256(
    json.dumps(
        _POLICY_DOCUMENT,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
).hexdigest()


class ExternalSourceCode(StrEnum):
    UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"
    INVALID_FACTORY = "INVALID_FACTORY"
    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_LABORATORY = "INVALID_LABORATORY"
    PATH_REJECTED = "PATH_REJECTED"
    HANDLE_OPEN_FAILED = "HANDLE_OPEN_FAILED"
    HANDLE_IDENTITY_MISMATCH = "HANDLE_IDENTITY_MISMATCH"
    HANDLE_CLOSE_FAILED = "HANDLE_CLOSE_FAILED"
    REPARSE_POINT = "REPARSE_POINT"
    TYPE_MISMATCH = "TYPE_MISMATCH"
    HARDLINK_REJECTED = "HARDLINK_REJECTED"
    ALTERNATE_STREAM_REJECTED = "ALTERNATE_STREAM_REJECTED"
    SQLITE_REJECTED = "SQLITE_REJECTED"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    SOURCE_CHANGED = "SOURCE_CHANGED"
    READ_FAILED = "READ_FAILED"
    CAPABILITY_ALREADY_USED = "CAPABILITY_ALREADY_USED"
    CAPABILITY_CROSS_THREAD = "CAPABILITY_CROSS_THREAD"
    INTERNAL_FAILURE = "INTERNAL_FAILURE"


class ExternalSourceError(PermissionError):
    """Path-free failure from the synthetic external-reference boundary."""

    def __init__(
        self,
        code: ExternalSourceCode,
        message: str,
        *,
        winerror: int | None = None,
    ) -> None:
        suffix = "" if winerror is None else f" (winerror={winerror})"
        super().__init__(f"{code.value}: {message}{suffix}")
        # ``OSError.__init__`` initializes its own Windows fields, so preserve
        # the typed boundary fields only after the base initializer returns.
        self.code = code
        self.message = message
        self.winerror = winerror

    def __repr__(self) -> str:
        return (
            "ExternalSourceError(code="
            f"'{self.code.value}', winerror={self.winerror!r}, source='<redacted>')"
        )

    def __reduce__(self) -> Any:
        del self
        raise TypeError("external-source errors cannot be serialized")


def _raise_path_free(error: ExternalSourceError) -> NoReturn:
    error.__traceback__ = None
    error.__context__ = None
    error.__cause__ = None
    error.__suppress_context__ = True
    try:
        raise error from None
    except ExternalSourceError as exposed:
        # ``from None`` suppresses display but does not guarantee that
        # ``__context__`` is empty when a caller is already handling an
        # exception.  Scrub the newly raised object and use bare re-raise so
        # Python does not attach the active exception a second time.
        exposed.__context__ = None
        exposed.__cause__ = None
        exposed.__suppress_context__ = True
        del error, exposed
        raise


@dataclass(frozen=True, slots=True)
class _ExternalBoundarySuccess:
    value: Any = field(repr=False)


@dataclass(frozen=True, slots=True)
class _ExternalBoundaryFailure:
    code: ExternalSourceCode
    message: str
    winerror: int | None


def _resolve_external_boundary(
    outcome: _ExternalBoundarySuccess | _ExternalBoundaryFailure,
) -> Any:
    if type(outcome) is _ExternalBoundarySuccess:
        value = outcome.value
        outcome = None  # type: ignore[assignment]
        del outcome
        return value
    if type(outcome) is _ExternalBoundaryFailure:
        code = outcome.code
        message = outcome.message
        winerror = outcome.winerror
        outcome = None  # type: ignore[assignment]
        del outcome
        _raise_path_free(ExternalSourceError(code, message, winerror=winerror))
    _raise_path_free(
        ExternalSourceError(
            ExternalSourceCode.INTERNAL_FAILURE,
            "external-source boundary failed safely",
        )
    )


_EXTERNAL_BOUNDARY_ALLOWED_QUALNAMES = (
    "SyntheticReferenceReadPolicy.matches_copy_scope",
    "SyntheticReferenceReadPolicy.open_reference",
    "SyntheticReferenceReadPolicy.close",
    "SyntheticReferenceReadPolicy.__enter__",
    "SyntheticReferenceReadPolicy.__exit__",
    "_SyntheticReferenceLease.read_once",
    "_SyntheticReferenceLease._checkpoint_unchanged",
    "_SyntheticReferenceLease.verify_unchanged",
    "_SyntheticReferenceLease.close",
    "_SyntheticReferenceLease.__enter__",
    "_SyntheticReferenceLease.__exit__",
    "_issue_copy_execution_permit",
    "_validate_copy_execution_permit",
    "_consume_copy_execution_permit",
    "_create_synthetic_reference_read_policy",
    "_RegisteredExternalReadLease.read_once",
    "_RegisteredExternalReadLease.verify_unchanged",
    "_RegisteredExternalReadLease.close",
    "_RegisteredExternalReadLease.__enter__",
    "_RegisteredExternalReadLease.__exit__",
    "open_registered_external_source",
)
_EXTERNAL_BOUNDARY_MAX = 21


def _external_boundary_template(*arguments: Any, **keywords: Any) -> Any:
    outcome = _dispatch_external_boundary(arguments, keywords)
    arguments = ()
    keywords = {}
    del arguments, keywords
    return _resolve_external_boundary(outcome)


def _create_external_boundary_runtime() -> tuple[
    Callable[[tuple[Any, ...], dict[str, Any]], _ExternalBoundarySuccess | _ExternalBoundaryFailure],
    Callable[[FunctionType], FunctionType],
    Callable[[], None],
]:
    """Build the fixed code-keyed vault before sealing the module surfaces."""

    if len(_EXTERNAL_BOUNDARY_ALLOWED_QUALNAMES) != _EXTERNAL_BOUNDARY_MAX:
        raise RuntimeError("external boundary allowlist size is invalid")
    allowed = frozenset(_EXTERNAL_BOUNDARY_ALLOWED_QUALNAMES)
    if len(allowed) != _EXTERNAL_BOUNDARY_MAX:
        raise RuntimeError("external boundary allowlist contains duplicates")
    vault: dict[CodeType, FunctionType] = {}
    registered: set[str] = set()
    sealed = False
    expected_module = __name__
    template_code = _external_boundary_template.__code__
    template_globals = globals()

    def dispatch(
        arguments: tuple[Any, ...],
        keywords: dict[str, Any],
    ) -> _ExternalBoundarySuccess | _ExternalBoundaryFailure:
        try:
            caller_code = sys._getframe(1).f_code
        except BaseException:
            return _ExternalBoundaryFailure(
                ExternalSourceCode.INTERNAL_FAILURE,
                "external-source boundary failed safely",
                None,
            )
        if (
            not sealed
            or type(arguments) is not tuple
            or type(keywords) is not dict
            or "__path_free_capture" in keywords
        ):
            return _ExternalBoundaryFailure(
                ExternalSourceCode.INTERNAL_FAILURE,
                "external-source boundary failed safely",
                None,
            )

        function: FunctionType | None = None
        registered_code: CodeType | None = None
        registered_function: FunctionType | None = None
        for registered_code, registered_function in vault.items():
            if caller_code is registered_code:
                function = registered_function
                break
        if type(function) is not FunctionType:
            return _ExternalBoundaryFailure(
                ExternalSourceCode.INTERNAL_FAILURE,
                "external-source boundary failed safely",
                None,
            )
        try:
            return _ExternalBoundarySuccess(function(*arguments, **keywords))
        except BaseException as caught:
            if (
                type(caught) is ExternalSourceError
                and type(caught.code) is ExternalSourceCode
                and type(caught.message) is str
                and (caught.winerror is None or type(caught.winerror) is int)
            ):
                failure_code = caught.code
                failure_message = caught.message
                failure_winerror = caught.winerror
            else:
                failure_code = ExternalSourceCode.INTERNAL_FAILURE
                failure_message = "external-source boundary failed safely"
                failure_winerror = None
            caught_traceback = caught.__traceback__
            if caught_traceback is not None:
                traceback.clear_frames(caught_traceback)
            caught.__traceback__ = None
            caught.__context__ = None
            caught.__cause__ = None
            caught.__suppress_context__ = True
            result = _ExternalBoundaryFailure(
                failure_code,
                failure_message,
                failure_winerror,
            )
            arguments = ()
            keywords = {}
            caller_code = None
            function = None
            registered_code = None
            registered_function = None
            del (
                arguments,
                keywords,
                caller_code,
                function,
                registered_code,
                registered_function,
                caught_traceback,
                caught,
            )
            return result

    def register(function: FunctionType) -> FunctionType:
        if (
            sealed
            or type(function) is not FunctionType
            or function.__module__ != expected_module
            or function.__qualname__ not in allowed
            or function.__qualname__ in registered
            or len(vault) >= _EXTERNAL_BOUNDARY_MAX
        ):
            raise RuntimeError("external boundary registration is not allowed")
        index = _EXTERNAL_BOUNDARY_ALLOWED_QUALNAMES.index(function.__qualname__)
        boundary_code = template_code.replace(
            co_name=f"_external_path_free_boundary_{index:02d}",
            co_qualname=f"_external_path_free_boundary_{index:02d}",
        )
        if any(boundary_code is existing for existing in vault):
            raise RuntimeError("external boundary code identity was reused")
        boundary = FunctionType(
            boundary_code,
            template_globals,
            function.__name__,
        )
        boundary.__qualname__ = function.__qualname__
        boundary.__module__ = function.__module__
        boundary.__doc__ = function.__doc__
        boundary.__annotations__ = dict(function.__annotations__)
        vault[boundary_code] = function
        registered.add(function.__qualname__)
        return boundary

    def seal() -> None:
        nonlocal sealed
        if (
            sealed
            or len(vault) != _EXTERNAL_BOUNDARY_MAX
            or registered != allowed
            or len({id(code) for code in vault}) != _EXTERNAL_BOUNDARY_MAX
        ):
            raise RuntimeError("external boundary vault cannot be sealed")
        sealed = True

    return dispatch, register, seal


(
    _dispatch_external_boundary,
    _register_external_boundary,
    _seal_external_boundaries,
) = _create_external_boundary_runtime()


def _path_free_exception_boundary(
    function: Callable[_P, _T],
) -> Callable[_P, _T]:
    """Register one allowlisted surface during module initialization only."""

    if type(function) is not FunctionType:
        raise RuntimeError("external boundary requires an exact function")
    return _register_external_boundary(function)  # type: ignore[return-value]


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _SHA256_HEX for character in value)
    )


@dataclass(frozen=True, slots=True)
class SyntheticSourceEvidence:
    policy_digest: str
    classification: DataClassification
    locator_hmac: str = field(repr=False)
    capability_binding_digest: str = field(repr=False)
    source_identity_digest: str = field(repr=False)
    size_bytes: int
    sha256: str
    stability_digest: str = field(repr=False)
    source_reference: str = field(repr=False)
    schema_version: str = field(default="1.0", init=False)
    policy_id: str = field(default=SYNTHETIC_REFERENCE_POLICY_ID, init=False)
    destination_name: str = field(
        default=SYNTHETIC_REFERENCE_PAYLOAD_NAME,
        init=False,
    )
    capability_state: str = field(
        default="SYNTHETIC_EXTERNAL_SOURCE_HANDLE_VERIFIED",
        init=False,
    )

    def __post_init__(self) -> None:
        digests = (
            self.policy_digest,
            self.locator_hmac,
            self.capability_binding_digest,
            self.source_identity_digest,
            self.sha256,
            self.stability_digest,
            self.source_reference,
        )
        if (
            any(not _is_sha256(value) for value in digests)
            or type(self.classification) is not DataClassification
            or type(self.size_bytes) is not int
            or not 0 <= self.size_bytes <= SYNTHETIC_REFERENCE_MAX_BYTES
            or self.policy_digest != SYNTHETIC_REFERENCE_POLICY_DIGEST
        ):
            raise TypeError("synthetic source evidence has an invalid typed shape")

    def to_source_record_fields(self) -> dict[str, Any]:
        """Return the path-free shape accepted by the future source ledger."""

        return {
            "capability_binding_digest": self.capability_binding_digest,
            "classification": self.classification.value,
            "destination_name": self.destination_name,
            "locator": {"digest": self.locator_hmac, "mode": "HMAC_ONLY"},
            "policy_digest": self.policy_digest,
            "policy_id": self.policy_id,
            "schema_version": self.schema_version,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "source_identity_digest": self.source_identity_digest,
            "source_reference": self.source_reference,
            "stability_digest": self.stability_digest,
        }

    def __repr__(self) -> str:
        return (
            "SyntheticSourceEvidence(classification="
            f"'{self.classification.value}', size_bytes={self.size_bytes}, "
            "sha256='<redacted>', locators='<redacted>')"
        )

    def __reduce__(self) -> Any:
        del self
        raise TypeError("synthetic source evidence cannot be serialized")


@dataclass(frozen=True, slots=True)
class SyntheticSourceMaterial:
    evidence: SyntheticSourceEvidence
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.evidence) is not SyntheticSourceEvidence
            or type(self.payload) is not bytes
            or len(self.payload) != self.evidence.size_bytes
            or hashlib.sha256(self.payload).hexdigest() != self.evidence.sha256
        ):
            raise TypeError("synthetic source material does not match its evidence")

    def __repr__(self) -> str:
        return (
            "SyntheticSourceMaterial(payload='<redacted>', size_bytes="
            f"{self.evidence.size_bytes}, evidence='<handle-verified>')"
        )

    def __reduce__(self) -> Any:
        del self
        raise TypeError("synthetic source material cannot be serialized")


@dataclass(frozen=True, slots=True)
class SyntheticSourceVerification:
    evidence: SyntheticSourceEvidence
    verification_digest: str = field(repr=False)
    capability_state: str = field(
        default="SYNTHETIC_EXTERNAL_SOURCE_FINAL_REVERIFIED",
        init=False,
    )

    def __post_init__(self) -> None:
        if (
            type(self.evidence) is not SyntheticSourceEvidence
            or not _is_sha256(self.verification_digest)
        ):
            raise TypeError("synthetic source verification has an invalid typed shape")

    def __repr__(self) -> str:
        return (
            "SyntheticSourceVerification(evidence='<redacted>', "
            "verification_digest='<redacted>')"
        )

    def __reduce__(self) -> Any:
        del self
        raise TypeError("synthetic source verifications cannot be serialized")


@dataclass(frozen=True, slots=True)
class RegisteredSourceEvidence:
    logical_id: str
    classification: DataClassification
    source_object_reference: str = field(repr=False)
    source_identity_digest: str = field(repr=False)
    size_bytes: int
    sha256: str
    schema_version: str = field(default="1.0", init=False)
    policy_id: str = field(default=REGISTERED_EXTERNAL_POLICY_ID, init=False)
    destination_name: str = field(
        default=SYNTHETIC_REFERENCE_PAYLOAD_NAME,
        init=False,
    )
    default_stream_only: bool = field(default=True, init=False)

    def __post_init__(self) -> None:
        if (
            type(self.logical_id) is not str
            or _LOGICAL_REFERENCE_ID.fullmatch(self.logical_id) is None
            or type(self.classification) is not DataClassification
            or not _is_sha256(self.source_object_reference)
            or not _is_sha256(self.source_identity_digest)
            or type(self.size_bytes) is not int
            or not 0 <= self.size_bytes <= SYNTHETIC_REFERENCE_MAX_BYTES
            or not _is_sha256(self.sha256)
        ):
            raise TypeError("registered source evidence has an invalid typed shape")

    def to_provenance_fields(self) -> dict[str, Any]:
        return {
            "classification": self.classification.value,
            "default_stream_only": self.default_stream_only,
            "destination_name": self.destination_name,
            "logical_id": self.logical_id,
            "policy_id": self.policy_id,
            "schema_version": self.schema_version,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "source_identity_digest": self.source_identity_digest,
            "source_object_reference": self.source_object_reference,
        }

    def __repr__(self) -> str:
        return (
            "RegisteredSourceEvidence(logical_id="
            f"'{self.logical_id}', classification='{self.classification.value}', "
            f"size_bytes={self.size_bytes}, source='<redacted>')"
        )

    def __reduce__(self) -> Any:
        del self
        raise TypeError("registered source evidence cannot be serialized")


@dataclass(frozen=True, slots=True)
class RegisteredSourceMaterial:
    evidence: RegisteredSourceEvidence
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.evidence) is not RegisteredSourceEvidence
            or type(self.payload) is not bytes
            or len(self.payload) != self.evidence.size_bytes
            or hashlib.sha256(self.payload).hexdigest() != self.evidence.sha256
        ):
            raise TypeError("registered source material differs from its evidence")

    def __repr__(self) -> str:
        return (
            "RegisteredSourceMaterial(payload='<redacted>', size_bytes="
            f"{self.evidence.size_bytes}, evidence='<handle-verified>')"
        )

    def __reduce__(self) -> Any:
        del self
        raise TypeError("registered source material cannot be serialized")


@dataclass(frozen=True, slots=True)
class RegisteredSourceVerification:
    evidence: RegisteredSourceEvidence
    verification_digest: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.evidence) is not RegisteredSourceEvidence
            or not _is_sha256(self.verification_digest)
        ):
            raise TypeError(
                "registered source verification has an invalid typed shape"
            )

    def __repr__(self) -> str:
        return (
            "RegisteredSourceVerification(evidence='<redacted>', "
            "verification_digest='<redacted>')"
        )

    def __reduce__(self) -> Any:
        del self
        raise TypeError("registered source verifications cannot be serialized")


@dataclass(frozen=True, slots=True)
class _ObservedReference:
    volume_serial: int
    file_id: bytes
    file_attributes: int
    reparse_tag: int
    link_count: int
    is_directory: bool
    end_of_file: int
    last_write_time: int
    change_time: int


@dataclass(frozen=True, slots=True)
class _ExpectedIdentity:
    device: int
    inode: int
    mode: int
    file_attributes: int
    reparse_tag: int
    link_count: int


class _FileId128(ctypes.Structure):
    _fields_ = [("identifier", ctypes.c_ubyte * 16)]


class _FileIdInfo(ctypes.Structure):
    _fields_ = [("volume_serial", ctypes.c_ulonglong), ("file_id", _FileId128)]


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = [("file_attributes", ctypes.c_ulong), ("reparse_tag", ctypes.c_ulong)]


class _FileBasicInfo(ctypes.Structure):
    _fields_ = [
        ("creation_time", ctypes.c_longlong),
        ("last_access_time", ctypes.c_longlong),
        ("last_write_time", ctypes.c_longlong),
        ("change_time", ctypes.c_longlong),
        ("file_attributes", ctypes.c_ulong),
    ]


class _FileStandardInfo(ctypes.Structure):
    _fields_ = [
        ("allocation_size", ctypes.c_longlong),
        ("end_of_file", ctypes.c_longlong),
        ("number_of_links", ctypes.c_ulong),
        ("delete_pending", ctypes.c_ubyte),
        ("directory", ctypes.c_ubyte),
    ]


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("file_attributes", ctypes.c_ulong),
        ("creation_time_low", ctypes.c_ulong),
        ("creation_time_high", ctypes.c_ulong),
        ("last_access_time_low", ctypes.c_ulong),
        ("last_access_time_high", ctypes.c_ulong),
        ("last_write_time_low", ctypes.c_ulong),
        ("last_write_time_high", ctypes.c_ulong),
        ("volume_serial", ctypes.c_ulong),
        ("size_high", ctypes.c_ulong),
        ("size_low", ctypes.c_ulong),
        ("link_count", ctypes.c_ulong),
        ("file_index_high", ctypes.c_ulong),
        ("file_index_low", ctypes.c_ulong),
    ]


class _ReferenceReadApi:
    """Win32 bindings deliberately limited to open/read/inspect/seek/close."""

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    OPEN_EXISTING = 3
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_BEGIN = 0
    FILE_BASIC_INFO = 0
    FILE_STANDARD_INFO = 1
    FILE_STREAM_INFO = 7
    FILE_ATTRIBUTE_TAG_INFO = 9
    FILE_ID_INFO = 18
    FILE_NAME_NORMALIZED = 0
    VOLUME_NAME_DOS = 0
    _MAX_IO_CHUNK = 1024 * 1024

    __slots__ = (
        "_close_handle",
        "_create_file",
        "_get_file_information",
        "_get_file_information_ex",
        "_get_final_path",
        "_invalid_handle",
        "_read_file",
        "_set_file_pointer",
        "_wintypes",
    )

    def __init__(self, *, _constructor: object) -> None:
        if _constructor is not _READ_API_CONSTRUCTOR:
            raise TypeError("reference-read bindings require the fixed factory")
        if os.name != "nt":
            raise ExternalSourceError(
                ExternalSourceCode.UNSUPPORTED_PLATFORM,
                "synthetic reference reads require Windows",
            )
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        create_file.restype = wintypes.HANDLE
        information_ex = kernel32.GetFileInformationByHandleEx
        information_ex.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        information_ex.restype = wintypes.BOOL
        information = kernel32.GetFileInformationByHandle
        information.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_ByHandleFileInformation),
        ]
        information.restype = wintypes.BOOL
        final_path = kernel32.GetFinalPathNameByHandleW
        final_path.argtypes = [
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        final_path.restype = wintypes.DWORD
        read_file = kernel32.ReadFile
        read_file.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        read_file.restype = wintypes.BOOL
        set_pointer = kernel32.SetFilePointerEx
        set_pointer.argtypes = [
            wintypes.HANDLE,
            ctypes.c_longlong,
            ctypes.POINTER(ctypes.c_longlong),
            wintypes.DWORD,
        ]
        set_pointer.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL

        self._create_file = create_file
        self._get_file_information_ex = information_ex
        self._get_file_information = information
        self._get_final_path = final_path
        self._read_file = read_file
        self._set_file_pointer = set_pointer
        self._close_handle = close_handle
        self._wintypes = wintypes
        self._invalid_handle = ctypes.c_void_p(-1).value

    def open_existing(self, path: Path, *, directory: bool) -> int:
        flags = self.FILE_FLAG_OPEN_REPARSE_POINT
        if directory:
            flags |= self.FILE_FLAG_BACKUP_SEMANTICS
        handle = self._create_file(
            str(path),
            self.GENERIC_READ,
            self.FILE_SHARE_READ,
            None,
            self.OPEN_EXISTING,
            flags,
            None,
        )
        raw = ctypes.c_void_p(handle).value
        if raw in {None, 0, self._invalid_handle}:
            raise ExternalSourceError(
                ExternalSourceCode.HANDLE_OPEN_FAILED,
                "Windows refused a read-only no-follow handle",
                winerror=ctypes.get_last_error(),
            )
        return int(raw)

    def close(self, handle: int) -> None:
        if not self._close_handle(handle):
            raise ExternalSourceError(
                ExternalSourceCode.HANDLE_CLOSE_FAILED,
                "Windows refused to close an internal read handle",
                winerror=ctypes.get_last_error(),
            )

    def observe(self, handle: int) -> _ObservedReference:
        file_id = _FileIdInfo()
        tag = _FileAttributeTagInfo()
        basic = _FileBasicInfo()
        standard = _FileStandardInfo()
        legacy = _ByHandleFileInformation()
        queries = (
            (self.FILE_ID_INFO, file_id),
            (self.FILE_ATTRIBUTE_TAG_INFO, tag),
            (self.FILE_BASIC_INFO, basic),
            (self.FILE_STANDARD_INFO, standard),
        )
        for information_class, target in queries:
            if not self._get_file_information_ex(
                handle,
                information_class,
                ctypes.byref(target),
                ctypes.sizeof(target),
            ):
                raise ExternalSourceError(
                    ExternalSourceCode.HANDLE_IDENTITY_MISMATCH,
                    "Windows could not observe the read handle",
                    winerror=ctypes.get_last_error(),
                )
        if not self._get_file_information(handle, ctypes.byref(legacy)):
            raise ExternalSourceError(
                ExternalSourceCode.HANDLE_IDENTITY_MISMATCH,
                "Windows identity APIs did not complete",
                winerror=ctypes.get_last_error(),
            )
        file_id_bytes = bytes(file_id.file_id.identifier)
        legacy_id = (int(legacy.file_index_high) << 32) | int(legacy.file_index_low)
        if (
            int(file_id.volume_serial) & 0xFFFFFFFF != int(legacy.volume_serial)
            or int.from_bytes(file_id_bytes[:8], "little") != legacy_id
            or any(file_id_bytes[8:])
            or int(tag.file_attributes) != int(basic.file_attributes)
            or int(standard.number_of_links) != int(legacy.link_count)
        ):
            raise ExternalSourceError(
                ExternalSourceCode.HANDLE_IDENTITY_MISMATCH,
                "Windows identity APIs returned contradictory evidence",
            )
        attributes = int(tag.file_attributes)
        reparse_tag = int(tag.reparse_tag)
        if attributes & _REPARSE_ATTRIBUTE or reparse_tag:
            raise ExternalSourceError(
                ExternalSourceCode.REPARSE_POINT,
                "reparse objects are forbidden at the external-source boundary",
            )
        if bool(standard.delete_pending):
            raise ExternalSourceError(
                ExternalSourceCode.HANDLE_IDENTITY_MISMATCH,
                "delete-pending source objects are forbidden",
            )
        is_directory = bool(standard.directory)
        if is_directory != bool(attributes & self.FILE_ATTRIBUTE_DIRECTORY):
            raise ExternalSourceError(
                ExternalSourceCode.HANDLE_IDENTITY_MISMATCH,
                "Windows type APIs returned contradictory evidence",
            )
        observed = _ObservedReference(
            volume_serial=int(file_id.volume_serial),
            file_id=file_id_bytes,
            file_attributes=attributes,
            reparse_tag=reparse_tag,
            link_count=int(standard.number_of_links),
            is_directory=is_directory,
            end_of_file=int(standard.end_of_file),
            last_write_time=int(basic.last_write_time),
            change_time=int(basic.change_time),
        )
        if not is_directory:
            self.require_default_stream(handle)
        return observed

    def require_default_stream(self, handle: int) -> None:
        buffer_size = 64 * 1024
        buffer = ctypes.create_string_buffer(buffer_size)
        if not self._get_file_information_ex(
            handle,
            self.FILE_STREAM_INFO,
            buffer,
            buffer_size,
        ):
            raise ExternalSourceError(
                ExternalSourceCode.ALTERNATE_STREAM_REJECTED,
                "the source data-stream set could not be proven default-only",
                winerror=ctypes.get_last_error(),
            )
        names: list[str] = []
        offset = 0
        while True:
            if offset + 24 > buffer_size:
                raise ExternalSourceError(
                    ExternalSourceCode.ALTERNATE_STREAM_REJECTED,
                    "the source data-stream metadata was malformed",
                )
            next_offset = int.from_bytes(buffer.raw[offset : offset + 4], "little")
            name_bytes = int.from_bytes(buffer.raw[offset + 4 : offset + 8], "little")
            name_start = offset + 24
            name_end = name_start + name_bytes
            if name_bytes % 2 or name_end > buffer_size:
                raise ExternalSourceError(
                    ExternalSourceCode.ALTERNATE_STREAM_REJECTED,
                    "the source data-stream metadata was malformed",
                )
            try:
                names.append(buffer.raw[name_start:name_end].decode("utf-16-le", "strict"))
            except UnicodeDecodeError:
                raise ExternalSourceError(
                    ExternalSourceCode.ALTERNATE_STREAM_REJECTED,
                    "the source data-stream metadata was not Unicode",
                ) from None
            if next_offset == 0:
                break
            if next_offset < 24 + name_bytes or offset + next_offset >= buffer_size:
                raise ExternalSourceError(
                    ExternalSourceCode.ALTERNATE_STREAM_REJECTED,
                    "the source data-stream metadata was malformed",
                )
            offset += next_offset
        if names != ["::$DATA"]:
            raise ExternalSourceError(
                ExternalSourceCode.ALTERNATE_STREAM_REJECTED,
                "alternate data streams are forbidden",
            )

    def final_path(self, handle: int) -> Path:
        buffer_size = 32768
        buffer = ctypes.create_unicode_buffer(buffer_size)
        returned = int(
            self._get_final_path(
                handle,
                buffer,
                buffer_size,
                self.FILE_NAME_NORMALIZED | self.VOLUME_NAME_DOS,
            )
        )
        if returned == 0 or returned >= buffer_size:
            raise ExternalSourceError(
                ExternalSourceCode.HANDLE_IDENTITY_MISMATCH,
                "Windows could not bind the handle to its final name",
                winerror=ctypes.get_last_error() if returned == 0 else None,
            )
        value = buffer.value
        if value.startswith("\\\\?\\UNC\\"):
            value = "\\\\" + value[8:]
        elif value.startswith("\\\\?\\"):
            value = value[4:]
        return Path(ntpath.normpath(value))

    def seek_start(self, handle: int) -> None:
        position = ctypes.c_longlong(0)
        if not self._set_file_pointer(
            handle,
            0,
            ctypes.byref(position),
            self.FILE_BEGIN,
        ) or int(position.value) != 0:
            raise ExternalSourceError(
                ExternalSourceCode.READ_FAILED,
                "Windows refused to reset the verified source handle",
                winerror=ctypes.get_last_error(),
            )

    def _read_chunk(self, handle: int, count: int) -> bytes:
        buffer = ctypes.create_string_buffer(count)
        returned = self._wintypes.DWORD(0)
        if not self._read_file(handle, buffer, count, ctypes.byref(returned), None):
            raise ExternalSourceError(
                ExternalSourceCode.READ_FAILED,
                "Windows refused a verified source-handle read",
                winerror=ctypes.get_last_error(),
            )
        return buffer.raw[: int(returned.value)]

    def read_prefix(self, handle: int, count: int) -> bytes:
        self.seek_start(handle)
        chunks: list[bytes] = []
        total = 0
        while total < count:
            chunk = self._read_chunk(handle, count - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    def read_bounded(self, handle: int, maximum_bytes: int) -> tuple[bytes, str]:
        self.seek_start(handle)
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        total = 0
        while True:
            request = min(self._MAX_IO_CHUNK, maximum_bytes + 1 - total)
            if request <= 0:
                raise ExternalSourceError(
                    ExternalSourceCode.RESOURCE_LIMIT,
                    "synthetic source exceeds the fixed 64 MiB limit",
                )
            chunk = self._read_chunk(handle, request)
            if not chunk:
                return b"".join(chunks), digest.hexdigest()
            total += len(chunk)
            if total > maximum_bytes:
                raise ExternalSourceError(
                    ExternalSourceCode.RESOURCE_LIMIT,
                    "synthetic source exceeds the fixed 64 MiB limit",
                )
            chunks.append(chunk)
            digest.update(chunk)


def _absolute_lexical(path: str | os.PathLike[str]) -> Path:
    return Path(ntpath.normpath(ntpath.abspath(os.fspath(path))))


def _same_path(left: Path, right: Path) -> bool:
    return ntpath.normcase(ntpath.normpath(str(left))) == ntpath.normcase(
        ntpath.normpath(str(right))
    )


def _relative_parts(candidate: Path, root: Path) -> tuple[str, ...] | None:
    candidate_parts = PureWindowsPath(str(candidate)).parts
    root_parts = PureWindowsPath(str(root)).parts
    if len(candidate_parts) < len(root_parts):
        return None
    if any(
        ntpath.normcase(actual) != ntpath.normcase(expected)
        for actual, expected in zip(candidate_parts, root_parts, strict=False)
    ):
        return None
    return tuple(candidate_parts[len(root_parts) :])


def _expected_identity(path: Path) -> _ExpectedIdentity:
    try:
        identity = os.lstat(path)
    except OSError:
        raise ExternalSourceError(
            ExternalSourceCode.PATH_REJECTED,
            "a required external-source object is absent or unreadable",
        ) from None
    return _ExpectedIdentity(
        device=int(identity.st_dev),
        inode=int(identity.st_ino),
        mode=int(identity.st_mode),
        file_attributes=int(getattr(identity, "st_file_attributes", 0)),
        reparse_tag=int(getattr(identity, "st_reparse_tag", 0)),
        link_count=int(identity.st_nlink),
    )


def _verify_expected(expected: _ExpectedIdentity, observed: _ObservedReference) -> None:
    expected_directory = stat.S_ISDIR(expected.mode)
    expected_regular = stat.S_ISREG(expected.mode)
    if (
        expected.device != observed.volume_serial
        or expected.inode != int.from_bytes(observed.file_id, "little")
        or expected.link_count != observed.link_count
        or expected_directory != observed.is_directory
        or (not expected_directory and not expected_regular)
        or expected.file_attributes & _REPARSE_ATTRIBUTE
        or expected.reparse_tag
    ):
        raise ExternalSourceError(
            ExternalSourceCode.HANDLE_IDENTITY_MISMATCH,
            "the no-follow handle differs from the inspected object",
        )


def _verify_path_binding(path: Path, observed: _ObservedReference) -> None:
    current = _expected_identity(path)
    _verify_expected(current, observed)


def _same_snapshot(left: _ObservedReference, right: _ObservedReference) -> bool:
    return left == right


def _open_verified(
    api: _ReferenceReadApi,
    path: Path,
    *,
    directory: bool,
    exact_name: str | None = None,
) -> tuple[int, _ObservedReference, str]:
    expected = _expected_identity(path)
    if expected.file_attributes & _REPARSE_ATTRIBUTE or expected.reparse_tag:
        raise ExternalSourceError(
            ExternalSourceCode.REPARSE_POINT,
            "reparse objects are forbidden at the external-source boundary",
        )
    if bool(stat.S_ISDIR(expected.mode)) != directory:
        raise ExternalSourceError(
            ExternalSourceCode.TYPE_MISMATCH,
            "a fixed external-source object has the wrong type",
        )
    handle: int | None = None
    try:
        handle = api.open_existing(path, directory=directory)
        observed = api.observe(handle)
        _verify_expected(expected, observed)
        actual = api.final_path(handle)
        if not _same_path(actual, path):
            raise ExternalSourceError(
                ExternalSourceCode.HANDLE_IDENTITY_MISMATCH,
                "the no-follow handle resolved to a different final object",
            )
        if exact_name is not None and actual.name != exact_name:
            raise ExternalSourceError(
                ExternalSourceCode.PATH_REJECTED,
                "a fixed external-source name differs in exact spelling",
            )
        _verify_path_binding(path, observed)
        return handle, observed, actual.name
    except BaseException:
        if handle is not None:
            try:
                api.close(handle)
            except ExternalSourceError as close_error:
                _raise_path_free(close_error)
        raise


def _close_handles(api: _ReferenceReadApi, handles: list[int]) -> None:
    first_error: ExternalSourceError | None = None
    while handles:
        handle = handles.pop()
        try:
            api.close(handle)
        except ExternalSourceError as error:
            if first_error is None:
                first_error = error
    if first_error is not None:
        _raise_path_free(first_error)


def _validated_source_name(value: str) -> str:
    if type(value) is not str or not value or value in {".", ".."}:
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_REQUEST,
            "source name must be one canonical file-name component",
        )
    if unicodedata.normalize("NFC", value) != value:
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_REQUEST,
            "source name must already be NFC normalized",
        )
    try:
        utf8 = value.encode("utf-8", "strict")
        utf16_units = len(value.encode("utf-16-le", "strict")) // 2
    except UnicodeError:
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_REQUEST,
            "source name is not valid Unicode",
        ) from None
    if (
        any(character in '\\/:*?"<>|' or ord(character) < 32 for character in value)
        or value.endswith((".", " "))
        or len(utf8) > 512
        or utf16_units > 255
    ):
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_REQUEST,
            "source name contains forbidden or overlong syntax",
        )
    stem = value.partition(".")[0].casefold()
    if stem in {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{number}" for number in range(1, 10)),
        *(f"lpt{number}" for number in range(1, 10)),
    }:
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_REQUEST,
            "source name is a reserved Windows device name",
        )
    return value


def _is_sqlite_name(name: str) -> bool:
    folded = name.casefold()
    return folded.endswith(
        (
            ".db",
            ".db3",
            ".sqlite",
            ".sqlite3",
            "-wal",
            "-shm",
            "-journal",
            ".wal",
            ".shm",
            ".journal",
        )
    )


def _observation_bytes(observed: _ObservedReference) -> bytes:
    return json.dumps(
        {
            "change_time": observed.change_time,
            "end_of_file": observed.end_of_file,
            "file_attributes": observed.file_attributes,
            "file_id": observed.file_id.hex(),
            "is_directory": observed.is_directory,
            "last_write_time": observed.last_write_time,
            "link_count": observed.link_count,
            "reparse_tag": observed.reparse_tag,
            "volume_serial": observed.volume_serial,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _keyed_digest(key: bytes, domain: bytes, *parts: bytes) -> str:
    digest = hmac.new(key, domain + b"\0", hashlib.sha256)
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.hexdigest()


class SyntheticReferenceReadPolicy:
    """One-shot Test-local authority with no mutation interface."""

    __slots__ = (
        "_api",
        "_classification",
        "_copy_id",
        "_handles",
        "_issued_lease",
        "_locator_key",
        "_marker_digest",
        "_owner_thread",
        "_owner_thread_object",
        "_reference_root",
        "_run_id",
        "_state",
    )

    def __init__(
        self,
        *,
        api: _ReferenceReadApi,
        handles: list[int],
        reference_root: Path,
        run_id: str,
        copy_id: str,
        classification: DataClassification,
        locator_key: bytes,
        marker_digest: str,
        _constructor: object,
    ) -> None:
        if (
            _constructor is not _POLICY_CONSTRUCTOR
            or type(api) is not _ReferenceReadApi
            or type(classification) is not DataClassification
            or len(locator_key) != 32
            or not handles
        ):
            raise TypeError("synthetic reference policies require the fixed factory")
        self._api = api
        self._handles = handles
        self._issued_lease: _SyntheticReferenceLease | None = None
        self._reference_root: Path | None = reference_root
        self._run_id = run_id
        self._copy_id = copy_id
        self._classification = classification
        self._locator_key = locator_key
        self._marker_digest = marker_digest
        self._owner_thread = threading.get_ident()
        self._owner_thread_object = threading.current_thread()
        if self._owner_thread_object.ident != self._owner_thread:
            raise ExternalSourceError(
                ExternalSourceCode.CAPABILITY_CROSS_THREAD,
                "synthetic reference authority thread identity is unstable",
            )
        self._state = "ISSUED"

    @property
    def classification(self) -> DataClassification:
        return self._classification

    @property
    def intent(self) -> PathIntent:
        return PathIntent.EXISTING_READ

    @property
    def policy_digest(self) -> str:
        return SYNTHETIC_REFERENCE_POLICY_DIGEST

    @_path_free_exception_boundary
    def matches_copy_scope(
        self,
        copy_id: str,
        classification: DataClassification,
    ) -> bool:
        """Confirm scope equality without exposing the bound business identifier."""

        self._assert_owner("ISSUED")
        if type(classification) is not DataClassification:
            return False
        try:
            canonical = validate_safe_id(copy_id, field_name="copy_id")
        except ContextError:
            return False
        return (
            classification is self._classification
            and hmac.compare_digest(canonical, self._copy_id)
        )

    @_path_free_exception_boundary
    def open_reference(self, source_name: str) -> _SyntheticReferenceLease:
        self._assert_owner("ISSUED")
        source_handle: int | None = None
        try:
            canonical_name = _validated_source_name(source_name)
            reference_root = self._reference_root
            if reference_root is None:
                raise ExternalSourceError(
                    ExternalSourceCode.CAPABILITY_ALREADY_USED,
                    "synthetic reference authority has already been consumed",
                )
            source_path = reference_root / canonical_name
            if not _same_path(source_path.parent, reference_root):
                raise ExternalSourceError(
                    ExternalSourceCode.PATH_REJECTED,
                    "source name escaped the fixed REFERENCE root",
                )
            source_handle, baseline, actual_name = _open_verified(
                self._api,
                source_path,
                directory=False,
            )
            # The no-follow handle and final-path identity are already verified.
            # Reject every SQLite spelling before applying the case-sensitive
            # leaf-name gate, while retaining exact spelling for eligible files.
            if _is_sqlite_name(canonical_name) or _is_sqlite_name(actual_name):
                raise ExternalSourceError(
                    ExternalSourceCode.SQLITE_REJECTED,
                    "SQLite databases and sidecars are excluded from generic Copy",
                )
            if actual_name != canonical_name:
                raise ExternalSourceError(
                    ExternalSourceCode.PATH_REJECTED,
                    "the opened external-source name differs in exact spelling",
                )
            if baseline.is_directory:
                raise ExternalSourceError(
                    ExternalSourceCode.TYPE_MISMATCH,
                    "synthetic source must be one regular file",
                )
            if baseline.link_count != 1:
                raise ExternalSourceError(
                    ExternalSourceCode.HARDLINK_REJECTED,
                    "synthetic source must have exactly one hard link",
                )
            if baseline.end_of_file > SYNTHETIC_REFERENCE_MAX_BYTES:
                raise ExternalSourceError(
                    ExternalSourceCode.RESOURCE_LIMIT,
                    "synthetic source exceeds the fixed 64 MiB limit",
                )
            prefix = self._api.read_prefix(source_handle, len(_SQLITE_HEADER))
            after_prefix = self._api.observe(source_handle)
            if not _same_snapshot(baseline, after_prefix):
                raise ExternalSourceError(
                    ExternalSourceCode.SOURCE_CHANGED,
                    "synthetic source changed during its SQLite-header gate",
                )
            if prefix.startswith(_SQLITE_HEADER):
                raise ExternalSourceError(
                    ExternalSourceCode.SQLITE_REJECTED,
                    "SQLite content is excluded from generic Copy",
                )
            locator = _keyed_digest(
                self._locator_key,
                b"SYNTHETIC-REFERENCE-LOCATOR-V1",
                self._run_id.encode("ascii"),
                self._copy_id.encode("ascii"),
                self._classification.value.encode("ascii"),
                actual_name.encode("utf-8", "strict"),
            )
            binding = _keyed_digest(
                self._locator_key,
                b"SYNTHETIC-REFERENCE-CAPABILITY-BINDING-V1",
                SYNTHETIC_REFERENCE_POLICY_DIGEST.encode("ascii"),
                self._marker_digest.encode("ascii"),
                locator.encode("ascii"),
                b"EXISTING_READ",
                b"ONE_SHOT",
            )
            handles = self._handles
            handles.append(source_handle)
            source_handle = None
            lease = _SyntheticReferenceLease(
                api=self._api,
                handles=handles,
                baseline=after_prefix,
                classification=self._classification,
                locator_hmac=locator,
                capability_binding_digest=binding,
                digest_key=self._locator_key,
                _constructor=_LEASE_CONSTRUCTOR,
            )
            self._issued_lease = lease
            self._handles = []
            self._reference_root = None
            self._state = "CONSUMED"
            return lease
        except ExternalSourceError as error:
            self._state = "FAILED"
            if source_handle is not None:
                self._handles.append(source_handle)
            try:
                _close_handles(self._api, self._handles)
            except ExternalSourceError as close_error:
                _raise_path_free(close_error)
            _raise_path_free(error)
        except BaseException:
            self._state = "FAILED"
            if source_handle is not None:
                self._handles.append(source_handle)
            try:
                _close_handles(self._api, self._handles)
            except ExternalSourceError as close_error:
                _raise_path_free(close_error)
            _raise_path_free(
                ExternalSourceError(
                    ExternalSourceCode.INTERNAL_FAILURE,
                    "synthetic reference authorization failed safely",
                )
            )

    @_path_free_exception_boundary
    def close(self) -> None:
        if self._state in {"CLOSED", "FAILED"}:
            return
        if (
            threading.get_ident() != self._owner_thread
            or threading.current_thread() is not self._owner_thread_object
            or self._owner_thread_object.ident != self._owner_thread
        ):
            raise ExternalSourceError(
                ExternalSourceCode.CAPABILITY_CROSS_THREAD,
                "synthetic reference authority must be closed by its issuing thread",
            )
        issued_lease = self._issued_lease if self._state == "CONSUMED" else None
        if self._state not in {"ISSUED", "CONSUMED"}:
            raise ExternalSourceError(
                ExternalSourceCode.CAPABILITY_ALREADY_USED,
                "synthetic reference authority is not live",
            )
        self._state = "CLOSED"
        self._reference_root = None
        if issued_lease is not None:
            issued_lease.close()
        else:
            _close_handles(self._api, self._handles)

    def _assert_owner(self, expected_state: str) -> None:
        if (
            threading.get_ident() != self._owner_thread
            or threading.current_thread() is not self._owner_thread_object
            or self._owner_thread_object.ident != self._owner_thread
        ):
            raise ExternalSourceError(
                ExternalSourceCode.CAPABILITY_CROSS_THREAD,
                "synthetic reference authority is bound to its issuing thread",
            )
        if self._state != expected_state:
            raise ExternalSourceError(
                ExternalSourceCode.CAPABILITY_ALREADY_USED,
                "synthetic reference authority is closed or already consumed",
            )

    @_path_free_exception_boundary
    def __enter__(self) -> SyntheticReferenceReadPolicy:
        self._assert_owner("ISSUED")
        return self

    @_path_free_exception_boundary
    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            "SyntheticReferenceReadPolicy(intent='EXISTING_READ', classification="
            f"'{self._classification.value}', state='{self._state}', roots='<redacted>')"
        )

    def __reduce__(self) -> Any:
        del self
        raise TypeError("synthetic reference policies cannot be serialized")


class _SyntheticReferenceLease:
    __slots__ = (
        "_api",
        "_baseline",
        "_binding_digest",
        "_classification",
        "_digest_key",
        "_evidence",
        "_handles",
        "_locator_hmac",
        "_owner_thread",
        "_owner_thread_object",
        "_state",
    )

    def __init__(
        self,
        *,
        api: _ReferenceReadApi,
        handles: list[int],
        baseline: _ObservedReference,
        classification: DataClassification,
        locator_hmac: str,
        capability_binding_digest: str,
        digest_key: bytes,
        _constructor: object,
    ) -> None:
        if (
            _constructor is not _LEASE_CONSTRUCTOR
            or type(api) is not _ReferenceReadApi
            or type(baseline) is not _ObservedReference
            or type(classification) is not DataClassification
            or not handles
            or not _is_sha256(locator_hmac)
            or not _is_sha256(capability_binding_digest)
            or len(digest_key) != 32
        ):
            raise TypeError("synthetic reference leases require the fixed policy")
        self._api = api
        self._handles = handles
        self._baseline = baseline
        self._classification = classification
        self._locator_hmac = locator_hmac
        self._binding_digest = capability_binding_digest
        self._digest_key = digest_key
        self._owner_thread = threading.get_ident()
        self._owner_thread_object = threading.current_thread()
        if self._owner_thread_object.ident != self._owner_thread:
            raise ExternalSourceError(
                ExternalSourceCode.CAPABILITY_CROSS_THREAD,
                "synthetic source lease thread identity is unstable",
            )
        self._evidence: SyntheticSourceEvidence | None = None
        self._state = "OPEN"

    @property
    def classification(self) -> DataClassification:
        return self._classification

    @property
    def intent(self) -> PathIntent:
        return PathIntent.EXISTING_READ

    @_path_free_exception_boundary
    def read_once(self) -> SyntheticSourceMaterial:
        self._assert_owner("OPEN")
        try:
            source_handle = self._handles[-1]
            before = self._api.observe(source_handle)
            self._require_baseline(before)
            payload, sha256 = self._api.read_bounded(
                source_handle,
                SYNTHETIC_REFERENCE_MAX_BYTES,
            )
            after = self._api.observe(source_handle)
            final = self._api.observe(source_handle)
            if (
                not _same_snapshot(before, after)
                or not _same_snapshot(after, final)
                or len(payload) != final.end_of_file
            ):
                raise ExternalSourceError(
                    ExternalSourceCode.SOURCE_CHANGED,
                    "synthetic source changed during its verified read",
                )
            if payload.startswith(_SQLITE_HEADER):
                raise ExternalSourceError(
                    ExternalSourceCode.SQLITE_REJECTED,
                    "SQLite content is excluded from generic Copy",
                )
            observation = _observation_bytes(final)
            identity_digest = _keyed_digest(
                self._digest_key,
                b"SYNTHETIC-REFERENCE-IDENTITY-V1",
                final.volume_serial.to_bytes(8, "big"),
                final.file_id,
            )
            stability_digest = _keyed_digest(
                self._digest_key,
                b"SYNTHETIC-REFERENCE-STABILITY-V1",
                observation,
                sha256.encode("ascii"),
            )
            source_reference = _keyed_digest(
                self._digest_key,
                b"SYNTHETIC-REFERENCE-SOURCE-V1",
                self._binding_digest.encode("ascii"),
                identity_digest.encode("ascii"),
                len(payload).to_bytes(8, "big"),
                sha256.encode("ascii"),
            )
            evidence = SyntheticSourceEvidence(
                policy_digest=SYNTHETIC_REFERENCE_POLICY_DIGEST,
                classification=self._classification,
                locator_hmac=self._locator_hmac,
                capability_binding_digest=self._binding_digest,
                source_identity_digest=identity_digest,
                size_bytes=len(payload),
                sha256=sha256,
                stability_digest=stability_digest,
                source_reference=source_reference,
            )
            material = SyntheticSourceMaterial(evidence=evidence, payload=payload)
            self._evidence = evidence
            self._state = "READ"
            return material
        except ExternalSourceError as error:
            self._fail_and_close(error)
        except BaseException:
            self._fail_and_close(
                ExternalSourceError(
                    ExternalSourceCode.INTERNAL_FAILURE,
                    "synthetic source read failed safely",
                )
            )

    @_path_free_exception_boundary
    def _checkpoint_unchanged(
        self,
        evidence: SyntheticSourceEvidence,
    ) -> None:
        """Re-observe the issued source without consuming its final gate.

        Recovery needs a proof immediately before it appends a durable
        resolution and one final, consuming proof afterwards.  This private
        checkpoint deliberately leaves the lease in READ; the public
        ``verify_unchanged`` capability remains single-use.
        """

        self._assert_owner("READ")
        if evidence is not self._evidence:
            self._fail_and_close(
                ExternalSourceError(
                    ExternalSourceCode.INVALID_REQUEST,
                    "source checkpoint requires the exact issued evidence",
                )
            )
        try:
            source_handle = self._handles[-1]
            before = self._api.observe(source_handle)
            self._require_baseline(before)
            payload, sha256 = self._api.read_bounded(
                source_handle,
                SYNTHETIC_REFERENCE_MAX_BYTES,
            )
            after = self._api.observe(source_handle)
            final = self._api.observe(source_handle)
            if (
                not _same_snapshot(before, after)
                or not _same_snapshot(after, final)
                or len(payload) != evidence.size_bytes
                or sha256 != evidence.sha256
            ):
                raise ExternalSourceError(
                    ExternalSourceCode.SOURCE_CHANGED,
                    "synthetic source differs at its recovery checkpoint",
                )
        except ExternalSourceError as error:
            self._fail_and_close(error)
        except BaseException:
            self._fail_and_close(
                ExternalSourceError(
                    ExternalSourceCode.INTERNAL_FAILURE,
                    "synthetic source checkpoint failed safely",
                )
            )

    @_path_free_exception_boundary
    def verify_unchanged(
        self,
        evidence: SyntheticSourceEvidence,
    ) -> SyntheticSourceVerification:
        self._assert_owner("READ")
        if evidence is not self._evidence:
            self._fail_and_close(
                ExternalSourceError(
                    ExternalSourceCode.INVALID_REQUEST,
                    "final verification requires the exact issued evidence",
                )
            )
        try:
            source_handle = self._handles[-1]
            before = self._api.observe(source_handle)
            self._require_baseline(before)
            payload, sha256 = self._api.read_bounded(
                source_handle,
                SYNTHETIC_REFERENCE_MAX_BYTES,
            )
            after = self._api.observe(source_handle)
            final = self._api.observe(source_handle)
            if (
                not _same_snapshot(before, after)
                or not _same_snapshot(after, final)
                or len(payload) != evidence.size_bytes
                or sha256 != evidence.sha256
            ):
                raise ExternalSourceError(
                    ExternalSourceCode.SOURCE_CHANGED,
                    "synthetic source differs from its issued evidence",
                )
            verification = SyntheticSourceVerification(
                evidence=evidence,
                verification_digest=_keyed_digest(
                    self._digest_key,
                    b"SYNTHETIC-REFERENCE-FINAL-VERIFICATION-V1",
                    evidence.source_reference.encode("ascii"),
                    _observation_bytes(final),
                    sha256.encode("ascii"),
                ),
            )
            self._state = "VERIFIED"
            return verification
        except ExternalSourceError as error:
            self._fail_and_close(error)
        except BaseException:
            self._fail_and_close(
                ExternalSourceError(
                    ExternalSourceCode.INTERNAL_FAILURE,
                    "synthetic source final verification failed safely",
                )
            )

    def _require_baseline(self, observed: _ObservedReference) -> None:
        if not _same_snapshot(self._baseline, observed):
            raise ExternalSourceError(
                ExternalSourceCode.SOURCE_CHANGED,
                "synthetic source no longer matches its opening evidence",
            )

    def _assert_owner(self, expected_state: str) -> None:
        if (
            threading.get_ident() != self._owner_thread
            or threading.current_thread() is not self._owner_thread_object
            or self._owner_thread_object.ident != self._owner_thread
        ):
            raise ExternalSourceError(
                ExternalSourceCode.CAPABILITY_CROSS_THREAD,
                "synthetic source lease is bound to its opening thread",
            )
        if self._state != expected_state:
            raise ExternalSourceError(
                ExternalSourceCode.CAPABILITY_ALREADY_USED,
                "synthetic source lease is closed or already consumed",
            )

    def _fail_and_close(self, error: ExternalSourceError) -> NoReturn:
        self._state = "FAILED"
        try:
            _close_handles(self._api, self._handles)
        except ExternalSourceError as close_error:
            _raise_path_free(close_error)
        _raise_path_free(error)

    @_path_free_exception_boundary
    def close(self) -> None:
        if self._state in {"CLOSED", "FAILED"}:
            return
        if (
            threading.get_ident() != self._owner_thread
            or threading.current_thread() is not self._owner_thread_object
            or self._owner_thread_object.ident != self._owner_thread
        ):
            raise ExternalSourceError(
                ExternalSourceCode.CAPABILITY_CROSS_THREAD,
                "synthetic source lease must be closed by its opening thread",
            )
        self._state = "CLOSED"
        _close_handles(self._api, self._handles)

    @_path_free_exception_boundary
    def __enter__(self) -> _SyntheticReferenceLease:
        if (
            threading.get_ident() != self._owner_thread
            or threading.current_thread() is not self._owner_thread_object
            or self._owner_thread_object.ident != self._owner_thread
            or self._state != "OPEN"
        ):
            self._assert_owner("OPEN")
        return self

    @_path_free_exception_boundary
    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            "_SyntheticReferenceLease(intent='EXISTING_READ', classification="
            f"'{self._classification.value}', state='{self._state}', source='<redacted>')"
        )

    def __reduce__(self) -> Any:
        del self
        raise TypeError("synthetic source leases cannot be serialized")


class _CopyExecutionPermit:
    """One-shot, exact-identity authorization for the private Copy orchestrator."""

    __slots__ = (
        "_binding_sha256",
        "_budget_sha256",
        "_classification",
        "_context_sha256",
        "_copy_scope_sha256",
        "_evidence",
        "_lease",
        "_manifest_sha256",
        "_operation_authority",
        "_operation_identity_sha256",
        "_owner_thread",
        "_owner_thread_object",
        "_policy",
        "_state",
        "_target_sha256",
    )

    def __init__(
        self,
        *,
        policy: SyntheticReferenceReadPolicy,
        lease: _SyntheticReferenceLease,
        evidence: SyntheticSourceEvidence,
        operation_authority: object,
        operation_identity_sha256: str,
        context_sha256: str,
        manifest_sha256: str,
        budget_sha256: str,
        target_sha256: str,
        copy_scope_sha256: str,
        classification: DataClassification,
        binding_sha256: str,
        owner_thread: int,
        owner_thread_object: threading.Thread,
        _constructor: object,
    ) -> None:
        if (
            _constructor is not _COPY_EXECUTION_PERMIT_CONSTRUCTOR
            or type(policy) is not SyntheticReferenceReadPolicy
            or type(lease) is not _SyntheticReferenceLease
            or type(evidence) is not SyntheticSourceEvidence
            or operation_authority is None
            or type(classification) is not DataClassification
            or type(owner_thread) is not int
            or not isinstance(owner_thread_object, threading.Thread)
            or owner_thread_object.ident != owner_thread
            or any(
                not _is_sha256(value)
                for value in (
                    operation_identity_sha256,
                    context_sha256,
                    manifest_sha256,
                    budget_sha256,
                    target_sha256,
                    copy_scope_sha256,
                    binding_sha256,
                )
            )
        ):
            raise ExternalSourceError(
                ExternalSourceCode.INVALID_FACTORY,
                "copy execution permits require exact private issuance",
            )
        self._policy = policy
        self._lease = lease
        self._evidence = evidence
        self._operation_authority = operation_authority
        self._operation_identity_sha256 = operation_identity_sha256
        self._context_sha256 = context_sha256
        self._manifest_sha256 = manifest_sha256
        self._budget_sha256 = budget_sha256
        self._target_sha256 = target_sha256
        self._copy_scope_sha256 = copy_scope_sha256
        self._classification = classification
        self._binding_sha256 = binding_sha256
        self._owner_thread = owner_thread
        self._owner_thread_object = owner_thread_object
        self._state = "ISSUED"

    def __repr__(self) -> str:
        return "_CopyExecutionPermit(state='<redacted>', bindings='<redacted>')"

    def __reduce__(self) -> Any:
        del self
        raise TypeError("copy execution permits cannot be serialized")


def _copy_execution_scope_sha256(
    lease: _SyntheticReferenceLease,
    copy_id: str,
    classification: DataClassification,
) -> str:
    return _keyed_digest(
        lease._digest_key,
        b"SYNTHETIC-COPY-EXECUTION-SCOPE-V1",
        copy_id.encode("ascii"),
        classification.value.encode("ascii"),
    )


def _copy_execution_binding_sha256(
    policy: SyntheticReferenceReadPolicy,
    lease: _SyntheticReferenceLease,
    evidence: SyntheticSourceEvidence,
    operation_authority: object,
    *,
    operation_identity_sha256: str,
    context_sha256: str,
    manifest_sha256: str,
    budget_sha256: str,
    target_sha256: str,
    copy_scope_sha256: str,
    owner_thread: int,
    owner_thread_object: threading.Thread,
) -> str:
    return _keyed_digest(
        lease._digest_key,
        b"SYNTHETIC-COPY-EXECUTION-PERMIT-V2",
        evidence.source_reference.encode("ascii"),
        evidence.capability_binding_digest.encode("ascii"),
        operation_identity_sha256.encode("ascii"),
        context_sha256.encode("ascii"),
        manifest_sha256.encode("ascii"),
        budget_sha256.encode("ascii"),
        target_sha256.encode("ascii"),
        copy_scope_sha256.encode("ascii"),
        str(owner_thread).encode("ascii"),
        str(id(owner_thread_object)).encode("ascii"),
        str(id(policy)).encode("ascii"),
        str(id(lease)).encode("ascii"),
        str(id(evidence)).encode("ascii"),
        str(id(operation_authority)).encode("ascii"),
    )


def _require_copy_execution_authorities(
    policy: SyntheticReferenceReadPolicy,
    lease: _SyntheticReferenceLease,
    evidence: SyntheticSourceEvidence,
    *,
    copy_id: str,
    classification: DataClassification,
) -> tuple[int, threading.Thread, str]:
    if (
        type(policy) is not SyntheticReferenceReadPolicy
        or type(lease) is not _SyntheticReferenceLease
        or type(evidence) is not SyntheticSourceEvidence
        or type(classification) is not DataClassification
    ):
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_FACTORY,
            "copy execution requires exact source authorities",
        )
    try:
        canonical_copy_id = validate_safe_id(copy_id, field_name="copy_id")
    except ContextError:
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_REQUEST,
            "copy execution scope is not canonical",
        ) from None
    owner = threading.get_ident()
    owner_object = threading.current_thread()
    if (
        policy._owner_thread != owner
        or lease._owner_thread != owner
        or policy._owner_thread_object is not owner_object
        or lease._owner_thread_object is not owner_object
        or owner_object.ident != owner
    ):
        raise ExternalSourceError(
            ExternalSourceCode.CAPABILITY_CROSS_THREAD,
            "copy execution authorities are bound to their issuing thread",
        )
    if (
        policy._state != "CONSUMED"
        or policy._issued_lease is not lease
        or lease._state != "READ"
        or lease._evidence is not evidence
    ):
        raise ExternalSourceError(
            ExternalSourceCode.CAPABILITY_ALREADY_USED,
            "copy execution authorities are absent, closed, or already consumed",
        )
    if (
        classification is not policy._classification
        or classification is not lease._classification
        or classification is not evidence.classification
        or not hmac.compare_digest(canonical_copy_id, policy._copy_id)
        or not hmac.compare_digest(policy._locator_key, lease._digest_key)
        or evidence.capability_binding_digest != lease._binding_digest
        or evidence.locator_hmac != lease._locator_hmac
    ):
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_REQUEST,
            "copy execution source authorities do not share one exact scope",
        )
    return owner, owner_object, _copy_execution_scope_sha256(
        lease,
        canonical_copy_id,
        classification,
    )


@_path_free_exception_boundary
def _issue_copy_execution_permit(
    policy: SyntheticReferenceReadPolicy,
    lease: _SyntheticReferenceLease,
    evidence: SyntheticSourceEvidence,
    *,
    operation_authority: object,
    operation_identity_sha256: str,
    context_sha256: str,
    manifest_sha256: str,
    budget_sha256: str,
    target_sha256: str,
    copy_id: str,
    classification: DataClassification,
) -> _CopyExecutionPermit:
    """Issue only from the exact consumed policy and its live READ-state lease."""

    digests = (
        operation_identity_sha256,
        context_sha256,
        manifest_sha256,
        budget_sha256,
        target_sha256,
    )
    if operation_authority is None or any(not _is_sha256(value) for value in digests):
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_REQUEST,
            "copy execution identity bindings are incomplete",
        )
    owner, owner_object, copy_scope_sha256 = _require_copy_execution_authorities(
        policy,
        lease,
        evidence,
        copy_id=copy_id,
        classification=classification,
    )
    binding = _copy_execution_binding_sha256(
        policy,
        lease,
        evidence,
        operation_authority,
        operation_identity_sha256=operation_identity_sha256,
        context_sha256=context_sha256,
        manifest_sha256=manifest_sha256,
        budget_sha256=budget_sha256,
        target_sha256=target_sha256,
        copy_scope_sha256=copy_scope_sha256,
        owner_thread=owner,
        owner_thread_object=owner_object,
    )
    return _CopyExecutionPermit(
        policy=policy,
        lease=lease,
        evidence=evidence,
        operation_authority=operation_authority,
        operation_identity_sha256=operation_identity_sha256,
        context_sha256=context_sha256,
        manifest_sha256=manifest_sha256,
        budget_sha256=budget_sha256,
        target_sha256=target_sha256,
        copy_scope_sha256=copy_scope_sha256,
        classification=classification,
        binding_sha256=binding,
        owner_thread=owner,
        owner_thread_object=owner_object,
        _constructor=_COPY_EXECUTION_PERMIT_CONSTRUCTOR,
    )


def _check_copy_execution_permit(
    permit: _CopyExecutionPermit,
    policy: SyntheticReferenceReadPolicy,
    lease: _SyntheticReferenceLease,
    evidence: SyntheticSourceEvidence,
    *,
    operation_authority: object,
    operation_identity_sha256: str,
    context_sha256: str,
    manifest_sha256: str,
    budget_sha256: str,
    target_sha256: str,
    copy_id: str,
    classification: DataClassification,
    consume: bool,
) -> None:
    if type(permit) is not _CopyExecutionPermit or type(consume) is not bool:
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_FACTORY,
            "copy execution requires an exact private permit",
        )
    if operation_authority is None or any(
        not _is_sha256(value)
        for value in (
            operation_identity_sha256,
            context_sha256,
            manifest_sha256,
            budget_sha256,
            target_sha256,
        )
    ):
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_REQUEST,
            "copy execution permit bindings are incomplete",
        )
    owner, owner_object, copy_scope_sha256 = _require_copy_execution_authorities(
        policy,
        lease,
        evidence,
        copy_id=copy_id,
        classification=classification,
    )
    expected_binding = _copy_execution_binding_sha256(
        policy,
        lease,
        evidence,
        operation_authority,
        operation_identity_sha256=operation_identity_sha256,
        context_sha256=context_sha256,
        manifest_sha256=manifest_sha256,
        budget_sha256=budget_sha256,
        target_sha256=target_sha256,
        copy_scope_sha256=copy_scope_sha256,
        owner_thread=owner,
        owner_thread_object=owner_object,
    )
    if (
        permit._owner_thread != owner
        or permit._owner_thread_object is not owner_object
    ):
        raise ExternalSourceError(
            ExternalSourceCode.CAPABILITY_CROSS_THREAD,
            "copy execution permit is bound to its issuing thread",
        )
    if permit._state != "ISSUED":
        raise ExternalSourceError(
            ExternalSourceCode.CAPABILITY_ALREADY_USED,
            "copy execution permit is already consumed",
        )
    if (
        permit._policy is not policy
        or permit._lease is not lease
        or permit._evidence is not evidence
        or permit._operation_authority is not operation_authority
        or permit._operation_identity_sha256 != operation_identity_sha256
        or permit._context_sha256 != context_sha256
        or permit._manifest_sha256 != manifest_sha256
        or permit._budget_sha256 != budget_sha256
        or permit._target_sha256 != target_sha256
        or permit._copy_scope_sha256 != copy_scope_sha256
        or permit._classification is not classification
        or not hmac.compare_digest(permit._binding_sha256, expected_binding)
    ):
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_REQUEST,
            "copy execution permit does not match this exact operation",
        )
    if consume:
        permit._state = "CONSUMED"


@_path_free_exception_boundary
def _validate_copy_execution_permit(
    permit: _CopyExecutionPermit,
    policy: SyntheticReferenceReadPolicy,
    lease: _SyntheticReferenceLease,
    evidence: SyntheticSourceEvidence,
    *,
    operation_authority: object,
    operation_identity_sha256: str,
    context_sha256: str,
    manifest_sha256: str,
    budget_sha256: str,
    target_sha256: str,
    copy_id: str,
    classification: DataClassification,
) -> None:
    _check_copy_execution_permit(
        permit,
        policy,
        lease,
        evidence,
        operation_authority=operation_authority,
        operation_identity_sha256=operation_identity_sha256,
        context_sha256=context_sha256,
        manifest_sha256=manifest_sha256,
        budget_sha256=budget_sha256,
        target_sha256=target_sha256,
        copy_id=copy_id,
        classification=classification,
        consume=False,
    )


@_path_free_exception_boundary
def _consume_copy_execution_permit(
    permit: _CopyExecutionPermit,
    policy: SyntheticReferenceReadPolicy,
    lease: _SyntheticReferenceLease,
    evidence: SyntheticSourceEvidence,
    *,
    operation_authority: object,
    operation_identity_sha256: str,
    context_sha256: str,
    manifest_sha256: str,
    budget_sha256: str,
    target_sha256: str,
    copy_id: str,
    classification: DataClassification,
) -> None:
    _check_copy_execution_permit(
        permit,
        policy,
        lease,
        evidence,
        operation_authority=operation_authority,
        operation_identity_sha256=operation_identity_sha256,
        context_sha256=context_sha256,
        manifest_sha256=manifest_sha256,
        budget_sha256=budget_sha256,
        target_sha256=target_sha256,
        copy_id=copy_id,
        classification=classification,
        consume=True,
    )


@_path_free_exception_boundary
def _create_synthetic_reference_read_policy(
    project_root: Path,
    *,
    copy_id: str,
    classification: DataClassification,
) -> SyntheticReferenceReadPolicy:
    """Bind the exact active safe-launcher RUN to a read-only REFERENCE root."""

    if os.name != "nt":
        raise ExternalSourceError(
            ExternalSourceCode.UNSUPPORTED_PLATFORM,
            "synthetic reference reads require Windows",
        )
    if type(classification) is not DataClassification:
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_REQUEST,
            "classification must be an exact DataClassification value",
        )
    if not isinstance(project_root, Path):
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_REQUEST,
            "project root must be an explicit Path value",
        )
    try:
        validated_copy_id = validate_safe_id(copy_id, field_name="copy_id")
    except ContextError:
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_REQUEST,
            "copy ID must be one canonical safe identifier",
        ) from None
    raw_run_root = os.environ.get("M0_TEST_LAB_ROOT")
    launch_token = os.environ.get("M0_TEST_LAB_TOKEN")
    if not raw_run_root or not launch_token:
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_FACTORY,
            "synthetic reference policy requires the active safe launcher",
        )
    try:
        contract_root = _absolute_lexical(_contract_project_root())
        test_lab_root = contract_root / "tmp" / "test_lab"
        run_root = _absolute_lexical(raw_run_root)
        project = _absolute_lexical(project_root)
    except (OSError, TypeError, ValueError):
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_LABORATORY,
            "safe-launcher roots could not be normalized",
        ) from None
    run_tail = _relative_parts(run_root, test_lab_root)
    if (
        run_tail != (run_root.name,)
        or not run_root.name.startswith("RUN-")
        or not _same_path(project, run_root / "project")
    ):
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_LABORATORY,
            "synthetic reference policy requires exact run/project topology",
        )
    try:
        validate_safe_id(run_root.name, field_name="run_id")
    except ContextError:
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_LABORATORY,
            "safe-launcher run ID is not canonical",
        ) from None
    external_root = run_root / "external"
    reference_root = external_root / "REFERENCE"
    marker_path = run_root / ".safety-marker.json"
    api = _ReferenceReadApi(_constructor=_READ_API_CONSTRUCTOR)
    handles: list[int] = []
    try:
        fixed_objects = (
            (contract_root, True, None),
            (contract_root / "tmp", True, "tmp"),
            (test_lab_root, True, "test_lab"),
            (run_root, True, run_root.name),
            (marker_path, False, ".safety-marker.json"),
            (project, True, "project"),
            (external_root, True, "external"),
            (reference_root, True, "REFERENCE"),
        )
        marker_bytes: bytes | None = None
        marker_observed: _ObservedReference | None = None
        for path, directory, exact_name in fixed_objects:
            handle, observed, _actual_name = _open_verified(
                api,
                path,
                directory=directory,
                exact_name=exact_name,
            )
            handles.append(handle)
            if path == marker_path:
                marker_observed = observed
                if observed.link_count != 1 or not 2 <= observed.end_of_file <= _MARKER_MAX_BYTES:
                    raise ExternalSourceError(
                        ExternalSourceCode.INVALID_LABORATORY,
                        "safe-launcher marker has an invalid immutable shape",
                    )
                marker_bytes, _marker_sha = api.read_bounded(handle, _MARKER_MAX_BYTES)
                after_marker = api.observe(handle)
                if not _same_snapshot(observed, after_marker):
                    raise ExternalSourceError(
                        ExternalSourceCode.INVALID_LABORATORY,
                        "safe-launcher marker changed during verification",
                    )
        if marker_bytes is None or marker_observed is None:
            raise ExternalSourceError(
                ExternalSourceCode.INVALID_LABORATORY,
                "safe-launcher marker was not verified",
            )
        try:
            decoded = json.loads(marker_bytes.decode("utf-8", "strict"))
        except (UnicodeError, json.JSONDecodeError):
            raise ExternalSourceError(
                ExternalSourceCode.INVALID_LABORATORY,
                "safe-launcher marker is not valid UTF-8 JSON",
            ) from None
        expected_marker_keys = {
            "cleanup_policy",
            "created_at",
            "launch_token_sha256",
            "project_root",
            "purpose",
            "run_id",
            "schema_version",
        }
        marker_project = decoded.get("project_root") if isinstance(decoded, dict) else None
        marker_valid = (
            isinstance(decoded, dict)
            and set(decoded) == expected_marker_keys
            and decoded.get("schema_version") == "1.0"
            and decoded.get("run_id") == run_root.name
            and decoded.get("purpose") == "M0-S1 WorkspaceGuard safety laboratory"
            and decoded.get("cleanup_policy") == "retain-until-manifested-quarantine"
            and type(decoded.get("created_at")) is str
            and type(marker_project) is str
            and _same_path(_absolute_lexical(marker_project), contract_root)
            and decoded.get("launch_token_sha256")
            == hashlib.sha256(launch_token.encode("utf-8", "strict")).hexdigest()
        )
        if not marker_valid:
            raise ExternalSourceError(
                ExternalSourceCode.INVALID_LABORATORY,
                "safe-launcher marker does not match the active run",
            )
        marker_digest = hashlib.sha256(marker_bytes).hexdigest()
        locator_key = hmac.new(
            hashlib.sha256(launch_token.encode("utf-8", "strict")).digest(),
            b"SYNTHETIC-REFERENCE-LOCATOR-KDF-V1\0"
            + SYNTHETIC_REFERENCE_POLICY_DIGEST.encode("ascii")
            + b"\0"
            + marker_digest.encode("ascii"),
            hashlib.sha256,
        ).digest()
        return SyntheticReferenceReadPolicy(
            api=api,
            handles=handles,
            reference_root=reference_root,
            run_id=run_root.name,
            copy_id=validated_copy_id,
            classification=classification,
            locator_key=locator_key,
            marker_digest=marker_digest,
            _constructor=_POLICY_CONSTRUCTOR,
        )
    except ExternalSourceError as error:
        try:
            _close_handles(api, handles)
        except ExternalSourceError as close_error:
            _raise_path_free(close_error)
        _raise_path_free(error)
    except BaseException:
        try:
            _close_handles(api, handles)
        except ExternalSourceError as close_error:
            _raise_path_free(close_error)
        _raise_path_free(
            ExternalSourceError(
                ExternalSourceCode.INTERNAL_FAILURE,
                "synthetic reference factory failed safely",
            )
        )


def _validated_registered_source_path(
    value: str | os.PathLike[str],
) -> Path:
    try:
        raw = os.fspath(value)
    except TypeError:
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_REQUEST,
            "registered source path must be an explicit filesystem path",
        ) from None
    if (
        type(raw) is not str
        or not raw
        or raw.startswith(("\\\\", "//", "\\\\?\\", "\\\\.\\"))
    ):
        raise ExternalSourceError(
            ExternalSourceCode.PATH_REJECTED,
            "registered sources must use one local absolute drive path",
        )
    try:
        source = _absolute_lexical(raw)
        windows = PureWindowsPath(str(source))
    except (OSError, TypeError, ValueError):
        raise ExternalSourceError(
            ExternalSourceCode.PATH_REJECTED,
            "registered source path could not be normalized",
        ) from None
    if (
        not windows.is_absolute()
        or len(windows.drive) != 2
        or windows.drive[1:] != ":"
        or windows.root != "\\"
        or len(windows.parts) < 2
        or any(
            part in {"", ".", ".."}
            or ":" in part
            or part.rstrip(" .") != part
            or any(ord(character) < 32 for character in part)
            for part in windows.parts[1:]
        )
    ):
        raise ExternalSourceError(
            ExternalSourceCode.PATH_REJECTED,
            "registered source path contains unsupported syntax",
        )

    contract_root = _absolute_lexical(_contract_project_root())
    inside_contract_root = _relative_parts(source, contract_root) is not None
    if inside_contract_root:
        raw_run_root = os.environ.get("M0_TEST_LAB_ROOT")
        if not raw_run_root:
            raise ExternalSourceError(
                ExternalSourceCode.PATH_REJECTED,
                "registered external sources must be outside the project root",
            )
        try:
            run_root = _absolute_lexical(raw_run_root)
        except (OSError, TypeError, ValueError):
            raise ExternalSourceError(
                ExternalSourceCode.INVALID_LABORATORY,
                "safe-launcher source exception could not be normalized",
            ) from None
        reference_root = run_root / "external" / "REFERENCE"
        relative = _relative_parts(source, reference_root)
        if relative is None or len(relative) != 1:
            raise ExternalSourceError(
                ExternalSourceCode.PATH_REJECTED,
                "project-local source is not the active synthetic reference",
            )

    chain = (*reversed(source.parents), source)
    for index, component in enumerate(chain):
        expected = _expected_identity(component)
        if expected.file_attributes & _REPARSE_ATTRIBUTE or expected.reparse_tag:
            raise ExternalSourceError(
                ExternalSourceCode.REPARSE_POINT,
                "registered source path contains a reparse object",
            )
        is_target = index == len(chain) - 1
        if is_target:
            if not stat.S_ISREG(expected.mode) or expected.link_count != 1:
                raise ExternalSourceError(
                    ExternalSourceCode.HARDLINK_REJECTED,
                    "registered source must be one single-link regular file",
                )
        elif not stat.S_ISDIR(expected.mode):
            raise ExternalSourceError(
                ExternalSourceCode.TYPE_MISMATCH,
                "registered source parent chain contains a non-directory",
            )
    _validated_source_name(source.name)
    return source


class _RegisteredExternalReadLease:
    """Thread-bound external read handle held until target publication ends."""

    __slots__ = (
        "_api",
        "_baseline",
        "_classification",
        "_handle",
        "_logical_id",
        "_material",
        "_owner_thread",
        "_owner_thread_object",
        "_source_path",
        "_state",
    )

    def __init__(
        self,
        *,
        api: _ReferenceReadApi,
        handle: int,
        baseline: _ObservedReference,
        source_path: Path,
        logical_id: str,
        classification: DataClassification,
        _constructor: object,
    ) -> None:
        if (
            _constructor is not _REGISTERED_LEASE_CONSTRUCTOR
            or type(api) is not _ReferenceReadApi
            or type(handle) is not int
            or type(baseline) is not _ObservedReference
            or not isinstance(source_path, Path)
            or type(logical_id) is not str
            or _LOGICAL_REFERENCE_ID.fullmatch(logical_id) is None
            or type(classification) is not DataClassification
        ):
            raise TypeError("registered source leases require the fixed factory")
        self._api = api
        self._handle: int | None = handle
        self._baseline = baseline
        self._source_path: Path | None = source_path
        self._logical_id = logical_id
        self._classification = classification
        self._material: RegisteredSourceMaterial | None = None
        self._owner_thread = threading.get_ident()
        self._owner_thread_object = threading.current_thread()
        if self._owner_thread_object.ident != self._owner_thread:
            raise ExternalSourceError(
                ExternalSourceCode.CAPABILITY_CROSS_THREAD,
                "registered source authority thread identity is unstable",
            )
        self._state = "ISSUED"

    def _assert_owner(self, *states: str) -> None:
        if (
            threading.get_ident() != self._owner_thread
            or threading.current_thread() is not self._owner_thread_object
            or self._owner_thread_object.ident != self._owner_thread
        ):
            raise ExternalSourceError(
                ExternalSourceCode.CAPABILITY_CROSS_THREAD,
                "registered source lease is bound to its issuing thread",
            )
        if self._state not in states:
            raise ExternalSourceError(
                ExternalSourceCode.CAPABILITY_ALREADY_USED,
                "registered source lease is closed or in the wrong state",
            )

    def _live(self) -> tuple[_ReferenceReadApi, int, Path]:
        handle = self._handle
        path = self._source_path
        if handle is None or path is None:
            raise ExternalSourceError(
                ExternalSourceCode.CAPABILITY_ALREADY_USED,
                "registered source lease no longer holds a source handle",
            )
        return self._api, handle, path

    def _close_handle(self) -> None:
        handle = self._handle
        self._handle = None
        self._source_path = None
        if handle is not None:
            self._api.close(handle)

    def _fail(self, error: ExternalSourceError) -> NoReturn:
        self._state = "FAILED"
        try:
            self._close_handle()
        except ExternalSourceError as close_error:
            _raise_path_free(close_error)
        _raise_path_free(error)

    @_path_free_exception_boundary
    def read_once(self) -> RegisteredSourceMaterial:
        self._assert_owner("ISSUED")
        try:
            api, handle, source_path = self._live()
            payload, payload_sha256 = api.read_bounded(
                handle,
                SYNTHETIC_REFERENCE_MAX_BYTES,
            )
            after = api.observe(handle)
            _verify_path_binding(source_path, after)
            if not _same_snapshot(self._baseline, after):
                raise ExternalSourceError(
                    ExternalSourceCode.SOURCE_CHANGED,
                    "registered source changed during its handle-bound read",
                )
            identity_digest = hashlib.sha256(
                _observation_bytes(after)
            ).hexdigest()
            object_reference = hashlib.sha256(
                b"REGISTERED-EXTERNAL-SOURCE-V1\0"
                + self._logical_id.encode("ascii")
                + b"\0"
                + identity_digest.encode("ascii")
                + b"\0"
                + payload_sha256.encode("ascii")
            ).hexdigest()
            evidence = RegisteredSourceEvidence(
                logical_id=self._logical_id,
                classification=self._classification,
                source_object_reference=object_reference,
                source_identity_digest=identity_digest,
                size_bytes=len(payload),
                sha256=payload_sha256,
            )
            material = RegisteredSourceMaterial(
                evidence=evidence,
                payload=payload,
            )
            self._material = material
            self._state = "READ"
            return material
        except ExternalSourceError as error:
            self._fail(error)
        except BaseException:
            self._fail(
                ExternalSourceError(
                    ExternalSourceCode.INTERNAL_FAILURE,
                    "registered source read failed safely",
                )
            )

    @_path_free_exception_boundary
    def verify_unchanged(
        self,
        evidence: RegisteredSourceEvidence,
    ) -> RegisteredSourceVerification:
        self._assert_owner("READ")
        material = self._material
        if (
            type(evidence) is not RegisteredSourceEvidence
            or material is None
            or evidence is not material.evidence
        ):
            self._fail(
                ExternalSourceError(
                    ExternalSourceCode.INVALID_REQUEST,
                    "registered source verification requires its exact read evidence",
                )
            )
        try:
            api, handle, source_path = self._live()
            _payload, payload_sha256 = api.read_bounded(
                handle,
                SYNTHETIC_REFERENCE_MAX_BYTES,
            )
            after = api.observe(handle)
            _verify_path_binding(source_path, after)
            if (
                not _same_snapshot(self._baseline, after)
                or payload_sha256 != evidence.sha256
                or after.end_of_file != evidence.size_bytes
            ):
                raise ExternalSourceError(
                    ExternalSourceCode.SOURCE_CHANGED,
                    "registered source changed before target publication",
                )
            verification_digest = hashlib.sha256(
                b"REGISTERED-EXTERNAL-FINAL-VERIFICATION-V1\0"
                + evidence.source_object_reference.encode("ascii")
                + b"\0"
                + payload_sha256.encode("ascii")
                + b"\0"
                + _observation_bytes(after)
            ).hexdigest()
            self._state = "VERIFIED"
            return RegisteredSourceVerification(
                evidence=evidence,
                verification_digest=verification_digest,
            )
        except ExternalSourceError as error:
            self._fail(error)
        except BaseException:
            self._fail(
                ExternalSourceError(
                    ExternalSourceCode.INTERNAL_FAILURE,
                    "registered source verification failed safely",
                )
            )

    @_path_free_exception_boundary
    def close(self) -> None:
        if self._state in {"CLOSED", "FAILED"}:
            return
        self._assert_owner("ISSUED", "READ", "VERIFIED")
        self._state = "CLOSED"
        self._material = None
        self._close_handle()

    @_path_free_exception_boundary
    def __enter__(self) -> _RegisteredExternalReadLease:
        self._assert_owner("ISSUED")
        return self

    @_path_free_exception_boundary
    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            "_RegisteredExternalReadLease(state="
            f"'{self._state}', logical_id='{self._logical_id}', source='<redacted>')"
        )

    def __reduce__(self) -> Any:
        del self
        raise TypeError("registered source leases cannot be serialized")


@_path_free_exception_boundary
def open_registered_external_source(
    source_path: str | os.PathLike[str],
    *,
    logical_id: str,
    classification: DataClassification,
) -> _RegisteredExternalReadLease:
    """Open one registered source without granting any mutation authority."""

    if (
        type(logical_id) is not str
        or _LOGICAL_REFERENCE_ID.fullmatch(logical_id) is None
        or type(classification) is not DataClassification
    ):
        raise ExternalSourceError(
            ExternalSourceCode.INVALID_REQUEST,
            "registered source metadata is not canonical",
        )
    source = _validated_registered_source_path(source_path)
    if _is_sqlite_name(source.name):
        raise ExternalSourceError(
            ExternalSourceCode.SQLITE_REJECTED,
            "SQLite databases and sidecars require the database backup flow",
        )
    api = _ReferenceReadApi(_constructor=_READ_API_CONSTRUCTOR)
    handle: int | None = None
    try:
        handle, baseline, _actual_name = _open_verified(
            api,
            source,
            directory=False,
            exact_name=source.name,
        )
        if baseline.link_count != 1:
            raise ExternalSourceError(
                ExternalSourceCode.HARDLINK_REJECTED,
                "registered source must have exactly one hard link",
            )
        if baseline.end_of_file > SYNTHETIC_REFERENCE_MAX_BYTES:
            raise ExternalSourceError(
                ExternalSourceCode.RESOURCE_LIMIT,
                "registered source exceeds the fixed 64 MiB limit",
            )
        prefix = api.read_prefix(handle, len(_SQLITE_HEADER))
        after_prefix = api.observe(handle)
        if not _same_snapshot(baseline, after_prefix):
            raise ExternalSourceError(
                ExternalSourceCode.SOURCE_CHANGED,
                "registered source changed during its content-type gate",
            )
        if prefix.startswith(_SQLITE_HEADER):
            raise ExternalSourceError(
                ExternalSourceCode.SQLITE_REJECTED,
                "SQLite content requires the database backup flow",
            )
        lease = _RegisteredExternalReadLease(
            api=api,
            handle=handle,
            baseline=after_prefix,
            source_path=source,
            logical_id=logical_id,
            classification=classification,
            _constructor=_REGISTERED_LEASE_CONSTRUCTOR,
        )
        handle = None
        return lease
    except ExternalSourceError as error:
        if handle is not None:
            try:
                api.close(handle)
            except ExternalSourceError as close_error:
                _raise_path_free(close_error)
        _raise_path_free(error)
    except BaseException:
        if handle is not None:
            try:
                api.close(handle)
            except ExternalSourceError as close_error:
                _raise_path_free(close_error)
        _raise_path_free(
            ExternalSourceError(
                ExternalSourceCode.INTERNAL_FAILURE,
                "registered source factory failed safely",
            )
        )


_seal_external_boundaries()
del (
    _create_external_boundary_runtime,
    _external_boundary_template,
    _path_free_exception_boundary,
    _register_external_boundary,
    _seal_external_boundaries,
)
