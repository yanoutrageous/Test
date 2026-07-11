from __future__ import annotations

import ctypes
import hashlib
import ntpath
import os
import re
import secrets
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterator, NoReturn, Protocol

from app.workspace_guard import (
    ExpectedKind,
    GuardedPath,
    PathIdentity,
    PathIntent,
    WorkspaceGuardError,
)


_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_SHA256_LENGTH = 64
_SAFE_FLAT_ENTRY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,178}[A-Za-z0-9])?$")


_HANDLE_WRITER_CONSTRUCTOR = object()
_MUTEX_REGISTRY_LOCK = threading.Lock()
_ACTIVE_MUTEX_NAMES: set[str] = set()
_MAX_SPENT_TICKETS = 8192


def _flat_entry_sort_key(value: tuple[str, int, int]) -> str:
    return ntpath.normcase(value[0])


class _GuardAuthority(Protocol):
    def authorize(
        self,
        requested: str | os.PathLike[str],
        *,
        intent: PathIntent,
        expected_kind: ExpectedKind,
    ) -> GuardedPath: ...

    def revalidate(self, ticket: GuardedPath) -> GuardedPath: ...

    def release(self, ticket: GuardedPath) -> bool: ...


class HandleWriterCode(StrEnum):
    UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"
    INVALID_TEST_WORKSPACE = "INVALID_TEST_WORKSPACE"
    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_TICKET = "INVALID_TICKET"
    TICKET_ALREADY_USED = "TICKET_ALREADY_USED"
    WRITER_BUSY = "WRITER_BUSY"
    GUARD_REJECTED = "GUARD_REJECTED"
    HANDLE_OPEN_FAILED = "HANDLE_OPEN_FAILED"
    HANDLE_CLOSE_FAILED = "HANDLE_CLOSE_FAILED"
    HANDLE_IDENTITY_MISMATCH = "HANDLE_IDENTITY_MISMATCH"
    REPARSE_POINT = "REPARSE_POINT"
    TYPE_MISMATCH = "TYPE_MISMATCH"
    HARDLINK_REJECTED = "HARDLINK_REJECTED"
    TARGET_CONFLICT = "TARGET_CONFLICT"
    WRITE_FAILED = "WRITE_FAILED"
    SHORT_WRITE = "SHORT_WRITE"
    FLUSH_FAILED = "FLUSH_FAILED"
    READBACK_FAILED = "READBACK_FAILED"
    PRECONDITION_FAILED = "PRECONDITION_FAILED"
    POSTCONDITION_FAILED = "POSTCONDITION_FAILED"
    DIRECTORY_SCAN_FAILED = "DIRECTORY_SCAN_FAILED"
    DIRECTORY_CHANGED = "DIRECTORY_CHANGED"
    RENAME_FAILED = "RENAME_FAILED"
    MUTATION_IN_DOUBT = "MUTATION_IN_DOUBT"
    MUTEX_BUSY = "MUTEX_BUSY"
    MUTEX_FAILED = "MUTEX_FAILED"
    TICKET_RELEASE_FAILED = "TICKET_RELEASE_FAILED"
    WRITER_SEALED = "WRITER_SEALED"


class HandleWriterError(RuntimeError):
    """Path-free failure raised by the Test-local handle kernel."""

    def __init__(
        self,
        code: HandleWriterCode,
        message: str,
        *,
        winerror: int | None = None,
    ) -> None:
        self.code = code
        self.winerror = winerror
        suffix = "" if winerror is None else f" (winerror={winerror})"
        super().__init__(f"{code.value}: {message}{suffix}")

    def __repr__(self) -> str:
        return (
            "HandleWriterError(code="
            f"'{self.code.value}', winerror={self.winerror!r}, path='<redacted>')"
        )


def _raise_handle_error_without_context(error: HandleWriterError) -> NoReturn:
    error.__traceback__ = None
    error.__context__ = None
    error.__cause__ = None
    error.__suppress_context__ = True
    raise error from None


@dataclass(frozen=True, slots=True)
class HandleWriteReceipt:
    operation: str
    size_bytes: int
    sha256: str
    object_reference: str
    capability_state: str = "TEST_LOCAL_HANDLE_VERIFIED"


@dataclass(frozen=True, slots=True)
class HandleReadResult:
    payload: bytes = field(repr=False)
    size_bytes: int
    sha256: str
    object_reference: str

    def __reduce__(self) -> Any:
        raise TypeError("verified handle read results cannot be serialized")


@dataclass(frozen=True, slots=True)
class HandleDirectoryEntry:
    name: str
    payload: bytes = field(repr=False)
    size_bytes: int
    sha256: str
    object_reference: str

    def __repr__(self) -> str:
        return (
            "HandleDirectoryEntry(name='<redacted>', size_bytes="
            f"{self.size_bytes}, sha256='{self.sha256}', object_reference='<redacted>')"
        )

    def __reduce__(self) -> Any:
        raise TypeError("verified directory entries cannot be serialized")


@dataclass(frozen=True, slots=True)
class HandleDirectorySnapshot:
    entries: tuple[HandleDirectoryEntry, ...]
    directory_reference: str
    capability_state: str = "TEST_LOCAL_FLAT_DIRECTORY_VERIFIED"

    def __repr__(self) -> str:
        return (
            "HandleDirectorySnapshot(entries='<redacted>', directory_reference="
            "'<redacted>', capability_state='TEST_LOCAL_FLAT_DIRECTORY_VERIFIED')"
        )

    def __reduce__(self) -> Any:
        raise TypeError("verified directory snapshots cannot be serialized")


@dataclass(frozen=True, slots=True)
class _ObservedHandle:
    volume_serial: int
    file_id: bytes
    file_attributes: int
    reparse_tag: int
    link_count: int
    is_directory: bool
    end_of_file: int
    last_write_time: int
    change_time: int


class _FileId128(ctypes.Structure):
    _fields_ = [("identifier", ctypes.c_ubyte * 16)]


class _FileIdInfo(ctypes.Structure):
    _fields_ = [
        ("volume_serial", ctypes.c_ulonglong),
        ("file_id", _FileId128),
    ]


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = [
        ("file_attributes", ctypes.c_ulong),
        ("reparse_tag", ctypes.c_ulong),
    ]


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


class _FileRenameInfo(ctypes.Structure):
    _fields_ = [
        ("replace_if_exists", ctypes.c_ubyte),
        ("root_directory", ctypes.c_void_p),
        ("file_name_length", ctypes.c_ulong),
        ("file_name", ctypes.c_wchar * 1),
    ]


class _FileIdBothDirectoryInfo(ctypes.Structure):
    _fields_ = [
        ("next_entry_offset", ctypes.c_ulong),
        ("file_index", ctypes.c_ulong),
        ("creation_time", ctypes.c_longlong),
        ("last_access_time", ctypes.c_longlong),
        ("last_write_time", ctypes.c_longlong),
        ("change_time", ctypes.c_longlong),
        ("end_of_file", ctypes.c_longlong),
        ("allocation_size", ctypes.c_longlong),
        ("file_attributes", ctypes.c_ulong),
        ("file_name_length", ctypes.c_ulong),
        ("ea_size", ctypes.c_ulong),
        ("short_name_length", ctypes.c_byte),
        ("short_name", ctypes.c_wchar * 12),
        ("file_id", ctypes.c_longlong),
        ("file_name", ctypes.c_wchar * 1),
    ]


class RuntimeMutexLease:
    __slots__ = (
        "_writer",
        "_api",
        "_handle",
        "_name",
        "_owner_thread",
        "abandoned",
        "_closed",
    )

    def __init__(
        self,
        writer: _WindowsHandleWriter,
        api: _WindowsApi,
        handle: int,
        *,
        name: str,
        abandoned: bool,
    ) -> None:
        self._writer = writer
        self._api = api
        self._handle = handle
        self._name = name
        self._owner_thread = threading.get_ident()
        self.abandoned = abandoned
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        release_error: HandleWriterError | None = None
        if threading.get_ident() != self._owner_thread:
            release_error = HandleWriterError(
                HandleWriterCode.MUTEX_FAILED,
                "local writer mutex must be released by its owning thread",
            )
        elif not self._api.kernel32.ReleaseMutex(self._handle):
            release_error = HandleWriterError(
                HandleWriterCode.MUTEX_FAILED,
                "Windows refused to release the local writer mutex",
                winerror=ctypes.get_last_error(),
            )
        try:
            self._api.close(self._handle)
        except HandleWriterError as exc:
            if release_error is None:
                release_error = exc
        self._closed = True
        if release_error is not None:
            self._writer._seal(HandleWriterCode.MUTEX_FAILED)
            _raise_handle_error_without_context(release_error)
        with _MUTEX_REGISTRY_LOCK:
            _ACTIVE_MUTEX_NAMES.discard(self._name)

    def __enter__(self) -> RuntimeMutexLease:
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()

    def _assert_live_owner(self, writer: _WindowsHandleWriter) -> None:
        with _MUTEX_REGISTRY_LOCK:
            valid = (
                not self._closed
                and self._handle not in {0, None}
                and self._writer is writer
                and self._api is writer._api
                and self._name == writer._mutex_name
                and self._owner_thread == threading.get_ident()
                and self._name in _ACTIVE_MUTEX_NAMES
            )
        if not valid:
            raise HandleWriterError(
                HandleWriterCode.MUTEX_FAILED,
                "local writer mutex lease is not live on its owning thread",
            )

    def __reduce__(self) -> Any:
        raise TypeError("runtime mutex leases cannot be serialized")


class _WindowsApi:
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_APPEND_DATA = 0x00000004
    FILE_READ_ATTRIBUTES = 0x00000080
    DELETE = 0x00010000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    CREATE_NEW = 1
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_FLAG_WRITE_THROUGH = 0x80000000
    FILE_BEGIN = 0
    FILE_END = 2
    FILE_BASIC_INFO = 0
    FILE_STANDARD_INFO = 1
    FILE_STREAM_INFO = 7
    FILE_ATTRIBUTE_TAG_INFO = 9
    FILE_ID_INFO = 18
    FILE_RENAME_INFO = 3
    FILE_ID_BOTH_DIRECTORY_INFO = 10
    FILE_ID_BOTH_DIRECTORY_RESTART_INFO = 11
    FILE_NAME_NORMALIZED = 0x0
    VOLUME_NAME_DOS = 0x0
    ERROR_FILE_EXISTS = 80
    ERROR_ALREADY_EXISTS = 183
    ERROR_NO_MORE_FILES = 18
    WAIT_OBJECT_0 = 0x00000000
    WAIT_ABANDONED = 0x00000080
    WAIT_TIMEOUT = 0x00000102

    def __init__(self) -> None:
        if os.name != "nt":
            raise HandleWriterError(
                HandleWriterCode.UNSUPPORTED_PLATFORM,
                "the handle kernel requires Windows",
            )
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.GetFileInformationByHandleEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
        kernel32.GetFileInformationByHandle.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_ByHandleFileInformation),
        ]
        kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
        kernel32.GetFinalPathNameByHandleW.argtypes = [
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        kernel32.WriteFile.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        kernel32.WriteFile.restype = wintypes.BOOL
        kernel32.ReadFile.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        kernel32.ReadFile.restype = wintypes.BOOL
        kernel32.SetFilePointerEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_longlong,
            ctypes.POINTER(ctypes.c_longlong),
            wintypes.DWORD,
        ]
        kernel32.SetFilePointerEx.restype = wintypes.BOOL
        kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
        kernel32.FlushFileBuffers.restype = wintypes.BOOL
        kernel32.SetFileInformationByHandle.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
        kernel32.CreateMutexW.argtypes = [
            ctypes.c_void_p,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        ]
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
        kernel32.ReleaseMutex.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        self.kernel32 = kernel32
        self.wintypes = wintypes
        self.invalid_handle = ctypes.c_void_p(-1).value

    def open_handle(
        self,
        path: Path,
        *,
        access: int,
        share: int,
        disposition: int,
        flags: int,
        conflict_code: HandleWriterCode = HandleWriterCode.HANDLE_OPEN_FAILED,
    ) -> int:
        handle = self.kernel32.CreateFileW(
            str(path),
            access,
            share,
            None,
            disposition,
            flags,
            None,
        )
        if ctypes.c_void_p(handle).value == self.invalid_handle:
            error = ctypes.get_last_error()
            code = (
                HandleWriterCode.TARGET_CONFLICT
                if error in {self.ERROR_FILE_EXISTS, self.ERROR_ALREADY_EXISTS}
                else conflict_code
            )
            raise HandleWriterError(code, "Windows refused the handle request", winerror=error)
        return int(handle)

    def close(self, handle: int) -> None:
        if not self.kernel32.CloseHandle(handle):
            raise HandleWriterError(
                HandleWriterCode.HANDLE_CLOSE_FAILED,
                "Windows refused to close an internal handle",
                winerror=ctypes.get_last_error(),
            )

    def rename_by_handle_no_replace(self, handle: int, target: Path) -> None:
        target_text = str(target)
        if "\0" in target_text:
            raise HandleWriterError(
                HandleWriterCode.INVALID_REQUEST,
                "rename target contains an invalid Windows name character",
            )
        encoded = target_text.encode("utf-16-le", "strict")
        if not encoded or len(encoded) > 64 * 1024 or len(encoded) % 2:
            raise HandleWriterError(
                HandleWriterCode.INVALID_REQUEST,
                "rename target has an invalid bounded Windows name",
            )
        name_offset = int(_FileRenameInfo.file_name.offset)
        # FILE_RENAME_INFO.FileNameLength excludes the terminator, while the
        # variable-length WCHAR buffer still needs room for one.  Supplying an
        # unterminated buffer can make a filesystem driver consume adjacent
        # bytes and append stale characters to the destination name.
        wchar_nul_size = ctypes.sizeof(ctypes.c_wchar)
        buffer = ctypes.create_string_buffer(
            name_offset + len(encoded) + wchar_nul_size
        )
        rename = ctypes.cast(buffer, ctypes.POINTER(_FileRenameInfo)).contents
        rename.replace_if_exists = 0
        rename.root_directory = None
        rename.file_name_length = len(encoded)
        ctypes.memmove(ctypes.addressof(buffer) + name_offset, encoded, len(encoded))
        if not self.kernel32.SetFileInformationByHandle(
            handle,
            self.FILE_RENAME_INFO,
            buffer,
            len(buffer),
        ):
            error = ctypes.get_last_error()
            code = (
                HandleWriterCode.TARGET_CONFLICT
                if error in {self.ERROR_FILE_EXISTS, self.ERROR_ALREADY_EXISTS}
                else HandleWriterCode.RENAME_FAILED
            )
            raise HandleWriterError(
                code,
                "Windows refused the source-handle no-replace publish",
                winerror=error,
            )

    def acquire_named_mutex(self, name: str) -> tuple[int, bool]:
        handle = self.kernel32.CreateMutexW(None, False, name)
        if not handle:
            raise HandleWriterError(
                HandleWriterCode.MUTEX_FAILED,
                "Windows refused to create or open the local writer mutex",
                winerror=ctypes.get_last_error(),
            )
        raw_handle = int(handle)
        outcome = int(self.kernel32.WaitForSingleObject(raw_handle, 0))
        if outcome in {self.WAIT_OBJECT_0, self.WAIT_ABANDONED}:
            return raw_handle, outcome == self.WAIT_ABANDONED
        try:
            self.close(raw_handle)
        except HandleWriterError:
            raise
        if outcome == self.WAIT_TIMEOUT:
            raise HandleWriterError(
                HandleWriterCode.MUTEX_BUSY,
                "another process or thread owns the local writer mutex",
            )
        raise HandleWriterError(
            HandleWriterCode.MUTEX_FAILED,
            "Windows returned an invalid local writer mutex state",
        )

    def enumerate_directory_handle(
        self,
        handle: int,
        *,
        maximum_entries: int,
    ) -> tuple[tuple[str, int, int], ...]:
        buffer_size = 64 * 1024
        rows: list[tuple[str, int, int]] = []
        information_class = self.FILE_ID_BOTH_DIRECTORY_RESTART_INFO
        while True:
            buffer = ctypes.create_string_buffer(buffer_size)
            if not self.kernel32.GetFileInformationByHandleEx(
                handle,
                information_class,
                buffer,
                buffer_size,
            ):
                error = ctypes.get_last_error()
                if error == self.ERROR_NO_MORE_FILES:
                    break
                raise HandleWriterError(
                    HandleWriterCode.DIRECTORY_SCAN_FAILED,
                    "Windows refused verified-handle directory enumeration",
                    winerror=error,
                )
            information_class = self.FILE_ID_BOTH_DIRECTORY_INFO
            offset = 0
            while True:
                if offset + _FileIdBothDirectoryInfo.file_name.offset > buffer_size:
                    raise HandleWriterError(
                        HandleWriterCode.DIRECTORY_SCAN_FAILED,
                        "Windows returned malformed directory metadata",
                    )
                row = ctypes.cast(
                    ctypes.addressof(buffer) + offset,
                    ctypes.POINTER(_FileIdBothDirectoryInfo),
                ).contents
                name_bytes = int(row.file_name_length)
                name_offset = offset + int(_FileIdBothDirectoryInfo.file_name.offset)
                if (
                    name_bytes < 2
                    or name_bytes % 2
                    or name_offset + name_bytes > buffer_size
                ):
                    raise HandleWriterError(
                        HandleWriterCode.DIRECTORY_SCAN_FAILED,
                        "Windows returned malformed directory entry name metadata",
                    )
                raw_name = ctypes.string_at(
                    ctypes.addressof(buffer) + name_offset,
                    name_bytes,
                )
                try:
                    name = raw_name.decode("utf-16-le", "strict")
                except UnicodeDecodeError:
                    raise HandleWriterError(
                        HandleWriterCode.DIRECTORY_SCAN_FAILED,
                        "Windows returned a non-Unicode directory entry name",
                    ) from None
                if name not in {".", ".."}:
                    rows.append(
                        (
                            name,
                            int(row.file_id) & 0xFFFFFFFFFFFFFFFF,
                            int(row.file_attributes),
                        )
                    )
                    if len(rows) > maximum_entries:
                        raise HandleWriterError(
                            HandleWriterCode.DIRECTORY_SCAN_FAILED,
                            "flat directory entry count exceeds its fixed limit",
                        )
                next_offset = int(row.next_entry_offset)
                if next_offset == 0:
                    break
                if next_offset % 8 or next_offset < _FileIdBothDirectoryInfo.file_name.offset:
                    raise HandleWriterError(
                        HandleWriterCode.DIRECTORY_SCAN_FAILED,
                        "Windows returned a malformed directory entry chain",
                    )
                offset += next_offset
                if offset >= buffer_size:
                    raise HandleWriterError(
                        HandleWriterCode.DIRECTORY_SCAN_FAILED,
                        "Windows returned an out-of-bounds directory entry chain",
                    )
        return tuple(rows)


class _WindowsHandleWriter:
    """Minimal Test-only writer; no production facade imports this candidate yet."""

    _MAX_IO_CHUNK = 1024 * 1024

    def __init__(
        self,
        guard: _GuardAuthority,
        *,
        _constructor: object,
        api: _WindowsApi | None = None,
        workspace_root: Path | None = None,
    ) -> None:
        if _constructor is not _HANDLE_WRITER_CONSTRUCTOR:
            raise HandleWriterError(
                HandleWriterCode.INVALID_TEST_WORKSPACE,
                "writer construction is restricted to the fixed boundary service",
            )
        self._path_authority = guard
        self._api = api or _WindowsApi()
        if workspace_root is None or not isinstance(workspace_root, Path) or not workspace_root.is_absolute():
            raise HandleWriterError(
                HandleWriterCode.INVALID_TEST_WORKSPACE,
                "writer requires its factory-bound absolute workspace root",
            )
        normalized_root = ntpath.normcase(ntpath.normpath(str(workspace_root)))
        root_digest = hashlib.sha256(
            b"M0-S3-WRITER-MUTEX-V1\0" + normalized_root.encode("utf-8", "strict")
        ).hexdigest()[:40]
        self._mutex_name = f"Local\\M0-EXAM-WRITER-{root_digest}"
        self._receipt_key = secrets.token_bytes(32)
        self._lock = threading.RLock()
        self._operation_lock = threading.Lock()
        self._issued: dict[str, GuardedPath] = {}
        self._inflight: set[str] = set()
        self._spent: dict[str, None] = {}
        self._poisoned: str | None = None
        self._seal_cleanup_failures = 0

    def authorize_create_file(self, relative_path: str | os.PathLike[str]) -> GuardedPath:
        return self._authorize(
            relative_path,
            intent=PathIntent.NEW_WRITE,
            expected_kind=ExpectedKind.FILE,
        )

    def authorize_append_file(self, relative_path: str | os.PathLike[str]) -> GuardedPath:
        return self._authorize(
            relative_path,
            intent=PathIntent.APPEND_EXISTING,
            expected_kind=ExpectedKind.FILE,
        )

    def authorize_read_file(self, relative_path: str | os.PathLike[str]) -> GuardedPath:
        return self._authorize(
            relative_path,
            intent=PathIntent.EXISTING_READ,
            expected_kind=ExpectedKind.FILE,
        )

    def acquire_runtime_mutex(self) -> RuntimeMutexLease:
        self._require_unsealed()
        with _MUTEX_REGISTRY_LOCK:
            if self._mutex_name in _ACTIVE_MUTEX_NAMES:
                raise HandleWriterError(
                    HandleWriterCode.MUTEX_BUSY,
                    "this process already owns the local writer mutex",
                )
            _ACTIVE_MUTEX_NAMES.add(self._mutex_name)
        try:
            handle, abandoned = self._api.acquire_named_mutex(self._mutex_name)
        except HandleWriterError as exc:
            with _MUTEX_REGISTRY_LOCK:
                _ACTIVE_MUTEX_NAMES.discard(self._mutex_name)
            _raise_handle_error_without_context(
                HandleWriterError(
                    exc.code,
                    "local writer mutex acquisition failed safely",
                    winerror=exc.winerror,
                )
            )
        return RuntimeMutexLease(
            self,
            self._api,
            handle,
            name=self._mutex_name,
            abandoned=abandoned,
        )

    def seal_after_indeterminate_mutation(self) -> None:
        self._seal(HandleWriterCode.MUTATION_IN_DOUBT)

    def _authorize(
        self,
        relative_path: str | os.PathLike[str],
        *,
        intent: PathIntent,
        expected_kind: ExpectedKind,
    ) -> GuardedPath:
        failure_code: str | None = None
        with self._lock:
            if self._poisoned is not None:
                raise HandleWriterError(
                    HandleWriterCode.WRITER_SEALED,
                    "writer is sealed after indeterminate handle or capability cleanup",
                )
            try:
                authorized = self._path_authority.authorize(
                    relative_path,
                    intent=intent,
                    expected_kind=expected_kind,
                )
            except WorkspaceGuardError as exc:
                failure_code = exc.code.value
                authorized = None
            if authorized is not None:
                self._issued[authorized.ticket_id] = authorized
        if authorized is None:
            raise HandleWriterError(
                HandleWriterCode.GUARD_REJECTED,
                f"Guard authorization failed ({failure_code})",
            ) from None
        return authorized

    def create_file(
        self,
        ticket: GuardedPath,
        payload: bytes,
        *,
        expected_sha256: str,
    ) -> HandleWriteReceipt:
        failure: tuple[HandleWriterCode, int | None] | None = None
        result: HandleWriteReceipt | None = None
        try:
            result = self._create_file_impl(
                ticket,
                payload,
                expected_sha256=expected_sha256,
            )
        except HandleWriterError as exc:
            failure = (exc.code, exc.winerror)
        if failure is not None:
            code, winerror = failure
            raise HandleWriterError(
                code,
                "handle-verified create failed safely",
                winerror=winerror,
            ) from None
        if result is None:
            raise HandleWriterError(
                HandleWriterCode.POSTCONDITION_FAILED,
                "handle-verified create returned no receipt",
            ) from None
        return result

    def _create_file_impl(
        self,
        ticket: GuardedPath,
        payload: bytes,
        *,
        expected_sha256: str,
    ) -> HandleWriteReceipt:
        data = self._validated_payload(payload)
        expected = self._validated_sha256(expected_sha256)
        with self._reserved(ticket, PathIntent.NEW_WRITE, ExpectedKind.FILE):
            self._require_existing_direct_parent(ticket)
            if hashlib.sha256(data).hexdigest() != expected:
                raise HandleWriterError(
                    HandleWriterCode.PRECONDITION_FAILED,
                    "declared content digest does not match the supplied bytes",
                )
            self._revalidate(ticket)
            handles = self._fence_snapshot(ticket)
            created = False
            mutation_verified = False
            try:
                self._after_fences(ticket)
                self._revalidate(ticket)
                handle = self._api.open_handle(
                    ticket.path,
                    access=self._api.GENERIC_READ | self._api.GENERIC_WRITE,
                    share=0,
                    disposition=self._api.CREATE_NEW,
                    flags=(
                        self._api.FILE_ATTRIBUTE_NORMAL
                        | self._api.FILE_FLAG_OPEN_REPARSE_POINT
                        | self._api.FILE_FLAG_WRITE_THROUGH
                    ),
                )
                handles.append(handle)
                created = True
                observed = self._observe_identity(handle)
                self._require_regular_single_link(observed)
                self._verify_final_path(handle, ticket.path)
                self._write_all(handle, data)
                self._flush(handle)
                size_bytes, digest = self._hash_handle(handle)
                after = self._observe_identity(handle)
                if (
                    size_bytes != len(data)
                    or digest != expected
                    or not self._same_object(after, observed)
                    or after.end_of_file != len(data)
                ):
                    raise HandleWriterError(
                        HandleWriterCode.POSTCONDITION_FAILED,
                        "created file did not match its exact postcondition",
                    )
                self._verify_path_matches_handle(ticket.path, observed)
                receipt = self._receipt("CREATE_FILE", observed, size_bytes, digest)
                mutation_verified = True
                return receipt
            finally:
                try:
                    self._close_all(handles)
                finally:
                    if created and not mutation_verified:
                        self._seal(HandleWriterCode.MUTATION_IN_DOUBT)

    def append_file(
        self,
        ticket: GuardedPath,
        payload: bytes,
        *,
        expected_before_size: int,
        expected_before_sha256: str,
    ) -> HandleWriteReceipt:
        failure: tuple[HandleWriterCode, int | None] | None = None
        result: HandleWriteReceipt | None = None
        try:
            result = self._append_file_impl(
                ticket,
                payload,
                expected_before_size=expected_before_size,
                expected_before_sha256=expected_before_sha256,
            )
        except HandleWriterError as exc:
            failure = (exc.code, exc.winerror)
        if failure is not None:
            code, winerror = failure
            raise HandleWriterError(
                code,
                "handle-verified append failed safely",
                winerror=winerror,
            ) from None
        if result is None:
            raise HandleWriterError(
                HandleWriterCode.POSTCONDITION_FAILED,
                "handle-verified append returned no receipt",
            ) from None
        return result

    def _append_file_impl(
        self,
        ticket: GuardedPath,
        payload: bytes,
        *,
        expected_before_size: int,
        expected_before_sha256: str,
    ) -> HandleWriteReceipt:
        data = self._validated_payload(payload)
        expected = self._validated_sha256(expected_before_sha256)
        if type(expected_before_size) is not int or expected_before_size < 0:
            raise HandleWriterError(
                HandleWriterCode.INVALID_REQUEST,
                "expected_before_size must be a non-negative integer",
            )
        with self._reserved(ticket, PathIntent.APPEND_EXISTING, ExpectedKind.FILE):
            self._revalidate(ticket)
            handles = self._fence_snapshot(ticket, omit_final=True)
            try:
                self._after_fences(ticket)
                self._revalidate(ticket)
                handle = self._api.open_handle(
                    ticket.path,
                    access=self._api.GENERIC_READ | self._api.GENERIC_WRITE,
                    share=0,
                    disposition=self._api.OPEN_EXISTING,
                    flags=self._api.FILE_FLAG_OPEN_REPARSE_POINT,
                )
                handles.append(handle)
                observed = self._observe_identity(handle)
                self._require_regular_single_link(observed)
                self._verify_identity(ticket.chain_snapshot[-1], observed)
                self._verify_final_path(handle, ticket.path)
                before_size, before_hasher = self._hash_handle_state(handle)
                before_digest = before_hasher.hexdigest()
                if (
                    before_size != expected_before_size
                    or observed.end_of_file != expected_before_size
                    or before_digest != expected
                ):
                    raise HandleWriterError(
                        HandleWriterCode.PRECONDITION_FAILED,
                        "append target changed before mutation",
                    )
                end_position = self._seek(handle, 0, self._api.FILE_END)
                if end_position != before_size:
                    raise HandleWriterError(
                        HandleWriterCode.PRECONDITION_FAILED,
                        "append target EOF changed before mutation",
                    )
                mutation_possible = True
                try:
                    self._write_all(handle, data)
                    self._flush(handle)
                    after_size, after_digest = self._hash_handle(handle)
                    expected_after = before_hasher.copy()
                    expected_after.update(data)
                    after = self._observe_identity(handle)
                    if (
                        after_size != before_size + len(data)
                        or after_digest != expected_after.hexdigest()
                        or after.end_of_file != after_size
                        or not self._same_object(after, observed)
                    ):
                        raise HandleWriterError(
                            HandleWriterCode.POSTCONDITION_FAILED,
                            "append target size did not match its exact postcondition",
                        )
                    self._verify_path_matches_handle(ticket.path, observed)
                    mutation_possible = False
                    return self._receipt("APPEND_FILE", observed, after_size, after_digest)
                finally:
                    if mutation_possible:
                        self._seal(HandleWriterCode.MUTATION_IN_DOUBT)
            finally:
                self._close_all(handles)

    def read_file(
        self,
        ticket: GuardedPath,
        *,
        maximum_bytes: int,
    ) -> HandleReadResult:
        failure: tuple[HandleWriterCode, int | None] | None = None
        result: HandleReadResult | None = None
        try:
            result = self._read_file_impl(ticket, maximum_bytes=maximum_bytes)
        except HandleWriterError as exc:
            failure = (exc.code, exc.winerror)
        if failure is not None:
            code, winerror = failure
            raise HandleWriterError(
                code,
                "handle-verified read failed safely",
                winerror=winerror,
            ) from None
        if result is None:
            raise HandleWriterError(
                HandleWriterCode.POSTCONDITION_FAILED,
                "handle-verified read returned no result",
            ) from None
        return result

    def _read_file_impl(
        self,
        ticket: GuardedPath,
        *,
        maximum_bytes: int,
    ) -> HandleReadResult:
        if type(maximum_bytes) is not int or maximum_bytes < 1 or maximum_bytes > 64 * 1024 * 1024:
            raise HandleWriterError(
                HandleWriterCode.INVALID_REQUEST,
                "verified reads require a fixed positive bound no larger than 64 MiB",
            )
        with self._reserved(ticket, PathIntent.EXISTING_READ, ExpectedKind.FILE):
            self._revalidate(ticket)
            handles = self._fence_snapshot(ticket, omit_final=True)
            try:
                handle = self._api.open_handle(
                    ticket.path,
                    access=self._api.GENERIC_READ,
                    share=self._api.FILE_SHARE_READ,
                    disposition=self._api.OPEN_EXISTING,
                    flags=self._api.FILE_FLAG_OPEN_REPARSE_POINT,
                )
                handles.append(handle)
                observed = self._observe_identity(handle)
                self._require_regular_single_link(observed)
                self._verify_identity(ticket.chain_snapshot[-1], observed)
                self._verify_final_path(handle, ticket.path)
                if observed.end_of_file < 0 or observed.end_of_file > maximum_bytes:
                    raise HandleWriterError(
                        HandleWriterCode.READBACK_FAILED,
                        "verified file exceeds its fixed read limit",
                    )
                payload = self._read_bounded_handle(handle, maximum_bytes)
                after = self._observe_identity(handle)
                digest = hashlib.sha256(payload).hexdigest()
                if (
                    len(payload) != observed.end_of_file
                    or not self._same_object(observed, after)
                    or after.end_of_file != observed.end_of_file
                    or after.last_write_time != observed.last_write_time
                    or after.change_time != observed.change_time
                ):
                    raise HandleWriterError(
                        HandleWriterCode.POSTCONDITION_FAILED,
                        "verified file changed during its bounded read",
                    )
                self._verify_path_matches_handle(ticket.path, observed)
                receipt = self._receipt("READ_FILE", observed, len(payload), digest)
                return HandleReadResult(
                    payload=payload,
                    size_bytes=len(payload),
                    sha256=digest,
                    object_reference=receipt.object_reference,
                )
            finally:
                self._close_all(handles)

    def read_flat_directory(
        self,
        relative_path: str | os.PathLike[str],
        *,
        maximum_entries: int,
        maximum_file_bytes: int,
        maximum_total_bytes: int,
    ) -> HandleDirectorySnapshot:
        self._validate_flat_scan_bounds(
            maximum_entries,
            maximum_file_bytes,
            maximum_total_bytes,
        )
        failure: tuple[HandleWriterCode, int | None] | None = None
        result: HandleDirectorySnapshot | None = None
        try:
            ticket = self._authorize(
                relative_path,
                intent=PathIntent.EXISTING_READ,
                expected_kind=ExpectedKind.DIRECTORY,
            )
            result = self._read_flat_directory_impl(
                ticket,
                maximum_entries=maximum_entries,
                maximum_file_bytes=maximum_file_bytes,
                maximum_total_bytes=maximum_total_bytes,
            )
        except HandleWriterError as exc:
            failure = (exc.code, exc.winerror)
        if failure is not None:
            code, winerror = failure
            raise HandleWriterError(
                code,
                "flat directory verification failed safely",
                winerror=winerror,
            ) from None
        if result is None:
            raise HandleWriterError(
                HandleWriterCode.DIRECTORY_SCAN_FAILED,
                "flat directory verification returned no snapshot",
            ) from None
        return result

    def _read_flat_directory_impl(
        self,
        ticket: GuardedPath,
        *,
        maximum_entries: int,
        maximum_file_bytes: int,
        maximum_total_bytes: int,
    ) -> HandleDirectorySnapshot:
        self._validate_flat_scan_bounds(
            maximum_entries,
            maximum_file_bytes,
            maximum_total_bytes,
        )
        with self._reserved(ticket, PathIntent.EXISTING_READ, ExpectedKind.DIRECTORY):
            self._revalidate(ticket)
            handles = self._fence_snapshot(ticket)
            try:
                if not handles:
                    raise HandleWriterError(
                        HandleWriterCode.DIRECTORY_SCAN_FAILED,
                        "flat directory fence is missing",
                    )
                directory_handle = handles[-1]
                directory_before = self._observe_identity(directory_handle)
                if not directory_before.is_directory:
                    raise HandleWriterError(
                        HandleWriterCode.TYPE_MISMATCH,
                        "flat directory target is not a directory",
                    )
                first_entries = self._flat_entries(
                    directory_handle,
                    maximum_entries,
                )
                total_bytes = 0
                rows: list[HandleDirectoryEntry] = []
                for name, enumerated_file_id, enumerated_attributes in first_entries:
                    child_path = ticket.path / name
                    child_handle = self._api.open_handle(
                        child_path,
                        access=self._api.GENERIC_READ,
                        share=self._api.FILE_SHARE_READ,
                        disposition=self._api.OPEN_EXISTING,
                        flags=(
                            self._api.FILE_FLAG_OPEN_REPARSE_POINT
                            | self._api.FILE_FLAG_BACKUP_SEMANTICS
                        ),
                    )
                    handles.append(child_handle)
                    observed = self._observe_identity(child_handle)
                    self._require_regular_single_link(observed)
                    self._verify_final_path(child_handle, child_path)
                    if (
                        int.from_bytes(observed.file_id[:8], "little")
                        != enumerated_file_id
                        or observed.file_attributes != enumerated_attributes
                    ):
                        raise HandleWriterError(
                            HandleWriterCode.DIRECTORY_CHANGED,
                            "directory entry handle differs from enumerated identity",
                        )
                    if observed.end_of_file < 0 or observed.end_of_file > maximum_file_bytes:
                        raise HandleWriterError(
                            HandleWriterCode.READBACK_FAILED,
                            "flat directory entry exceeds its fixed read limit",
                        )
                    payload = self._read_bounded_handle(child_handle, maximum_file_bytes)
                    total_bytes += len(payload)
                    if total_bytes > maximum_total_bytes:
                        raise HandleWriterError(
                            HandleWriterCode.READBACK_FAILED,
                            "flat directory exceeds its fixed aggregate read limit",
                        )
                    after = self._observe_identity(child_handle)
                    if (
                        len(payload) != observed.end_of_file
                        or not self._same_object(observed, after)
                        or after.end_of_file != observed.end_of_file
                        or after.last_write_time != observed.last_write_time
                        or after.change_time != observed.change_time
                    ):
                        raise HandleWriterError(
                            HandleWriterCode.DIRECTORY_CHANGED,
                            "flat directory entry changed during verified read",
                        )
                    self._verify_path_matches_handle(child_path, observed)
                    digest = hashlib.sha256(payload).hexdigest()
                    receipt = self._receipt("READ_DIRECTORY_ENTRY", observed, len(payload), digest)
                    rows.append(
                        HandleDirectoryEntry(
                            name=name,
                            payload=payload,
                            size_bytes=len(payload),
                            sha256=digest,
                            object_reference=receipt.object_reference,
                        )
                    )
                second_entries = self._flat_entries(
                    directory_handle,
                    maximum_entries,
                )
                directory_after = self._observe_identity(directory_handle)
                if (
                    first_entries != second_entries
                    or not self._same_object(directory_before, directory_after)
                    or directory_before.last_write_time != directory_after.last_write_time
                    or directory_before.change_time != directory_after.change_time
                ):
                    raise HandleWriterError(
                        HandleWriterCode.DIRECTORY_CHANGED,
                        "flat directory changed during its bounded snapshot",
                    )
                listing_digest = hashlib.sha256(
                    b"M0-S3-FLAT-DIRECTORY-V1\0"
                    + b"\0".join(
                        row.name.encode("ascii") + b"\0" + bytes.fromhex(row.sha256)
                        for row in rows
                    )
                ).hexdigest()
                directory_receipt = self._receipt(
                    "READ_FLAT_DIRECTORY",
                    directory_before,
                    total_bytes,
                    listing_digest,
                )
                return HandleDirectorySnapshot(
                    entries=tuple(rows),
                    directory_reference=directory_receipt.object_reference,
                )
            finally:
                self._close_all(handles)

    @staticmethod
    def _validate_flat_scan_bounds(
        maximum_entries: int,
        maximum_file_bytes: int,
        maximum_total_bytes: int,
    ) -> None:
        if (
            type(maximum_entries) is not int
            or maximum_entries < 1
            or maximum_entries > 4096
            or type(maximum_file_bytes) is not int
            or maximum_file_bytes < 1
            or maximum_file_bytes > 16 * 1024 * 1024
            or type(maximum_total_bytes) is not int
            or maximum_total_bytes < maximum_file_bytes
            or maximum_total_bytes > 64 * 1024 * 1024
        ):
            raise HandleWriterError(
                HandleWriterCode.INVALID_REQUEST,
                "flat directory scan bounds are invalid",
            )

    def _flat_entries(
        self,
        directory_handle: int,
        maximum_entries: int,
    ) -> tuple[tuple[str, int, int], ...]:
        entries = self._api.enumerate_directory_handle(
            directory_handle,
            maximum_entries=maximum_entries,
        )
        normalized: set[str] = set()
        for name, _file_id, _attributes in entries:
            if not _SAFE_FLAT_ENTRY.fullmatch(name) or name in {".", ".."}:
                raise HandleWriterError(
                    HandleWriterCode.DIRECTORY_SCAN_FAILED,
                    "flat directory contains a non-canonical entry name",
                )
            folded = name.casefold()
            if folded in normalized:
                raise HandleWriterError(
                    HandleWriterCode.DIRECTORY_SCAN_FAILED,
                    "flat directory contains a case-colliding entry name",
                )
            normalized.add(folded)
        return tuple(sorted(entries, key=_flat_entry_sort_key))

    def publish_new_file(
        self,
        staging_relative_path: str | os.PathLike[str],
        target_relative_path: str | os.PathLike[str],
        payload: bytes,
        *,
        expected_sha256: str,
    ) -> HandleWriteReceipt:
        data = self._validated_payload(payload)
        expected = self._validated_sha256(expected_sha256)
        if hashlib.sha256(data).hexdigest() != expected:
            raise HandleWriterError(
                HandleWriterCode.PRECONDITION_FAILED,
                "declared publish digest does not match the supplied bytes",
            ) from None
        staging: GuardedPath | None = None
        target: GuardedPath | None = None
        failure: tuple[HandleWriterCode, int | None] | None = None
        result: HandleWriteReceipt | None = None
        try:
            staging = self.authorize_create_file(staging_relative_path)
            try:
                target = self.authorize_create_file(target_relative_path)
            except BaseException:
                self._discard_issued_ticket(staging)
                raise
            result = self._publish_new_file_impl(staging, target, data, expected)
        except HandleWriterError as exc:
            failure = (exc.code, exc.winerror)
        except Exception:
            self._seal(HandleWriterCode.MUTATION_IN_DOUBT)
            failure = (HandleWriterCode.MUTATION_IN_DOUBT, None)
        if failure is not None:
            code, winerror = failure
            raise HandleWriterError(
                code,
                "handle-verified no-replace publish failed safely",
                winerror=winerror,
            ) from None
        if result is None:
            self._seal(HandleWriterCode.MUTATION_IN_DOUBT)
            raise HandleWriterError(
                HandleWriterCode.MUTATION_IN_DOUBT,
                "handle-verified no-replace publish returned no receipt",
            ) from None
        return result

    def _publish_new_file_impl(
        self,
        staging: GuardedPath,
        target: GuardedPath,
        payload: bytes,
        expected_sha256: str,
    ) -> HandleWriteReceipt:
        if ntpath.normcase(ntpath.normpath(str(staging.path.parent))) != ntpath.normcase(
            ntpath.normpath(str(target.path.parent))
        ) or ntpath.normcase(str(staging.path)) == ntpath.normcase(str(target.path)):
            raise HandleWriterError(
                HandleWriterCode.INVALID_REQUEST,
                "no-replace publish requires distinct files in one verified directory",
            )
        self._require_existing_direct_parent(staging)
        self._require_existing_direct_parent(target)
        with self._reserved_group(
            (
                (staging, PathIntent.NEW_WRITE, ExpectedKind.FILE),
                (target, PathIntent.NEW_WRITE, ExpectedKind.FILE),
            )
        ):
            self._revalidate(staging)
            self._revalidate(target)
            staging_parent = staging.chain_snapshot[-1]
            target_parent = target.chain_snapshot[-1]
            if (
                staging_parent.device != target_parent.device
                or staging_parent.inode != target_parent.inode
            ):
                raise HandleWriterError(
                    HandleWriterCode.PRECONDITION_FAILED,
                    "publish paths do not share one verified parent object",
                )
            handles = self._fence_snapshot(staging)
            stage_created = False
            mutation_verified = False
            try:
                self._after_fences(staging)
                self._revalidate(staging)
                self._revalidate(target)
                source_handle = self._api.open_handle(
                    staging.path,
                    access=(
                        self._api.GENERIC_READ
                        | self._api.GENERIC_WRITE
                        | self._api.DELETE
                    ),
                    share=self._api.FILE_SHARE_READ,
                    disposition=self._api.CREATE_NEW,
                    flags=(
                        self._api.FILE_ATTRIBUTE_NORMAL
                        | self._api.FILE_FLAG_OPEN_REPARSE_POINT
                        | self._api.FILE_FLAG_WRITE_THROUGH
                    ),
                )
                handles.append(source_handle)
                stage_created = True
                source_observed = self._observe_identity(source_handle)
                self._require_regular_single_link(source_observed)
                self._verify_final_path(source_handle, staging.path)
                self._write_all(source_handle, payload)
                self._flush(source_handle)
                source_size, source_digest = self._hash_handle(source_handle)
                source_after_write = self._observe_identity(source_handle)
                if (
                    source_size != len(payload)
                    or source_digest != expected_sha256
                    or not self._same_object(source_observed, source_after_write)
                    or source_after_write.end_of_file != source_size
                ):
                    raise HandleWriterError(
                        HandleWriterCode.POSTCONDITION_FAILED,
                        "staging file failed its exact write postcondition",
                    )
                verification_handle = self._api.open_handle(
                    staging.path,
                    access=self._api.GENERIC_READ,
                    share=(
                        self._api.FILE_SHARE_READ
                        | self._api.FILE_SHARE_WRITE
                        | self._api.FILE_SHARE_DELETE
                    ),
                    disposition=self._api.OPEN_EXISTING,
                    flags=self._api.FILE_FLAG_OPEN_REPARSE_POINT,
                )
                handles.append(verification_handle)
                verification_observed = self._observe_identity(verification_handle)
                self._require_regular_single_link(verification_observed)
                self._verify_final_path(verification_handle, staging.path)
                verify_size, verify_digest = self._hash_handle(verification_handle)
                if (
                    not self._same_object(source_observed, verification_observed)
                    or verify_size != source_size
                    or verify_digest != source_digest
                ):
                    raise HandleWriterError(
                        HandleWriterCode.POSTCONDITION_FAILED,
                        "reopened staging file differs from its source handle",
                    )
                self._api.close(verification_handle)
                handles.pop()
                self._after_stage_verified(staging, target)
                self._api.rename_by_handle_no_replace(source_handle, target.path)
                self._after_publish(staging, target)
                renamed_observed = self._observe_identity(source_handle)
                self._verify_final_path(source_handle, target.path)
                renamed_size, renamed_digest = self._hash_handle(source_handle)
                if (
                    not self._same_object(source_observed, renamed_observed)
                    or renamed_size != source_size
                    or renamed_digest != source_digest
                    or os.path.lexists(staging.path)
                ):
                    raise HandleWriterError(
                        HandleWriterCode.POSTCONDITION_FAILED,
                        "published source handle failed its final target postcondition",
                    )
                self._verify_path_matches_handle(target.path, source_observed)
                final_handle = self._api.open_handle(
                    target.path,
                    access=self._api.GENERIC_READ,
                    share=(
                        self._api.FILE_SHARE_READ
                        | self._api.FILE_SHARE_WRITE
                        | self._api.FILE_SHARE_DELETE
                    ),
                    disposition=self._api.OPEN_EXISTING,
                    flags=self._api.FILE_FLAG_OPEN_REPARSE_POINT,
                )
                handles.append(final_handle)
                final_observed = self._observe_identity(final_handle)
                self._require_regular_single_link(final_observed)
                self._verify_final_path(final_handle, target.path)
                final_size, final_digest = self._hash_handle(final_handle)
                if (
                    not self._same_object(source_observed, final_observed)
                    or final_size != source_size
                    or final_digest != source_digest
                ):
                    raise HandleWriterError(
                        HandleWriterCode.POSTCONDITION_FAILED,
                        "independently reopened final file failed verification",
                    )
                mutation_verified = True
                return self._receipt(
                    "PUBLISH_NEW_FILE",
                    source_observed,
                    final_size,
                    final_digest,
                )
            finally:
                if stage_created and not mutation_verified:
                    self._seal(HandleWriterCode.MUTATION_IN_DOUBT)
                self._close_all(handles)

    def _discard_issued_ticket(self, ticket: GuardedPath) -> None:
        with self._lock:
            issued = self._issued.pop(ticket.ticket_id, None)
        if issued is not ticket:
            self._seal(HandleWriterCode.TICKET_RELEASE_FAILED)
            raise HandleWriterError(
                HandleWriterCode.TICKET_RELEASE_FAILED,
                "unused writer capability could not be recovered",
            )
        try:
            released = self._path_authority.release(ticket)
        except BaseException:
            released = False
        with self._lock:
            self._remember_spent(ticket.ticket_id)
        if not released:
            self._seal(HandleWriterCode.TICKET_RELEASE_FAILED)
            raise HandleWriterError(
                HandleWriterCode.TICKET_RELEASE_FAILED,
                "unused writer capability could not be released",
            )

    @staticmethod
    def _validated_payload(payload: bytes) -> bytes:
        if type(payload) is not bytes:
            raise HandleWriterError(
                HandleWriterCode.INVALID_REQUEST,
                "payload must be exact immutable bytes",
            )
        return payload

    @staticmethod
    def _validated_sha256(value: str) -> str:
        if (
            type(value) is not str
            or len(value) != _SHA256_LENGTH
            or value != value.casefold()
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise HandleWriterError(
                HandleWriterCode.INVALID_REQUEST,
                "SHA-256 preconditions must be lowercase hexadecimal",
            )
        return value

    @contextmanager
    def _reserved(
        self,
        ticket: GuardedPath,
        intent: PathIntent,
        expected_kind: ExpectedKind,
    ) -> Iterator[None]:
        with self._reserved_group(((ticket, intent, expected_kind),)):
            yield

    @contextmanager
    def _reserved_group(
        self,
        specifications: tuple[tuple[GuardedPath, PathIntent, ExpectedKind], ...],
    ) -> Iterator[None]:
        if not specifications or len(specifications) > 2:
            raise HandleWriterError(
                HandleWriterCode.INVALID_TICKET,
                "writer reservation requires one or two exact capabilities",
            )
        tickets: list[GuardedPath] = []
        for ticket, intent, expected_kind in specifications:
            if type(ticket) is not GuardedPath:
                raise HandleWriterError(
                    HandleWriterCode.INVALID_TICKET,
                    "writer requires an exact GuardedPath ticket",
                )
            if ticket.intent is not intent or ticket.expected_kind is not expected_kind:
                raise HandleWriterError(
                    HandleWriterCode.INVALID_TICKET,
                    "ticket operation does not match the requested writer primitive",
                )
            tickets.append(ticket)
        ticket_ids = tuple(ticket.ticket_id for ticket in tickets)
        if len(set(ticket_ids)) != len(ticket_ids):
            raise HandleWriterError(
                HandleWriterCode.INVALID_TICKET,
                "writer reservation capabilities must be distinct",
            )
        if not self._operation_lock.acquire(blocking=False):
            with self._lock:
                code = (
                    HandleWriterCode.TICKET_ALREADY_USED
                    if any(
                        ticket_id in self._inflight or ticket_id in self._spent
                        for ticket_id in ticket_ids
                    )
                    else HandleWriterCode.WRITER_BUSY
                )
            raise HandleWriterError(
                code,
                "writer already has an active mutation",
            )
        try:
            with self._lock:
                if self._poisoned is not None:
                    raise HandleWriterError(
                        HandleWriterCode.WRITER_SEALED,
                        "writer is sealed after indeterminate handle or capability cleanup",
                    )
                for ticket in tickets:
                    ticket_id = ticket.ticket_id
                    issued = self._issued.get(ticket_id)
                    if (
                        issued is not ticket
                        or ticket_id in self._inflight
                        or ticket_id in self._spent
                    ):
                        raise HandleWriterError(
                            HandleWriterCode.TICKET_ALREADY_USED,
                            "writer capability is unknown or already used",
                        )
                for ticket_id in ticket_ids:
                    self._issued.pop(ticket_id)
                    self._inflight.add(ticket_id)
            primary_error: BaseException | None = None
            primary_traceback = None
            try:
                yield
            except BaseException as exc:
                primary_error = exc
                primary_traceback = exc.__traceback__
            release_error: HandleWriterError | None = None
            for ticket in tickets:
                try:
                    released = self._path_authority.release(ticket)
                    if not released and release_error is None:
                        release_error = HandleWriterError(
                            HandleWriterCode.TICKET_RELEASE_FAILED,
                            "writer capability had already left the Guard registry",
                        )
                except BaseException:
                    if release_error is None:
                        release_error = HandleWriterError(
                            HandleWriterCode.TICKET_RELEASE_FAILED,
                            "writer could not release its Guard capability",
                        )
            with self._lock:
                for ticket_id in ticket_ids:
                    self._inflight.discard(ticket_id)
                    self._remember_spent(ticket_id)
            if release_error is not None:
                self._seal(HandleWriterCode.TICKET_RELEASE_FAILED)
                if (
                    isinstance(primary_error, HandleWriterError)
                    and primary_error.code is HandleWriterCode.HANDLE_CLOSE_FAILED
                ):
                    _raise_handle_error_without_context(primary_error)
                _raise_handle_error_without_context(release_error)
            if primary_error is not None:
                raise primary_error.with_traceback(primary_traceback)
        finally:
            self._operation_lock.release()

    def _require_unsealed(self) -> None:
        with self._lock:
            if self._poisoned is not None:
                raise HandleWriterError(
                    HandleWriterCode.WRITER_SEALED,
                    "writer is sealed after indeterminate handle or capability cleanup",
                )

    @staticmethod
    def _require_existing_direct_parent(ticket: GuardedPath) -> None:
        parent = ntpath.normcase(ntpath.normpath(str(ticket.path.parent)))
        nearest = ntpath.normcase(
            ntpath.normpath(str(ticket.nearest_existing_ancestor))
        )
        chain_parent = (
            ntpath.normcase(ntpath.normpath(str(ticket.chain_snapshot[-1].path)))
            if ticket.chain_snapshot
            else ""
        )
        if parent != nearest or parent != chain_parent:
            raise HandleWriterError(
                HandleWriterCode.PRECONDITION_FAILED,
                "create-file requires a pre-existing verified direct parent",
            )

    def _seal(self, code: HandleWriterCode) -> None:
        with self._lock:
            if self._poisoned is None:
                self._poisoned = code.value
            unused = tuple(self._issued.values())
            self._issued.clear()
        cleanup_failures = 0
        for ticket in unused:
            try:
                released = self._path_authority.release(ticket)
                if not released:
                    cleanup_failures += 1
            except BaseException:
                cleanup_failures += 1
        if cleanup_failures:
            with self._lock:
                self._seal_cleanup_failures += cleanup_failures

    def _remember_spent(self, ticket_id: str) -> None:
        self._spent[ticket_id] = None
        while len(self._spent) > _MAX_SPENT_TICKETS:
            self._spent.pop(next(iter(self._spent)))

    def _fence_snapshot(
        self,
        ticket: GuardedPath,
        *,
        omit_final: bool = False,
    ) -> list[int]:
        identities = ticket.chain_snapshot[:-1] if omit_final else ticket.chain_snapshot
        handles: list[int] = []
        seen: set[str] = set()
        try:
            for identity in identities:
                normalized = ntpath.normcase(str(identity.path))
                if normalized in seen:
                    continue
                seen.add(normalized)
                flags = self._api.FILE_FLAG_OPEN_REPARSE_POINT
                share = self._api.FILE_SHARE_READ
                if stat.S_ISDIR(identity.mode):
                    flags |= self._api.FILE_FLAG_BACKUP_SEMANTICS
                    share |= self._api.FILE_SHARE_WRITE
                handle = self._api.open_handle(
                    identity.path,
                    access=self._api.GENERIC_READ,
                    share=share,
                    disposition=self._api.OPEN_EXISTING,
                    flags=flags,
                )
                handles.append(handle)
                observed = self._observe_identity(handle)
                self._verify_identity(identity, observed)
                self._verify_final_path(handle, identity.path)
            return handles
        except BaseException:
            self._close_all(handles)
            raise

    def _revalidate(self, ticket: GuardedPath) -> None:
        failure_code: str | None = None
        try:
            self._path_authority.revalidate(ticket)
        except WorkspaceGuardError as exc:
            failure_code = exc.code.value
        if failure_code is not None:
            raise HandleWriterError(
                HandleWriterCode.GUARD_REJECTED,
                f"Guard revalidation failed ({failure_code})",
            ) from None

    def _observe_identity(self, handle: int) -> _ObservedHandle:
        file_id = _FileIdInfo()
        if not self._api.kernel32.GetFileInformationByHandleEx(
            handle,
            self._api.FILE_ID_INFO,
            ctypes.byref(file_id),
            ctypes.sizeof(file_id),
        ):
            raise HandleWriterError(
                HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                "cannot read handle file identity",
                winerror=ctypes.get_last_error(),
            )
        tag = _FileAttributeTagInfo()
        if not self._api.kernel32.GetFileInformationByHandleEx(
            handle,
            self._api.FILE_ATTRIBUTE_TAG_INFO,
            ctypes.byref(tag),
            ctypes.sizeof(tag),
        ):
            raise HandleWriterError(
                HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                "cannot read handle attribute identity",
                winerror=ctypes.get_last_error(),
            )
        basic = _FileBasicInfo()
        if not self._api.kernel32.GetFileInformationByHandleEx(
            handle,
            self._api.FILE_BASIC_INFO,
            ctypes.byref(basic),
            ctypes.sizeof(basic),
        ):
            raise HandleWriterError(
                HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                "cannot read handle basic identity",
                winerror=ctypes.get_last_error(),
            )
        standard = _FileStandardInfo()
        if not self._api.kernel32.GetFileInformationByHandleEx(
            handle,
            self._api.FILE_STANDARD_INFO,
            ctypes.byref(standard),
            ctypes.sizeof(standard),
        ):
            raise HandleWriterError(
                HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                "cannot read handle standard identity",
                winerror=ctypes.get_last_error(),
            )
        legacy = _ByHandleFileInformation()
        if not self._api.kernel32.GetFileInformationByHandle(
            handle,
            ctypes.byref(legacy),
        ):
            raise HandleWriterError(
                HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                "cannot read handle link identity",
                winerror=ctypes.get_last_error(),
            )
        file_id_bytes = bytes(file_id.file_id.identifier)
        file_id_low = int.from_bytes(file_id_bytes[:8], "little")
        legacy_id = (int(legacy.file_index_high) << 32) | int(legacy.file_index_low)
        if (
            int(file_id.volume_serial) & 0xFFFFFFFF != int(legacy.volume_serial)
            or file_id_low != legacy_id
            or any(file_id_bytes[8:])
        ):
            raise HandleWriterError(
                HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                "Windows identity APIs returned incompatible object IDs",
            )
        attributes = int(tag.file_attributes)
        reparse_tag = int(tag.reparse_tag)
        if attributes != int(basic.file_attributes):
            raise HandleWriterError(
                HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                "Windows attribute APIs returned incompatible values",
            )
        if attributes & _REPARSE_ATTRIBUTE or reparse_tag:
            raise HandleWriterError(
                HandleWriterCode.REPARSE_POINT,
                "reparse objects are forbidden",
            )
        if bool(standard.delete_pending):
            raise HandleWriterError(
                HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                "delete-pending objects are forbidden",
            )
        if int(standard.number_of_links) != int(legacy.link_count):
            raise HandleWriterError(
                HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                "Windows link-count APIs returned incompatible values",
            )
        is_directory = bool(standard.directory)
        if is_directory != bool(attributes & self._api.FILE_ATTRIBUTE_DIRECTORY):
            raise HandleWriterError(
                HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                "Windows type APIs returned incompatible values",
            )
        if not is_directory:
            self._require_default_stream_only(handle)
        return _ObservedHandle(
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

    def _require_default_stream_only(self, handle: int) -> None:
        buffer_size = 64 * 1024
        buffer = ctypes.create_string_buffer(buffer_size)
        if not self._api.kernel32.GetFileInformationByHandleEx(
            handle,
            self._api.FILE_STREAM_INFO,
            buffer,
            buffer_size,
        ):
            raise HandleWriterError(
                HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                "cannot enumerate file data streams",
                winerror=ctypes.get_last_error(),
            )
        names: list[str] = []
        offset = 0
        while True:
            if offset + 24 > buffer_size:
                raise HandleWriterError(
                    HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                    "file stream metadata was malformed",
                )
            next_offset = int.from_bytes(buffer.raw[offset : offset + 4], "little")
            name_bytes = int.from_bytes(buffer.raw[offset + 4 : offset + 8], "little")
            name_start = offset + 24
            name_end = name_start + name_bytes
            if name_bytes % 2 or name_end > buffer_size:
                raise HandleWriterError(
                    HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                    "file stream metadata was malformed",
                )
            names.append(
                str(buffer.raw[name_start:name_end], "utf-16-le", "strict")
            )
            if next_offset == 0:
                break
            if next_offset < 24 + name_bytes or offset + next_offset >= buffer_size:
                raise HandleWriterError(
                    HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                    "file stream metadata was malformed",
                )
            offset += next_offset
        if names != ["::$DATA"]:
            raise HandleWriterError(
                HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                "alternate data streams are forbidden",
            )

    def _verify_final_path(self, handle: int, expected: Path) -> None:
        buffer_size = 32768
        buffer = ctypes.create_unicode_buffer(buffer_size)
        returned = int(
            self._api.kernel32.GetFinalPathNameByHandleW(
                handle,
                buffer,
                buffer_size,
                self._api.FILE_NAME_NORMALIZED | self._api.VOLUME_NAME_DOS,
            )
        )
        if returned == 0 or returned >= buffer_size:
            raise HandleWriterError(
                HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                "cannot bind the handle to its normalized final name",
                winerror=ctypes.get_last_error() if returned == 0 else None,
            )
        actual = buffer.value
        if actual.startswith("\\\\?\\"):
            actual = actual[4:]
        if ntpath.normcase(ntpath.normpath(actual)) != ntpath.normcase(
            ntpath.normpath(str(expected))
        ):
            raise HandleWriterError(
                HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                "handle final name differs from the authorized object",
            )

    def _verify_identity(
        self,
        expected: PathIdentity,
        observed: _ObservedHandle,
    ) -> None:
        expected_directory = stat.S_ISDIR(expected.mode)
        expected_regular = stat.S_ISREG(expected.mode)
        observed_file_id = int.from_bytes(observed.file_id, "little")
        if (
            observed.volume_serial != expected.device
            or observed_file_id != expected.inode
            or observed.link_count != expected.nlink
            or observed.is_directory != expected_directory
            or (not expected_directory and not expected_regular)
            or expected.file_attributes & _REPARSE_ATTRIBUTE
            or expected.reparse_tag
        ):
            raise HandleWriterError(
                HandleWriterCode.HANDLE_IDENTITY_MISMATCH,
                "opened handle does not match the authorized object",
            )

    def _verify_path_matches_handle(
        self,
        path: Path,
        observed: _ObservedHandle,
    ) -> None:
        try:
            current = os.lstat(path)
        except OSError:
            current = None
        if current is None:
            raise HandleWriterError(
                HandleWriterCode.POSTCONDITION_FAILED,
                "published object cannot be inspected",
            ) from None
        if (
            int(current.st_dev) != observed.volume_serial
            or int(current.st_ino) != int.from_bytes(observed.file_id, "little")
            or int(current.st_nlink) != observed.link_count
            or bool(stat.S_ISDIR(current.st_mode)) != observed.is_directory
            or int(getattr(current, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
            or int(getattr(current, "st_reparse_tag", 0))
        ):
            raise HandleWriterError(
                HandleWriterCode.POSTCONDITION_FAILED,
                "path no longer names the verified handle object",
            )

    @staticmethod
    def _require_regular_single_link(observed: _ObservedHandle) -> None:
        if observed.is_directory:
            raise HandleWriterError(
                HandleWriterCode.TYPE_MISMATCH,
                "writer target is not a regular file",
            )
        if observed.link_count != 1:
            raise HandleWriterError(
                HandleWriterCode.HARDLINK_REJECTED,
                "writer target has multiple hard links",
            )

    @staticmethod
    def _same_object(left: _ObservedHandle, right: _ObservedHandle) -> bool:
        return (
            left.volume_serial == right.volume_serial
            and left.file_id == right.file_id
            and left.link_count == right.link_count
            and left.is_directory == right.is_directory
            and left.file_attributes == right.file_attributes
            and left.reparse_tag == right.reparse_tag
        )

    def _write_once(self, handle: int, payload: bytes) -> int:
        if not payload:
            return 0
        buffer = ctypes.create_string_buffer(payload, len(payload))
        written = self._api.wintypes.DWORD(0)
        if not self._api.kernel32.WriteFile(
            handle,
            buffer,
            len(payload),
            ctypes.byref(written),
            None,
        ):
            raise HandleWriterError(
                HandleWriterCode.WRITE_FAILED,
                "Windows refused the file write",
                winerror=ctypes.get_last_error(),
            )
        return int(written.value)

    def _write_all(self, handle: int, payload: bytes) -> None:
        offset = 0
        while offset < len(payload):
            chunk = payload[offset : offset + self._MAX_IO_CHUNK]
            written = self._write_once(handle, chunk)
            if written != len(chunk):
                raise HandleWriterError(
                    HandleWriterCode.SHORT_WRITE,
                    "regular-file write did not complete its requested chunk",
                )
            offset += written

    def _flush(self, handle: int) -> None:
        if not self._api.kernel32.FlushFileBuffers(handle):
            raise HandleWriterError(
                HandleWriterCode.FLUSH_FAILED,
                "Windows refused to flush the file handle",
                winerror=ctypes.get_last_error(),
            )

    def _seek(self, handle: int, distance: int, origin: int) -> int:
        position = ctypes.c_longlong(0)
        if not self._api.kernel32.SetFilePointerEx(
            handle,
            distance,
            ctypes.byref(position),
            origin,
        ):
            raise HandleWriterError(
                HandleWriterCode.READBACK_FAILED,
                "Windows refused to seek the verified handle",
                winerror=ctypes.get_last_error(),
            )
        return int(position.value)

    def _hash_handle(self, handle: int) -> tuple[int, str]:
        total, digest = self._hash_handle_state(handle)
        return total, digest.hexdigest()

    def _read_bounded_handle(self, handle: int, maximum_bytes: int) -> bytes:
        if type(maximum_bytes) is not int or maximum_bytes < 1:
            raise HandleWriterError(
                HandleWriterCode.INVALID_REQUEST,
                "bounded handle reads require a positive maximum",
            )
        self._seek(handle, 0, self._api.FILE_BEGIN)
        chunks: list[bytes] = []
        total = 0
        while True:
            request = min(self._MAX_IO_CHUNK, maximum_bytes + 1 - total)
            if request <= 0:
                raise HandleWriterError(
                    HandleWriterCode.READBACK_FAILED,
                    "verified handle content exceeds its fixed read limit",
                )
            buffer = ctypes.create_string_buffer(request)
            returned = self._api.wintypes.DWORD(0)
            if not self._api.kernel32.ReadFile(
                handle,
                buffer,
                request,
                ctypes.byref(returned),
                None,
            ):
                raise HandleWriterError(
                    HandleWriterCode.READBACK_FAILED,
                    "Windows refused a bounded verified-handle read",
                    winerror=ctypes.get_last_error(),
                )
            count = int(returned.value)
            if count == 0:
                return b"".join(chunks)
            total += count
            if total > maximum_bytes:
                raise HandleWriterError(
                    HandleWriterCode.READBACK_FAILED,
                    "verified handle content exceeds its fixed read limit",
                )
            chunks.append(buffer.raw[:count])

    def _hash_handle_state(self, handle: int) -> tuple[int, Any]:
        self._seek(handle, 0, self._api.FILE_BEGIN)
        digest = hashlib.sha256()
        total = 0
        while True:
            buffer = ctypes.create_string_buffer(self._MAX_IO_CHUNK)
            returned = self._api.wintypes.DWORD(0)
            if not self._api.kernel32.ReadFile(
                handle,
                buffer,
                self._MAX_IO_CHUNK,
                ctypes.byref(returned),
                None,
            ):
                raise HandleWriterError(
                    HandleWriterCode.READBACK_FAILED,
                    "Windows refused to read back the verified handle",
                    winerror=ctypes.get_last_error(),
                )
            count = int(returned.value)
            if count == 0:
                break
            digest.update(buffer.raw[:count])
            total += count
        return total, digest

    def _receipt(
        self,
        operation: str,
        observed: _ObservedHandle,
        size_bytes: int,
        digest: str,
    ) -> HandleWriteReceipt:
        reference = hashlib.sha256(
            b"M0-S3-TEST-OBJECT-V1\0"
            + self._receipt_key
            + observed.volume_serial.to_bytes(8, "little")
            + observed.file_id
        ).hexdigest()
        return HandleWriteReceipt(
            operation=operation,
            size_bytes=size_bytes,
            sha256=digest,
            object_reference=reference,
        )

    def _close_all(self, handles: list[int]) -> None:
        close_error: HandleWriterError | None = None
        for handle in reversed(handles):
            try:
                self._api.close(handle)
            except HandleWriterError as exc:
                if close_error is None:
                    close_error = exc
            except BaseException:
                if close_error is None:
                    close_error = HandleWriterError(
                        HandleWriterCode.HANDLE_CLOSE_FAILED,
                        "internal handle close raised an unexpected failure",
                    )
        if close_error is not None:
            self._seal(HandleWriterCode.HANDLE_CLOSE_FAILED)
            raise close_error

    def _after_fences(self, ticket: GuardedPath) -> None:
        """Trusted-test injection point; production integration will not expose it."""

    def _after_stage_verified(
        self,
        staging: GuardedPath,
        target: GuardedPath,
    ) -> None:
        """Trusted-test crash injection point immediately before no-replace publish."""

    def _after_publish(
        self,
        staging: GuardedPath,
        target: GuardedPath,
    ) -> None:
        """Trusted-test crash injection point immediately after handle rename."""
