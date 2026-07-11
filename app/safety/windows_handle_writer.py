from __future__ import annotations

import ctypes
import hashlib
import ntpath
import os
import secrets
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
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


_HANDLE_WRITER_CONSTRUCTOR = object()


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


class _WindowsApi:
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_APPEND_DATA = 0x00000004
    FILE_READ_ATTRIBUTES = 0x00000080
    DELETE = 0x00010000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
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
    FILE_NAME_NORMALIZED = 0x0
    VOLUME_NAME_DOS = 0x0
    ERROR_FILE_EXISTS = 80
    ERROR_ALREADY_EXISTS = 183

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


class _WindowsHandleWriter:
    """Minimal Test-only writer; no production facade imports this candidate yet."""

    _MAX_IO_CHUNK = 1024 * 1024

    def __init__(
        self,
        guard: _GuardAuthority,
        *,
        _constructor: object,
        api: _WindowsApi | None = None,
    ) -> None:
        if _constructor is not _HANDLE_WRITER_CONSTRUCTOR:
            raise HandleWriterError(
                HandleWriterCode.INVALID_TEST_WORKSPACE,
                "writer construction is restricted to the fixed boundary service",
            )
        self._path_authority = guard
        self._api = api or _WindowsApi()
        self._receipt_key = secrets.token_bytes(32)
        self._lock = threading.RLock()
        self._operation_lock = threading.Lock()
        self._issued: dict[str, GuardedPath] = {}
        self._inflight: set[str] = set()
        self._spent: set[str] = set()
        self._poisoned: str | None = None

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
                return self._receipt("CREATE_FILE", observed, size_bytes, digest)
            finally:
                self._close_all(handles)

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
                return self._receipt("APPEND_FILE", observed, after_size, after_digest)
            finally:
                self._close_all(handles)

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
        ticket_id = ticket.ticket_id
        if not self._operation_lock.acquire(blocking=False):
            with self._lock:
                code = (
                    HandleWriterCode.TICKET_ALREADY_USED
                    if ticket_id in self._inflight or ticket_id in self._spent
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
            try:
                released = self._path_authority.release(ticket)
                if not released:
                    release_error = HandleWriterError(
                        HandleWriterCode.TICKET_RELEASE_FAILED,
                        "writer capability had already left the Guard registry",
                    )
            except BaseException:
                release_error = HandleWriterError(
                    HandleWriterCode.TICKET_RELEASE_FAILED,
                    "writer could not release its Guard capability",
                )
            with self._lock:
                self._inflight.discard(ticket_id)
                self._spent.add(ticket_id)
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
        for ticket in unused:
            try:
                self._path_authority.release(ticket)
            except BaseException:
                pass

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
                if stat.S_ISDIR(identity.mode):
                    flags |= self._api.FILE_FLAG_BACKUP_SEMANTICS
                handle = self._api.open_handle(
                    identity.path,
                    access=self._api.GENERIC_READ,
                    share=self._api.FILE_SHARE_READ,
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
