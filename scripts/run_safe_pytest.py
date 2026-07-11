from __future__ import annotations

import argparse
import hashlib
import json
import ntpath
import os
import re
import secrets
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from pathlib import Path, PureWindowsPath
from threading import Event, Lock, Thread
from typing import Any, Sequence


EXPECTED_PROJECT_ROOT = Path(r"D:\AAA命题\Test")
RUN_ID_PATTERN = re.compile(r"RUN-[A-Z0-9][A-Z0-9-]{5,80}")
REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
SYMLINK_TEST = "test_real_directory_symlink_is_rejected"


class SafetyStop(RuntimeError):
    pass


class _WindowsJob:
    """Minimal kill-on-close Job Object for one pytest process tree."""

    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    _JOB_OBJECT_BASIC_PROCESS_ID_LIST = 3
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _MAX_TRACKED_PROCESSES = 4096
    _TH32CS_SNAPTHREAD = 0x00000004
    _THREAD_SUSPEND_RESUME = 0x0002

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        class _BasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class _IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class _ExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BasicLimitInformation),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        class _ProcessIdList(ctypes.Structure):
            _fields_ = [
                ("NumberOfAssignedProcesses", wintypes.DWORD),
                ("NumberOfProcessIdsInList", wintypes.DWORD),
                ("ProcessIdList", ctypes.c_size_t * self._MAX_TRACKED_PROCESSES),
            ]

        class _ThreadEntry32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ThreadID", wintypes.DWORD),
                ("th32OwnerProcessID", wintypes.DWORD),
                ("tpBasePri", wintypes.LONG),
                ("tpDeltaPri", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.Thread32First.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_ThreadEntry32),
        ]
        kernel32.Thread32First.restype = wintypes.BOOL
        kernel32.Thread32Next.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_ThreadEntry32),
        ]
        kernel32.Thread32Next.restype = wintypes.BOOL
        kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenThread.restype = wintypes.HANDLE
        kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
        kernel32.ResumeThread.restype = wintypes.DWORD

        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise SafetyStop(f"cannot create pytest Job Object: {ctypes.get_last_error()}")
        limits = _ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = self._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            handle,
            self._JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            error = ctypes.get_last_error()
            kernel32.CloseHandle(handle)
            raise SafetyStop(f"cannot configure pytest Job Object: {error}")
        self._ctypes = ctypes
        self._kernel32 = kernel32
        self._process_id_list_type = _ProcessIdList
        self._thread_entry_type = _ThreadEntry32
        self._handle = handle

    def assign(self, process_handle: int) -> None:
        if not self._kernel32.AssignProcessToJobObject(self._handle, process_handle):
            raise SafetyStop(
                f"cannot assign pytest to Job Object: {self._ctypes.get_last_error()}"
            )

    def resume_process(self, process_id: int) -> None:
        invalid_handle = self._ctypes.c_void_p(-1).value
        snapshot = self._kernel32.CreateToolhelp32Snapshot(
            self._TH32CS_SNAPTHREAD,
            0,
        )
        if self._ctypes.c_void_p(snapshot).value == invalid_handle:
            raise SafetyStop(
                f"cannot enumerate suspended pytest thread: {self._ctypes.get_last_error()}"
            )
        thread_id: int | None = None
        try:
            entry = self._thread_entry_type()
            entry.dwSize = self._ctypes.sizeof(entry)
            present = bool(self._kernel32.Thread32First(snapshot, self._ctypes.byref(entry)))
            while present:
                if int(entry.th32OwnerProcessID) == process_id:
                    thread_id = int(entry.th32ThreadID)
                    break
                present = bool(
                    self._kernel32.Thread32Next(snapshot, self._ctypes.byref(entry))
                )
        finally:
            self._kernel32.CloseHandle(snapshot)
        if thread_id is None:
            raise SafetyStop("cannot find the suspended pytest primary thread")
        thread = self._kernel32.OpenThread(
            self._THREAD_SUSPEND_RESUME,
            False,
            thread_id,
        )
        if not thread:
            raise SafetyStop(
                f"cannot open suspended pytest thread: {self._ctypes.get_last_error()}"
            )
        try:
            result = int(self._kernel32.ResumeThread(thread))
            if result == 0xFFFFFFFF:
                raise SafetyStop(
                    f"cannot resume pytest process: {self._ctypes.get_last_error()}"
                )
            if result != 1:
                raise SafetyStop(
                    f"pytest primary thread had unexpected suspend count: {result}"
                )
        finally:
            self._kernel32.CloseHandle(thread)

    def terminate(self, exit_code: int = 124) -> bool:
        return bool(self._kernel32.TerminateJobObject(self._handle, exit_code))

    def active_process_ids(self) -> tuple[int, ...]:
        payload = self._process_id_list_type()
        returned = self._ctypes.c_ulong(0)
        if not self._kernel32.QueryInformationJobObject(
            self._handle,
            self._JOB_OBJECT_BASIC_PROCESS_ID_LIST,
            self._ctypes.byref(payload),
            self._ctypes.sizeof(payload),
            self._ctypes.byref(returned),
        ):
            raise SafetyStop(
                f"cannot query pytest Job Object: {self._ctypes.get_last_error()}"
            )
        count = int(payload.NumberOfProcessIdsInList)
        if int(payload.NumberOfAssignedProcesses) > self._MAX_TRACKED_PROCESSES:
            raise SafetyStop("pytest Job Object exceeded its audited process capacity")
        return tuple(int(payload.ProcessIdList[index]) for index in range(count))

    def close(self) -> bool:
        handle = self._handle
        if not handle:
            return True
        self._handle = None
        return bool(self._kernel32.CloseHandle(handle))


class _WindowsProtectedTreeWatcher:
    """Record recursive Test-tree changes while pytest is running."""

    _FILE_LIST_DIRECTORY = 0x0001
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _FILE_SHARE_DELETE = 0x00000004
    _OPEN_EXISTING = 3
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _NOTIFY_FILTER = (
        0x00000001  # FILE_NOTIFY_CHANGE_FILE_NAME
        | 0x00000002  # FILE_NOTIFY_CHANGE_DIR_NAME
        | 0x00000004  # FILE_NOTIFY_CHANGE_ATTRIBUTES
        | 0x00000008  # FILE_NOTIFY_CHANGE_SIZE
        | 0x00000010  # FILE_NOTIFY_CHANGE_LAST_WRITE
        | 0x00000040  # FILE_NOTIFY_CHANGE_CREATION
        | 0x00000100  # FILE_NOTIFY_CHANGE_SECURITY
    )
    _ERROR_OPERATION_ABORTED = 995
    _ERROR_NOT_FOUND = 1168
    _BUFFER_BYTES = 64 * 1024
    _ACTION_NAMES = {
        1: "ADDED",
        2: "REMOVED",
        3: "MODIFIED",
        4: "RENAMED_OLD",
        5: "RENAMED_NEW",
    }

    def __init__(self, root: Path, *, excluded_root: Path) -> None:
        if os.name != "nt":
            raise SafetyStop("recursive protected-tree monitoring requires Windows")
        self._root = _absolute_lexical(root)
        self._excluded_root = _absolute_lexical(excluded_root)
        excluded_parts = _relative_parts(self._excluded_root, self._root)
        if not excluded_parts:
            raise SafetyStop("protected-tree monitor exclusion must be below the root")
        _verify_existing_chain(self._root)
        _verify_existing_chain(self._excluded_root)

        import ctypes
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
        kernel32.ReadDirectoryChangesW.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        kernel32.ReadDirectoryChangesW.restype = wintypes.BOOL
        kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        kernel32.CancelIoEx.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        handle = kernel32.CreateFileW(
            str(self._root),
            self._FILE_LIST_DIRECTORY,
            self._FILE_SHARE_READ | self._FILE_SHARE_WRITE | self._FILE_SHARE_DELETE,
            None,
            self._OPEN_EXISTING,
            self._FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if ctypes.c_void_p(handle).value == invalid_handle:
            raise SafetyStop(
                f"cannot open protected-tree monitor: {ctypes.get_last_error()}"
            )

        arm_token = secrets.token_hex(12)
        drain_token = secrets.token_hex(24)
        self._arm_path = self._excluded_root / f".watcher-arm-{arm_token}.marker"
        self._drain_path = (
            self._excluded_root / f".watcher-drain-{drain_token}.marker"
        )
        self._ctypes = ctypes
        self._kernel32 = kernel32
        self._handle = handle
        self._armed = Event()
        self._drained = Event()
        self._drain_requested = Event()
        self._lock = Lock()
        self._changes: set[str] = set()
        self._error: str | None = None
        self._finished: tuple[tuple[str, ...], str | None] | None = None
        self._thread = Thread(
            target=self._watch,
            name="protected-tree-watcher",
            daemon=True,
        )
        try:
            self._thread.start()
            self._write_marker(self._arm_path)
            if not self._armed.wait(timeout=10):
                self._record_error("protected-tree monitor did not arm")
                self.finish()
                raise SafetyStop("protected-tree monitor did not arm")
        except Exception:
            if self._finished is None:
                self.finish()
            raise

    def _write_marker(self, path: Path) -> None:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            os.write(descriptor, b"watcher-order-marker\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        identity = _lstat_no_reparse(path)
        if not stat.S_ISREG(identity.st_mode) or identity.st_nlink != 1:
            raise SafetyStop("protected-tree monitor marker is not a single-link file")

    def _record_error(self, message: str) -> None:
        with self._lock:
            if self._error is None:
                self._error = message

    def _event_candidate(self, name: str) -> Path:
        if not name or ntpath.isabs(name) or any(
            component in {"", ".", ".."}
            for component in PureWindowsPath(name).parts
        ):
            raise SafetyStop("protected-tree monitor returned an invalid relative path")
        candidate = _absolute_lexical(self._root / Path(name))
        if _relative_parts(candidate, self._root) is None:
            raise SafetyStop("protected-tree monitor event escaped the project root")
        return candidate

    def _consume(self, raw: bytes) -> bool:
        offset = 0
        saw_drain = False
        while True:
            if offset + 12 > len(raw):
                raise SafetyStop("protected-tree monitor returned a truncated event")
            next_offset = int.from_bytes(raw[offset : offset + 4], "little")
            action = int.from_bytes(raw[offset + 4 : offset + 8], "little")
            name_bytes = int.from_bytes(raw[offset + 8 : offset + 12], "little")
            name_end = offset + 12 + name_bytes
            if (
                action not in self._ACTION_NAMES
                or name_bytes % 2
                or name_end > len(raw)
            ):
                raise SafetyStop("protected-tree monitor returned an invalid event name")
            encoded_name = raw[offset + 12 : name_end]
            name = str(encoded_name, "utf-16-le", "strict")
            candidate = self._event_candidate(name)
            if _same_path(candidate, self._arm_path):
                self._armed.set()
            if (
                _same_path(candidate, self._drain_path)
                and self._drain_requested.is_set()
                and action in {1, 5}
            ):
                self._drained.set()
                saw_drain = True
            if _relative_parts(candidate, self._excluded_root) is None:
                relative = PureWindowsPath(*(_relative_parts(candidate, self._root) or ()))
                action_name = self._ACTION_NAMES.get(action, f"ACTION_{action}")
                with self._lock:
                    self._changes.add(f"{action_name}:{relative.as_posix()}")
            if next_offset == 0:
                break
            if (
                next_offset % 4
                or next_offset < 12 + name_bytes
                or offset + next_offset >= len(raw)
            ):
                raise SafetyStop("protected-tree monitor returned an invalid event chain")
            offset += next_offset
        return saw_drain

    def _watch(self) -> None:
        buffer = self._ctypes.create_string_buffer(self._BUFFER_BYTES)
        try:
            while True:
                returned = self._ctypes.c_ulong(0)
                ok = self._kernel32.ReadDirectoryChangesW(
                    self._handle,
                    buffer,
                    self._BUFFER_BYTES,
                    True,
                    self._NOTIFY_FILTER,
                    self._ctypes.byref(returned),
                    None,
                    None,
                )
                if not ok:
                    error = self._ctypes.get_last_error()
                    if (
                        error == self._ERROR_OPERATION_ABORTED
                        and self._drain_requested.is_set()
                    ):
                        return
                    self._record_error(
                        f"protected-tree monitor read failed with Windows error {error}"
                    )
                    return
                byte_count = int(returned.value)
                if byte_count == 0:
                    self._record_error("protected-tree monitor buffer overflowed")
                    return
                if self._consume(bytes(buffer.raw[:byte_count])):
                    return
        except Exception as exc:
            self._record_error(f"protected-tree monitor failed: {exc}")

    def finish(self) -> tuple[tuple[str, ...], str | None]:
        if self._finished is not None:
            return self._finished
        try:
            if (
                not self._thread.is_alive()
                and not self._drained.is_set()
                and self._error is None
            ):
                self._record_error("protected-tree monitor stopped before drain")
            if self._thread.is_alive():
                try:
                    self._drain_requested.set()
                    self._write_marker(self._drain_path)
                except Exception as exc:
                    self._record_error(
                        f"cannot write protected-tree drain marker: {exc}"
                    )
                if not self._drained.wait(timeout=10):
                    self._record_error("protected-tree monitor did not drain")
                self._thread.join(timeout=2)
            if self._thread.is_alive():
                if not self._kernel32.CancelIoEx(self._handle, None):
                    error = self._ctypes.get_last_error()
                    if error != self._ERROR_NOT_FOUND:
                        self._record_error(
                            f"cannot cancel protected-tree monitor: {error}"
                        )
                self._thread.join(timeout=5)
            if self._thread.is_alive():
                self._record_error("protected-tree monitor thread did not stop")
        finally:
            handle = self._handle
            self._handle = None
            if handle and not self._kernel32.CloseHandle(handle):
                self._record_error(
                    f"cannot close protected-tree monitor: {self._ctypes.get_last_error()}"
                )
        with self._lock:
            self._finished = (tuple(sorted(self._changes)), self._error)
        return self._finished


class _WindowsProtectedTreeFence:
    """Hold deny-write/delete handles for every pre-existing protected object."""

    _GENERIC_READ = 0x80000000
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _OPEN_EXISTING = 3
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000

    def __init__(
        self,
        root: Path,
        *,
        excluded_root: Path,
        snapshot: dict[str, dict[str, Any]],
    ) -> None:
        if os.name != "nt":
            raise SafetyStop("protected-tree handle fencing requires Windows")
        self._root = _absolute_lexical(root)
        self._excluded_root = _absolute_lexical(excluded_root)
        if not _relative_parts(self._excluded_root, self._root):
            raise SafetyStop("protected-tree fence exclusion must be below the root")
        if type(snapshot) is not dict or not snapshot:
            raise SafetyStop("protected-tree fence requires a non-empty snapshot")
        _verify_existing_chain(self._root)
        _verify_existing_chain(self._excluded_root)

        import ctypes
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
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        self._ctypes = ctypes
        self._kernel32 = kernel32
        self._handles: list[int] = []
        self._finished: tuple[int, str | None] | None = None
        try:
            for key in sorted(snapshot):
                kind, separator, relative = key.partition(":")
                if separator != ":" or kind not in {"D", "F"} or not relative:
                    raise SafetyStop("protected-tree snapshot contains an invalid key")
                candidate = (
                    self._root
                    if relative == "."
                    else self._root / Path(relative.replace("/", os.sep))
                )
                candidate = _absolute_lexical(candidate)
                if _relative_parts(candidate, self._root) is None or _relative_parts(
                    candidate,
                    self._excluded_root,
                ) is not None:
                    raise SafetyStop("protected-tree fence path escaped its audited set")
                identity = _lstat_no_reparse(candidate)
                is_directory = stat.S_ISDIR(identity.st_mode)
                if is_directory is not (kind == "D"):
                    raise SafetyStop("protected-tree fence object changed type")
                share_mode = self._FILE_SHARE_READ
                if is_directory:
                    share_mode |= self._FILE_SHARE_WRITE
                flags = self._FILE_FLAG_OPEN_REPARSE_POINT
                if is_directory:
                    flags |= self._FILE_FLAG_BACKUP_SEMANTICS
                handle = kernel32.CreateFileW(
                    str(candidate),
                    self._GENERIC_READ,
                    share_mode,
                    None,
                    self._OPEN_EXISTING,
                    flags,
                    None,
                )
                invalid_handle = ctypes.c_void_p(-1).value
                if ctypes.c_void_p(handle).value == invalid_handle:
                    raise SafetyStop(
                        "cannot fence protected-tree object: "
                        f"Windows error {ctypes.get_last_error()}"
                    )
                self._handles.append(handle)
            fenced_snapshot = _protected_tree_snapshot(
                self._root,
                excluded_root=self._excluded_root,
            )
            changes = _snapshot_changes(snapshot, fenced_snapshot)
            if changes:
                raise SafetyStop(
                    "protected tree changed while deny-write handles were acquired"
                )
        except Exception:
            self.finish()
            raise

    @property
    def count(self) -> int:
        return len(self._handles) if self._finished is None else self._finished[0]

    def finish(self) -> tuple[int, str | None]:
        if self._finished is not None:
            return self._finished
        count = len(self._handles)
        errors: list[str] = []
        while self._handles:
            handle = self._handles.pop()
            if not self._kernel32.CloseHandle(handle):
                errors.append(str(self._ctypes.get_last_error()))
        error = None
        if errors:
            error = "cannot close protected-tree fence handles: " + ",".join(errors)
        self._finished = (count, error)
        return self._finished


def _absolute_lexical(path: str | os.PathLike[str]) -> Path:
    return Path(ntpath.normpath(ntpath.abspath(os.fspath(path))))


def _same_path(left: Path, right: Path) -> bool:
    return ntpath.normcase(str(left)) == ntpath.normcase(str(right))


def _relative_parts(candidate: Path, root: Path) -> tuple[str, ...] | None:
    candidate_parts = PureWindowsPath(str(candidate)).parts
    root_parts = PureWindowsPath(str(root)).parts
    if len(candidate_parts) < len(root_parts):
        return None
    for candidate_part, root_part in zip(candidate_parts, root_parts, strict=False):
        if ntpath.normcase(candidate_part) != ntpath.normcase(root_part):
            return None
    return tuple(candidate_parts[len(root_parts) :])


def _lstat_no_reparse(path: Path) -> os.stat_result:
    try:
        identity = os.lstat(path)
    except OSError as exc:
        raise SafetyStop(f"cannot inspect required path {path}: {exc}") from exc
    attributes = int(getattr(identity, "st_file_attributes", 0))
    reparse_tag = int(getattr(identity, "st_reparse_tag", 0))
    if stat.S_ISLNK(identity.st_mode) or attributes & REPARSE_ATTRIBUTE or reparse_tag:
        raise SafetyStop(f"reparse point in safety-critical path chain: {path}")
    return identity


def _verify_existing_chain(path: Path) -> None:
    for component in (*reversed(path.parents), path):
        _lstat_no_reparse(component)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular_file_evidence(path: Path) -> dict[str, Any]:
    identity = _lstat_no_reparse(path)
    if not stat.S_ISREG(identity.st_mode):
        raise SafetyStop(f"safety evidence is not a regular file: {path}")
    if identity.st_nlink != 1:
        raise SafetyStop(f"safety evidence must have exactly one hard link: {path}")
    return {
        "size": int(identity.st_size),
        "mtime_ns": int(identity.st_mtime_ns),
        "sha256": _sha256(path),
        **_identity_payload(identity),
    }


def _verify_run_tree_no_reparse(run_root: Path) -> None:
    for current_text, directory_names, file_names in os.walk(
        run_root,
        topdown=True,
        followlinks=False,
        onerror=_raise_walk_error,
    ):
        current = Path(current_text)
        current_identity = _lstat_no_reparse(current)
        if not stat.S_ISDIR(current_identity.st_mode):
            raise SafetyStop(f"run tree directory changed type: {current}")
        for name in directory_names:
            identity = _lstat_no_reparse(current / name)
            if not stat.S_ISDIR(identity.st_mode):
                raise SafetyStop(f"run tree directory entry changed type: {current / name}")
        for name in file_names:
            identity = _lstat_no_reparse(current / name)
            if not stat.S_ISREG(identity.st_mode):
                raise SafetyStop(f"run tree file entry changed type: {current / name}")
            if identity.st_nlink != 1:
                raise SafetyStop(f"run tree file has multiple hard links: {current / name}")


def _junit_evidence(path: Path) -> dict[str, Any]:
    file_evidence = _regular_file_evidence(path)
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise SafetyStop(f"JUnit XML is invalid: {exc}") from exc
    if root.tag not in {"testsuite", "testsuites"}:
        raise SafetyStop(f"JUnit XML has an unexpected root element: {root.tag}")

    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    if not suites:
        raise SafetyStop("JUnit XML contains no test suites")
    leaf_suites = [suite for suite in suites if not suite.findall("testsuite")]
    if not leaf_suites:
        raise SafetyStop("JUnit XML contains no leaf test suites")

    def _count(attribute: str) -> int:
        total = 0
        for suite in leaf_suites:
            raw = suite.attrib.get(attribute, "0")
            try:
                value = int(raw)
            except ValueError as exc:
                raise SafetyStop(
                    f"JUnit XML has a non-integer {attribute} count"
                ) from exc
            if value < 0:
                raise SafetyStop(f"JUnit XML has a negative {attribute} count")
            total += value
        return total

    reported = {
        "tests": _count("tests"),
        "failures": _count("failures"),
        "errors": _count("errors"),
        "skipped": _count("skipped"),
    }
    testcases = list(root.iter("testcase"))
    direct_status_counts = {"failures": 0, "errors": 0, "skipped": 0}
    for testcase in testcases:
        per_case = {
            "failures": len(testcase.findall("failure")),
            "errors": len(testcase.findall("error")),
            "skipped": len(testcase.findall("skipped")),
        }
        status_count = sum(per_case.values())
        if status_count > 1:
            raise SafetyStop("JUnit testcase contains multiple terminal statuses")
        for key, value in per_case.items():
            direct_status_counts[key] += value
    global_status_counts = {
        "failures": sum(1 for _ in root.iter("failure")),
        "errors": sum(1 for _ in root.iter("error")),
        "skipped": sum(1 for _ in root.iter("skipped")),
    }
    if global_status_counts != direct_status_counts:
        raise SafetyStop("JUnit status elements must be direct testcase children")
    actual = {
        "tests": len(testcases),
        **direct_status_counts,
    }
    if actual != reported:
        raise SafetyStop(
            "JUnit aggregate counts do not match testcase status elements"
        )

    return {
        **file_evidence,
        **actual,
    }


def _is_within(path: Path, parent: Path) -> bool:
    return _relative_parts(_absolute_lexical(path), _absolute_lexical(parent)) is not None


def _identity_payload(identity: os.stat_result) -> dict[str, int]:
    return {
        "device": int(identity.st_dev),
        "inode": int(identity.st_ino),
        "mode": int(identity.st_mode),
        "nlink": int(identity.st_nlink),
        "file_attributes": int(getattr(identity, "st_file_attributes", 0)),
        "reparse_tag": int(getattr(identity, "st_reparse_tag", 0)),
    }


def _protected_tree_snapshot(
    project_root: Path,
    *,
    excluded_root: Path,
) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    hardlink_groups: dict[tuple[int, int], list[tuple[Path, os.stat_result]]] = (
        defaultdict(list)
    )
    for current_text, directory_names, file_names in os.walk(
        project_root,
        topdown=True,
        followlinks=False,
        onerror=_raise_walk_error,
    ):
        current = Path(current_text)
        directory_names.sort(key=str.casefold)
        file_names.sort(key=str.casefold)
        kept_directories: list[str] = []
        for name in directory_names:
            candidate = current / name
            if _is_within(candidate, excluded_root):
                continue
            identity = _lstat_no_reparse(candidate)
            if not stat.S_ISDIR(identity.st_mode):
                raise SafetyStop(f"protected directory entry changed type: {candidate}")
            kept_directories.append(name)
        directory_names[:] = kept_directories

        if not _is_within(current, excluded_root):
            identity = _lstat_no_reparse(current)
            relative = current.relative_to(project_root).as_posix() or "."
            rows[f"D:{relative}"] = {
                "kind": "directory",
                "mtime_ns": int(identity.st_mtime_ns),
                "ctime_ns": int(identity.st_ctime_ns),
                **_identity_payload(identity),
            }
        for name in file_names:
            candidate = current / name
            if _is_within(candidate, excluded_root):
                continue
            identity = _lstat_no_reparse(candidate)
            if not stat.S_ISREG(identity.st_mode):
                raise SafetyStop(f"protected file entry is not regular: {candidate}")
            if identity.st_nlink > 1:
                if int(identity.st_ino) <= 0:
                    raise SafetyStop(
                        f"protected hard-link identity is unavailable: {candidate}"
                    )
                hardlink_groups[(int(identity.st_dev), int(identity.st_ino))].append(
                    (candidate, identity)
                )
            relative = candidate.relative_to(project_root).as_posix()
            rows[f"F:{relative}"] = {
                "kind": "file",
                "size": int(identity.st_size),
                "mtime_ns": int(identity.st_mtime_ns),
                "ctime_ns": int(identity.st_ctime_ns),
                "sha256": _sha256(candidate),
                **_identity_payload(identity),
            }
    for group in hardlink_groups.values():
        link_counts = {int(identity.st_nlink) for _, identity in group}
        if len(link_counts) != 1 or len(group) != next(iter(link_counts)):
            raise SafetyStop(
                "protected hard-link group is not wholly contained in the audited tree: "
                + ", ".join(str(path) for path, _ in group)
            )
    return dict(sorted(rows.items()))


def _raise_walk_error(error: OSError) -> None:
    raise SafetyStop(f"cannot enumerate safety-critical tree: {error}") from error


def _snapshot_digest(snapshot: dict[str, dict[str, Any]]) -> str:
    canonical = json.dumps(
        snapshot,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(b"SAFE-PYTEST-PROTECTED-TREE-V1\0" + canonical).hexdigest()


def _snapshot_changes(
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
) -> list[str]:
    return sorted(
        key
        for key in set(before) | set(after)
        if before.get(key) != after.get(key)
    )


def _write_json_exclusive(path: Path, payload: dict[str, Any]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def _build_command(
    project_root: Path,
    run_root: Path,
    *,
    mode: str,
    exclude_symlink: bool,
) -> tuple[list[str], Path, Path]:
    basetemp = run_root / "pytest-basetemp"
    junit = run_root / "junit.xml"
    if os.path.lexists(basetemp) or os.path.lexists(junit):
        raise SafetyStop("basetemp and junit targets must not exist before pytest starts")

    selection: list[str]
    if mode == "full":
        selection = []
    elif mode == "guard":
        selection = ["tests/test_workspace_guard.py"]
    elif mode == "symlink":
        selection = [f"tests/test_workspace_guard.py::{SYMLINK_TEST}"]
    else:  # pragma: no cover - argparse constrains this value.
        raise SafetyStop(f"unsupported mode: {mode}")

    if mode == "symlink" and exclude_symlink:
        raise SafetyStop("the symlink-only mode cannot exclude the symlink gate")
    command = [
        sys.executable,
        "-m",
        "pytest",
        *selection,
        "-q",
        "-p",
        "no:cacheprovider",
    ]
    if exclude_symlink:
        command.extend(["-k", f"not {SYMLINK_TEST}"])
    command.extend(
        [
            "--basetemp",
            str(basetemp),
            "--junitxml",
            str(junit),
        ]
    )
    return command, basetemp, junit


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run pytest in a new, fail-closed Test-local safety laboratory.",
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=("full", "guard", "symlink"), required=True)
    parser.add_argument(
        "--exclude-symlink",
        action="store_true",
        help="Run all selected tests except the separately audited symlink privilege gate.",
    )
    parser.add_argument("--timeout-seconds", type=int, default=900)
    return parser.parse_args(argv)


def _run_test_process(
    command: list[str],
    *,
    project_root: Path,
    environment: dict[str, str],
    timeout_seconds: int,
) -> tuple[int, bool, bool]:
    creationflags = 0
    job: _WindowsJob | None = None
    if os.name == "nt":
        creationflags = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)) | 0x00000004
        job = _WindowsJob()
    try:
        process = subprocess.Popen(
            command,
            cwd=project_root,
            env=environment,
            shell=False,
            creationflags=creationflags,
            start_new_session=os.name != "nt",
        )
    except Exception:
        if job is not None:
            job.close()
        raise
    if job is not None:
        try:
            job.assign(int(process._handle))  # type: ignore[attr-defined]
            job.resume_process(process.pid)
        except Exception:
            try:
                try:
                    job.terminate(96)
                except Exception:
                    pass
                try:
                    if process.poll() is None:
                        process.kill()
                except Exception:
                    pass
            finally:
                try:
                    job.close()
                finally:
                    try:
                        process.wait(timeout=30)
                    except Exception:
                        pass
            raise
    try:
        exit_code = int(process.wait(timeout=timeout_seconds))
        if job is None:
            return exit_code, False, True
        active: tuple[int, ...] = ()
        for _ in range(20):
            active = job.active_process_ids()
            if not active:
                break
            time.sleep(0.05)
        closed = job.close()
        job = None
        return exit_code, False, closed and not active
    except subprocess.TimeoutExpired:
        tree_terminated = False
        if job is not None:
            terminated = job.terminate(124)
            active: tuple[int, ...] = job.active_process_ids()
            for _ in range(100):
                if not active:
                    break
                time.sleep(0.05)
                active = job.active_process_ids()
            tree_terminated = terminated and not active
            closed = job.close()
            tree_terminated = tree_terminated and closed
            job = None
        elif process.poll() is None:
            try:
                os.killpg(process.pid, 9)
            except (OSError, AttributeError):
                process.kill()
            tree_terminated = True
        else:
            tree_terminated = True
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            tree_terminated = False
        return 124, True, tree_terminated
    finally:
        if job is not None:
            job.close()


def _effective_exit_code(
    *,
    pytest_exit_code: int,
    junit_valid: bool,
    junit_details: dict[str, Any],
    process_tree_terminated: bool,
    run_tree_safe: bool,
    immutable_evidence_unchanged: bool,
    database_unchanged: bool,
    protected_tree_unchanged: bool,
    protected_runtime_monitor_valid: bool,
    protected_runtime_unchanged: bool,
    protected_handle_fence_valid: bool,
) -> int:
    if (
        not database_unchanged
        or not protected_tree_unchanged
        or not protected_runtime_monitor_valid
        or not protected_runtime_unchanged
        or not protected_handle_fence_valid
    ):
        return 97
    if not run_tree_safe or not immutable_evidence_unchanged:
        return 95
    if not process_tree_terminated:
        return 99
    if pytest_exit_code == 0 and (
        not junit_valid
        or int(junit_details.get("tests", 0)) < 1
        or int(junit_details.get("failures", 0)) != 0
        or int(junit_details.get("errors", 0)) != 0
        or int(junit_details.get("skipped", 0)) != 0
    ):
        return 98
    return pytest_exit_code


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    if not RUN_ID_PATTERN.fullmatch(args.run_id):
        raise SafetyStop("run ID must match RUN-[A-Z0-9-] and contain no path syntax")
    if not 1 <= args.timeout_seconds <= 3600:
        raise SafetyStop("timeout must be between 1 and 3600 seconds")

    project_root = _absolute_lexical(Path(__file__).parent.parent)
    expected_root = _absolute_lexical(EXPECTED_PROJECT_ROOT)
    if not _same_path(project_root, expected_root):
        raise SafetyStop(
            f"launcher is outside the contracted project root: {project_root}"
        )
    expected_python = project_root / ".venv" / "Scripts" / "python.exe"
    if not _same_path(_absolute_lexical(sys.executable), expected_python):
        raise SafetyStop(f"use the audited project Python: {expected_python}")

    test_lab_root = project_root / "tmp" / "test_lab"
    _verify_existing_chain(expected_python)
    _verify_existing_chain(test_lab_root)
    if not test_lab_root.is_dir():
        raise SafetyStop(f"test laboratory parent is not a directory: {test_lab_root}")

    run_root = test_lab_root / args.run_id
    if _relative_parts(run_root, test_lab_root) != (args.run_id,):
        raise SafetyStop(f"run root escaped the direct test_lab child boundary: {run_root}")
    if os.path.lexists(run_root):
        raise SafetyStop(f"refusing to reuse or delete an existing run: {run_root}")
    os.mkdir(run_root)
    _verify_existing_chain(run_root)

    temp_root = run_root / "temp"
    pycache_root = run_root / "pycache"
    cache_root = run_root / "cache"
    os.mkdir(temp_root)
    os.mkdir(pycache_root)
    os.mkdir(cache_root)
    _lstat_no_reparse(temp_root)
    _lstat_no_reparse(pycache_root)
    _lstat_no_reparse(cache_root)

    created_at = datetime.now().astimezone().isoformat(timespec="seconds")
    launch_token = secrets.token_urlsafe(32)
    launch_token_sha256 = hashlib.sha256(launch_token.encode("utf-8")).hexdigest()
    marker = {
        "schema_version": "1.0",
        "run_id": args.run_id,
        "project_root": str(project_root),
        "purpose": "M0-S1 WorkspaceGuard safety laboratory",
        "cleanup_policy": "retain-until-manifested-quarantine",
        "created_at": created_at,
        "launch_token_sha256": launch_token_sha256,
    }
    _write_json_exclusive(run_root / ".safety-marker.json", marker)

    command, basetemp, junit = _build_command(
        project_root,
        run_root,
        mode=args.mode,
        exclude_symlink=args.exclude_symlink,
    )
    database = project_root / "data" / "db" / "question_bank.sqlite3"
    _verify_existing_chain(database)
    if not database.is_file():
        raise SafetyStop(f"required activity database is not a file: {database}")
    protected_before = _protected_tree_snapshot(
        project_root,
        excluded_root=run_root,
    )
    protected_digest_before = _snapshot_digest(protected_before)
    _write_json_exclusive(
        run_root / "protected-tree-before.json",
        {
            "schema_version": "1.0",
            "entry_count": len(protected_before),
            "digest_sha256": protected_digest_before,
            "entries": protected_before,
        },
    )
    database_before = _sha256(database)
    bootstrap_root = project_root / "tests" / "safe_bootstrap"
    bootstrap_module = bootstrap_root / "sitecustomize.py"
    _verify_existing_chain(bootstrap_module)
    bootstrap_identity = _lstat_no_reparse(bootstrap_module)
    if (
        not stat.S_ISREG(bootstrap_identity.st_mode)
        or bootstrap_identity.st_nlink != 1
    ):
        raise SafetyStop("test hardlink bootstrap must be a single-link regular file")
    environment = os.environ.copy()
    for untrusted_name in (
        "COVERAGE_FILE",
        "COVERAGE_PROCESS_START",
        "M0_TEST_DIRECT_PYTEST_CANARY",
        "M0_TEST_HARDLINK_GUARD_ACTIVE",
        "M0_TEST_HARDLINK_GUARD_REQUIRED",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
    ):
        environment.pop(untrusted_name, None)
    environment.update(
        {
            "M0_TEST_LAB_ROOT": str(run_root),
            "M0_TEST_LAB_TOKEN": launch_token,
            "TEMP": str(temp_root),
            "TMP": str(temp_root),
            "XDG_CACHE_HOME": str(cache_root),
            "MPLCONFIGDIR": str(cache_root / "matplotlib"),
            "PYTHONPYCACHEPREFIX": str(pycache_root),
            "PYTHONPATH": str(bootstrap_root),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "M0_TEST_HARDLINK_GUARD_REQUIRED": "1",
        }
    )
    manifest = {
        "schema_version": "1.0",
        "run_id": args.run_id,
        "created_at": created_at,
        "mode": args.mode,
        "exclude_symlink": bool(args.exclude_symlink),
        "project_root": str(project_root),
        "run_root": str(run_root),
        "basetemp": str(basetemp),
        "junit": str(junit),
        "command": command,
        "timeout_seconds": args.timeout_seconds,
        "launch_token_sha256": launch_token_sha256,
        "environment": {
            name: environment[name]
            for name in (
                "M0_TEST_LAB_ROOT",
                "TEMP",
                "TMP",
                "XDG_CACHE_HOME",
                "MPLCONFIGDIR",
                "PYTHONPYCACHEPREFIX",
                "PYTHONPATH",
                "PYTHONDONTWRITEBYTECODE",
                "PYTHONNOUSERSITE",
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
                "M0_TEST_HARDLINK_GUARD_REQUIRED",
            )
        },
        "protected_tree_entry_count_before": len(protected_before),
        "protected_tree_digest_before": protected_digest_before,
        "protected_runtime_monitor": "ReadDirectoryChangesW recursive",
        "protected_handle_fence": "deny write/delete sharing on existing objects",
        "activity_database": str(database.relative_to(project_root)),
        "activity_database_sha256_before": database_before,
    }
    _write_json_exclusive(run_root / "run-manifest.json", manifest)
    immutable_evidence_paths = (
        run_root / ".safety-marker.json",
        run_root / "protected-tree-before.json",
        run_root / "run-manifest.json",
    )
    immutable_evidence_before = {
        path.name: _regular_file_evidence(path) for path in immutable_evidence_paths
    }

    handle_fence = _WindowsProtectedTreeFence(
        project_root,
        excluded_root=run_root,
        snapshot=protected_before,
    )
    try:
        runtime_monitor = _WindowsProtectedTreeWatcher(
            project_root,
            excluded_root=run_root,
        )
    except Exception:
        handle_fence.finish()
        raise
    try:
        pytest_exit_code, timed_out, process_tree_terminated = _run_test_process(
            command,
            project_root=project_root,
            environment=environment,
            timeout_seconds=args.timeout_seconds,
        )
        _verify_existing_chain(run_root)
        protected_after = _protected_tree_snapshot(
            project_root,
            excluded_root=run_root,
        )
    finally:
        protected_runtime_changes, protected_runtime_error = runtime_monitor.finish()
        protected_handle_count, protected_handle_fence_error = handle_fence.finish()
    protected_runtime_monitor_valid = protected_runtime_error is None
    protected_runtime_unchanged = (
        protected_runtime_monitor_valid and not protected_runtime_changes
    )
    protected_handle_fence_valid = protected_handle_fence_error is None
    protected_digest_after = _snapshot_digest(protected_after)
    _write_json_exclusive(
        run_root / "protected-tree-after.json",
        {
            "schema_version": "1.0",
            "entry_count": len(protected_after),
            "digest_sha256": protected_digest_after,
            "entries": protected_after,
        },
    )
    protected_changes = _snapshot_changes(protected_before, protected_after)
    protected_tree_unchanged = not protected_changes
    database_after = _sha256(database) if database.is_file() else None
    database_unchanged = database_before == database_after
    run_tree_safe = True
    run_tree_error: str | None = None
    try:
        _verify_run_tree_no_reparse(run_root)
    except SafetyStop as exc:
        run_tree_safe = False
        run_tree_error = str(exc)

    immutable_evidence_unchanged = False
    immutable_evidence_after: dict[str, dict[str, Any]] = {}
    immutable_evidence_error: str | None = None
    if run_tree_safe:
        try:
            immutable_evidence_after = {
                path.name: _regular_file_evidence(path)
                for path in immutable_evidence_paths
            }
            immutable_evidence_unchanged = (
                immutable_evidence_before == immutable_evidence_after
            )
        except SafetyStop as exc:
            immutable_evidence_error = str(exc)

    junit_exists = os.path.lexists(junit)
    junit_valid = False
    junit_error: str | None = None
    junit_details: dict[str, Any] = {}
    if junit_exists and run_tree_safe:
        try:
            junit_details = _junit_evidence(junit)
            junit_valid = True
        except SafetyStop as exc:
            junit_error = str(exc)
    effective_exit_code = _effective_exit_code(
        pytest_exit_code=pytest_exit_code,
        junit_valid=junit_valid,
        junit_details=junit_details,
        process_tree_terminated=process_tree_terminated,
        run_tree_safe=run_tree_safe,
        immutable_evidence_unchanged=immutable_evidence_unchanged,
        database_unchanged=database_unchanged,
        protected_tree_unchanged=protected_tree_unchanged,
        protected_runtime_monitor_valid=protected_runtime_monitor_valid,
        protected_runtime_unchanged=protected_runtime_unchanged,
        protected_handle_fence_valid=protected_handle_fence_valid,
    )
    result = {
        "schema_version": "1.0",
        "run_id": args.run_id,
        "finished_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "pytest_exit_code": pytest_exit_code,
        "effective_exit_code": effective_exit_code,
        "timed_out": timed_out,
        "process_tree_terminated": process_tree_terminated,
        "junit_exists": junit_exists,
        "junit_valid": junit_valid,
        "junit_error": junit_error,
        "junit_sha256": junit_details.get("sha256"),
        "junit_tests": junit_details.get("tests"),
        "junit_failures": junit_details.get("failures"),
        "junit_errors": junit_details.get("errors"),
        "junit_skipped": junit_details.get("skipped"),
        "run_tree_safe": run_tree_safe,
        "run_tree_error": run_tree_error,
        "immutable_evidence_unchanged": immutable_evidence_unchanged,
        "immutable_evidence_error": immutable_evidence_error,
        "immutable_evidence_before": immutable_evidence_before,
        "immutable_evidence_after": immutable_evidence_after,
        "activity_database_sha256_before": database_before,
        "activity_database_sha256_after": database_after,
        "activity_database_unchanged": database_unchanged,
        "protected_tree_entry_count_before": len(protected_before),
        "protected_tree_entry_count_after": len(protected_after),
        "protected_tree_digest_before": protected_digest_before,
        "protected_tree_digest_after": protected_digest_after,
        "protected_tree_unchanged": protected_tree_unchanged,
        "protected_runtime_monitor_valid": protected_runtime_monitor_valid,
        "protected_runtime_monitor_error": protected_runtime_error,
        "protected_runtime_unchanged": protected_runtime_unchanged,
        "protected_runtime_changes": protected_runtime_changes,
        "protected_handle_count": protected_handle_count,
        "protected_handle_fence_valid": protected_handle_fence_valid,
        "protected_handle_fence_error": protected_handle_fence_error,
        "source_inputs_unchanged": (
            protected_tree_unchanged and protected_runtime_unchanged
        ),
        "changed_source_inputs": protected_changes,
    }
    _write_json_exclusive(run_root / "run-result.json", result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return effective_exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SafetyStop as exc:
        print(f"SAFETY_STOP: {exc}", file=sys.stderr)
        raise SystemExit(96) from exc
