from __future__ import annotations

import hashlib
import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Iterator

from app.project_root import PROJECT_ROOT

from .production_guard import (
    PRODUCTION_WRITER_CONTRACT_VERSION,
    ProductionWorkspaceBoundary,
    get_production_boundary,
)
from .windows_handle_writer import (
    DirectoryMoveReceipt,
    HandleReadResult,
    HandleWriteReceipt,
    HandleWriterCode,
    HandleWriterError,
    _WindowsHandleWriter,
)


MAX_DIRECT_WRITE_BYTES = 64 * 1024 * 1024
_WORKSPACE_IO_CONSTRUCTOR = object()
_WORKSPACE_IO_LOCK = threading.Lock()
_workspace_io_singleton: ProductionWorkspaceIO | None = None


class WorkspaceIOCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    PATH_REJECTED = "PATH_REJECTED"
    TARGET_CONFLICT = "TARGET_CONFLICT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    WRITER_FAILURE = "WRITER_FAILURE"


class WorkspaceIOError(RuntimeError):
    """Path-redacted application-facing failure from the production writer."""

    def __init__(self, code: WorkspaceIOCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code.value}: {message}")


@dataclass(frozen=True, slots=True)
class WorkspaceWriteReceipt:
    operation: str
    relative_path: str
    size_bytes: int
    sha256: str
    object_reference: str
    idempotent: bool
    writer_contract_version: str = PRODUCTION_WRITER_CONTRACT_VERSION

    def to_dict(self) -> dict[str, str | int | bool]:
        return {
            "idempotent": self.idempotent,
            "object_reference": self.object_reference,
            "operation": self.operation,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "writer_contract_version": self.writer_contract_version,
        }


class ProductionWorkspaceIO:
    """Narrow fixed-root facade over the boundary-owned handle writer."""

    __slots__ = ("_boundary", "_writer")

    def __init__(
        self,
        boundary: ProductionWorkspaceBoundary,
        *,
        _constructor: object | None = None,
    ) -> None:
        if (
            _constructor is not _WORKSPACE_IO_CONSTRUCTOR
            or type(boundary) is not ProductionWorkspaceBoundary
            or boundary.project_root != PROJECT_ROOT
            or not boundary.writer_available
        ):
            raise WorkspaceIOError(
                WorkspaceIOCode.INVALID_REQUEST,
                "workspace I/O requires the fixed production boundary",
            )
        writer = boundary.require_writer()
        if type(writer) is not _WindowsHandleWriter:
            raise WorkspaceIOError(
                WorkspaceIOCode.WRITER_FAILURE,
                "production boundary did not provide its exact writer",
            )
        self._boundary = boundary
        self._writer = writer

    @property
    def project_root(self) -> Path:
        return self._boundary.project_root

    @property
    def writer_contract_version(self) -> str:
        return PRODUCTION_WRITER_CONTRACT_VERSION

    def ensure_directory(
        self,
        requested: str | os.PathLike[str],
    ) -> Path:
        relative = self._directory_relative_path(requested)
        if relative == Path("."):
            return self.project_root

        current = Path()
        for component in relative.parts:
            current /= component
            try:
                ticket = self._writer.authorize_read_directory(current)
                self._writer.verify_existing_directory(ticket)
                continue
            except HandleWriterError as read_error:
                if read_error.code is not HandleWriterCode.GUARD_REJECTED:
                    self._raise_writer_error(read_error)

            try:
                ticket = self._writer.authorize_create_directory(current)
                with self._writer.create_directory_lease(ticket):
                    pass
            except HandleWriterError as create_error:
                if create_error.code in {
                    HandleWriterCode.GUARD_REJECTED,
                    HandleWriterCode.TARGET_CONFLICT,
                }:
                    try:
                        ticket = self._writer.authorize_read_directory(current)
                        self._writer.verify_existing_directory(ticket)
                        continue
                    except HandleWriterError:
                        pass
                self._raise_writer_error(create_error)
        return self.project_root / relative

    def validate_directory_path(
        self,
        requested: str | os.PathLike[str],
    ) -> Path:
        try:
            ticket = self._writer.authorize_read_directory(requested)
            relative = self._writer.verify_existing_directory(ticket)
        except HandleWriterError as error:
            self._raise_writer_error(error)
        return (
            self.project_root
            if relative == Path(".")
            else self.project_root / relative
        )

    def create_new_bytes(
        self,
        requested: str | os.PathLike[str],
        payload: bytes,
    ) -> WorkspaceWriteReceipt:
        data = self._validate_payload(payload)
        relative = self._new_file_relative_path(requested)
        self.ensure_directory(relative.parent)
        try:
            ticket = self._writer.authorize_create_file(relative)
            receipt = self._writer.create_file(
                ticket,
                data,
                expected_sha256=hashlib.sha256(data).hexdigest(),
            )
        except HandleWriterError as error:
            self._raise_writer_error(error)
        return self._write_receipt(relative, receipt, idempotent=False)

    def write_bytes_idempotent(
        self,
        requested: str | os.PathLike[str],
        payload: bytes,
    ) -> WorkspaceWriteReceipt:
        data = self._validate_payload(payload)
        expected_sha256 = hashlib.sha256(data).hexdigest()
        try:
            ticket = self._writer.authorize_read_file(requested)
            observed = self._writer.read_file(
                ticket,
                maximum_bytes=max(1, len(data)),
            )
        except HandleWriterError as read_error:
            if read_error.code is not HandleWriterCode.GUARD_REJECTED:
                self._raise_writer_error(read_error)
        else:
            if observed.size_bytes != len(data) or observed.sha256 != expected_sha256:
                raise WorkspaceIOError(
                    WorkspaceIOCode.TARGET_CONFLICT,
                    "existing file differs from the requested immutable bytes",
                )
            relative = self._existing_file_relative_path(requested)
            return self._read_receipt(relative, observed)

        return self.create_new_bytes(requested, data)

    def create_new_text(
        self,
        requested: str | os.PathLike[str],
        text: str,
    ) -> WorkspaceWriteReceipt:
        if type(text) is not str:
            raise WorkspaceIOError(
                WorkspaceIOCode.INVALID_REQUEST,
                "text payload must be an exact string",
            )
        return self.create_new_bytes(requested, text.encode("utf-8"))

    def write_text_idempotent(
        self,
        requested: str | os.PathLike[str],
        text: str,
    ) -> WorkspaceWriteReceipt:
        if type(text) is not str:
            raise WorkspaceIOError(
                WorkspaceIOCode.INVALID_REQUEST,
                "text payload must be an exact string",
            )
        return self.write_bytes_idempotent(requested, text.encode("utf-8"))

    def read_bytes(
        self,
        requested: str | os.PathLike[str],
        *,
        maximum_bytes: int,
    ) -> bytes:
        if type(maximum_bytes) is not int or maximum_bytes < 1:
            raise WorkspaceIOError(
                WorkspaceIOCode.INVALID_REQUEST,
                "read limit must be a positive integer",
            )
        try:
            ticket = self._writer.authorize_read_file(requested)
            result = self._writer.read_file(
                ticket,
                maximum_bytes=maximum_bytes,
            )
        except HandleWriterError as error:
            self._raise_writer_error(error)
        return result.payload

    def validate_read_file_path(
        self,
        requested: str | os.PathLike[str],
    ) -> Path:
        """Return one fixed-root path only after handle-level read validation."""

        try:
            ticket = self._writer.authorize_read_file(requested)
            return self._writer.verify_existing_file(ticket)
        except HandleWriterError as error:
            self._raise_writer_error(error)

    def move_directory_no_replace(
        self,
        source: str | os.PathLike[str],
        target: str | os.PathLike[str],
    ) -> DirectoryMoveReceipt:
        """Move one existing fixed-root directory through the handle writer."""

        try:
            return self._writer.move_existing_directory_no_replace(source, target)
        except HandleWriterError as error:
            self._raise_writer_error(error)

    @contextmanager
    def database_mutation_lease(
        self,
        requested: str | os.PathLike[str],
    ) -> Iterator[Path]:
        """Create if needed, then pin one database file for a full connection."""

        try:
            ticket = self._writer.authorize_existing_file_write(requested)
        except HandleWriterError as read_error:
            if read_error.code is not HandleWriterCode.GUARD_REJECTED:
                self._raise_writer_error(read_error)
            relative = self._new_file_relative_path(requested)
            self.ensure_directory(relative.parent)
            try:
                create_ticket = self._writer.authorize_create_file(relative)
                self._writer.create_file(
                    create_ticket,
                    b"",
                    expected_sha256=hashlib.sha256(b"").hexdigest(),
                )
            except HandleWriterError as create_error:
                if create_error.code not in {
                    HandleWriterCode.GUARD_REJECTED,
                    HandleWriterCode.TARGET_CONFLICT,
                }:
                    self._raise_writer_error(create_error)
            try:
                ticket = self._writer.authorize_existing_file_write(relative)
            except HandleWriterError as error:
                self._raise_writer_error(error)

        try:
            with self._writer.lease_existing_mutable_file(ticket) as path:
                yield path
        except HandleWriterError as error:
            self._raise_writer_error(error)

    def _directory_relative_path(
        self,
        requested: str | os.PathLike[str],
    ) -> Path:
        try:
            ticket = self._writer.authorize_read_directory(requested)
        except HandleWriterError:
            try:
                ticket = self._writer.authorize_create_directory(requested)
            except HandleWriterError as error:
                self._raise_writer_error(error)
            relative = ticket.relative_path
            self._writer.discard_issued_ticket(ticket)
            return relative
        relative = self._writer.verify_existing_directory(ticket)
        return relative

    def _new_file_relative_path(
        self,
        requested: str | os.PathLike[str],
    ) -> Path:
        try:
            ticket = self._writer.authorize_create_file(requested)
        except HandleWriterError as error:
            self._raise_writer_error(error)
        relative = ticket.relative_path
        self._writer.discard_issued_ticket(ticket)
        return relative

    def _existing_file_relative_path(
        self,
        requested: str | os.PathLike[str],
    ) -> Path:
        try:
            ticket = self._writer.authorize_read_file(requested)
        except HandleWriterError as error:
            self._raise_writer_error(error)
        relative = ticket.relative_path
        self._writer.discard_issued_ticket(ticket)
        return relative

    @staticmethod
    def _validate_payload(payload: bytes) -> bytes:
        if type(payload) is not bytes:
            raise WorkspaceIOError(
                WorkspaceIOCode.INVALID_REQUEST,
                "file payload must be exact immutable bytes",
            )
        if len(payload) > MAX_DIRECT_WRITE_BYTES:
            raise WorkspaceIOError(
                WorkspaceIOCode.RESOURCE_LIMIT,
                "file payload exceeds the fixed direct-write limit",
            )
        return payload

    @staticmethod
    def _write_receipt(
        relative: Path,
        receipt: HandleWriteReceipt,
        *,
        idempotent: bool,
    ) -> WorkspaceWriteReceipt:
        return WorkspaceWriteReceipt(
            operation=receipt.operation,
            relative_path=relative.as_posix(),
            size_bytes=receipt.size_bytes,
            sha256=receipt.sha256,
            object_reference=receipt.object_reference,
            idempotent=idempotent,
        )

    @staticmethod
    def _read_receipt(
        relative: Path,
        result: HandleReadResult,
    ) -> WorkspaceWriteReceipt:
        return WorkspaceWriteReceipt(
            operation="IDEMPOTENT_EXISTING_FILE",
            relative_path=relative.as_posix(),
            size_bytes=result.size_bytes,
            sha256=result.sha256,
            object_reference=result.object_reference,
            idempotent=True,
        )

    @staticmethod
    def _raise_writer_error(error: HandleWriterError) -> None:
        if error.code is HandleWriterCode.TARGET_CONFLICT:
            code = WorkspaceIOCode.TARGET_CONFLICT
        elif error.code is HandleWriterCode.RESOURCE_LIMIT:
            code = WorkspaceIOCode.RESOURCE_LIMIT
        elif error.code in {
            HandleWriterCode.GUARD_REJECTED,
            HandleWriterCode.INVALID_REQUEST,
            HandleWriterCode.INVALID_TICKET,
        }:
            code = WorkspaceIOCode.PATH_REJECTED
        else:
            code = WorkspaceIOCode.WRITER_FAILURE
        raise WorkspaceIOError(code, "workspace writer rejected the operation") from None


def get_workspace_io() -> ProductionWorkspaceIO:
    global _workspace_io_singleton

    boundary = get_production_boundary()
    current = _workspace_io_singleton
    if current is not None and current._boundary is boundary:
        return current
    with _WORKSPACE_IO_LOCK:
        current = _workspace_io_singleton
        if current is None or current._boundary is not boundary:
            current = ProductionWorkspaceIO(
                boundary,
                _constructor=_WORKSPACE_IO_CONSTRUCTOR,
            )
            _workspace_io_singleton = current
        return current
