from __future__ import annotations

import ntpath
import os
import re
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PureWindowsPath
from typing import Any, Protocol


_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_INVALID_COMPONENT_CHARACTERS = frozenset('<>"|?*')
_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CLOCK$",
        "CONIN$",
        "CONOUT$",
    }
)
_RESERVED_NUMBERED = re.compile(r"^(?:COM|LPT)(?:[1-9¹²³])$", re.IGNORECASE)
_UNEXPANDED_VARIABLE = re.compile(
    r"(?:%[^%]+%|\$env:|\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)


class GuardErrorCode(StrEnum):
    EMPTY_PATH = "EMPTY_PATH"
    IMPLICIT_CWD = "IMPLICIT_CWD"
    UNEXPANDED_VARIABLE = "UNEXPANDED_VARIABLE"
    PARENT_TRAVERSAL = "PARENT_TRAVERSAL"
    UNC_PATH = "UNC_PATH"
    DEVICE_PATH = "DEVICE_PATH"
    ROOTED_NO_DRIVE = "ROOTED_NO_DRIVE"
    DRIVE_RELATIVE = "DRIVE_RELATIVE"
    WRONG_DRIVE = "WRONG_DRIVE"
    ADS = "ADS"
    CONTROL_CHARACTER = "CONTROL_CHARACTER"
    INVALID_CHARACTER = "INVALID_CHARACTER"
    TRAILING_DOT_OR_SPACE = "TRAILING_DOT_OR_SPACE"
    RESERVED_NAME = "RESERVED_NAME"
    ROOT_NOT_ABSOLUTE = "ROOT_NOT_ABSOLUTE"
    ROOT_NOT_FOUND = "ROOT_NOT_FOUND"
    ROOT_NOT_DIRECTORY = "ROOT_NOT_DIRECTORY"
    OUTSIDE_AUTH_ROOT = "OUTSIDE_AUTH_ROOT"
    OUTSIDE_WORKSPACE = "OUTSIDE_WORKSPACE"
    WORKSPACE_ROOT_TARGET = "WORKSPACE_ROOT_TARGET"
    NOT_FOUND = "NOT_FOUND"
    TARGET_ALREADY_EXISTS = "TARGET_ALREADY_EXISTS"
    TYPE_MISMATCH = "TYPE_MISMATCH"
    REPARSE_POINT = "REPARSE_POINT"
    HARDLINK_WRITE_TARGET = "HARDLINK_WRITE_TARGET"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    FILESYSTEM_INSPECTION_FAILED = "FILESYSTEM_INSPECTION_FAILED"
    PATH_STATE_CHANGED = "PATH_STATE_CHANGED"
    INVALID_POLICY = "INVALID_POLICY"


class PathIntent(StrEnum):
    EXISTING_READ = "EXISTING_READ"
    NEW_WRITE = "NEW_WRITE"
    EXISTING_WRITE = "EXISTING_WRITE"
    CREATE_DIRECTORY = "CREATE_DIRECTORY"
    MOVE_SOURCE = "MOVE_SOURCE"
    MOVE_TARGET = "MOVE_TARGET"
    QUARANTINE_SOURCE = "QUARANTINE_SOURCE"

    @property
    def mutating(self) -> bool:
        return self is not PathIntent.EXISTING_READ

    @property
    def requires_existing(self) -> bool:
        return self in {
            PathIntent.EXISTING_READ,
            PathIntent.EXISTING_WRITE,
            PathIntent.MOVE_SOURCE,
            PathIntent.QUARANTINE_SOURCE,
        }

    @property
    def requires_missing(self) -> bool:
        return self in {
            PathIntent.NEW_WRITE,
            PathIntent.CREATE_DIRECTORY,
            PathIntent.MOVE_TARGET,
        }


class ExpectedKind(StrEnum):
    ANY = "ANY"
    FILE = "FILE"
    DIRECTORY = "DIRECTORY"


class WorkspaceGuardError(ValueError):
    def __init__(
        self,
        code: GuardErrorCode,
        *,
        requested: str,
        message: str,
        normalized: str | None = None,
        intent: PathIntent | None = None,
        component: str | None = None,
    ) -> None:
        self.code = code
        self.requested = requested
        self.normalized = normalized
        self.intent = intent
        self.component = component
        self.message = message
        super().__init__(f"{code.value}: {message}")

    def to_audit_dict(self) -> dict[str, str | None]:
        return {
            "code": self.code.value,
            "requested": self.requested,
            "normalized": self.normalized,
            "intent": self.intent.value if self.intent else None,
            "component": self.component,
            "message": self.message,
        }


class WorkspaceGuardConfigurationError(WorkspaceGuardError):
    """Raised when the authorization or workspace root is unsafe."""


class WorkspacePathRejectedError(WorkspaceGuardError):
    """Raised when a requested path is outside policy."""


class WorkspacePathChangedError(WorkspaceGuardError):
    """Raised when a previously authorized path ticket is no longer valid."""


class PathProbe(Protocol):
    def lstat(self, path: Path) -> Any: ...


class NativePathProbe:
    def lstat(self, path: Path) -> os.stat_result:
        return os.lstat(path)


@dataclass(frozen=True)
class PathIdentity:
    path: Path
    device: int
    inode: int
    mode: int
    file_attributes: int
    reparse_tag: int
    nlink: int


@dataclass(frozen=True)
class GuardedPath:
    requested: str
    path: Path
    relative_path: Path
    workspace_root: Path
    intent: PathIntent
    expected_kind: ExpectedKind
    exists: bool
    nearest_existing_ancestor: Path
    chain_snapshot: tuple[PathIdentity, ...]

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "requested": self.requested,
            "path": str(self.path),
            "relative_path": self.relative_path.as_posix(),
            "workspace_root": str(self.workspace_root),
            "intent": self.intent.value,
            "expected_kind": self.expected_kind.value,
            "exists": self.exists,
            "nearest_existing_ancestor": str(self.nearest_existing_ancestor),
            "chain": [
                {
                    "path": str(item.path),
                    "device": item.device,
                    "inode": item.inode,
                    "mode": item.mode,
                    "file_attributes": item.file_attributes,
                    "reparse_tag": item.reparse_tag,
                    "nlink": item.nlink,
                }
                for item in self.chain_snapshot
            ],
        }


class WorkspaceGuard:
    """Side-effect-free Windows path authorization for a bounded workspace.

    This class never creates, opens for write, moves, replaces, or deletes a path.
    A returned ticket must be revalidated immediately before a later writer acts.
    """

    def __init__(
        self,
        authorization_root: str | os.PathLike[str],
        workspace_root: str | os.PathLike[str] | None = None,
        *,
        probe: PathProbe | None = None,
    ) -> None:
        self._probe = probe or NativePathProbe()
        self.authorization_root, self._authorization_snapshot = self._validate_root(
            authorization_root,
            label="authorization_root",
        )
        requested_workspace = (
            self.authorization_root if workspace_root is None else workspace_root
        )
        workspace_raw = _coerce_path(
            requested_workspace,
            error_type=WorkspaceGuardConfigurationError,
        )
        _validate_lexical(
            workspace_raw,
            expected_drive=self.authorization_root.drive,
            require_absolute=True,
            error_type=WorkspaceGuardConfigurationError,
        )
        lexical_workspace = _absolute_lexical(workspace_raw)
        workspace_parts = _relative_components(
            lexical_workspace,
            self.authorization_root,
        )
        if workspace_parts is None:
            raise WorkspaceGuardConfigurationError(
                GuardErrorCode.OUTSIDE_AUTH_ROOT,
                requested=workspace_raw,
                normalized=str(lexical_workspace),
                message="workspace_root must be the authorization root or one of its descendants",
            )
        workspace = self.authorization_root.joinpath(*workspace_parts)
        snapshot, exists = self._inspect_chain(
            self.authorization_root,
            workspace,
            error_type=WorkspaceGuardConfigurationError,
        )
        if not exists:
            raise WorkspaceGuardConfigurationError(
                GuardErrorCode.ROOT_NOT_FOUND,
                requested=workspace_raw,
                normalized=str(workspace),
                message="workspace_root must already exist",
            )
        if not stat.S_ISDIR(snapshot[-1].mode):
            raise WorkspaceGuardConfigurationError(
                GuardErrorCode.ROOT_NOT_DIRECTORY,
                requested=workspace_raw,
                normalized=str(workspace),
                message="workspace_root must be a directory",
            )
        self.workspace_root = workspace
        self._workspace_snapshot = snapshot

    def authorize(
        self,
        requested: str | os.PathLike[str] | None,
        *,
        intent: PathIntent,
        expected_kind: ExpectedKind = ExpectedKind.ANY,
    ) -> GuardedPath:
        if not isinstance(intent, PathIntent):
            raise WorkspacePathRejectedError(
                GuardErrorCode.INVALID_POLICY,
                requested=str(requested),
                message="intent must be a PathIntent value",
            )
        if not isinstance(expected_kind, ExpectedKind):
            raise WorkspacePathRejectedError(
                GuardErrorCode.INVALID_POLICY,
                requested=str(requested),
                intent=intent,
                message="expected_kind must be an ExpectedKind value",
            )
        if (
            intent is PathIntent.CREATE_DIRECTORY
            and expected_kind is not ExpectedKind.DIRECTORY
        ):
            raise WorkspacePathRejectedError(
                GuardErrorCode.INVALID_POLICY,
                requested=str(requested),
                intent=intent,
                message="CREATE_DIRECTORY requires ExpectedKind.DIRECTORY",
            )

        raw = _coerce_path(requested)
        _validate_lexical(
            raw,
            expected_drive=self.workspace_root.drive,
            require_absolute=False,
            error_type=WorkspacePathRejectedError,
            intent=intent,
        )
        pure = PureWindowsPath(raw)
        lexical_candidate = (
            _absolute_lexical(raw)
            if pure.is_absolute()
            else _absolute_lexical(str(self.workspace_root / Path(raw)))
        )
        relative_parts = _relative_components(lexical_candidate, self.workspace_root)
        if relative_parts is None:
            raise WorkspacePathRejectedError(
                GuardErrorCode.OUTSIDE_WORKSPACE,
                requested=raw,
                normalized=str(lexical_candidate),
                intent=intent,
                message="requested path is outside workspace_root",
            )
        candidate = self.workspace_root.joinpath(*relative_parts)
        if not relative_parts and intent.mutating:
            raise WorkspacePathRejectedError(
                GuardErrorCode.WORKSPACE_ROOT_TARGET,
                requested=raw,
                normalized=str(candidate),
                intent=intent,
                message="workspace_root cannot be a mutation target",
            )

        authorization_snapshot, workspace_snapshot = self._revalidate_roots(
            requested=raw,
            intent=intent,
        )
        target_snapshot, exists = self._inspect_chain(
            self.workspace_root,
            candidate,
            error_type=WorkspacePathRejectedError,
            intent=intent,
        )
        target_identity = target_snapshot[-1] if exists else None

        if intent.requires_existing and not exists:
            raise WorkspacePathRejectedError(
                GuardErrorCode.NOT_FOUND,
                requested=raw,
                normalized=str(candidate),
                intent=intent,
                message="requested existing target was not found",
            )
        if intent.requires_missing and exists:
            raise WorkspacePathRejectedError(
                GuardErrorCode.TARGET_ALREADY_EXISTS,
                requested=raw,
                normalized=str(candidate),
                intent=intent,
                message="requested new target already exists",
            )
        if target_identity is not None:
            if expected_kind is ExpectedKind.FILE and not stat.S_ISREG(target_identity.mode):
                raise WorkspacePathRejectedError(
                    GuardErrorCode.TYPE_MISMATCH,
                    requested=raw,
                    normalized=str(candidate),
                    intent=intent,
                    message="target is not a regular file",
                )
            if expected_kind is ExpectedKind.DIRECTORY and not stat.S_ISDIR(
                target_identity.mode
            ):
                raise WorkspacePathRejectedError(
                    GuardErrorCode.TYPE_MISMATCH,
                    requested=raw,
                    normalized=str(candidate),
                    intent=intent,
                    message="target is not a directory",
                )
            if (
                intent.mutating
                and stat.S_ISREG(target_identity.mode)
                and target_identity.nlink > 1
            ):
                raise WorkspacePathRejectedError(
                    GuardErrorCode.HARDLINK_WRITE_TARGET,
                    requested=raw,
                    normalized=str(candidate),
                    intent=intent,
                    message="mutating a file with multiple hard links is forbidden",
                )

        relative_path = Path(*relative_parts) if relative_parts else Path(".")
        snapshot = (
            authorization_snapshot
            + workspace_snapshot[1:]
            + target_snapshot[1:]
        )
        return GuardedPath(
            requested=raw,
            path=candidate,
            relative_path=relative_path,
            workspace_root=self.workspace_root,
            intent=intent,
            expected_kind=expected_kind,
            exists=exists,
            nearest_existing_ancestor=target_snapshot[-1].path,
            chain_snapshot=snapshot,
        )

    def revalidate(self, ticket: GuardedPath) -> GuardedPath:
        if ticket.workspace_root != self.workspace_root:
            raise WorkspacePathChangedError(
                GuardErrorCode.PATH_STATE_CHANGED,
                requested=ticket.requested,
                normalized=str(ticket.path),
                intent=ticket.intent,
                message="ticket belongs to a different workspace",
            )
        try:
            current = self.authorize(
                ticket.requested,
                intent=ticket.intent,
                expected_kind=ticket.expected_kind,
            )
        except WorkspaceGuardError as exc:
            raise WorkspacePathChangedError(
                GuardErrorCode.PATH_STATE_CHANGED,
                requested=ticket.requested,
                normalized=str(ticket.path),
                intent=ticket.intent,
                component=exc.component,
                message=f"path policy or state changed after authorization ({exc.code.value})",
            ) from exc
        if (
            current.path != ticket.path
            or current.exists != ticket.exists
            or current.chain_snapshot != ticket.chain_snapshot
        ):
            raise WorkspacePathChangedError(
                GuardErrorCode.PATH_STATE_CHANGED,
                requested=ticket.requested,
                normalized=str(ticket.path),
                intent=ticket.intent,
                message="path identity changed after authorization",
            )
        return current

    def _validate_root(
        self,
        requested: str | os.PathLike[str],
        *,
        label: str,
    ) -> tuple[Path, tuple[PathIdentity, ...]]:
        raw = _coerce_path(
            requested,
            error_type=WorkspaceGuardConfigurationError,
        )
        _validate_lexical(
            raw,
            expected_drive=None,
            require_absolute=True,
            error_type=WorkspaceGuardConfigurationError,
        )
        root = _absolute_lexical(raw)
        snapshot = self._inspect_full_existing_chain(
            root,
            error_type=WorkspaceGuardConfigurationError,
        )
        if not snapshot:
            raise WorkspaceGuardConfigurationError(
                GuardErrorCode.ROOT_NOT_FOUND,
                requested=raw,
                normalized=str(root),
                message=f"{label} must already exist",
            )
        if snapshot[-1].path != root:
            raise WorkspaceGuardConfigurationError(
                GuardErrorCode.ROOT_NOT_FOUND,
                requested=raw,
                normalized=str(root),
                message=f"{label} must already exist",
            )
        if not stat.S_ISDIR(snapshot[-1].mode):
            raise WorkspaceGuardConfigurationError(
                GuardErrorCode.ROOT_NOT_DIRECTORY,
                requested=raw,
                normalized=str(root),
                message=f"{label} must be a directory",
            )
        return root, snapshot

    def _revalidate_roots(
        self,
        *,
        requested: str,
        intent: PathIntent,
    ) -> tuple[tuple[PathIdentity, ...], tuple[PathIdentity, ...]]:
        try:
            authorization_snapshot = self._inspect_full_existing_chain(
                self.authorization_root,
                error_type=WorkspacePathRejectedError,
            )
            workspace_snapshot, workspace_exists = self._inspect_chain(
                self.authorization_root,
                self.workspace_root,
                error_type=WorkspacePathRejectedError,
                intent=intent,
            )
        except WorkspaceGuardError as exc:
            raise WorkspacePathRejectedError(
                exc.code,
                requested=requested,
                normalized=str(self.workspace_root),
                intent=intent,
                component=exc.component,
                message=f"authorization root chain is no longer safe ({exc.code.value})",
            ) from exc

        if (
            authorization_snapshot != self._authorization_snapshot
            or not workspace_exists
            or workspace_snapshot != self._workspace_snapshot
        ):
            raise WorkspacePathRejectedError(
                GuardErrorCode.PATH_STATE_CHANGED,
                requested=requested,
                normalized=str(self.workspace_root),
                intent=intent,
                message="authorization or workspace root identity changed",
            )
        return authorization_snapshot, workspace_snapshot

    def _inspect_full_existing_chain(
        self,
        target: Path,
        *,
        error_type: type[WorkspaceGuardError],
    ) -> tuple[PathIdentity, ...]:
        chain: list[PathIdentity] = []
        for component in (*reversed(target.parents), target):
            try:
                identity = self._identity(component)
            except FileNotFoundError:
                break
            except PermissionError as exc:
                raise error_type(
                    GuardErrorCode.PERMISSION_DENIED,
                    requested=str(target),
                    normalized=str(target),
                    component=str(component),
                    message="permission denied while inspecting path chain",
                ) from exc
            except OSError as exc:
                raise error_type(
                    GuardErrorCode.FILESYSTEM_INSPECTION_FAILED,
                    requested=str(target),
                    normalized=str(target),
                    component=str(component),
                    message="filesystem inspection failed closed",
                ) from exc
            self._reject_reparse(
                identity,
                requested=str(target),
                error_type=error_type,
            )
            chain.append(identity)
        return tuple(chain)

    def _inspect_chain(
        self,
        root: Path,
        target: Path,
        *,
        error_type: type[WorkspaceGuardError],
        intent: PathIntent | None = None,
    ) -> tuple[tuple[PathIdentity, ...], bool]:
        relative_parts = _relative_components(target, root)
        if relative_parts is None:
            raise error_type(
                GuardErrorCode.OUTSIDE_WORKSPACE,
                requested=str(target),
                normalized=str(target),
                intent=intent,
                message="target escaped the inspected root",
            )
        chain: list[PathIdentity] = []
        current = root
        components = ((), *[(part,) for part in relative_parts])
        for index, addition in enumerate(components):
            if addition:
                current = current / addition[0]
            try:
                identity = self._identity(current)
            except FileNotFoundError:
                return tuple(chain), False
            except PermissionError as exc:
                raise error_type(
                    GuardErrorCode.PERMISSION_DENIED,
                    requested=str(target),
                    normalized=str(target),
                    intent=intent,
                    component=str(current),
                    message="permission denied while inspecting target chain",
                ) from exc
            except OSError as exc:
                raise error_type(
                    GuardErrorCode.FILESYSTEM_INSPECTION_FAILED,
                    requested=str(target),
                    normalized=str(target),
                    intent=intent,
                    component=str(current),
                    message="filesystem inspection failed closed",
                ) from exc
            self._reject_reparse(
                identity,
                requested=str(target),
                intent=intent,
                error_type=error_type,
            )
            chain.append(identity)
            if index < len(components) - 1 and not stat.S_ISDIR(identity.mode):
                raise error_type(
                    GuardErrorCode.TYPE_MISMATCH,
                    requested=str(target),
                    normalized=str(target),
                    intent=intent,
                    component=str(current),
                    message="an existing parent component is not a directory",
                )
        return tuple(chain), True

    def _identity(self, path: Path) -> PathIdentity:
        result = self._probe.lstat(path)
        required_fields = ("st_dev", "st_ino", "st_mode", "st_nlink")
        missing_fields = [name for name in required_fields if not hasattr(result, name)]
        if os.name == "nt":
            missing_fields.extend(
                name
                for name in ("st_file_attributes", "st_reparse_tag")
                if not hasattr(result, name)
            )
        if missing_fields:
            raise OSError(
                "filesystem identity is missing required fields: "
                + ", ".join(sorted(set(missing_fields)))
            )
        device = int(result.st_dev)
        inode = int(result.st_ino)
        if device <= 0 or inode <= 0:
            raise OSError("filesystem did not provide a stable volume and file identity")
        return PathIdentity(
            path=path,
            device=device,
            inode=inode,
            mode=int(result.st_mode),
            file_attributes=int(getattr(result, "st_file_attributes", 0)),
            reparse_tag=int(getattr(result, "st_reparse_tag", 0)),
            nlink=int(result.st_nlink),
        )

    @staticmethod
    def _reject_reparse(
        identity: PathIdentity,
        *,
        requested: str,
        error_type: type[WorkspaceGuardError],
        intent: PathIntent | None = None,
    ) -> None:
        if (
            stat.S_ISLNK(identity.mode)
            or identity.file_attributes & _REPARSE_ATTRIBUTE
            or identity.reparse_tag != 0
        ):
            raise error_type(
                GuardErrorCode.REPARSE_POINT,
                requested=requested,
                normalized=requested,
                intent=intent,
                component=str(identity.path),
                message="symbolic links, junctions and other reparse points are forbidden",
            )


def _coerce_path(
    value: str | os.PathLike[str] | None,
    *,
    error_type: type[WorkspaceGuardError] = WorkspacePathRejectedError,
) -> str:
    if value is None:
        return ""
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise error_type(
            GuardErrorCode.EMPTY_PATH,
            requested="",
            message="path must be text or a path-like value",
        ) from exc
    if isinstance(raw, bytes):
        raise error_type(
            GuardErrorCode.CONTROL_CHARACTER,
            requested=repr(raw),
            message="byte paths are not accepted",
        )
    return raw


def _validate_lexical(
    raw: str,
    *,
    expected_drive: str | None,
    require_absolute: bool,
    error_type: type[WorkspaceGuardError],
    intent: PathIntent | None = None,
) -> None:
    def reject(
        code: GuardErrorCode,
        message: str,
        *,
        component: str | None = None,
    ) -> None:
        raise error_type(
            code,
            requested=raw,
            intent=intent,
            component=component,
            message=message,
        )

    if not raw or not raw.strip():
        reject(GuardErrorCode.EMPTY_PATH, "path is empty")
    if any(ord(character) < 32 or ord(character) == 127 for character in raw):
        reject(GuardErrorCode.CONTROL_CHARACTER, "path contains a control character")
    if raw.startswith("~") or _UNEXPANDED_VARIABLE.search(raw):
        reject(GuardErrorCode.UNEXPANDED_VARIABLE, "path contains an unexpanded variable")

    windows_raw = raw.replace("/", "\\")
    lower = windows_raw.casefold()
    if lower.startswith(("\\\\?\\", "\\\\.\\", "\\??\\")):
        reject(GuardErrorCode.DEVICE_PATH, "device and extended namespaces are forbidden")
    if lower.startswith("\\\\"):
        reject(GuardErrorCode.UNC_PATH, "UNC paths are forbidden")
    if re.match(r"^[A-Za-z]:(?!\\)", windows_raw):
        reject(GuardErrorCode.DRIVE_RELATIVE, "drive-relative paths are forbidden")

    pure = PureWindowsPath(windows_raw)
    if pure.root and not pure.drive:
        reject(GuardErrorCode.ROOTED_NO_DRIVE, "root-relative paths are forbidden")
    if require_absolute and not pure.is_absolute():
        reject(GuardErrorCode.ROOT_NOT_ABSOLUTE, "root paths must be absolute")
    if expected_drive and pure.drive and ntpath.normcase(pure.drive) != ntpath.normcase(
        expected_drive
    ):
        reject(GuardErrorCode.WRONG_DRIVE, "path uses a different drive")

    allowed_colon = 1 if re.match(r"^[A-Za-z]:\\", windows_raw) else None
    for index, character in enumerate(windows_raw):
        if character == ":" and index != allowed_colon:
            reject(GuardErrorCode.ADS, "alternate data stream syntax is forbidden")

    body = windows_raw[3:] if allowed_colon == 1 else windows_raw
    if not body and not require_absolute:
        reject(GuardErrorCode.IMPLICIT_CWD, "path resolves to the implicit current directory")
    components = body.split("\\") if body else []
    for component in components:
        if component == "":
            reject(GuardErrorCode.IMPLICIT_CWD, "empty path components are forbidden")
        if component == ".":
            reject(GuardErrorCode.IMPLICIT_CWD, "current-directory components are forbidden")
        if component == "..":
            reject(GuardErrorCode.PARENT_TRAVERSAL, "parent traversal is forbidden")
        if component.endswith((".", " ")):
            reject(
                GuardErrorCode.TRAILING_DOT_OR_SPACE,
                "path components cannot end in a dot or space",
                component=component,
            )
        if any(character in _INVALID_COMPONENT_CHARACTERS for character in component):
            reject(
                GuardErrorCode.INVALID_CHARACTER,
                "path component contains an invalid character",
                component=component,
            )
        stem = component.split(".", 1)[0].upper()
        if stem in _RESERVED_NAMES or _RESERVED_NUMBERED.fullmatch(stem):
            reject(
                GuardErrorCode.RESERVED_NAME,
                "reserved Windows device name is forbidden",
                component=component,
            )


def _absolute_lexical(raw: str) -> Path:
    return Path(ntpath.normpath(ntpath.abspath(raw)))


def _relative_components(candidate: Path, root: Path) -> tuple[str, ...] | None:
    candidate_parts = PureWindowsPath(str(candidate)).parts
    root_parts = PureWindowsPath(str(root)).parts
    if len(candidate_parts) < len(root_parts):
        return None
    for candidate_part, root_part in zip(candidate_parts, root_parts, strict=False):
        if ntpath.normcase(candidate_part) != ntpath.normcase(root_part):
            return None
    return tuple(candidate_parts[len(root_parts) :])
