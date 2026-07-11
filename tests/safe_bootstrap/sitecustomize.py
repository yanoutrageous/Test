from __future__ import annotations

import ntpath
import os
import stat
import sys
from collections.abc import Mapping
from pathlib import Path, PureWindowsPath


_EXPECTED_PROJECT_ROOT = Path(r"D:\AAA命题\Test")
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _absolute_lexical(path: str | os.PathLike[str]) -> Path:
    raw = os.fspath(path)
    if type(raw) is not str:
        raise PermissionError("SAFE_TEST_HARDLINK_DENIED: byte paths are forbidden")
    return Path(ntpath.normpath(ntpath.abspath(raw)))


def _relative_parts(candidate: Path, root: Path) -> tuple[str, ...] | None:
    candidate_parts = PureWindowsPath(str(candidate)).parts
    root_parts = PureWindowsPath(str(root)).parts
    if len(candidate_parts) < len(root_parts):
        return None
    for candidate_part, root_part in zip(candidate_parts, root_parts, strict=False):
        if ntpath.normcase(candidate_part) != ntpath.normcase(root_part):
            return None
    return tuple(candidate_parts[len(root_parts) :])


def _same_path(left: Path, right: Path) -> bool:
    return ntpath.normcase(str(left)) == ntpath.normcase(str(right))


def _verify_chain(path: Path) -> None:
    for component in (*reversed(path.parents), path):
        identity = os.lstat(component)
        attributes = int(getattr(identity, "st_file_attributes", 0))
        reparse_tag = int(getattr(identity, "st_reparse_tag", 0))
        if stat.S_ISLNK(identity.st_mode) or attributes & _REPARSE_ATTRIBUTE or reparse_tag:
            raise PermissionError(
                "SAFE_TEST_HARDLINK_DENIED: reparse point in hardlink path"
            )


def _install_hardlink_guard() -> None:
    if os.environ.get("M0_TEST_HARDLINK_GUARD_REQUIRED") != "1":
        return
    raw_run_root = os.environ.get("M0_TEST_LAB_ROOT")
    if not raw_run_root:
        raise PermissionError(
            "SAFE_TEST_HARDLINK_DENIED: required laboratory root is missing"
        )
    project_root = _absolute_lexical(_EXPECTED_PROJECT_ROOT)
    run_root = _absolute_lexical(raw_run_root)
    test_lab_root = project_root / "tmp" / "test_lab"
    if _relative_parts(run_root, test_lab_root) != (run_root.name,):
        raise PermissionError(
            "SAFE_TEST_HARDLINK_DENIED: invalid test laboratory root"
        )
    _verify_chain(run_root)
    bootstrap_root = _absolute_lexical(Path(__file__).parent)
    original_link = os.link

    def validate_link_request(
        source: str | os.PathLike[str],
        destination: str | os.PathLike[str],
        src_dir_fd: int | None,
        dst_dir_fd: int | None,
    ) -> tuple[Path, Path]:
        if src_dir_fd not in {None, -1} or dst_dir_fd not in {None, -1}:
            raise PermissionError(
                "SAFE_TEST_HARDLINK_DENIED: directory descriptors are forbidden"
            )
        source_path = _absolute_lexical(source)
        destination_path = _absolute_lexical(destination)
        source_tail = _relative_parts(source_path, run_root)
        destination_tail = _relative_parts(destination_path, run_root)
        if not source_tail or not destination_tail:
            raise PermissionError(
                "SAFE_TEST_HARDLINK_DENIED: both endpoints must be inside the current run"
            )
        _verify_chain(source_path)
        _verify_chain(destination_path.parent)
        source_identity = os.lstat(source_path)
        if not stat.S_ISREG(source_identity.st_mode):
            raise PermissionError(
                "SAFE_TEST_HARDLINK_DENIED: source must be a regular file"
            )
        return source_path, destination_path

    def process_tokens(value: object) -> tuple[str, ...]:
        if type(value) is str:
            if os.name != "nt":
                raise PermissionError(
                    "SAFE_TEST_PROCESS_DENIED: command-line parsing requires Windows"
                )
            import ctypes
            from ctypes import wintypes

            shell32 = ctypes.WinDLL("shell32", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            shell32.CommandLineToArgvW.argtypes = [
                wintypes.LPCWSTR,
                ctypes.POINTER(ctypes.c_int),
            ]
            shell32.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
            kernel32.LocalFree.argtypes = [ctypes.c_void_p]
            kernel32.LocalFree.restype = ctypes.c_void_p
            argument_count = ctypes.c_int(0)
            argument_vector = shell32.CommandLineToArgvW(
                value,
                ctypes.byref(argument_count),
            )
            if not argument_vector or argument_count.value < 1:
                raise PermissionError(
                    "SAFE_TEST_PROCESS_DENIED: cannot parse Windows command line"
                )
            try:
                return tuple(
                    argument_vector[index] for index in range(argument_count.value)
                )
            finally:
                if kernel32.LocalFree(ctypes.cast(argument_vector, ctypes.c_void_p)):
                    raise PermissionError(
                        "SAFE_TEST_PROCESS_DENIED: cannot release parsed command line"
                    )
        if isinstance(value, (list, tuple)):
            if not value or any(type(item) is not str for item in value):
                raise PermissionError(
                    "SAFE_TEST_PROCESS_DENIED: process arguments must be strings"
                )
            return tuple(value)
        raise PermissionError(
            "SAFE_TEST_PROCESS_DENIED: process arguments are not auditable"
        )

    def direct_pytest_canary_allowed(
        tokens: tuple[str, ...],
        environment: object,
        cwd: object,
    ) -> bool:
        if type(environment) is not dict:
            return False
        expected_environment = os.environ.copy()
        for name in (
            "M0_TEST_LAB_ROOT",
            "M0_TEST_LAB_TOKEN",
            "M0_TEST_HARDLINK_GUARD_ACTIVE",
            "M0_TEST_HARDLINK_GUARD_REQUIRED",
            "PYTHONPATH",
            "PYTEST_ADDOPTS",
            "PYTEST_PLUGINS",
        ):
            expected_environment.pop(name, None)
        expected_environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        expected_environment["M0_TEST_DIRECT_PYTEST_CANARY"] = "1"
        if environment != expected_environment:
            return False
        if cwd is None or not _same_path(
            _absolute_lexical(os.fspath(cwd)),
            project_root,
        ):
            return False
        if len(tokens) != 10 or not _same_path(
            _absolute_lexical(tokens[0]),
            Path(sys.executable),
        ):
            return False
        if tokens[1:9] != (
            "-m",
            "pytest",
            "tests/test_safe_pytest_launcher.py",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            "--basetemp",
        ):
            return False
        try:
            basetemp = _absolute_lexical(tokens[9])
            _verify_chain(basetemp)
        except (OSError, PermissionError, TypeError):
            return False
        return bool(_relative_parts(basetemp, run_root)) and basetemp.is_dir()

    def audited_junction_canary_allowed(
        tokens: tuple[str, ...],
        environment: object,
        cwd: object,
    ) -> bool:
        if not isinstance(environment, Mapping) or cwd is None:
            return False
        if len(tokens) != 8 or tuple(token.casefold() for token in tokens[1:6]) != (
            "/d",
            "/q",
            "/c",
            "mklink",
            "/j",
        ):
            return False
        if set(environment) != {"ComSpec", "SystemRoot", "TEMP", "TMP"}:
            return False
        try:
            system_root = _absolute_lexical(environment["SystemRoot"])
            expected_cmd = system_root / "System32" / "cmd.exe"
            executable_path = _absolute_lexical(tokens[0])
            configured_comspec = _absolute_lexical(environment["ComSpec"])
            cwd_path = _absolute_lexical(os.fspath(cwd))
            temp_path = _absolute_lexical(environment["TEMP"])
            tmp_path = _absolute_lexical(environment["TMP"])
            link_path = _absolute_lexical(tokens[6])
            target_path = _absolute_lexical(tokens[7])
            if not (
                _same_path(executable_path, expected_cmd)
                and _same_path(configured_comspec, expected_cmd)
                and _same_path(temp_path, tmp_path)
            ):
                return False
            if not all(
                _relative_parts(path, run_root)
                for path in (cwd_path, temp_path, link_path, target_path)
            ):
                return False
            _verify_chain(expected_cmd)
            _verify_chain(cwd_path)
            _verify_chain(temp_path)
            _verify_chain(link_path.parent)
            _verify_chain(target_path)
        except (KeyError, OSError, PermissionError, TypeError):
            return False
        return (
            expected_cmd.is_file()
            and cwd_path.is_dir()
            and temp_path.is_dir()
            and not os.path.lexists(link_path)
            and target_path.is_dir()
        )

    def validate_process(event_args: tuple[object, ...]) -> None:
        if len(event_args) < 2:
            raise PermissionError(
                "SAFE_TEST_PROCESS_DENIED: malformed process audit event"
            )
        executable = event_args[0]
        tokens = process_tokens(event_args[1])
        cwd = event_args[2] if len(event_args) > 2 else None
        environment = event_args[3] if len(event_args) > 3 else None
        executable_text = os.fspath(executable) if executable is not None else tokens[0]
        if type(executable_text) is not str:
            raise PermissionError(
                "SAFE_TEST_PROCESS_DENIED: byte executable paths are forbidden"
            )
        basename = ntpath.basename(executable_text).casefold()
        pythonish = basename in {
            "python.exe",
            "pythonw.exe",
            "python3.exe",
            "py.exe",
        }
        def validate_python_invocation() -> None:
            option_index = 1
            if option_index < len(tokens) and tokens[option_index] == "-B":
                option_index += 1
            if option_index >= len(tokens) or tokens[option_index] not in {"-c", "-m"}:
                raise PermissionError(
                    "SAFE_TEST_PROCESS_DENIED: Python child must use audited -c or -m mode"
                )

        if pythonish:
            if not _same_path(_absolute_lexical(executable_text), Path(sys.executable)):
                raise PermissionError(
                    "SAFE_TEST_PROCESS_DENIED: alternate Python is forbidden"
                )
            validate_python_invocation()
            if not direct_pytest_canary_allowed(tokens, environment, cwd):
                child_environment = os.environ if environment is None else environment
                if not isinstance(child_environment, Mapping):
                    raise PermissionError(
                        "SAFE_TEST_PROCESS_DENIED: child environment is not auditable"
                    )
                if child_environment.get("M0_TEST_LAB_ROOT") != str(run_root):
                    raise PermissionError(
                        "SAFE_TEST_PROCESS_DENIED: child lost its laboratory root"
                    )
                if child_environment.get("M0_TEST_HARDLINK_GUARD_REQUIRED") != "1":
                    raise PermissionError(
                        "SAFE_TEST_PROCESS_DENIED: child disabled the hardlink guard"
                    )
                child_pythonpath = child_environment.get("PYTHONPATH")
                if not child_pythonpath or not _same_path(
                    _absolute_lexical(child_pythonpath),
                    bootstrap_root,
                ):
                    raise PermissionError(
                        "SAFE_TEST_PROCESS_DENIED: child lost the audited bootstrap"
                    )
        elif not audited_junction_canary_allowed(tokens, environment, cwd):
            raise PermissionError(
                "SAFE_TEST_PROCESS_DENIED: external processes are not allow-listed"
            )
        joined = " ".join(tokens).casefold()
        if (
            ("fsutil" in joined and "hardlink" in joined)
            or ("mklink" in joined and "/h" in joined)
            or ("new-item" in joined and "hardlink" in joined)
            or "createhardlink" in joined
        ):
            raise PermissionError(
                "SAFE_TEST_PROCESS_DENIED: native hardlink commands are forbidden"
            )

    def audit_hook(event: str, event_args: tuple[object, ...]) -> None:
        if event == "os.link":
            if len(event_args) != 4:
                raise PermissionError(
                    "SAFE_TEST_HARDLINK_DENIED: malformed link audit event"
                )
            validate_link_request(
                event_args[0],
                event_args[1],
                event_args[2],
                event_args[3],
            )
        elif event == "subprocess.Popen":
            validate_process(event_args)
        elif event == "os.system" or event.startswith("os.startfile"):
            raise PermissionError(
                "SAFE_TEST_PROCESS_DENIED: unaudited process API is forbidden"
            )
        elif (
            event.startswith("os.exec")
            or event.startswith("os.spawn")
            or event == "os.posix_spawn"
        ):
            raise PermissionError(
                "SAFE_TEST_PROCESS_DENIED: alternate process API is forbidden"
            )
        elif event == "ctypes.dlsym" and len(event_args) >= 2:
            symbol = str(event_args[1]).casefold()
            if symbol in {
                "createhardlinka",
                "createhardlinkw",
                "createhardlinktransacteda",
                "createhardlinktransactedw",
                "createprocessa",
                "createprocessw",
                "createprocessasusera",
                "createprocessasuserw",
                "createprocesswithlogona",
                "createprocesswithlogonw",
                "createprocesswithtokenw",
                "shellexecutea",
                "shellexecutew",
                "shellexecuteexa",
                "shellexecuteexw",
                "winexec",
            }:
                raise PermissionError(
                    "SAFE_TEST_PROCESS_DENIED: native process or hardlink API is forbidden"
                )

    globals()["_INSTALLED_AUDIT_HOOK"] = audit_hook
    sys.addaudithook(audit_hook)

    def guarded_link(
        source: str | os.PathLike[str],
        destination: str | os.PathLike[str],
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        source_path, destination_path = validate_link_request(
            source,
            destination,
            src_dir_fd,
            dst_dir_fd,
        )
        original_link(
            source_path,
            destination_path,
            follow_symlinks=follow_symlinks,
        )
        source_after = os.lstat(source_path)
        destination_after = os.lstat(destination_path)
        if (
            not stat.S_ISREG(destination_after.st_mode)
            or source_after.st_dev != destination_after.st_dev
            or source_after.st_ino != destination_after.st_ino
            or source_after.st_nlink < 2
            or destination_after.st_nlink < 2
        ):
            raise PermissionError(
                "SAFE_TEST_HARDLINK_DENIED: hardlink postcondition failed"
            )

    globals()["_INSTALLED_LINK_GUARD"] = guarded_link
    os.link = guarded_link
    if os.name == "nt":
        nt_module = __import__("nt")
        nt_module.link = guarded_link
    os.environ["M0_TEST_HARDLINK_GUARD_ACTIVE"] = "1"


try:
    os.environ.pop("M0_TEST_HARDLINK_GUARD_ACTIVE", None)
    _install_hardlink_guard()
except BaseException:
    os._exit(96)
