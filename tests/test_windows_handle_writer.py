from __future__ import annotations

import ctypes
import hashlib
import json
import os
import threading
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest

from app.safety import production_guard as production_guard_module
from app.safety.production_guard import _create_test_handle_writer
from app.safety.windows_handle_writer import (
    HandleWriterCode,
    HandleWriterError,
    _ByHandleFileInformation,
    _FileAttributeTagInfo,
    _FileBasicInfo,
    _FileId128,
    _FileIdInfo,
    _FileStandardInfo,
    _WindowsApi,
    _WindowsHandleWriter,
)


@dataclass(frozen=True)
class _HandleLab:
    project: Path
    protected: Path
    sentinel: Path
    writer: object


@pytest.fixture
def handle_lab(tmp_path: Path) -> Iterator[_HandleLab]:
    project = tmp_path / "project"
    protected = tmp_path / "protected"
    project.mkdir()
    protected.mkdir()
    sentinel = protected / "sentinel.bin"
    sentinel.write_bytes(b"handle-writer-protected-sentinel")
    lab = _HandleLab(
        project=project,
        protected=protected,
        sentinel=sentinel,
        writer=_create_test_handle_writer(project),
    )
    yield lab
    assert sentinel.read_bytes() == b"handle-writer-protected-sentinel"
    assert {path.name for path in protected.iterdir()} == {"sentinel.bin"}


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _assert_serialized_error_is_path_free(
    error: HandleWriterError,
    *forbidden_values: str,
) -> None:
    surface = repr(error.args) + repr(error.__dict__) + str(error) + repr(error)
    assert error.__cause__ is None
    assert error.__context__ is None
    for value in forbidden_values:
        assert value not in surface


def test_create_file_with_chinese_path_is_handle_verified(handle_lab: _HandleLab) -> None:
    writer = handle_lab.writer
    parent = handle_lab.project / "中文目录"
    parent.mkdir()
    payload = "函数与几何\n".encode("utf-8")
    ticket = writer.authorize_create_file(Path("中文目录") / "题目.tex")

    receipt = writer.create_file(ticket, payload, expected_sha256=_sha256(payload))

    target = parent / "题目.tex"
    assert target.read_bytes() == payload
    assert receipt.operation == "CREATE_FILE"
    assert receipt.size_bytes == len(payload)
    assert receipt.sha256 == _sha256(payload)
    assert receipt.capability_state == "TEST_LOCAL_HANDLE_VERIFIED"
    assert handle_lab.sentinel.read_bytes() == b"handle-writer-protected-sentinel"


def test_ctypes_structures_match_the_64_bit_windows_abi() -> None:
    assert ctypes.sizeof(ctypes.c_void_p) == 8
    assert ctypes.sizeof(_FileId128) == 16
    assert ctypes.sizeof(_FileIdInfo) == 24
    assert ctypes.sizeof(_FileAttributeTagInfo) == 8
    assert ctypes.sizeof(_FileBasicInfo) == 40
    assert _FileBasicInfo.file_attributes.offset == 32
    assert ctypes.sizeof(_FileStandardInfo) == 24
    assert _FileStandardInfo.number_of_links.offset == 16
    assert _FileStandardInfo.delete_pending.offset == 20
    assert _FileStandardInfo.directory.offset == 21
    assert ctypes.sizeof(_ByHandleFileInformation) == 52


def test_factory_requires_current_launcher_token(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("M0_TEST_LAB_TOKEN")

    with pytest.raises(HandleWriterError) as captured:
        _create_test_handle_writer(handle_lab.project)

    assert captured.value.code is HandleWriterCode.INVALID_TEST_WORKSPACE


def test_factory_rejects_a_fabricated_or_historical_run_path(
    handle_lab: _HandleLab,
) -> None:
    active_run = Path(os.environ["M0_TEST_LAB_ROOT"])
    stale_workspace = active_run.parent / "RUN-FABRICATED-HISTORY" / "project"

    with pytest.raises(HandleWriterError) as captured:
        _create_test_handle_writer(stale_workspace)

    assert captured.value.code is HandleWriterCode.INVALID_TEST_WORKSPACE


def test_factory_fences_every_workspace_intermediate_during_guard_construction(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    intermediate = handle_lab.project / "factory-chain"
    moved = handle_lab.project / "factory-chain-moved"
    nested_project = intermediate / "project"
    intermediate.mkdir()
    nested_project.mkdir()
    real_guard = production_guard_module.WorkspaceGuard
    blocked_errors: list[int | None] = []

    def racing_guard(*args: object, **kwargs: object) -> object:
        try:
            os.rename(intermediate, moved)
        except OSError as exc:
            blocked_errors.append(getattr(exc, "winerror", None))
        else:
            os.rename(moved, intermediate)
            pytest.fail("factory intermediate was renameable while its fence was live")
        return real_guard(*args, **kwargs)

    monkeypatch.setattr(production_guard_module, "WorkspaceGuard", racing_guard)
    try:
        production_guard_module._create_test_handle_writer(nested_project)
        assert blocked_errors
        os.rename(intermediate, moved)
        os.rename(moved, intermediate)
    finally:
        if moved.exists() and not intermediate.exists():
            os.rename(moved, intermediate)
        nested_project.rmdir()
        intermediate.rmdir()


def test_factory_verifies_each_opened_ancestor_before_descending(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract_root = Path(production_guard_module.CONTRACT_PROJECT_ROOT)
    tmp_root = contract_root / "tmp"
    actual_lstat = os.lstat
    opened: list[Path] = []
    original_open = _WindowsApi.open_handle

    def substituted_identity(path: object) -> object:
        candidate = Path(path)
        if os.path.normcase(str(candidate)) == os.path.normcase(str(tmp_root)):
            return actual_lstat(contract_root)
        return actual_lstat(candidate)

    def recording_open(self: object, path: Path, **kwargs: int) -> int:
        opened.append(path)
        return original_open(self, path, **kwargs)

    monkeypatch.setattr(os, "lstat", substituted_identity)
    monkeypatch.setattr(_WindowsApi, "open_handle", recording_open)
    with pytest.raises(HandleWriterError) as captured:
        production_guard_module._create_test_handle_writer(handle_lab.project)

    assert captured.value.code is HandleWriterCode.HANDLE_IDENTITY_MISMATCH
    assert [os.path.normcase(str(path)) for path in opened] == [
        os.path.normcase(str(contract_root)),
        os.path.normcase(str(tmp_root)),
    ]


def test_factory_reads_marker_only_after_same_handle_verification(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity_verified: set[int] = set()
    final_path_verified: set[int] = set()
    current_path_verified: set[int] = set()
    marker_reads: list[int] = []
    observed_handles: dict[int, int] = {}
    original_observe = _WindowsHandleWriter._observe_identity
    original_identity = _WindowsHandleWriter._verify_identity
    original_verify = _WindowsHandleWriter._verify_final_path
    original_path_match = _WindowsHandleWriter._verify_path_matches_handle
    original_read = _WindowsHandleWriter._read_bounded_handle

    def recording_observe(self: object, handle: int) -> object:
        observed = original_observe(self, handle)
        observed_handles[id(observed)] = handle
        return observed

    def recording_identity(self: object, expected: object, observed: object) -> None:
        original_identity(self, expected, observed)
        identity_verified.add(observed_handles[id(observed)])

    def recording_verify(self: object, handle: int, expected: Path) -> None:
        original_verify(self, handle, expected)
        final_path_verified.add(handle)

    def recording_path_match(self: object, path: Path, observed: object) -> None:
        original_path_match(self, path, observed)
        current_path_verified.add(observed_handles[id(observed)])

    def recording_read(self: object, handle: int, maximum_bytes: int) -> bytes:
        assert handle in final_path_verified
        assert handle in identity_verified
        assert handle in current_path_verified
        marker_reads.append(handle)
        return original_read(self, handle, maximum_bytes)

    monkeypatch.setattr(_WindowsHandleWriter, "_observe_identity", recording_observe)
    monkeypatch.setattr(_WindowsHandleWriter, "_verify_identity", recording_identity)
    monkeypatch.setattr(_WindowsHandleWriter, "_verify_final_path", recording_verify)
    monkeypatch.setattr(
        _WindowsHandleWriter,
        "_verify_path_matches_handle",
        recording_path_match,
    )
    monkeypatch.setattr(_WindowsHandleWriter, "_read_bounded_handle", recording_read)
    production_guard_module._create_test_handle_writer(handle_lab.project)

    assert len(marker_reads) == 1
    assert marker_reads[0] in final_path_verified


def test_factory_closes_every_acquired_handle_after_unexpected_failure(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[int] = []
    closed: list[int] = []
    original_open = _WindowsApi.open_handle
    original_close = _WindowsApi.close
    original_verify = _WindowsHandleWriter._verify_final_path

    def recording_open(self: object, path: Path, **kwargs: int) -> int:
        handle = original_open(self, path, **kwargs)
        opened.append(handle)
        return handle

    def recording_close(self: object, handle: int) -> None:
        closed.append(handle)
        original_close(self, handle)

    def fail_after_first_verified_path(
        self: object,
        handle: int,
        expected: Path,
    ) -> None:
        original_verify(self, handle, expected)
        if len(opened) == 2:
            raise RuntimeError("injected unexpected factory verification failure")

    monkeypatch.setattr(_WindowsApi, "open_handle", recording_open)
    monkeypatch.setattr(_WindowsApi, "close", recording_close)
    monkeypatch.setattr(
        _WindowsHandleWriter,
        "_verify_final_path",
        fail_after_first_verified_path,
    )
    with pytest.raises(HandleWriterError) as captured:
        production_guard_module._create_test_handle_writer(handle_lab.project)

    assert captured.value.code is HandleWriterCode.INVALID_TEST_WORKSPACE
    assert opened
    assert sorted(closed) == sorted(opened)


def test_create_file_uses_exact_exclusive_handle_flags(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = handle_lab.writer
    ticket = writer.authorize_create_file("flags.bin")
    original = writer._api.open_handle
    calls: list[dict[str, int]] = []

    def recording_open(path: Path, **kwargs: int) -> int:
        calls.append(dict(kwargs))
        return original(path, **kwargs)

    monkeypatch.setattr(writer._api, "open_handle", recording_open)
    writer.create_file(ticket, b"flags", expected_sha256=_sha256(b"flags"))

    target_calls = [
        call for call in calls if call["disposition"] == writer._api.CREATE_NEW
    ]
    assert target_calls == [
        {
            "access": writer._api.GENERIC_READ | writer._api.GENERIC_WRITE,
            "share": 0,
            "disposition": writer._api.CREATE_NEW,
            "flags": (
                writer._api.FILE_ATTRIBUTE_NORMAL
                | writer._api.FILE_FLAG_OPEN_REPARSE_POINT
                | writer._api.FILE_FLAG_WRITE_THROUGH
            ),
        }
    ]


def test_append_checks_before_state_and_reads_back(handle_lab: _HandleLab) -> None:
    writer = handle_lab.writer
    target = handle_lab.project / "ledger.segment"
    before = b"PREPARED\n"
    addition = b"COMMITTED\n"
    target.write_bytes(before)
    ticket = writer.authorize_append_file("ledger.segment")

    receipt = writer.append_file(
        ticket,
        addition,
        expected_before_size=len(before),
        expected_before_sha256=_sha256(before),
    )

    assert target.read_bytes() == before + addition
    assert receipt.operation == "APPEND_FILE"
    assert receipt.size_bytes == len(before + addition)
    assert receipt.sha256 == _sha256(before + addition)


def test_declared_digest_mismatch_has_no_write_and_consumes_ticket(
    handle_lab: _HandleLab,
) -> None:
    writer = handle_lab.writer
    payload = b"candidate"
    ticket = writer.authorize_create_file("digest-mismatch.bin")

    with pytest.raises(HandleWriterError) as captured:
        writer.create_file(ticket, payload, expected_sha256=_sha256(b"other"))

    assert captured.value.code is HandleWriterCode.PRECONDITION_FAILED
    assert not (handle_lab.project / "digest-mismatch.bin").exists()
    with pytest.raises(HandleWriterError) as replay:
        writer.create_file(ticket, payload, expected_sha256=_sha256(payload))
    assert replay.value.code is HandleWriterCode.TICKET_ALREADY_USED


def test_parent_traversal_cannot_reach_sibling_protected_tree(
    handle_lab: _HandleLab,
) -> None:
    writer = handle_lab.writer

    with pytest.raises(HandleWriterError) as captured:
        writer.authorize_create_file(Path("..") / "protected" / "escape.bin")

    assert captured.value.code is HandleWriterCode.GUARD_REJECTED
    _assert_serialized_error_is_path_free(
        captured.value,
        str(handle_lab.project),
        str(handle_lab.protected),
        "escape.bin",
    )
    assert not (handle_lab.protected / "escape.bin").exists()


def test_append_precondition_failure_does_not_change_file(handle_lab: _HandleLab) -> None:
    writer = handle_lab.writer
    target = handle_lab.project / "append-precondition.bin"
    before = b"immutable-before"
    target.write_bytes(before)
    ticket = writer.authorize_append_file(target.name)

    with pytest.raises(HandleWriterError) as captured:
        writer.append_file(
            ticket,
            b"forbidden",
            expected_before_size=len(before),
            expected_before_sha256=_sha256(b"wrong"),
        )

    assert captured.value.code is HandleWriterCode.PRECONDITION_FAILED
    assert target.read_bytes() == before


def test_parent_replacement_after_authorization_is_rejected(handle_lab: _HandleLab) -> None:
    writer = handle_lab.writer
    parent = handle_lab.project / "stable-parent"
    old_parent = handle_lab.project / "old-parent"
    parent.mkdir()
    ticket = writer.authorize_create_file(Path(parent.name) / "target.bin")
    parent.rename(old_parent)
    parent.mkdir()

    with pytest.raises(HandleWriterError) as captured:
        writer.create_file(ticket, b"x", expected_sha256=_sha256(b"x"))

    assert captured.value.code is HandleWriterCode.GUARD_REJECTED
    assert not (parent / "target.bin").exists()
    assert not (old_parent / "target.bin").exists()


def test_create_file_rejects_a_missing_direct_parent_before_open(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = handle_lab.writer
    ticket = writer.authorize_create_file(Path("missing-parent") / "target.bin")

    def forbidden_open(*_args: object, **_kwargs: object) -> int:
        pytest.fail("missing direct parent reached the native open primitive")

    monkeypatch.setattr(writer._api, "open_handle", forbidden_open)

    with pytest.raises(HandleWriterError) as captured:
        writer.create_file(ticket, b"never", expected_sha256=_sha256(b"never"))

    assert captured.value.code is HandleWriterCode.PRECONDITION_FAILED
    assert not (handle_lab.project / "missing-parent").exists()


def test_parent_fence_blocks_rename_until_postcondition(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = handle_lab.writer
    parent = handle_lab.project / "fenced-parent"
    moved = handle_lab.project / "moved-parent"
    parent.mkdir()
    ticket = writer.authorize_create_file(Path(parent.name) / "target.bin")
    observed: list[int] = []

    def try_rename(_ticket: object) -> None:
        with pytest.raises(PermissionError) as captured:
            os.rename(parent, moved)
        observed.append(int(captured.value.winerror or 0))

    monkeypatch.setattr(writer, "_after_fences", try_rename)
    receipt = writer.create_file(ticket, b"safe", expected_sha256=_sha256(b"safe"))

    assert observed
    assert receipt.sha256 == _sha256(b"safe")
    assert (parent / "target.bin").read_bytes() == b"safe"
    assert not moved.exists()
    os.rename(parent, moved)
    assert (moved / "target.bin").read_bytes() == b"safe"
    os.rename(moved, parent)


def test_concurrent_ticket_reuse_has_exactly_one_winner(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = handle_lab.writer
    ticket = writer.authorize_create_file("concurrent.bin")
    entered = threading.Event()
    release = threading.Event()
    result: list[object] = []

    def pause(_ticket: object) -> None:
        entered.set()
        assert release.wait(timeout=10)

    def first_writer() -> None:
        try:
            result.append(
                writer.create_file(ticket, b"winner", expected_sha256=_sha256(b"winner"))
            )
        except BaseException as exc:  # pragma: no cover - asserted after join.
            result.append(exc)

    monkeypatch.setattr(writer, "_after_fences", pause)
    thread = threading.Thread(target=first_writer, daemon=True)
    thread.start()
    assert entered.wait(timeout=10)
    with pytest.raises(HandleWriterError) as captured:
        writer.create_file(ticket, b"winner", expected_sha256=_sha256(b"winner"))
    assert captured.value.code is HandleWriterCode.TICKET_ALREADY_USED
    release.set()
    thread.join(timeout=10)

    assert not thread.is_alive()
    assert len(result) == 1
    assert not isinstance(result[0], BaseException)
    assert (handle_lab.project / "concurrent.bin").read_bytes() == b"winner"


def test_different_ticket_is_busy_not_consumed_during_an_active_mutation(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = handle_lab.writer
    first_ticket = writer.authorize_create_file("busy-first.bin")
    second_ticket = writer.authorize_create_file("busy-second.bin")
    entered = threading.Event()
    release = threading.Event()
    result: list[object] = []

    def pause(_ticket: object) -> None:
        entered.set()
        assert release.wait(timeout=10)

    def first_writer() -> None:
        try:
            result.append(
                writer.create_file(
                    first_ticket,
                    b"first",
                    expected_sha256=_sha256(b"first"),
                )
            )
        except BaseException as exc:  # pragma: no cover - asserted after join.
            result.append(exc)

    monkeypatch.setattr(writer, "_after_fences", pause)
    thread = threading.Thread(target=first_writer, daemon=True)
    thread.start()
    assert entered.wait(timeout=10)
    with pytest.raises(HandleWriterError) as captured:
        writer.create_file(
            second_ticket,
            b"second",
            expected_sha256=_sha256(b"second"),
        )
    assert captured.value.code is HandleWriterCode.WRITER_BUSY
    release.set()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert result and not isinstance(result[0], BaseException)

    monkeypatch.setattr(writer, "_after_fences", lambda _ticket: None)
    writer.create_file(
        second_ticket,
        b"second",
        expected_sha256=_sha256(b"second"),
    )
    assert (handle_lab.project / "busy-second.bin").read_bytes() == b"second"


def test_short_write_fails_and_retains_unpublished_residue(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = handle_lab.writer
    ticket = writer.authorize_create_file("short-write.staging")
    payload = b"0123456789"
    original = writer._write_once

    def short_write(handle: int, requested: bytes) -> int:
        return original(handle, requested[:3])

    monkeypatch.setattr(writer, "_write_once", short_write)
    with pytest.raises(HandleWriterError) as captured:
        writer.create_file(ticket, payload, expected_sha256=_sha256(payload))

    assert captured.value.code is HandleWriterCode.SHORT_WRITE
    residue = handle_lab.project / "short-write.staging"
    assert residue.read_bytes() == payload[:3]
    with pytest.raises(HandleWriterError) as replay:
        writer.create_file(ticket, payload, expected_sha256=_sha256(payload))
    assert replay.value.code is HandleWriterCode.TICKET_ALREADY_USED


def test_same_length_corrupt_append_is_rejected_by_expected_after_hash(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = handle_lab.writer
    target = handle_lab.project / "corrupt-append.staging"
    before = b"before\n"
    payload = b"expected\n"
    target.write_bytes(before)
    ticket = writer.authorize_append_file(target.name)
    original = writer._write_once

    def corrupt_write(handle: int, requested: bytes) -> int:
        replacement = bytes((byte ^ 0x01) for byte in requested)
        return original(handle, replacement)

    monkeypatch.setattr(writer, "_write_once", corrupt_write)
    with pytest.raises(HandleWriterError) as captured:
        writer.append_file(
            ticket,
            payload,
            expected_before_size=len(before),
            expected_before_sha256=_sha256(before),
        )

    assert captured.value.code is HandleWriterCode.POSTCONDITION_FAILED
    assert len(target.read_bytes()) == len(before + payload)
    assert target.read_bytes() != before + payload


def test_guard_release_failure_seals_writer_without_ticket_accumulation(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = handle_lab.writer
    ticket = writer.authorize_create_file("release-failure.bin")

    def fail_release(_ticket: object) -> bool:
        raise RuntimeError("injected release failure")

    monkeypatch.setattr(writer._path_authority, "release", fail_release)
    with pytest.raises(HandleWriterError) as captured:
        writer.create_file(ticket, b"x", expected_sha256=_sha256(b"wrong"))

    assert captured.value.code is HandleWriterCode.TICKET_RELEASE_FAILED
    assert captured.value.__context__ is None
    assert writer._path_authority.live_ticket_count == 1
    with pytest.raises(HandleWriterError) as sealed:
        writer.authorize_create_file("must-not-issue.bin")
    assert sealed.value.code is HandleWriterCode.WRITER_SEALED
    assert writer._path_authority.live_ticket_count == 1


def test_close_failure_blocks_success_and_seals_writer(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = handle_lab.writer
    ticket = writer.authorize_create_file("close-failure.staging")
    original = writer._api.close
    injected = False

    def close_then_fail(handle: int) -> None:
        nonlocal injected
        original(handle)
        if not injected:
            injected = True
            raise HandleWriterError(
                HandleWriterCode.HANDLE_CLOSE_FAILED,
                "injected close failure",
            )

    monkeypatch.setattr(writer._api, "close", close_then_fail)
    with pytest.raises(HandleWriterError) as captured:
        writer.create_file(ticket, b"closed", expected_sha256=_sha256(b"closed"))

    assert captured.value.code is HandleWriterCode.HANDLE_CLOSE_FAILED
    with pytest.raises(HandleWriterError) as sealed:
        writer.authorize_create_file("must-not-open.bin")
    assert sealed.value.code is HandleWriterCode.WRITER_SEALED


def test_seal_releases_preissued_unused_tickets(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = handle_lab.writer
    active = writer.authorize_create_file("seal-active.bin")
    unused = writer.authorize_create_file("seal-unused.bin")
    original = writer._api.close
    injected = False

    def close_then_fail(handle: int) -> None:
        nonlocal injected
        original(handle)
        if not injected:
            injected = True
            raise HandleWriterError(
                HandleWriterCode.HANDLE_CLOSE_FAILED,
                "injected close failure",
            )

    monkeypatch.setattr(writer._api, "close", close_then_fail)
    with pytest.raises(HandleWriterError) as captured:
        writer.create_file(active, b"x", expected_sha256=_sha256(b"x"))

    assert captured.value.code is HandleWriterCode.HANDLE_CLOSE_FAILED
    assert writer._issued == {}
    assert writer._path_authority.live_ticket_count == 0
    with pytest.raises(HandleWriterError) as replay:
        writer.create_file(unused, b"y", expected_sha256=_sha256(b"y"))
    assert replay.value.code is HandleWriterCode.WRITER_SEALED


def test_close_failure_remains_primary_when_ticket_release_also_fails(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = handle_lab.writer
    ticket = writer.authorize_create_file("double-cleanup-failure.bin")
    original_close = writer._api.close
    injected = False
    close_calls = 0
    release_calls = 0

    def close_then_fail(handle: int) -> None:
        nonlocal close_calls, injected
        close_calls += 1
        original_close(handle)
        if not injected:
            injected = True
            raise HandleWriterError(
                HandleWriterCode.HANDLE_CLOSE_FAILED,
                "injected close failure",
            )

    def fail_release(_ticket: object) -> bool:
        nonlocal release_calls
        release_calls += 1
        raise RuntimeError("injected release failure")

    monkeypatch.setattr(writer._api, "close", close_then_fail)
    monkeypatch.setattr(writer._path_authority, "release", fail_release)
    with pytest.raises(HandleWriterError) as captured:
        writer.create_file(ticket, b"x", expected_sha256=_sha256(b"x"))

    assert captured.value.code is HandleWriterCode.HANDLE_CLOSE_FAILED
    assert writer._poisoned == HandleWriterCode.HANDLE_CLOSE_FAILED.value
    assert close_calls >= 2
    assert release_calls == 1


def test_hardlink_append_target_is_rejected_before_writer(handle_lab: _HandleLab) -> None:
    writer = handle_lab.writer
    source = handle_lab.project / "hardlink-source.bin"
    alias = handle_lab.project / "hardlink-alias.bin"
    source.write_bytes(b"source")
    os.link(source, alias)

    try:
        with pytest.raises(HandleWriterError) as captured:
            writer.authorize_append_file(source.name)

        assert captured.value.code is HandleWriterCode.GUARD_REJECTED
        assert source.read_bytes() == b"source"
        assert alias.read_bytes() == b"source"
    finally:
        manifest = {
            "action": "unlink-exact-synthetic-hardlink-alias",
            "alias": alias.name,
            "source": source.name,
            "sha256": _sha256(b"source"),
        }
        (handle_lab.project / "hardlink-cleanup.json").write_text(
            json.dumps(manifest, ensure_ascii=True, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        alias.unlink()


def test_hardlink_added_after_authorization_is_rejected_by_revalidation(
    handle_lab: _HandleLab,
) -> None:
    writer = handle_lab.writer
    source = handle_lab.project / "race-source.bin"
    alias = handle_lab.project / "race-alias.bin"
    source.write_bytes(b"source")
    ticket = writer.authorize_append_file(source.name)
    os.link(source, alias)
    try:
        with pytest.raises(HandleWriterError) as captured:
            writer.append_file(
                ticket,
                b"forbidden",
                expected_before_size=6,
                expected_before_sha256=_sha256(b"source"),
            )
        assert captured.value.code is HandleWriterCode.GUARD_REJECTED
        assert source.read_bytes() == b"source"
    finally:
        (handle_lab.project / "race-hardlink-cleanup.json").write_text(
            json.dumps(
                {
                    "action": "unlink-exact-synthetic-race-alias",
                    "alias": alias.name,
                    "sha256": _sha256(b"source"),
                },
                ensure_ascii=True,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        alias.unlink()


def test_final_component_swap_after_authorization_is_rejected(
    handle_lab: _HandleLab,
) -> None:
    writer = handle_lab.writer
    target = handle_lab.project / "swap.bin"
    old = handle_lab.project / "swap-old.bin"
    target.write_bytes(b"authorized")
    ticket = writer.authorize_append_file(target.name)
    target.rename(old)
    target.write_bytes(b"replacement")

    with pytest.raises(HandleWriterError) as captured:
        writer.append_file(
            ticket,
            b"forbidden",
            expected_before_size=len(b"authorized"),
            expected_before_sha256=_sha256(b"authorized"),
        )

    assert captured.value.code is HandleWriterCode.GUARD_REJECTED
    assert target.read_bytes() == b"replacement"
    assert old.read_bytes() == b"authorized"


def test_flush_failure_never_returns_success_and_consumes_ticket(
    handle_lab: _HandleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = handle_lab.writer
    payload = b"flush-failure"
    ticket = writer.authorize_create_file("flush-failure.staging")

    def fail_flush(_handle: int) -> None:
        raise HandleWriterError(HandleWriterCode.FLUSH_FAILED, "injected flush failure")

    monkeypatch.setattr(writer, "_flush", fail_flush)
    with pytest.raises(HandleWriterError) as captured:
        writer.create_file(ticket, payload, expected_sha256=_sha256(payload))

    assert captured.value.code is HandleWriterCode.FLUSH_FAILED
    assert (handle_lab.project / "flush-failure.staging").read_bytes() == payload
    with pytest.raises(HandleWriterError) as replay:
        writer.create_file(ticket, payload, expected_sha256=_sha256(payload))
    assert replay.value.code is HandleWriterCode.TICKET_ALREADY_USED


def test_alternate_data_stream_is_rejected_without_default_stream_change(
    handle_lab: _HandleLab,
) -> None:
    writer = handle_lab.writer
    target = handle_lab.project / "ads-source.bin"
    before = b"default-stream"
    target.write_bytes(before)
    with open(f"{target}:hidden", "wb") as stream:
        stream.write(b"hidden-stream")
    ticket = writer.authorize_append_file(target.name)

    with pytest.raises(HandleWriterError) as captured:
        writer.append_file(
            ticket,
            b"forbidden",
            expected_before_size=len(before),
            expected_before_sha256=_sha256(before),
        )

    assert captured.value.code is HandleWriterCode.HANDLE_IDENTITY_MISMATCH
    assert target.read_bytes() == before


def test_receipt_and_errors_do_not_disclose_paths_or_handles(handle_lab: _HandleLab) -> None:
    writer = handle_lab.writer
    secret_name = "绝密路径名.bin"
    payload = b"redacted"
    ticket = writer.authorize_create_file(secret_name)
    receipt = writer.create_file(ticket, payload, expected_sha256=_sha256(payload))
    serialized = repr(receipt) + str(asdict(receipt))

    assert str(handle_lab.project) not in serialized
    assert secret_name not in serialized
    assert len(receipt.object_reference) == 64

    conflict = writer.authorize_create_file("conflict.bin")
    (handle_lab.project / "conflict.bin").write_bytes(b"racer")
    with pytest.raises(HandleWriterError) as captured:
        writer.create_file(conflict, b"new", expected_sha256=_sha256(b"new"))
    error_text = str(captured.value) + repr(captured.value)
    assert str(handle_lab.project) not in error_text
    assert "conflict.bin" not in error_text
    _assert_serialized_error_is_path_free(
        captured.value,
        str(handle_lab.project),
        "conflict.bin",
    )
