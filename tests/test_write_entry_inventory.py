from __future__ import annotations

import ast
import copy
import hashlib
import json
from collections import Counter
from dataclasses import replace

import pytest

from app.config import PROJECT_ROOT
from app.safety.static_audit import (
    _AUDITED_CAPABILITY_STORES,
    _AUDITED_DYNAMIC_CALLS,
    _AUDITED_INDEXED_CALLS,
    _AUDITED_PARAMETER_CALLS,
    _assert_audited_indexed_hits,
    _normalize_source_bytes,
    ENTRY_CHUNK_SIZE,
    MigrationStatus,
    SCANNER_VERSION,
    SOURCE_BYTE_NORMALIZATION,
    WritePrimitiveKind,
    inventory_digest,
    payload_digest,
    production_source_manifest,
    scan_production_write_entries,
    scan_python_source,
    scan_unauthorized_guard_construction,
    scan_unauthorized_guard_source,
)


INVENTORY_PATH = (
    PROJECT_ROOT / "Task" / "reports" / "M0" / "M0-write-entry-inventory.json"
)


def _payload() -> dict:
    return json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))


def _entry_rows(payload: dict) -> list[dict]:
    rows: list[dict] = []
    for expected_index, reference in enumerate(payload["entry_chunks"]):
        chunk_path = PROJECT_ROOT / reference["path"]
        chunk = json.loads(chunk_path.read_text(encoding="utf-8"))
        assert chunk["schema_version"] == "2.0"
        assert chunk["chunk_index"] == expected_index
        assert chunk["entry_count"] == len(chunk["entries"])
        assert 0 < chunk["entry_count"] <= payload["entry_chunk_size"]
        digest_input = dict(chunk)
        chunk_digest = digest_input.pop("chunk_digest_sha256")
        encoded = json.dumps(
            digest_input,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        assert hashlib.sha256(encoded).hexdigest() == chunk_digest
        assert reference["canonical_payload_sha256"] == chunk_digest
        assert reference["serialized_file_sha256"] == hashlib.sha256(
            chunk_path.read_bytes()
        ).hexdigest()
        assert reference["entry_count"] == chunk["entry_count"]
        rows.extend(chunk["entries"])
    return rows


def test_tracked_inventory_matches_full_current_scanner_and_source_manifest() -> None:
    payload = _payload()
    entries = scan_production_write_entries()

    assert payload["schema_version"] == "2.0"
    assert payload["scanner_version"] == SCANNER_VERSION
    assert payload["source_byte_normalization"] == SOURCE_BYTE_NORMALIZATION
    assert payload["entry_chunk_size"] == ENTRY_CHUNK_SIZE
    assert len(payload["source_head"]) == 40
    assert all(character in "0123456789abcdef" for character in payload["source_head"])
    assert payload["entry_count"] == len(entries)
    rows = _entry_rows(payload)
    assert rows == [entry.to_dict() for entry in entries]
    assert payload["entries_digest_sha256"] == inventory_digest(entries)
    assert payload["source_manifest"] == list(production_source_manifest())
    expected_manifest_digest = hashlib.sha256(
        json.dumps(
            payload["source_manifest"],
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    assert payload["source_manifest_digest_sha256"] == expected_manifest_digest
    assert payload["inventory_digest_sha256"] == payload_digest(payload)
    assert inventory_digest(entries)
    referenced_chunks = {reference["path"] for reference in payload["entry_chunks"]}
    actual_chunks = {
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in (INVENTORY_PATH.parent / "write-entry-inventory").glob(
            "entries-*.json"
        )
    }
    assert actual_chunks == referenced_chunks


def test_source_manifest_is_checkout_independent_utf8_lf() -> None:
    payload = _payload()
    assert payload["source_byte_normalization"] == "UTF8_LF_V1"
    attributes = {
        line
        for line in (PROJECT_ROOT / ".gitattributes")
        .read_text(encoding="utf-8")
        .splitlines()
        if line and not line.startswith("#")
    }
    assert {
        "app/*.py text eol=lf",
        "app/**/*.py text eol=lf",
        "app/*.sql text eol=lf",
        "app/**/*.sql text eol=lf",
        "scripts/*.py text eol=lf",
        "scripts/**/*.py text eol=lf",
        "Task/**/*.json text eol=lf",
    }.issubset(attributes)
    for row in payload["source_manifest"]:
        path = PROJECT_ROOT / row["file"]
        canonical = _normalize_source_bytes(path, path.read_bytes())
        assert row["normalization"] == SOURCE_BYTE_NORMALIZATION
        assert row["size_bytes"] == len(canonical)
        assert row["sha256"] == hashlib.sha256(canonical).hexdigest()
        assert b"\r" not in canonical

    fixture = b"first\r\nsecond\rthird\n"
    assert _normalize_source_bytes(PROJECT_ROOT / "synthetic.py", fixture) == (
        b"first\nsecond\nthird\n"
    )


def test_inventory_counts_and_policy_metadata_are_internally_consistent() -> None:
    payload = _payload()
    rows = _entry_rows(payload)
    counts = Counter(row["kind"] for row in rows)

    assert payload["counts_by_kind"] == dict(sorted(counts.items()))
    assert len({row["entry_id"] for row in rows}) == len(rows)
    for row in rows:
        assert row["owner"] not in {"", "UNASSIGNED"}
        assert row["target_namespace"] not in {"", "UNCLASSIFIED"}
        assert row["required_control"]
        assert row["migration_status"] in {
            MigrationStatus.UNMIGRATED_BLOCKED.value,
            MigrationStatus.ACCEPTED_MEMORY_ONLY.value,
        }
        assert row["root_ids"]
        assert row["call_chain"]
        assert row["source_sha256"]
        assert row["statement_fingerprint"]
    assert payload["global_status"] == "UNMIGRATED_BLOCKED"
    assert payload["gate"]["production_writer_connected"] is False
    assert payload["gate"]["m0_exit_allowed"] is False
    assert payload["gate"]["unknown_dynamic_count"] == counts.get(
        WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY.value,
        0,
    )
    assert payload["gate"]["unmigrated_count"] == sum(
        row["migration_status"] == MigrationStatus.UNMIGRATED_BLOCKED.value
        for row in rows
    )
    assert sum(reference["entry_count"] for reference in payload["entry_chunks"]) == len(rows)


def test_inventory_covers_sql_sinks_schema_scripts_and_injected_connections() -> None:
    entries = scan_production_write_entries()
    sites = {(entry.file, entry.function, entry.kind) for entry in entries}
    counts = Counter(entry.kind for entry in entries)

    assert counts[WritePrimitiveKind.SQLITE_MUTATION] >= 52
    assert counts[WritePrimitiveKind.SQLITE_SCHEMA_MUTATION] >= 80
    assert counts[WritePrimitiveKind.SQLITE_RAW_CONNECT] == 7
    assert any(
        file == "app/review_events.py"
        and function.endswith("ReviewEventService.record")
        and kind is WritePrimitiveKind.SQLITE_MUTATION
        for file, function, kind in sites
    )
    assert any(
        file == "app/structured_service.py"
        and function.endswith("StructuredContentService.update_review_status")
        and kind is WritePrimitiveKind.SQLITE_MUTATION
        for file, function, kind in sites
    )
    assert any(entry.file == "app/schema.sql" for entry in entries)
    assert any(
        entry.file == "app/database_migrations.py"
        and entry.kind is WritePrimitiveKind.SQLITE_RAW_CONNECT
        for entry in entries
    )
    assert any(
        entry.file == "app/database_backup.py"
        and entry.kind is WritePrimitiveKind.SQLITE_BACKUP_OR_EXTENSION
        for entry in entries
    )
    assert any(
        entry.file == "scripts/run_safe_pytest.py"
        and entry.kind is WritePrimitiveKind.EXTERNAL_PROCESS
        for entry in entries
    )
    assert any(
        entry.file == "app/__main__.py"
        and entry.kind is WritePrimitiveKind.NETWORK_REQUEST
        for entry in entries
    )
    assert not any(
        entry.kind is WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY
        for entry in entries
    )


def test_no_memory_only_exception_is_inferred_from_file_or_function_name() -> None:
    entries = scan_production_write_entries()
    accepted = [
        entry
        for entry in entries
        if entry.migration_status is MigrationStatus.ACCEPTED_MEMORY_ONLY
    ]

    assert accepted == []
    assert all(
        entry.migration_status is MigrationStatus.UNMIGRATED_BLOCKED
        for entry in entries
    )


def test_full_digests_cover_policy_metadata_and_are_key_order_stable() -> None:
    entries = scan_production_write_entries()
    first = entries[0]
    changed = (replace(first, owner=first.owner + "_CHANGED"), *entries[1:])

    assert inventory_digest(entries) != inventory_digest(changed)

    payload = _payload()
    reordered = {key: payload[key] for key in reversed(tuple(payload))}
    assert payload_digest(payload) == payload_digest(reordered)
    changed_payload = copy.deepcopy(payload)
    changed_payload["entry_chunks"][0]["canonical_payload_sha256"] = "0" * 64
    assert payload_digest(payload) != payload_digest(changed_payload)


def test_alias_dynamic_file_sql_process_and_network_canaries_are_detected() -> None:
    entries = scan_python_source(
        """
import os as operating
import sqlite3 as sql
from shutil import move as mv
from subprocess import run as launch
from urllib.request import urlopen as fetch

def exercise(path, conn, dynamic_sql, dynamic_name):
    writer = path.write_text
    writer('x')
    operating.open(path, operating.O_RDONLY)
    operating.remove(path)
    mv(path, path)
    conn.execute('UPDATE q SET x = 1')
    conn.execute(dynamic_sql)
    launch(['tool'])
    fetch('https://example.invalid')
    getattr(path, dynamic_name)('x')
""",
        file="app/synthetic.py",
    )
    kinds = Counter(entry.kind for entry in entries)

    assert kinds[WritePrimitiveKind.FILESYSTEM_FILE_WRITE] == 1
    assert kinds[WritePrimitiveKind.FILESYSTEM_DELETE] == 1
    assert kinds[WritePrimitiveKind.FILESYSTEM_MOVE_OR_REPLACE] == 1
    assert kinds[WritePrimitiveKind.SQLITE_MUTATION] == 1
    assert kinds[WritePrimitiveKind.SQLITE_DYNAMIC_SQL] == 1
    assert kinds[WritePrimitiveKind.EXTERNAL_PROCESS] == 1
    assert kinds[WritePrimitiveKind.NETWORK_REQUEST] == 1
    assert kinds[WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY] == 1


def test_dynamic_sql_dataflow_and_bound_execute_fail_closed() -> None:
    entries = scan_python_source(
        '''
def exercise(db, user_sql, flag):
    first = "SELECT 1"
    first = user_sql
    db.execute(first)

    second = "SELECT 1"
    second += "; DELETE FROM q"
    db.execute(second)

    if flag:
        third = "DELETE FROM q"
    else:
        third = "SELECT 1"
    db.execute(third)

    run = db.execute
    run(user_sql)
''',
        file="app/synthetic.py",
    )
    assert Counter(entry.kind for entry in entries)[WritePrimitiveKind.SQLITE_DYNAMIC_SQL] == 4


def test_sql_shadowing_and_alternate_branches_are_fail_closed() -> None:
    entries = scan_python_source(
        '''
q = "SELECT 1"

def parameter_shadow(conn, q):
    conn.execute(q)

def tuple_shadow(conn, user_sql):
    q = "SELECT 1"
    (q, other) = (user_sql, 1)
    conn.execute(q)

def named_expr_shadow(conn, user_sql):
    q = "SELECT 1"
    (q := user_sql)
    conn.execute(q)

def with_shadow(conn, ctx):
    q = "SELECT 1"
    with ctx() as q:
        conn.execute(q)

def alternate_if(conn, user_sql, flag):
    q = user_sql
    if flag:
        q = "SELECT 1"
    else:
        conn.execute(q)

def alternate_try(conn, user_sql):
    q = user_sql
    try:
        q = "SELECT 1"
    except Exception:
        conn.execute(q)
''',
        file="app/synthetic.py",
    )
    assert Counter(entry.kind for entry in entries)[WritePrimitiveKind.SQLITE_DYNAMIC_SQL] == 6


def test_lambda_and_comprehension_targets_shadow_outer_sql_constants() -> None:
    entries = scan_python_source(
        '''
q = "SELECT 1"
lambda_case = lambda q, conn: conn.execute(q)

def comprehensions(conn, values):
    a = [conn.execute(q) for q in values]
    b = {conn.execute(q) for q in values}
    c = {q: conn.execute(q) for q in values}
    d = tuple(conn.execute(q) for q in values)
    return a, b, c, d
''',
        file="app/synthetic.py",
    )
    assert Counter(entry.kind for entry in entries)[WritePrimitiveKind.SQLITE_DYNAMIC_SQL] == 5


def test_async_match_trystar_import_and_global_shadows_fail_closed() -> None:
    entries = scan_python_source(
        '''
q = "SELECT 1"

async def async_with_shadow(conn, ctx):
    async with ctx() as q:
        conn.execute(q)

def match_shadow(conn, value):
    match value:
        case {"sql": q}:
            conn.execute(q)

def trystar_shadow(conn):
    try:
        raise ExceptionGroup("x", [ValueError("x")])
    except* ValueError as q:
        conn.execute(q)

def import_from_shadow(conn):
    from config import dynamic_sql as q
    conn.execute(q)

def import_shadow(conn):
    import config as q
    conn.execute(q)

def global_shadow(conn, user_sql):
    global q
    q = user_sql
    conn.execute(q)
''',
        file="app/synthetic.py",
    )
    assert Counter(entry.kind for entry in entries)[WritePrimitiveKind.SQLITE_DYNAMIC_SQL] == 6


def test_sql_lexer_ignores_case_end_and_words_inside_literals() -> None:
    entries = scan_python_source(
        '''
def read_only(conn):
    conn.execute("SELECT CASE WHEN 1 THEN 1 END")
    conn.execute("SELECT 'DELETE; COMMIT; END'")
''',
        file="app/synthetic.py",
    )
    assert entries == ()


def test_dynamic_registry_call_is_never_silently_dropped() -> None:
    entries = scan_python_source(
        '''
def exercise(registry, name):
    fn = registry[name]
    fn()

def alternate_name(reg, name):
    fn = reg[name]
    fn()
''',
        file="app/synthetic.py",
    )
    assert [entry.kind for entry in entries] == [
        WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
        WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
    ]


def test_indexed_methods_wrappers_and_process_factories_fail_closed() -> None:
    entries = scan_python_source(
        '''
import functools
import multiprocessing
import operator
from concurrent.futures import ProcessPoolExecutor

def exercise(registry, key, conn, user_sql, path):
    registry[key].danger()
    registry[key].get("https://example.invalid")
    functools.partial(conn.execute, user_sql)()
    run = functools.partial(path.unlink)
    run()
    operator.methodcaller("execute", user_sql)(conn)
    operator.attrgetter(key)(registry)
    multiprocessing.Process(target=lambda: None)
    multiprocessing.Pool(1)
    ProcessPoolExecutor(max_workers=1)
''',
        file="app/synthetic.py",
    )
    counts = Counter(entry.kind for entry in entries)
    assert counts[WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY] == 6
    assert counts[WritePrimitiveKind.EXTERNAL_PROCESS] == 3


def test_indexed_callsite_suppressions_must_each_match_exactly_once() -> None:
    exact = Counter(
        {
            callsite: 1
            for callsite in (
                _AUDITED_INDEXED_CALLS
                | _AUDITED_CAPABILITY_STORES
                | _AUDITED_DYNAMIC_CALLS
                | _AUDITED_PARAMETER_CALLS
            )
        }
    )
    _assert_audited_indexed_hits(exact)

    stale = Counter(exact)
    stale[next(iter(_AUDITED_INDEXED_CALLS))] = 0
    with pytest.raises(RuntimeError, match="suppression drifted"):
        _assert_audited_indexed_hits(stale)

    duplicate = Counter(exact)
    duplicate[next(iter(_AUDITED_INDEXED_CALLS))] = 2
    with pytest.raises(RuntimeError, match="suppression drifted"):
        _assert_audited_indexed_hits(duplicate)

    stale_store = Counter(exact)
    stale_store[next(iter(_AUDITED_CAPABILITY_STORES))] = 0
    with pytest.raises(RuntimeError, match="capability-store suppression drifted"):
        _assert_audited_indexed_hits(stale_store)

    stale_dynamic = Counter(exact)
    stale_dynamic[next(iter(_AUDITED_DYNAMIC_CALLS))] = 0
    with pytest.raises(RuntimeError, match="dynamic callsite suppression drifted"):
        _assert_audited_indexed_hits(stale_dynamic)

    stale_parameter = Counter(exact)
    stale_parameter[next(iter(_AUDITED_PARAMETER_CALLS))] = 0
    with pytest.raises(RuntimeError, match="parameter-call suppression drifted"):
        _assert_audited_indexed_hits(stale_parameter)


def test_capability_store_suppression_hash_binds_the_assignment_target() -> None:
    tree = ast.parse(
        "import ctypes\n"
        "class _WindowsJob:\n"
        "    def __init__(self):\n"
        "        self.public_native = ctypes\n"
    )
    assignment = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign))
    fingerprint = hashlib.sha256(
        ast.dump(assignment, include_attributes=False).encode("utf-8")
    ).hexdigest()
    assert (
        "scripts/run_safe_pytest.py",
        "scripts.run_safe_pytest._WindowsJob.__init__",
        fingerprint,
    ) not in _AUDITED_CAPABILITY_STORES


def test_reference_read_capability_stores_are_exact_and_remain_fail_closed() -> None:
    reviewed_stores = {
        callsite
        for callsite in _AUDITED_CAPABILITY_STORES
        if callsite[:2]
        == (
            "app/safety/external_source.py",
            "app.safety.external_source._ReferenceReadApi.__init__",
        )
    }
    assert len(reviewed_stores) == 14

    entries = scan_python_source(
        '''
import ctypes

class _ReferenceReadApi:
    def __init__(self):
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        self.public_create_file = create_file
''',
        file="app/synthetic.py",
    )
    assert sum(
        entry.kind is WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY
        for entry in entries
    ) >= 2


def test_archive_link_low_level_and_negative_canaries() -> None:
    entries = scan_python_source(
        """
import os
import zipfile
from dataclasses import replace

def exercise(path, value):
    os.open(path, os.O_RDONLY)
    os.open(path, os.O_CREAT | os.O_WRONLY)
    os.symlink(path, path)
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('a', 'b')
        archive.open('answer', 'w')
        archive.open('x', 'r')
    replace(value, x=1)
    value.replace('a', 'b')
""",
        file="app/synthetic.py",
    )
    counts = Counter(entry.kind for entry in entries)

    assert counts[WritePrimitiveKind.FILESYSTEM_FILE_WRITE] == 1
    assert counts[WritePrimitiveKind.FILESYSTEM_LINK] == 1
    assert counts[WritePrimitiveKind.ARCHIVE_WRITE] == 3
    assert counts[WritePrimitiveKind.FILESYSTEM_MOVE_OR_REPLACE] == 0


def test_process_network_client_and_listener_canaries_are_detected() -> None:
    entries = scan_python_source(
        '''
import os
import socket
import subprocess
from urllib.request import urlretrieve

def exercise(requests_session, httpx_client, app):
    os.startfile('local.txt')
    subprocess.getoutput('tool')
    requests_session.put('https://example.invalid')
    httpx_client.post('https://example.invalid')
    socket.create_connection(('127.0.0.1', 9))
    urlretrieve('https://example.invalid', 'out')
    app.run(host='127.0.0.1', port=5000)
''',
        file="app/synthetic.py",
    )
    counts = Counter(entry.kind for entry in entries)
    assert counts[WritePrimitiveKind.EXTERNAL_PROCESS] == 2
    assert counts[WritePrimitiveKind.NETWORK_REQUEST] == 5


def test_additional_filesystem_archive_and_network_primitives_are_detected() -> None:
    entries = scan_python_source(
        '''
import os
import shutil
import socket
from urllib.request import Request

def exercise(src, dst, source_handle, target_handle, zf, session, sock):
    src.replace(dst)
    os.removedirs(dst)
    shutil.copyfileobj(source_handle, target_handle)
    print("x", file=target_handle)
    zf.open("member", "w")
    session.request("GET", "https://example.invalid")
    sock.connect(("127.0.0.1", 9))
    socket.socket().listen(1)
    Request("https://example.invalid")
''',
        file="app/synthetic.py",
    )
    counts = Counter(entry.kind for entry in entries)
    assert counts[WritePrimitiveKind.FILESYSTEM_MOVE_OR_REPLACE] == 1
    assert counts[WritePrimitiveKind.FILESYSTEM_DELETE] == 1
    assert counts[WritePrimitiveKind.FILESYSTEM_COPY] == 1
    assert counts[WritePrimitiveKind.FILESYSTEM_FILE_WRITE] == 1
    assert counts[WritePrimitiveKind.ARCHIVE_WRITE] == 1
    assert counts[WritePrimitiveKind.NETWORK_REQUEST] == 3


def test_win32_handle_mutation_primitives_are_never_invisible() -> None:
    entries = scan_python_source(
        '''
def exercise(kernel32, path, handle, info):
    kernel32.CreateFileW(path, 1, 0, None, 1, 0, None)
    kernel32.WriteFile(handle, None, 0, None, None)
    kernel32.FlushFileBuffers(handle)
    kernel32.SetEndOfFile(handle)
    kernel32.CreateDirectoryW(path, None)
    kernel32.SetFileInformationByHandle(handle, 3, info, 1)
''',
        file="app/synthetic.py",
    )
    counts = Counter(entry.kind for entry in entries)
    assert counts[WritePrimitiveKind.FILESYSTEM_FILE_WRITE] == 4
    assert counts[WritePrimitiveKind.FILESYSTEM_DIRECTORY_CREATE] == 1
    assert counts[WritePrimitiveKind.FILESYSTEM_MOVE_OR_REPLACE] == 1
    assert counts[WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY] == 0


def test_named_mutex_primitives_have_a_dedicated_runtime_classification() -> None:
    entries = scan_python_source(
        '''
def synchronize(kernel32, handle, name):
    kernel32.CreateMutexW(None, False, name)
    kernel32.WaitForSingleObject(handle, 0)
    kernel32.ReleaseMutex(handle)
''',
        file="app/synthetic.py",
    )
    counts = Counter(entry.kind for entry in entries)
    assert counts[WritePrimitiveKind.RUNTIME_SYNCHRONIZATION] == 3
    assert counts[WritePrimitiveKind.SYSTEM_STATE] == 0
    assert counts[WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY] == 0


def test_durable_storage_publication_gateway_is_visible() -> None:
    entries = scan_python_source(
        '''
def persist(storage, staging, final, payload, digest):
    return storage.publish_new_file(
        staging,
        final,
        payload,
        expected_sha256=digest,
    )
''',
        file="app/synthetic.py",
    )
    counts = Counter(entry.kind for entry in entries)
    assert counts[WritePrimitiveKind.DURABLE_LEDGER_GATEWAY] == 1
    assert counts[WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY] == 0


def test_native_library_binding_and_unknown_symbols_fail_closed() -> None:
    entries = scan_python_source(
        '''
import ctypes

def exercise(handle):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFileInformationByHandle(handle, None)
    kernel32.MysteryMutation(handle)
''',
        file="app/synthetic.py",
    )
    counts = Counter(entry.kind for entry in entries)
    assert counts[WritePrimitiveKind.NATIVE_API_BINDING] == 1
    assert counts[WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY] == 1


def test_portable_root_volume_queries_are_read_only_native_symbols() -> None:
    entries = scan_python_source(
        '''
import ctypes

def inspect_volume(path, path_buffer, filesystem_buffer):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetVolumePathNameW(path, path_buffer, len(path_buffer))
    kernel32.GetVolumeInformationW(
        path_buffer,
        None,
        0,
        None,
        None,
        None,
        filesystem_buffer,
        len(filesystem_buffer),
    )
''',
        file="app/synthetic.py",
    )
    counts = Counter(entry.kind for entry in entries)
    assert counts[WritePrimitiveKind.NATIVE_API_BINDING] == 1
    assert counts[WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY] == 0


def test_file_mapping_and_native_function_pointer_paths_fail_closed() -> None:
    entries = scan_python_source(
        '''
import ctypes

def exercise(kernel32, handle, address):
    kernel32.CreateFileMappingW(handle, None, 0, 0, 4096, None)
    ctypes.pythonapi.MysteryMutation(handle)
    callback_type = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
    callback = callback_type(address)
    callback(handle)
''',
        file="app/synthetic.py",
    )
    counts = Counter(entry.kind for entry in entries)
    assert counts[WritePrimitiveKind.FILESYSTEM_FILE_WRITE] == 1
    assert counts[WritePrimitiveKind.NATIVE_API_BINDING] >= 1
    assert counts[WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY] >= 2


def test_reflective_pythonapi_lookup_is_fail_closed_even_with_aliases() -> None:
    entries = scan_python_source(
        '''
import ctypes
import inspect
from ctypes import pythonapi as native_python

def exercise(name):
    first = object.__getattribute__(ctypes.pythonapi, "PyRun_SimpleString")
    first(b"never run")
    second = getattr(native_python, name)
    second()
    third = inspect.getattr_static(ctypes.pythonapi, name)
    third()
''',
        file="app/synthetic.py",
    )
    counts = Counter(entry.kind for entry in entries)
    assert counts[WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY] >= 3


def test_private_ctypes_and_callable_capability_laundering_fail_closed() -> None:
    entries = scan_python_source(
        '''
import _ctypes
import os

def invoke(fn):
    fn("never-run")

def identity(value):
    return value

invoke(os.remove)
hidden = identity(os.remove)
hidden("never-run")
''',
        file="app/synthetic.py",
    )
    counts = Counter(entry.kind for entry in entries)
    assert counts[WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY] >= 4


def test_stored_reflected_and_registry_capabilities_cannot_lose_provenance() -> None:
    entries = scan_python_source(
        '''
import ctypes
import os
import sys

class Holder:
    delete = os.remove
    native = ctypes.pythonapi

def dangerous_default(value=os.remove):
    value("never-run")

def dangerous_return():
    return os.remove

ctype_base = ctypes.__dict__["_CFuncPtr"]
loader = ctypes.__getattribute__("windll")
module = sys.modules.get("ctypes")
mapping = vars(sys.modules["ctypes"])
factory_argument = ("GetCurrentProcessId", ctypes.windll.kernel32)

Holder.delete("never-run")
Holder.native.PyRun_SimpleString(b"never run")
dangerous_return()("never-run")
loader.kernel32.GetCurrentProcessId()
module.pythonapi.PyRun_SimpleString(b"never run")
''',
        file="app/synthetic.py",
    )
    counts = Counter(entry.kind for entry in entries)
    assert counts[WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY] >= 10


def test_control_flow_native_escape_and_dynamic_code_paths_fail_closed() -> None:
    entries = scan_python_source(
        '''
import ctypes
import os
import runpy
import types
from importlib.machinery import ExtensionFileLoader

def invoke(action):
    action()

def native_factory():
    return ctypes.WinDLL("kernel32")

module = os if True else None
delete = (os if True else None).remove
api = (ctypes.pythonapi,)[0]
loaders = [ctypes.WinDLL("kernel32")]
callbacks = [ctypes.CFUNCTYPE(None)(1234)]
casts = []
casts.append(ctypes.cast(1234, ctypes.CFUNCTYPE(None)))
dynamic = types.FunctionType(compile("x = 1", "x", "exec"), {})
ExtensionFileLoader("x", "untrusted.pyd").load_module()
runpy.run_path("untrusted.py")
''',
        file="app/synthetic.py",
    )
    counts = Counter(entry.kind for entry in entries)
    assert counts[WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY] >= 12


def test_cffi_mmap_fileio_and_parameter_native_style_calls_are_visible() -> None:
    entries = scan_python_source(
        '''
import io
import mmap
from cffi import FFI

def native_call(api):
    api.MysteryMutation()

ffi = FFI()
library = ffi.dlopen("kernel32")
library.CopyFileW("source", "target", False)
mmap.mmap(1, 1, access=mmap.ACCESS_WRITE)
io.FileIO("target", "w")
''',
        file="app/synthetic.py",
    )
    counts = Counter(entry.kind for entry in entries)
    assert counts[WritePrimitiveKind.NATIVE_API_BINDING] >= 2
    assert counts[WritePrimitiveKind.FILESYSTEM_COPY] >= 1
    assert counts[WritePrimitiveKind.FILESYSTEM_FILE_WRITE] >= 2
    assert counts[WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY] >= 1


def test_guard_bypass_scanner_resolves_aliases_private_factories_and_state_assignment() -> None:
    findings = scan_unauthorized_guard_source(
        """
import app.workspace_guard as wg
import app.safety.production_guard as pg
import functools
from app.safety.production_guard import (
    ProductionWorkspaceBoundary as Boundary,
    _BoundaryCore,
    _create_test_boundary as test_boundary,
)
from app.safety.namespace_policy import NamespacePolicy

guard = wg.WorkspaceGuard('D:/x')
Ctor = wg.WorkspaceGuard
alias_guard = Ctor('D:/x')
partial_guard = functools.partial(wg.WorkspaceGuard, 'D:/x')
registry = {'guard': wg.WorkspaceGuard}
raw = wg.WorkspaceGuard.__new__(wg.WorkspaceGuard)
wg.WorkspaceGuard.__init__(raw, 'D:/x')
class CustomGuard(wg.WorkspaceGuard):
    pass
custom_guard = CustomGuard('D:/x')
boundary = Boundary()
lab = test_boundary('D:/x')
core = _BoundaryCore()
boundary._guard = guard
setattr(boundary, '__core', core)
policy = NamespacePolicy()
policy._NamespacePolicy__authorize(None, None, pair_seal=object())
private_name = '_BoundaryNamespacePolicy'
dynamic_private = getattr(pg, private_name)
dictionary_private = vars(pg)[private_name]
dunder_private = pg.__dict__[private_name]
object_private = object.__getattribute__(pg, private_name)
module_private = pg.__getattribute__(private_name)
type_private = type(pg).__getattribute__(pg, private_name)
"""
    )
    rendered = "\n".join(item[2] for item in findings)

    assert "WorkspaceGuard" in rendered
    assert "ProductionWorkspaceBoundary" in rendered
    assert "_create_test_boundary" in rendered
    assert "_BoundaryCore" in rendered
    assert "NamespacePolicy" in rendered
    assert "_NamespacePolicy__authorize" in rendered
    assert "dynamic safety attribute lookup" in rendered
    assert "dynamic safety module dictionary lookup" in rendered
    assert "safety module __dict__ lookup" in rendered
    assert "reflective safety attribute lookup" in rendered
    assert sum(
        detail == "reflective safety attribute lookup"
        for _file, _line, detail in findings
    ) == 3
    assert "subclass" in rendered
    assert "private state assignment" in rendered


def test_guard_alias_resolution_is_local_to_each_function_scope() -> None:
    findings = scan_unauthorized_guard_source(
        '''
def authority_reader(self):
    revisions = self._key_store._load_all_under_mutex()
    return revisions

def plain_parser(revisions):
    return revisions.get("KEYREV")
''',
        file="app/safety/segment_ledger.py",
    )
    rendered = "\n".join(detail for _file, _line, detail in findings)
    assert len(findings) == 1
    assert "self._key_store" in rendered
    assert "revisions.get" not in rendered

    local_alias_findings = scan_unauthorized_guard_source(
        '''
from app.safety.copy_ledger import DurableCopyLedgers

def bypass():
    constructor = DurableCopyLedgers
    return constructor(object())
'''
    )
    assert any(
        "DurableCopyLedgers" in detail
        for _file, _line, detail in local_alias_findings
    )


def test_pair_policy_base_authorize_is_allowlisted_only_in_claim_verifier() -> None:
    findings = scan_unauthorized_guard_source(
        '''
class _BoundaryNamespacePolicy:
    def _authorize_pair_member(self, ticket, context):
        return self._NamespacePolicy__authorize(ticket, context, pair_seal=self._seal)

    def bypass_claim(self, ticket, context):
        return self._NamespacePolicy__authorize(ticket, context, pair_seal=self._seal)
''',
        file="app/safety/production_guard.py",
    )
    assert len(findings) == 1
    assert findings[0][2] == "private pair policy call _NamespacePolicy__authorize"


def test_durable_ledger_authority_bypasses_are_all_visible() -> None:
    findings = scan_unauthorized_guard_source(
        '''
import functools
import app.safety.production_guard as pg
import app.safety.segment_ledger as sl
from app.safety.segment_ledger import (
    AuditKeyRevisionStore,
    DurableAuditLedger,
    DurableAuditSink,
    _LEDGER_CONSTRUCTOR,
)

store = AuditKeyRevisionStore(object())
ledger_alias = DurableAuditLedger
ledger = ledger_alias(object(), store, epoch_id="E", initial_revision_id="K")
sink = functools.partial(DurableAuditSink, ledger)()
raw = DurableAuditLedger.__new__(DurableAuditLedger)
class CustomLedger(DurableAuditLedger):
    pass
bundle = pg._create_test_durable_boundary(object())
authority = pg._AuditAuthority(object())
token = sl._LEDGER_CONSTRUCTOR
constant_lookup = getattr(sl, "DurableAuditLedger")
dynamic_lookup = getattr(sl, input())
module_vars = vars(sl)
module_dict = sl.__dict__
object_lookup = object.__getattribute__(sl, "DurableAuditLedger")
setattr(raw, "_storage", object())
raw._sealed_code = None
sl._SEGMENT_ROOT = object()
''',
    )
    rendered = "\n".join(detail for _file, _line, detail in findings)
    for symbol in (
        "AuditKeyRevisionStore",
        "DurableAuditLedger",
        "DurableAuditSink",
        "_create_test_durable_boundary",
        "_AuditAuthority",
        "_LEDGER_CONSTRUCTOR",
    ):
        assert symbol in rendered
    assert "subclass" in rendered
    assert "dynamic safety attribute lookup" in rendered
    assert "dynamic safety module dictionary lookup" in rendered
    assert "safety module __dict__ lookup" in rendered
    assert "reflective safety attribute lookup" in rendered
    assert "private state assignment _storage" in rendered
    assert "private state assignment _sealed_code" in rendered
    assert "private state assignment _SEGMENT_ROOT" in rendered


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        (
            "from app.safety.production_guard import "
            "_AUDIT_AUTHORITY_CONSTRUCTOR\n"
            "token = _AUDIT_AUTHORITY_CONSTRUCTOR\n",
            (
                (
                    "app/synthetic.py",
                    1,
                    "private import _AUDIT_AUTHORITY_CONSTRUCTOR",
                ),
                (
                    "app/synthetic.py",
                    2,
                    "forbidden symbol reference "
                    "app.safety.production_guard._AUDIT_AUTHORITY_CONSTRUCTOR",
                ),
            ),
        ),
        (
            "import app.safety.segment_ledger as sl\n"
            "token = sl._LEDGER_CONSTRUCTOR\n",
            (
                (
                    "app/synthetic.py",
                    2,
                    "forbidden symbol reference "
                    "app.safety.segment_ledger._LEDGER_CONSTRUCTOR",
                ),
            ),
        ),
        (
            "class Holder: pass\n"
            "raw = Holder()\n"
            "raw._policy = object()\n",
            (("app/synthetic.py", 3, "private state assignment _policy"),),
        ),
        (
            "class Holder: pass\n"
            "raw = Holder()\n"
            "raw._mutex_name = 'Local\\\\synthetic'\n",
            (("app/synthetic.py", 3, "private state assignment _mutex_name"),),
        ),
        (
            "from app.safety.segment_ledger import AuditKeyRevisionStore\n"
            "store = AuditKeyRevisionStore(object())\n",
            (
                ("app/synthetic.py", 1, "private import AuditKeyRevisionStore"),
                (
                    "app/synthetic.py",
                    2,
                    "constructor app.safety.segment_ledger.AuditKeyRevisionStore",
                ),
                (
                    "app/synthetic.py",
                    2,
                    "forbidden symbol reference "
                    "app.safety.segment_ledger.AuditKeyRevisionStore",
                ),
            ),
        ),
        (
            "from app.safety.segment_ledger import DurableAuditLedger\n"
            "Alias = DurableAuditLedger\n"
            "ledger = Alias(object(), object(), epoch_id='E', "
            "initial_revision_id='K')\n",
            (
                ("app/synthetic.py", 1, "private import DurableAuditLedger"),
                (
                    "app/synthetic.py",
                    2,
                    "forbidden symbol reference "
                    "app.safety.segment_ledger.DurableAuditLedger",
                ),
                (
                    "app/synthetic.py",
                    3,
                    "constructor app.safety.segment_ledger.DurableAuditLedger",
                ),
                (
                    "app/synthetic.py",
                    3,
                    "forbidden symbol reference "
                    "app.safety.segment_ledger.DurableAuditLedger",
                ),
            ),
        ),
        (
            "import functools\n"
            "from app.safety.segment_ledger import DurableAuditSink\n"
            "sink = functools.partial(DurableAuditSink, object())()\n",
            (
                ("app/synthetic.py", 2, "private import DurableAuditSink"),
                (
                    "app/synthetic.py",
                    3,
                    "forbidden symbol reference "
                    "app.safety.segment_ledger.DurableAuditSink",
                ),
            ),
        ),
        (
            "from app.safety.segment_ledger import DurableAuditLedger\n"
            "raw = DurableAuditLedger.__new__(DurableAuditLedger)\n",
            (
                ("app/synthetic.py", 1, "private import DurableAuditLedger"),
                (
                    "app/synthetic.py",
                    2,
                    "forbidden symbol reference "
                    "app.safety.segment_ledger.DurableAuditLedger",
                ),
            ),
        ),
        (
            "from app.safety.segment_ledger import DurableAuditLedger\n"
            "class CustomLedger(DurableAuditLedger):\n"
            "    pass\n",
            (
                ("app/synthetic.py", 1, "private import DurableAuditLedger"),
                (
                    "app/synthetic.py",
                    2,
                    "forbidden symbol reference "
                    "app.safety.segment_ledger.DurableAuditLedger",
                ),
                (
                    "app/synthetic.py",
                    2,
                    "subclass app.safety.segment_ledger.DurableAuditLedger",
                ),
            ),
        ),
        (
            "import app.safety.production_guard as pg\n"
            "bundle = pg._create_test_durable_boundary(object())\n",
            (
                (
                    "app/synthetic.py",
                    2,
                    "constructor "
                    "app.safety.production_guard._create_test_durable_boundary",
                ),
                (
                    "app/synthetic.py",
                    2,
                    "forbidden symbol reference "
                    "app.safety.production_guard._create_test_durable_boundary",
                ),
            ),
        ),
        (
            "import app.safety.production_guard as pg\n"
            "authority = pg._AuditAuthority(object())\n",
            (
                (
                    "app/synthetic.py",
                    2,
                    "constructor app.safety.production_guard._AuditAuthority",
                ),
                (
                    "app/synthetic.py",
                    2,
                    "forbidden symbol reference "
                    "app.safety.production_guard._AuditAuthority",
                ),
            ),
        ),
        (
            "import app.safety.segment_ledger as sl\n"
            "value = getattr(sl, 'DurableAuditLedger')\n",
            (
                ("app/synthetic.py", 2, "dynamic safety attribute lookup"),
                (
                    "app/synthetic.py",
                    2,
                    "forbidden symbol reference "
                    "app.safety.segment_ledger.DurableAuditLedger",
                ),
            ),
        ),
        (
            "import app.safety.segment_ledger as sl\n"
            "value = getattr(sl, input())\n",
            (("app/synthetic.py", 2, "dynamic safety attribute lookup"),),
        ),
        (
            "import app.safety.segment_ledger as sl\n"
            "value = vars(sl)\n",
            (
                (
                    "app/synthetic.py",
                    2,
                    "dynamic safety module dictionary lookup",
                ),
            ),
        ),
        (
            "import app.safety.segment_ledger as sl\n"
            "value = sl.__dict__\n",
            (("app/synthetic.py", 2, "safety module __dict__ lookup"),),
        ),
        (
            "import app.safety.segment_ledger as sl\n"
            "value = object.__getattribute__(sl, 'DurableAuditLedger')\n",
            (("app/synthetic.py", 2, "reflective safety attribute lookup"),),
        ),
        (
            "class Holder: pass\n"
            "raw = Holder()\n"
            "raw._storage = object()\n",
            (("app/synthetic.py", 3, "private state assignment _storage"),),
        ),
        (
            "class Holder: pass\n"
            "raw = Holder()\n"
            "raw._sealed_code = None\n",
            (("app/synthetic.py", 3, "private state assignment _sealed_code"),),
        ),
        (
            "import app.safety.segment_ledger as sl\n"
            "sl._SEGMENT_ROOT = object()\n",
            (("app/synthetic.py", 2, "private state assignment _SEGMENT_ROOT"),),
        ),
    ),
)
def test_each_durable_authority_bypass_route_has_an_exact_canary(
    source: str,
    expected: tuple[tuple[str, int, str], ...],
) -> None:
    assert scan_unauthorized_guard_source(source) == expected


def test_no_current_production_module_bypasses_fixed_boundary() -> None:
    assert scan_unauthorized_guard_construction() == ()


@pytest.mark.parametrize(
    ("module", "symbol"),
    [
        ("app.safety.windows_handle_writer", "_ImmutableFileLease"),
        ("app.safety.production_guard", "_JobContextPin"),
    ],
)
def test_private_job_lease_constructors_have_synthetic_bypass_canaries(
    module: str,
    symbol: str,
) -> None:
    findings = scan_unauthorized_guard_source(
        f"from {module} import {symbol}\nvalue = {symbol}(object())\n"
    )
    rendered = "\n".join(detail for _file, _line, detail in findings)
    assert f"private import {symbol}" in rendered
    assert f"constructor {module}.{symbol}" in rendered
    assert f"forbidden symbol reference {module}.{symbol}" in rendered


def test_operation_ledger_and_publish_kernel_bypasses_are_visible() -> None:
    findings = scan_unauthorized_guard_source(
        '''
from app.safety.operation_ledger import (
    DurableOperationLedger,
    _OPERATION_LEDGER_CONSTRUCTOR,
)

ledger = DurableOperationLedger(object(), object(), epoch_id="E", policy_digest="0" * 64)
token = _OPERATION_LEDGER_CONSTRUCTOR
writer._publish_observed_directory_no_replace(tree, "target", journal)
writer._observe_existing_tree_snapshot("source", budget)
ledger._append_transition_under_existing_mutex(mutex, transition)
boundary._issue_publish_pair_for_job("source", "target")
''',
        file="app/synthetic.py",
    )
    rendered = "\n".join(detail for _file, _line, detail in findings)
    assert "private import DurableOperationLedger" in rendered
    assert "private import _OPERATION_LEDGER_CONSTRUCTOR" in rendered
    assert "constructor app.safety.operation_ledger.DurableOperationLedger" in rendered
    for symbol in (
        "_publish_observed_directory_no_replace",
        "_observe_existing_tree_snapshot",
        "_append_transition_under_existing_mutex",
        "_issue_publish_pair_for_job",
    ):
        assert f"restricted private call {symbol}" in rendered


@pytest.mark.parametrize(
    ("file", "source", "line", "detail"),
    (
        (
            "app/safety/job_operation.py",
            "def unrelated():\n    writer._publish_observed_directory_no_replace(tree, target, journal)\n",
            2,
            "restricted private call _publish_observed_directory_no_replace",
        ),
        (
            "app/safety/job_operation.py",
            "def unrelated():\n    writer._issue_directory_publish_journal_permit(tree)\n",
            2,
            "restricted private call _issue_directory_publish_journal_permit",
        ),
        (
            "app/safety/job_operation.py",
            "def unrelated():\n    boundary._reserve_publish_pair_for_job(token)\n",
            2,
            "restricted private call _reserve_publish_pair_for_job",
        ),
        (
            "app/safety/job_operation.py",
            "def unrelated():\n    boundary._finish_reserved_pair_for_job(lease)\n",
            2,
            "restricted private call _finish_reserved_pair_for_job",
        ),
        (
            "app/safety/job_operation.py",
            "def unrelated():\n    boundary._validate_reserved_pair_for_job(lease)\n",
            2,
            "restricted private call _validate_reserved_pair_for_job",
        ),
        (
            "app/safety/production_guard.py",
            "def unrelated():\n    ledger._seal_recovery_contradiction()\n",
            2,
            "restricted private call _seal_recovery_contradiction",
        ),
        (
            "app/safety/production_guard.py",
            "def unrelated():\n    _ReservedPairLease(object())\n",
            2,
            "restricted private call _ReservedPairLease",
        ),
        (
            "app/safety/production_guard.py",
            "def unrelated():\n    value = _PAIR_RESERVATION_CONSTRUCTOR\n",
            2,
            "restricted private symbol _PAIR_RESERVATION_CONSTRUCTOR outside exact scope unrelated",
        ),
        (
            "app/safety/windows_handle_writer.py",
            "def unrelated():\n    value = _DIRECTORY_PUBLISH_PERMIT_CONSTRUCTOR\n",
            2,
            "restricted private symbol _DIRECTORY_PUBLISH_PERMIT_CONSTRUCTOR outside exact scope unrelated",
        ),
    ),
)
def test_privileged_routes_are_rejected_outside_exact_qualified_scope(
    file: str,
    source: str,
    line: int,
    detail: str,
) -> None:
    assert scan_unauthorized_guard_source(source, file=file) == ((file, line, detail),)


def test_exact_job_publish_scopes_remain_the_only_allowed_synthetic_callers() -> None:
    source = '''
class _OperationLease:
    def authorize_publish(self):
        boundary._issue_publish_pair_for_job(source, target)
        boundary._reserve_publish_pair_for_job(token)
        boundary._finish_reserved_pair_for_job(reservation)

    def execute_publish_pair(self):
        boundary._validate_reserved_pair_for_job(reservation)
        writer._issue_directory_publish_journal_permit(tree)
        writer._publish_observed_directory_no_replace(tree, target, journal)
        boundary._finish_reserved_pair_for_job(reservation)

    def close(self):
        boundary._finish_reserved_pair_for_job(reservation)
'''
    assert (
        scan_unauthorized_guard_source(
            source,
            file="app/safety/job_operation.py",
        )
        == ()
    )


def test_exact_quarantine_and_retained_restore_scopes_remain_clean() -> None:
    job_source = '''
class _TestJobRuntime:
    def replay_committed_quarantine(self):
        ledger._rescan_under_existing_mutex(mutex)
        reference = operation_ledger.operation_reference(operation_id, classification)
        return operation_ledger.operation_result_under_existing_mutex(mutex, reference)

class _OperationLease:
    def observe_quarantine_source(self):
        return ledger._rescan_under_existing_mutex(mutex)

    def prepare_retained_restore(self):
        return ledger._rescan_under_existing_mutex(mutex)

    def authorize_quarantine(self):
        ledger._rescan_under_existing_mutex(mutex)
        boundary._finish_reserved_pair_for_job(reservation)

    def execute_quarantine_pair(self):
        boundary._validate_reserved_pair_for_job(reservation)
        ledger._rescan_under_existing_mutex(mutex)
        writer._issue_directory_publish_journal_permit(tree)
        writer._publish_observed_directory_no_replace(tree, target, journal)
        operation_ledger.transaction_result_under_existing_mutex(mutex, transaction)
        boundary._finish_reserved_pair_for_job(reservation)

class _ObservedQuarantineTreeLease:
    def revalidate(self):
        return self._operation._runtime._ledger._rescan_under_existing_mutex(
            self._operation._mutex
        )

class _RetainedRestoreSourceLease:
    def operation_tree_evidence(self):
        ledger = self._operation._runtime._operation_ledger
        root = self._operation._runtime._writer._observe_identity(handle)
        self._operation._runtime._writer._same_object(observed, root)
        return ledger.durable_tree_evidence_identity_digest(
            root.volume_serial,
            root.file_id,
            self.revalidate().tree_identity_material,
        )
'''
    assert (
        scan_unauthorized_guard_source(
            job_source,
            file="app/safety/job_operation.py",
        )
        == ()
    )

    recovery_source = '''
class _BoundaryCore:
    def consume_restricted_recovery_locator(self, capability, transaction_id):
        record = self.__restricted_recovery_records.get(locator_id)
        quarantine_pair_id = (
            record.target_relative_path.name
            if record.context.purpose is Purpose.QUARANTINE
            else None
        )
        return quarantine_pair_id
'''
    assert (
        scan_unauthorized_guard_source(
            recovery_source,
            file="app/safety/production_guard.py",
        )
        == ()
    )


@pytest.mark.parametrize(
    ("file", "source", "expected"),
    [
        (
            "app/safety/job_operation.py",
            "class _TestJobRuntime:\n"
            "    def replay_committed_quarantine_extra(self):\n"
            "        return ledger.operation_result_under_existing_mutex(mutex, ref)\n",
            "restricted private call operation_result_under_existing_mutex",
        ),
        (
            "app/safety/job_operation.py",
            "class _ObservedQuarantineTreeLease:\n"
            "    def unrelated(self):\n"
            "        return self._operation._runtime._ledger\n",
            "sensitive authority attribute access",
        ),
        (
            "app/safety/job_operation.py",
            "class _RetainedRestoreSourceLease:\n"
            "    def unrelated(self):\n"
            "        return self._operation._runtime._writer\n",
            "sensitive authority attribute access",
        ),
        (
            "app/safety/production_guard.py",
            "class _BoundaryCore:\n"
            "    def consume_restricted_recovery_locator(self, capability, transaction_id):\n"
            "        record = self.__restricted_recovery_records.get(locator_id)\n"
            "        leaked = (\n"
            "            record.target_relative_path.name\n"
            "            if record.context.purpose is Purpose.QUARANTINE\n"
            "            else None\n"
            "        )\n",
            "restricted recovery attribute access",
        ),
        (
            "app/safety/production_guard.py",
            "class _BoundaryCore:\n"
            "    def consume_restricted_recovery_locator(self, capability, transaction_id):\n"
            "        record = self.__restricted_recovery_records.get(locator_id)\n"
            "        return record.target_relative_path.name\n",
            "restricted recovery attribute access",
        ),
    ],
)
def test_quarantine_and_retained_restore_scopes_fail_closed(
    file: str,
    source: str,
    expected: str,
) -> None:
    details = {
        detail
        for _finding_file, _line, detail in scan_unauthorized_guard_source(
            source,
            file=file,
        )
    }
    assert any(expected in detail for detail in details)


def test_s3_f_copy_authority_bypasses_and_plain_attribute_chains_are_visible() -> None:
    findings = scan_unauthorized_guard_source(
        '''
from app.safety.copy_ledger import (
    COPY_PROVENANCE_FILE_NAME,
    CopyProvenanceMaterial,
    DurableCopyLedgers,
    _AuthenticatedCopyAncestors,
    _AUTHENTICATED_COPY_ANCESTORS_CONSTRUCTOR,
    _COPY_LEDGERS_CONSTRUCTOR,
    build_copy_provenance_material,
)
from app.safety.copy_operation import _TestLocalCopyOperation, _COPY_OPERATION_CONSTRUCTOR
from app.safety.external_source import (
    SyntheticReferenceReadPolicy,
    _CopyExecutionPermit,
    _SyntheticReferenceLease,
    _create_synthetic_reference_read_policy,
    _issue_copy_execution_permit,
    _validate_copy_execution_permit,
    _consume_copy_execution_permit,
)
from app.safety.production_guard import (
    _RECOVERY_LOCATOR_CONSTRUCTOR,
    _RestrictedRecoveryLocatorCapability,
    _RestrictedRecoveryLocatorRecord,
    _create_test_copy_ledgers,
    _create_test_copy_operation,
)

copy_ledgers = DurableCopyLedgers(object(), _constructor=_COPY_LEDGERS_CONSTRUCTOR)
provenance = CopyProvenanceMaterial(object())
derived = build_copy_provenance_material(object(), object(), manifest_id="M")
provenance_name = COPY_PROVENANCE_FILE_NAME
publish_binding = copy_ledgers.publish_operation_binding(
    operation_reference="O",
    transaction_binding_sha256="0" * 64,
    copy_binding_sha256="0" * 64,
    target_locator=object(),
    classification=object(),
)
copy_ledgers._authenticated_publish_terminal_bindings_under_existing_mutex(
    object(), object()
)
ancestor_capability = _AuthenticatedCopyAncestors(
    object(), object(), object(), object(), object(), (), (), "0" * 64, "0" * 64,
    _constructor=_AUTHENTICATED_COPY_ANCESTORS_CONSTRUCTOR,
)
copy_operation = _TestLocalCopyOperation(object(), _constructor=_COPY_OPERATION_CONSTRUCTOR)
policy = SyntheticReferenceReadPolicy()
lease = _SyntheticReferenceLease()
permit = _CopyExecutionPermit()
source_policy = _create_synthetic_reference_read_policy(object())
issued = _issue_copy_execution_permit(policy, lease, object())
_validate_copy_execution_permit(permit, policy, lease, object())
_consume_copy_execution_permit(permit, policy, lease, object())
_create_test_copy_ledgers(object(), object())
_create_test_copy_operation(object(), object(), copy_ledgers, object(), object(), object())
recovery = _RestrictedRecoveryLocatorCapability(
    "0" * 64, b"x" * 32,
    _constructor=_RECOVERY_LOCATOR_CONSTRUCTOR,
)
recovery_record = _RestrictedRecoveryLocatorRecord()
boundary._issue_restricted_recovery_locator(object(), "T")
boundary._consume_restricted_recovery_locator(recovery, "T")
boundary._issue_restricted_copy_recovery_locator(object())
boundary._consume_restricted_copy_recovery_locator(recovery, object())
runtime_writer = copy_operation._runtime._writer
storage = copy_ledgers._storage
native_api = policy._api
copy_key = copy_ledgers._copy_chain.auth_key
ancestor_audit = ancestor_capability._audit_ledger._storage
ancestor_audit_segments = ancestor_capability._audit_segment_sha256s
ancestor_publish_segments = ancestor_capability._publish_segment_sha256s
ancestor_publish_terminals = ancestor_capability._publish_terminal_binding_sha256s
ancestor_cross_reference = ancestor_capability._copy_cross_reference_sha256
copy_ledgers._seal(object())
copy_ledgers._issue_authenticated_ancestors_under_existing_mutex(
    object(), object(), object()
)
copy_ledgers._verify_external_ancestors_under_existing_mutex(
    object(), ancestor_capability
)
'''
    )
    rendered = "\n".join(detail for _file, _line, detail in findings)
    for symbol in (
        "DurableCopyLedgers",
        "_COPY_LEDGERS_CONSTRUCTOR",
        "_AuthenticatedCopyAncestors",
        "_AUTHENTICATED_COPY_ANCESTORS_CONSTRUCTOR",
        "_TestLocalCopyOperation",
        "_COPY_OPERATION_CONSTRUCTOR",
        "SyntheticReferenceReadPolicy",
        "_SyntheticReferenceLease",
        "_CopyExecutionPermit",
        "_create_synthetic_reference_read_policy",
        "_create_test_copy_ledgers",
        "_create_test_copy_operation",
        "_RestrictedRecoveryLocatorRecord",
        "_RestrictedRecoveryLocatorCapability",
        "_RECOVERY_LOCATOR_CONSTRUCTOR",
        "CopyProvenanceMaterial",
        "build_copy_provenance_material",
        "COPY_PROVENANCE_FILE_NAME",
    ):
        assert symbol in rendered
    for helper in (
        "_issue_copy_execution_permit",
        "_validate_copy_execution_permit",
        "_consume_copy_execution_permit",
        "_issue_restricted_recovery_locator",
        "_consume_restricted_recovery_locator",
        "_issue_restricted_copy_recovery_locator",
        "_consume_restricted_copy_recovery_locator",
        "_seal",
        "_issue_authenticated_ancestors_under_existing_mutex",
        "_verify_external_ancestors_under_existing_mutex",
        "publish_operation_binding",
        "_authenticated_publish_terminal_bindings_under_existing_mutex",
    ):
        assert f"restricted private call {helper}" in rendered
    for chain in (
        "_runtime._writer",
        "_storage",
        "_api",
        "_copy_chain.auth_key",
        "_audit_ledger._storage",
        "_audit_segment_sha256s",
        "_publish_segment_sha256s",
        "_publish_terminal_binding_sha256s",
        "_copy_cross_reference_sha256",
    ):
        assert chain in rendered
    assert "sensitive authority attribute access" in rendered


def test_exact_s3_f_production_factories_and_recovery_scopes_remain_clean() -> None:
    source = '''
def _create_test_copy_ledgers():
    ledgers = DurableCopyLedgers(_constructor=_COPY_LEDGERS_CONSTRUCTOR)
    if mismatch:
        ledgers._seal(code)
    capability = ledgers._issue_authenticated_ancestors_under_existing_mutex(
        mutex, bundle.ledger, operation_ledger
    )
    ledgers._verify_external_ancestors_under_existing_mutex(mutex, capability)
    return ledgers

def _create_test_copy_operation():
    if copy_ledgers._storage is not bundle.writer:
        raise TypeError
    if copy_epoch != copy_ledgers.storage_epoch_id:
        raise TypeError
    if not copy_ledgers.matches_run_scope(context.run_id):
        raise TypeError
    policy = _create_synthetic_reference_read_policy(bundle.writer._workspace_root)
    return _TestLocalCopyOperation(
        runtime, copy_ledgers, policy, _constructor=_COPY_OPERATION_CONSTRUCTOR
    )

class _RestrictedRecoveryLocatorRecord:
    def __repr__(self):
        return self.lifecycle

class _RestrictedRecoveryLocatorCapability:
    def __init__(self, locator_id, authenticator, *, _constructor):
        if _constructor is not _RECOVERY_LOCATOR_CONSTRUCTOR:
            raise TypeError
        self.__locator_id = locator_id
        self.__authenticator = authenticator

    def _read(self, constructor):
        if constructor is not _RECOVERY_LOCATOR_CONSTRUCTOR:
            raise TypeError
        return self.__locator_id, self.__authenticator

class _BoundaryCore:
    def __init__(self):
        self.__restricted_recovery_records = {}

    @property
    def diagnostic_registry_counts(self):
        return len(self.__restricted_recovery_records)

    def issue_restricted_recovery_locator(self, context, transaction_id):
        source, target = self._derive_restricted_recovery_paths(context, purpose)
        owner_thread_object_binding = (
            self._restricted_recovery_owner_thread_object_binding(owner_thread_object)
        )
        binding = self._restricted_recovery_locator_binding(
            locator_id,
            context,
            transaction_id,
            source,
            target,
            purpose,
            owner_thread,
            owner_thread_object_binding,
        )
        authenticator = self._restricted_recovery_capability_authenticator(
            locator_id, binding
        )
        capability = _RestrictedRecoveryLocatorCapability(
            locator_id,
            authenticator,
            _constructor=_RECOVERY_LOCATOR_CONSTRUCTOR,
        )
        self.__restricted_recovery_records[locator_id] = (
            _RestrictedRecoveryLocatorRecord()
        )
        return capability

    def consume_restricted_recovery_locator(self, capability, transaction_id):
        locator_id, supplied_authenticator = capability._read(
            _RECOVERY_LOCATOR_CONSTRUCTOR
        )
        record = self.__restricted_recovery_records.get(locator_id)
        expected_source, expected_target = self._derive_restricted_recovery_paths(
            record.context, record.purpose
        )
        owner_thread_object_binding = (
            self._restricted_recovery_owner_thread_object_binding(owner_thread_object)
        )
        binding = self._restricted_recovery_locator_binding(
            record.locator_id,
            record.context,
            record.transaction_id,
            expected_source,
            expected_target,
            record.purpose,
            owner_thread,
            owner_thread_object_binding,
        )
        authenticator = self._restricted_recovery_capability_authenticator(
            record.locator_id, binding
        )
        valid = (
            record.core_instance_id == core_id
            and record.context_digest == record.context.digest
            and record.context_ticket_id == record.context.authority_ticket_id
            and record.owner_thread_object.ident == record.owner_thread
            and record.owner_thread_object_binding_sha256
            == owner_thread_object_binding
            and type(record.source_relative_path) is type(expected_source)
            and type(record.target_relative_path) is type(expected_target)
            and record.source_relative_path.as_posix()
            == expected_source.as_posix()
            and record.target_relative_path.as_posix()
            == expected_target.as_posix()
            and record.policy_version == policy_version
            and record.policy_digest == policy_digest
            and record.binding_sha256 == binding
            and record.capability_authenticator == authenticator
            and record.lifecycle is issued
            and supplied_authenticator == authenticator
        )
        if valid and record.purpose == copy_purpose:
            valid = record.transaction_id == self._restricted_copy_recovery_binding_id(
                record.context
            )
        removed = self.__restricted_recovery_records.pop(locator_id, None)
        if removed is not record:
            self.__restricted_recovery_records[locator_id] = removed
        return expected_source, expected_target

    def issue_restricted_copy_recovery_locator(self, context):
        binding = self._restricted_copy_recovery_binding_id(context)
        return self.issue_restricted_recovery_locator(context, binding)

    def consume_restricted_copy_recovery_locator(self, capability, context):
        binding = self._restricted_copy_recovery_binding_id(context)
        return self.consume_restricted_recovery_locator(capability, binding)

    def _revoke_restricted_recovery_records(self, ticket_id):
        locator_ids = tuple(
            locator_id
            for locator_id, record in self.__restricted_recovery_records.items()
            if record.context_ticket_id == ticket_id
        )
        for locator_id in locator_ids:
            self.__restricted_recovery_records.pop(locator_id, None)

    def release_test_context(self, context):
        self._revoke_restricted_recovery_records(context.authority_ticket_id)

    def finish_test_job_context(self, context):
        self._revoke_restricted_recovery_records(context.authority_ticket_id)

    def _assert_invariants(self):
        return all(
            record.locator_id == locator_id
            and record.lifecycle is issued
            and record.context_ticket_id == record.context.authority_ticket_id
            and record.owner_thread_object.ident == record.owner_thread
            and record.owner_thread_object_binding_sha256
            == self._restricted_recovery_owner_thread_object_binding(
                record.owner_thread_object
            )
            and type(record.source_relative_path) is Path
            and type(record.target_relative_path) is Path
            for locator_id, record in self.__restricted_recovery_records.items()
        )

class _TestWorkspaceBoundary:
    def _issue_restricted_recovery_locator(self):
        return self.__core.issue_restricted_recovery_locator()

    def _consume_restricted_recovery_locator(self, capability):
        return self.__core.consume_restricted_recovery_locator(capability)

    def _issue_restricted_copy_recovery_locator(self, context):
        return self.__core.issue_restricted_copy_recovery_locator(context)

    def _consume_restricted_copy_recovery_locator(self, capability, context):
        return self.__core.consume_restricted_copy_recovery_locator(capability, context)

def _reconcile_test_publish_operation():
    return boundary._consume_restricted_recovery_locator(capability)
'''
    assert (
        scan_unauthorized_guard_source(
            source,
            file="app/safety/production_guard.py",
        )
        == ()
    )


def test_restricted_recovery_capability_is_opaque_and_absent_from_production_surface() -> None:
    tree = ast.parse(
        (PROJECT_ROOT / "app" / "safety" / "production_guard.py").read_text(
            encoding="utf-8"
        )
    )
    classes = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    capability = classes["_RestrictedRecoveryLocatorCapability"]
    slots_assignment = next(
        node
        for node in capability.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__slots__"
            for target in node.targets
        )
    )
    assert ast.literal_eval(slots_assignment.value) == (
        "__locator_id",
        "__authenticator",
    )

    production_methods = {
        node.name
        for node in classes["ProductionWorkspaceBoundary"].body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert not any("restricted_recovery" in name for name in production_methods)

    test_facade_methods = {
        node.name
        for node in classes["_TestWorkspaceBoundary"].body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert {
        "_issue_restricted_recovery_locator",
        "_consume_restricted_recovery_locator",
        "_issue_restricted_copy_recovery_locator",
        "_consume_restricted_copy_recovery_locator",
    } <= test_facade_methods


def test_exact_s3_f_directory_absence_observation_scopes_remain_clean() -> None:
    writer_source = '''
class _WindowsHandleWriter:
    def _require_directory_target_absent_under_existing_mutex(self, mutex, target):
        self._after_directory_target_absence_first_observation(target)
'''
    assert (
        scan_unauthorized_guard_source(
            writer_source,
            file="app/safety/windows_handle_writer.py",
        )
        == ()
    )

    copy_source = '''
class _TestLocalCopyOperation:
    def _require_target_absent_twice(self, mutex, target):
        self._runtime._writer._require_directory_target_absent_under_existing_mutex(
            mutex,
            target,
        )
'''
    assert (
        scan_unauthorized_guard_source(
            copy_source,
            file="app/safety/copy_operation.py",
        )
        == ()
    )


def test_exact_s3_f_copy_runtime_internal_scopes_remain_clean() -> None:
    source = '''
class _TestLocalCopyOperation:
    def __init__(self, runtime, ledgers, source_policy, _constructor):
        if _constructor is not _COPY_OPERATION_CONSTRUCTOR:
            raise TypeError
        if ledgers._storage is not runtime._writer:
            raise TypeError
        if copy_epoch != ledgers.storage_epoch_id:
            raise TypeError
        if not ledgers.matches_run_scope(context.run_id):
            raise TypeError
        self._runtime = runtime
        self._ledgers = ledgers
        self._source_policy = source_policy

    def _execute_new(self):
        self._ledgers._append_source_under_existing_mutex(mutex, source)
        self._ledgers._append_transition_under_existing_mutex(mutex, transition)

    def _try_replay(self):
        self._ledgers._rescan_under_existing_mutex(mutex)
        self._ledgers.transaction_result_under_existing_mutex(mutex, transaction)
        self._ledgers.source_result_under_existing_mutex(mutex, source)

    def _validate_ledgers_for_new_operation(self):
        self._ledgers._rescan_under_existing_mutex(mutex)

    def _verify_all_ancestors(self):
        capability = self._ledgers._issue_authenticated_ancestors_under_existing_mutex(
            mutex, self._runtime._ledger, operation_ledger
        )
        self._ledgers._verify_external_ancestors_under_existing_mutex(
            mutex, capability
        )

    def _append_failure_fact(self):
        operation_ledger.operation_result_under_existing_mutex(mutex, operation)
        self._ledgers._append_transition_under_existing_mutex(mutex, transition)

    def _issue_execution_permit(self):
        return _issue_copy_execution_permit(self._source_policy, lease, evidence)

    def _validate_execution_permit(self):
        _validate_copy_execution_permit(permit, self._source_policy, lease, evidence)

    def _consume_execution_permit(self):
        _consume_copy_execution_permit(permit, self._source_policy, lease, evidence)

    def reconcile(self, capability):
        return self._boundary._consume_restricted_copy_recovery_locator(
            capability, self._context
        )

    def _seal_cross_reference_failure(self):
        self._ledgers._seal(code)

    def _copy_provenance_material(self):
        return build_copy_provenance_material(
            source, receipt, manifest_id=self._manifest.manifest_id
        )

    def _publish_operation_binding(self):
        return self._ledgers.publish_operation_binding(
            operation_reference=reference,
            transaction_binding_sha256=transaction,
            copy_binding_sha256=copy,
            target_locator=target,
            classification=classification,
        )
'''
    assert (
        scan_unauthorized_guard_source(
            source,
            file="app/safety/copy_operation.py",
        )
        == ()
    )


def test_exact_s3_f_copy_ancestor_capability_scope_remains_clean() -> None:
    source = '''
from app.safety.operation_ledger import DurableOperationLedger
from app.safety.segment_ledger import DurableAuditLedger

class _AuthenticatedCopyAncestors:
    def __init__(self, storage, audit_ledger, operation_ledger, _constructor):
        if _constructor is not _AUTHENTICATED_COPY_ANCESTORS_CONSTRUCTOR:
            raise TypeError
        self._storage = storage
        self._audit_ledger = audit_ledger
        self._operation_ledger = operation_ledger
        self._publish_terminal_binding_sha256s = ()
        self._copy_cross_reference_sha256 = "0" * 64

def build_copy_provenance_material(source, receipt, manifest_id):
    return CopyProvenanceMaterial(source, receipt, manifest_id)

class DurableCopyLedgers:
    def _authenticated_publish_terminal_bindings_under_existing_mutex(
        self, mutex, operation_ledger, audit_inventory
    ):
        return self._authenticated_publish_terminal_bindings_for_epochs_under_existing_mutex(
            mutex, (operation_ledger,), audit_inventory
        )

    def _authenticated_publish_terminal_bindings_for_epochs_under_existing_mutex(
        self, mutex, operation_ledgers, audit_inventory
    ):
        for operation_ledger in operation_ledgers:
            operation_ledger.transaction_result_under_existing_mutex(
                mutex, transaction_id
            )
        return ()

    def _issue_authenticated_ancestors_under_existing_mutex(
        self, mutex, audit_ledger, operation_ledger
    ):
        if audit_ledger._storage is not self._storage:
            raise TypeError
        audit = audit_ledger.authenticated_segment_sha256s_under_existing_mutex(mutex)
        publish = operation_ledger.authenticated_segment_sha256s_under_existing_mutex(mutex)
        terminals = self._authenticated_publish_terminal_bindings_under_existing_mutex(
            mutex, operation_ledger, audit
        )
        return _AuthenticatedCopyAncestors(
            self._storage,
            audit_ledger,
            operation_ledger,
            _constructor=_AUTHENTICATED_COPY_ANCESTORS_CONSTRUCTOR,
        )

    def _verify_external_ancestors_under_existing_mutex(self, mutex, capability):
        audit = capability._audit_ledger.authenticated_segment_sha256s_under_existing_mutex(mutex)
        capability._operation_ledger.authenticated_segment_sha256s_under_existing_mutex(mutex)
        self._authenticated_publish_terminal_bindings_under_existing_mutex(
            mutex, capability._operation_ledger, audit
        )
        tuple(capability._publish_terminal_binding_sha256s)
        str(capability._copy_cross_reference_sha256)
        self.bound_audit_ancestors_under_existing_mutex(mutex)
        self.bound_publish_terminals_under_existing_mutex(mutex)
'''
    assert (
        scan_unauthorized_guard_source(
            source,
            file="app/safety/copy_ledger.py",
        )
        == ()
    )


def test_exact_s3_f_source_factory_and_permit_scopes_remain_clean() -> None:
    source = '''
class _ReferenceReadApi:
    def __init__(self, _constructor):
        if _constructor is not _READ_API_CONSTRUCTOR:
            raise TypeError

class SyntheticReferenceReadPolicy:
    def __init__(self, api, _constructor):
        if _constructor is not _POLICY_CONSTRUCTOR:
            raise TypeError
        self._api = api

    def open_reference(self):
        return _SyntheticReferenceLease(
            api=self._api, _constructor=_LEASE_CONSTRUCTOR
        )

class _SyntheticReferenceLease:
    def __init__(self, api, digest_key, _constructor):
        if _constructor is not _LEASE_CONSTRUCTOR:
            raise TypeError
        self._api = api
        self._digest_key = digest_key

class _CopyExecutionPermit:
    def __init__(self, policy, _constructor):
        if _constructor is not _COPY_EXECUTION_PERMIT_CONSTRUCTOR:
            raise TypeError
        self._policy = policy

def _copy_execution_scope_sha256(lease):
    return lease._digest_key

def _copy_execution_binding_sha256(lease):
    return lease._digest_key

def _require_copy_execution_authorities(lease):
    return _copy_execution_scope_sha256(lease)

def _issue_copy_execution_permit(policy, lease):
    _require_copy_execution_authorities(lease)
    _copy_execution_binding_sha256(lease)
    return _CopyExecutionPermit(
        policy=policy, _constructor=_COPY_EXECUTION_PERMIT_CONSTRUCTOR
    )

def _check_copy_execution_permit(permit, lease):
    _require_copy_execution_authorities(lease)
    _copy_execution_binding_sha256(lease)
    return permit._policy

def _validate_copy_execution_permit(permit, lease):
    return _check_copy_execution_permit(permit, lease)

def _consume_copy_execution_permit(permit, lease):
    return _check_copy_execution_permit(permit, lease)

def _create_synthetic_reference_read_policy():
    api = _ReferenceReadApi(_constructor=_READ_API_CONSTRUCTOR)
    return SyntheticReferenceReadPolicy(api=api, _constructor=_POLICY_CONSTRUCTOR)
'''
    assert (
        scan_unauthorized_guard_source(
            source,
            file="app/safety/external_source.py",
        )
        == ()
    )


def test_exact_s3_f_copy_reconcile_scopes_remain_clean() -> None:
    source = '''
class _TestLocalCopyOperation:
    def execute(self):
        with self._source_policy.open_reference(source_name) as source_lease:
            material = source_lease.read_once()
            return self._issue_execution_permit(source_lease, evidence, target)

    def reconcile(self):
        with self._source_policy.open_reference(source_name) as source_lease:
            material = source_lease.read_once()
            permit = self._issue_execution_permit(source_lease, evidence, target)
            self._consume_execution_permit(
                permit, source_lease, material, transaction, copy, target
            )
            try:
                return self._reconcile_consumed_source(
                    material, source_lease, transaction, copy, target
                )
            except Exception:
                self._raise_recovery_contradiction()

    def _reconcile_consumed_source(self):
        self._runtime._ledger._rescan_under_existing_mutex(mutex)
        self._ledgers._rescan_under_existing_mutex(mutex)
        current = self._copy_recovery_result(target_locator)
        source_by_transaction = (
            self._ledgers.transaction_source_result_under_existing_mutex(
                mutex, transaction
            )
        )
        source = self._ledgers.source_result_under_existing_mutex(mutex, source_id)
        operation = operation_ledger.operation_result_under_existing_mutex(
            mutex, operation_ledger.operation_reference(operation_id, classification)
        )
        self._validate_recovery_binding(source, current)
        self._validate_source_only_recovery_binding(source_by_transaction, current)
        self._validate_recovery_publish_binding(operation, binding, target)
        self._reconcile_source_only_abort(material, source_lease, current, target)
        self._reconcile_committed_publish(material, source_lease, current, target)
        self._reconcile_absent_publish(material, source_lease, current, target)
        self._verify_all_ancestors(mutex)
        self._raise_recovery_contradiction()

    def _copy_recovery_result(self):
        self._raise_recovery_contradiction()

    def _reconcile_source_only_abort(self):
        self._require_target_absent_twice(target)
        source_lease.verify_unchanged(evidence)
        recovered = self._source_only_recovered_abort_transition(source)
        receipt = self._ledgers._append_transition_under_existing_mutex(mutex, recovered)
        self._ledgers.transaction_result_under_existing_mutex(mutex, transaction)
        self._raise_recovery_contradiction()

    def _reconcile_committed_publish(self):
        target_evidence = self._target_evidence(target, material)
        source_lease.verify_unchanged(evidence)
        recovered = self._recovered_transition(previous, state)
        receipt = self._ledgers._append_transition_under_existing_mutex(mutex, recovered)
        self._ledgers.transaction_result_under_existing_mutex(mutex, transaction)
        self._verify_all_ancestors(mutex)
        self._raise_recovery_contradiction()

    def _reconcile_absent_publish(self):
        self._require_target_absent_twice(target)
        source_lease.verify_unchanged(evidence)
        recovered = self._recovered_transition(previous, state)
        receipt = self._ledgers._append_transition_under_existing_mutex(mutex, recovered)
        self._ledgers.transaction_result_under_existing_mutex(mutex, transaction)
        self._verify_all_ancestors(mutex)
        self._raise_recovery_contradiction()

    def _validate_recovery_binding(self):
        self._raise_recovery_contradiction()

    def _validate_recovery_publish_binding(self):
        operation_ledger.operation_reference(operation_id, classification)
        self._raise_recovery_contradiction()

    def _validate_source_only_recovery_binding(self):
        self._raise_recovery_contradiction()

    def _recovered_transition(self):
        self._raise_recovery_contradiction()

    def _source_only_recovered_abort_transition(self):
        return None

    def _require_target_absent_twice(self):
        self._raise_recovery_contradiction()

    def _execute_new(self):
        self._consume_execution_permit(permit, lease, material, transaction, copy, target)
        self._ledgers._append_source_under_existing_mutex(mutex, source)
        self._ledgers._append_transition_under_existing_mutex(mutex, transition)
        self._target_evidence(target, material)
        source_lease.verify_unchanged(evidence)

    def _try_replay(self):
        self._validate_execution_permit(permit, lease, material, transaction, copy, target)
        self._consume_execution_permit(permit, lease, material, transaction, copy, target)
        self._ledgers._rescan_under_existing_mutex(mutex)
        self._ledgers.transaction_result_under_existing_mutex(mutex, transaction)
        self._ledgers.source_result_under_existing_mutex(mutex, source)
        self._target_evidence(target, material)
        source_lease.verify_unchanged(evidence)

    def _append_failure_fact(self):
        operation_ledger.operation_result_under_existing_mutex(
            mutex, operation_ledger.operation_reference(operation_id, classification)
        )
        self._ledgers._append_transition_under_existing_mutex(mutex, transition)

    def _verify_all_ancestors(self):
        capability = self._ledgers._issue_authenticated_ancestors_under_existing_mutex(
            mutex, self._runtime._ledger, operation_ledger
        )
        self._ledgers._verify_external_ancestors_under_existing_mutex(
            mutex, capability
        )

    def _raise_recovery_contradiction(self):
        self._ledgers._seal(code)
        self._runtime._writer.seal_after_indeterminate_mutation()

    def _target_evidence(self):
        return None

    def _stable_bindings(self):
        transaction = self._ledgers.transaction_binding(context, evidence)
        copy = self._ledgers.copy_object_binding(context, evidence)
        return transaction, copy

    def _copy_target_locator(self):
        return self._ledgers.target_locator(target, classification)
'''
    assert (
        scan_unauthorized_guard_source(
            source,
            file="app/safety/copy_operation.py",
        )
        == ()
    )


def test_exact_s3_f_opaque_epoch_and_revision_gate_scopes_remain_clean() -> None:
    source = '''
def _derive_copy_ledger_epoch_id(revision, run_scope_id):
    return revision.segment_hmac_key

class DurableCopyLedgers:
    def __init__(self, revision, run_scope_id):
        self._run_scope_id = run_scope_id
        self._run_scope_hmac_sha256 = self._derive_run_scope_hmac(revision)
        self._known_revisions = {revision.revision_id: revision}
        self._requested_revision_id = revision.revision_id
        self._append_enabled = True
        self._epoch_id = _derive_copy_ledger_epoch_id(revision, run_scope_id)

    @property
    def storage_epoch_id(self):
        return self._epoch_id

    def matches_run_scope(self, run_scope_id):
        return self._epoch_id == _derive_copy_ledger_epoch_id(
            self._revision, run_scope_id
        )

    def _derive_run_scope_hmac(self, revision):
        return revision.segment_hmac_key

    def _select_persisted_revision_under_mutex(self):
        self._run_scope_hmac_sha256 = self._derive_run_scope_hmac(self._revision)

    def _append_source_under_existing_mutex(self):
        self._require_append_revision_current()

    def _append_transition_under_existing_mutex(self):
        self._require_transition_append_allowed(transition)
'''
    assert (
        scan_unauthorized_guard_source(
            source,
            file="app/safety/copy_ledger.py",
        )
        == ()
    )


def test_exact_s3_g_rotation_and_attestation_scopes_remain_clean() -> None:
    copy_ledger_source = '''
def _copy_epoch_pair_presence(storage):
    def present(relative):
        return storage._workspace_root / relative
    return present

class DurableCopyLedgers:
    @staticmethod
    def _preflight_new_epoch_under_existing_mutex(storage, revision, scope):
        current = _derive_copy_ledger_epoch_id(revision, scope)
        historical = _derive_copy_ledger_epoch_id(revision, scope)
        candidate = _derive_copy_ledger_epoch_id(revision, scope)
        return DurableCopyLedgers(storage, current, historical, candidate)

    def _append_revision_is_current_under_existing_mutex(self, lease):
        self._audit_ledger._rescan_under_existing_mutex(lease)
        return self._audit_ledger._activated_revision_ids_under_existing_mutex(lease)
'''
    assert (
        scan_unauthorized_guard_source(
            copy_ledger_source,
            file="app/safety/copy_ledger.py",
        )
        == ()
    )

    production_guard_source = '''
class _AuditAuthority:
    def __post_init__(self):
        return (
            self.sink._ledger,
            self.ledger._key_store,
            self.ledger._storage,
            self.key_store._storage,
        )

class _BoundaryCore:
    def _attest_copy_ledger_read(self, lease, revision, scope):
        self.audit.ledger._rescan_under_existing_mutex(lease)
        self.audit.ledger._activated_revision_ids_under_existing_mutex(lease)
        return _derive_copy_ledger_epoch_id(revision, scope)
'''
    assert (
        scan_unauthorized_guard_source(
            production_guard_source,
            file="app/safety/production_guard.py",
        )
        == ()
    )


@pytest.mark.parametrize(
    ("file", "source", "expected"),
    [
        (
            "app/safety/copy_ledger.py",
            "def unrelated(storage):\n    return storage._workspace_root\n",
            "sensitive authority attribute access storage._workspace_root",
        ),
        (
            "app/safety/copy_ledger.py",
            "def unrelated(revision, scope):\n"
            "    return _derive_copy_ledger_epoch_id(revision, scope)\n",
            "restricted private call _derive_copy_ledger_epoch_id",
        ),
        (
            "app/safety/copy_ledger.py",
            "def unrelated(storage):\n    return DurableCopyLedgers(storage)\n",
            "restricted private call DurableCopyLedgers",
        ),
        (
            "app/safety/copy_ledger.py",
            "def unrelated(audit, lease):\n"
            "    audit._rescan_under_existing_mutex(lease)\n"
            "    return audit._activated_revision_ids_under_existing_mutex(lease)\n",
            "restricted private call _rescan_under_existing_mutex",
        ),
        (
            "app/safety/production_guard.py",
            "def unrelated(authority):\n    return authority.sink._ledger\n",
            "sensitive authority attribute access authority.sink._ledger",
        ),
        (
            "app/safety/production_guard.py",
            "def unrelated(audit, lease):\n"
            "    audit._rescan_under_existing_mutex(lease)\n"
            "    return audit._activated_revision_ids_under_existing_mutex(lease)\n",
            "restricted private call _rescan_under_existing_mutex",
        ),
    ],
)
def test_s3_g_rotation_and_attestation_routes_fail_closed_outside_exact_scope(
    file: str,
    source: str,
    expected: str,
) -> None:
    details = {
        detail
        for _finding_file, _line, detail in scan_unauthorized_guard_source(
            source,
            file=file,
        )
    }
    assert expected in details


def test_exact_s3_f_identity_material_scopes_remain_clean() -> None:
    writer_source = '''
_IDENTITY_MATERIAL_CONSTRUCTOR = object()

class HandleObjectIdentityMaterial:
    def __init__(self, *, _constructor):
        if _constructor is not _IDENTITY_MATERIAL_CONSTRUCTOR:
            raise TypeError
        self.__frame = b"frame"

class HandleTreeIdentityMaterial:
    def __init__(self, *, _constructor):
        if _constructor is not _IDENTITY_MATERIAL_CONSTRUCTOR:
            raise TypeError
        self.__rows = ()

class _WindowsHandleWriter:
    def _read_flat_directory_impl(self):
        return HandleTreeIdentityMaterial(
            _constructor=_IDENTITY_MATERIAL_CONSTRUCTOR
        )

    def _build_tree_snapshot(self):
        return HandleTreeIdentityMaterial(
            _constructor=_IDENTITY_MATERIAL_CONSTRUCTOR
        )

    def _identity_material(self):
        return HandleObjectIdentityMaterial(
            _constructor=_IDENTITY_MATERIAL_CONSTRUCTOR
        )
'''
    assert (
        scan_unauthorized_guard_source(
            writer_source,
            file="app/safety/windows_handle_writer.py",
        )
        == ()
    )

    ledger_source = '''
class DurableOperationLedger:
    def durable_object_identity_digest(self, material):
        return material._operation_hmac_sha256(key)

    def durable_tree_identity_digest(self, material):
        return material._operation_hmac_sha256(key)

    def durable_tree_evidence_identity_digest(self, material):
        return material._operation_hmac_sha256(key)
'''
    assert (
        scan_unauthorized_guard_source(
            ledger_source,
            file="app/safety/operation_ledger.py",
        )
        == ()
    )


@pytest.mark.parametrize(
    ("file", "source", "expected"),
    [
        (
            "app/synthetic.py",
            "ledger.source_result_under_existing_mutex(mutex, source_id)\n",
            "restricted private call source_result_under_existing_mutex",
        ),
        (
            "app/synthetic.py",
            "source_policy.open_reference(source_name)\n",
            "restricted private call open_reference",
        ),
        (
            "app/synthetic.py",
            "source_lease.read_once()\n",
            "restricted private call read_once",
        ),
        (
            "app/synthetic.py",
            "operation_ledger.operation_result_under_existing_mutex(mutex, operation)\n",
            "restricted private call operation_result_under_existing_mutex",
        ),
        (
            "app/synthetic.py",
            "copy_ledgers.transaction_result_under_existing_mutex(mutex, transaction)\n",
            "restricted private call transaction_result_under_existing_mutex",
        ),
        (
            "app/synthetic.py",
            "copy_ledgers.transaction_source_result_under_existing_mutex(mutex, transaction)\n",
            "restricted private call transaction_source_result_under_existing_mutex",
        ),
        (
            "app/safety/copy_operation.py",
            "class _TestLocalCopyOperation:\n"
            "    def unrelated(self):\n"
            "        return build_copy_provenance_material(source, receipt, manifest_id='M')\n",
            "restricted private call build_copy_provenance_material",
        ),
        (
            "app/safety/copy_ledger.py",
            "def unrelated():\n"
            "    return CopyProvenanceMaterial(object())\n",
            "restricted private call CopyProvenanceMaterial",
        ),
        (
            "app/safety/copy_operation.py",
            "class _TestLocalCopyOperation:\n"
            "    def unrelated(self):\n"
            "        return self._ledgers.publish_operation_binding()\n",
            "restricted private call publish_operation_binding",
        ),
        (
            "app/safety/copy_ledger.py",
            "class DurableCopyLedgers:\n"
            "    def unrelated(self):\n"
            "        return self._authenticated_publish_terminal_bindings_under_existing_mutex(mutex, ledger)\n",
            "restricted private call _authenticated_publish_terminal_bindings_under_existing_mutex",
        ),
        (
            "app/synthetic.py",
            "terminals = capability._publish_terminal_binding_sha256s\n"
            "binding = capability._copy_cross_reference_sha256\n",
            "sensitive authority attribute access",
        ),
        (
            "app/safety/copy_operation.py",
            "class _TestLocalCopyOperation:\n"
            "    def reconcile(self):\n"
            "        return self._boundary._consume_restricted_recovery_locator(capability, transaction)\n",
            "restricted private call _consume_restricted_recovery_locator",
        ),
        (
            "app/safety/production_guard.py",
            "def _reconcile_test_publish_operation():\n"
            "    return boundary._consume_restricted_copy_recovery_locator(capability, context)\n",
            "restricted private call _consume_restricted_copy_recovery_locator",
        ),
        (
            "app/synthetic.py",
            "def leak_paths(recovery_record):\n"
            "    return (recovery_record.source_relative_path, "
            "recovery_record.target_relative_path)\n",
            "restricted recovery attribute access recovery_record.source_relative_path",
        ),
        (
            "app/safety/production_guard.py",
            "class _BoundaryCore:\n"
            "    def consume_restricted_recovery_locator(self, capability, transaction_id):\n"
                "        record = self.__restricted_recovery_records.get(locator_id)\n"
                "        return (Path(record.source_relative_path), "
                "Path(record.target_relative_path))\n",
                "restricted recovery attribute access "
                "self.__restricted_recovery_records.get().source_relative_path",
        ),
        (
            "app/safety/production_guard.py",
            "class _BoundaryCore:\n"
                "    def consume_restricted_recovery_locator(self, capability, transaction_id):\n"
                "        record = self.__restricted_recovery_records.get(locator_id)\n"
                "        return record.source_relative_path.as_posix()\n",
                "restricted recovery attribute access "
                "self.__restricted_recovery_records.get().source_relative_path",
        ),
        (
            "app/synthetic.py",
            "def reset_owner(recovery_record):\n"
            "    recovery_record.owner_thread = 0\n",
            "restricted recovery authority assignment recovery_record.owner_thread",
        ),
        (
            "app/synthetic.py",
            "def reset_owner_object(recovery_record, replacement):\n"
            "    recovery_record.owner_thread_object = replacement\n",
            "restricted recovery authority assignment recovery_record.owner_thread_object",
        ),
        (
            "app/synthetic.py",
            "def reset_owner_object_binding(recovery_record):\n"
            "    recovery_record.owner_thread_object_binding_sha256 = '0' * 64\n",
            "restricted recovery authority assignment "
            "recovery_record.owner_thread_object_binding_sha256",
        ),
        (
            "app/synthetic.py",
            "def reset_lifecycle(recovery_record):\n"
            "    recovery_record.lifecycle = 'ISSUED'\n",
            "restricted recovery authority assignment recovery_record.lifecycle",
        ),
        (
            "app/synthetic.py",
            "def reset_consumed(recovery_record):\n"
            "    recovery_record.consumed = False\n",
            "restricted recovery authority assignment recovery_record.consumed",
        ),
        (
            "app/synthetic.py",
            "capability._RestrictedRecoveryLocatorCapability__locator_id = '0' * 64\n",
            "restricted recovery authority assignment "
            "capability._RestrictedRecoveryLocatorCapability__locator_id",
        ),
        (
            "app/synthetic.py",
            "object.__setattr__(\n"
            "    capability,\n"
            "    '_RestrictedRecoveryLocatorCapability__authenticator',\n"
            "    b'x' * 32,\n"
            ")\n",
            "reflective restricted recovery authority __setattr__",
        ),
        (
            "app/synthetic.py",
            "def tamper_binding(recovery_record):\n"
            "    recovery_record.binding_sha256 = '0' * 64\n",
            "restricted recovery authority assignment recovery_record.binding_sha256",
        ),
        (
            "app/synthetic.py",
            "def tamper_authenticator(recovery_record):\n"
            "    recovery_record.capability_authenticator = b'x' * 32\n",
            "restricted recovery authority assignment "
            "recovery_record.capability_authenticator",
        ),
        (
            "app/synthetic.py",
            "core._BoundaryCore__restricted_recovery_records.clear()\n",
            "restricted recovery attribute access "
            "core._BoundaryCore__restricted_recovery_records",
        ),
        (
            "app/synthetic.py",
            "getattr(core, '_BoundaryCore__restricted_recovery_records')\n",
            "dynamic restricted recovery authority getattr",
        ),
        (
            "app/synthetic.py",
            "vars(core)['_BoundaryCore__restricted_recovery_records']\n",
            "dynamic restricted recovery registry lookup",
        ),
        (
            "app/synthetic.py",
            "capability._read(object())\n",
            "restricted recovery attribute access capability._read",
        ),
        (
            "app/synthetic.py",
            "core._derive_restricted_recovery_paths(context, purpose)\n",
            "restricted private call _derive_restricted_recovery_paths",
        ),
        (
            "app/synthetic.py",
            "core._restricted_recovery_locator_binding(\n"
            "    locator, context, transaction, source, target, purpose, owner, "
            "owner_object_binding\n"
            ")\n",
            "restricted private call _restricted_recovery_locator_binding",
        ),
        (
            "app/synthetic.py",
            "core._restricted_recovery_owner_thread_object_binding(owner_object)\n",
            "restricted private call "
            "_restricted_recovery_owner_thread_object_binding",
        ),
        (
            "app/synthetic.py",
            "core._restricted_recovery_capability_authenticator(locator, binding)\n",
            "restricted private call _restricted_recovery_capability_authenticator",
        ),
        (
            "app/synthetic.py",
            "core._revoke_restricted_recovery_records(ticket_id)\n",
            "restricted private call _revoke_restricted_recovery_records",
        ),
        (
            "app/safety/production_guard.py",
            "class _BoundaryCore:\n"
            "    @property\n"
            "    def diagnostic_registry_counts(self):\n"
            "        return tuple(self.__restricted_recovery_records.keys())\n",
            "restricted recovery attribute access "
            "self.__restricted_recovery_records",
        ),
        (
            "app/safety/production_guard.py",
            "class _BoundaryCore:\n"
            "    @property\n"
            "    def diagnostic_registry_counts(self):\n"
            "        return tuple(\n"
            "            record.source_relative_path\n"
            "            for record in self.__restricted_recovery_records.values()\n"
            "        )\n",
            "restricted recovery attribute access "
            "self.__restricted_recovery_records",
        ),
        (
            "app/safety/production_guard.py",
            "class _BoundaryCore:\n"
            "    def unrelated(self, recovery_record):\n"
            "        return recovery_record.locator_id\n",
            "restricted recovery attribute access recovery_record.locator_id",
        ),
        (
            "app/safety/production_guard.py",
            "class _BoundaryCore:\n"
            "    def consume_restricted_recovery_locator(self, capability):\n"
            "        return capability."
            "_RestrictedRecoveryLocatorCapability__locator_id\n",
            "restricted recovery attribute access capability."
            "_RestrictedRecoveryLocatorCapability__locator_id",
        ),
        (
            "app/synthetic.py",
            "copy_ledgers.matches_run_scope(run_id)\n",
            "restricted private call matches_run_scope",
        ),
        (
            "app/synthetic.py",
            "copy_ledgers.transaction_binding(context, evidence)\n",
            "restricted private call transaction_binding",
        ),
        (
            "app/synthetic.py",
            "copy_ledgers.target_locator(target, classification)\n",
            "restricted private call target_locator",
        ),
        (
            "app/synthetic.py",
            "epoch = copy_ledgers.storage_epoch_id\n",
            "sensitive authority attribute access copy_ledgers.storage_epoch_id",
        ),
        (
            "app/safety/copy_ledger.py",
            "def unrelated():\n"
            "    return _derive_copy_ledger_epoch_id(revision, run_id)\n",
            "restricted private call _derive_copy_ledger_epoch_id",
        ),
        (
            "app/synthetic.py",
            "operation_ledger.operation_reference(operation_id, classification)\n",
            "restricted private call operation_reference",
        ),
        (
            "app/synthetic.py",
            "copy_ledgers._append_transition_under_existing_mutex(mutex, recovery)\n",
            "restricted private call _append_transition_under_existing_mutex",
        ),
        (
            "app/safety/copy_operation.py",
            "class _TestLocalCopyOperation:\n"
            "    def unrelated(self):\n"
            "        self._target_evidence(target, material)\n",
            "restricted private call _target_evidence",
        ),
        (
            "app/safety/copy_operation.py",
            "class _TestLocalCopyOperation:\n"
            "    def unrelated(self):\n"
            "        self._require_target_absent_twice(target)\n",
            "restricted private call _require_target_absent_twice",
        ),
        (
            "app/synthetic.py",
            "writer._require_directory_target_absent_under_existing_mutex(\n"
            "    mutex, target\n"
            ")\n",
            "restricted private call "
            "_require_directory_target_absent_under_existing_mutex",
        ),
        (
            "app/safety/copy_operation.py",
            "class _TestLocalCopyOperation:\n"
            "    def unrelated(self):\n"
            "        self._runtime._writer."
            "_require_directory_target_absent_under_existing_mutex(\n"
            "            mutex, target\n"
            "        )\n",
            "restricted private call "
            "_require_directory_target_absent_under_existing_mutex",
        ),
        (
            "app/safety/windows_handle_writer.py",
            "class _WindowsHandleWriter:\n"
            "    def unrelated(self, target):\n"
            "        self._after_directory_target_absence_first_observation(target)\n",
            "restricted private call "
            "_after_directory_target_absence_first_observation",
        ),
        (
            "app/synthetic.py",
            "source_lease.verify_unchanged(evidence)\n",
            "restricted private call verify_unchanged",
        ),
        (
            "app/safety/copy_operation.py",
            "class _TestLocalCopyOperation:\n"
            "    def unrelated(self):\n"
            "        self._raise_recovery_contradiction()\n",
            "restricted private call _raise_recovery_contradiction",
        ),
        (
            "app/synthetic.py",
            "proof = capability._audit_ledger._storage\n"
            "segments = capability._audit_segment_sha256s\n",
            "sensitive authority attribute access",
        ),
        (
            "app/synthetic.py",
            "copy_ledgers._seal(code)\n",
            "restricted private call _seal",
        ),
        (
            "app/safety/copy_ledger.py",
            "def unrelated():\n"
            "    return _AuthenticatedCopyAncestors(\n"
            "        object(), _constructor=_AUTHENTICATED_COPY_ANCESTORS_CONSTRUCTOR\n"
            "    )\n",
            "restricted private symbol _AUTHENTICATED_COPY_ANCESTORS_CONSTRUCTOR outside exact scope unrelated",
        ),
        (
            "app/synthetic.py",
            "from app.safety.windows_handle_writer import "
            "HandleObjectIdentityMaterial\n",
            "private import HandleObjectIdentityMaterial",
        ),
        (
            "app/safety/windows_handle_writer.py",
            "def unrelated():\n"
            "    return HandleObjectIdentityMaterial(\n"
            "        _constructor=_IDENTITY_MATERIAL_CONSTRUCTOR\n"
            "    )\n",
            "restricted private symbol _IDENTITY_MATERIAL_CONSTRUCTOR outside exact scope unrelated",
        ),
        (
            "app/synthetic.py",
            "material._operation_hmac_sha256(key)\n",
            "restricted private call _operation_hmac_sha256",
        ),
        (
            "app/synthetic.py",
            "raw = material._HandleObjectIdentityMaterial__frame\n",
            "sensitive authority attribute access",
        ),
        (
            "app/synthetic.py",
            "material = snapshot.tree_identity_material\n",
            "sensitive authority attribute access",
        ),
    ],
)
def test_s3_f_reconcile_authority_canaries_fail_closed(
    file: str,
    source: str,
    expected: str,
) -> None:
    rendered = "\n".join(
        detail
        for _finding_file, _line, detail in scan_unauthorized_guard_source(
            source,
            file=file,
        )
    )
    assert expected in rendered


def test_s3_f_plain_digest_ancestor_self_proof_is_rejected_in_allowed_scope() -> None:
    findings = scan_unauthorized_guard_source(
        '''
def _create_test_copy_ledgers():
    ledgers._verify_external_ancestors_under_existing_mutex(
        mutex, ("a" * 64,), ("b" * 64,)
    )
''',
        file="app/safety/production_guard.py",
    )
    rendered = "\n".join(detail for _file, _line, detail in findings)
    assert "authenticated ancestor verify requires its exact one-shot issue result" in rendered


def test_s3_f_authenticated_ancestor_capability_cannot_be_reassigned_or_reused() -> None:
    findings = scan_unauthorized_guard_source(
        '''
def _create_test_copy_ledgers():
    capability = ledgers._issue_authenticated_ancestors_under_existing_mutex(
        mutex, audit_ledger, operation_ledger
    )
    capability = ("a" * 64,)
    ledgers._verify_external_ancestors_under_existing_mutex(mutex, capability)
    ledgers._verify_external_ancestors_under_existing_mutex(mutex, capability)
''',
        file="app/safety/production_guard.py",
    )
    rendered = "\n".join(detail for _file, _line, detail in findings)
    assert "authenticated ancestor issue must feed one exact local verify" in rendered
    assert "authenticated ancestor verify requires its exact one-shot issue result" in rendered
