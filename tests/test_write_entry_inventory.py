from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter
from dataclasses import replace

import pytest

from app.config import PROJECT_ROOT
from app.safety.static_audit import (
    _AUDITED_INDEXED_CALLS,
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
    assert counts[WritePrimitiveKind.SQLITE_RAW_CONNECT] == 2
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
    exact = Counter({callsite: 1 for callsite in _AUDITED_INDEXED_CALLS})
    _assert_audited_indexed_hits(exact)

    stale = Counter(exact)
    stale[next(iter(_AUDITED_INDEXED_CALLS))] = 0
    with pytest.raises(RuntimeError, match="suppression drifted"):
        _assert_audited_indexed_hits(stale)

    duplicate = Counter(exact)
    duplicate[next(iter(_AUDITED_INDEXED_CALLS))] = 2
    with pytest.raises(RuntimeError, match="suppression drifted"):
        _assert_audited_indexed_hits(duplicate)


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


def test_no_current_production_module_bypasses_fixed_boundary() -> None:
    assert scan_unauthorized_guard_construction() == ()
