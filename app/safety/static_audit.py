from __future__ import annotations

import ast
import hashlib
import json
import re
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterable, Iterator

from app.config import PROJECT_ROOT


SCANNER_VERSION = "M0-S2-STATIC-AUDIT-V5"
PRODUCTION_ROOTS = ("app", "scripts")
SOURCE_SUFFIXES = (".py", ".sql")
SOURCE_BYTE_NORMALIZATION = "UTF8_LF_V1"
ENTRY_CHUNK_SIZE = 25

# Indexed receivers lose their concrete type in this small AST analysis.  Only
# exact repository callsites that were manually reviewed as in-memory/read-only
# are suppressed.  A new or changed callsite therefore becomes UNKNOWN instead
# of inheriting a globally safe-looking method name such as ``get`` or
# ``resolve``.  Sink-shaped methods are classified before this table is used.
_AUDITED_INDEXED_CALLS = frozenset(
    {
        ("app/codex_structure.py", "app.codex_structure._extract_subquestions", "5d696616fed58ea711bb2f29ca183415c5f1e01fb3141173844d22532a3d954a"),
        ("app/codex_structure.py", "app.codex_structure._split_options", "6bbcc55d9f54b6026e2874e6b35eac1854e1437245667404e34d2639a9a57bcc"),
        ("app/codex_structure.py", "app.codex_structure._split_options", "99342fe48f8acb91372d8433584c8dcd1d45989fba0a77bb24beeddc232c0403"),
        ("app/codex_structure.py", "app.codex_structure.run_codex_structure_batch", "ebd6facba6ebaa9a5b0a749c238e4ad564856552820e1b84ac0884dea26bdb2a"),
        ("app/config.py", "app.config.find_unique_target_pdf", "c8826b2017d8b2011090ccfb484159adf9d8b424f3bc48ebf63690ed20a288f2"),
        ("app/export_quality.py", "app.export_quality._render_stage12_report", "3585d9395fde7249ada143ccc279b9d15390a9bdc8d3b09eab21dcc2df8a520f"),
        ("app/export_quality.py", "app.export_quality._render_stage12_report", "4795090d0b5fc39492946cdb4a5ecf36a86fdf6760b1f45d1318b1540296ae3b"),
        ("app/export_quality.py", "app.export_quality._render_stage12_report", "542987264d37611c7ccdee8e1a81525098f8d50666d6247590ed1a165c12b2d6"),
        ("app/export_quality.py", "app.export_quality._render_stage12_report", "a04e02570adeb3db19b2556212d08e6082eb2feef991b6d165926a41c1823d09"),
        ("app/export_quality.py", "app.export_quality._render_stage12_report", "c8ed9a43925d451f0b5579a270b8ba82b1783037b2a9d341f450e87b9eefbdb8"),
        ("app/export_quality.py", "app.export_quality._render_stage12_report", "e3425abfab8c3a52c0f751a3b1d63a21984b48dea3a310ad2bf54d29bffeeb55"),
        ("app/health.py", "app.health.check_sqlite", "69fff54d09cbb7d3929c377db944c875cffd0c105fb53679760bbb9f6462374c"),
        ("app/pdf_import.py", "app.pdf_import.build_paper_code", "8d49edced4935578aaad294e6558fd2044c7603f2eefd2c9f10f8f69f953f6b6"),
        ("app/pdf_import.py", "app.pdf_import.render_pdf_pages", "ca9b3303b86d492168981dc7d9d34210b4f45d9e732280fcca469d8657573f01"),
        ("app/question_assets.py", "app.question_assets.crop_question_assets", "43569ee06df8a7fc8875ec3f15a3cb2d3d0583ae4941fb94e72b99eac9f8171a"),
        ("app/question_split.py", "app.question_split.extract_page_text_blocks", "1aef377320dac5bfadb0aac1281fdacb17d8c36ac214ddcd92ed1e69aa05edc3"),
        ("app/safety/audit_events.py", "app.safety.audit_events.audit_hmac_key_id", "c78ca38e66dbcf5cb8df482b19dead92b2a003dd04d5b48bc239e6d3d3606cda"),
        ("app/safety/production_guard.py", "app.safety.production_guard._create_test_boundary", "c74c3f6c1d132b896ac4b6ac0a6da4f83e6615421cee5858697dd38d5ce975d6"),
        ("app/safety/static_audit.py", "app.safety.static_audit._SinkVisitor.visit_Global", "addd2d256c10ae286feedeedb6b0ecd310c6d9eafc4b429f7a54cdf1f5a21a56"),
        ("app/safety/static_audit.py", "app.safety.static_audit._SinkVisitor.visit_Global", "ecacb8e1ecbe79b62f74dc0dc6885b5f1b269854da13461baf3572b7b28de490"),
        ("app/safety/static_audit.py", "app.safety.static_audit._SinkVisitor.visit_Global", "f323ea157bced7c5a1ad1886625e0797582641ab0e7681bfd28fbfe4eb2b12e3"),
        ("app/safety/static_audit.py", "app.safety.static_audit._build_call_graph", "18dcb3736c328b8e1e8a31ef5f8dc1d657dd350f47d40b40ee97c26d13af41f6"),
        ("app/safety/static_audit.py", "app.safety.static_audit._enrich_entries", "4ac8662fbdb63066e027975e837fc53bbc8dca18dbcc35fa7ffd77235c9be50a"),
        ("app/safety/static_audit.py", "app.safety.static_audit._enrich_entries", "cffa030ff7a8a3fddcf11639e26b92ac4bd4f1e2fdb69909ca82a22181c3a283"),
        ("app/safety/static_audit.py", "app.safety.static_audit._looks_like_archive_receiver", "059deb25070485d5b51b6cf7e1ea8d2e366ad1a7613452bf8281e0a916965ef4"),
        ("app/safety/static_audit.py", "app.safety.static_audit._looks_like_path_receiver", "059deb25070485d5b51b6cf7e1ea8d2e366ad1a7613452bf8281e0a916965ef4"),
        ("app/safety/static_audit.py", "app.safety.static_audit._looks_like_path_receiver", "860a78c752c4f7a5534593cdd7b5577dee88be8b0aa2ac93783c95cb0af7215f"),
        ("app/safety/static_audit.py", "app.safety.static_audit._looks_like_path_receiver", "8d9664d4bc9274a8c1dbe02c2522e099c040d9b5b23274481e44fd4528aed811"),
        ("app/safety/static_audit.py", "app.safety.static_audit._resolve_import_module", "797054c5fce90fcfeac97951fb5df588a649e82230605a92d6c174903ca1a967"),
        ("app/safety/static_audit.py", "app.safety.static_audit._root_ids", "fae67c1b67f348de7a2602636941a1f4d55b8b0f37cad7388b63e49dc1615b3a"),
        ("app/source_attribution.py", "app.source_attribution._find_previous_header", "e23cbd304697341859f0f6725b92a684b565d084c4efc700c719367ff06a5ef2"),
        ("app/source_attribution.py", "app.source_attribution._load_headers_for_rows", "184edec26d0fd915e5eceb6ab4fc7a6dcd5b05f21b2c2a5a3a7bd55dd325493e"),
        ("app/source_attribution.py", "app.source_attribution._load_headers_for_rows", "1b15b27f234a11c6888d061e89703732ef423d5ff1fd5b9c285bd697b31d3cd4"),
        ("app/source_attribution.py", "app.source_attribution._render_report_markdown", "9d0713e662e8a5726f025bf7694010807cf59bb5f4109a4f2eedcad54d748644"),
        ("app/source_attribution.py", "app.source_attribution._render_report_markdown", "c89bcb0c81ea5a4aba6469cc094c5cb4c1384804f6edbb8a65e6076a4a95ccb0"),
        ("app/source_attribution.py", "app.source_attribution._render_report_markdown", "e231b2ac9653afaa9018aabd02b3d4d87d23ab6cc9a5ed7e9baf1a23920c6a96"),
        ("app/stage10.py", "app.stage10._extract_subquestions", "5d696616fed58ea711bb2f29ca183415c5f1e01fb3141173844d22532a3d954a"),
        ("app/stage10.py", "app.stage10._render_stage10_report", "130a6f05c1c473057734b3c1ca44b04753c8ddead6f52605f67e6e11a1f55bd0"),
        ("app/stage10.py", "app.stage10._render_stage10_report", "6c0522b6580a099a9c4dffd6a9c846648be242d2b5208fd0222b8a8469ca88cb"),
        ("app/stage10.py", "app.stage10._render_stage10_report", "81dab40a921cf215cb545ac24e4e080cba90127887f2ff8e101de3121d6a8815"),
        ("app/stage10.py", "app.stage10._render_stage10_report", "888a3981d64bd5ecb328936d0a42e0aeb25374706f624dc3b49ba16c48a18e42"),
        ("app/stage10.py", "app.stage10._render_stage10_report", "8f1520a8d7f78796297180083b6baa8eca6b5bb68a009eb492d955e6a6d53ee8"),
        ("app/stage10.py", "app.stage10._render_stage10_report", "a5f02b29265136ecca94f2c47c9d569d3ec367e5afcfc45d1e18a92438152eee"),
        ("app/stage10.py", "app.stage10._select_baseline_rows.add", "ab1df94f59890c70f23a453d282060f7caf2b210a63c2763ad6ed59da378d1fb"),
        ("app/stage10.py", "app.stage10._split_options", "6bbcc55d9f54b6026e2874e6b35eac1854e1437245667404e34d2639a9a57bcc"),
        ("app/stage10.py", "app.stage10._split_options", "99342fe48f8acb91372d8433584c8dcd1d45989fba0a77bb24beeddc232c0403"),
        ("app/stage11.py", "app.stage11._render_stage11_report", "10b6e76de9ce8e8b0a87a95fc69fee81a26b2bc049a93d73b5fcd22c12fc20c4"),
        ("app/stage11.py", "app.stage11._render_stage11_report", "19bb361eb3d842776732e11f03bc757a5f3a21bf09b51d9f00d5aec026b90c04"),
        ("app/stage11.py", "app.stage11._render_stage11_report", "58b515614b6129152b60eb4fd73f7d31984f36368472ba97f17d5065d76f6824"),
        ("app/stage11.py", "app.stage11._render_stage11_report", "6c0522b6580a099a9c4dffd6a9c846648be242d2b5208fd0222b8a8469ca88cb"),
        ("app/stage11.py", "app.stage11._render_stage11_report", "bfa80573cc0c34b60cbb107134f55c4d237f3394c07d3d0636759d34aca85a40"),
        ("app/stage11.py", "app.stage11._render_stage11_report", "c818bed85cf2507efebe74715d250eca6438c6d3b0a75822d2228aa685403308"),
        ("app/stage14.py", "app.stage14.Stage14QualityService._audit_inferred_source_group", "184edec26d0fd915e5eceb6ab4fc7a6dcd5b05f21b2c2a5a3a7bd55dd325493e"),
        ("app/stage14.py", "app.stage14.Stage14QualityService.audit_inferred_sources", "ecdbe07e5bd9a03f071abe682871c9bd143f4ffd07e74531eb445097ab9e423e"),
        ("app/stage9_report.py", "app.stage9_report._render_report_v2", "9b6773289ff82312f8dde9df4fb678db2f4dba67cce6cf847148529493a94b45"),
        ("app/stage9_report.py", "app.stage9_report._render_report_v2", "b139a081c198d0f700aad7f28a5aaeae3f2599f43530663783e8e9877fd922fb"),
        ("app/stage9_report.py", "app.stage9_report._render_report_v2", "d21fe8a51c3f0353a8b734f31eb9271407c21587fe6ebfa22b7815b8f15d1f65"),
        ("app/structured_ai.py", "app.structured_ai._parse_provider_json_content", "9e0718357d7a03b61e184e52d3f1069445e4243df937fc4f8c7f8d270a063a17"),
        ("app/structured_ai.py", "app.structured_ai._parse_provider_json_content", "b856a360605aab5df22cfa221d145129961fa395b74ff0dad2bf1971da300835"),
        ("app/structured_render.py", "app.structured_render.build_paper_sections", "add654e0974bad72d73f1af46dc9b543a3619f0085f028daace34744ff8805bf"),
        ("app/workspace_guard.py", "app.workspace_guard._validate_lexical", "e504908ef3a59bd463559472b05fe46da547b630c375ffd0fd665b462d3bf23d"),
        ("scripts/run_safe_pytest.py", "scripts.run_safe_pytest._protected_tree_snapshot", "e1d3bd62adce6c525c264f4d980a76bfda2c42d6aecd83285afa0a7be53f6b06"),
    }
)


class WritePrimitiveKind(StrEnum):
    FILESYSTEM_DIRECTORY_CREATE = "FILESYSTEM_DIRECTORY_CREATE"
    FILESYSTEM_FILE_WRITE = "FILESYSTEM_FILE_WRITE"
    FILESYSTEM_COPY = "FILESYSTEM_COPY"
    FILESYSTEM_MOVE_OR_REPLACE = "FILESYSTEM_MOVE_OR_REPLACE"
    FILESYSTEM_DELETE = "FILESYSTEM_DELETE"
    FILESYSTEM_LINK = "FILESYSTEM_LINK"
    FILESYSTEM_METADATA = "FILESYSTEM_METADATA"
    TEMPORARY_RESOURCE = "TEMPORARY_RESOURCE"
    ARCHIVE_WRITE = "ARCHIVE_WRITE"
    ARCHIVE_EXTRACT = "ARCHIVE_EXTRACT"
    SQLITE_RAW_CONNECT = "SQLITE_RAW_CONNECT"
    DATABASE_GATEWAY = "DATABASE_GATEWAY"
    DATABASE_IMPLICIT_INITIALIZER = "DATABASE_IMPLICIT_INITIALIZER"
    SQLITE_MUTATION = "SQLITE_MUTATION"
    SQLITE_DYNAMIC_SQL = "SQLITE_DYNAMIC_SQL"
    SQLITE_TRANSACTION = "SQLITE_TRANSACTION"
    SQLITE_BACKUP_OR_EXTENSION = "SQLITE_BACKUP_OR_EXTENSION"
    SQLITE_SCHEMA_MUTATION = "SQLITE_SCHEMA_MUTATION"
    EXTERNAL_PROCESS = "EXTERNAL_PROCESS"
    NETWORK_REQUEST = "NETWORK_REQUEST"
    SYSTEM_STATE = "SYSTEM_STATE"
    UNKNOWN_DYNAMIC_CAPABILITY = "UNKNOWN_DYNAMIC_CAPABILITY"


class ResolutionConfidence(StrEnum):
    EXACT = "EXACT"
    ALIAS_RESOLVED = "ALIAS_RESOLVED"
    CONSERVATIVE = "CONSERVATIVE"
    DYNAMIC = "DYNAMIC"


class MigrationStatus(StrEnum):
    UNMIGRATED_BLOCKED = "UNMIGRATED_BLOCKED"
    ACCEPTED_MEMORY_ONLY = "ACCEPTED_MEMORY_ONLY"


class RiskLevel(StrEnum):
    P0 = "P0"
    P1 = "P1"


@dataclass(frozen=True, slots=True)
class WriteEntry:
    entry_id: str
    file: str
    source_sha256: str
    line: int
    column: int
    end_line: int
    end_column: int
    function: str
    kind: WritePrimitiveKind
    callee: str
    resolution: ResolutionConfidence
    statement_fingerprint: str
    owner: str
    target_namespace: str
    required_control: str
    migration_status: MigrationStatus
    input_source: str
    risk: RiskLevel
    root_ids: tuple[str, ...]
    call_chain: tuple[str, ...]
    detail: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        for name in ("kind", "resolution", "migration_status", "risk"):
            payload[name] = getattr(self, name).value
        payload["root_ids"] = list(self.root_ids)
        payload["call_chain"] = list(self.call_chain)
        return payload


@dataclass(frozen=True, slots=True)
class _RawEntry:
    file: str
    source_sha256: str
    line: int
    column: int
    end_line: int
    end_column: int
    function: str
    kind: WritePrimitiveKind
    callee: str
    resolution: ResolutionConfidence
    statement_fingerprint: str
    detail: str


@dataclass(frozen=True, slots=True)
class _FunctionFact:
    canonical: str
    file: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    root_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ModuleFacts:
    file: str
    module: str
    source_sha256: str
    tree: ast.Module
    parents: dict[ast.AST, ast.AST]
    imports: dict[str, str]
    functions: dict[str, _FunctionFact]


_SQL_MUTATION = frozenset(
    {
        "INSERT",
        "UPDATE",
        "DELETE",
        "REPLACE",
        "CREATE",
        "ALTER",
        "DROP",
        "VACUUM",
        "ATTACH",
        "DETACH",
        "REINDEX",
        "ANALYZE",
        "PRAGMA",
    }
)
_SQL_TRANSACTION = frozenset(
    {"BEGIN", "COMMIT", "END", "ROLLBACK", "SAVEPOINT", "RELEASE"}
)
_SQL_PREFIX = re.compile(
    r"\b(SELECT|WITH|INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP|VACUUM|ATTACH|DETACH|REINDEX|ANALYZE|PRAGMA|BEGIN|COMMIT|END|ROLLBACK|SAVEPOINT|RELEASE|EXPLAIN)\b",
    re.IGNORECASE,
)
_SQL_COMMENTS = re.compile(r"(?:--[^\n]*(?:\n|$)|/\*.*?\*/)", re.DOTALL)


def scan_production_write_entries() -> tuple[WriteEntry, ...]:
    root = _verified_project_root()
    snapshot = _production_source_snapshot(root)
    return _scan_production_snapshot(root, snapshot)


def _scan_production_snapshot(
    root: Path,
    snapshot: tuple[tuple[Path, bytes], ...],
) -> tuple[WriteEntry, ...]:
    facts = _load_module_facts(root, snapshot)
    raw_entries: list[_RawEntry] = []
    audited_indexed_hits: Counter[tuple[str, str, str]] = Counter()
    for module in facts.values():
        raw_entries.extend(
            _scan_module(module, audited_indexed_hits=audited_indexed_hits)
        )
    _assert_audited_indexed_hits(audited_indexed_hits)
    raw_entries.extend(_scan_sql_files(root, snapshot))
    graph, roots = _build_call_graph(facts)
    entries = _enrich_entries(raw_entries, graph, roots)
    return tuple(
        sorted(
            entries,
            key=lambda item: (
                item.file,
                item.line,
                item.column,
                item.kind.value,
                item.entry_id,
            ),
        )
    )


def _assert_audited_indexed_hits(
    hits: Counter[tuple[str, str, str]],
) -> None:
    drift = {
        callsite: hits.get(callsite, 0)
        for callsite in _AUDITED_INDEXED_CALLS
        if hits.get(callsite, 0) != 1
    }
    if drift:
        raise RuntimeError(
            "audited indexed callsite suppression drifted: "
            + "; ".join(
                f"{file}:{function}:{fingerprint}={count}"
                for (file, function, fingerprint), count in sorted(drift.items())
            )
        )


def scan_python_source(source: str, *, file: str = "synthetic.py") -> tuple[WriteEntry, ...]:
    """Scan a synthetic fixture without importing or executing it."""

    module = _module_facts_from_text(source, file=file)
    raw = _scan_module(module)
    graph, roots = _build_call_graph({module.module: module})
    return tuple(_enrich_entries(raw, graph, roots))


def scan_unauthorized_guard_construction() -> tuple[tuple[str, int, str], ...]:
    findings: list[tuple[str, int, str]] = []
    for module in _load_module_facts(_verified_project_root()).values():
        findings.extend(_guard_findings(module))
    return tuple(sorted(set(findings)))


def scan_unauthorized_guard_source(
    source: str,
    *,
    file: str = "app/synthetic.py",
) -> tuple[tuple[str, int, str], ...]:
    return tuple(sorted(set(_guard_findings(_module_facts_from_text(source, file=file)))))


def _guard_findings(module: _ModuleFacts) -> list[tuple[str, int, str]]:
    findings: list[tuple[str, int, str]] = []
    allowed_file = "app/safety/production_guard.py"
    scope_aliases: dict[str, str] = dict(module.imports)
    for _ in range(8):
        changed = False
        for node in ast.walk(module.tree):
            if isinstance(node, ast.Assign):
                targets = node.targets
                value = node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets = [node.target]
                value = node.value
            else:
                continue
            resolved, _confidence = _resolve_callee(value, scope_aliases)
            for target in targets:
                if isinstance(target, ast.Name) and scope_aliases.get(target.id) != resolved:
                    scope_aliases[target.id] = resolved
                    changed = True
        if not changed:
            break

    forbidden_constructors = {
        "WorkspaceGuard",
        "ProductionWorkspaceBoundary",
        "_TestWorkspaceBoundary",
        "_create_test_boundary",
        "_BoundaryCore",
        "_BoundaryNamespacePolicy",
        "NamespacePolicy",
    }
    forbidden_private_imports = {
        "_BoundaryCore",
        "_create_test_boundary",
        "_TestWorkspaceBoundary",
        "_TOKEN_CONSTRUCTOR",
        "_PAIR_CLAIM_CONSTRUCTOR",
        "_PairPolicyClaim",
        "_authorize_pair_for_boundary",
        "_BoundaryNamespacePolicy",
    }
    sensitive_assignments = {
        "CONTRACT_PROJECT_ROOT",
        "PROJECT_ROOT",
        "_contract_root",
        "_PRODUCTION_BOUNDARY_CONSTRUCTOR",
        "_TOKEN_CONSTRUCTOR",
        "_PAIR_CLAIM_CONSTRUCTOR",
        "_guard",
        "_policy",
        "__guard",
        "__policy",
        "__core",
        "_rules",
        "_digest",
        "_pair_claim_key",
        "_pair_authority",
        "__pair_authority",
        "__pair_policy_authority",
    }
    symbol_definition_files = {
        "WorkspaceGuard": {"app/workspace_guard.py", allowed_file},
        "NamespacePolicy": {"app/safety/namespace_policy.py", allowed_file},
        "ProductionWorkspaceBoundary": {allowed_file},
        "_TestWorkspaceBoundary": {allowed_file},
        "_create_test_boundary": {allowed_file},
        "_BoundaryCore": {allowed_file},
        "_BoundaryNamespacePolicy": {
            allowed_file,
            "app/safety/namespace_policy.py",
        },
    }
    for node in ast.walk(module.tree):
        if isinstance(node, ast.ImportFrom):
            base = _resolve_import_module(module.module, node.module, node.level)
            for alias in node.names:
                if (
                    module.file != allowed_file
                    and base.startswith(
                        ("app.safety.production_guard", "app.safety.namespace_policy")
                    )
                    and (
                        alias.name.startswith("_")
                        or alias.name in forbidden_private_imports
                        or alias.name in forbidden_constructors
                    )
                ):
                    findings.append(
                        (module.file, node.lineno, f"private import {alias.name}")
                    )
        if isinstance(node, (ast.Name, ast.Attribute)):
            resolved, _ = _resolve_callee(node, scope_aliases)
            leaf = resolved.rsplit(".", 1)[-1]
            if (
                leaf in forbidden_constructors
                and module.file not in symbol_definition_files.get(leaf, {allowed_file})
            ):
                findings.append(
                    (module.file, getattr(node, "lineno", 0), f"forbidden symbol reference {resolved}")
                )
        if isinstance(node, ast.ClassDef) and module.file != allowed_file:
            for base in node.bases:
                resolved, _ = _resolve_callee(base, scope_aliases)
                if resolved.rsplit(".", 1)[-1] in forbidden_constructors:
                    findings.append(
                        (module.file, node.lineno, f"subclass {resolved}")
                    )
        if isinstance(node, ast.Call):
            callee, _ = _resolve_callee(node.func, scope_aliases)
            leaf = callee.rsplit(".", 1)[-1]
            if leaf in forbidden_constructors and module.file != allowed_file:
                findings.append((module.file, node.lineno, f"constructor {callee}"))
            if leaf == "_NamespacePolicy__authorize":
                enclosing = _enclosing_function_qualname(node, module.parents)
                if not (
                    module.file == allowed_file
                    and enclosing
                    == "_BoundaryNamespacePolicy._authorize_pair_member"
                ):
                    findings.append(
                        (module.file, node.lineno, f"private pair policy call {leaf}")
                    )
            elif leaf in {
                "_authorize_paired",
                "_issue_pair_claim",
                "_authorize_pair_for_boundary",
                "_authorize_pair",
                "_install_boundary_pair_seal",
            } and module.file != allowed_file:
                findings.append((module.file, node.lineno, f"private pair policy call {leaf}"))
            if leaf in {"setattr", "__setattr__"} and len(node.args) >= 2:
                attribute = _constant_text(node.args[1])
                if attribute in sensitive_assignments and module.file != allowed_file:
                    findings.append(
                        (module.file, node.lineno, f"private state assignment {attribute}")
                    )
            if leaf == "getattr" and len(node.args) >= 2:
                receiver, _ = _resolve_callee(node.args[0], scope_aliases)
                attribute = _constant_text(node.args[1])
                if (
                    receiver.startswith(
                        ("app.safety.production_guard", "app.safety.namespace_policy")
                    )
                    and attribute is None
                    and module.file != allowed_file
                ):
                    findings.append(
                        (module.file, node.lineno, "dynamic safety attribute lookup")
                    )
            if leaf == "vars" and node.args:
                receiver, _ = _resolve_callee(node.args[0], scope_aliases)
                if receiver.startswith(
                    ("app.safety.production_guard", "app.safety.namespace_policy")
                ) and module.file != allowed_file:
                    findings.append(
                        (module.file, node.lineno, "dynamic safety module dictionary lookup")
                    )
            if leaf == "__getattribute__":
                receiver = ""
                if isinstance(node.func, ast.Attribute):
                    receiver_node = node.func.value
                    receiver, _ = _resolve_callee(receiver_node, scope_aliases)
                    if (
                        isinstance(receiver_node, ast.Call)
                        and receiver_node.args
                        and _resolve_callee(receiver_node.func, scope_aliases)[0]
                        in {"type", "builtins.type"}
                    ):
                        receiver, _ = _resolve_callee(
                            receiver_node.args[0],
                            scope_aliases,
                        )
                    if receiver in {"object", "builtins.object"} and node.args:
                        receiver, _ = _resolve_callee(node.args[0], scope_aliases)
                elif node.args:
                    receiver, _ = _resolve_callee(node.args[0], scope_aliases)
                if receiver.startswith(
                    ("app.safety.production_guard", "app.safety.namespace_policy")
                ) and module.file != allowed_file:
                    findings.append(
                        (module.file, node.lineno, "reflective safety attribute lookup")
                    )
            if leaf == "NamespacePolicy" and module.file != allowed_file:
                if any(keyword.arg == "_pair_authority" for keyword in node.keywords):
                    findings.append(
                        (module.file, node.lineno, "pair-enabled policy construction")
                    )
        if isinstance(node, ast.Attribute) and node.attr == "__dict__":
            receiver, _ = _resolve_callee(node.value, scope_aliases)
            if receiver.startswith(
                ("app.safety.production_guard", "app.safety.namespace_policy")
            ) and module.file != allowed_file:
                findings.append(
                    (module.file, node.lineno, "safety module __dict__ lookup")
                )
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets: list[ast.expr]
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            else:
                targets = [node.target]
            for target in targets:
                target_name = ""
                if isinstance(target, ast.Attribute):
                    target_name = target.attr
                elif isinstance(target, ast.Name):
                    target_name = target.id
                if target_name not in sensitive_assignments:
                    continue
                allowed_assignment = (
                    module.file == allowed_file
                    or (module.file == "app/config.py" and target_name == "PROJECT_ROOT")
                    or (
                        module.file == "app/safety/namespace_policy.py"
                        and target_name
                        in {
                            "_rules",
                            "_digest",
                            "_pair_claim_key",
                            "_pair_authority",
                            "__pair_authority",
                            "_PAIR_CLAIM_CONSTRUCTOR",
                        }
                    )
                )
                if not allowed_assignment:
                    findings.append(
                        (module.file, node.lineno, f"private state assignment {target_name}")
                    )
    return findings


def inventory_digest(entries: Iterable[WriteEntry]) -> str:
    return _canonical_sha256([entry.to_dict() for entry in entries])


def payload_digest(payload: dict[str, Any]) -> str:
    canonical = dict(payload)
    canonical.pop("inventory_digest_sha256", None)
    return _canonical_sha256(canonical)


def production_source_manifest(
    snapshot: tuple[tuple[Path, bytes], ...] | None = None,
) -> tuple[dict[str, Any], ...]:
    root = _verified_project_root()
    source_snapshot = snapshot or _production_source_snapshot(root)
    rows: list[dict[str, Any]] = []
    for path, data in source_snapshot:
        rows.append(
            {
                "file": path.relative_to(root).as_posix(),
                "normalization": SOURCE_BYTE_NORMALIZATION,
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return tuple(rows)


def build_inventory_payload(
    *,
    generated_at: str,
    source_head: str,
) -> dict[str, Any]:
    manifest, _ = build_inventory_bundle(
        generated_at=generated_at,
        source_head=source_head,
    )
    return manifest


def build_inventory_bundle(
    *,
    generated_at: str,
    source_head: str,
) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
    root = _verified_project_root()
    snapshot = _production_source_snapshot(root)
    entries = _scan_production_snapshot(root, snapshot)
    counts = Counter(entry.kind.value for entry in entries)
    source_manifest = list(production_source_manifest(snapshot))
    chunks: list[dict[str, Any]] = []
    chunk_refs: list[dict[str, Any]] = []
    entry_rows = [entry.to_dict() for entry in entries]
    for start in range(0, len(entry_rows), ENTRY_CHUNK_SIZE):
        chunk_index = start // ENTRY_CHUNK_SIZE
        rows = entry_rows[start : start + ENTRY_CHUNK_SIZE]
        chunk: dict[str, Any] = {
            "schema_version": "2.0",
            "chunk_index": chunk_index,
            "entry_count": len(rows),
            "entries": rows,
        }
        chunk["chunk_digest_sha256"] = _canonical_sha256(chunk)
        chunks.append(chunk)
        chunk_refs.append(
            {
                "path": (
                    "Task/reports/M0/write-entry-inventory/"
                    f"entries-{chunk_index:03d}.json"
                ),
                "entry_count": len(rows),
                "canonical_payload_sha256": chunk["chunk_digest_sha256"],
                "serialized_file_sha256": hashlib.sha256(
                    _pretty_json_bytes(chunk)
                ).hexdigest(),
            }
        )
    payload: dict[str, Any] = {
        "schema_version": "2.0",
        "scanner_version": SCANNER_VERSION,
        "generated_at": generated_at,
        "source_head": source_head,
        "source_dirty": True,
        "project_root_id": "CONTRACT_PROJECT_ROOT",
        "included_roots": list(PRODUCTION_ROOTS),
        "excluded_roots": ["tests", "Base", "Copy", "Task/local", ".git"],
        "source_byte_normalization": SOURCE_BYTE_NORMALIZATION,
        "source_manifest": source_manifest,
        "source_manifest_digest_sha256": _canonical_sha256(source_manifest),
        "entry_count": len(entries),
        "entry_chunk_size": ENTRY_CHUNK_SIZE,
        "entry_chunks": chunk_refs,
        "entries_digest_sha256": inventory_digest(entries),
        "counts_by_kind": dict(sorted(counts.items())),
        "global_status": "UNMIGRATED_BLOCKED",
        "gate": {
            "unknown_dynamic_count": counts.get(
                WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY.value, 0
            ),
            "unmigrated_count": sum(
                entry.migration_status is MigrationStatus.UNMIGRATED_BLOCKED
                for entry in entries
            ),
            "production_writer_connected": False,
            "m0_exit_allowed": False,
        },
    }
    payload["inventory_digest_sha256"] = payload_digest(payload)
    return payload, tuple(chunks)


def _verified_project_root() -> Path:
    root = Path(PROJECT_ROOT)
    expected = Path(r"D:\AAA命题\Test")
    if str(root).casefold() != str(expected).casefold():
        raise RuntimeError("static audit project root differs from the execution contract")
    return root


def _production_source_paths(root: Path) -> tuple[Path, ...]:
    paths: set[Path] = set()
    for relative_root in PRODUCTION_ROOTS:
        candidate = root / relative_root
        if candidate.is_dir():
            for path in candidate.rglob("*"):
                if path.is_file() and path.suffix.casefold() in SOURCE_SUFFIXES:
                    paths.add(path)
    return tuple(sorted(paths, key=lambda item: item.as_posix().casefold()))


def _production_source_snapshot(root: Path) -> tuple[tuple[Path, bytes], ...]:
    paths = _production_source_paths(root)
    raw_snapshot = tuple((path, path.read_bytes()) for path in paths)
    if _production_source_paths(root) != paths:
        raise RuntimeError("production source set changed while inventory was captured")
    for path, data in raw_snapshot:
        if path.read_bytes() != data:
            raise RuntimeError(
                f"production source changed while inventory was captured: {path.name}"
            )
    return tuple(
        (path, _normalize_source_bytes(path, data)) for path, data in raw_snapshot
    )


def _normalize_source_bytes(path: Path, data: bytes) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"production source is not UTF-8: {path.name}") from exc
    if text.startswith("\ufeff"):
        raise RuntimeError(f"production source must not use a UTF-8 BOM: {path.name}")
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def _load_module_facts(
    root: Path,
    snapshot: tuple[tuple[Path, bytes], ...] | None = None,
) -> dict[str, _ModuleFacts]:
    result: dict[str, _ModuleFacts] = {}
    for path, data in snapshot or _production_source_snapshot(root):
        if path.suffix.casefold() != ".py":
            continue
        relative = path.relative_to(root).as_posix()
        facts = _module_facts_from_text(
            data.decode("utf-8"),
            file=relative,
            source_sha256=hashlib.sha256(data).hexdigest(),
        )
        result[facts.module] = facts
    return result


def _module_facts_from_text(
    source: str,
    *,
    file: str,
    source_sha256: str | None = None,
) -> _ModuleFacts:
    tree = ast.parse(source, filename=file)
    module_name = _module_name(file)
    imports = _collect_imports(tree, module_name)
    parents = _parents(tree)
    functions: dict[str, _FunctionFact] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        qualname = _qualname(node, parents)
        canonical = f"{module_name}.{qualname}"
        functions[canonical] = _FunctionFact(
            canonical=canonical,
            file=file,
            node=node,
            root_ids=_root_ids(node, file),
        )
    return _ModuleFacts(
        file=file,
        module=module_name,
        source_sha256=source_sha256 or hashlib.sha256(source.encode("utf-8")).hexdigest(),
        tree=tree,
        parents=parents,
        imports=imports,
        functions=functions,
    )


def _scan_module(
    module: _ModuleFacts,
    *,
    audited_indexed_hits: Counter[tuple[str, str, str]] | None = None,
) -> list[_RawEntry]:
    visitor = _SinkVisitor(module, audited_indexed_hits=audited_indexed_hits)
    visitor.visit(module.tree)
    return visitor.entries


class _SinkVisitor(ast.NodeVisitor):
    def __init__(
        self,
        module: _ModuleFacts,
        *,
        audited_indexed_hits: Counter[tuple[str, str, str]] | None = None,
    ) -> None:
        self.module = module
        self.entries: list[_RawEntry] = []
        self.scope_stack: list[str] = ["<module>"]
        self.alias_stack: list[dict[str, str]] = [dict(module.imports)]
        self.constant_stack: list[dict[str, str | None]] = [{}]
        self.global_stack: list[set[str]] = [set()]
        self.ordinal: Counter[tuple[str, str, str]] = Counter()
        self.audited_indexed_hits = audited_indexed_hits

    @property
    def aliases(self) -> dict[str, str]:
        merged: dict[str, str] = {}
        for scope in self.alias_stack:
            merged.update(scope)
        return merged

    @property
    def function(self) -> str:
        return self.scope_stack[-1]

    @property
    def constants(self) -> dict[str, str]:
        merged: dict[str, str] = {}
        for scope in self.constant_stack:
            for name, value in scope.items():
                if value is None:
                    merged.pop(name, None)
                else:
                    merged[name] = value
        return merged

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        return self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        return self._visit_function(node)

    def visit_Lambda(self, node: ast.Lambda) -> Any:
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        argument_nodes = (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        )
        argument_names = {argument.arg for argument in argument_nodes}
        if node.args.vararg is not None:
            argument_names.add(node.args.vararg.arg)
        if node.args.kwarg is not None:
            argument_names.add(node.args.kwarg.arg)
        self.alias_stack.append({name: name for name in argument_names})
        self.constant_stack.append({name: None for name in argument_names})
        self.global_stack.append(set())
        self.visit(node.body)
        self.global_stack.pop()
        self.constant_stack.pop()
        self.alias_stack.pop()

    def visit_ListComp(self, node: ast.ListComp) -> Any:
        self._visit_comprehension(node.generators, (node.elt,))

    def visit_SetComp(self, node: ast.SetComp) -> Any:
        self._visit_comprehension(node.generators, (node.elt,))

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> Any:
        self._visit_comprehension(node.generators, (node.elt,))

    def visit_DictComp(self, node: ast.DictComp) -> Any:
        self._visit_comprehension(node.generators, (node.key, node.value))

    def _visit_comprehension(
        self,
        generators: list[ast.comprehension],
        outputs: tuple[ast.AST, ...],
    ) -> None:
        self.alias_stack.append({})
        self.constant_stack.append({})
        self.global_stack.append(set())
        try:
            for generator in generators:
                self.visit(generator.iter)
                self._invalidate_target(generator.target)
                for condition in generator.ifs:
                    self.visit(condition)
            for output in outputs:
                self.visit(output)
        finally:
            self.global_stack.pop()
            self.constant_stack.pop()
            self.alias_stack.pop()

    def _visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        qualname = _qualname(node, self.module.parents)
        canonical = f"{self.module.module}.{qualname}"
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        if node.returns is not None:
            self.visit(node.returns)
        argument_nodes = (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        )
        for argument in argument_nodes:
            if argument.annotation is not None:
                self.visit(argument.annotation)
        if node.args.vararg is not None and node.args.vararg.annotation is not None:
            self.visit(node.args.vararg.annotation)
        if node.args.kwarg is not None and node.args.kwarg.annotation is not None:
            self.visit(node.args.kwarg.annotation)
        argument_names = {argument.arg for argument in argument_nodes}
        if node.args.vararg is not None:
            argument_names.add(node.args.vararg.arg)
        if node.args.kwarg is not None:
            argument_names.add(node.args.kwarg.arg)
        self.scope_stack.append(canonical)
        self.alias_stack.append({name: name for name in argument_names})
        self.constant_stack.append({name: None for name in argument_names})
        self.global_stack.append(set())
        for statement in node.body:
            self.visit(statement)
        self.global_stack.pop()
        self.constant_stack.pop()
        self.alias_stack.pop()
        self.scope_stack.pop()

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            bound_name = alias.asname or alias.name.split(".", 1)[0]
            self._invalidate_names({bound_name})
            self._set_alias(bound_name, alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if any(alias.name == "*" for alias in node.names):
            self._emit(
                node,
                WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
                "star-import",
                ResolutionConfidence.DYNAMIC,
                "star import prevents fail-closed capability resolution",
            )
            return
        base = _resolve_import_module(self.module.module, node.module, node.level)
        for alias in node.names:
            bound_name = alias.asname or alias.name
            self._invalidate_names({bound_name})
            self._set_alias(bound_name, f"{base}.{alias.name}")

    def visit_Global(self, node: ast.Global) -> Any:
        self.global_stack[-1].update(node.names)
        for name in node.names:
            if len(self.constant_stack) > 1:
                self.constant_stack[-1].pop(name, None)
                self.alias_stack[-1].pop(name, None)
            self.constant_stack[0][name] = None
            self.alias_stack[0][name] = "<ambiguous>"

    def visit_Nonlocal(self, node: ast.Nonlocal) -> Any:
        for name in node.names:
            for constants in self.constant_stack[:-1]:
                constants[name] = None
            for aliases in self.alias_stack[:-1]:
                aliases[name] = "<ambiguous>"

    def visit_Assign(self, node: ast.Assign) -> Any:
        value_name, _ = _resolve_callee(node.value, self.aliases)
        constant = _constant_text_with_aliases(node.value, self.constants)
        for target in node.targets:
            self._invalidate_target(target)
            self._record_alias(target, value_name)
            if isinstance(target, ast.Name):
                self._set_constant(target.id, constant)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            value_name, _ = _resolve_callee(node.value, self.aliases)
            self._invalidate_target(node.target)
            self._record_alias(node.target, value_name)
            constant = _constant_text_with_aliases(node.value, self.constants)
            if isinstance(node.target, ast.Name):
                self._set_constant(node.target.id, constant)
            self.visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> Any:
        self._invalidate_target(node.target)
        self.visit(node.value)

    def visit_If(self, node: ast.If) -> Any:
        self._visit_control_flow(node)

    def visit_For(self, node: ast.For) -> Any:
        self._visit_control_flow(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self._visit_control_flow(node)

    def visit_While(self, node: ast.While) -> Any:
        self._visit_control_flow(node)

    def visit_Try(self, node: ast.Try) -> Any:
        self._visit_control_flow(node)

    def visit_TryStar(self, node: ast.TryStar) -> Any:
        self._visit_control_flow(node)

    def visit_Match(self, node: ast.Match) -> Any:
        self._visit_control_flow(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self.visit(node.value)
        value_name, _ = _resolve_callee(node.value, self.aliases)
        constant = _constant_text_with_aliases(node.value, self.constants)
        self._invalidate_target(node.target)
        self._record_alias(node.target, value_name)
        if isinstance(node.target, ast.Name):
            self._set_constant(node.target.id, constant)

    def _visit_control_flow(self, node: ast.AST) -> None:
        branches: list[tuple[tuple[ast.AST, ...], list[ast.stmt]]] = []
        if isinstance(node, ast.If):
            self.visit(node.test)
            branches = [((), node.body), ((), node.orelse)]
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self.visit(node.iter)
            branches = [((), node.body), ((), node.orelse)]
        elif isinstance(node, ast.While):
            self.visit(node.test)
            branches = [((), node.body), ((), node.orelse)]
        elif isinstance(node, (ast.Try, ast.TryStar)):
            branches = [((), node.body), ((), node.orelse), ((), node.finalbody)]
            branches.extend(
                (
                    ((handler.type,) if handler.type is not None else ()),
                    handler.body,
                )
                for handler in node.handlers
            )
        elif isinstance(node, ast.Match):
            self.visit(node.subject)
            branches = [
                (
                    (case.pattern, case.guard)
                    if case.guard is not None
                    else (case.pattern,),
                    case.body,
                )
                for case in node.cases
            ]
        assigned = _assigned_names(node)
        if isinstance(node, ast.Match):
            for case in node.cases:
                assigned.update(_pattern_bound_names(case.pattern))
        if isinstance(node, (ast.Try, ast.TryStar)):
            assigned.update(
                handler.name
                for handler in node.handlers
                if isinstance(handler.name, str)
            )
        self._invalidate_names(assigned)
        base_aliases = dict(self.alias_stack[-1])
        base_constants = dict(self.constant_stack[-1])
        for prelude, statements in branches:
            self.alias_stack[-1] = dict(base_aliases)
            self.constant_stack[-1] = dict(base_constants)
            for item in prelude:
                self.visit(item)
            for statement in statements:
                self.visit(statement)
        self.alias_stack[-1] = base_aliases
        self.constant_stack[-1] = base_constants
        self._invalidate_names(assigned)

    def _invalidate_names(self, names: set[str]) -> None:
        for name in names:
            index = self._binding_scope_index(name)
            self.constant_stack[index][name] = None
            self.alias_stack[index][name] = "<ambiguous>"

    def _binding_scope_index(self, name: str) -> int:
        if name in self.global_stack[-1]:
            return 0
        return len(self.alias_stack) - 1

    def _set_constant(self, name: str, value: str | None) -> None:
        self.constant_stack[self._binding_scope_index(name)][name] = value

    def _set_alias(self, name: str, value: str) -> None:
        self.alias_stack[self._binding_scope_index(name)][name] = value

    def _invalidate_target(self, target: ast.expr) -> None:
        if isinstance(target, ast.Name):
            self._invalidate_names({target.id})
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._invalidate_target(element)

    def visit_With(self, node: ast.With) -> Any:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                value_name, _ = _resolve_callee(item.context_expr, self.aliases)
                self._invalidate_target(item.optional_vars)
                self._record_alias(item.optional_vars, value_name)
        for statement in node.body:
            self.visit(statement)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> Any:
        self.visit_With(node)

    def _record_alias(self, target: ast.expr, value_name: str) -> None:
        if not value_name:
            return
        if isinstance(target, ast.Name):
            self._set_alias(target.id, value_name)
        elif isinstance(target, ast.Attribute):
            target_name, _ = _resolve_callee(target, self.aliases)
            self.alias_stack[-1][target_name] = value_name

    def visit_Call(self, node: ast.Call) -> Any:
        callee, resolution = _resolve_callee(node.func, self.aliases)
        callsite = _indexed_callsite_key(
            node,
            file=self.module.file,
            function=self.function,
        )
        classification = _classify_call(
            node,
            callee,
            self.constants,
            file=self.module.file,
            function=self.function,
            allow_audited_indexed=self.audited_indexed_hits is not None,
        )
        if (
            classification is None
            and callsite in _AUDITED_INDEXED_CALLS
            and self.audited_indexed_hits is not None
        ):
            self.audited_indexed_hits[callsite] += 1
        if classification is not None:
            kind, detail, forced_resolution = classification
            self._emit(
                node,
                kind,
                callee,
                forced_resolution or resolution,
                detail,
            )
        self.generic_visit(node)

    def _emit(
        self,
        node: ast.AST,
        kind: WritePrimitiveKind,
        callee: str,
        resolution: ResolutionConfidence,
        detail: str,
    ) -> None:
        fingerprint = hashlib.sha256(
            ast.dump(node, include_attributes=False).encode("utf-8")
        ).hexdigest()
        self.entries.append(
            _RawEntry(
                file=self.module.file,
                source_sha256=self.module.source_sha256,
                line=getattr(node, "lineno", 0),
                column=getattr(node, "col_offset", 0),
                end_line=getattr(node, "end_lineno", getattr(node, "lineno", 0)),
                end_column=getattr(node, "end_col_offset", 0),
                function=self.function,
                kind=kind,
                callee=callee,
                resolution=resolution,
                statement_fingerprint=fingerprint,
                detail=detail,
            )
        )


def _indexed_callsite_key(
    node: ast.Call,
    *,
    file: str,
    function: str,
) -> tuple[str, str, str]:
    fingerprint = hashlib.sha256(
        ast.dump(node, include_attributes=False).encode("utf-8")
    ).hexdigest()
    return file, function, fingerprint


def _classify_call(
    node: ast.Call,
    callee: str,
    constants: dict[str, str] | None = None,
    *,
    file: str = "synthetic.py",
    function: str = "<module>",
    allow_audited_indexed: bool = False,
) -> tuple[WritePrimitiveKind, str, ResolutionConfidence | None] | None:
    canonical = callee.casefold()
    leaf = canonical.rsplit(".", 1)[-1]
    source_leaf = callee.rsplit(".", 1)[-1]
    if canonical in {
        "eval",
        "exec",
        "__import__",
        "builtins.eval",
        "builtins.exec",
        "importlib.import_module",
        "importlib.util.module_from_spec",
        "globals",
        "locals",
    }:
        return (
            WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
            "dynamic execution or import can hide a write capability",
            ResolutionConfidence.DYNAMIC,
        )
    if canonical in {
        "functools.partial",
        "functools.partialmethod",
        "operator.attrgetter",
        "operator.methodcaller",
    }:
        return (
            WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
            "callable wrapper can hide a write or external-execution capability",
            ResolutionConfidence.DYNAMIC,
        )
    if leaf == "mkdir" or canonical in {"os.mkdir", "os.makedirs"}:
        return WritePrimitiveKind.FILESYSTEM_DIRECTORY_CREATE, "directory creation", None
    if canonical in {"print", "builtins.print"}:
        file_targets = tuple(
            _resolve_callee(keyword.value, {})[0]
            for keyword in node.keywords
            if keyword.arg == "file"
        )
        if file_targets and not all(
            target in {"sys.stdout", "sys.stderr"} for target in file_targets
        ):
            return (
                WritePrimitiveKind.FILESYSTEM_FILE_WRITE,
                "print with an explicit file target",
                ResolutionConfidence.CONSERVATIVE,
            )
    if leaf in {"write_text", "write_bytes", "writelines", "truncate", "touch"}:
        return WritePrimitiveKind.FILESYSTEM_FILE_WRITE, "file content mutation", None
    if leaf == "write":
        if _looks_like_archive_receiver(canonical):
            return WritePrimitiveKind.ARCHIVE_WRITE, "archive member write", None
        return (
            WritePrimitiveKind.FILESYSTEM_FILE_WRITE,
            "stream or file descriptor write",
            ResolutionConfidence.CONSERVATIVE,
        )
    if canonical in {"os.write", "os.pwrite", "os.ftruncate"}:
        return WritePrimitiveKind.FILESYSTEM_FILE_WRITE, "low-level descriptor mutation", None
    if canonical == "os.open":
        if _os_open_may_write(node):
            return WritePrimitiveKind.FILESYSTEM_FILE_WRITE, "low-level open may write", None
        return None
    if leaf == "open" and _looks_like_archive_receiver(canonical):
        if _archive_member_open_may_write(node):
            return WritePrimitiveKind.ARCHIVE_WRITE, "archive member opened for writing", None
        return None
    if leaf == "open" and _is_file_open_symbol(canonical):
        if _open_call_may_write(node, canonical):
            return WritePrimitiveKind.FILESYSTEM_FILE_WRITE, "file open in write-capable mode", None
        return None
    if leaf == "save":
        return (
            WritePrimitiveKind.FILESYSTEM_FILE_WRITE,
            "serializer/image save writes a target",
            ResolutionConfidence.CONSERVATIVE,
        )
    if canonical in {
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.copyfileobj",
        "shutil.copytree",
        "pathlib.path.copy",
    }:
        return WritePrimitiveKind.FILESYSTEM_COPY, "filesystem copy", None
    if leaf == "rename" or (
        leaf == "replace"
        and len(node.args) == 1
        and canonical not in {"dataclasses.replace", "str.replace"}
    ) or canonical in {
        "os.rename",
        "os.replace",
        "shutil.move",
    }:
        if canonical in {"dataclasses.replace", "str.replace"}:
            return None
        return (
            WritePrimitiveKind.FILESYSTEM_MOVE_OR_REPLACE,
            "filesystem move or replacement",
            ResolutionConfidence.CONSERVATIVE,
        )
    if leaf in {"unlink", "rmdir"} or canonical in {
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.removedirs",
        "shutil.rmtree",
    }:
        return WritePrimitiveKind.FILESYSTEM_DELETE, "filesystem deletion", None
    if leaf in {"symlink_to", "hardlink_to", "link_to"} or canonical in {
        "os.symlink",
        "os.link",
    }:
        return WritePrimitiveKind.FILESYSTEM_LINK, "link creation", None
    if leaf in {"chmod", "chown", "lchmod"} or canonical in {
        "os.chmod",
        "os.chown",
        "os.lchmod",
        "os.utime",
    }:
        return WritePrimitiveKind.FILESYSTEM_METADATA, "filesystem metadata mutation", None
    if canonical.startswith("tempfile.") and leaf in {
        "mkstemp",
        "mkdtemp",
        "namedtemporaryfile",
        "temporaryfile",
        "temporarydirectory",
        "spooledtemporaryfile",
    }:
        return WritePrimitiveKind.TEMPORARY_RESOURCE, "temporary filesystem resource", None
    if canonical in {"shutil.make_archive"} or leaf == "writestr" or (
        leaf == "add" and _looks_like_archive_receiver(canonical)
    ):
        return WritePrimitiveKind.ARCHIVE_WRITE, "archive creation or member add", None
    if canonical in {"shutil.unpack_archive"} or leaf in {"extract", "extractall"}:
        return WritePrimitiveKind.ARCHIVE_EXTRACT, "archive extraction writes files", None
    if canonical in {"zipfile.zipfile", "tarfile.open"} and _archive_open_may_write(node, canonical):
        return WritePrimitiveKind.ARCHIVE_WRITE, "archive opened in write-capable mode", None
    if canonical == "sqlite3.connect":
        return WritePrimitiveKind.SQLITE_RAW_CONNECT, "SQLite connection may create database/sidecars", None
    if leaf == "connect_database":
        return WritePrimitiveKind.DATABASE_GATEWAY, "legacy database gateway", None
    if leaf == "initialize_database":
        return WritePrimitiveKind.DATABASE_IMPLICIT_INITIALIZER, "implicit schema/directory initialization", None
    if leaf in {"execute", "executemany", "executescript"}:
        sql = (
            _constant_text_with_aliases(node.args[0], constants or {})
            if node.args
            else None
        )
        if sql is None:
            return (
                WritePrimitiveKind.SQLITE_DYNAMIC_SQL,
                "dynamic SQL is fail-closed because its effect cannot be proven",
                ResolutionConfidence.DYNAMIC,
            )
        effect, verbs = _sql_effect(sql)
        if effect == "READ":
            return None
        if effect == "DYNAMIC":
            return (
                WritePrimitiveKind.SQLITE_DYNAMIC_SQL,
                "SQL effect cannot be proven read-only",
                ResolutionConfidence.DYNAMIC,
            )
        if effect == "TRANSACTION":
            return WritePrimitiveKind.SQLITE_TRANSACTION, ",".join(verbs), None
        return WritePrimitiveKind.SQLITE_MUTATION, ",".join(verbs), None
    if leaf in {"commit", "rollback"} and _looks_like_database_receiver(canonical):
        return WritePrimitiveKind.SQLITE_TRANSACTION, f"transaction {leaf}", None
    if leaf in {"backup", "deserialize", "load_extension", "enable_load_extension"} and _looks_like_database_receiver(canonical):
        return WritePrimitiveKind.SQLITE_BACKUP_OR_EXTENSION, f"SQLite {leaf}", None
    if canonical in {
        "subprocess.run",
        "subprocess.popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "os.system",
        "os.popen",
        "os.startfile",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "multiprocessing.process",
        "multiprocessing.pool",
        "concurrent.futures.processpoolexecutor",
    } or canonical.startswith(("os.spawn", "os.exec")) or (
        canonical.startswith("multiprocessing.")
        and leaf in {"process", "pool"}
    ) or (
        "processpoolexecutor" in canonical
        and leaf in {"processpoolexecutor", "submit", "map"}
    ) or (
        leaf == "start"
        and any(token in canonical for token in ("multiprocessing", "process()"))
    ):
        return WritePrimitiveKind.EXTERNAL_PROCESS, "external process invocation", None
    if source_leaf != "Request" and (
        canonical in {
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.request",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "socket.create_connection",
        }
        or leaf in {"urlopen", "urlretrieve"}
        or (
        any(token in canonical for token in ("requests", "httpx", "urllib", "socket"))
        and leaf in {
            "request",
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "head",
            "options",
            "connect",
            "create_connection",
        }
        )
        or (
            source_leaf in {"request", "connect", "listen", "send", "sendall"}
            and canonical not in {"sqlite3.connect"}
        )
    ):
        return WritePrimitiveKind.NETWORK_REQUEST, "network request", None
    if canonical == "app.run" or (
        leaf in {"run", "serve", "listen"}
        and any(keyword.arg in {"host", "port"} for keyword in node.keywords)
    ):
        return WritePrimitiveKind.NETWORK_REQUEST, "network listener startup", None
    if canonical.startswith("winreg.") and leaf in {
        "createkey",
        "createkeyex",
        "setvalue",
        "setvalueex",
        "deletekey",
        "deletevalue",
    }:
        return WritePrimitiveKind.SYSTEM_STATE, "Windows registry mutation", None
    if callee.startswith("<indexed>."):
        if leaf == "start":
            return (
                WritePrimitiveKind.EXTERNAL_PROCESS,
                "unresolved indexed receiver start may launch a process or thread",
                ResolutionConfidence.CONSERVATIVE,
            )
        callsite = _indexed_callsite_key(node, file=file, function=function)
        if allow_audited_indexed and callsite in _AUDITED_INDEXED_CALLS:
            return None
        return (
            WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
            "unresolved method on an indexed receiver",
            ResolutionConfidence.DYNAMIC,
        )
    if (
        callee in {"<ambiguous>", "<dynamic>", "<indexed>"}
        or callee.startswith("<dynamic>.")
    ):
        return (
            WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
            "unresolved dynamic call",
            ResolutionConfidence.DYNAMIC,
        )
    return None


def _scan_sql_files(
    root: Path,
    snapshot: tuple[tuple[Path, bytes], ...] | None = None,
) -> list[_RawEntry]:
    result: list[_RawEntry] = []
    for path, data in snapshot or _production_source_snapshot(root):
        if path.suffix.casefold() != ".sql":
            continue
        relative = path.relative_to(root).as_posix()
        source = data.decode("utf-8")
        source_hash = hashlib.sha256(data).hexdigest()
        for ordinal, match in enumerate(_SQL_PREFIX.finditer(_SQL_COMMENTS.sub("", source)), start=1):
            verb = match.group(1).upper()
            if verb not in _SQL_MUTATION and verb not in _SQL_TRANSACTION:
                continue
            line = source.count("\n", 0, match.start()) + 1
            fingerprint = hashlib.sha256(
                f"{verb}:{ordinal}:{match.start()}".encode("ascii")
            ).hexdigest()
            result.append(
                _RawEntry(
                    file=relative,
                    source_sha256=source_hash,
                    line=line,
                    column=0,
                    end_line=line,
                    end_column=len(verb),
                    function="<sql-script>",
                    kind=(
                        WritePrimitiveKind.SQLITE_TRANSACTION
                        if verb in _SQL_TRANSACTION
                        else WritePrimitiveKind.SQLITE_SCHEMA_MUTATION
                    ),
                    callee=f"SQL:{verb}",
                    resolution=ResolutionConfidence.EXACT,
                    statement_fingerprint=fingerprint,
                    detail=f"schema statement {verb}",
                )
            )
    return result


def _enrich_entries(
    raw_entries: Iterable[_RawEntry],
    graph: dict[str, set[str]],
    roots: dict[str, tuple[str, ...]],
) -> list[WriteEntry]:
    reverse: dict[str, set[str]] = defaultdict(set)
    for caller, callees in graph.items():
        for callee in callees:
            reverse[callee].add(caller)
    result: list[WriteEntry] = []
    ordinal: Counter[tuple[str, str, str, str]] = Counter()
    for raw in raw_entries:
        key = (raw.file, raw.function, raw.kind.value, raw.statement_fingerprint)
        ordinal[key] += 1
        stable_payload = {
            "file": raw.file,
            "function": raw.function,
            "kind": raw.kind.value,
            "callee": raw.callee,
            "fingerprint": raw.statement_fingerprint,
            "ordinal": ordinal[key],
        }
        entry_id = "WE-" + _canonical_sha256(stable_payload)[:24].upper()
        root_ids, chain = _reachable_roots(raw.function, reverse, roots)
        owner = _owner_for(raw.file)
        target = _target_namespace(raw)
        control = _required_control(raw.kind)
        status = _migration_status(raw)
        input_source = _input_source(raw, root_ids)
        risk = _risk_level(raw.kind)
        result.append(
            WriteEntry(
                entry_id=entry_id,
                file=raw.file,
                source_sha256=raw.source_sha256,
                line=raw.line,
                column=raw.column,
                end_line=raw.end_line,
                end_column=raw.end_column,
                function=raw.function,
                kind=raw.kind,
                callee=raw.callee,
                resolution=raw.resolution,
                statement_fingerprint=raw.statement_fingerprint,
                owner=owner,
                target_namespace=target,
                required_control=control,
                migration_status=status,
                input_source=input_source,
                risk=risk,
                root_ids=root_ids,
                call_chain=chain,
                detail=raw.detail,
            )
        )
    return result


def _build_call_graph(
    modules: dict[str, _ModuleFacts],
) -> tuple[dict[str, set[str]], dict[str, tuple[str, ...]]]:
    known = {name for module in modules.values() for name in module.functions}
    graph: dict[str, set[str]] = defaultdict(set)
    roots: dict[str, tuple[str, ...]] = {}
    for module in modules.values():
        for function in module.functions.values():
            roots[function.canonical] = function.root_ids
            local_aliases = dict(module.imports)
            for _ in range(8):
                changed = False
                for assignment in ast.walk(function.node):
                    if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                        continue
                    if isinstance(assignment, ast.Assign):
                        targets = assignment.targets
                        value = assignment.value
                    elif assignment.value is not None:
                        targets = [assignment.target]
                        value = assignment.value
                    else:
                        continue
                    resolved, _ = _resolve_callee(value, local_aliases)
                    for target in targets:
                        if isinstance(target, ast.Name) and local_aliases.get(target.id) != resolved:
                            local_aliases[target.id] = resolved
                            changed = True
                if not changed:
                    break
            class_prefix = function.canonical.rsplit(".", 1)[0]
            for node in ast.walk(function.node):
                if isinstance(node, ast.Call):
                    callee, _ = _resolve_callee(node.func, local_aliases)
                    candidates = {callee}
                    if callee.startswith("self."):
                        candidates.add(f"{class_prefix}.{callee[5:]}")
                    if not callee.startswith("app.") and "." not in callee:
                        candidates.add(f"{module.module}.{callee}")
                    for candidate in candidates:
                        if candidate in known:
                            graph[function.canonical].add(candidate)
    return graph, roots


def _reachable_roots(
    function: str,
    reverse: dict[str, set[str]],
    roots: dict[str, tuple[str, ...]],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if function == "<module>" or function == "<sql-script>":
        return ("MODULE-LOAD",), (function,)
    queue: deque[tuple[str, tuple[str, ...]]] = deque([(function, (function,))])
    visited = {function}
    found: list[tuple[str, tuple[str, ...]]] = []
    while queue and len(visited) <= 5000:
        current, path = queue.popleft()
        for root_id in roots.get(current, ()):
            found.append((root_id, tuple(reversed(path))))
        for parent in sorted(reverse.get(current, ())):
            if parent not in visited:
                visited.add(parent)
                queue.append((parent, path + (parent,)))
    if not found:
        return ("INTERNAL-DIRECT",), (function,)
    found.sort(key=lambda item: (len(item[1]), item[0], item[1]))
    root_ids = tuple(sorted({item[0] for item in found}))
    return root_ids, found[0][1]


def _root_ids(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    file: str,
) -> tuple[str, ...]:
    roots: list[str] = []
    if file == "app/cli.py" and node.name == "main":
        roots.append("CLI:MAIN")
    if file == "app/__main__.py" and node.name == "main":
        roots.append("MODULE:APP")
    if file == "app/web.py" and node.name == "create_app":
        roots.append("FACTORY:CREATE_APP")
    if file.startswith("scripts/") and node.name == "main":
        roots.append(f"SCRIPT:{file}")
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        leaf = _raw_callee_name(decorator.func).rsplit(".", 1)[-1].upper()
        if leaf not in {"GET", "POST", "PUT", "PATCH", "DELETE", "ROUTE"}:
            continue
        route = _constant_text(decorator.args[0]) if decorator.args else "<dynamic>"
        methods: list[str] = [leaf]
        if leaf == "ROUTE":
            methods = ["ROUTE"]
            for keyword in decorator.keywords:
                if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                    methods = [
                        str(item.value).upper()
                        for item in keyword.value.elts
                        if isinstance(item, ast.Constant)
                    ] or methods
        roots.extend(f"WEB:{method} {route}" for method in methods)
    return tuple(sorted(set(roots)))


def _collect_imports(tree: ast.Module, module_name: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                result[alias.asname or alias.name.split(".", 1)[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_import_module(module_name, node.module, node.level)
            for alias in node.names:
                if alias.name != "*":
                    result[alias.asname or alias.name] = f"{base}.{alias.name}"
    return result


def _resolve_import_module(current: str, module: str | None, level: int) -> str:
    if level <= 0:
        return module or ""
    parts = current.split(".")[:-1]
    keep = max(0, len(parts) - (level - 1))
    base = parts[:keep]
    if module:
        base.extend(module.split("."))
    return ".".join(base)


def _resolve_callee(
    node: ast.AST,
    aliases: dict[str, str],
) -> tuple[str, ResolutionConfidence]:
    if isinstance(node, ast.Name):
        resolved = aliases.get(node.id, node.id)
        return (
            resolved,
            ResolutionConfidence.ALIAS_RESOLVED
            if resolved != node.id
            else ResolutionConfidence.EXACT,
        )
    if isinstance(node, ast.Attribute):
        prefix, confidence = _resolve_callee(node.value, aliases)
        direct = f"{prefix}.{node.attr}" if prefix else node.attr
        resolved = aliases.get(direct, direct)
        return (
            resolved,
            ResolutionConfidence.ALIAS_RESOLVED
            if resolved != direct or confidence is ResolutionConfidence.ALIAS_RESOLVED
            else confidence,
        )
    if isinstance(node, ast.Call):
        callee, confidence = _resolve_callee(node.func, aliases)
        if callee.rsplit(".", 1)[-1] == "getattr" and len(node.args) >= 2:
            attr = _constant_text(node.args[1])
            if attr is not None:
                base, _ = _resolve_callee(node.args[0], aliases)
                return f"{base}.{attr}", ResolutionConfidence.ALIAS_RESOLVED
            return "<dynamic>", ResolutionConfidence.DYNAMIC
        return f"{callee}()", confidence
    if isinstance(node, ast.Subscript):
        return "<indexed>", ResolutionConfidence.DYNAMIC
    if isinstance(
        node,
        (
            ast.Constant,
            ast.JoinedStr,
            ast.List,
            ast.Tuple,
            ast.Set,
            ast.Dict,
            ast.BinOp,
            ast.UnaryOp,
            ast.BoolOp,
            ast.Compare,
            ast.IfExp,
            ast.ListComp,
            ast.SetComp,
            ast.DictComp,
            ast.GeneratorExp,
        ),
    ):
        return "<value>", ResolutionConfidence.DYNAMIC
    return "<dynamic>", ResolutionConfidence.DYNAMIC


def _raw_callee_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _raw_callee_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return "<dynamic>"


def _module_name(file: str) -> str:
    path = Path(file)
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or "synthetic"


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    result: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            result[child] = parent
    return result


def _assigned_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for candidate in ast.walk(node):
        if isinstance(candidate, ast.Name) and isinstance(candidate.ctx, ast.Store):
            names.add(candidate.id)
    return names


def _pattern_bound_names(pattern: ast.pattern) -> set[str]:
    names: set[str] = set()
    if isinstance(pattern, ast.MatchAs):
        if pattern.name is not None:
            names.add(pattern.name)
        if pattern.pattern is not None:
            names.update(_pattern_bound_names(pattern.pattern))
    elif isinstance(pattern, ast.MatchStar):
        if pattern.name is not None:
            names.add(pattern.name)
    elif isinstance(pattern, ast.MatchMapping):
        if pattern.rest is not None:
            names.add(pattern.rest)
        for child in pattern.patterns:
            names.update(_pattern_bound_names(child))
    elif isinstance(pattern, ast.MatchClass):
        for child in (*pattern.patterns, *pattern.kwd_patterns):
            names.update(_pattern_bound_names(child))
    elif isinstance(pattern, (ast.MatchSequence, ast.MatchOr)):
        for child in pattern.patterns:
            names.update(_pattern_bound_names(child))
    return names


def _enclosing_function_qualname(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> str:
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return _qualname(current, parents)
    return "<module>"


def _qualname(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    names: list[str] = [getattr(node, "name", "<anonymous>")]
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, ast.ClassDef):
            names.append(current.name)
        elif isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.append(current.name)
    return ".".join(reversed(names))


def _constant_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        if all(isinstance(value, ast.Constant) for value in node.values):
            return "".join(str(value.value) for value in node.values if isinstance(value, ast.Constant))
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_text(node.left)
        right = _constant_text(node.right)
        return left + right if left is not None and right is not None else None
    return None


def _constant_text_with_aliases(
    node: ast.AST,
    constants: dict[str, str],
) -> str | None:
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_text_with_aliases(node.left, constants)
        right = _constant_text_with_aliases(node.right, constants)
        return left + right if left is not None and right is not None else None
    return _constant_text(node)


def _open_call_may_write(node: ast.Call, callee: str) -> bool:
    mode_index = 1 if callee in {"open", "builtins.open", "io.open"} else 0
    mode_node: ast.AST | None = node.args[mode_index] if len(node.args) > mode_index else None
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode_node = keyword.value
    if mode_node is None:
        return False
    mode = _constant_text(mode_node)
    return True if mode is None else any(flag in mode for flag in "wax+")


def _os_open_may_write(node: ast.Call) -> bool:
    if len(node.args) < 2:
        return True
    flags = node.args[1]
    if isinstance(flags, ast.Constant) and isinstance(flags.value, int):
        return flags.value != 0
    text = ast.dump(flags, include_attributes=False).upper()
    write_markers = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "O_EXCL")
    if any(marker in text for marker in write_markers):
        return True
    return "O_RDONLY" not in text


def _archive_open_may_write(node: ast.Call, callee: str) -> bool:
    mode_index = 1 if callee == "zipfile.zipfile" else 1
    mode_node: ast.AST | None = node.args[mode_index] if len(node.args) > mode_index else None
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode_node = keyword.value
    if mode_node is None:
        return False
    mode = _constant_text(mode_node)
    return True if mode is None else any(flag in mode for flag in "wax")


def _archive_member_open_may_write(node: ast.Call) -> bool:
    mode_node: ast.AST | None = node.args[1] if len(node.args) > 1 else None
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode_node = keyword.value
    if mode_node is None:
        return False
    mode = _constant_text(mode_node)
    return True if mode is None else any(flag in mode for flag in "wax+")


def _is_file_open_symbol(callee: str) -> bool:
    return callee in {"open", "builtins.open", "io.open", "path.open", "pathlib.path.open"} or (
        callee.endswith(".open")
        and not any(
            token in callee
            for token in (
                "fitz.",
                "pymupdf.",
                "urllib.",
                "webbrowser.",
                "tarfile.",
                "zipfile.",
                "archive",
            )
        )
    )


def _looks_like_archive_receiver(callee: str) -> bool:
    receiver = callee.rsplit(".", 1)[0]
    receiver_leaf = receiver.rsplit(".", 1)[-1]
    return any(token in callee for token in ("zip", "tar", "archive")) or receiver_leaf in {
        "zf",
        "tf",
    }


def _looks_like_path_receiver(callee: str) -> bool:
    receiver = callee.rsplit(".", 1)[0]
    leaf = receiver.rsplit(".", 1)[-1]
    return receiver.startswith(("pathlib.path", "path()")) or leaf.endswith(
        (
            "path",
            "file",
            "target",
            "source",
            "output",
            "candidate",
            "partial",
            "staging",
            "temp",
            "tmp",
        )
    )


def _looks_like_database_receiver(callee: str) -> bool:
    receiver = callee.rsplit(".", 1)[0]
    return any(token in receiver for token in ("conn", "connection", "cursor", "sqlite", ".db", "database"))


def _looks_like_sql_call(node: ast.Call, callee: str) -> bool:
    return callee.rsplit(".", 1)[-1] in {
        "execute",
        "executemany",
        "executescript",
    }


def _sql_effect(sql: str) -> tuple[str, tuple[str, ...]]:
    verbs = _sql_statement_verbs(sql)
    if not verbs:
        return "DYNAMIC", ()
    known = _SQL_MUTATION | _SQL_TRANSACTION | {"SELECT", "EXPLAIN"}
    if any(verb not in known for verb in verbs):
        return "DYNAMIC", verbs
    if any(verb in _SQL_MUTATION for verb in verbs):
        return "MUTATION", verbs
    if any(verb in _SQL_TRANSACTION for verb in verbs):
        return "TRANSACTION", verbs
    return "READ", verbs


def _sql_statement_verbs(sql: str) -> tuple[str, ...]:
    cleaned = _strip_sql_literals_and_comments(sql)
    verbs: list[str] = []
    for statement in cleaned.split(";"):
        tokens = re.findall(r"[A-Za-z_]+|[()]", statement)
        if not tokens:
            continue
        upper = [token.upper() for token in tokens]
        index = 0
        if upper[index] == "EXPLAIN":
            index += 1
            if index + 1 < len(upper) and upper[index : index + 2] == ["QUERY", "PLAN"]:
                index += 2
        if index >= len(upper):
            continue
        if upper[index] != "WITH":
            verbs.append(upper[index])
            continue
        index += 1
        if index < len(upper) and upper[index] == "RECURSIVE":
            index += 1
        depth = 0
        main_verb: str | None = None
        while index < len(upper):
            token = upper[index]
            if token == "(":
                depth += 1
            elif token == ")":
                depth = max(0, depth - 1)
            elif depth == 0 and token in {
                "SELECT",
                "INSERT",
                "UPDATE",
                "DELETE",
                "REPLACE",
            }:
                main_verb = token
                break
            index += 1
        verbs.append(main_verb or "WITH")
    return tuple(verbs)


def _strip_sql_literals_and_comments(sql: str) -> str:
    output: list[str] = []
    index = 0
    quote: str | None = None
    while index < len(sql):
        char = sql[index]
        next_char = sql[index + 1] if index + 1 < len(sql) else ""
        if quote is not None:
            if quote == "]":
                if char == "]":
                    quote = None
                output.append(" ")
                index += 1
                continue
            if char == quote:
                if next_char == quote:
                    output.extend((" ", " "))
                    index += 2
                    continue
                quote = None
            output.append(" ")
            index += 1
            continue
        if char == "-" and next_char == "-":
            while index < len(sql) and sql[index] not in "\r\n":
                output.append(" ")
                index += 1
            continue
        if char == "/" and next_char == "*":
            output.extend((" ", " "))
            index += 2
            while index < len(sql):
                if sql[index] == "*" and index + 1 < len(sql) and sql[index + 1] == "/":
                    output.extend((" ", " "))
                    index += 2
                    break
                output.append(" ")
                index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            output.append(" ")
            index += 1
            continue
        if char == "[":
            quote = "]"
            output.append(" ")
            index += 1
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _owner_for(file: str) -> str:
    name = Path(file).name
    if file.startswith("scripts/"):
        return "TEST_INFRASTRUCTURE"
    if file.startswith("app/safety/") or name == "workspace_guard.py":
        return "SAFETY_SERVICE"
    if name in {"database.py", "search_index.py"}:
        return "DATABASE_SERVICE"
    if any(token in name for token in ("import", "question_split", "question_assets", "pdf_scan")):
        return "IMPORT_SERVICE"
    if any(token in name for token in ("export", "render")):
        return "EXPORT_SERVICE"
    if "report" in name or name.startswith("stage"):
        return "REPORT_SERVICE"
    if name == "web.py":
        return "WEB_ADAPTER"
    if name == "cli.py":
        return "CLI_ADAPTER"
    if name == "health.py":
        return "HEALTH_SERVICE"
    return "APPLICATION_SERVICE"


def _target_namespace(raw: _RawEntry) -> str:
    if _migration_status(raw) is MigrationStatus.ACCEPTED_MEMORY_ONLY:
        return "MEMORY_ONLY"
    if raw.file.startswith("scripts/"):
        return "TEST_LAB_RUNTIME"
    if raw.kind in {
        WritePrimitiveKind.SQLITE_RAW_CONNECT,
        WritePrimitiveKind.DATABASE_GATEWAY,
        WritePrimitiveKind.DATABASE_IMPLICIT_INITIALIZER,
        WritePrimitiveKind.SQLITE_MUTATION,
        WritePrimitiveKind.SQLITE_DYNAMIC_SQL,
        WritePrimitiveKind.SQLITE_TRANSACTION,
        WritePrimitiveKind.SQLITE_BACKUP_OR_EXTENSION,
        WritePrimitiveKind.SQLITE_SCHEMA_MUTATION,
    }:
        return "LEGACY_CALLER_CONTROLLED_DATABASE_PATH"
    if raw.kind is WritePrimitiveKind.NETWORK_REQUEST:
        return "NETWORK_DEFAULT_DENY"
    if raw.kind is WritePrimitiveKind.EXTERNAL_PROCESS:
        return "PROCESS_DEFAULT_DENY"
    if raw.kind is WritePrimitiveKind.SYSTEM_STATE:
        return "SYSTEM_STATE_DEFAULT_DENY"
    if raw.kind is WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY:
        return "UNRESOLVED_DYNAMIC_TARGET"
    return "LEGACY_CALLER_CONTROLLED_FILESYSTEM"


def _required_control(kind: WritePrimitiveKind) -> str:
    if kind in {
        WritePrimitiveKind.SQLITE_RAW_CONNECT,
        WritePrimitiveKind.DATABASE_GATEWAY,
        WritePrimitiveKind.DATABASE_IMPLICIT_INITIALIZER,
        WritePrimitiveKind.SQLITE_MUTATION,
        WritePrimitiveKind.SQLITE_DYNAMIC_SQL,
        WritePrimitiveKind.SQLITE_TRANSACTION,
        WritePrimitiveKind.SQLITE_BACKUP_OR_EXTENSION,
        WritePrimitiveKind.SQLITE_SCHEMA_MUTATION,
    }:
        return "S3_DATABASE_LEASE_AND_TRANSACTION_GATE"
    if kind is WritePrimitiveKind.NETWORK_REQUEST:
        return "S3_NETWORK_DEFAULT_DENY_LOOPBACK_ALLOWLIST"
    if kind is WritePrimitiveKind.EXTERNAL_PROCESS:
        return "S3_CONTROLLED_PROCESS_WRAPPER"
    if kind in {WritePrimitiveKind.ARCHIVE_WRITE, WritePrimitiveKind.ARCHIVE_EXTRACT}:
        return "S3_ARCHIVE_MANIFEST_AND_ZIP_SLIP_GATE"
    if kind in {WritePrimitiveKind.FILESYSTEM_DELETE, WritePrimitiveKind.FILESYSTEM_MOVE_OR_REPLACE}:
        return "S3_PAIRED_QUARANTINE_OR_ATOMIC_PUBLISH_WRITER"
    if kind is WritePrimitiveKind.FILESYSTEM_LINK:
        return "PERMANENT_LINK_CREATION_DENY"
    if kind is WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY:
        return "P0_RESOLVE_OR_REMOVE_DYNAMIC_CAPABILITY"
    if kind is WritePrimitiveKind.SYSTEM_STATE:
        return "D3_USER_DECISION_SYSTEM_MUTATION"
    return "S3_HANDLE_LEVEL_WORKSPACE_WRITER"


def _migration_status(raw: _RawEntry) -> MigrationStatus:
    return MigrationStatus.UNMIGRATED_BLOCKED


def _input_source(raw: _RawEntry, roots: tuple[str, ...]) -> str:
    if any(root.startswith("WEB:") for root in roots):
        return "HTTP_REQUEST_OR_SERVICE_STATE"
    if any(root.startswith("CLI:") for root in roots):
        return "CLI_ARGUMENT_OR_CONFIG"
    if raw.kind in {
        WritePrimitiveKind.SQLITE_MUTATION,
        WritePrimitiveKind.SQLITE_DYNAMIC_SQL,
        WritePrimitiveKind.SQLITE_TRANSACTION,
    }:
        return "DATABASE_CONNECTION_AND_CALLER_DATA"
    if raw.function == "<module>" or raw.function == "<sql-script>":
        return "STATIC_SOURCE_DECLARATION"
    return "CALLER_ARGUMENT_OR_INTERNAL_DERIVATION"


def _risk_level(kind: WritePrimitiveKind) -> RiskLevel:
    if kind in {
        WritePrimitiveKind.FILESYSTEM_DELETE,
        WritePrimitiveKind.FILESYSTEM_MOVE_OR_REPLACE,
        WritePrimitiveKind.FILESYSTEM_LINK,
        WritePrimitiveKind.ARCHIVE_EXTRACT,
        WritePrimitiveKind.SQLITE_DYNAMIC_SQL,
        WritePrimitiveKind.SQLITE_BACKUP_OR_EXTENSION,
        WritePrimitiveKind.EXTERNAL_PROCESS,
        WritePrimitiveKind.NETWORK_REQUEST,
        WritePrimitiveKind.SYSTEM_STATE,
        WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY,
    }:
        return RiskLevel.P0
    return RiskLevel.P1


def _canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _pretty_json_bytes(payload: Any) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
