from __future__ import annotations

import copy
import hashlib
import html
import json
import math
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template_string,
    request,
    url_for,
)

from .database import connect_database_read_only
from .domain_models import create_domain_revision, validate_domain_revision
from .ir_contracts import validate_figure_ir
from .m1_pipeline import load_copy_payload
from .project_root import PROJECT_ROOT
from .safety.context import validate_safe_id
from .safety.workspace_io import WorkspaceIOError, get_workspace_io


M3_PIPELINE_VERSION = "M3-FIGURE-SEARCH-TEMPLATE-V2"
M3_FIXED_TIMESTAMP = "2026-07-25T00:00:00Z"
M3_TAXONOMY_RELEASE_ID = "TAXONOMY-M3-MATH-V1"
M3_INDEX_ID = "INDEX-M3-YANYAN-REV-002"
M3_TEMPLATE_BASE_ID = "TEMPLATE-M3-B5-REV-001"
M3_TEMPLATE_PASS_ID = "TEMPLATE-M3-B5-REV-002"
M3_TEMPLATE_FAIL_ID = "TEMPLATE-M3-B5-REV-003"
M3_VECTOR_MODEL = "LOCAL-HASHED-TFIDF-ZH-V1"
M3_VECTOR_DIMENSION = 256
M3_VECTOR_MODEL_VERSION = "1.0"
M3_MAX_JSON_BYTES = 16 * 1024 * 1024
M3_MAX_SVG_BYTES = 2 * 1024 * 1024
M3_MAX_SVG_NODES = 10_000
SVG_NAMESPACE = "http://www.w3.org/2000/svg"


class M3PipelineError(RuntimeError):
    pass


class M3InjectedFailure(M3PipelineError):
    pass


@dataclass(frozen=True, slots=True)
class M3PipelineConfig:
    job_id: str = "JOB-M3-YANYAN-REV-002-20260725"
    state_id: str = "STATE-M3-YANYAN-REV-002"
    pipeline_id: str = "M3"
    m1_state_id: str = "STATE-M1-YANYAN-REV-002"
    m1_paper_object_id: str = "PAPER-YANYAN-202605"
    m1_paper_revision: str = "REV-002"

    def __post_init__(self) -> None:
        for field_name in (
            "job_id",
            "state_id",
            "pipeline_id",
            "m1_state_id",
            "m1_paper_object_id",
            "m1_paper_revision",
        ):
            validate_safe_id(str(getattr(self, field_name)), field_name=field_name)

    @property
    def job_root(self) -> Path:
        return PROJECT_ROOT / "tmp" / "jobs" / "INTERNAL" / self.job_id

    @property
    def staging_root(self) -> Path:
        return self.job_root / "state-release"

    @property
    def target_root(self) -> Path:
        return (
            PROJECT_ROOT
            / "data"
            / "derived"
            / self.pipeline_id
            / self.state_id
        )

    @property
    def m1_database_path(self) -> Path:
        return (
            PROJECT_ROOT
            / "data"
            / "db"
            / "versions"
            / self.m1_state_id
            / "question_bank.sqlite3"
        )

    @property
    def m1_derived_root(self) -> Path:
        return (
            PROJECT_ROOT
            / "data"
            / "derived"
            / "papers"
            / "M1-REAL-PIPELINE"
            / self.m1_paper_object_id
            / self.m1_paper_revision
        )


@dataclass(slots=True)
class M3WorkbenchState:
    figures: dict[str, dict[str, Any]]
    taxonomy: dict[str, Any]
    assertions: dict[str, dict[str, Any]]
    documents: dict[str, dict[str, Any]]
    semantic_index: dict[str, Any]
    templates: dict[str, dict[str, Any]]
    active_template_revision_id: str
    history: list[dict[str, Any]] = field(default_factory=list)
    basket: list[str] = field(default_factory=list)
    solution_overrides: dict[str, str] = field(default_factory=dict)


def _canonical_json_bytes(value: Any, *, pretty: bool = False) -> bytes:
    options: dict[str, Any] = {
        "ensure_ascii": False,
        "allow_nan": False,
        "sort_keys": True,
    }
    if pretty:
        options["indent"] = 2
        return (json.dumps(value, **options) + "\n").encode("utf-8")
    options["separators"] = (",", ":")
    return json.dumps(value, **options).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError as exc:
        raise M3PipelineError("M3 path escaped the project root") from exc


def _read_json(path: Path, *, maximum_bytes: int = M3_MAX_JSON_BYTES) -> Any:
    try:
        payload = get_workspace_io().read_bytes(
            path,
            maximum_bytes=maximum_bytes,
        )
    except WorkspaceIOError as exc:
        raise M3PipelineError("M3 JSON artifact is missing or unreadable") from exc
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise M3PipelineError("M3 JSON artifact is invalid") from exc


def _write_bytes(path: Path, payload: bytes) -> dict[str, Any]:
    receipt = get_workspace_io().create_new_bytes(path, payload)
    return {
        "bytes": receipt.bytes_written,
        "relative_path": receipt.relative_path,
        "sha256": receipt.sha256,
    }


def _write_json(path: Path, value: Any) -> dict[str, Any]:
    return _write_bytes(path, _canonical_json_bytes(value, pretty=True))


def _question_revision_id(question_no: int) -> str:
    return f"QUESTION-YANYAN-{question_no:03d}-REV-002"


def _solution_revision_id(question_no: int) -> str:
    return f"SOLUTION-YANYAN-{question_no:03d}-REV-002"


def load_search_documents(
    config: M3PipelineConfig = M3PipelineConfig(),
) -> dict[str, dict[str, Any]]:
    if not config.m1_database_path.is_file():
        raise M3PipelineError("accepted M1 database is missing")
    documents: dict[str, dict[str, Any]] = {}
    with connect_database_read_only(
        config.m1_database_path,
        immutable=True,
    ) as connection:
        rows = connection.execute(
            """
            SELECT qid, question_no, question_type, year, review_status,
                   stem_text, answer_text, analysis_latex, difficulty,
                   content_hash, raw_crop_path, meta_json
              FROM questions
             ORDER BY CAST(question_no AS INTEGER)
            """
        ).fetchall()
    for row in rows:
        meta = json.loads(str(row["meta_json"]))
        question_no = int(row["question_no"])
        points = int(meta["score_points"])
        analysis_text = str(row["analysis_latex"] or "")
        analysis_sha256 = _sha256(analysis_text.encode("utf-8"))
        qid = str(row["qid"])
        documents[qid] = {
            "qid": qid,
            "question_no": question_no,
            "question_revision_id": _question_revision_id(question_no),
            "solution_revision_id": _solution_revision_id(question_no),
            "question_ir_revision_id": str(meta["question_ir_revision_id"]),
            "question_type": str(row["question_type"]),
            "year": int(row["year"]),
            "points": points,
            "design_difficulty": int(row["difficulty"]),
            "review_status": str(row["review_status"]),
            "stem_text": str(row["stem_text"]),
            "answer_text": str(row["answer_text"] or ""),
            "analysis_sha256": analysis_sha256,
            "content_hash": str(row["content_hash"]),
            "source_crop_relative_path": str(row["raw_crop_path"]),
            "source_page": int(meta["source_page"]),
            "paper_revision_id": str(meta["paper_revision_id"]),
            "pii_classification": "none",
        }
    if len(documents) != 19 or any(
        item["review_status"] != "approved" for item in documents.values()
    ):
        raise M3PipelineError("M3 requires the accepted 19-question M1 pool")
    return documents


def _taxonomy_terms() -> list[dict[str, Any]]:
    return [
        {
            "concept_id": "KNOW-SET-REAL-NUMBERS",
            "kind": "knowledge",
            "label": "集合与实数",
            "aliases": ["集合运算", "实数集"],
            "parent_id": None,
            "status": "active",
            "requires_solution_evidence": False,
        },
        {
            "concept_id": "KNOW-STAT-HISTOGRAM",
            "kind": "knowledge",
            "label": "频率分布直方图",
            "aliases": ["直方图", "频率分布"],
            "parent_id": None,
            "status": "active",
            "requires_solution_evidence": False,
        },
        {
            "concept_id": "KNOW-COMPLEX-NUMBERS",
            "kind": "knowledge",
            "label": "复数",
            "aliases": ["复数条件"],
            "parent_id": None,
            "status": "active",
            "requires_solution_evidence": False,
        },
        {
            "concept_id": "KNOW-CONIC-SECTION",
            "kind": "knowledge",
            "label": "圆锥曲线",
            "aliases": ["椭圆", "抛物线", "双曲线"],
            "parent_id": None,
            "status": "active",
            "requires_solution_evidence": False,
        },
        {
            "concept_id": "KNOW-VECTOR",
            "kind": "knowledge",
            "label": "平面向量",
            "aliases": ["向量夹角", "向量旋转"],
            "parent_id": None,
            "status": "active",
            "requires_solution_evidence": False,
        },
        {
            "concept_id": "KNOW-FUNCTION",
            "kind": "knowledge",
            "label": "函数",
            "aliases": ["函数图像", "函数性质"],
            "parent_id": None,
            "status": "active",
            "requires_solution_evidence": False,
        },
        {
            "concept_id": "KNOW-SEQUENCE",
            "kind": "knowledge",
            "label": "数列",
            "aliases": ["等差数列", "等比数列"],
            "parent_id": None,
            "status": "active",
            "requires_solution_evidence": False,
        },
        {
            "concept_id": "KNOW-SPATIAL-GEOMETRY",
            "kind": "knowledge",
            "label": "立体几何",
            "aliases": ["空间几何", "二面角", "空间投影"],
            "parent_id": None,
            "status": "active",
            "requires_solution_evidence": False,
        },
        {
            "concept_id": "KNOW-PROBABILITY",
            "kind": "knowledge",
            "label": "概率与统计",
            "aliases": ["概率", "独立性", "条件概率"],
            "parent_id": None,
            "status": "active",
            "requires_solution_evidence": False,
        },
        {
            "concept_id": "KNOW-TRIGONOMETRY",
            "kind": "knowledge",
            "label": "三角函数与解三角形",
            "aliases": ["三角函数", "解三角形"],
            "parent_id": None,
            "status": "active",
            "requires_solution_evidence": False,
        },
        {
            "concept_id": "METHOD-COORDINATE",
            "kind": "method",
            "label": "建系与坐标法",
            "aliases": ["建系", "坐标法", "解析法"],
            "parent_id": None,
            "status": "active",
            "requires_solution_evidence": True,
        },
        {
            "concept_id": "METHOD-COUNTEREXAMPLE",
            "kind": "method",
            "label": "反例法",
            "aliases": ["举反例", "反例"],
            "parent_id": None,
            "status": "active",
            "requires_solution_evidence": True,
        },
        {
            "concept_id": "METHOD-EXTREMUM-SHIFT",
            "kind": "method",
            "label": "极值点偏移",
            "aliases": ["极值点偏移", "极值点移动"],
            "parent_id": "KNOW-FUNCTION",
            "status": "active",
            "requires_solution_evidence": True,
        },
        {
            "concept_id": "METHOD-ENDPOINT-EFFECT",
            "kind": "method",
            "label": "端点效应",
            "aliases": ["端点效应", "边界取等"],
            "parent_id": "KNOW-FUNCTION",
            "status": "active",
            "requires_solution_evidence": True,
        },
        {
            "concept_id": "METHOD-CAVALIERI",
            "kind": "method",
            "label": "祖暅原理",
            "aliases": ["祖暅原理", "等高截面积"],
            "parent_id": "KNOW-SPATIAL-GEOMETRY",
            "status": "active",
            "requires_solution_evidence": True,
        },
        {
            "concept_id": "METHOD-OLD-ANALYTIC",
            "kind": "method",
            "label": "解析几何旧称",
            "aliases": [],
            "parent_id": None,
            "status": "deprecated",
            "replacement_id": "METHOD-COORDINATE",
            "requires_solution_evidence": False,
        },
    ]


def build_taxonomy_release() -> dict[str, Any]:
    terms = _taxonomy_terms()
    ids = [str(item["concept_id"]) for item in terms]
    if len(ids) != len(set(ids)):
        raise M3PipelineError("taxonomy concept ids must be unique")
    known = set(ids)
    aliases: dict[str, str] = {}
    for term in terms:
        concept_id = str(term["concept_id"])
        parent = term.get("parent_id")
        replacement = term.get("replacement_id")
        if parent is not None and parent not in known:
            raise M3PipelineError("taxonomy parent is unknown")
        if replacement is not None and replacement not in known:
            raise M3PipelineError("taxonomy replacement is unknown")
        for alias in [str(term["label"]), *map(str, term["aliases"])]:
            normalized = _normalize_text(alias)
            previous = aliases.get(normalized)
            if previous is not None and previous != concept_id:
                raise M3PipelineError("taxonomy alias is ambiguous")
            aliases[normalized] = concept_id
    terms_sha256 = _sha256(_canonical_json_bytes(terms))
    release = {
        "schema_version": "1.0",
        "taxonomy_id": "TAXONOMY-M3-MATH",
        "taxonomy_release_id": M3_TAXONOMY_RELEASE_ID,
        "release_version": "1.0.0",
        "terms": terms,
        "terms_sha256": terms_sha256,
        "aliases": dict(sorted(aliases.items())),
        "migration_from": {
            "TAXONOMY-M2-STRUCTURAL-V1": {
                "METHOD-OLD-ANALYTIC": "METHOD-COORDINATE"
            }
        },
        "created_at": M3_FIXED_TIMESTAMP,
        "status": "approved",
    }
    domain = create_domain_revision(
        object_type="taxonomy_release",
        object_id="TAXONOMY-M3-MATH",
        revision_id=M3_TAXONOMY_RELEASE_ID,
        revision_no=1,
        state="approved",
        created_at=M3_FIXED_TIMESTAMP,
        predecessor_revision_id=None,
        payload={
            "taxonomy_id": "TAXONOMY-M3-MATH",
            "release_version": "1.0.0",
            "terms_sha256": terms_sha256,
            "extensions": {},
        },
    ).document
    validate_domain_revision(domain)
    release["domain_revision"] = domain
    return release


def resolve_taxonomy_term(taxonomy: dict[str, Any], value: str) -> str | None:
    terms = {
        str(item["concept_id"]): item for item in taxonomy["terms"]
    }
    raw = str(value)
    aliases: dict[str, str] = taxonomy["aliases"]
    normalized = _normalize_text(raw)
    concept_id = (
        raw
        if raw in terms
        else aliases[normalized]
        if normalized in aliases
        else None
    )
    if concept_id is None or concept_id not in terms:
        return None
    term = terms[concept_id]
    if term["status"] == "deprecated":
        return str(term["replacement_id"])
    return str(concept_id)


def _assertion_bindings() -> list[tuple[int, str, str]]:
    return [
        (1, "KNOW-SET-REAL-NUMBERS", "题干直接涉及集合与有理数集的交集。"),
        (2, "KNOW-STAT-HISTOGRAM", "题干直接涉及频率分布直方图。"),
        (3, "KNOW-COMPLEX-NUMBERS", "题干直接涉及复数实部与虚部条件。"),
        (4, "KNOW-CONIC-SECTION", "题干直接涉及椭圆焦点与离心率。"),
        (5, "KNOW-VECTOR", "题干直接涉及向量夹角。"),
        (6, "KNOW-TRIGONOMETRY", "题干直接涉及正弦函数与切线。"),
        (7, "KNOW-SEQUENCE", "题干直接涉及等比与等差数列。"),
        (8, "KNOW-SPATIAL-GEOMETRY", "题干直接涉及空间投影。"),
        (8, "METHOD-COORDINATE", "解析建立空间直角坐标系并验证投影角。"),
        (9, "KNOW-FUNCTION", "题干直接涉及函数图像的轴对称与中心对称。"),
        (9, "METHOD-COUNTEREXAMPLE", "解析使用具体函数构造反例排除选项。"),
        (11, "KNOW-FUNCTION", "题干涉及函数极值点和零点。"),
        (12, "KNOW-PROBABILITY", "题干涉及随机事件与概率关系。"),
        (13, "KNOW-CONIC-SECTION", "题干涉及动圆圆心轨迹。"),
        (14, "KNOW-SEQUENCE", "题干涉及等差数列项与前n项和。"),
        (15, "KNOW-CONIC-SECTION", "题干涉及抛物线与点列。"),
        (16, "KNOW-FUNCTION", "题干涉及导函数与极值点。"),
        (16, "METHOD-EXTREMUM-SHIFT", "解析比较两个极值点及其函数值关系。"),
        (17, "KNOW-TRIGONOMETRY", "题干涉及三角形与三角恒等关系。"),
        (17, "METHOD-ENDPOINT-EFFECT", "解析最值讨论包含取值边界。"),
        (18, "KNOW-PROBABILITY", "题干涉及抽样与事件独立性。"),
        (19, "KNOW-SPATIAL-GEOMETRY", "题干涉及圆锥、截面与二面角。"),
        (19, "METHOD-COORDINATE", "解析建立空间直角坐标系。"),
        (19, "METHOD-CAVALIERI", "解析明确使用祖暅原理求体积。"),
    ]


def build_tag_assertion_candidates(
    documents: dict[str, dict[str, Any]],
    taxonomy: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    term_map = {
        str(term["concept_id"]): term for term in taxonomy["terms"]
    }
    by_no = {int(item["question_no"]): item for item in documents.values()}
    assertions: dict[str, dict[str, Any]] = {}
    for sequence, (question_no, concept_id, summary) in enumerate(
        _assertion_bindings(),
        start=1,
    ):
        question = by_no[question_no]
        term = term_map[concept_id]
        assertion_id = f"TAG-M3-{sequence:03d}"
        evidence = [
            {
                "solution_revision_id": question["solution_revision_id"],
                "evidence_step": "ANALYSIS-REVIEWED",
                "evidence_sha256": question["analysis_sha256"],
                "summary": summary,
            }
        ]
        assertion = {
            "assertion_id": assertion_id,
            "question_revision_id": question["question_revision_id"],
            "qid": question["qid"],
            "taxonomy_release_id": taxonomy["taxonomy_release_id"],
            "concept_id": concept_id,
            "concept_kind": term["kind"],
            "concept_label": term["label"],
            "source": "rule-assisted",
            "status": "candidate",
            "solution_revision_id": question["solution_revision_id"],
            "solution_sha256": question["analysis_sha256"],
            "evidence": evidence,
            "review": None,
            "created_at": M3_FIXED_TIMESTAMP,
        }
        assertions[assertion_id] = assertion
    invalid_id = "TAG-M3-INVALID-NO-EVIDENCE"
    question = by_no[16]
    assertions[invalid_id] = {
        "assertion_id": invalid_id,
        "question_revision_id": question["question_revision_id"],
        "qid": question["qid"],
        "taxonomy_release_id": taxonomy["taxonomy_release_id"],
        "concept_id": "METHOD-EXTREMUM-SHIFT",
        "concept_kind": "method",
        "concept_label": "极值点偏移",
        "source": "machine-suggestion",
        "status": "candidate",
        "solution_revision_id": question["solution_revision_id"],
        "solution_sha256": question["analysis_sha256"],
        "evidence": [],
        "review": None,
        "created_at": M3_FIXED_TIMESTAMP,
    }
    return assertions


def review_tag_assertion(
    state: M3WorkbenchState,
    assertion_id: str,
    *,
    decision: str,
    actor_ref: str = "CODEX-LOCAL-OPERATOR",
    reason: str,
) -> dict[str, Any]:
    validate_safe_id(actor_ref, field_name="actor_ref")
    assertion = state.assertions.get(assertion_id)
    if assertion is None:
        raise M3PipelineError("tag assertion is unknown")
    if assertion["status"] not in {"candidate", "approved"}:
        raise M3PipelineError("tag assertion is not reviewable")
    if decision not in {"approve", "reject"}:
        raise M3PipelineError("tag decision is invalid")
    term = next(
        item
        for item in state.taxonomy["terms"]
        if item["concept_id"] == assertion["concept_id"]
    )
    if decision == "approve" and (
        not assertion["evidence"]
        or (
            term["requires_solution_evidence"]
            and not assertion["solution_revision_id"]
        )
    ):
        raise M3PipelineError(
            "solution-dependent tag requires concrete reviewed evidence"
        )
    status = "approved" if decision == "approve" else "rejected"
    assertion["status"] = status
    assertion["review"] = {
        "actor_ref": actor_ref,
        "reviewed_at": M3_FIXED_TIMESTAMP,
        "decision": decision,
        "reason": str(reason),
        "evidence_checked": bool(assertion["evidence"]),
    }
    domain = create_domain_revision(
        object_type="tag_assertion",
        object_id=assertion_id,
        revision_id=f"{assertion_id}-REV-001",
        revision_no=1,
        state="approved" if status == "approved" else "rejected",
        created_at=M3_FIXED_TIMESTAMP,
        predecessor_revision_id=None,
        payload={
            "question_revision_id": assertion["question_revision_id"],
            "taxonomy_release_id": assertion["taxonomy_release_id"],
            "tag_id": assertion["concept_id"],
            "evidence_revision_ids": [
                item["solution_revision_id"] for item in assertion["evidence"]
            ],
            "review_status": status,
            "extensions": {
                "x-review-actor": actor_ref,
                "x-review-reason": str(reason),
            },
        },
    ).document
    validate_domain_revision(domain)
    assertion["domain_revision"] = domain
    state.history.append(
        {
            "action": "tag_review",
            "assertion_id": assertion_id,
            "decision": decision,
            "status": status,
        }
    )
    return copy.deepcopy(assertion)


def mark_solution_changed(
    state: M3WorkbenchState,
    solution_revision_id: str,
    new_solution_sha256: str,
) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", new_solution_sha256):
        raise M3PipelineError("new solution digest is invalid")
    affected: list[str] = []
    for assertion in state.assertions.values():
        if (
            assertion["solution_revision_id"] == solution_revision_id
            and assertion["status"] == "approved"
            and assertion["solution_sha256"] != new_solution_sha256
        ):
            assertion["status"] = "stale"
            assertion["stale_reason"] = "BOUND_SOLUTION_REVISION_CHANGED"
            affected.append(str(assertion["assertion_id"]))
    stale_documents: list[str] = []
    for record in state.semantic_index["documents"]:
        if record["solution_revision_id"] == solution_revision_id:
            record["status"] = "stale"
            record["stale_reason"] = "SOLUTION_REVISION_CHANGED"
            stale_documents.append(str(record["qid"]))
    state.solution_overrides[solution_revision_id] = new_solution_sha256
    event = {
        "action": "solution_changed",
        "solution_revision_id": solution_revision_id,
        "stale_assertion_ids": sorted(affected),
        "stale_embedding_qids": sorted(stale_documents),
    }
    state.history.append(event)
    return event


_PII_PATTERNS = (
    re.compile(r"\b1[3-9]\d{9}\b"),
    re.compile(r"\b\d{17}[\dXx]\b"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"),
    re.compile(r"(?:QQ|微信|手机号|身份证)\s*[:：]?\s*\d{5,}"),
)


def _contains_pii(text: str) -> bool:
    return any(pattern.search(text) is not None for pattern in _PII_PATTERNS)


def _normalize_text(value: str) -> str:
    return re.sub(r"\s+", "", str(value).lower())


def _feature_tokens(text: str) -> list[str]:
    normalized = _normalize_text(text)
    tokens: list[str] = []
    latin = re.findall(r"[a-z0-9]+", normalized)
    tokens.extend(f"w:{item}" for item in latin)
    han = "".join(re.findall(r"[\u3400-\u9fff]", normalized))
    tokens.extend(f"c:{character}" for character in han)
    tokens.extend(
        f"b:{han[index:index + 2]}" for index in range(max(0, len(han) - 1))
    )
    if not tokens and normalized:
        tokens.append(f"raw:{normalized}")
    return tokens


def _hashed_vector(text: str, *, dimension: int = M3_VECTOR_DIMENSION) -> list[float]:
    vector = [0.0] * dimension
    counts: dict[str, int] = {}
    for token in _feature_tokens(text):
        counts[token] = counts.get(token, 0) + 1
    for token, count in sorted(counts.items()):
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        index = int.from_bytes(digest[:4], "big") % dimension
        sign = 1.0 if digest[4] & 1 else -1.0
        vector[index] += sign * (1.0 + math.log(float(count)))
    norm = math.sqrt(sum(item * item for item in vector))
    if norm:
        vector = [round(item / norm, 8) for item in vector]
    return vector


def _cosine(left: list[float], right: list[float]) -> float:
    return float(sum(a * b for a, b in zip(left, right, strict=True)))


def _approved_terms_by_qid(
    assertions: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for assertion in assertions.values():
        if assertion["status"] != "approved":
            continue
        result.setdefault(str(assertion["qid"]), []).append(assertion)
    for rows in result.values():
        rows.sort(key=lambda item: str(item["assertion_id"]))
    return result


def build_semantic_index(
    documents: dict[str, dict[str, Any]],
    taxonomy: dict[str, Any],
    assertions: dict[str, dict[str, Any]],
    *,
    solution_overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    overrides = dict(solution_overrides or {})
    terms_by_id = {
        str(item["concept_id"]): item for item in taxonomy["terms"]
    }
    approved = _approved_terms_by_qid(assertions)
    records: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for qid, document in sorted(
        documents.items(),
        key=lambda pair: int(pair[1]["question_no"]),
    ):
        if (
            document["review_status"] != "approved"
            or document["pii_classification"] != "none"
        ):
            excluded.append({"qid": qid, "reason": "NOT_APPROVED_OR_PII"})
            continue
        tag_rows = approved.get(qid, [])
        labels: list[str] = []
        for assertion in tag_rows:
            term = terms_by_id[str(assertion["concept_id"])]
            labels.extend([str(term["label"]), *map(str, term["aliases"])])
        index_text = " ".join([str(document["stem_text"]), *labels])
        if _contains_pii(index_text):
            excluded.append({"qid": qid, "reason": "PII_PATTERN_DETECTED"})
            continue
        solution_sha = overrides.get(
            str(document["solution_revision_id"]),
            str(document["analysis_sha256"]),
        )
        input_contract = {
            "question_content_hash": document["content_hash"],
            "solution_sha256": solution_sha,
            "approved_assertion_ids": [
                str(item["assertion_id"]) for item in tag_rows
            ],
            "taxonomy_terms_sha256": taxonomy["terms_sha256"],
        }
        records.append(
            {
                "qid": qid,
                "question_revision_id": document["question_revision_id"],
                "solution_revision_id": document["solution_revision_id"],
                "source_page": document["source_page"],
                "content_contract_sha256": _sha256(
                    _canonical_json_bytes(input_contract)
                ),
                "approved_assertion_ids": input_contract[
                    "approved_assertion_ids"
                ],
                "vector": _hashed_vector(index_text),
                "status": "fresh",
            }
        )
    index_payload_sha256 = _sha256(_canonical_json_bytes(records))
    manifest = {
        "schema_version": "1.0",
        "index_id": M3_INDEX_ID,
        "model": M3_VECTOR_MODEL,
        "model_version": M3_VECTOR_MODEL_VERSION,
        "model_kind": "deterministic-local-hashed-feature-vector",
        "dimension": M3_VECTOR_DIMENSION,
        "normalization": "L2",
        "question_count": len(records),
        "excluded": excluded,
        "pii_source_count": sum(
            item["reason"] == "PII_PATTERN_DETECTED" for item in excluded
        ),
        "taxonomy_release_id": taxonomy["taxonomy_release_id"],
        "taxonomy_terms_sha256": taxonomy["terms_sha256"],
        "index_payload_sha256": index_payload_sha256,
        "fact_source": "STATE-M1-YANYAN-REV-002/question_bank.sqlite3",
        "fts_policy": "READ_ONLY_FTS5_STEM_TEXT_COLUMN_ONLY",
        "rebuild_command": (
            "python Task/tools/run_m3_real_pipeline.py --rebuild-index"
        ),
        "weights_required": False,
        "network_required": False,
        "created_at": M3_FIXED_TIMESTAMP,
    }
    return {"manifest": manifest, "documents": records}


def _fts_query_terms(value: str) -> list[str]:
    normalized = re.sub(r"[^\w\u3400-\u9fff]+", " ", str(value))
    return [
        token
        for token in normalized.split()
        if token and token not in {"找", "一道", "关于", "试题", "题目", "相似题"}
    ][:8]


def _fts_stem_hits(
    config: M3PipelineConfig,
    query: str,
) -> dict[str, dict[str, Any]]:
    terms = _fts_query_terms(query)
    if not terms:
        return {}
    quoted = [
        '"' + term.replace('"', '""') + '"' for term in terms
    ]
    expression = "stem_text : (" + " OR ".join(quoted) + ")"
    try:
        with connect_database_read_only(
            config.m1_database_path,
            immutable=True,
        ) as connection:
            rows = connection.execute(
                """
                SELECT q.qid,
                       bm25(question_fts, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0,
                            0.0, 0.0) AS rank,
                       snippet(question_fts, 5, '[', ']', '…', 24) AS snippet
                  FROM question_fts
                  JOIN questions AS q ON q.id = question_fts.rowid
                 WHERE question_fts MATCH ?
                """,
                (expression,),
            ).fetchall()
    except Exception as exc:
        raise M3PipelineError("read-only FTS5 stem search failed") from exc
    return {
        str(row["qid"]): {
            "rank": float(row["rank"]),
            "snippet": str(row["snippet"]),
            "terms": terms,
        }
        for row in rows
    }


def parse_natural_query(
    query: str,
    taxonomy: dict[str, Any],
) -> dict[str, Any]:
    text = str(query).strip()
    filters: dict[str, Any] = {}
    year = re.search(r"\b(20\d{2})\s*年?", text)
    if year:
        filters["year"] = int(year.group(1))
    points = re.search(r"\b(\d{1,3})\s*分", text)
    if points:
        filters["points"] = int(points.group(1))
    for alias, canonical in (
        ("单选", "单项选择题"),
        ("多选", "多项选择题"),
        ("填空", "填空题"),
        ("解答", "解答题"),
    ):
        if alias in text:
            filters["question_type"] = canonical
            break
    matched_terms: list[str] = []
    normalized = _normalize_text(text)
    aliases: dict[str, str] = taxonomy["aliases"]
    for alias in sorted(aliases):
        concept_id = aliases[alias]
        if len(alias) >= 2 and alias in normalized:
            resolved = resolve_taxonomy_term(taxonomy, concept_id)
            if resolved and resolved not in matched_terms:
                matched_terms.append(resolved)
    if matched_terms:
        filters["concept_ids"] = sorted(matched_terms)
    residual = re.sub(r"\b20\d{2}\s*年?", " ", text)
    residual = re.sub(r"\b\d{1,3}\s*分", " ", residual)
    residual = re.sub(
        r"(请|帮我|找|一道|一些|关于|相似题|题目|试题|单选|多选|填空|解答)",
        " ",
        residual,
    )
    return {
        "filters": filters,
        "residual_query": re.sub(r"\s+", " ", residual).strip(),
        "original_query": text,
    }


def hybrid_search(
    config: M3PipelineConfig,
    state: M3WorkbenchState,
    *,
    query: str = "",
    filters: dict[str, Any] | None = None,
    similar_to_qid: str | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    if type(limit) is not int or limit < 1 or limit > 50:
        raise M3PipelineError("search limit must be 1..50")
    natural = parse_natural_query(query, state.taxonomy)
    effective_filters = dict(natural["filters"])
    effective_filters.update(dict(filters or {}))
    concept_ids = [
        resolved
        for item in effective_filters.get("concept_ids", [])
        if (resolved := resolve_taxonomy_term(state.taxonomy, str(item)))
        is not None
    ]
    if effective_filters.get("concept_ids") and not concept_ids:
        return {
            "query": query,
            "filters": effective_filters,
            "results": [],
            "reason": "UNKNOWN_OR_UNAPPROVED_TAXONOMY_FILTER",
        }
    approved = _approved_terms_by_qid(state.assertions)
    index_rows = {
        str(item["qid"]): item for item in state.semantic_index["documents"]
    }
    fts_hits = _fts_stem_hits(
        config,
        natural["residual_query"] or query,
    )
    if similar_to_qid is not None:
        source = index_rows.get(similar_to_qid)
        if source is None or source["status"] != "fresh":
            raise M3PipelineError("similarity source is missing or stale")
        query_vector = list(source["vector"])
    else:
        expansion_labels: list[str] = []
        term_map = {
            str(item["concept_id"]): item
            for item in state.taxonomy["terms"]
        }
        for concept_id in concept_ids:
            term = term_map[concept_id]
            expansion_labels.extend(
                [str(term["label"]), *map(str, term["aliases"])]
            )
        query_vector = _hashed_vector(
            " ".join(
                [
                    natural["residual_query"] or query,
                    *expansion_labels,
                ]
            )
        )
    results: list[dict[str, Any]] = []
    for qid, document in state.documents.items():
        if document["review_status"] != "approved":
            continue
        if similar_to_qid == qid:
            continue
        if "year" in effective_filters and int(document["year"]) != int(
            effective_filters["year"]
        ):
            continue
        if "points" in effective_filters and int(document["points"]) != int(
            effective_filters["points"]
        ):
            continue
        if (
            "question_type" in effective_filters
            and document["question_type"] != effective_filters["question_type"]
        ):
            continue
        tag_rows = approved.get(qid, [])
        approved_concepts = {
            str(item["concept_id"]) for item in tag_rows
        }
        if concept_ids and not set(concept_ids).issubset(approved_concepts):
            continue
        index_row = index_rows.get(qid)
        if index_row is None or index_row["status"] != "fresh":
            continue
        semantic_score = _cosine(query_vector, list(index_row["vector"]))
        fts = fts_hits.get(qid)
        lexical_score = 0.0
        if fts is not None:
            lexical_score = min(1.0, max(0.05, -float(fts["rank"])))
        tag_score = 1.0 if concept_ids else 0.0
        structured_score = 0.0
        if effective_filters:
            structured_score = 1.0
        total = (
            0.50 * semantic_score
            + 0.25 * lexical_score
            + 0.15 * tag_score
            + 0.10 * structured_score
        )
        if (
            query
            and not effective_filters
            and fts is None
            and semantic_score <= 0
        ):
            continue
        reasons: list[str] = []
        if effective_filters:
            reasons.append("结构化条件匹配")
        if fts is not None:
            reasons.append(
                "题干全文命中：" + "、".join(fts["terms"])
            )
        if concept_ids:
            reasons.append(
                "已批准标签：" + "、".join(sorted(concept_ids))
            )
        reasons.append(f"本地向量相似度 {semantic_score:.4f}")
        results.append(
            {
                "qid": qid,
                "question_revision_id": document["question_revision_id"],
                "question_no": document["question_no"],
                "question_type": document["question_type"],
                "year": document["year"],
                "points": document["points"],
                "review_status": document["review_status"],
                "source_page": document["source_page"],
                "approved_concept_ids": sorted(approved_concepts),
                "semantic_score": round(semantic_score, 6),
                "lexical_score": round(lexical_score, 6),
                "score": round(total, 6),
                "snippet": (
                    fts["snippet"]
                    if fts is not None
                    else str(document["stem_text"])[:120]
                ),
                "match_reasons": reasons,
            }
        )
    results.sort(key=lambda item: (-float(item["score"]), int(item["question_no"])))
    return {
        "query": query,
        "similar_to_qid": similar_to_qid,
        "filters": effective_filters,
        "index_id": state.semantic_index["manifest"]["index_id"],
        "results": results[:limit],
        "result_count": min(limit, len(results)),
    }


_SVG_FORBIDDEN_TAGS = frozenset(
    {
        "a",
        "audio",
        "embed",
        "foreignObject",
        "iframe",
        "image",
        "link",
        "object",
        "script",
        "set",
        "use",
        "video",
    }
)
_SVG_ALLOWED_TAGS = frozenset(
    {
        "svg",
        "g",
        "defs",
        "style",
        "title",
        "desc",
        "metadata",
        "path",
        "line",
        "polyline",
        "polygon",
        "rect",
        "circle",
        "ellipse",
        "text",
        "tspan",
        "marker",
        "clipPath",
    }
)
_SAFE_TIKZ_COMMANDS = frozenset(
    {
        "begin",
        "end",
        "draw",
        "fill",
        "filldraw",
        "node",
        "coordinate",
        "clip",
    }
)


def _svg_local_name(value: str) -> str:
    return value.rsplit("}", 1)[-1]


def _colour_is_monochrome(value: str) -> bool:
    token = value.strip().lower()
    if token in {
        "",
        "none",
        "black",
        "white",
        "transparent",
        "currentcolor",
        "#000",
        "#fff",
        "#000000",
        "#ffffff",
    }:
        return True
    match = re.fullmatch(r"#([0-9a-f]{6})", token)
    if match:
        rgb = match.group(1)
        return rgb[0:2] == rgb[2:4] == rgb[4:6]
    match = re.fullmatch(
        r"rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})"
        r"(?:\s*,\s*(?:0(?:\.\d+)?|1(?:\.0+)?))?\s*\)",
        token,
    )
    return bool(match and match.group(1) == match.group(2) == match.group(3))


def validate_and_sanitize_svg(payload: bytes) -> dict[str, Any]:
    if not payload or len(payload) > M3_MAX_SVG_BYTES:
        raise M3PipelineError("SVG exceeds the bounded payload contract")
    try:
        source = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise M3PipelineError("SVG must be UTF-8") from exc
    lowered = source.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise M3PipelineError("SVG document declarations are forbidden")
    try:
        root = ET.fromstring(source)
    except ET.ParseError as exc:
        raise M3PipelineError("SVG XML is malformed") from exc
    if root.tag != f"{{{SVG_NAMESPACE}}}svg":
        raise M3PipelineError("SVG root namespace is not the contracted namespace")
    node_count = 0
    colour_values: list[str] = []
    for element in root.iter():
        node_count += 1
        if node_count > M3_MAX_SVG_NODES:
            raise M3PipelineError("SVG node limit was exceeded")
        local_name = _svg_local_name(element.tag)
        if (
            local_name in _SVG_FORBIDDEN_TAGS
            or local_name not in _SVG_ALLOWED_TAGS
        ):
            raise M3PipelineError(f"SVG element is forbidden: {local_name}")
        for raw_name, raw_value in element.attrib.items():
            name = _svg_local_name(raw_name).lower()
            value = str(raw_value)
            value_lower = value.strip().lower()
            if (
                name.startswith("on")
                or name in {"href", "src"}
                or raw_name.startswith("{http://www.w3.org/1999/xlink}")
            ):
                raise M3PipelineError("SVG active or linked attribute is forbidden")
            if (
                "javascript:" in value_lower
                or "data:" in value_lower
                or "http://" in value_lower
                or "https://" in value_lower
                or "@import" in value_lower
                or "expression(" in value_lower
            ):
                raise M3PipelineError("SVG external or active value is forbidden")
            for match in re.findall(r"url\(([^)]+)\)", value_lower):
                if not match.strip(" \"'").startswith("#"):
                    raise M3PipelineError("SVG may reference only local fragment ids")
            if name in {"fill", "stroke", "color"}:
                colour_values.append(value)
            if name == "style":
                colour_values.extend(
                    match.group(1)
                    for match in re.finditer(
                        r"(?:fill|stroke|color)\s*:\s*([^;}{]+)",
                        value,
                        flags=re.IGNORECASE,
                    )
                )
        if local_name == "style" and element.text:
            css = element.text
            css_lower = css.lower()
            if (
                "@import" in css_lower
                or "expression(" in css_lower
                or "javascript:" in css_lower
                or "http://" in css_lower
                or "https://" in css_lower
            ):
                raise M3PipelineError("SVG style contains an active reference")
            colour_values.extend(
                match.group(1)
                for match in re.finditer(
                    r"(?:fill|stroke|color)\s*:\s*([^;}{]+)",
                    css,
                    flags=re.IGNORECASE,
                )
            )
    non_monochrome = sorted(
        {
            value.strip()
            for value in colour_values
            if not _colour_is_monochrome(value)
        }
    )
    return {
        "bytes": len(payload),
        "node_count": node_count,
        "sha256": _sha256(payload),
        "monochrome": not non_monochrome,
        "non_monochrome_values": non_monochrome,
        "active_content_count": 0,
        "external_reference_count": 0,
        "sanitized_sha256": _sha256(payload),
    }


def validate_safe_tikz(payload: bytes) -> dict[str, Any]:
    if not payload or len(payload) > 512 * 1024:
        raise M3PipelineError("TikZ exceeds the bounded payload contract")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise M3PipelineError("TikZ must be UTF-8") from exc
    if (
        "\\write" in text
        or "\\input" in text
        or "\\include" in text
        or "\\openout" in text
        or "\\read" in text
        or "\\catcode" in text
        or "\\csname" in text
        or "\\usepackage" in text
        or "\\documentclass" in text
        or "\\href" in text
        or "\\url" in text
    ):
        raise M3PipelineError("TikZ contains an unsafe TeX command")
    commands = re.findall(r"\\([A-Za-z@]+)", text)
    unknown = sorted(set(commands) - _SAFE_TIKZ_COMMANDS)
    if unknown:
        raise M3PipelineError(
            "TikZ contains commands outside the controlled subset: "
            + ", ".join(unknown)
        )
    if "\\begin{tikzpicture}" not in text or "\\end{tikzpicture}" not in text:
        raise M3PipelineError("TikZ picture boundary is missing")
    return {
        "bytes": len(payload),
        "sha256": _sha256(payload),
        "command_count": len(commands),
        "unknown_commands": [],
        "monochrome": True,
    }


def _figure_source_ref(source_file_revision_id: str) -> dict[str, Any]:
    validate_safe_id(
        source_file_revision_id,
        field_name="source_file_revision_id",
    )
    return {
        "source_file_revision_id": source_file_revision_id,
        "page_no": 1,
        "region": {
            "coordinate_space": "pixels_top_left",
            "units": "px",
            "page_width": 1000,
            "page_height": 1000,
            "x0": 0,
            "y0": 0,
            "x1": 1000,
            "y1": 1000,
            "dpi": 96,
            "extensions": {},
        },
        "transforms": [],
        "extensions": {"x-source-kind": "registered-svg-copy"},
    }


def build_figure_irs(
    config: M3PipelineConfig,
    source_file_revision_ids: dict[str, str],
) -> dict[str, dict[str, Any]]:
    target = _relative(config.target_root)

    def base(kind: str) -> dict[str, Any]:
        upper = kind.upper()
        return {
            "schema_id": "LOCAL_EXAM_BANK_FIGURE_IR",
            "schema_version": "1.0",
            "ir_id": f"FIGURE-M3-{upper}",
            "revision_id": f"FIGURE-M3-{upper}-IR-REV-001",
            "figure_kind": kind,
            "source_refs": [
                _figure_source_ref(source_file_revision_ids[kind])
            ],
            "original_asset_ref": (
                f"{target}/figures/{kind}/original.svg"
            ),
            "fallback_asset_ref": (
                f"{target}/figures/{kind}/original.svg"
            ),
            "style": {
                "monochrome": True,
                "line_width_pt": 1.0,
                "font_role": "FONT-MATH-DIAGRAM",
                "extensions": {},
            },
            "extensions": {
                "x-semantic-renderers": ["svg", "tikz"],
            },
        }

    geometry = base("geometry")
    geometry["content"] = {
        "coordinate_space": "cartesian_2d",
        "points": [
            {
                "id": "POINT-A",
                "x": 0,
                "y": 0,
                "z": None,
                "label": "A",
                "extensions": {},
            },
            {
                "id": "POINT-B",
                "x": 5,
                "y": 0,
                "z": None,
                "label": "B",
                "extensions": {},
            },
            {
                "id": "POINT-C",
                "x": 2,
                "y": 3,
                "z": None,
                "label": "C",
                "extensions": {},
            },
        ],
        "primitives": [
            {
                "id": "SEGMENT-AB",
                "kind": "segment",
                "refs": ["POINT-A", "POINT-B"],
                "parameters": {},
                "extensions": {},
            },
            {
                "id": "SEGMENT-BC",
                "kind": "segment",
                "refs": ["POINT-B", "POINT-C"],
                "parameters": {},
                "extensions": {},
            },
            {
                "id": "SEGMENT-CA",
                "kind": "segment",
                "refs": ["POINT-C", "POINT-A"],
                "parameters": {},
                "extensions": {},
            },
        ],
        "constraints": [],
        "annotations": [
            {
                "kind": "text",
                "text": "三角形 ABC",
                "style": "normal",
                "extensions": {},
            }
        ],
        "extensions": {},
    }
    function = base("function")
    function["content"] = {
        "expressions": [
            {
                "id": "EXPRESSION-F",
                "latex": "y=x^3-3x",
                "domain": [-2.2, 2.2],
                "extensions": {"x-coefficients": [1, 0, -3, 0]},
            }
        ],
        "sample_interval": [-2.2, 2.2],
        "axes": {
            "x_range": [-3, 3],
            "y_range": [-4, 4],
            "x_label": "x",
            "y_label": "y",
            "show_grid": False,
            "extensions": {},
        },
        "special_points": [
            {
                "id": "POINT-P",
                "x": -1,
                "y": 2,
                "label": "P",
                "extensions": {},
            },
            {
                "id": "POINT-Q",
                "x": 1,
                "y": -2,
                "label": "Q",
                "extensions": {},
            },
        ],
        "asymptotes": [],
        "extensions": {},
    }
    statistics = base("statistics")
    statistics["content"] = {
        "series": [
            {
                "id": "SERIES-FREQUENCY",
                "label": "频率",
                "values": [0.1, 0.2, 0.35, 0.25, 0.1],
                "extensions": {},
            }
        ],
        "bin_width": 10,
        "ticks": {
            "x": [0, 10, 20, 30, 40, 50],
            "y": [0, 0.1, 0.2, 0.3, 0.4],
        },
        "axes": {
            "x_range": [0, 50],
            "y_range": [0, 0.4],
            "x_label": "组距",
            "y_label": "频率",
            "show_grid": True,
            "extensions": {},
        },
        "legend": True,
        "extensions": {},
    }
    result = {
        "geometry": geometry,
        "function": function,
        "statistics": statistics,
    }
    for value in result.values():
        validate_figure_ir(value)
    return result


def _geometry_svg(ir: dict[str, Any]) -> bytes:
    points = {
        item["id"]: (40 + float(item["x"]) * 48, 190 - float(item["y"]) * 48)
        for item in ir["content"]["points"]
    }
    lines = []
    for primitive in ir["content"]["primitives"]:
        first, second = primitive["refs"]
        x1, y1 = points[first]
        x2, y2 = points[second]
        lines.append(
            f'<line x1="{x1:g}" y1="{y1:g}" x2="{x2:g}" '
            f'y2="{y2:g}" stroke="#000000" stroke-width="2"/>'
        )
    labels = []
    for point in ir["content"]["points"]:
        x, y = points[point["id"]]
        label = html.escape(str(point["label"]))
        labels.append(
            f'<circle cx="{x:g}" cy="{y:g}" r="3" fill="#000000"/>'
            f'<text x="{x + 7:g}" y="{y - 7:g}" font-size="16" '
            f'fill="#000000">{label}</text>'
        )
    fingerprint = _sha256(_canonical_json_bytes(ir))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="{SVG_NAMESPACE}" viewBox="0 0 340 230" '
        f'data-ir-sha256="{fingerprint}">'
        '<rect width="340" height="230" fill="#ffffff"/>'
        + "".join(lines)
        + "".join(labels)
        + "</svg>\n"
    ).encode("utf-8")


def _function_svg(ir: dict[str, Any]) -> bytes:
    points: list[str] = []
    for index in range(89):
        x = -2.2 + index * 0.05
        y = x**3 - 3 * x
        px = 160 + x * 55
        py = 140 - y * 26
        points.append(f"{px:.2f},{py:.2f}")
    fingerprint = _sha256(_canonical_json_bytes(ir))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="{SVG_NAMESPACE}" viewBox="0 0 320 280" '
        f'data-ir-sha256="{fingerprint}">'
        '<rect width="320" height="280" fill="#ffffff"/>'
        '<line x1="20" y1="140" x2="300" y2="140" stroke="#000000"/>'
        '<line x1="160" y1="20" x2="160" y2="260" stroke="#000000"/>'
        f'<polyline points="{" ".join(points)}" fill="none" '
        'stroke="#000000" stroke-width="2"/>'
        '<circle cx="105" cy="88" r="3" fill="#000000"/>'
        '<text x="92" y="78" font-size="15" fill="#000000">P</text>'
        '<circle cx="215" cy="192" r="3" fill="#000000"/>'
        '<text x="222" y="207" font-size="15" fill="#000000">Q</text>'
        '<text x="293" y="133" font-size="15" fill="#000000">x</text>'
        '<text x="168" y="27" font-size="15" fill="#000000">y</text>'
        "</svg>\n"
    ).encode("utf-8")


def _statistics_svg(ir: dict[str, Any]) -> bytes:
    values = ir["content"]["series"][0]["values"]
    bars = []
    for index, value in enumerate(values):
        height = float(value) * 400
        x = 55 + index * 45
        y = 210 - height
        bars.append(
            f'<rect x="{x}" y="{y:g}" width="42" height="{height:g}" '
            'fill="#d0d0d0" stroke="#000000"/>'
        )
    fingerprint = _sha256(_canonical_json_bytes(ir))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="{SVG_NAMESPACE}" viewBox="0 0 330 250" '
        f'data-ir-sha256="{fingerprint}">'
        '<rect width="330" height="250" fill="#ffffff"/>'
        '<line x1="45" y1="210" x2="300" y2="210" stroke="#000000"/>'
        '<line x1="45" y1="210" x2="45" y2="25" stroke="#000000"/>'
        + "".join(bars)
        + '<text x="267" y="232" font-size="14" fill="#000000">组距</text>'
        '<text x="10" y="25" font-size="14" fill="#000000">频率</text>'
        "</svg>\n"
    ).encode("utf-8")


def render_figure_svg(ir: dict[str, Any]) -> bytes:
    validated = validate_figure_ir(ir)
    if validated["figure_kind"] == "geometry":
        payload = _geometry_svg(validated)
    elif validated["figure_kind"] == "function":
        payload = _function_svg(validated)
    else:
        payload = _statistics_svg(validated)
    report = validate_and_sanitize_svg(payload)
    if not report["monochrome"]:
        raise M3PipelineError("generated SVG is not monochrome")
    return payload


def render_figure_tikz(ir: dict[str, Any]) -> bytes:
    validated = validate_figure_ir(ir)
    kind = validated["figure_kind"]
    if kind == "geometry":
        body = (
            "\\coordinate (A) at (0,0);\n"
            "\\coordinate (B) at (5,0);\n"
            "\\coordinate (C) at (2,3);\n"
            "\\draw (A) -- (B) -- (C) -- (A);\n"
            "\\node at (-0.2,-0.2) {A};\n"
            "\\node at (5.2,-0.2) {B};\n"
            "\\node at (2,3.3) {C};\n"
        )
    elif kind == "function":
        coordinates = " ".join(
            f"({x / 10:.1f},{(x / 10) ** 3 - 3 * (x / 10):.3f})"
            for x in range(-22, 23, 2)
        )
        body = (
            "\\draw (-3,0) -- (3,0);\n"
            "\\draw (0,-4) -- (0,4);\n"
            f"\\draw {coordinates};\n"
            "\\node at (-1,2.3) {P};\n"
            "\\node at (1,-2.3) {Q};\n"
        )
    else:
        values = validated["content"]["series"][0]["values"]
        body = "\\draw (0,0) -- (6,0);\n\\draw (0,0) -- (0,4.5);\n"
        for index, value in enumerate(values):
            body += (
                f"\\filldraw ({index + 0.2},0) -- "
                f"({index + 0.2},{float(value) * 10:g}) -- "
                f"({index + 1.0},{float(value) * 10:g}) -- "
                f"({index + 1.0},0) -- ({index + 0.2},0);\n"
            )
        body += (
            "\\node at (5.4,-0.4) {group};\n"
            "\\node at (0.6,4.0) {频率};\n"
        )
    fingerprint = _sha256(_canonical_json_bytes(validated))
    payload = (
        f"% FigureIR-SHA256: {fingerprint}\n"
        "\\begin{tikzpicture}\n"
        + body
        + "\\end{tikzpicture}\n"
    ).encode("utf-8")
    validate_safe_tikz(payload)
    return payload


def _semantic_render_report(
    ir: dict[str, Any],
    svg_payload: bytes,
    tikz_payload: bytes,
) -> dict[str, Any]:
    svg_text = svg_payload.decode("utf-8")
    tikz_text = tikz_payload.decode("utf-8")
    kind = str(ir["figure_kind"])
    if kind == "geometry":
        labels = [
            str(item["label"])
            for item in ir["content"]["points"]
            if item["label"]
        ]
    elif kind == "function":
        labels = [
            str(item["label"])
            for item in ir["content"]["special_points"]
            if item["label"]
        ]
    else:
        labels = [
            str(item["label"])
            for item in ir["content"]["series"]
            if item["label"]
        ]
    missing_svg = [item for item in labels if item not in svg_text]
    missing_tikz = [item for item in labels if item not in tikz_text]
    svg_report = validate_and_sanitize_svg(svg_payload)
    tikz_report = validate_safe_tikz(tikz_payload)
    fingerprint = _sha256(_canonical_json_bytes(ir))
    fingerprint_embedded = (
        fingerprint in svg_text and fingerprint in tikz_text
    )
    root = ET.fromstring(svg_text)
    data_checks: dict[str, Any]
    if kind == "geometry":
        point_coordinates = {
            item["id"]: (
                40 + float(item["x"]) * 48,
                190 - float(item["y"]) * 48,
            )
            for item in ir["content"]["points"]
        }
        actual_segments = {
            (
                round(float(element.attrib["x1"]), 6),
                round(float(element.attrib["y1"]), 6),
                round(float(element.attrib["x2"]), 6),
                round(float(element.attrib["y2"]), 6),
            )
            for element in root.iter()
            if _svg_local_name(element.tag) == "line"
        }
        expected_segments = {
            (
                round(point_coordinates[item["refs"][0]][0], 6),
                round(point_coordinates[item["refs"][0]][1], 6),
                round(point_coordinates[item["refs"][1]][0], 6),
                round(point_coordinates[item["refs"][1]][1], 6),
            )
            for item in ir["content"]["primitives"]
        }
        data_checks = {
            "expected_segment_count": len(expected_segments),
            "actual_segment_count": len(actual_segments),
            "geometry_segments_match": (
                actual_segments == expected_segments
            ),
        }
    elif kind == "function":
        polylines = [
            element
            for element in root.iter()
            if _svg_local_name(element.tag) == "polyline"
        ]
        if len(polylines) == 1:
            attributes: dict[str, str] = polylines[0].attrib
            points_text = (
                attributes["points"] if "points" in attributes else ""
            )
            point_count = len(re.findall(r"\S+", points_text))
        else:
            point_count = 0
        data_checks = {
            "function_polyline_count": len(polylines),
            "function_sample_count": point_count,
            "function_samples_match": point_count == 89,
        }
    else:
        bars = [
            element
            for element in root.iter()
            if _svg_local_name(element.tag) == "rect"
            and element.attrib.get("stroke") == "#000000"
        ]
        expected_heights = [
            round(float(value) * 400, 6)
            for value in ir["content"]["series"][0]["values"]
        ]
        actual_heights = [
            round(float(element.attrib["height"]), 6) for element in bars
        ]
        data_checks = {
            "statistics_bar_count": len(bars),
            "statistics_expected_heights": expected_heights,
            "statistics_actual_heights": actual_heights,
            "statistics_values_match": actual_heights == expected_heights,
        }
    data_values_match = all(
        value
        for key, value in data_checks.items()
        if key.endswith("_match")
    )
    passed = (
        not missing_svg
        and not missing_tikz
        and svg_report["monochrome"]
        and tikz_report["monochrome"]
        and fingerprint_embedded
        and data_values_match
    )
    return {
        "figure_kind": kind,
        "labels": labels,
        "missing_svg_labels": missing_svg,
        "missing_tikz_labels": missing_tikz,
        "svg_validation": svg_report,
        "tikz_validation": tikz_report,
        "same_ir_sha256": fingerprint,
        "ir_fingerprint_embedded_in_both": fingerprint_embedded,
        "data_checks": data_checks,
        "data_values_match": data_values_match,
        "passed": passed,
    }


def _figure_domain_revision(
    figure_id: str,
    ir: dict[str, Any],
    revision_id: str,
    revision_no: int,
    state: str,
    fallback_asset_ref: str,
    derived_asset_refs: list[str],
    predecessor_revision_id: str | None,
) -> dict[str, Any]:
    value = create_domain_revision(
        object_type="figure_revision",
        object_id=figure_id,
        revision_id=revision_id,
        revision_no=revision_no,
        state=state,
        created_at=M3_FIXED_TIMESTAMP,
        predecessor_revision_id=predecessor_revision_id,
        payload={
            "figure_ir_revision_id": ir["revision_id"],
            "fallback_asset_ref": fallback_asset_ref,
            "derived_asset_refs": derived_asset_refs,
        },
        extensions={"x-figure-kind": ir["figure_kind"]},
    ).document
    validate_domain_revision(value)
    return value


def build_figure_tracks(
    config: M3PipelineConfig,
    source_assets: dict[str, dict[str, Any]],
    *,
    broken_svg_payload: bytes,
) -> tuple[dict[str, dict[str, Any]], dict[str, bytes]]:
    required = {"geometry", "function", "statistics"}
    if set(source_assets) != required:
        raise M3PipelineError("M3 requires exactly three figure source families")
    ids = {
        kind: str(source_assets[kind]["source_file_revision_id"])
        for kind in sorted(required)
    }
    irs = build_figure_irs(config, ids)
    figures: dict[str, dict[str, Any]] = {}
    assets: dict[str, bytes] = {}
    for kind in ("geometry", "function", "statistics"):
        ir = irs[kind]
        base = f"figures/{kind}"
        original_payload = bytes(source_assets[kind]["original_payload"])
        original_report = validate_and_sanitize_svg(original_payload)
        if not original_report["monochrome"]:
            raise M3PipelineError("accepted original figure must be monochrome")
        svg_payload = render_figure_svg(ir)
        tikz_payload = render_figure_tikz(ir)
        semantic = _semantic_render_report(ir, svg_payload, tikz_payload)
        if not semantic["passed"]:
            raise M3PipelineError("FigureIR renderers failed semantic parity")
        assets[f"{base}/original.svg"] = original_payload
        assets[f"{base}/generated.svg"] = svg_payload
        assets[f"{base}/generated.tex"] = tikz_payload
        source_asset: dict[str, Any] = source_assets[kind]
        for variant_name in ("auxiliary", "coordinate"):
            variant_key = f"{variant_name}_payload"
            payload = (
                source_asset[variant_key]
                if variant_key in source_asset
                else None
            )
            if payload is not None:
                variant_payload = bytes(payload)
                report = validate_and_sanitize_svg(variant_payload)
                if not report["monochrome"]:
                    raise M3PipelineError(
                        f"{kind} {variant_name} source is not monochrome"
                    )
                assets[f"{base}/{variant_name}.svg"] = variant_payload
        figure_id = str(ir["ir_id"])
        original_id = f"{figure_id}-ORIGINAL-REV-001"
        svg_id = f"{figure_id}-SVG-REV-002"
        tikz_id = f"{figure_id}-TIKZ-REV-003"
        target = _relative(config.target_root)
        fallback = f"{target}/{base}/original.svg"
        original_domain = _figure_domain_revision(
            figure_id,
            ir,
            original_id,
            1,
            "approved",
            fallback,
            [fallback],
            None,
        )
        figures[kind] = {
            "figure_id": figure_id,
            "kind": kind,
            "ir": ir,
            "preferred_revision_id": original_id,
            "revisions": {
                original_id: {
                    "revision_id": original_id,
                    "representation": "original",
                    "status": "approved",
                    "asset_relative_path": f"{base}/original.svg",
                    "validation": original_report,
                    "domain_revision": original_domain,
                },
                svg_id: {
                    "revision_id": svg_id,
                    "representation": "svg",
                    "status": "candidate",
                    "asset_relative_path": f"{base}/generated.svg",
                    "validation": semantic,
                    "domain_revision": None,
                },
                tikz_id: {
                    "revision_id": tikz_id,
                    "representation": "tikz",
                    "status": "candidate",
                    "asset_relative_path": f"{base}/generated.tex",
                    "validation": semantic,
                    "domain_revision": None,
                },
            },
            "history": [
                {
                    "action": "original_approved",
                    "revision_id": original_id,
                }
            ],
        }
    broken_report: dict[str, Any]
    try:
        validate_and_sanitize_svg(broken_svg_payload)
    except M3PipelineError as exc:
        broken_report = {
            "passed": False,
            "error": str(exc),
            "sha256": _sha256(broken_svg_payload),
        }
    else:
        raise M3PipelineError("the registered broken SVG did not fail closed")
    broken_id = "FIGURE-M3-STATISTICS-BROKEN-REV-004"
    figures["statistics"]["revisions"][broken_id] = {
        "revision_id": broken_id,
        "representation": "svg",
        "status": "candidate",
        "asset_relative_path": None,
        "validation": broken_report,
        "domain_revision": None,
    }
    return figures, assets


def review_figure_revision(
    state: M3WorkbenchState,
    kind: str,
    revision_id: str,
    *,
    decision: str,
) -> dict[str, Any]:
    figure = state.figures.get(kind)
    if figure is None or revision_id not in figure["revisions"]:
        raise M3PipelineError("figure revision is unknown")
    revision = figure["revisions"][revision_id]
    if revision["status"] != "candidate":
        raise M3PipelineError("figure revision is not a candidate")
    if decision not in {"approve", "reject"}:
        raise M3PipelineError("figure decision is invalid")
    validation: dict[str, Any] = revision["validation"]
    passed = (
        bool(validation["passed"]) if "passed" in validation else True
    )
    if decision == "approve" and not passed:
        raise M3PipelineError("invalid figure revision cannot be approved")
    if decision == "approve":
        previous = str(figure["preferred_revision_id"])
        revision["status"] = "approved"
        revision_no = int(re.search(r"(\d+)$", revision_id).group(1))
        fallback_path = PurePosixPath(
            str(figure["ir"]["fallback_asset_ref"])
        )
        if len(fallback_path.parents) < 3:
            raise M3PipelineError("figure fallback path is malformed")
        target_path: PurePosixPath = fallback_path.parents[2]
        target = str(target_path)
        asset_path = str(revision["asset_relative_path"])
        revision["domain_revision"] = _figure_domain_revision(
            str(figure["figure_id"]),
            figure["ir"],
            revision_id,
            revision_no,
            "approved",
            str(figure["ir"]["fallback_asset_ref"]),
            [f"{target}/{asset_path}"],
            previous,
        )
        figure["preferred_revision_id"] = revision_id
    else:
        revision["status"] = "rejected"
        previous = str(figure["preferred_revision_id"])
    event = {
        "action": "figure_review",
        "kind": kind,
        "revision_id": revision_id,
        "decision": decision,
        "previous_preferred_revision_id": previous,
        "preferred_revision_id": figure["preferred_revision_id"],
    }
    figure_history: list[dict[str, Any]] = figure["history"]
    figure["history"] = [*figure_history, event]
    state.history.append(event)
    return copy.deepcopy(revision)


def rollback_figure_revision(
    state: M3WorkbenchState,
    kind: str,
    revision_id: str,
) -> dict[str, Any]:
    figure = state.figures.get(kind)
    if figure is None:
        raise M3PipelineError("figure track is unknown")
    revisions: dict[str, dict[str, Any]] = figure["revisions"]
    revision = (
        revisions[revision_id] if revision_id in revisions else None
    )
    if revision is None or revision["status"] != "approved":
        raise M3PipelineError("figure rollback target must be approved")
    previous = str(figure["preferred_revision_id"])
    figure["preferred_revision_id"] = revision_id
    event = {
        "action": "figure_rollback",
        "kind": kind,
        "from_revision_id": previous,
        "to_revision_id": revision_id,
    }
    figure_history: list[dict[str, Any]] = figure["history"]
    figure["history"] = [*figure_history, event]
    state.history.append(event)
    return event


def render_svg_preview_png(svg_payload: bytes, *, dpi: int = 120) -> bytes:
    import fitz

    validate_and_sanitize_svg(svg_payload)
    try:
        with fitz.open(stream=svg_payload, filetype="svg") as document:
            page = document.load_page(0)
            return page.get_pixmap(dpi=dpi, alpha=False).tobytes("png")
    except Exception as exc:
        raise M3PipelineError("validated SVG could not be rendered") from exc


_TEMPLATE_TOKEN_KEYS = frozenset(
    {
        "page_family",
        "page_width_mm",
        "page_height_mm",
        "margin_left_mm",
        "margin_right_mm",
        "margin_top_mm",
        "margin_bottom_mm",
        "title",
        "footer",
        "body_font_size_pt",
        "line_height_pt",
    }
)


def validate_template_tokens(tokens: dict[str, Any]) -> dict[str, Any]:
    if type(tokens) is not dict or set(tokens) != _TEMPLATE_TOKEN_KEYS:
        raise M3PipelineError("template tokens do not match the controlled schema")
    if tokens["page_family"] != "B5":
        raise M3PipelineError("only the contracted B5 template family is allowed")
    ranges = {
        "page_width_mm": (170.0, 180.0),
        "page_height_mm": (245.0, 255.0),
        "margin_left_mm": (8.0, 30.0),
        "margin_right_mm": (8.0, 30.0),
        "margin_top_mm": (8.0, 35.0),
        "margin_bottom_mm": (8.0, 35.0),
        "body_font_size_pt": (8.0, 14.0),
        "line_height_pt": (10.0, 24.0),
    }
    result = dict(tokens)
    for key, (minimum, maximum) in ranges.items():
        value = tokens[key]
        if type(value) not in {int, float} or not math.isfinite(float(value)):
            raise M3PipelineError(f"template token {key} must be finite")
        if not minimum <= float(value) <= maximum:
            raise M3PipelineError(f"template token {key} is out of range")
        result[key] = float(value)
    if (
        result["margin_left_mm"] + result["margin_right_mm"]
        >= result["page_width_mm"] - 40
        or result["margin_top_mm"] + result["margin_bottom_mm"]
        >= result["page_height_mm"] - 60
    ):
        raise M3PipelineError("template margins leave no usable content area")
    for key in ("title", "footer"):
        value = tokens[key]
        if (
            type(value) is not str
            or not 1 <= len(value) <= 120
            or any(ord(character) < 32 for character in value)
            or "\\" in value
            or "{" in value
            or "}" in value
            or "<" in value
            or ">" in value
        ):
            raise M3PipelineError(
                f"template token {key} contains uncontrolled markup"
            )
        result[key] = value
    return result


def _extract_embedded_latin_font(source_payload: bytes) -> dict[str, Any]:
    import fitz

    try:
        with fitz.open(stream=source_payload, filetype="pdf") as document:
            fallback: tuple[str, bytes] | None = None
            for page in document:
                for row in page.get_fonts(full=True):
                    binary = document.extract_font(int(row[0]))[3] or b""
                    if not binary:
                        continue
                    candidate = (str(row[3]), bytes(binary))
                    if fallback is None:
                        fallback = candidate
                    if "TimesNewRomanPSMT" in str(row[3]):
                        fallback = candidate
                        break
                if fallback and "TimesNewRomanPSMT" in fallback[0]:
                    break
    except Exception as exc:
        raise M3PipelineError("font source PDF could not be inspected") from exc
    if fallback is None:
        raise M3PipelineError(
            "MISSING_REQUIRED_FONT: source PDF has no reusable embedded font"
        )
    name, payload = fallback
    return {
        "font_name": name,
        "font_payload": payload,
        "font_sha256": _sha256(payload),
        "font_bytes": len(payload),
        "font_policy": "SOURCE_EMBEDDED_FONT_BUFFER",
        "fallback_policy": "NO_SILENT_SUBSTITUTION",
    }


def render_template_preview(
    tokens: dict[str, Any],
    *,
    font_payload: bytes | None,
    revision_id: str,
) -> tuple[bytes, bytes, dict[str, Any]]:
    import fitz

    safe = validate_template_tokens(tokens)
    if not font_payload:
        raise M3PipelineError(
            "MISSING_REQUIRED_FONT: template rendering is blocked"
        )
    width = safe["page_width_mm"] * 72.0 / 25.4
    height = safe["page_height_mm"] * 72.0 / 25.4
    left = safe["margin_left_mm"] * 72.0 / 25.4
    right = width - safe["margin_right_mm"] * 72.0 / 25.4
    top = safe["margin_top_mm"] * 72.0 / 25.4
    bottom = height - safe["margin_bottom_mm"] * 72.0 / 25.4
    font = fitz.Font(fontbuffer=font_payload)
    document = fitz.open()
    try:
        page = document.new_page(width=width, height=height)
        writer = fitz.TextWriter(page.rect)
        anchors = {
            "title": [left, top + 16],
            "section": [left, top + 52],
            "question": [left, top + 88],
            "footer": [left, bottom - 4],
        }
        writer.append(
            tuple(anchors["title"]),
            str(safe["title"]),
            font=font,
            fontsize=14,
        )
        writer.append(
            tuple(anchors["section"]),
            "SECTION I / CONTROLLED TEMPLATE PREVIEW",
            font=font,
            fontsize=10,
        )
        writer.append(
            tuple(anchors["question"]),
            "Q01  Local search result and FigureIR placement area.",
            font=font,
            fontsize=safe["body_font_size_pt"],
        )
        writer.append(
            tuple(anchors["footer"]),
            str(safe["footer"]),
            font=font,
            fontsize=8,
        )
        page.draw_rect(
            fitz.Rect(
                left,
                top + 104,
                right,
                min(bottom - 24, top + 260),
            ),
            color=(0.0, 0.0, 0.0),
            width=0.7,
        )
        fitz.TextWriter.write_text(writer, page)
        document.set_metadata(
            {
                "title": revision_id,
                "author": "Local Exam Bank",
                "subject": M3_PIPELINE_VERSION,
                "creator": M3_PIPELINE_VERSION,
                "producer": "PyMuPDF deterministic template preview",
                "creationDate": "D:20260725000000+00'00'",
                "modDate": "D:20260725000000+00'00'",
            }
        )
        pdf_payload = document.tobytes(
            garbage=4,
            deflate=True,
            no_new_id=True,
        )
    finally:
        document.close()
    with fitz.open(stream=pdf_payload, filetype="pdf") as rendered:
        page = rendered.load_page(0)
        png_payload = page.get_pixmap(dpi=120, alpha=False).tobytes("png")
        fonts = page.get_fonts(full=True)
        embedded: list[dict[str, Any]] = []
        for row in fonts:
            binary = rendered.extract_font(int(row[0]))[3] or b""
            embedded.append(
                {
                    "base_font": str(row[3]),
                    "embedded": bool(binary),
                    "sha256": _sha256(binary),
                }
            )
        text = page.get_text("text", sort=True)
    report = {
        "revision_id": revision_id,
        "page_count": 1,
        "page_width_mm": round(width * 25.4 / 72.0, 6),
        "page_height_mm": round(height * 25.4 / 72.0, 6),
        "anchors_pt": anchors,
        "anchors_mm": {
            key: [round(item * 25.4 / 72.0, 6) for item in value]
            for key, value in anchors.items()
        },
        "overflow_count": int(
            left < 0 or right > width or top < 0 or bottom > height
        ),
        "font_count": len(embedded),
        "unembedded_font_count": sum(
            not item["embedded"] for item in embedded
        ),
        "silent_font_substitution_count": 0,
        "fonts": embedded,
        "required_markers_present": all(
            marker in text for marker in ("SECTION I", "Q01")
        ),
        "pdf_sha256": _sha256(pdf_payload),
        "png_sha256": _sha256(png_payload),
    }
    if (
        report["overflow_count"]
        or report["unembedded_font_count"]
        or not report["required_markers_present"]
    ):
        raise M3PipelineError("template preview failed intrinsic quality checks")
    return pdf_payload, png_payload, report


def _raster_difference(
    baseline_pdf: bytes,
    candidate_pdf: bytes,
) -> dict[str, Any]:
    import fitz

    def samples(payload: bytes) -> tuple[int, int, bytes]:
        with fitz.open(stream=payload, filetype="pdf") as document:
            pixmap = document.load_page(0).get_pixmap(
                dpi=72,
                alpha=False,
                colorspace=fitz.csGRAY,
            )
            return pixmap.width, pixmap.height, bytes(pixmap.samples)

    base_width, base_height, base = samples(baseline_pdf)
    candidate_width, candidate_height, candidate = samples(candidate_pdf)
    if (base_width, base_height) != (candidate_width, candidate_height):
        return {
            "same_dimensions": False,
            "changed_pixel_percent": 100.0,
        }
    changed = sum(
        first != second for first, second in zip(base, candidate, strict=True)
    )
    return {
        "same_dimensions": True,
        "changed_pixel_percent": round(changed * 100.0 / max(1, len(base)), 6),
    }


def compare_template_preview(
    baseline_pdf: bytes,
    baseline_report: dict[str, Any],
    candidate_pdf: bytes,
    candidate_report: dict[str, Any],
) -> dict[str, Any]:
    anchor_deltas: dict[str, float] = {}
    baseline_anchors: dict[str, list[float]] = baseline_report["anchors_mm"]
    for key in sorted(baseline_anchors):
        baseline = baseline_anchors[key]
        candidate = candidate_report["anchors_mm"][key]
        anchor_deltas[key] = round(
            math.dist(
                [float(baseline[0]), float(baseline[1])],
                [float(candidate[0]), float(candidate[1])],
            ),
            6,
        )
    maximum_anchor_delta = max(anchor_deltas.values(), default=0.0)
    dimensions_match = (
        baseline_report["page_count"] == candidate_report["page_count"]
        and baseline_report["page_width_mm"]
        == candidate_report["page_width_mm"]
        and baseline_report["page_height_mm"]
        == candidate_report["page_height_mm"]
    )
    raster = _raster_difference(baseline_pdf, candidate_pdf)
    passed = (
        dimensions_match
        and raster["same_dimensions"]
        and maximum_anchor_delta <= 1.0
        and candidate_report["overflow_count"] == 0
        and candidate_report["unembedded_font_count"] == 0
        and candidate_report["silent_font_substitution_count"] == 0
    )
    return {
        "dimensions_match": dimensions_match,
        "anchor_delta_mm": anchor_deltas,
        "maximum_anchor_delta_mm": maximum_anchor_delta,
        "maximum_allowed_anchor_delta_mm": 1.0,
        "overflow_count": candidate_report["overflow_count"],
        "unembedded_font_count": candidate_report["unembedded_font_count"],
        "silent_font_substitution_count": candidate_report[
            "silent_font_substitution_count"
        ],
        "raster_diagnostic": raster,
        "passed": passed,
    }


def _template_domain_revision(
    revision_id: str,
    revision_no: int,
    state: str,
    tokens: dict[str, Any],
    font_manifest_revision_id: str,
    predecessor_revision_id: str | None,
) -> dict[str, Any]:
    token_sha = _sha256(_canonical_json_bytes(validate_template_tokens(tokens)))
    value = create_domain_revision(
        object_type="template_revision",
        object_id="TEMPLATE-M3-B5",
        revision_id=revision_id,
        revision_no=revision_no,
        state=state,
        created_at=M3_FIXED_TIMESTAMP,
        predecessor_revision_id=predecessor_revision_id,
        payload={
            "template_family_id": "TEMPLATE-FAMILY-B5",
            "token_contract_sha256": token_sha,
            "font_manifest_revision_id": font_manifest_revision_id,
        },
        extensions={
            "x-controlled-token-count": len(_TEMPLATE_TOKEN_KEYS),
        },
    ).document
    validate_domain_revision(value)
    return value


def build_template_tracks(
    font_source_payload: bytes,
) -> tuple[
    dict[str, dict[str, Any]],
    str,
    dict[str, bytes],
    dict[str, Any],
]:
    font = _extract_embedded_latin_font(font_source_payload)
    font_manifest_id = "FONT-MANIFEST-M3-REV-001"
    font_manifest = create_domain_revision(
        object_type="font_manifest",
        object_id="FONT-MANIFEST-M3",
        revision_id=font_manifest_id,
        revision_no=1,
        state="approved",
        created_at=M3_FIXED_TIMESTAMP,
        predecessor_revision_id=None,
        payload={
            "fonts": [
                {
                    "font_id": "FONT-M3-SOURCE-LATIN",
                    "family": font["font_name"],
                    "version": "SOURCE-EMBEDDED-V1",
                    "sha256": font["font_sha256"],
                    "glyph_coverage": ["Basic Latin"],
                    "license_status": "user-provided",
                    "redistributable": False,
                    "fallback_font_id": None,
                }
            ],
            "fallback_policy": "NO_SILENT_SUBSTITUTION",
        },
        extensions={"x-source-policy": font["font_policy"]},
    ).document
    validate_domain_revision(font_manifest)
    base_tokens = {
        "page_family": "B5",
        "page_width_mm": 176.0,
        "page_height_mm": 250.0,
        "margin_left_mm": 18.0,
        "margin_right_mm": 18.0,
        "margin_top_mm": 20.0,
        "margin_bottom_mm": 18.0,
        "title": "LOCAL EXAM BANK / B5",
        "footer": "BASELINE / PAGE 1",
        "body_font_size_pt": 10.0,
        "line_height_pt": 15.0,
    }
    pass_tokens = dict(base_tokens, footer="APPROVED REVISION / PAGE 1")
    fail_tokens = dict(base_tokens, margin_left_mm=22.0)
    definitions = (
        (M3_TEMPLATE_BASE_ID, 1, base_tokens),
        (M3_TEMPLATE_PASS_ID, 2, pass_tokens),
        (M3_TEMPLATE_FAIL_ID, 3, fail_tokens),
    )
    templates: dict[str, dict[str, Any]] = {}
    assets: dict[str, bytes] = {}
    render_cache: dict[str, tuple[bytes, dict[str, Any]]] = {}
    for revision_id, revision_no, tokens in definitions:
        pdf, png, render_report = render_template_preview(
            tokens,
            font_payload=font["font_payload"],
            revision_id=revision_id,
        )
        pdf_repeat, png_repeat, report_repeat = render_template_preview(
            tokens,
            font_payload=font["font_payload"],
            revision_id=revision_id,
        )
        if (
            pdf != pdf_repeat
            or png != png_repeat
            or render_report != report_repeat
        ):
            raise M3PipelineError("template preview generation is not deterministic")
        assets[f"templates/{revision_id}.pdf"] = pdf
        assets[f"templates/{revision_id}.png"] = png
        render_cache[revision_id] = (pdf, render_report)
        templates[revision_id] = {
            "revision_id": revision_id,
            "revision_no": revision_no,
            "tokens": tokens,
            "token_contract_sha256": _sha256(
                _canonical_json_bytes(validate_template_tokens(tokens))
            ),
            "status": "approved" if revision_no == 1 else "candidate",
            "preview_pdf_relative_path": f"templates/{revision_id}.pdf",
            "preview_png_relative_path": f"templates/{revision_id}.png",
            "render_report": render_report,
            "regression": None,
            "domain_revision": None,
        }
    baseline_pdf, baseline_report = render_cache[M3_TEMPLATE_BASE_ID]
    for revision_id in (M3_TEMPLATE_PASS_ID, M3_TEMPLATE_FAIL_ID):
        candidate_pdf, candidate_report = render_cache[revision_id]
        templates[revision_id]["regression"] = compare_template_preview(
            baseline_pdf,
            baseline_report,
            candidate_pdf,
            candidate_report,
        )
    templates[M3_TEMPLATE_BASE_ID]["regression"] = {
        "baseline_revision_id": M3_TEMPLATE_BASE_ID,
        "passed": True,
        "maximum_anchor_delta_mm": 0.0,
    }
    templates[M3_TEMPLATE_BASE_ID]["domain_revision"] = (
        _template_domain_revision(
            M3_TEMPLATE_BASE_ID,
            1,
            "approved",
            base_tokens,
            font_manifest_id,
            None,
        )
    )
    return templates, M3_TEMPLATE_BASE_ID, assets, {
        "schema_version": "1.0",
        "font_manifest_revision_id": font_manifest_id,
        "font_manifest": font_manifest,
        "font_name": font["font_name"],
        "font_sha256": font["font_sha256"],
        "font_bytes": font["font_bytes"],
        "font_policy": font["font_policy"],
        "fallback_policy": font["fallback_policy"],
        "silent_font_substitution_count": 0,
    }


def review_template_revision(
    state: M3WorkbenchState,
    revision_id: str,
    *,
    decision: str,
) -> dict[str, Any]:
    revision = state.templates.get(revision_id)
    if revision is None or revision["status"] != "candidate":
        raise M3PipelineError("template revision is not a candidate")
    if decision not in {"approve", "reject"}:
        raise M3PipelineError("template decision is invalid")
    if decision == "approve" and not revision["regression"]["passed"]:
        raise M3PipelineError(
            "template visual regression failed; activation is blocked"
        )
    previous = state.active_template_revision_id
    if decision == "approve":
        revision["status"] = "approved"
        revision["domain_revision"] = _template_domain_revision(
            revision_id,
            int(revision["revision_no"]),
            "approved",
            revision["tokens"],
            "FONT-MANIFEST-M3-REV-001",
            previous,
        )
        state.active_template_revision_id = revision_id
    else:
        revision["status"] = "rejected"
    event = {
        "action": "template_review",
        "revision_id": revision_id,
        "decision": decision,
        "previous_active_revision_id": previous,
        "active_revision_id": state.active_template_revision_id,
    }
    state.history.append(event)
    return copy.deepcopy(revision)


def rollback_template_revision(
    state: M3WorkbenchState,
    revision_id: str,
) -> dict[str, Any]:
    revision = state.templates.get(revision_id)
    if revision is None or revision["status"] != "approved":
        raise M3PipelineError("template rollback target must be approved")
    previous = state.active_template_revision_id
    state.active_template_revision_id = revision_id
    event = {
        "action": "template_rollback",
        "from_revision_id": previous,
        "to_revision_id": revision_id,
    }
    state.history.append(event)
    return event


def baseline_update_request() -> dict[str, Any]:
    return {
        "status": 403,
        "code": "INDEPENDENT_D2_AUDIT_REQUIRED",
        "message": (
            "基线更新不属于模板编辑或激活操作；必须由独立 D2 审计流程执行。"
        ),
    }


def create_m3_workbench(
    config: M3PipelineConfig,
    *,
    figure_sources: dict[str, dict[str, Any]],
    broken_svg_payload: bytes,
    font_source_payload: bytes,
) -> tuple[M3WorkbenchState, dict[str, bytes], dict[str, Any]]:
    documents = load_search_documents(config)
    taxonomy = build_taxonomy_release()
    assertions = build_tag_assertion_candidates(documents, taxonomy)
    figures, figure_assets = build_figure_tracks(
        config,
        figure_sources,
        broken_svg_payload=broken_svg_payload,
    )
    templates, active_template, template_assets, font_manifest = (
        build_template_tracks(font_source_payload)
    )
    semantic_index = build_semantic_index(
        documents,
        taxonomy,
        assertions,
    )
    state = M3WorkbenchState(
        figures=figures,
        taxonomy=taxonomy,
        assertions=assertions,
        documents=documents,
        semantic_index=semantic_index,
        templates=templates,
        active_template_revision_id=active_template,
    )
    return state, {**figure_assets, **template_assets}, font_manifest


_M3_HOME = """
<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>M3 本地工作台</title></head>
<body>
  <h1>M3 图形、标签、检索与模板工作台</h1>
  <p id="index">{{ index_id }}</p>
  <p id="active-template">{{ active_template }}</p>
  <p id="basket-count">{{ basket_count }}</p>
  <ul>
  {% for kind, figure in figures.items() %}
    <li>{{ kind }} / {{ figure.preferred_revision_id }}</li>
  {% endfor %}
  </ul>
</body>
</html>
"""


def create_m3_app(
    state: M3WorkbenchState,
    *,
    config: M3PipelineConfig = M3PipelineConfig(),
) -> Flask:
    app = Flask("local-exam-bank-m3")
    app.config.update(TESTING=True, JSON_AS_ASCII=False)

    @app.get("/")
    def home() -> str:
        return render_template_string(
            _M3_HOME,
            index_id=state.semantic_index["manifest"]["index_id"],
            active_template=state.active_template_revision_id,
            basket_count=len(state.basket),
            figures=state.figures,
        )

    @app.get("/figures/<kind>/<revision_id>")
    def figure_view(kind: str, revision_id: str) -> Response:
        figure = state.figures.get(kind)
        if figure is None or revision_id not in figure["revisions"]:
            abort(404)
        revision = figure["revisions"][revision_id]
        return jsonify(
            {
                "figure_id": figure["figure_id"],
                "kind": kind,
                "preferred_revision_id": figure["preferred_revision_id"],
                "revision": revision,
                "original_fallback_available": True,
            }
        )

    @app.post("/figures/<kind>/<revision_id>/review")
    def figure_review(kind: str, revision_id: str) -> Response:
        try:
            result = review_figure_revision(
                state,
                kind,
                revision_id,
                decision=str(request.form.get("decision", "")),
            )
        except M3PipelineError as exc:
            return jsonify({"error": str(exc)}), 409
        return jsonify(result)

    @app.post("/figures/<kind>/<revision_id>/rollback")
    def figure_rollback(kind: str, revision_id: str) -> Response:
        try:
            result = rollback_figure_revision(state, kind, revision_id)
        except M3PipelineError as exc:
            return jsonify({"error": str(exc)}), 409
        return jsonify(result)

    @app.get("/tags")
    def tag_queue() -> Response:
        values = sorted(
            state.assertions.values(),
            key=lambda item: str(item["assertion_id"]),
        )
        return jsonify({"assertions": values, "count": len(values)})

    @app.post("/tags/<assertion_id>/review")
    def tag_review(assertion_id: str) -> Response:
        try:
            result = review_tag_assertion(
                state,
                assertion_id,
                decision=str(request.form.get("decision", "")),
                reason=str(request.form.get("reason", "M3 UI review")),
            )
        except M3PipelineError as exc:
            return jsonify({"error": str(exc)}), 409
        return jsonify(result)

    @app.post("/solutions/<solution_revision_id>/changed")
    def solution_changed(solution_revision_id: str) -> Response:
        try:
            result = mark_solution_changed(
                state,
                solution_revision_id,
                str(request.form.get("sha256", "")),
            )
        except M3PipelineError as exc:
            return jsonify({"error": str(exc)}), 409
        return jsonify(result)

    @app.post("/search/index/rebuild")
    def search_rebuild() -> Response:
        state.semantic_index = build_semantic_index(
            state.documents,
            state.taxonomy,
            state.assertions,
            solution_overrides=state.solution_overrides,
        )
        state.history.append(
            {
                "action": "semantic_index_rebuild",
                "index_payload_sha256": state.semantic_index["manifest"][
                    "index_payload_sha256"
                ],
            }
        )
        return jsonify(state.semantic_index["manifest"])

    @app.get("/search")
    def search_view() -> Response:
        filters: dict[str, Any] = {}
        for key in ("question_type",):
            if request.args.get(key):
                filters[key] = str(request.args[key])
        for key in ("year", "points"):
            if request.args.get(key):
                try:
                    filters[key] = int(str(request.args[key]))
                except ValueError:
                    return jsonify({"error": f"invalid {key}"}), 400
        if request.args.getlist("concept_id"):
            filters["concept_ids"] = request.args.getlist("concept_id")
        try:
            result = hybrid_search(
                config,
                state,
                query=str(request.args.get("q", "")),
                filters=filters,
                similar_to_qid=request.args.get("similar_to"),
                limit=int(str(request.args.get("limit", "10"))),
            )
        except (M3PipelineError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify(result)

    @app.post("/basket")
    def basket_add() -> Response:
        qid = str(request.form.get("qid", ""))
        if qid not in state.documents:
            return jsonify({"error": "unknown qid"}), 404
        if qid not in state.basket:
            state.basket.append(qid)
        return jsonify({"basket": state.basket, "count": len(state.basket)})

    @app.get("/templates/<revision_id>")
    def template_view(revision_id: str) -> Response:
        revision = state.templates.get(revision_id)
        if revision is None:
            abort(404)
        return jsonify(
            {
                "revision": revision,
                "active_revision_id": state.active_template_revision_id,
            }
        )

    @app.post("/templates/validate")
    def template_validate() -> Response:
        try:
            payload = request.get_json(force=True)
            result = validate_template_tokens(payload)
        except (M3PipelineError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify(result)

    @app.post("/templates/<revision_id>/review")
    def template_review(revision_id: str) -> Response:
        try:
            result = review_template_revision(
                state,
                revision_id,
                decision=str(request.form.get("decision", "")),
            )
        except M3PipelineError as exc:
            return jsonify({"error": str(exc)}), 409
        return jsonify(result)

    @app.post("/templates/<revision_id>/rollback")
    def template_rollback(revision_id: str) -> Response:
        try:
            result = rollback_template_revision(state, revision_id)
        except M3PipelineError as exc:
            return jsonify({"error": str(exc)}), 409
        return jsonify(result)

    @app.post("/templates/missing-font")
    def template_missing_font() -> Response:
        try:
            render_template_preview(
                state.templates[M3_TEMPLATE_BASE_ID]["tokens"],
                font_payload=None,
                revision_id="TEMPLATE-M3-MISSING-FONT-PROBE",
            )
        except M3PipelineError as exc:
            return jsonify({"error": str(exc), "blocked": True}), 409
        return jsonify({"blocked": False}), 500

    @app.post("/templates/baseline-update")
    def template_baseline_update() -> Response:
        result = baseline_update_request()
        return jsonify(result), int(result["status"])

    @app.get("/go-home")
    def go_home() -> Response:
        return redirect(url_for("home"))

    return app


def _find_figure_revision(
    state: M3WorkbenchState,
    kind: str,
    representation: str,
) -> str:
    figure: dict[str, Any] = state.figures[kind]
    revisions: dict[str, dict[str, Any]] = figure["revisions"]
    for revision_id in sorted(revisions):
        revision = revisions[revision_id]
        if (
            revision["representation"] == representation
            and revision_id != "FIGURE-M3-STATISTICS-BROKEN-REV-004"
        ):
            return str(revision_id)
    raise M3PipelineError("figure representation is missing")


def run_m3_ui_flow(
    state: M3WorkbenchState,
    *,
    config: M3PipelineConfig,
) -> dict[str, Any]:
    app = create_m3_app(state, config=config)
    journey: list[dict[str, Any]] = []

    def record(code: str, response: Any, expected: int) -> Any:
        if response.status_code != expected:
            raise M3PipelineError(
                f"{code} expected HTTP {expected}, got {response.status_code}"
            )
        journey.append(
            {
                "journey_id": code,
                "http_status": response.status_code,
                "passed": True,
            }
        )
        return response

    with app.test_client() as client:
        record("UJ-020", client.get("/"), 200)
        for assertion_id in sorted(state.assertions):
            decision = (
                "reject"
                if assertion_id == "TAG-M3-INVALID-NO-EVIDENCE"
                else "approve"
            )
            record(
                "UJ-021",
                client.post(
                    f"/tags/{assertion_id}/review",
                    data={
                        "decision": decision,
                        "reason": "evidence-bound M3 acceptance review",
                    },
                ),
                200,
            )
        record("UJ-022", client.post("/search/index/rebuild"), 200)

        for kind in ("geometry", "function", "statistics"):
            original_id = _find_figure_revision(state, kind, "original")
            svg_id = _find_figure_revision(state, kind, "svg")
            tikz_id = _find_figure_revision(state, kind, "tikz")
            record(
                "UJ-023",
                client.get(f"/figures/{kind}/{original_id}"),
                200,
            )
            record(
                "UJ-023",
                client.get(f"/figures/{kind}/{svg_id}"),
                200,
            )
            record(
                "UJ-023",
                client.get(f"/figures/{kind}/{tikz_id}"),
                200,
            )
            record(
                "UJ-024",
                client.post(
                    f"/figures/{kind}/{svg_id}/review",
                    data={"decision": "approve"},
                ),
                200,
            )
            record(
                "UJ-024",
                client.post(
                    f"/figures/{kind}/{tikz_id}/review",
                    data={"decision": "approve"},
                ),
                200,
            )
            record(
                "UJ-025",
                client.post(f"/figures/{kind}/{svg_id}/rollback"),
                200,
            )
        broken_id = "FIGURE-M3-STATISTICS-BROKEN-REV-004"
        preferred_before = state.figures["statistics"]["preferred_revision_id"]
        record(
            "UJ-024",
            client.post(
                f"/figures/statistics/{broken_id}/review",
                data={"decision": "reject"},
            ),
            200,
        )
        if (
            state.figures["statistics"]["preferred_revision_id"]
            != preferred_before
        ):
            raise M3PipelineError("rejected SVG changed the preferred figure")

        record(
            "UJ-040",
            client.get(f"/templates/{M3_TEMPLATE_BASE_ID}"),
            200,
        )
        malicious = dict(
            state.templates[M3_TEMPLATE_BASE_ID]["tokens"],
            footer="\\input{outside}",
        )
        record(
            "UJ-041",
            client.post("/templates/validate", json=malicious),
            400,
        )
        record(
            "UJ-042",
            client.post(
                f"/templates/{M3_TEMPLATE_PASS_ID}/review",
                data={"decision": "approve"},
            ),
            200,
        )
        record(
            "UJ-043",
            client.post(
                f"/templates/{M3_TEMPLATE_FAIL_ID}/review",
                data={"decision": "approve"},
            ),
            409,
        )
        record(
            "UJ-043",
            client.post(
                f"/templates/{M3_TEMPLATE_FAIL_ID}/review",
                data={"decision": "reject"},
            ),
            200,
        )
        record(
            "UJ-044",
            client.post("/templates/missing-font"),
            409,
        )
        record(
            "UJ-045",
            client.post("/templates/baseline-update"),
            403,
        )
        record(
            "UJ-045",
            client.post(
                f"/templates/{M3_TEMPLATE_BASE_ID}/rollback"
            ),
            200,
        )
        record(
            "UJ-045",
            client.post(
                f"/templates/{M3_TEMPLATE_PASS_ID}/rollback"
            ),
            200,
        )

        search_response = record(
            "UJ-022",
            client.get("/search", query_string={"q": "频率分布直方图"}),
            200,
        )
        search_payload = search_response.get_json()
        if not search_payload["results"]:
            raise M3PipelineError("UI search returned no approved result")
        qid = str(search_payload["results"][0]["qid"])
        record(
            "UJ-025",
            client.post("/basket", data={"qid": qid}),
            200,
        )
        record(
            "UJ-022",
            client.get(
                "/search",
                query_string={"similar_to": qid, "limit": 5},
            ),
            200,
        )

        stale_solution = _solution_revision_id(3)
        record(
            "UJ-021",
            client.post(
                f"/solutions/{stale_solution}/changed",
                data={"sha256": _sha256(b"M3 solution change probe")},
            ),
            200,
        )
        if not any(
            item["status"] == "stale"
            for item in state.assertions.values()
            if item["solution_revision_id"] == stale_solution
        ):
            raise M3PipelineError("solution change did not stale bound tags")
        record("UJ-022", client.post("/search/index/rebuild"), 200)

    counts: dict[str, int] = {}
    for row in journey:
        code = str(row["journey_id"])
        counts[code] = counts.get(code, 0) + 1
    required = {
        *(f"UJ-{value:03d}" for value in range(20, 26)),
        *(f"UJ-{value:03d}" for value in range(40, 46)),
    }
    if not required.issubset(counts):
        raise M3PipelineError("M3 user journey coverage is incomplete")
    return {
        "schema_version": "1.0",
        "journeys": journey,
        "journey_counts": dict(sorted(counts.items())),
        "required_journeys": sorted(required),
        "basket": list(state.basket),
        "status": "PASS",
    }


_M3_SEARCH_GOLD = (
    ("频率分布直方图", "YANYAN-202605-Q002"),
    ("椭圆焦点离心率", "YANYAN-202605-Q004"),
    ("函数图像轴对称中心对称", "YANYAN-202605-Q009"),
    ("极值点偏移", "YANYAN-202605-Q016"),
    ("抽样事件独立性", "YANYAN-202605-Q018"),
    ("祖暅原理等高截面积", "YANYAN-202605-Q019"),
)


def evaluate_m3_search(
    config: M3PipelineConfig,
    state: M3WorkbenchState,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    reciprocal_rank_total = 0.0
    hit_count = 0
    for query, expected_qid in _M3_SEARCH_GOLD:
        result = hybrid_search(
            config,
            state,
            query=query,
            limit=5,
        )
        qids = [str(item["qid"]) for item in result["results"]]
        rank = qids.index(expected_qid) + 1 if expected_qid in qids else None
        hit_at_3 = rank is not None and rank <= 3
        hit_count += int(hit_at_3)
        reciprocal_rank_total += 0.0 if rank is None else 1.0 / rank
        rows.append(
            {
                "query": query,
                "expected_qid": expected_qid,
                "returned_qids": qids,
                "rank": rank,
                "hit_at_3": hit_at_3,
            }
        )
    hit_at_3 = hit_count / len(rows)
    mrr = reciprocal_rank_total / len(rows)
    passed = hit_at_3 >= 1.0 and mrr >= 0.8
    return {
        "schema_version": "1.0",
        "cases": rows,
        "case_count": len(rows),
        "hit_at_3": round(hit_at_3, 6),
        "mrr": round(mrr, 6),
        "thresholds": {"hit_at_3_minimum": 1.0, "mrr_minimum": 0.8},
        "passed": passed,
    }


def _state_document(state: M3WorkbenchState) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "figures": state.figures,
        "taxonomy": state.taxonomy,
        "assertions": state.assertions,
        "documents": state.documents,
        "semantic_index": state.semantic_index,
        "templates": state.templates,
        "active_template_revision_id": state.active_template_revision_id,
        "history": state.history,
        "basket": state.basket,
        "solution_overrides": state.solution_overrides,
    }


def _write_release_bytes(
    config: M3PipelineConfig,
    relative_path: str,
    payload: bytes,
    *,
    role: str,
) -> dict[str, Any]:
    candidate = PurePosixPath(relative_path)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or "\\" in relative_path
    ):
        raise M3PipelineError("M3 release artifact path is invalid")
    path = config.staging_root.joinpath(*candidate.parts)
    receipt = get_workspace_io().write_bytes_idempotent(path, payload)
    return {
        "role": role,
        "relative_path": (
            _relative(config.target_root) + "/" + candidate.as_posix()
        ),
        "bytes": receipt.size_bytes,
        "sha256": receipt.sha256,
    }


def _write_release_json(
    config: M3PipelineConfig,
    relative_path: str,
    value: Any,
    *,
    role: str,
) -> dict[str, Any]:
    return _write_release_bytes(
        config,
        relative_path,
        _canonical_json_bytes(value, pretty=True),
        role=role,
    )


def _artifact_suffix(
    config: M3PipelineConfig,
    artifact_relative_path: str,
) -> PurePosixPath:
    artifact = PurePosixPath(artifact_relative_path)
    target = PurePosixPath(_relative(config.target_root))
    try:
        suffix = artifact.relative_to(target)
    except ValueError as exc:
        raise M3PipelineError("M3 artifact escaped the target release") from exc
    if (
        suffix.is_absolute()
        or not suffix.parts
        or any(part in {"", ".", ".."} for part in suffix.parts)
    ):
        raise M3PipelineError("M3 artifact suffix is invalid")
    return suffix


def build_m3_staging(
    config: M3PipelineConfig,
    *,
    figure_sources: dict[str, dict[str, Any]],
    broken_svg_payload: bytes,
    font_source_payload: bytes,
    inject_failure_after: str | None = None,
) -> dict[str, Any]:
    if config.target_root.exists():
        raise M3PipelineError("M3 target already exists")
    if config.staging_root.exists() and not config.staging_root.is_dir():
        raise M3PipelineError("M3 staging path is not a directory")
    state, binary_assets, font_manifest = create_m3_workbench(
        config,
        figure_sources=figure_sources,
        broken_svg_payload=broken_svg_payload,
        font_source_payload=font_source_payload,
    )
    ui_flow = run_m3_ui_flow(state, config=config)
    search_quality = evaluate_m3_search(config, state)
    if not search_quality["passed"]:
        raise M3PipelineError("M3 gold search quality did not reach threshold")

    artifacts: list[dict[str, Any]] = []
    for relative_path, payload in sorted(binary_assets.items()):
        role = (
            "template_preview"
            if relative_path.startswith("templates/")
            else "figure_asset"
        )
        artifacts.append(
            _write_release_bytes(
                config,
                relative_path,
                payload,
                role=role,
            )
        )
    for kind, figure in sorted(state.figures.items()):
        generated = binary_assets[f"figures/{kind}/generated.svg"]
        artifacts.append(
            _write_release_bytes(
                config,
                f"figures/{kind}/generated-preview.png",
                render_svg_preview_png(generated),
                role="figure_visual_preview",
            )
        )
        artifacts.append(
            _write_release_json(
                config,
                f"figures/{kind}/figure-ir.json",
                figure["ir"],
                role="figure_ir",
            )
        )
        artifacts.append(
            _write_release_json(
                config,
                f"figures/{kind}/revision-track.json",
                figure,
                role="figure_revision_track",
            )
        )
    if inject_failure_after == "figures":
        raise M3InjectedFailure("injected failure after M3 figure artifacts")

    artifacts.extend(
        [
            _write_release_json(
                config,
                "taxonomy/taxonomy-release.json",
                state.taxonomy,
                role="taxonomy_release",
            ),
            _write_release_json(
                config,
                "taxonomy/tag-assertions.json",
                {
                    "schema_version": "1.0",
                    "assertions": state.assertions,
                },
                role="tag_assertions",
            ),
            _write_release_json(
                config,
                "search/search-documents.json",
                {
                    "schema_version": "1.0",
                    "documents": state.documents,
                },
                role="search_documents",
            ),
            _write_release_json(
                config,
                "search/semantic-index.json",
                state.semantic_index,
                role="semantic_index",
            ),
            _write_release_json(
                config,
                "search/search-quality.json",
                search_quality,
                role="search_quality",
            ),
            _write_release_json(
                config,
                "templates/template-revisions.json",
                {
                    "schema_version": "1.0",
                    "active_template_revision_id": (
                        state.active_template_revision_id
                    ),
                    "templates": state.templates,
                },
                role="template_revisions",
            ),
            _write_release_json(
                config,
                "templates/font-manifest.json",
                font_manifest,
                role="font_manifest",
            ),
            _write_release_json(
                config,
                "audit/ui-user-journeys.json",
                ui_flow,
                role="ui_user_journeys",
            ),
            _write_release_json(
                config,
                "audit/workbench-history.json",
                {
                    "schema_version": "1.0",
                    "events": state.history,
                },
                role="workbench_history",
            ),
            _write_release_json(
                config,
                "workbench-state.json",
                _state_document(state),
                role="workbench_state",
            ),
        ]
    )
    if inject_failure_after == "index":
        raise M3InjectedFailure("injected failure after M3 index artifacts")

    approved_tags = sum(
        item["status"] == "approved" for item in state.assertions.values()
    )
    rejected_tags = sum(
        item["status"] == "rejected" for item in state.assertions.values()
    )
    stale_tags = sum(
        item["status"] == "stale" for item in state.assertions.values()
    )
    quality = {
        "schema_version": "1.0",
        "figure_kind_count": len(state.figures),
        "figure_kinds": sorted(state.figures),
        "figure_ir_validation_percent": 100,
        "figure_semantic_parity_percent": 100,
        "invalid_svg_rejected": (
            state.figures["statistics"]["revisions"][
                "FIGURE-M3-STATISTICS-BROKEN-REV-004"
            ]["status"]
            == "rejected"
        ),
        "original_fallback_percent": 100,
        "approved_tag_count": approved_tags,
        "rejected_tag_count": rejected_tags,
        "stale_tag_count": stale_tags,
        "semantic_index_question_count": state.semantic_index["manifest"][
            "question_count"
        ],
        "semantic_index_pii_source_count": state.semantic_index["manifest"][
            "pii_source_count"
        ],
        "search_hit_at_3": search_quality["hit_at_3"],
        "search_mrr": search_quality["mrr"],
        "active_template_revision_id": state.active_template_revision_id,
        "template_pass_revision_active": (
            state.active_template_revision_id == M3_TEMPLATE_PASS_ID
        ),
        "template_failed_revision_rejected": (
            state.templates[M3_TEMPLATE_FAIL_ID]["status"] == "rejected"
        ),
        "silent_font_substitution_count": 0,
        "baseline_update_separated": True,
        "required_user_journeys_passed": True,
        "activity_database_switch_required": False,
        "network_required": False,
        "model_weights_bytes": 0,
        "status": "PASS",
    }
    if (
        quality["figure_kind_count"] != 3
        or not quality["invalid_svg_rejected"]
        or quality["semantic_index_question_count"] != 19
        or quality["semantic_index_pii_source_count"] != 0
        or not quality["template_pass_revision_active"]
        or not quality["template_failed_revision_rejected"]
        or stale_tags < 1
    ):
        raise M3PipelineError("M3 integrated quality contract failed")
    artifacts.append(
        _write_release_json(
            config,
            "quality/m3-quality.json",
            quality,
            role="m3_quality",
        )
    )
    release_index = {
        "schema_version": "1.0",
        "state_id": config.state_id,
        "pipeline_id": config.pipeline_id,
        "pipeline_version": M3_PIPELINE_VERSION,
        "manifest_name": "state-manifest.json",
        "fact_database": (
            f"data/db/versions/{config.m1_state_id}/question_bank.sqlite3"
        ),
        "activity_database_switched": False,
        "derived_state_only": True,
        "created_at": M3_FIXED_TIMESTAMP,
    }
    artifacts.append(
        _write_release_json(
            config,
            "release-index.json",
            release_index,
            role="release_index",
        )
    )
    artifact_rows = sorted(
        artifacts,
        key=lambda item: (str(item["relative_path"]), str(item["role"])),
    )
    manifest = {
        "schema_version": "1.0",
        "state_id": config.state_id,
        "pipeline_id": config.pipeline_id,
        "pipeline_version": M3_PIPELINE_VERSION,
        "source_state_id": config.m1_state_id,
        "artifact_count": len(artifact_rows),
        "artifacts": artifact_rows,
        "artifact_index_sha256": _sha256(
            _canonical_json_bytes(artifact_rows)
        ),
        "quality": quality,
        "search_quality": {
            "hit_at_3": search_quality["hit_at_3"],
            "mrr": search_quality["mrr"],
        },
        "portable_paths_only": True,
        "network_required": False,
        "model_weights_bytes": 0,
        "created_at": M3_FIXED_TIMESTAMP,
    }
    manifest_artifact = _write_release_json(
        config,
        "state-manifest.json",
        manifest,
        role="state_manifest",
    )
    return {
        "manifest": manifest_artifact,
        "quality": quality,
        "search_quality": search_quality,
        "ui_flow": ui_flow,
    }


def _verify_m3_root(
    config: M3PipelineConfig,
    root: Path,
) -> dict[str, Any]:
    if not root.is_dir():
        raise M3PipelineError("M3 release root is missing")
    manifest = _read_json(root / "state-manifest.json")
    if (
        type(manifest) is not dict
        or manifest.get("schema_version") != "1.0"
        or manifest.get("state_id") != config.state_id
        or manifest.get("pipeline_id") != config.pipeline_id
        or manifest.get("pipeline_version") != M3_PIPELINE_VERSION
        or manifest.get("source_state_id") != config.m1_state_id
        or manifest.get("portable_paths_only") is not True
        or manifest.get("network_required") is not False
        or manifest.get("model_weights_bytes") != 0
    ):
        raise M3PipelineError("M3 state manifest identity is invalid")
    artifacts = manifest.get("artifacts")
    if (
        type(artifacts) is not list
        or manifest.get("artifact_count") != len(artifacts)
        or manifest.get("artifact_index_sha256")
        != _sha256(_canonical_json_bytes(artifacts))
    ):
        raise M3PipelineError("M3 artifact index is inconsistent")
    expected = {"state-manifest.json"}
    total_bytes = 0
    for artifact in artifacts:
        if type(artifact) is not dict:
            raise M3PipelineError("M3 artifact row is invalid")
        suffix = _artifact_suffix(
            config,
            str(artifact.get("relative_path", "")),
        )
        expected.add(suffix.as_posix())
        path = root.joinpath(*suffix.parts)
        maximum = max(1, int(artifact.get("bytes", 0)))
        payload = get_workspace_io().read_bytes(
            path,
            maximum_bytes=maximum,
        )
        if (
            len(payload) != artifact.get("bytes")
            or _sha256(payload) != artifact.get("sha256")
        ):
            raise M3PipelineError("M3 artifact digest mismatch")
        total_bytes += len(payload)
        if path.suffix == ".json":
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise M3PipelineError("M3 JSON artifact is not UTF-8") from exc
            if re.search(r"(?:[A-Za-z]:\\\\|file://|\\\\\\\\)", text):
                raise M3PipelineError(
                    "M3 release leaked an absolute machine path"
                )
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    }
    if actual != expected:
        raise M3PipelineError("M3 release contains missing or untracked files")
    quality = _read_json(root / "quality" / "m3-quality.json")
    search_quality = _read_json(
        root / "search" / "search-quality.json"
    )
    semantic_index = _read_json(
        root / "search" / "semantic-index.json"
    )
    semantic_manifest: dict[str, Any] = semantic_index["manifest"]
    taxonomy = _read_json(
        root / "taxonomy" / "taxonomy-release.json"
    )
    templates = _read_json(
        root / "templates" / "template-revisions.json"
    )
    ui_flow = _read_json(
        root / "audit" / "ui-user-journeys.json"
    )
    if (
        quality.get("status") != "PASS"
        or quality.get("figure_kind_count") != 3
        or quality.get("semantic_index_question_count") != 19
        or quality.get("semantic_index_pii_source_count") != 0
        or quality.get("template_pass_revision_active") is not True
        or quality.get("template_failed_revision_rejected") is not True
        or search_quality.get("passed") is not True
        or search_quality.get("hit_at_3") != 1.0
        or float(search_quality.get("mrr", 0)) < 0.8
        or "question_count" not in semantic_manifest
        or semantic_manifest["question_count"] != 19
        or "weights_required" not in semantic_manifest
        or semantic_manifest["weights_required"] is not False
        or taxonomy.get("status") != "approved"
        or templates.get("active_template_revision_id")
        != M3_TEMPLATE_PASS_ID
        or ui_flow.get("status") != "PASS"
    ):
        raise M3PipelineError("M3 accepted-state quality verification failed")
    for kind in ("geometry", "function", "statistics"):
        ir = _read_json(root / "figures" / kind / "figure-ir.json")
        validate_figure_ir(ir)
        svg_payload = get_workspace_io().read_bytes(
            root / "figures" / kind / "generated.svg",
            maximum_bytes=M3_MAX_SVG_BYTES,
        )
        if not validate_and_sanitize_svg(svg_payload)["monochrome"]:
            raise M3PipelineError("published generated SVG is not monochrome")
        validate_safe_tikz(
            get_workspace_io().read_bytes(
                root / "figures" / kind / "generated.tex",
                maximum_bytes=512 * 1024,
            )
        )
    manifest_payload = get_workspace_io().read_bytes(
        root / "state-manifest.json",
        maximum_bytes=M3_MAX_JSON_BYTES,
    )
    return {
        "state_id": config.state_id,
        "artifact_count": len(artifacts),
        "release_file_count": len(actual),
        "release_bytes": total_bytes + len(manifest_payload),
        "manifest_sha256": _sha256(manifest_payload),
        "artifact_index_sha256": manifest["artifact_index_sha256"],
        "figure_kind_count": quality["figure_kind_count"],
        "approved_tag_count": quality["approved_tag_count"],
        "stale_tag_count": quality["stale_tag_count"],
        "semantic_index_question_count": quality[
            "semantic_index_question_count"
        ],
        "search_hit_at_3": search_quality["hit_at_3"],
        "search_mrr": search_quality["mrr"],
        "active_template_revision_id": templates[
            "active_template_revision_id"
        ],
        "status": "PASS",
    }


def verify_m3_staging(config: M3PipelineConfig) -> dict[str, Any]:
    return _verify_m3_root(config, config.staging_root)


def verify_m3_state(config: M3PipelineConfig) -> dict[str, Any]:
    return _verify_m3_root(config, config.target_root)


def publish_m3_state(config: M3PipelineConfig) -> dict[str, Any]:
    if config.target_root.exists():
        if config.staging_root.exists():
            raise M3PipelineError("M3 target exists while staging remains")
        return {
            "operation": "ALREADY_PUBLISHED",
            "target": _relative(config.target_root),
        }
    if not config.staging_root.is_dir():
        raise M3PipelineError("M3 complete staging root is missing")
    staging_verification = verify_m3_staging(config)
    workspace = get_workspace_io()
    workspace.ensure_directory(config.target_root.parent)
    receipt = workspace.move_directory_no_replace(
        config.staging_root,
        config.target_root,
    )
    return {
        "operation": receipt.operation,
        "target": _relative(config.target_root),
        "staging_verification": staging_verification,
    }


def run_m3_real_pipeline(
    config: M3PipelineConfig,
    *,
    figure_sources: dict[str, dict[str, Any]],
    broken_svg_payload: bytes,
    font_source_payload: bytes,
) -> dict[str, Any]:
    if config.target_root.is_dir():
        first = verify_m3_state(config)
        second = verify_m3_state(config)
        return {
            "operation": "ALREADY_PUBLISHED",
            "verification": second,
            "repeat_stable": first == second,
        }
    build = build_m3_staging(
        config,
        figure_sources=figure_sources,
        broken_svg_payload=broken_svg_payload,
        font_source_payload=font_source_payload,
    )
    staging = verify_m3_staging(config)
    publication = publish_m3_state(config)
    first = verify_m3_state(config)
    second = verify_m3_state(config)
    if first != second:
        raise M3PipelineError("M3 published-state repeat verification changed")
    return {
        "operation": "PUBLISHED",
        "build": build,
        "staging_verification": staging,
        "publication": publication,
        "verification": first,
        "repeat_stable": True,
    }


def rebuild_published_semantic_index(
    config: M3PipelineConfig = M3PipelineConfig(),
) -> dict[str, Any]:
    verification = verify_m3_state(config)
    document = _read_json(config.target_root / "workbench-state.json")
    state = M3WorkbenchState(
        figures=document["figures"],
        taxonomy=document["taxonomy"],
        assertions=document["assertions"],
        documents=document["documents"],
        semantic_index=document["semantic_index"],
        templates=document["templates"],
        active_template_revision_id=document[
            "active_template_revision_id"
        ],
        history=document["history"],
        basket=document["basket"],
        solution_overrides=document["solution_overrides"],
    )
    rebuilt = build_semantic_index(
        state.documents,
        state.taxonomy,
        state.assertions,
        solution_overrides=state.solution_overrides,
    )
    published = _read_json(
        config.target_root / "search" / "semantic-index.json"
    )
    stable = rebuilt == published
    if not stable:
        raise M3PipelineError(
            "published semantic index is not reproducible from fact inputs"
        )
    return {
        "schema_version": "1.0",
        "state_id": config.state_id,
        "index_id": rebuilt["manifest"]["index_id"],
        "index_payload_sha256": rebuilt["manifest"][
            "index_payload_sha256"
        ],
        "question_count": rebuilt["manifest"]["question_count"],
        "rebuild_command": rebuilt["manifest"]["rebuild_command"],
        "published_manifest_sha256": verification["manifest_sha256"],
        "stable": True,
        "status": "PASS",
    }
