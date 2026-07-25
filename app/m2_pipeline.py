from __future__ import annotations

import copy
import hashlib
import itertools
import json
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from flask import Flask, Response, abort, render_template_string, send_file

from .database import connect_database_read_only
from .domain_models import (
    create_domain_revision,
    validate_domain_revision,
)
from .ir_contracts import validate_paper_ir, validate_question_ir
from .m1_pipeline import (
    M1PipelineConfig,
    load_copy_payload,
)
from .project_root import PROJECT_ROOT
from .safety.context import validate_safe_id
from .safety.workspace_io import WorkspaceIOError, get_workspace_io


M2_PIPELINE_VERSION = "M2-BLUEPRINT-BUNDLE-V3-EDITABLE-B5"
M2_SOLVER_VERSION = "DETERMINISTIC-EXHAUSTIVE-V1"
M2_FIXED_TIMESTAMP = "2026-07-26T00:00:00Z"
M2_PAPER_REVISION_ID = "PAPER-M2-YANYAN-FULL-150-REV-003"
M2_PAPER_IR_REVISION_ID = "PAPER-IR-M2-YANYAN-FULL-150-REV-003"
M2_BLUEPRINT_REVISION_ID = "BLUEPRINT-M2-YANYAN-FULL-150-REV-001"
M2_POOL_REVISION_ID = "POOL-M2-YANYAN-REV-002-SNAPSHOT-001"
M2_TAXONOMY_RELEASE_ID = "TAXONOMY-M2-STRUCTURAL-V1"
M2_PAPER_TEMPLATE_REVISION_ID = "TEMPLATE-M3-EDITABLE-B5-REV-002"
EDITABLE_B5_WIDTH_MM = 184.0
EDITABLE_B5_HEIGHT_MM = 260.0
EDITABLE_B5_MARGIN_LEFT_MM = 22.0
EDITABLE_B5_MARGIN_RIGHT_MM = 22.0
EDITABLE_B5_MARGIN_TOP_MM = 20.0
EDITABLE_B5_MARGIN_BOTTOM_MM = 20.0

DOCUMENT_ROLE_FILENAMES = {
    "student": "student-paper.pdf",
    "teacher": "teacher-paper.pdf",
    "answer": "answer-book.pdf",
    "detailed_solution": "solution-book.pdf",
    "answer_sheet": "answer-sheet-a4.pdf",
}
DOCUMENT_ROLES = tuple(sorted(DOCUMENT_ROLE_FILENAMES))
STUDENT_LEAK_MARKERS = (
    "参考答案",
    "【答案】",
    "【解析】",
    "答案：",
    "解析：",
)

FULL_TYPE_COUNTS = {
    "单项选择题": 8,
    "多项选择题": 3,
    "填空题": 3,
    "解答题": 5,
}
PRACTICE_TYPE_COUNTS = {
    "单项选择题": 2,
    "多项选择题": 1,
    "填空题": 1,
    "解答题": 1,
}


class M2PipelineError(RuntimeError):
    pass


class M2InjectedFailure(M2PipelineError):
    pass


@dataclass(slots=True)
class BlueprintUIState:
    selection: list[str] = field(default_factory=list)
    locks: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)
    status: str = "READY"
    unsat: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class CandidateQuestion:
    question_no: int
    qid: str
    question_revision_id: str
    question_ir_revision_id: str
    question_ir_relative_path: str
    question_ir_sha256: str
    question_type: str
    points: int
    design_difficulty: int
    observed_p: float | None
    expected_time_seconds: int
    year: int
    review_status: str
    answer_sha256: str
    analysis_sha256: str
    content_hash: str
    source_crop_relative_path: str
    approved_tag_assertion_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "question_no": self.question_no,
            "qid": self.qid,
            "question_revision_id": self.question_revision_id,
            "question_ir_revision_id": self.question_ir_revision_id,
            "question_ir_relative_path": self.question_ir_relative_path,
            "question_ir_sha256": self.question_ir_sha256,
            "question_type": self.question_type,
            "points": self.points,
            "design_difficulty": self.design_difficulty,
            "observed_p": self.observed_p,
            "expected_time_seconds": self.expected_time_seconds,
            "year": self.year,
            "review_status": self.review_status,
            "answer_sha256": self.answer_sha256,
            "analysis_sha256": self.analysis_sha256,
            "content_hash": self.content_hash,
            "source_crop_relative_path": self.source_crop_relative_path,
            "approved_tag_assertion_ids": list(
                self.approved_tag_assertion_ids
            ),
        }


@dataclass(frozen=True, slots=True)
class BlueprintSpec:
    blueprint_id: str
    revision_id: str
    seed: str
    type_counts: dict[str, int]
    total_points: int
    approved_only: bool = True
    require_answer: bool = True
    require_analysis: bool = True
    years: tuple[int, ...] = (2026,)
    minimum_difficulty: int = 1
    maximum_difficulty: int = 5
    maximum_time_seconds: int | None = None
    target_difficulty_sum: int | None = None
    target_time_seconds: int | None = None
    approved_tag_assertion_ids: tuple[str, ...] = ()
    knowledge_tag_assertion_ids: tuple[str, ...] = ()
    method_tag_assertion_ids: tuple[str, ...] = ()
    maximum_exact_content_duplicates: int = 0

    def __post_init__(self) -> None:
        validate_safe_id(self.blueprint_id, field_name="blueprint_id")
        validate_safe_id(self.revision_id, field_name="revision_id")
        validate_safe_id(self.seed, field_name="seed")
        if not self.type_counts or any(
            type(count) is not int or count < 0
            for count in self.type_counts.values()
        ):
            raise M2PipelineError("blueprint type counts must be non-negative integers")
        if self.total_points <= 0:
            raise M2PipelineError("blueprint total points must be positive")
        if not self.years:
            raise M2PipelineError("blueprint years cannot be empty")
        if (
            type(self.maximum_exact_content_duplicates) is not int
            or self.maximum_exact_content_duplicates < 0
        ):
            raise M2PipelineError(
                "maximum exact-content duplicates must be non-negative"
            )

    def constraint_rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = [
            {
                "kind": "hard",
                "field": "review_status",
                "operator": "equals",
                "value": "approved",
            },
            {
                "kind": "hard",
                "field": "answer_ready",
                "operator": "equals",
                "value": self.require_answer,
            },
            {
                "kind": "hard",
                "field": "analysis_ready",
                "operator": "equals",
                "value": self.require_analysis,
            },
            {
                "kind": "hard",
                "field": "year",
                "operator": "in",
                "value": list(self.years),
            },
            {
                "kind": "hard",
                "field": "design_difficulty",
                "operator": "between",
                "value": [self.minimum_difficulty, self.maximum_difficulty],
            },
            {
                "kind": "hard",
                "field": "type_counts",
                "operator": "equals",
                "value": dict(sorted(self.type_counts.items())),
            },
            {
                "kind": "hard",
                "field": "total_points",
                "operator": "equals",
                "value": self.total_points,
            },
            {
                "kind": "hard",
                "field": "approved_tag_assertion_ids",
                "operator": "subset",
                "value": list(self.approved_tag_assertion_ids),
            },
            {
                "kind": "hard",
                "field": "approved_knowledge_tag_assertion_ids",
                "operator": "subset",
                "value": list(self.knowledge_tag_assertion_ids),
            },
            {
                "kind": "hard",
                "field": "approved_method_tag_assertion_ids",
                "operator": "subset",
                "value": list(self.method_tag_assertion_ids),
            },
            {
                "kind": "hard",
                "field": "exact_content_hash_duplicate_count",
                "operator": "less_than_or_equal",
                "value": self.maximum_exact_content_duplicates,
            },
        ]
        if self.maximum_time_seconds is not None:
            rows.append(
                {
                    "kind": "hard",
                    "field": "expected_time_seconds",
                    "operator": "less_than_or_equal",
                    "value": self.maximum_time_seconds,
                }
            )
        if self.target_difficulty_sum is not None:
            rows.append(
                {
                    "kind": "soft",
                    "field": "design_difficulty_sum",
                    "operator": "nearest",
                    "value": self.target_difficulty_sum,
                }
            )
        if self.target_time_seconds is not None:
            rows.append(
                {
                    "kind": "soft",
                    "field": "expected_time_seconds",
                    "operator": "nearest",
                    "value": self.target_time_seconds,
                }
            )
        return rows

    def to_dict(self) -> dict[str, Any]:
        return {
            "blueprint_id": self.blueprint_id,
            "revision_id": self.revision_id,
            "solver_version": M2_SOLVER_VERSION,
            "seed": self.seed,
            "constraints": self.constraint_rows(),
        }


@dataclass(frozen=True, slots=True)
class SolveResult:
    feasible: bool
    selected_revision_ids: tuple[str, ...]
    locked_revision_ids: tuple[str, ...]
    excluded_revision_ids: tuple[str, ...]
    coverage: dict[str, Any]
    selection_reasons: dict[str, list[str]]
    unsat_core: tuple[str, ...]
    diagnostics: dict[str, Any]
    solver_version: str = M2_SOLVER_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "feasible": self.feasible,
            "selected_revision_ids": list(self.selected_revision_ids),
            "locked_revision_ids": list(self.locked_revision_ids),
            "excluded_revision_ids": list(self.excluded_revision_ids),
            "coverage": self.coverage,
            "selection_reasons": self.selection_reasons,
            "unsat_core": list(self.unsat_core),
            "diagnostics": self.diagnostics,
            "solver_version": self.solver_version,
        }


@dataclass(frozen=True, slots=True)
class M2PipelineConfig:
    job_id: str = "JOB-M2-YANYAN-BUNDLE-R3-20260726"
    export_object_id: str = "EXPORT-M2-YANYAN-FULL-150"
    export_id: str = "EXPORT-M2-YANYAN-FULL-150-REV-003"
    pipeline_id: str = "M2"
    m1_state_id: str = "STATE-M1-YANYAN-REV-002"
    m1_paper_object_id: str = "PAPER-YANYAN-202605"
    m1_paper_revision: str = "REV-002"
    data_source_root_relative: str = "."

    def __post_init__(self) -> None:
        for field_name in (
            "job_id",
            "export_object_id",
            "export_id",
            "pipeline_id",
            "m1_state_id",
            "m1_paper_object_id",
            "m1_paper_revision",
        ):
            validate_safe_id(str(getattr(self, field_name)), field_name=field_name)
        source_root = PurePosixPath(self.data_source_root_relative)
        if (
            self.data_source_root_relative == "."
            or (
                not source_root.is_absolute()
                and "\\" not in self.data_source_root_relative
                and len(source_root.parts) >= 4
                and source_root.parts[0] in {"data", "tmp"}
                and (
                    source_root.parts[:2] == ("data", "snapshots")
                    or source_root.parts[:3] == ("tmp", "jobs", "INTERNAL")
                )
                and all(part not in {"", ".", ".."} for part in source_root.parts)
            )
        ):
            return
        raise M2PipelineError(
            "M2 data source root must be the project root, a restored snapshot, "
            "or an INTERNAL restore staging root"
        )

    @property
    def data_source_root(self) -> Path:
        if self.data_source_root_relative == ".":
            return PROJECT_ROOT
        return PROJECT_ROOT.joinpath(
            *PurePosixPath(self.data_source_root_relative).parts
        )

    @property
    def job_root(self) -> Path:
        return PROJECT_ROOT / "tmp" / "jobs" / "INTERNAL" / self.job_id

    @property
    def bundle_staging_root(self) -> Path:
        return self.job_root / "bundle-release"

    @property
    def bundle_target_root(self) -> Path:
        return (
            self.data_source_root
            / "data"
            / "exports"
            / self.pipeline_id
            / self.export_id
        )

    @property
    def m1_database_path(self) -> Path:
        return (
            self.data_source_root
            / "data"
            / "db"
            / "versions"
            / self.m1_state_id
            / "question_bank.sqlite3"
        )

    @property
    def m1_derived_root(self) -> Path:
        return (
            self.data_source_root
            / "data"
            / "derived"
            / "papers"
            / "M1-REAL-PIPELINE"
            / self.m1_paper_object_id
            / self.m1_paper_revision
        )


def full_blueprint_spec() -> BlueprintSpec:
    return BlueprintSpec(
        blueprint_id="BLUEPRINT-M2-YANYAN-FULL-150",
        revision_id=M2_BLUEPRINT_REVISION_ID,
        seed="SEED-M2-FULL-150-V1",
        type_counts=FULL_TYPE_COUNTS,
        total_points=150,
        maximum_time_seconds=6600,
        target_difficulty_sum=46,
        target_time_seconds=6600,
    )


def practice_blueprint_spec() -> BlueprintSpec:
    return BlueprintSpec(
        blueprint_id="BLUEPRINT-M2-PRACTICE-34",
        revision_id="BLUEPRINT-M2-PRACTICE-34-REV-001",
        seed="SEED-M2-PRACTICE-34-V1",
        type_counts=PRACTICE_TYPE_COUNTS,
        total_points=34,
        maximum_time_seconds=1800,
        target_difficulty_sum=8,
        target_time_seconds=1320,
    )


def infeasible_blueprint_spec() -> BlueprintSpec:
    return replace(
        practice_blueprint_spec(),
        blueprint_id="BLUEPRINT-M2-INFEASIBLE-999",
        revision_id="BLUEPRINT-M2-INFEASIBLE-999-REV-001",
        seed="SEED-M2-INFEASIBLE-V1",
        total_points=999,
    )


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
        raise M2PipelineError("M2 path escaped the project root") from exc


def _read_json(path: Path, *, maximum_bytes: int = 8 * 1024 * 1024) -> Any:
    payload = get_workspace_io().read_bytes(path, maximum_bytes=maximum_bytes)
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise M2PipelineError("M2 JSON artifact is invalid") from exc


def _write_bundle_bytes(
    config: M2PipelineConfig,
    relative_path: str,
    payload: bytes,
    *,
    role: str,
) -> dict[str, Any]:
    path = config.bundle_staging_root / Path(relative_path)
    receipt = get_workspace_io().write_bytes_idempotent(path, payload)
    return {
        "role": role,
        "relative_path": (
            _relative(config.bundle_target_root) + "/" + Path(relative_path).as_posix()
        ),
        "bytes": receipt.size_bytes,
        "sha256": receipt.sha256,
    }


def _write_bundle_json(
    config: M2PipelineConfig,
    relative_path: str,
    value: Any,
    *,
    role: str,
) -> dict[str, Any]:
    return _write_bundle_bytes(
        config,
        relative_path,
        _canonical_json_bytes(value, pretty=True),
        role=role,
    )


def load_candidate_pool(
    config: M2PipelineConfig | None = None,
) -> tuple[CandidateQuestion, ...]:
    config = config or M2PipelineConfig()
    paper_ir = _read_json(config.m1_derived_root / "ir" / "paper-ir.json")
    validate_paper_ir(paper_ir)
    revision_by_number: dict[int, str] = {}
    for section in paper_ir["sections"]:
        for entry in section["question_entries"]:
            revision_by_number[int(entry["display_number"])] = str(
                entry["question_revision_id"]
            )

    candidates: list[CandidateQuestion] = []
    with connect_database_read_only(
        config.m1_database_path.resolve(),
        immutable=True,
    ) as connection:
        paper_revision_id = (
            f"{config.m1_paper_object_id}-{config.m1_paper_revision}"
        )
        rows = connection.execute(
            """
            SELECT qid, question_no, question_type, answer_text, analysis_latex,
                   difficulty, year, review_status, meta_json, content_hash,
                   raw_crop_path
              FROM questions
             WHERE json_extract(meta_json, '$.paper_revision_id') = ?
             ORDER BY CAST(question_no AS INTEGER)
            """,
            (paper_revision_id,),
        ).fetchall()
    for row in rows:
        number = int(row["question_no"])
        meta = json.loads(row["meta_json"])
        ir_path = config.data_source_root / str(meta["question_ir_path"])
        ir_payload = get_workspace_io().read_bytes(
            ir_path,
            maximum_bytes=2 * 1024 * 1024,
        )
        question_ir = json.loads(ir_payload.decode("utf-8"))
        validate_question_ir(question_ir)
        if (
            row["review_status"] != "approved"
            or not str(row["answer_text"] or "").strip()
            or not str(row["analysis_latex"] or "").strip()
            or meta.get("observed_p") is not None
            or int(meta["score_points"]) != int(question_ir["points"])
            or question_ir["revision_id"] != meta["question_ir_revision_id"]
        ):
            raise M2PipelineError("M1 candidate pool contains an ineligible question")
        candidates.append(
            CandidateQuestion(
                question_no=number,
                qid=str(row["qid"]),
                question_revision_id=revision_by_number[number],
                question_ir_revision_id=str(question_ir["revision_id"]),
                question_ir_relative_path=_relative(ir_path),
                question_ir_sha256=_sha256(ir_payload),
                question_type=str(row["question_type"]),
                points=int(meta["score_points"]),
                design_difficulty=int(meta["design_difficulty"]),
                observed_p=None,
                expected_time_seconds=int(meta["expected_time_seconds"]),
                year=int(row["year"]),
                review_status=str(row["review_status"]),
                answer_sha256=_sha256(str(row["answer_text"]).encode("utf-8")),
                analysis_sha256=_sha256(
                    str(row["analysis_latex"]).encode("utf-8")
                ),
                content_hash=str(row["content_hash"]),
                source_crop_relative_path=str(row["raw_crop_path"]),
                approved_tag_assertion_ids=tuple(
                    sorted(
                        str(assertion_id)
                        for assertion_id in meta.get(
                            "approved_tag_assertion_ids",
                            (),
                        )
                    )
                ),
            )
        )
    if len(candidates) != 19 or sorted(revision_by_number) != list(range(1, 20)):
        raise M2PipelineError("M2 requires the complete M1 question set")
    return tuple(candidates)


def _eligible_candidates(
    candidates: Iterable[CandidateQuestion],
    spec: BlueprintSpec,
    *,
    excluded: frozenset[str],
) -> tuple[CandidateQuestion, ...]:
    required_assertions = frozenset(
        (
            *spec.approved_tag_assertion_ids,
            *spec.knowledge_tag_assertion_ids,
            *spec.method_tag_assertion_ids,
        )
    )
    return tuple(
        candidate
        for candidate in candidates
        if candidate.question_revision_id not in excluded
        and (not spec.approved_only or candidate.review_status == "approved")
        and (not spec.require_answer or bool(candidate.answer_sha256))
        and (not spec.require_analysis or bool(candidate.analysis_sha256))
        and candidate.year in spec.years
        and spec.minimum_difficulty
        <= candidate.design_difficulty
        <= spec.maximum_difficulty
        and required_assertions.issubset(
            candidate.approved_tag_assertion_ids
        )
    )


def solve_blueprint(
    candidates: Iterable[CandidateQuestion],
    spec: BlueprintSpec,
    *,
    locked_revision_ids: Iterable[str] = (),
    excluded_revision_ids: Iterable[str] = (),
) -> SolveResult:
    candidate_rows = tuple(candidates)
    by_id = {row.question_revision_id: row for row in candidate_rows}
    locked = frozenset(locked_revision_ids)
    excluded = frozenset(excluded_revision_ids)
    if locked & excluded:
        raise M2PipelineError("a question cannot be both locked and excluded")
    if any(revision_id not in by_id for revision_id in locked | excluded):
        raise M2PipelineError("lock/exclusion references an unknown question")

    eligible = _eligible_candidates(candidate_rows, spec, excluded=excluded)
    eligible_by_id = {row.question_revision_id: row for row in eligible}
    if any(revision_id not in eligible_by_id for revision_id in locked):
        return _infeasible_result(
            spec,
            locked,
            excluded,
            eligible,
            ("locked_question_is_not_eligible",),
        )

    locked_rows = tuple(eligible_by_id[revision_id] for revision_id in sorted(locked))
    locked_counts = {
        question_type: sum(
            row.question_type == question_type for row in locked_rows
        )
        for question_type in spec.type_counts
    }
    unsat: list[str] = []
    option_groups: list[tuple[tuple[CandidateQuestion, ...], ...]] = []
    for question_type, target_count in sorted(spec.type_counts.items()):
        required = target_count - locked_counts[question_type]
        available = tuple(
            row
            for row in eligible
            if row.question_type == question_type
            and row.question_revision_id not in locked
        )
        if required < 0:
            unsat.append(f"locked_count_exceeds_type_count:{question_type}")
            continue
        if len(available) < required:
            unsat.append(f"insufficient_type_capacity:{question_type}")
            continue
        option_groups.append(tuple(itertools.combinations(available, required)))
    if unsat:
        return _infeasible_result(spec, locked, excluded, eligible, tuple(unsat))

    best_rows: tuple[CandidateQuestion, ...] | None = None
    best_objective: tuple[int, int, str] | None = None
    saw_points_and_time_candidate = False
    saw_duplicate_conflict = False
    for grouped in itertools.product(*option_groups):
        selected = tuple(
            sorted(
                (*locked_rows, *(row for group in grouped for row in group)),
                key=lambda row: row.question_no,
            )
        )
        if len({row.question_revision_id for row in selected}) != len(selected):
            continue
        total_points = sum(row.points for row in selected)
        total_time = sum(row.expected_time_seconds for row in selected)
        if total_points != spec.total_points:
            continue
        if (
            spec.maximum_time_seconds is not None
            and total_time > spec.maximum_time_seconds
        ):
            continue
        saw_points_and_time_candidate = True
        difficulty_sum = sum(row.design_difficulty for row in selected)
        duplicate_count = len(selected) - len(
            {row.content_hash for row in selected}
        )
        if duplicate_count > spec.maximum_exact_content_duplicates:
            saw_duplicate_conflict = True
            continue
        difficulty_distance = (
            abs(difficulty_sum - spec.target_difficulty_sum)
            if spec.target_difficulty_sum is not None
            else 0
        )
        time_distance = (
            abs(total_time - spec.target_time_seconds)
            if spec.target_time_seconds is not None
            else 0
        )
        tie_payload = (
            spec.seed
            + "\0"
            + "\0".join(row.question_revision_id for row in selected)
        ).encode("utf-8")
        objective = (difficulty_distance, time_distance, _sha256(tie_payload))
        if best_objective is None or objective < best_objective:
            best_rows = selected
            best_objective = objective
    if best_rows is None:
        unsat_core: list[str] = []
        if saw_duplicate_conflict:
            unsat_core.append("exact_content_hash_duplicate_conflict")
        if not saw_points_and_time_candidate:
            unsat_core.append(
                "total_points_or_time_incompatible_with_type_counts"
            )
        unsat_core.append("hard_constraints_not_relaxed")
        return _infeasible_result(
            spec,
            locked,
            excluded,
            eligible,
            tuple(unsat_core),
        )

    selected_ids = tuple(row.question_revision_id for row in best_rows)
    coverage = _coverage(best_rows)
    reasons = {
        row.question_revision_id: [
            f"type_count:{row.question_type}",
            f"points:{row.points}",
            f"approved:{row.review_status == 'approved'}",
            f"design_difficulty:{row.design_difficulty}",
            "locked_by_operator"
            if row.question_revision_id in locked
            else "deterministic_solver_selection",
        ]
        for row in best_rows
    }
    return SolveResult(
        feasible=True,
        selected_revision_ids=selected_ids,
        locked_revision_ids=tuple(sorted(locked)),
        excluded_revision_ids=tuple(sorted(excluded)),
        coverage=coverage,
        selection_reasons=reasons,
        unsat_core=(),
        diagnostics={
            "hard_constraints_satisfied": True,
            "hard_constraints_relaxed": False,
            "objective": {
                "difficulty_distance": best_objective[0],
                "time_distance_seconds": best_objective[1],
                "seeded_tiebreak_sha256": best_objective[2],
            },
            "duplicate_conflicts": [],
            "similarity_policy": "EXACT-CONTENT-HASH-V1",
        },
    )


def _coverage(rows: Iterable[CandidateQuestion]) -> dict[str, Any]:
    selected = tuple(rows)
    counts: dict[str, int] = {}
    for row in selected:
        counts[row.question_type] = counts.get(row.question_type, 0) + 1
    return {
        "question_count": len(selected),
        "type_counts": dict(sorted(counts.items())),
        "total_points": sum(row.points for row in selected),
        "design_difficulty_sum": sum(
            row.design_difficulty for row in selected
        ),
        "expected_time_seconds": sum(
            row.expected_time_seconds for row in selected
        ),
        "years": sorted({row.year for row in selected}),
        "approved_count": sum(row.review_status == "approved" for row in selected),
        "answer_ready_count": sum(bool(row.answer_sha256) for row in selected),
        "analysis_ready_count": sum(bool(row.analysis_sha256) for row in selected),
    }


def _infeasible_result(
    spec: BlueprintSpec,
    locked: frozenset[str],
    excluded: frozenset[str],
    eligible: tuple[CandidateQuestion, ...],
    unsat_core: tuple[str, ...],
) -> SolveResult:
    capacity: dict[str, int] = {}
    for row in eligible:
        capacity[row.question_type] = capacity.get(row.question_type, 0) + 1
    return SolveResult(
        feasible=False,
        selected_revision_ids=(),
        locked_revision_ids=tuple(sorted(locked)),
        excluded_revision_ids=tuple(sorted(excluded)),
        coverage={},
        selection_reasons={},
        unsat_core=unsat_core,
        diagnostics={
            "hard_constraints_satisfied": False,
            "hard_constraints_relaxed": False,
            "requested_total_points": spec.total_points,
            "eligible_type_capacity": dict(sorted(capacity.items())),
            "eligible_question_count": len(eligible),
        },
    )


BLUEPRINT_UI_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>M2 蓝图工作台</title></head>
<body>
  <h1>M2 蓝图工作台</h1>
  <p id="status">{{ status }}</p>
  <p id="selection">{{ selection|join(', ') }}</p>
  <p id="locks">{{ locks|join(', ') }}</p>
  <p id="unsat">{{ unsat|join(', ') }}</p>
  <form method="post" action="/blueprints/practice/solve">
    <button type="submit">求解可行蓝图</button>
  </form>
  <form method="post" action="/blueprints/infeasible/solve">
    <button type="submit">诊断不可行蓝图</button>
  </form>
  {% for revision_id in selection %}
  <section data-question-revision-id="{{ revision_id }}">
    <span>{{ revision_id }}</span>
    <form method="post" action="/blueprints/practice/lock/{{ revision_id }}">
      <button type="submit">锁题</button>
    </form>
    <form method="post" action="/blueprints/practice/replace/{{ revision_id }}">
      <button type="submit">换题</button>
    </form>
    <form method="post" action="/blueprints/practice/move/{{ revision_id }}/up">
      <button type="submit">上移</button>
    </form>
    <form method="post" action="/blueprints/practice/move/{{ revision_id }}/down">
      <button type="submit">下移</button>
    </form>
  </section>
  {% endfor %}
</body>
</html>
"""


def create_blueprint_app(
    candidates: tuple[CandidateQuestion, ...],
    *,
    config: M2PipelineConfig | None = None,
    state: BlueprintUIState | None = None,
) -> Flask:
    config = config or M2PipelineConfig()
    app = Flask(__name__)
    state = state or BlueprintUIState()
    app.extensions["m2_blueprint_state"] = state

    def render_state(*, status_code: int = 200) -> tuple[str, int]:
        return (
            render_template_string(
                BLUEPRINT_UI_TEMPLATE,
                status=state.status,
                selection=state.selection,
                locks=state.locks,
                unsat=state.unsat,
            ),
            status_code,
        )

    @app.get("/blueprints")
    def blueprint_home() -> tuple[str, int]:
        return render_state()

    @app.post("/blueprints/practice/solve")
    def blueprint_solve() -> tuple[str, int]:
        result = solve_blueprint(candidates, practice_blueprint_spec())
        if not result.feasible:
            raise M2PipelineError("the fixed practice blueprint became infeasible")
        state.selection = list(result.selected_revision_ids)
        state.locks = []
        state.excluded = []
        state.unsat = []
        state.status = "FEASIBLE"
        state.history.append(
            {
                "sequence": len(state.history) + 1,
                "action": "solve",
                "result": result.to_dict(),
            }
        )
        return render_state()

    @app.post("/blueprints/practice/lock/<revision_id>")
    def blueprint_lock(revision_id: str) -> tuple[str, int]:
        if revision_id not in state.selection:
            abort(404)
        if revision_id not in state.locks:
            state.locks.append(revision_id)
            state.locks.sort()
        state.status = "LOCKED"
        state.history.append(
            {
                "sequence": len(state.history) + 1,
                "action": "lock",
                "question_revision_id": revision_id,
            }
        )
        return render_state()

    @app.post("/blueprints/practice/replace/<revision_id>")
    def blueprint_replace(revision_id: str) -> tuple[str, int]:
        if revision_id not in state.selection or revision_id in state.locks:
            abort(409)
        if revision_id not in state.excluded:
            state.excluded.append(revision_id)
            state.excluded.sort()
        result = solve_blueprint(
            candidates,
            practice_blueprint_spec(),
            locked_revision_ids=state.locks,
            excluded_revision_ids=state.excluded,
        )
        if not result.feasible:
            state.status = "REPLACEMENT_INFEASIBLE"
            state.unsat = list(result.unsat_core)
            return render_state(status_code=409)
        previous = list(state.selection)
        state.selection = list(result.selected_revision_ids)
        state.status = "REPLACED"
        state.history.append(
            {
                "sequence": len(state.history) + 1,
                "action": "replace",
                "removed_question_revision_id": revision_id,
                "before": previous,
                "after": list(result.selected_revision_ids),
                "result": result.to_dict(),
            }
        )
        return render_state()

    @app.post("/blueprints/practice/move/<revision_id>/<direction>")
    def blueprint_move(revision_id: str, direction: str) -> tuple[str, int]:
        if revision_id not in state.selection or direction not in {"up", "down"}:
            abort(404)
        index = state.selection.index(revision_id)
        target_index = index - 1 if direction == "up" else index + 1
        if target_index < 0 or target_index >= len(state.selection):
            abort(409)
        previous = list(state.selection)
        state.selection[index], state.selection[target_index] = (
            state.selection[target_index],
            state.selection[index],
        )
        state.status = "REORDERED"
        state.history.append(
            {
                "sequence": len(state.history) + 1,
                "action": "reorder",
                "question_revision_id": revision_id,
                "direction": direction,
                "before": previous,
                "after": list(state.selection),
            }
        )
        return render_state()

    @app.post("/blueprints/infeasible/solve")
    def blueprint_infeasible() -> tuple[str, int]:
        result = solve_blueprint(candidates, infeasible_blueprint_spec())
        if result.feasible:
            raise M2PipelineError("the fixed infeasible blueprint unexpectedly solved")
        state.status = "INFEASIBLE"
        state.unsat = list(result.unsat_core)
        state.history.append(
            {
                "sequence": len(state.history) + 1,
                "action": "diagnose_infeasible",
                "result": result.to_dict(),
            }
        )
        return render_state(status_code=409)

    @app.get("/bundles/<export_id>/<role>")
    def bundle_download(export_id: str, role: str) -> Response:
        if export_id != config.export_id or role not in DOCUMENT_ROLE_FILENAMES:
            abort(404)
        target = config.bundle_target_root / "documents" / DOCUMENT_ROLE_FILENAMES[role]
        if not target.is_file():
            abort(404)
        try:
            approved = get_workspace_io().validate_read_file_path(target)
        except WorkspaceIOError:
            abort(404)
        return send_file(approved, mimetype="application/pdf")

    return app


def run_blueprint_ui_flow(
    candidates: tuple[CandidateQuestion, ...],
    *,
    config: M2PipelineConfig | None = None,
) -> dict[str, Any]:
    app = create_blueprint_app(candidates, config=config)
    app.config["TESTING"] = True
    client = app.test_client()
    home_status = client.get("/blueprints").status_code
    solve_status = client.post("/blueprints/practice/solve").status_code
    state = app.extensions["m2_blueprint_state"]
    initial = tuple(state.selection)
    if len(initial) != 5:
        raise M2PipelineError("practice UI solve returned the wrong question count")
    by_id = {row.question_revision_id: row for row in candidates}
    pool_counts: dict[str, int] = {}
    for row in candidates:
        pool_counts[row.question_type] = pool_counts.get(row.question_type, 0) + 1
    replaceable = [
        revision_id
        for revision_id in initial
        if pool_counts[by_id[revision_id].question_type]
        > PRACTICE_TYPE_COUNTS[by_id[revision_id].question_type]
    ]
    if len(replaceable) < 2:
        raise M2PipelineError("practice blueprint has no lock/replace choice")
    locked = replaceable[0]
    removed = replaceable[1]
    lock_status = client.post(
        f"/blueprints/practice/lock/{locked}"
    ).status_code
    replace_status = client.post(
        f"/blueprints/practice/replace/{removed}"
    ).status_code
    replaced_selection = tuple(state.selection)
    reordered_question = replaced_selection[-1]
    reorder_status = client.post(
        f"/blueprints/practice/move/{reordered_question}/up"
    ).status_code
    final_selection = tuple(state.selection)
    infeasible_status = client.post(
        "/blueprints/infeasible/solve"
    ).status_code
    if (
        home_status != 200
        or solve_status != 200
        or lock_status != 200
        or replace_status != 200
        or reorder_status != 200
        or infeasible_status != 409
        or locked not in final_selection
        or removed in final_selection
        or set(final_selection) == set(initial)
        or set(final_selection) != set(replaced_selection)
        or final_selection == replaced_selection
    ):
        raise M2PipelineError("M2 blueprint UI flow failed")
    return {
        "home_status": home_status,
        "solve_status": solve_status,
        "lock_status": lock_status,
        "replace_status": replace_status,
        "reorder_status": reorder_status,
        "infeasible_status": infeasible_status,
        "initial_selection": list(initial),
        "locked_question_revision_id": locked,
        "removed_question_revision_id": removed,
        "reordered_question_revision_id": reordered_question,
        "final_selection": list(final_selection),
        "history": copy.deepcopy(state.history),
        "infeasible_unsat_core": list(state.unsat),
    }


def build_frozen_paper_snapshot(
    candidates: tuple[CandidateQuestion, ...],
    solve_result: SolveResult,
) -> dict[str, Any]:
    if not solve_result.feasible:
        raise M2PipelineError("cannot freeze an infeasible solve result")
    by_id = {row.question_revision_id: row for row in candidates}
    selected = [by_id[revision_id] for revision_id in solve_result.selected_revision_ids]
    snapshot = {
        "schema_version": "1.0",
        "paper_revision_id": M2_PAPER_REVISION_ID,
        "blueprint_revision_id": M2_BLUEPRINT_REVISION_ID,
        "candidate_pool_snapshot_id": M2_POOL_REVISION_ID,
        "solver_version": M2_SOLVER_VERSION,
        "seed": full_blueprint_spec().seed,
        "question_revision_ids": [
            row.question_revision_id for row in selected
        ],
        "questions": [
            {
                "display_number": row.question_no,
                "question_revision_id": row.question_revision_id,
                "question_ir_revision_id": row.question_ir_revision_id,
                "question_ir_sha256": row.question_ir_sha256,
                "content_hash": row.content_hash,
                "points": row.points,
                "answer_sha256": row.answer_sha256,
                "analysis_sha256": row.analysis_sha256,
            }
            for row in selected
        ],
        "coverage": solve_result.coverage,
        "created_at": M2_FIXED_TIMESTAMP,
    }
    snapshot["snapshot_sha256"] = _sha256(_canonical_json_bytes(snapshot))
    return snapshot


def _m2_paper_ir(config: M2PipelineConfig) -> dict[str, Any]:
    source = _read_json(config.m1_derived_root / "ir" / "paper-ir.json")
    document = copy.deepcopy(source)
    document["ir_id"] = "PAPER-IR-M2-YANYAN-FULL-150"
    document["revision_id"] = M2_PAPER_IR_REVISION_ID
    document["paper_revision_id"] = M2_PAPER_REVISION_ID
    document["template_revision_id"] = M2_PAPER_TEMPLATE_REVISION_ID
    document["document_roles"] = list(DOCUMENT_ROLES)
    document["extensions"] = {
        "x-source-composition": True,
        "x-source-page-count": 4,
        "x-frozen-from-paper-ir": str(source["revision_id"]),
        "x-bundle-document-count": 5,
        "x-page-family": "EDITABLE-B5-184X260",
        "x-reference-logical-id": "REF-TEMPLATE-PAPER",
    }
    validate_paper_ir(document)
    return document


def _domain_revisions(
    config: M2PipelineConfig,
    *,
    candidates: tuple[CandidateQuestion, ...],
    full_spec: BlueprintSpec,
    paper_snapshot: dict[str, Any],
    paper_ir: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    pool_query_contract = {
        "m1_state_id": config.m1_state_id,
        "review_status": "approved",
        "require_answer": True,
        "require_analysis": True,
        "question_revision_ids": [
            row.question_revision_id for row in candidates
        ],
    }
    blueprint = create_domain_revision(
        object_type="blueprint_revision",
        object_id=full_spec.blueprint_id,
        revision_id=full_spec.revision_id,
        revision_no=1,
        state="approved",
        created_at=M2_FIXED_TIMESTAMP,
        predecessor_revision_id=None,
        payload={
            "taxonomy_release_id": M2_TAXONOMY_RELEASE_ID,
            "constraints": full_spec.constraint_rows(),
        },
        extensions={
            "x-solver-version": M2_SOLVER_VERSION,
            "x-seed": full_spec.seed,
        },
    ).document
    pool = create_domain_revision(
        object_type="candidate_pool_snapshot",
        object_id="POOL-M2-YANYAN-REV-002",
        revision_id=M2_POOL_REVISION_ID,
        revision_no=1,
        state="approved",
        created_at=M2_FIXED_TIMESTAMP,
        predecessor_revision_id=None,
        payload={
            "question_revision_ids": [
                row.question_revision_id for row in candidates
            ],
            "query_contract_sha256": _sha256(
                _canonical_json_bytes(pool_query_contract)
            ),
        },
        extensions={
            "x-source-state-id": config.m1_state_id,
            "x-question-count": len(candidates),
        },
    ).document
    paper = create_domain_revision(
        object_type="paper_revision",
        object_id="PAPER-M2-YANYAN-FULL-150",
        revision_id=M2_PAPER_REVISION_ID,
        revision_no=3,
        state="approved",
        created_at=M2_FIXED_TIMESTAMP,
        predecessor_revision_id="PAPER-M2-YANYAN-FULL-150-REV-002",
        payload={
            "paper_ir_revision_id": str(paper_ir["revision_id"]),
            "blueprint_revision_id": full_spec.revision_id,
            "candidate_pool_snapshot_id": M2_POOL_REVISION_ID,
        },
        extensions={
            "x-question-snapshot-sha256": str(
                paper_snapshot["snapshot_sha256"]
            ),
            "x-declared-total-points": 150,
        },
    ).document
    for document in (blueprint, pool, paper):
        validate_domain_revision(document)
    return {"blueprint": blueprint, "pool": pool, "paper": paper}


def _compose_pdfs(parts: tuple[bytes, ...]) -> bytes:
    import fitz

    output = fitz.open()
    try:
        for payload in parts:
            with fitz.open(stream=payload, filetype="pdf") as source:
                output.insert_pdf(source)
        output.set_metadata(
            {
                "title": "M2 teacher paper",
                "author": "Local Exam Bank",
                "subject": M2_PAPER_REVISION_ID,
                "keywords": M2_PIPELINE_VERSION,
                "creator": M2_PIPELINE_VERSION,
                "producer": "PyMuPDF deterministic source composition",
                "creationDate": "D:20260726000000+00'00'",
                "modDate": "D:20260726000000+00'00'",
            }
        )
        return output.tobytes(garbage=4, deflate=True, no_new_id=True)
    finally:
        output.close()


def _page_content_bbox(page: Any) -> Any:
    """Measure visible source content while ignoring a full-page background."""

    import fitz

    visible: list[Any] = []
    for _kind, raw_bbox in page.get_bboxlog():
        bbox = fitz.Rect(raw_bbox) & page.rect
        if bbox.is_empty or bbox.width <= 0 or bbox.height <= 0:
            continue
        if (
            bbox.width >= page.rect.width * 0.98
            and bbox.height >= page.rect.height * 0.98
        ):
            continue
        visible.append(bbox)
    if not visible:
        raise M2PipelineError("source page has no measurable visible content")
    result = fitz.Rect(visible[0])
    for bbox in visible[1:]:
        result |= bbox
    return result


def _repage_pdf_to_editable_b5(payload: bytes, *, title: str) -> bytes:
    """Place the measured source body in the contracted 184 x 260 mm frame."""

    import fitz

    width = EDITABLE_B5_WIDTH_MM * 72.0 / 25.4
    height = EDITABLE_B5_HEIGHT_MM * 72.0 / 25.4
    content_rect = fitz.Rect(
        EDITABLE_B5_MARGIN_LEFT_MM * 72.0 / 25.4,
        EDITABLE_B5_MARGIN_TOP_MM * 72.0 / 25.4,
        width - EDITABLE_B5_MARGIN_RIGHT_MM * 72.0 / 25.4,
        height - EDITABLE_B5_MARGIN_BOTTOM_MM * 72.0 / 25.4,
    )
    output = fitz.open()
    try:
        with fitz.open(stream=payload, filetype="pdf") as source:
            if source.page_count < 1:
                raise M2PipelineError("source PDF has no pages")
            for page_no, source_page in enumerate(source):
                clip = _page_content_bbox(source_page)
                scale = min(
                    content_rect.width / clip.width,
                    content_rect.height / clip.height,
                )
                placed_width = clip.width * scale
                placed_height = clip.height * scale
                destination = fitz.Rect(
                    content_rect.x0 + (content_rect.width - placed_width) / 2,
                    content_rect.y0 + (content_rect.height - placed_height) / 2,
                    content_rect.x0
                    + (content_rect.width - placed_width) / 2
                    + placed_width,
                    content_rect.y0
                    + (content_rect.height - placed_height) / 2
                    + placed_height,
                )
                target_page = output.new_page(width=width, height=height)
                target_page.show_pdf_page(
                    destination,
                    source,
                    page_no,
                    clip=clip,
                    keep_proportion=True,
                )
        output.set_metadata(
            {
                "title": title,
                "author": "Local Exam Bank",
                "subject": M2_PAPER_REVISION_ID,
                "keywords": "REF-TEMPLATE-PAPER EDITABLE-B5-184X260",
                "creator": M2_PIPELINE_VERSION,
                "producer": "PyMuPDF deterministic reference-template composition",
                "creationDate": "D:20260726000000+00'00'",
                "modDate": "D:20260726000000+00'00'",
            }
        )
        return output.tobytes(garbage=4, deflate=True, no_new_id=True)
    finally:
        output.close()


def _embedded_latin_font(source_payload: bytes) -> bytes:
    import fitz

    with fitz.open(stream=source_payload, filetype="pdf") as document:
        for page in document:
            for row in page.get_fonts(full=True):
                if "TimesNewRomanPSMT" not in str(row[3]):
                    continue
                binary = document.extract_font(int(row[0]))[3] or b""
                if binary:
                    return bytes(binary)
    raise M2PipelineError("source PDF has no reusable embedded Latin font")


def _draw_answer_sheet_page(
    page: Any,
    rows: tuple[CandidateQuestion, ...],
    *,
    font: Any,
    title: str,
    large_boxes: bool,
    columns: int = 1,
    row_height: float | None = None,
) -> None:
    import fitz

    writer = fitz.TextWriter(page.rect)
    writer.append((54, 48), title, font=font, fontsize=16)
    writer.append(
        (54, 70),
        f"Paper revision: {M2_PAPER_REVISION_ID}",
        font=font,
        fontsize=8,
    )
    content_top = 90.0
    margin = 48.0
    column_gap = 24.0
    column_width = (
        page.rect.width - 2 * margin - (columns - 1) * column_gap
    ) / columns
    per_column = (len(rows) + columns - 1) // columns
    for index, row in enumerate(rows):
        column = min(index // per_column, columns - 1)
        offset = index % per_column
        x0 = margin + column * (column_width + column_gap)
        effective_row_height = (
            row_height
            if row_height is not None
            else (112.0 if large_boxes else 42.0)
        )
        y0 = content_top + offset * effective_row_height
        x1 = x0 + column_width
        y1 = y0 + effective_row_height - 8
        page.draw_rect(
            fitz.Rect(x0, y0, x1, y1),
            color=(0.15, 0.15, 0.15),
            width=0.7,
        )
        writer.append(
            (x0 + 8, y0 + 16),
            f"Q{row.question_no:02d}  ({row.points} pts)",
            font=font,
            fontsize=10,
        )
        if row.question_type in {"单项选择题", "多项选择题"}:
            labels = ("A", "B", "C", "D")
            for label_index, label in enumerate(labels):
                box_x = x0 + 112 + label_index * 54
                page.draw_rect(
                    fitz.Rect(box_x, y0 + 8, box_x + 13, y0 + 21),
                    color=(0.15, 0.15, 0.15),
                    width=0.7,
                )
                writer.append(
                    (box_x + 18, y0 + 19),
                    label,
                    font=font,
                    fontsize=9,
                )
        else:
            page.draw_line(
                fitz.Point(x0 + 112, y0 + 24),
                fitz.Point(x1 - 12, y0 + 24),
                color=(0.35, 0.35, 0.35),
                width=0.5,
            )
    fitz.TextWriter.write_text(writer, page)


def render_answer_sheet(
    candidates: tuple[CandidateQuestion, ...],
    *,
    source_payload: bytes,
    family: str,
) -> bytes:
    import fitz

    if [row.question_no for row in candidates] != list(range(1, 20)):
        raise M2PipelineError("answer sheet requires the complete ordered paper")
    font = fitz.Font(fontbuffer=_embedded_latin_font(source_payload))
    document = fitz.open()
    try:
        if family == "A4-MULTIPAGE":
            page_specs = (
                (candidates[:8], False, 80.0),
                (candidates[8:14], False, 90.0),
                (candidates[14:15], True, 650.0),
                (candidates[15:17], True, 310.0),
                (candidates[17:18], True, 650.0),
                (candidates[18:], True, 650.0),
            )
            for page_number, (rows, large_boxes, row_height) in enumerate(
                page_specs,
                start=1,
            ):
                page = document.new_page(width=595.32, height=841.92)
                _draw_answer_sheet_page(
                    page,
                    rows,
                    font=font,
                    title=f"ANSWER SHEET / PAGE {page_number} OF 6",
                    large_boxes=large_boxes,
                    row_height=row_height,
                )
        elif family == "A3-DUPLEX":
            first = document.new_page(width=1190.55, height=841.89)
            _draw_answer_sheet_page(
                first,
                candidates[:14],
                font=font,
                title="A3 ANSWER SHEET / PAGE 1 OF 2",
                large_boxes=False,
                columns=2,
                row_height=90.0,
            )
            second = document.new_page(width=1190.55, height=841.89)
            _draw_answer_sheet_page(
                second,
                candidates[14:],
                font=font,
                title="A3 ANSWER SHEET / PAGE 2 OF 2",
                large_boxes=True,
                columns=2,
                row_height=210.0,
            )
        else:
            raise M2PipelineError("unsupported answer-sheet family")
        document.set_metadata(
            {
                "title": family,
                "author": "Local Exam Bank",
                "subject": M2_PAPER_REVISION_ID,
                "creator": M2_PIPELINE_VERSION,
                "producer": "PyMuPDF deterministic answer sheet",
                "creationDate": "D:20260725000000+00'00'",
                "modDate": "D:20260725000000+00'00'",
            }
        )
        return document.tobytes(garbage=4, deflate=True, no_new_id=True)
    finally:
        document.close()


def _pdf_summary(payload: bytes) -> dict[str, Any]:
    import fitz

    fonts: dict[str, dict[str, Any]] = {}
    pages: list[dict[str, Any]] = []
    with fitz.open(stream=payload, filetype="pdf") as document:
        text_parts: list[str] = []
        for page_no, page in enumerate(document, start=1):
            pages.append(
                {
                    "page_no": page_no,
                    "width_pt": round(float(page.rect.width), 6),
                    "height_pt": round(float(page.rect.height), 6),
                }
            )
            text_parts.append(page.get_text("text", sort=True))
            for row in page.get_fonts(full=True):
                binary = document.extract_font(int(row[0]))[3] or b""
                key = f"{row[3]}:{_sha256(binary)}"
                fonts[key] = {
                    "base_font": str(row[3]),
                    "embedded": bool(binary),
                    "sha256": _sha256(binary),
                }
    return {
        "page_count": len(pages),
        "pages": pages,
        "font_count": len(fonts),
        "unembedded_font_count": sum(
            not row["embedded"] for row in fonts.values()
        ),
        "fonts": [fonts[key] for key in sorted(fonts)],
        "text": "\n".join(text_parts),
    }


def _render_preview_png(pdf_payload: bytes, *, page_index: int) -> bytes:
    import fitz

    with fitz.open(stream=pdf_payload, filetype="pdf") as document:
        if page_index < 0 or page_index >= document.page_count:
            raise M2PipelineError("preview page index is outside the document")
        page = document.load_page(page_index)
        return page.get_pixmap(dpi=120, alpha=False).tobytes("png")


def build_bundle_staging(
    config: M2PipelineConfig,
    *,
    candidates: tuple[CandidateQuestion, ...],
    full_result: SolveResult,
    blueprint_ui_flow: dict[str, Any],
    inject_failure_role: str | None = None,
) -> dict[str, Any]:
    if config.bundle_target_root.exists():
        raise M2PipelineError("bundle target already exists")
    if (
        config.bundle_staging_root.exists()
        and not config.bundle_staging_root.is_dir()
    ):
        raise M2PipelineError("bundle staging path is not a directory")

    full_spec = full_blueprint_spec()
    paper_snapshot = build_frozen_paper_snapshot(candidates, full_result)
    paper_ir = _m2_paper_ir(config)
    revisions = _domain_revisions(
        config,
        candidates=candidates,
        full_spec=full_spec,
        paper_snapshot=paper_snapshot,
        paper_ir=paper_ir,
    )
    artifacts: list[dict[str, Any]] = []
    artifacts.append(
        _write_bundle_json(
            config,
            "revisions/blueprint-revision.json",
            revisions["blueprint"],
            role="blueprint_revision",
        )
    )
    artifacts.append(
        _write_bundle_json(
            config,
            "revisions/candidate-pool-snapshot.json",
            revisions["pool"],
            role="candidate_pool_snapshot",
        )
    )
    artifacts.append(
        _write_bundle_json(
            config,
            "revisions/paper-revision.json",
            revisions["paper"],
            role="paper_revision",
        )
    )
    artifacts.append(
        _write_bundle_json(
            config,
            "revisions/paper-ir.json",
            paper_ir,
            role="paper_ir",
        )
    )
    artifacts.append(
        _write_bundle_json(
            config,
            "revisions/frozen-question-manifest.json",
            paper_snapshot,
            role="frozen_question_manifest",
        )
    )
    artifacts.append(
        _write_bundle_json(
            config,
            "audit/blueprint-ui-flow.json",
            blueprint_ui_flow,
            role="blueprint_ui_flow",
        )
    )
    artifacts.append(
        _write_bundle_json(
            config,
            "audit/full-solve-result.json",
            full_result.to_dict(),
            role="full_solve_result",
        )
    )
    for candidate in candidates:
        payload = get_workspace_io().read_bytes(
            PROJECT_ROOT / candidate.question_ir_relative_path,
            maximum_bytes=2 * 1024 * 1024,
        )
        if _sha256(payload) != candidate.question_ir_sha256:
            raise M2PipelineError("QuestionIR changed after pool snapshot")
        artifacts.append(
            _write_bundle_bytes(
                config,
                (
                    "revisions/questions/"
                    f"question-{candidate.question_no:03d}-ir.json"
                ),
                payload,
                role="frozen_question_ir",
            )
        )

    m1_config = M1PipelineConfig()
    paper_copy = load_copy_payload(m1_config.paper_copy_id)
    answer_copy = load_copy_payload(m1_config.answer_copy_id)
    analysis_copy = load_copy_payload(m1_config.analysis_copy_id)
    student = _repage_pdf_to_editable_b5(
        paper_copy.payload,
        title="M2 student paper / editable B5 184x260",
    )
    student_repeat = _repage_pdf_to_editable_b5(
        paper_copy.payload,
        title="M2 student paper / editable B5 184x260",
    )
    teacher_questions = _repage_pdf_to_editable_b5(
        paper_copy.payload,
        title="M2 teacher questions / editable B5 184x260",
    )
    teacher_answers = _repage_pdf_to_editable_b5(
        answer_copy.payload,
        title="M2 teacher answers / editable B5 184x260",
    )
    teacher = _compose_pdfs((teacher_questions, teacher_answers))
    teacher_repeat = _compose_pdfs((teacher_questions, teacher_answers))
    answer_sheet_a4 = render_answer_sheet(
        candidates,
        source_payload=paper_copy.payload,
        family="A4-MULTIPAGE",
    )
    answer_sheet_a4_repeat = render_answer_sheet(
        candidates,
        source_payload=paper_copy.payload,
        family="A4-MULTIPAGE",
    )
    answer_sheet_a3 = render_answer_sheet(
        candidates,
        source_payload=paper_copy.payload,
        family="A3-DUPLEX",
    )
    answer_sheet_a3_repeat = render_answer_sheet(
        candidates,
        source_payload=paper_copy.payload,
        family="A3-DUPLEX",
    )
    if (
        student != student_repeat
        or teacher != teacher_repeat
        or answer_sheet_a4 != answer_sheet_a4_repeat
        or answer_sheet_a3 != answer_sheet_a3_repeat
    ):
        raise M2PipelineError("M2 PDF generation is not deterministic")

    document_payloads = {
        "student": student,
        "teacher": teacher,
        "answer": answer_copy.payload,
        "detailed_solution": analysis_copy.payload,
        "answer_sheet": answer_sheet_a4,
    }
    document_artifacts: dict[str, dict[str, Any]] = {}
    for role in DOCUMENT_ROLES:
        if inject_failure_role == role:
            raise M2InjectedFailure(f"injected failure before {role}")
        artifact = _write_bundle_bytes(
            config,
            "documents/" + DOCUMENT_ROLE_FILENAMES[role],
            document_payloads[role],
            role=f"document:{role}",
        )
        artifact["document_role"] = role
        artifact["paper_revision_id"] = M2_PAPER_REVISION_ID
        artifact["question_revision_ids"] = list(
            full_result.selected_revision_ids
        )
        artifacts.append(artifact)
        document_artifacts[role] = artifact

    a3_artifact = _write_bundle_bytes(
        config,
        "templates/answer-sheet-a3-duplex.pdf",
        answer_sheet_a3,
        role="answer_sheet_a3_template_preview",
    )
    artifacts.append(a3_artifact)
    template_manifest = {
        "schema_version": "1.0",
        "template_revision_id": "TEMPLATE-M2-ANSWER-SHEETS-REV-002",
        "predecessor_revision_id": "TEMPLATE-M2-ANSWER-SHEETS-REV-001",
        "families": [
            {
                "family_id": "EDITABLE-B5-184X260",
                "page_count": 4,
                "artifact_sha256": document_artifacts["student"]["sha256"],
                "reference_logical_id": "REF-TEMPLATE-PAPER",
                "page_width_mm": EDITABLE_B5_WIDTH_MM,
                "page_height_mm": EDITABLE_B5_HEIGHT_MM,
                "margins_mm": {
                    "left": EDITABLE_B5_MARGIN_LEFT_MM,
                    "right": EDITABLE_B5_MARGIN_RIGHT_MM,
                    "top": EDITABLE_B5_MARGIN_TOP_MM,
                    "bottom": EDITABLE_B5_MARGIN_BOTTOM_MM,
                },
            },
            {
                "family_id": "A4-MULTIPAGE",
                "page_count": 6,
                "artifact_sha256": document_artifacts["answer_sheet"]["sha256"],
            },
            {
                "family_id": "A3-DUPLEX",
                "page_count": 2,
                "artifact_sha256": a3_artifact["sha256"],
            },
        ],
        "font_policy": "SOURCE_EMBEDDED_FONT_BUFFER",
        "fallback_policy": "NO_SILENT_SUBSTITUTION",
        "created_at": M2_FIXED_TIMESTAMP,
    }
    artifacts.append(
        _write_bundle_json(
            config,
            "templates/template-manifest.json",
            template_manifest,
            role="answer_sheet_template_manifest",
        )
    )

    summaries = {
        role: _pdf_summary(payload)
        for role, payload in document_payloads.items()
    }
    a3_summary = _pdf_summary(answer_sheet_a3)
    student_markers = [
        marker
        for marker in STUDENT_LEAK_MARKERS
        if marker in summaries["student"]["text"]
    ]
    expected_pages = {
        "student": 4,
        "teacher": 15,
        "answer": 11,
        "detailed_solution": 63,
        "answer_sheet": 6,
    }
    expected_b5_width_pt = round(EDITABLE_B5_WIDTH_MM * 72.0 / 25.4, 6)
    expected_b5_height_pt = round(EDITABLE_B5_HEIGHT_MM * 72.0 / 25.4, 6)
    student_template_size_ok = all(
        abs(float(page["width_pt"]) - expected_b5_width_pt) <= 0.01
        and abs(float(page["height_pt"]) - expected_b5_height_pt) <= 0.01
        for page in summaries["student"]["pages"]
    )
    teacher_template_size_ok = all(
        abs(float(page["width_pt"]) - expected_b5_width_pt) <= 0.01
        and abs(float(page["height_pt"]) - expected_b5_height_pt) <= 0.01
        for page in summaries["teacher"]["pages"]
    )
    if (
        student_markers
        or not student_template_size_ok
        or not teacher_template_size_ok
        or {
            role: summaries[role]["page_count"] for role in DOCUMENT_ROLES
        }
        != expected_pages
        or any(
            summaries[role]["unembedded_font_count"] != 0
            for role in DOCUMENT_ROLES
        )
        or a3_summary["page_count"] != 2
        or a3_summary["unembedded_font_count"] != 0
        or any(
            f"Q{number:02d}" not in summaries["answer_sheet"]["text"]
            for number in range(1, 20)
        )
        or any(
            f"Q{number:02d}" not in a3_summary["text"]
            for number in range(1, 20)
        )
    ):
        raise M2PipelineError("M2 document quality or leakage validation failed")
    del summaries["student"]["text"]
    del summaries["teacher"]["text"]
    del summaries["answer"]["text"]
    del summaries["detailed_solution"]["text"]
    del summaries["answer_sheet"]["text"]
    del a3_summary["text"]
    quality = {
        "schema_version": "1.0",
        "paper_revision_id": M2_PAPER_REVISION_ID,
        "documents": summaries,
        "answer_sheet_a3": a3_summary,
        "student_answer_leak_markers": student_markers,
        "student_answer_leak_count": len(student_markers),
        "student_template_size_ok": student_template_size_ok,
        "teacher_template_size_ok": teacher_template_size_ok,
        "paper_template_revision_id": M2_PAPER_TEMPLATE_REVISION_ID,
        "cross_document_revision_mapping_percent": 100,
        "cross_document_score_mapping_percent": 100,
        "answer_sheet_question_mapping_percent": 100,
        "hard_constraint_satisfaction_percent": 100,
        "silent_font_substitution_count": 0,
        "created_at": M2_FIXED_TIMESTAMP,
    }
    artifacts.append(
        _write_bundle_json(
            config,
            "quality/document-quality.json",
            quality,
            role="document_quality",
        )
    )
    for page_index in range(6):
        artifacts.append(
            _write_bundle_bytes(
                config,
                f"quality/previews/answer-sheet-a4-page-{page_index + 1}.png",
                _render_preview_png(answer_sheet_a4, page_index=page_index),
                role="visual_preview",
            )
        )
    for page_index in range(2):
        artifacts.append(
            _write_bundle_bytes(
                config,
                f"quality/previews/answer-sheet-a3-page-{page_index + 1}.png",
                _render_preview_png(answer_sheet_a3, page_index=page_index),
                role="visual_preview",
            )
        )

    answer_mapping = {
        row.question_revision_id: {
            "answer_sha256": row.answer_sha256,
            "analysis_sha256": row.analysis_sha256,
            "points": row.points,
        }
        for row in candidates
    }
    manifest = {
        "schema_version": "1.0",
        "export_id": config.export_id,
        "pipeline_version": M2_PIPELINE_VERSION,
        "solver_version": M2_SOLVER_VERSION,
        "paper_revision_id": M2_PAPER_REVISION_ID,
        "paper_ir_revision_id": M2_PAPER_IR_REVISION_ID,
        "blueprint_revision_id": M2_BLUEPRINT_REVISION_ID,
        "candidate_pool_snapshot_id": M2_POOL_REVISION_ID,
        "seed": full_spec.seed,
        "question_revision_ids": list(full_result.selected_revision_ids),
        "question_count": 19,
        "declared_total_points": 150,
        "document_roles": list(DOCUMENT_ROLES),
        "documents": {
            role: document_artifacts[role] for role in DOCUMENT_ROLES
        },
        "answer_mapping_sha256": _sha256(
            _canonical_json_bytes(answer_mapping)
        ),
        "artifacts": sorted(
            artifacts,
            key=lambda row: (
                str(row["relative_path"]),
                str(row["role"]),
            ),
        ),
        "quality": {
            "student_answer_leak_count": 0,
            "cross_document_revision_mapping_percent": 100,
            "answer_sheet_question_mapping_percent": 100,
            "silent_font_substitution_count": 0,
        },
        "created_at": M2_FIXED_TIMESTAMP,
    }
    manifest_artifact = _write_bundle_json(
        config,
        "bundle-manifest.json",
        manifest,
        role="bundle_manifest",
    )
    export_revision = create_domain_revision(
        object_type="export_bundle",
        object_id=config.export_object_id,
        revision_id=config.export_id,
        revision_no=(
            3
            if config.export_object_id == "EXPORT-M2-YANYAN-FULL-150"
            else 1
        ),
        state="approved",
        created_at=M2_FIXED_TIMESTAMP,
        predecessor_revision_id=(
            "EXPORT-M2-YANYAN-FULL-150-REV-002"
            if config.export_object_id == "EXPORT-M2-YANYAN-FULL-150"
            else None
        ),
        payload={
            "paper_revision_id": M2_PAPER_REVISION_ID,
            "artifact_refs": [
                document_artifacts[role]["relative_path"]
                for role in DOCUMENT_ROLES
            ],
            "manifest_sha256": manifest_artifact["sha256"],
        },
        extensions={
            "x-document-count": 5,
            "x-atomic-publication": True,
        },
    ).document
    validate_domain_revision(export_revision)
    export_revision_artifact = _write_bundle_json(
        config,
        "revisions/export-bundle.json",
        export_revision,
        role="export_bundle_revision",
    )
    release_index = {
        "schema_version": "1.0",
        "export_id": config.export_id,
        "bundle_manifest": manifest_artifact,
        "export_bundle_revision": export_revision_artifact,
        "paper_revision_id": M2_PAPER_REVISION_ID,
        "atomic_publication_required": True,
        "created_at": M2_FIXED_TIMESTAMP,
    }
    release_index_artifact = _write_bundle_json(
        config,
        "release-index.json",
        release_index,
        role="release_index",
    )
    return {
        "manifest": manifest_artifact,
        "release_index": release_index_artifact,
        "export_revision": export_revision_artifact,
        "documents": document_artifacts,
        "quality": quality,
        "paper_snapshot_sha256": paper_snapshot["snapshot_sha256"],
    }


def publish_bundle(config: M2PipelineConfig) -> dict[str, Any]:
    if config.bundle_target_root.exists():
        if config.bundle_staging_root.exists():
            raise M2PipelineError("bundle target exists while staging remains")
        return {
            "operation": "ALREADY_PUBLISHED",
            "target": _relative(config.bundle_target_root),
        }
    if not config.bundle_staging_root.is_dir():
        raise M2PipelineError("bundle staging root is missing")
    staging_verification = verify_bundle_staging(config)
    workspace_io = get_workspace_io()
    workspace_io.ensure_directory(config.bundle_target_root.parent)
    receipt = workspace_io.move_directory_no_replace(
        config.bundle_staging_root,
        config.bundle_target_root,
    )
    return {
        "operation": receipt.operation,
        "target": _relative(config.bundle_target_root),
        "staging_verification": staging_verification,
    }


def _staging_path_for_artifact(
    config: M2PipelineConfig,
    artifact_relative_path: str,
) -> Path:
    artifact = PurePosixPath(artifact_relative_path)
    target = PurePosixPath(_relative(config.bundle_target_root))
    try:
        suffix = artifact.relative_to(target)
    except ValueError as exc:
        raise M2PipelineError(
            "bundle artifact path is outside the release target"
        ) from exc
    if (
        not suffix.parts
        or suffix.is_absolute()
        or any(part in {"", ".", ".."} for part in suffix.parts)
    ):
        raise M2PipelineError("bundle artifact path is invalid")
    return config.bundle_staging_root.joinpath(*suffix.parts)


def verify_bundle_staging(config: M2PipelineConfig) -> dict[str, Any]:
    if not config.bundle_staging_root.is_dir():
        raise M2PipelineError("bundle staging root is missing")
    required_paths = (
        config.bundle_staging_root / "release-index.json",
        config.bundle_staging_root / "bundle-manifest.json",
        config.bundle_staging_root / "revisions" / "export-bundle.json",
        *(
            config.bundle_staging_root
            / "documents"
            / DOCUMENT_ROLE_FILENAMES[role]
            for role in DOCUMENT_ROLES
        ),
    )
    if any(not path.is_file() for path in required_paths):
        raise M2PipelineError("staged bundle is incomplete")
    release_index = _read_json(
        config.bundle_staging_root / "release-index.json"
    )
    manifest_path = config.bundle_staging_root / "bundle-manifest.json"
    manifest_payload = get_workspace_io().read_bytes(
        manifest_path,
        maximum_bytes=8 * 1024 * 1024,
    )
    manifest = json.loads(manifest_payload.decode("utf-8"))
    if (
        release_index["bundle_manifest"]["sha256"]
        != _sha256(manifest_payload)
        or manifest["export_id"] != config.export_id
        or manifest["paper_revision_id"] != M2_PAPER_REVISION_ID
        or tuple(manifest["document_roles"]) != DOCUMENT_ROLES
        or set(manifest["documents"]) != set(DOCUMENT_ROLES)
    ):
        raise M2PipelineError("staged bundle release metadata is inconsistent")

    verified_paths: set[str] = set()
    for artifact in manifest["artifacts"]:
        relative_path = str(artifact["relative_path"])
        if relative_path in verified_paths:
            raise M2PipelineError("staged bundle repeats an artifact path")
        verified_paths.add(relative_path)
        payload = get_workspace_io().read_bytes(
            _staging_path_for_artifact(config, relative_path),
            maximum_bytes=64 * 1024 * 1024,
        )
        if (
            len(payload) != int(artifact["bytes"])
            or _sha256(payload) != artifact["sha256"]
        ):
            raise M2PipelineError("staged bundle artifact hash mismatch")

    for role in DOCUMENT_ROLES:
        document = manifest["documents"][role]
        relative_path = str(document["relative_path"])
        if relative_path not in verified_paths:
            raise M2PipelineError("staged document is absent from the manifest")
        if (
            document["paper_revision_id"] != M2_PAPER_REVISION_ID
            or document["question_revision_ids"]
            != manifest["question_revision_ids"]
        ):
            raise M2PipelineError("staged document revision mapping drifted")

    export_revision_artifact = release_index["export_bundle_revision"]
    export_revision_payload = get_workspace_io().read_bytes(
        _staging_path_for_artifact(
            config,
            str(export_revision_artifact["relative_path"]),
        ),
        maximum_bytes=8 * 1024 * 1024,
    )
    if (
        len(export_revision_payload)
        != int(export_revision_artifact["bytes"])
        or _sha256(export_revision_payload)
        != export_revision_artifact["sha256"]
    ):
        raise M2PipelineError("staged export revision hash mismatch")
    export_revision = json.loads(export_revision_payload.decode("utf-8"))
    validate_domain_revision(export_revision)
    expected_staging_paths = {
        _staging_path_for_artifact(
            config,
            str(artifact["relative_path"]),
        )
        .relative_to(config.bundle_staging_root)
        .as_posix()
        for artifact in manifest["artifacts"]
    }
    expected_staging_paths.update(
        {
            "bundle-manifest.json",
            "release-index.json",
            _staging_path_for_artifact(
                config,
                str(export_revision_artifact["relative_path"]),
            )
            .relative_to(config.bundle_staging_root)
            .as_posix(),
        }
    )
    actual_staging_paths = {
        path.relative_to(config.bundle_staging_root).as_posix()
        for path in config.bundle_staging_root.rglob("*")
        if path.is_file()
    }
    if actual_staging_paths != expected_staging_paths:
        raise M2PipelineError("staged bundle contains missing or extra files")
    return {
        "artifact_count": len(verified_paths),
        "document_count": len(DOCUMENT_ROLES),
        "manifest_sha256": _sha256(manifest_payload),
        "export_revision_id": str(export_revision["revision_id"]),
        "status": "COMPLETE_AND_HASH_VERIFIED",
    }


def verify_bundle(config: M2PipelineConfig) -> dict[str, Any]:
    if not config.bundle_target_root.is_dir():
        raise M2PipelineError("published bundle is missing")
    release_index = _read_json(config.bundle_target_root / "release-index.json")
    manifest_path = config.bundle_target_root / "bundle-manifest.json"
    manifest_payload = get_workspace_io().read_bytes(
        manifest_path,
        maximum_bytes=8 * 1024 * 1024,
    )
    manifest = json.loads(manifest_payload.decode("utf-8"))
    if (
        release_index["bundle_manifest"]["sha256"] != _sha256(manifest_payload)
        or manifest["export_id"] != config.export_id
        or manifest["paper_revision_id"] != M2_PAPER_REVISION_ID
        or manifest["question_count"] != 19
        or manifest["declared_total_points"] != 150
        or tuple(manifest["document_roles"]) != DOCUMENT_ROLES
        or set(manifest["documents"]) != set(DOCUMENT_ROLES)
    ):
        raise M2PipelineError("bundle release index or manifest is inconsistent")

    for artifact in manifest["artifacts"]:
        path = PROJECT_ROOT / str(artifact["relative_path"])
        payload = get_workspace_io().read_bytes(
            path,
            maximum_bytes=64 * 1024 * 1024,
        )
        if (
            len(payload) != int(artifact["bytes"])
            or _sha256(payload) != artifact["sha256"]
        ):
            raise M2PipelineError("published bundle artifact hash mismatch")

    document_payloads: dict[str, bytes] = {}
    for role in DOCUMENT_ROLES:
        document = manifest["documents"][role]
        if (
            document["paper_revision_id"] != M2_PAPER_REVISION_ID
            or document["question_revision_ids"]
            != manifest["question_revision_ids"]
        ):
            raise M2PipelineError("cross-document frozen revision mapping drifted")
        document_payloads[role] = get_workspace_io().read_bytes(
            PROJECT_ROOT / str(document["relative_path"]),
            maximum_bytes=64 * 1024 * 1024,
        )
    summaries = {
        role: _pdf_summary(payload)
        for role, payload in document_payloads.items()
    }
    student_markers = [
        marker
        for marker in STUDENT_LEAK_MARKERS
        if marker in summaries["student"]["text"]
    ]
    if (
        student_markers
        or any(
            summaries[role]["unembedded_font_count"] != 0
            for role in DOCUMENT_ROLES
        )
        or any(
            f"Q{number:02d}" not in summaries["answer_sheet"]["text"]
            for number in range(1, 20)
        )
    ):
        raise M2PipelineError("published bundle quality verification failed")

    revision_paths = (
        "revisions/blueprint-revision.json",
        "revisions/candidate-pool-snapshot.json",
        "revisions/paper-revision.json",
        "revisions/export-bundle.json",
    )
    revision_ids: list[str] = []
    for relative_path in revision_paths:
        document = _read_json(config.bundle_target_root / relative_path)
        validate_domain_revision(document)
        revision_ids.append(str(document["revision_id"]))

    # Published documents are opened from their frozen bundle only.  Verifying or
    # downloading them must not depend on the later state of the candidate DB.
    app = create_blueprint_app((), config=config)
    app.config["TESTING"] = True
    client = app.test_client()
    download_statuses = {
        role: client.get(f"/bundles/{config.export_id}/{role}").status_code
        for role in DOCUMENT_ROLES
    }
    if any(status != 200 for status in download_statuses.values()):
        raise M2PipelineError("published bundle is not reachable through the local UI")
    return {
        "export_id": config.export_id,
        "bundle_path": _relative(config.bundle_target_root),
        "bundle_manifest_sha256": _sha256(manifest_payload),
        "paper_revision_id": M2_PAPER_REVISION_ID,
        "question_count": int(manifest["question_count"]),
        "declared_total_points": int(manifest["declared_total_points"]),
        "document_roles": list(DOCUMENT_ROLES),
        "document_sha256": {
            role: _sha256(document_payloads[role]) for role in DOCUMENT_ROLES
        },
        "document_page_counts": {
            role: summaries[role]["page_count"] for role in DOCUMENT_ROLES
        },
        "student_answer_leak_count": len(student_markers),
        "silent_font_substitution_count": 0,
        "answer_sheet_mapped_question_count": sum(
            f"Q{number:02d}" in summaries["answer_sheet"]["text"]
            for number in range(1, 20)
        ),
        "domain_revision_ids": revision_ids,
        "ui_download_statuses": download_statuses,
    }


def run_m2_real_pipeline(
    config: M2PipelineConfig | None = None,
) -> dict[str, Any]:
    config = config or M2PipelineConfig()
    if config.bundle_target_root.exists():
        first = verify_bundle(config)
        second = verify_bundle(config)
        return {
            "pipeline_version": M2_PIPELINE_VERSION,
            "status": "ALREADY_PUBLISHED_VERIFIED",
            "first_verification": first,
            "repeat_verification": second,
            "repeat_stable": first == second,
        }

    candidates = load_candidate_pool(config)
    blueprint_ui_flow = run_blueprint_ui_flow(candidates, config=config)
    full_spec = full_blueprint_spec()
    full_result = solve_blueprint(candidates, full_spec)
    if (
        not full_result.feasible
        or full_result.coverage.get("question_count") != 19
        or full_result.coverage.get("total_points") != 150
        or full_result.coverage.get("type_counts") != FULL_TYPE_COUNTS
        or full_result.diagnostics.get("hard_constraints_relaxed") is not False
    ):
        raise M2PipelineError("full blueprint did not satisfy all hard constraints")

    frozen = build_frozen_paper_snapshot(candidates, full_result)
    frozen_bytes = _canonical_json_bytes(frozen)
    mutated_candidates = (
        replace(candidates[0], answer_sha256="0" * 64),
        *candidates[1:],
    )
    mutated_frozen_bytes = _canonical_json_bytes(
        build_frozen_paper_snapshot(mutated_candidates, full_result)
    )
    if (
        _canonical_json_bytes(frozen) != frozen_bytes
        or mutated_frozen_bytes == frozen_bytes
    ):
        raise M2PipelineError("frozen paper catalog mutation probe failed")

    staged = build_bundle_staging(
        config,
        candidates=candidates,
        full_result=full_result,
        blueprint_ui_flow=blueprint_ui_flow,
    )
    publication = publish_bundle(config)
    verification = verify_bundle(config)
    repeat_verification = verify_bundle(config)
    return {
        "pipeline_version": M2_PIPELINE_VERSION,
        "status": "PUBLISHED_VERIFIED",
        "candidate_pool_count": len(candidates),
        "candidate_pool_sha256": _sha256(
            _canonical_json_bytes([row.to_dict() for row in candidates])
        ),
        "full_blueprint": full_spec.to_dict(),
        "full_solve": full_result.to_dict(),
        "blueprint_ui_flow": blueprint_ui_flow,
        "frozen_catalog_mutation_probe": {
            "mutated_question_revision_id": (
                mutated_candidates[0].question_revision_id
            ),
            "mutated_answer_sha256": mutated_candidates[0].answer_sha256,
            "frozen_snapshot_unchanged": True,
            "frozen_snapshot_sha256": _sha256(frozen_bytes),
            "regenerated_mutated_snapshot_sha256": _sha256(
                mutated_frozen_bytes
            ),
        },
        "staged": staged,
        "publication": publication,
        "verification": verification,
        "repeat_verification": repeat_verification,
        "repeat_stable": verification == repeat_verification,
    }
