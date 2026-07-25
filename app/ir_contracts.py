from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping


IR_SCHEMA_VERSION = "1.0"
LEGACY_IR_SCHEMA_VERSION = "0.9"
QUESTION_IR_SCHEMA_ID = "LOCAL_EXAM_BANK_QUESTION_IR"
FIGURE_IR_SCHEMA_ID = "LOCAL_EXAM_BANK_FIGURE_IR"
PAPER_IR_SCHEMA_ID = "LOCAL_EXAM_BANK_PAPER_IR"
IR_SCHEMA_IDS = frozenset(
    {QUESTION_IR_SCHEMA_ID, FIGURE_IR_SCHEMA_ID, PAPER_IR_SCHEMA_ID}
)

QUESTION_TYPES = frozenset(
    {"selection", "fill", "solution", "proof", "drawing", "additional"}
)
FIGURE_KINDS = frozenset({"geometry", "function", "statistics"})
DOCUMENT_ROLES = frozenset(
    {"student", "teacher", "answer", "detailed_solution", "answer_sheet"}
)
COORDINATE_SPACES = frozenset(
    {"pdf_points_top_left", "pixels_top_left", "millimetres_top_left"}
)

_ID_PATTERN = re.compile(r"[A-Z][A-Z0-9._-]{2,127}")
_EXTENSION_KEY_PATTERN = re.compile(r"x-[a-z0-9][a-z0-9._-]{0,62}")
_TOKEN_KEY_PATTERN = re.compile(r"[a-z][a-z0-9._-]{0,62}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class IrContractError(ValueError):
    pass


class IrVersionError(IrContractError):
    pass


def _fail(message: str) -> None:
    raise IrContractError(message)


def _require_exact(
    value: Mapping[str, Any],
    required: Iterable[str],
    context: str,
) -> None:
    expected = frozenset(required)
    actual = frozenset(value)
    missing = expected - actual
    unknown = actual - expected
    if missing:
        _fail(f"{context} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        _fail(f"{context} has unknown fields: {', '.join(sorted(unknown))}")


def _require_id(value: Any, context: str) -> str:
    if type(value) is not str or not _ID_PATTERN.fullmatch(value):
        _fail(f"{context} must be a contracted identifier")
    if value.casefold() == "latest":
        _fail(f"{context} cannot use a latest-version alias")
    return value


def _require_string(value: Any, context: str, *, allow_empty: bool = False) -> str:
    if (
        type(value) is not str
        or (not allow_empty and not value)
        or len(value) > 32768
    ):
        _fail(f"{context} must be a bounded string")
    return value


def _number(
    value: Any,
    context: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    if type(value) not in (int, float) or not math.isfinite(float(value)):
        _fail(f"{context} must be a finite number")
    result = float(value)
    if minimum is not None and result < minimum:
        _fail(f"{context} must be >= {minimum}")
    if maximum is not None and result > maximum:
        _fail(f"{context} must be <= {maximum}")
    return result


def _extensions(value: Any, context: str) -> None:
    if type(value) is not dict:
        _fail(f"{context} must be an object")
    for key, item in value.items():
        if type(key) is not str or not _EXTENSION_KEY_PATTERN.fullmatch(key):
            _fail(f"{context} keys must use the x-* namespace")
        _json_value(item, f"{context}.{key}")


def _json_value(value: Any, context: str, depth: int = 0) -> None:
    if depth > 24:
        _fail(f"{context} exceeds the maximum JSON depth")
    if value is None or type(value) in (bool, int, str):
        return
    if type(value) is float:
        if not math.isfinite(value):
            _fail(f"{context} contains a non-finite number")
        return
    if type(value) is list:
        if len(value) > 4096:
            _fail(f"{context} has too many items")
        for index, item in enumerate(value):
            _json_value(item, f"{context}[{index}]", depth + 1)
        return
    if type(value) is dict:
        if len(value) > 4096:
            _fail(f"{context} has too many fields")
        for key, item in value.items():
            if type(key) is not str or not key or len(key) > 128:
                _fail(f"{context} contains an invalid key")
            _json_value(item, f"{context}.{key}", depth + 1)
        return
    _fail(f"{context} contains a non-JSON value")


def _id_list(value: Any, context: str) -> list[str]:
    if type(value) is not list:
        _fail(f"{context} must be a list")
    result = [_require_id(item, f"{context}[{index}]") for index, item in enumerate(value)]
    if len(result) != len(set(result)):
        _fail(f"{context} cannot contain duplicates")
    return result


def _relative_path_or_id(value: Any, context: str) -> None:
    if type(value) is not str or not value:
        _fail(f"{context} must be a project-relative path or object identifier")
    if _ID_PATTERN.fullmatch(value):
        return
    if "\\" in value or ":" in value:
        _fail(f"{context} contains non-portable path syntax")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in ("", ".", "..") for part in path.parts)
        or path.as_posix() != value
    ):
        _fail(f"{context} must be a normalized project-relative path")


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise IrContractError("IR contains non-canonical JSON data") from exc


def _clone(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(canonical_json_bytes(value).decode("utf-8"))


def ir_sha256(document: Mapping[str, Any]) -> str:
    validated = validate_ir_document(document)
    return hashlib.sha256(canonical_json_bytes(validated)).hexdigest()


def _validate_block(
    value: Any,
    context: str,
    *,
    depth: int = 0,
    allow_table: bool = True,
) -> None:
    if depth > 8 or type(value) is not dict:
        _fail(f"{context} must be a bounded block object")
    kind = value.get("kind")
    if kind == "text":
        _require_exact(value, {"kind", "text", "style", "extensions"}, context)
        _require_string(value["text"], f"{context}.text")
        if value["style"] not in {
            "normal",
            "bold",
            "italic",
            "instruction",
            "heading",
        }:
            _fail(f"{context}.style is invalid")
    elif kind == "math":
        _require_exact(value, {"kind", "latex", "display", "extensions"}, context)
        _require_string(value["latex"], f"{context}.latex")
        if type(value["display"]) is not bool:
            _fail(f"{context}.display must be boolean")
    elif kind == "figure":
        _require_exact(
            value,
            {"kind", "figure_revision_id", "caption_blocks", "extensions"},
            context,
        )
        _require_id(value["figure_revision_id"], f"{context}.figure_revision_id")
        _validate_blocks(
            value["caption_blocks"],
            f"{context}.caption_blocks",
            allow_empty=True,
            depth=depth + 1,
            allow_table=False,
        )
    elif kind == "table" and allow_table:
        _require_exact(value, {"kind", "rows", "header_rows", "extensions"}, context)
        rows = value["rows"]
        if type(rows) is not list or not rows:
            _fail(f"{context}.rows must be a non-empty list")
        width: int | None = None
        for row_index, row in enumerate(rows):
            if type(row) is not list or not row:
                _fail(f"{context}.rows[{row_index}] must be a non-empty list")
            if width is None:
                width = len(row)
            elif len(row) != width:
                _fail(f"{context}.rows must be rectangular")
            for column_index, cell in enumerate(row):
                _validate_blocks(
                    cell,
                    f"{context}.rows[{row_index}][{column_index}]",
                    allow_empty=False,
                    depth=depth + 1,
                    allow_table=False,
                )
        if (
            type(value["header_rows"]) is not int
            or value["header_rows"] < 0
            or value["header_rows"] > len(rows)
        ):
            _fail(f"{context}.header_rows is invalid")
    else:
        _fail(f"{context}.kind is unsupported")
    _extensions(value["extensions"], f"{context}.extensions")


def _validate_blocks(
    value: Any,
    context: str,
    *,
    allow_empty: bool,
    depth: int = 0,
    allow_table: bool = True,
) -> None:
    if type(value) is not list or (not allow_empty and not value):
        _fail(f"{context} must be a {'non-empty ' if not allow_empty else ''}list")
    for index, block in enumerate(value):
        _validate_block(
            block,
            f"{context}[{index}]",
            depth=depth,
            allow_table=allow_table,
        )


def _validate_region(value: Any, context: str) -> None:
    if type(value) is not dict:
        _fail(f"{context} must be an object")
    _require_exact(
        value,
        {
            "coordinate_space",
            "units",
            "page_width",
            "page_height",
            "x0",
            "y0",
            "x1",
            "y1",
            "dpi",
            "extensions",
        },
        context,
    )
    coordinate_space = value["coordinate_space"]
    if coordinate_space not in COORDINATE_SPACES:
        _fail(f"{context}.coordinate_space is invalid")
    expected_units = {
        "pdf_points_top_left": "pt",
        "pixels_top_left": "px",
        "millimetres_top_left": "mm",
    }[coordinate_space]
    if value["units"] != expected_units:
        _fail(f"{context}.units does not match coordinate_space")
    page_width = _number(value["page_width"], f"{context}.page_width", minimum=0.001)
    page_height = _number(value["page_height"], f"{context}.page_height", minimum=0.001)
    x0 = _number(value["x0"], f"{context}.x0", minimum=0)
    y0 = _number(value["y0"], f"{context}.y0", minimum=0)
    x1 = _number(value["x1"], f"{context}.x1", minimum=0)
    y1 = _number(value["y1"], f"{context}.y1", minimum=0)
    if x1 <= x0 or y1 <= y0 or x1 > page_width or y1 > page_height:
        _fail(f"{context} must be a non-empty rectangle inside its page")
    if coordinate_space == "pixels_top_left":
        _number(value["dpi"], f"{context}.dpi", minimum=1)
    elif value["dpi"] is not None:
        _fail(f"{context}.dpi is only valid for pixel coordinates")
    _extensions(value["extensions"], f"{context}.extensions")


def _validate_transform(value: Any, context: str) -> None:
    if type(value) is not dict:
        _fail(f"{context} must be an object")
    _require_exact(
        value,
        {
            "sequence",
            "kind",
            "input_coordinate_space",
            "output_coordinate_space",
            "matrix_3x3",
            "algorithm",
            "parameters",
            "extensions",
        },
        context,
    )
    if type(value["sequence"]) is not int or value["sequence"] < 1:
        _fail(f"{context}.sequence must be a positive integer")
    if value["kind"] not in {
        "crop",
        "rotate",
        "scale",
        "deskew",
        "perspective",
        "normalize",
    }:
        _fail(f"{context}.kind is invalid")
    if value["input_coordinate_space"] not in COORDINATE_SPACES:
        _fail(f"{context}.input_coordinate_space is invalid")
    if value["output_coordinate_space"] not in COORDINATE_SPACES:
        _fail(f"{context}.output_coordinate_space is invalid")
    matrix = value["matrix_3x3"]
    if type(matrix) is not list or len(matrix) != 9:
        _fail(f"{context}.matrix_3x3 must contain nine values")
    for index, item in enumerate(matrix):
        _number(item, f"{context}.matrix_3x3[{index}]")
    _require_string(value["algorithm"], f"{context}.algorithm")
    if type(value["parameters"]) is not dict:
        _fail(f"{context}.parameters must be an object")
    _json_value(value["parameters"], f"{context}.parameters")
    _extensions(value["extensions"], f"{context}.extensions")


def _validate_source_ref(value: Any, context: str) -> None:
    if type(value) is not dict:
        _fail(f"{context} must be an object")
    _require_exact(
        value,
        {
            "source_file_revision_id",
            "page_no",
            "region",
            "transforms",
            "extensions",
        },
        context,
    )
    _require_id(value["source_file_revision_id"], f"{context}.source_file_revision_id")
    if type(value["page_no"]) is not int or value["page_no"] < 1:
        _fail(f"{context}.page_no must be a positive integer")
    _validate_region(value["region"], f"{context}.region")
    transforms = value["transforms"]
    if type(transforms) is not list:
        _fail(f"{context}.transforms must be a list")
    for index, transform in enumerate(transforms):
        _validate_transform(transform, f"{context}.transforms[{index}]")
        if transform["sequence"] != index + 1:
            _fail(f"{context}.transforms sequence must be contiguous")
        expected_input = (
            value["region"]["coordinate_space"]
            if index == 0
            else transforms[index - 1]["output_coordinate_space"]
        )
        if transform["input_coordinate_space"] != expected_input:
            _fail(f"{context}.transforms coordinate spaces must form a chain")
    _extensions(value["extensions"], f"{context}.extensions")


def _validate_source_refs(value: Any, context: str, *, allow_empty: bool) -> None:
    if type(value) is not list or (not allow_empty and not value):
        _fail(f"{context} must be a {'non-empty ' if not allow_empty else ''}list")
    for index, item in enumerate(value):
        _validate_source_ref(item, f"{context}[{index}]")


def _validate_scoring_points(value: Any, context: str, points: float) -> None:
    if type(value) is not list:
        _fail(f"{context} must be a list")
    identifiers: list[str] = []
    total = 0.0
    for index, item in enumerate(value):
        item_context = f"{context}[{index}]"
        if type(item) is not dict:
            _fail(f"{item_context} must be an object")
        _require_exact(
            item,
            {
                "scoring_point_revision_id",
                "points",
                "criteria_blocks",
                "extensions",
            },
            item_context,
        )
        identifiers.append(
            _require_id(
                item["scoring_point_revision_id"],
                f"{item_context}.scoring_point_revision_id",
            )
        )
        total += _number(item["points"], f"{item_context}.points", minimum=0)
        _validate_blocks(
            item["criteria_blocks"],
            f"{item_context}.criteria_blocks",
            allow_empty=False,
        )
        _extensions(item["extensions"], f"{item_context}.extensions")
    if len(identifiers) != len(set(identifiers)):
        _fail(f"{context} contains duplicate scoring point revisions")
    if value and not math.isclose(total, points, rel_tol=0, abs_tol=1e-9):
        _fail(f"{context} point sum must equal its owning item points")


def _figure_ids_from_blocks(blocks: list[Any]) -> set[str]:
    result: set[str] = set()
    for block in blocks:
        if block["kind"] == "figure":
            result.add(block["figure_revision_id"])
            result.update(_figure_ids_from_blocks(block["caption_blocks"]))
        elif block["kind"] == "table":
            for row in block["rows"]:
                for cell in row:
                    result.update(_figure_ids_from_blocks(cell))
    return result


def validate_question_ir(document: Any) -> dict[str, Any]:
    if type(document) is not dict:
        _fail("QuestionIR must be an object")
    _require_exact(
        document,
        {
            "schema_id",
            "schema_version",
            "ir_id",
            "revision_id",
            "question_type",
            "blocks",
            "options",
            "subquestions",
            "figure_revision_ids",
            "answer_blocks",
            "solution_blocks",
            "scoring_points",
            "source_refs",
            "points",
            "design_difficulty",
            "observed_p",
            "expected_time_seconds",
            "observed_item_time_seconds",
            "observed_item_time_source",
            "extensions",
        },
        "QuestionIR",
    )
    if document["schema_id"] != QUESTION_IR_SCHEMA_ID:
        _fail("QuestionIR schema_id is unsupported")
    if document["schema_version"] != IR_SCHEMA_VERSION:
        raise IrVersionError("QuestionIR schema_version is unsupported")
    _require_id(document["ir_id"], "QuestionIR.ir_id")
    _require_id(document["revision_id"], "QuestionIR.revision_id")
    if document["question_type"] not in QUESTION_TYPES:
        _fail("QuestionIR.question_type is invalid")
    _validate_blocks(document["blocks"], "QuestionIR.blocks", allow_empty=False)
    options = document["options"]
    if type(options) is not list:
        _fail("QuestionIR.options must be a list")
    option_labels: list[str] = []
    for index, option in enumerate(options):
        context = f"QuestionIR.options[{index}]"
        if type(option) is not dict:
            _fail(f"{context} must be an object")
        _require_exact(option, {"label", "blocks", "extensions"}, context)
        option_labels.append(_require_string(option["label"], f"{context}.label"))
        _validate_blocks(option["blocks"], f"{context}.blocks", allow_empty=False)
        _extensions(option["extensions"], f"{context}.extensions")
    if len(option_labels) != len(set(option_labels)):
        _fail("QuestionIR.options labels must be unique")
    if document["question_type"] == "selection":
        if len(options) < 2:
            _fail("selection QuestionIR requires at least two options")
    elif options:
        _fail("only selection QuestionIR may contain options")
    points = _number(document["points"], "QuestionIR.points", minimum=0)
    subquestions = document["subquestions"]
    if type(subquestions) is not list:
        _fail("QuestionIR.subquestions must be a list")
    sub_labels: list[str] = []
    sub_total = 0.0
    for index, subquestion in enumerate(subquestions):
        context = f"QuestionIR.subquestions[{index}]"
        if type(subquestion) is not dict:
            _fail(f"{context} must be an object")
        _require_exact(
            subquestion,
            {
                "label",
                "blocks",
                "answer_blocks",
                "solution_blocks",
                "scoring_points",
                "points",
                "extensions",
            },
            context,
        )
        sub_labels.append(
            _require_string(subquestion["label"], f"{context}.label")
        )
        _validate_blocks(subquestion["blocks"], f"{context}.blocks", allow_empty=False)
        _validate_blocks(
            subquestion["answer_blocks"],
            f"{context}.answer_blocks",
            allow_empty=True,
        )
        _validate_blocks(
            subquestion["solution_blocks"],
            f"{context}.solution_blocks",
            allow_empty=True,
        )
        sub_points = _number(subquestion["points"], f"{context}.points", minimum=0)
        sub_total += sub_points
        _validate_scoring_points(
            subquestion["scoring_points"],
            f"{context}.scoring_points",
            sub_points,
        )
        _extensions(subquestion["extensions"], f"{context}.extensions")
    if len(sub_labels) != len(set(sub_labels)):
        _fail("QuestionIR.subquestions labels must be unique")
    if subquestions and not math.isclose(sub_total, points, rel_tol=0, abs_tol=1e-9):
        _fail("QuestionIR subquestion point sum must equal question points")
    _validate_blocks(
        document["answer_blocks"], "QuestionIR.answer_blocks", allow_empty=True
    )
    _validate_blocks(
        document["solution_blocks"], "QuestionIR.solution_blocks", allow_empty=True
    )
    _validate_scoring_points(
        document["scoring_points"], "QuestionIR.scoring_points", points
    )
    figure_ids = _id_list(
        document["figure_revision_ids"], "QuestionIR.figure_revision_ids"
    )
    referenced_figures = _figure_ids_from_blocks(document["blocks"])
    for option in options:
        referenced_figures.update(_figure_ids_from_blocks(option["blocks"]))
    for subquestion in subquestions:
        referenced_figures.update(_figure_ids_from_blocks(subquestion["blocks"]))
    if set(figure_ids) != referenced_figures:
        _fail("QuestionIR.figure_revision_ids must exactly match figure blocks")
    _validate_source_refs(
        document["source_refs"], "QuestionIR.source_refs", allow_empty=False
    )
    difficulty = document["design_difficulty"]
    if difficulty is not None and (
        type(difficulty) is not int or difficulty < 1 or difficulty > 5
    ):
        _fail("QuestionIR.design_difficulty must be 1..5 or null")
    observed_p = document["observed_p"]
    if observed_p is not None:
        _number(observed_p, "QuestionIR.observed_p", minimum=0, maximum=1)
    expected_time = document["expected_time_seconds"]
    if expected_time is not None and (
        type(expected_time) is not int or expected_time < 1
    ):
        _fail("QuestionIR.expected_time_seconds must be positive or null")
    observed_item_time = document["observed_item_time_seconds"]
    observed_item_source = document["observed_item_time_source"]
    if (observed_item_time is None) != (observed_item_source is None):
        _fail("observed item time and its source must be present together")
    if observed_item_time is not None:
        if type(observed_item_time) is not int or observed_item_time < 1:
            _fail("QuestionIR.observed_item_time_seconds must be positive")
        _require_id(observed_item_source, "QuestionIR.observed_item_time_source")
    _extensions(document["extensions"], "QuestionIR.extensions")
    return _clone(document)


def _validate_axes(value: Any, context: str) -> None:
    if type(value) is not dict:
        _fail(f"{context} must be an object")
    _require_exact(
        value,
        {"x_range", "y_range", "x_label", "y_label", "show_grid", "extensions"},
        context,
    )
    for key in ("x_range", "y_range"):
        interval = value[key]
        if type(interval) is not list or len(interval) != 2:
            _fail(f"{context}.{key} must be a two-value interval")
        start = _number(interval[0], f"{context}.{key}[0]")
        end = _number(interval[1], f"{context}.{key}[1]")
        if end <= start:
            _fail(f"{context}.{key} must be increasing")
    _require_string(value["x_label"], f"{context}.x_label", allow_empty=True)
    _require_string(value["y_label"], f"{context}.y_label", allow_empty=True)
    if type(value["show_grid"]) is not bool:
        _fail(f"{context}.show_grid must be boolean")
    _extensions(value["extensions"], f"{context}.extensions")


def _validate_geometry_content(value: Any) -> None:
    context = "FigureIR.content"
    if type(value) is not dict:
        _fail(f"{context} must be an object")
    _require_exact(
        value,
        {
            "coordinate_space",
            "points",
            "primitives",
            "constraints",
            "annotations",
            "extensions",
        },
        context,
    )
    if value["coordinate_space"] not in {"diagram", "cartesian_2d", "cartesian_3d"}:
        _fail(f"{context}.coordinate_space is invalid")
    points = value["points"]
    if type(points) is not list or not points:
        _fail(f"{context}.points must be a non-empty list")
    point_ids: set[str] = set()
    for index, point in enumerate(points):
        item_context = f"{context}.points[{index}]"
        if type(point) is not dict:
            _fail(f"{item_context} must be an object")
        _require_exact(
            point, {"id", "x", "y", "z", "label", "extensions"}, item_context
        )
        point_id = _require_id(point["id"], f"{item_context}.id")
        if point_id in point_ids:
            _fail(f"{context}.points contains duplicate ids")
        point_ids.add(point_id)
        _number(point["x"], f"{item_context}.x")
        _number(point["y"], f"{item_context}.y")
        if point["z"] is not None:
            _number(point["z"], f"{item_context}.z")
        _require_string(point["label"], f"{item_context}.label", allow_empty=True)
        _extensions(point["extensions"], f"{item_context}.extensions")
    primitive_ids: set[str] = set()
    primitives = value["primitives"]
    if type(primitives) is not list:
        _fail(f"{context}.primitives must be a list")
    for index, primitive in enumerate(primitives):
        item_context = f"{context}.primitives[{index}]"
        if type(primitive) is not dict:
            _fail(f"{item_context} must be an object")
        _require_exact(
            primitive, {"id", "kind", "refs", "parameters", "extensions"}, item_context
        )
        primitive_id = _require_id(primitive["id"], f"{item_context}.id")
        if primitive_id in primitive_ids:
            _fail(f"{context}.primitives contains duplicate ids")
        primitive_ids.add(primitive_id)
        if primitive["kind"] not in {
            "segment",
            "line",
            "ray",
            "circle",
            "arc",
            "polygon",
            "angle",
        }:
            _fail(f"{item_context}.kind is invalid")
        refs = _id_list(primitive["refs"], f"{item_context}.refs")
        if any(ref not in point_ids for ref in refs):
            _fail(f"{item_context}.refs contains an unknown point")
        if type(primitive["parameters"]) is not dict:
            _fail(f"{item_context}.parameters must be an object")
        _json_value(primitive["parameters"], f"{item_context}.parameters")
        _extensions(primitive["extensions"], f"{item_context}.extensions")
    constraints = value["constraints"]
    if type(constraints) is not list:
        _fail(f"{context}.constraints must be a list")
    allowed_refs = point_ids | primitive_ids
    for index, constraint in enumerate(constraints):
        item_context = f"{context}.constraints[{index}]"
        if type(constraint) is not dict:
            _fail(f"{item_context} must be an object")
        _require_exact(
            constraint, {"kind", "refs", "value", "extensions"}, item_context
        )
        if constraint["kind"] not in {
            "parallel",
            "perpendicular",
            "tangent",
            "equal_length",
            "equal_angle",
            "collinear",
            "concyclic",
        }:
            _fail(f"{item_context}.kind is invalid")
        refs = _id_list(constraint["refs"], f"{item_context}.refs")
        if any(ref not in allowed_refs for ref in refs):
            _fail(f"{item_context}.refs contains an unknown geometry id")
        if constraint["value"] is not None:
            _number(constraint["value"], f"{item_context}.value")
        _extensions(constraint["extensions"], f"{item_context}.extensions")
    _validate_blocks(
        value["annotations"], f"{context}.annotations", allow_empty=True, allow_table=False
    )
    _extensions(value["extensions"], f"{context}.extensions")


def _validate_function_content(value: Any) -> None:
    context = "FigureIR.content"
    if type(value) is not dict:
        _fail(f"{context} must be an object")
    _require_exact(
        value,
        {
            "expressions",
            "sample_interval",
            "axes",
            "special_points",
            "asymptotes",
            "extensions",
        },
        context,
    )
    expressions = value["expressions"]
    if type(expressions) is not list or not expressions:
        _fail(f"{context}.expressions must be a non-empty list")
    expression_ids: set[str] = set()
    for index, expression in enumerate(expressions):
        item_context = f"{context}.expressions[{index}]"
        if type(expression) is not dict:
            _fail(f"{item_context} must be an object")
        _require_exact(expression, {"id", "latex", "domain", "extensions"}, item_context)
        expression_id = _require_id(expression["id"], f"{item_context}.id")
        if expression_id in expression_ids:
            _fail(f"{context}.expressions contains duplicate ids")
        expression_ids.add(expression_id)
        _require_string(expression["latex"], f"{item_context}.latex")
        domain = expression["domain"]
        if type(domain) is not list or len(domain) != 2:
            _fail(f"{item_context}.domain must be a two-value interval")
        if _number(domain[1], f"{item_context}.domain[1]") <= _number(
            domain[0], f"{item_context}.domain[0]"
        ):
            _fail(f"{item_context}.domain must be increasing")
        _extensions(expression["extensions"], f"{item_context}.extensions")
    interval = value["sample_interval"]
    if type(interval) is not list or len(interval) != 2:
        _fail(f"{context}.sample_interval must be a two-value interval")
    if _number(interval[1], f"{context}.sample_interval[1]") <= _number(
        interval[0], f"{context}.sample_interval[0]"
    ):
        _fail(f"{context}.sample_interval must be increasing")
    _validate_axes(value["axes"], f"{context}.axes")
    special_points = value["special_points"]
    if type(special_points) is not list:
        _fail(f"{context}.special_points must be a list")
    point_ids: set[str] = set()
    for index, point in enumerate(special_points):
        item_context = f"{context}.special_points[{index}]"
        if type(point) is not dict:
            _fail(f"{item_context} must be an object")
        _require_exact(point, {"id", "x", "y", "label", "extensions"}, item_context)
        point_id = _require_id(point["id"], f"{item_context}.id")
        if point_id in point_ids:
            _fail(f"{context}.special_points contains duplicate ids")
        point_ids.add(point_id)
        _number(point["x"], f"{item_context}.x")
        _number(point["y"], f"{item_context}.y")
        _require_string(point["label"], f"{item_context}.label", allow_empty=True)
        _extensions(point["extensions"], f"{item_context}.extensions")
    asymptotes = value["asymptotes"]
    if type(asymptotes) is not list:
        _fail(f"{context}.asymptotes must be a list")
    for index, asymptote in enumerate(asymptotes):
        item_context = f"{context}.asymptotes[{index}]"
        if type(asymptote) is not dict:
            _fail(f"{item_context} must be an object")
        _require_exact(asymptote, {"latex", "kind", "extensions"}, item_context)
        _require_string(asymptote["latex"], f"{item_context}.latex")
        if asymptote["kind"] not in {"vertical", "horizontal", "oblique"}:
            _fail(f"{item_context}.kind is invalid")
        _extensions(asymptote["extensions"], f"{item_context}.extensions")
    _extensions(value["extensions"], f"{context}.extensions")


def _validate_statistics_content(value: Any) -> None:
    context = "FigureIR.content"
    if type(value) is not dict:
        _fail(f"{context} must be an object")
    _require_exact(
        value,
        {"series", "bin_width", "ticks", "axes", "legend", "extensions"},
        context,
    )
    series = value["series"]
    if type(series) is not list or not series:
        _fail(f"{context}.series must be a non-empty list")
    series_ids: set[str] = set()
    for index, item in enumerate(series):
        item_context = f"{context}.series[{index}]"
        if type(item) is not dict:
            _fail(f"{item_context} must be an object")
        _require_exact(item, {"id", "label", "values", "extensions"}, item_context)
        series_id = _require_id(item["id"], f"{item_context}.id")
        if series_id in series_ids:
            _fail(f"{context}.series contains duplicate ids")
        series_ids.add(series_id)
        _require_string(item["label"], f"{item_context}.label", allow_empty=True)
        if type(item["values"]) is not list or not item["values"]:
            _fail(f"{item_context}.values must be a non-empty list")
        for value_index, number in enumerate(item["values"]):
            _number(number, f"{item_context}.values[{value_index}]")
        _extensions(item["extensions"], f"{item_context}.extensions")
    if value["bin_width"] is not None:
        _number(value["bin_width"], f"{context}.bin_width", minimum=0.0000001)
    ticks = value["ticks"]
    if type(ticks) is not dict:
        _fail(f"{context}.ticks must be an object")
    _require_exact(ticks, {"x", "y"}, f"{context}.ticks")
    for axis in ("x", "y"):
        if type(ticks[axis]) is not list:
            _fail(f"{context}.ticks.{axis} must be a list")
        for index, number in enumerate(ticks[axis]):
            _number(number, f"{context}.ticks.{axis}[{index}]")
    _validate_axes(value["axes"], f"{context}.axes")
    if type(value["legend"]) is not bool:
        _fail(f"{context}.legend must be boolean")
    _extensions(value["extensions"], f"{context}.extensions")


def validate_figure_ir(document: Any) -> dict[str, Any]:
    if type(document) is not dict:
        _fail("FigureIR must be an object")
    _require_exact(
        document,
        {
            "schema_id",
            "schema_version",
            "ir_id",
            "revision_id",
            "figure_kind",
            "content",
            "source_refs",
            "original_asset_ref",
            "fallback_asset_ref",
            "style",
            "extensions",
        },
        "FigureIR",
    )
    if document["schema_id"] != FIGURE_IR_SCHEMA_ID:
        _fail("FigureIR schema_id is unsupported")
    if document["schema_version"] != IR_SCHEMA_VERSION:
        raise IrVersionError("FigureIR schema_version is unsupported")
    _require_id(document["ir_id"], "FigureIR.ir_id")
    _require_id(document["revision_id"], "FigureIR.revision_id")
    figure_kind = document["figure_kind"]
    if figure_kind not in FIGURE_KINDS:
        _fail("FigureIR.figure_kind is invalid")
    if figure_kind == "geometry":
        _validate_geometry_content(document["content"])
    elif figure_kind == "function":
        _validate_function_content(document["content"])
    else:
        _validate_statistics_content(document["content"])
    _validate_source_refs(
        document["source_refs"], "FigureIR.source_refs", allow_empty=False
    )
    _relative_path_or_id(document["original_asset_ref"], "FigureIR.original_asset_ref")
    _relative_path_or_id(document["fallback_asset_ref"], "FigureIR.fallback_asset_ref")
    style = document["style"]
    if type(style) is not dict:
        _fail("FigureIR.style must be an object")
    _require_exact(
        style,
        {"monochrome", "line_width_pt", "font_role", "extensions"},
        "FigureIR.style",
    )
    if type(style["monochrome"]) is not bool:
        _fail("FigureIR.style.monochrome must be boolean")
    _number(style["line_width_pt"], "FigureIR.style.line_width_pt", minimum=0.01)
    _require_id(style["font_role"], "FigureIR.style.font_role")
    _extensions(style["extensions"], "FigureIR.style.extensions")
    _extensions(document["extensions"], "FigureIR.extensions")
    return _clone(document)


def validate_paper_ir(document: Any) -> dict[str, Any]:
    if type(document) is not dict:
        _fail("PaperIR must be an object")
    _require_exact(
        document,
        {
            "schema_id",
            "schema_version",
            "ir_id",
            "revision_id",
            "paper_revision_id",
            "document_roles",
            "template_revision_id",
            "title_blocks",
            "instruction_blocks",
            "sections",
            "header_blocks",
            "footer_blocks",
            "template_tokens",
            "declared_total_points",
            "source_refs",
            "extensions",
        },
        "PaperIR",
    )
    if document["schema_id"] != PAPER_IR_SCHEMA_ID:
        _fail("PaperIR schema_id is unsupported")
    if document["schema_version"] != IR_SCHEMA_VERSION:
        raise IrVersionError("PaperIR schema_version is unsupported")
    _require_id(document["ir_id"], "PaperIR.ir_id")
    _require_id(document["revision_id"], "PaperIR.revision_id")
    _require_id(document["paper_revision_id"], "PaperIR.paper_revision_id")
    document_roles = document["document_roles"]
    if type(document_roles) is not list or not document_roles:
        _fail("PaperIR.document_roles must be a non-empty list")
    if (
        any(type(role) is not str or role not in DOCUMENT_ROLES for role in document_roles)
        or document_roles != sorted(set(document_roles))
    ):
        _fail("PaperIR.document_roles must be supported, unique and sorted")
    _require_id(document["template_revision_id"], "PaperIR.template_revision_id")
    _validate_blocks(document["title_blocks"], "PaperIR.title_blocks", allow_empty=False)
    _validate_blocks(
        document["instruction_blocks"],
        "PaperIR.instruction_blocks",
        allow_empty=True,
    )
    _validate_blocks(
        document["header_blocks"], "PaperIR.header_blocks", allow_empty=True
    )
    _validate_blocks(
        document["footer_blocks"], "PaperIR.footer_blocks", allow_empty=True
    )
    sections = document["sections"]
    if type(sections) is not list or not sections:
        _fail("PaperIR.sections must be a non-empty list")
    section_ids: set[str] = set()
    question_ids: set[str] = set()
    display_numbers: set[str] = set()
    total_points = 0.0
    for section_index, section in enumerate(sections):
        section_context = f"PaperIR.sections[{section_index}]"
        if type(section) is not dict:
            _fail(f"{section_context} must be an object")
        _require_exact(
            section,
            {
                "section_id",
                "title_blocks",
                "question_entries",
                "page_break_before",
                "extensions",
            },
            section_context,
        )
        section_id = _require_id(section["section_id"], f"{section_context}.section_id")
        if section_id in section_ids:
            _fail("PaperIR.sections contains duplicate section_id values")
        section_ids.add(section_id)
        _validate_blocks(
            section["title_blocks"],
            f"{section_context}.title_blocks",
            allow_empty=False,
        )
        if type(section["page_break_before"]) is not bool:
            _fail(f"{section_context}.page_break_before must be boolean")
        entries = section["question_entries"]
        if type(entries) is not list or not entries:
            _fail(f"{section_context}.question_entries must be a non-empty list")
        for entry_index, entry in enumerate(entries):
            entry_context = f"{section_context}.question_entries[{entry_index}]"
            if type(entry) is not dict:
                _fail(f"{entry_context} must be an object")
            _require_exact(
                entry,
                {
                    "question_revision_id",
                    "display_number",
                    "points",
                    "options_layout",
                    "answer_space_mm",
                    "page_break_before",
                    "extensions",
                },
                entry_context,
            )
            question_id = _require_id(
                entry["question_revision_id"],
                f"{entry_context}.question_revision_id",
            )
            if question_id in question_ids:
                _fail("PaperIR cannot contain duplicate question revisions")
            question_ids.add(question_id)
            display_number = _require_string(
                entry["display_number"], f"{entry_context}.display_number"
            )
            if display_number in display_numbers:
                _fail("PaperIR display numbers must be unique")
            display_numbers.add(display_number)
            total_points += _number(
                entry["points"], f"{entry_context}.points", minimum=0
            )
            if entry["options_layout"] not in {
                "auto",
                "one_column",
                "two_columns",
                "four_columns",
            }:
                _fail(f"{entry_context}.options_layout is invalid")
            if entry["answer_space_mm"] is not None:
                _number(
                    entry["answer_space_mm"],
                    f"{entry_context}.answer_space_mm",
                    minimum=0,
                )
            if type(entry["page_break_before"]) is not bool:
                _fail(f"{entry_context}.page_break_before must be boolean")
            _extensions(entry["extensions"], f"{entry_context}.extensions")
        _extensions(section["extensions"], f"{section_context}.extensions")
    declared_total = _number(
        document["declared_total_points"],
        "PaperIR.declared_total_points",
        minimum=0,
    )
    if not math.isclose(total_points, declared_total, rel_tol=0, abs_tol=1e-9):
        _fail("PaperIR question point sum must equal declared_total_points")
    tokens = document["template_tokens"]
    if type(tokens) is not dict:
        _fail("PaperIR.template_tokens must be an object")
    for key in sorted(tokens):
        value = tokens[key]
        if type(key) is not str or not _TOKEN_KEY_PATTERN.fullmatch(key):
            _fail("PaperIR.template_tokens contains an invalid key")
        if type(value) not in (str, int, float, bool) or (
            type(value) is float and not math.isfinite(value)
        ):
            _fail("PaperIR.template_tokens values must be finite scalars")
    _validate_source_refs(
        document["source_refs"], "PaperIR.source_refs", allow_empty=True
    )
    _extensions(document["extensions"], "PaperIR.extensions")
    return _clone(document)


def validate_ir_document(document: Any) -> dict[str, Any]:
    if type(document) is not dict:
        _fail("IR document must be an object")
    schema_id = document.get("schema_id")
    if schema_id == QUESTION_IR_SCHEMA_ID:
        return validate_question_ir(document)
    if schema_id == FIGURE_IR_SCHEMA_ID:
        return validate_figure_ir(document)
    if schema_id == PAPER_IR_SCHEMA_ID:
        return validate_paper_ir(document)
    _fail("IR schema_id is unsupported")


def migrate_ir_document(document: Mapping[str, Any]) -> dict[str, Any]:
    value = _clone(document)
    version = value.get("schema_version")
    if version == IR_SCHEMA_VERSION:
        return validate_ir_document(value)
    if version != LEGACY_IR_SCHEMA_VERSION:
        raise IrVersionError("no migration is registered for this IR version")
    if "id" not in value or "ir_id" in value or "extensions" in value:
        raise IrVersionError("legacy IR envelope is not the exact 0.9 shape")
    value["ir_id"] = value.pop("id")
    value["extensions"] = {}
    value["schema_version"] = IR_SCHEMA_VERSION
    return validate_ir_document(value)


def rollback_ir_document(
    document: Mapping[str, Any],
    *,
    target_version: str = LEGACY_IR_SCHEMA_VERSION,
) -> dict[str, Any]:
    if target_version != LEGACY_IR_SCHEMA_VERSION:
        raise IrVersionError("no rollback is registered for the target IR version")
    value = validate_ir_document(document)
    if value["extensions"]:
        raise IrVersionError("cannot losslessly roll back non-empty v1 extensions")
    value["id"] = value.pop("ir_id")
    value.pop("extensions")
    value["schema_version"] = LEGACY_IR_SCHEMA_VERSION
    return value


def dependency_revision_ids(document: Mapping[str, Any]) -> tuple[str, ...]:
    value = validate_ir_document(document)
    dependencies: set[str] = set()
    for source in value["source_refs"]:
        dependencies.add(source["source_file_revision_id"])
    if value["schema_id"] == QUESTION_IR_SCHEMA_ID:
        dependencies.update(value["figure_revision_ids"])
        for scoring_point in value["scoring_points"]:
            dependencies.add(scoring_point["scoring_point_revision_id"])
        for subquestion in value["subquestions"]:
            for scoring_point in subquestion["scoring_points"]:
                dependencies.add(scoring_point["scoring_point_revision_id"])
    elif value["schema_id"] == PAPER_IR_SCHEMA_ID:
        dependencies.add(value["template_revision_id"])
        for section in value["sections"]:
            for entry in section["question_entries"]:
                dependencies.add(entry["question_revision_id"])
    return tuple(sorted(dependencies))


def assert_dependencies_available(
    document: Mapping[str, Any],
    available_revision_ids: Iterable[str],
) -> tuple[str, ...]:
    available = {_require_id(item, "available revision id") for item in available_revision_ids}
    required = dependency_revision_ids(document)
    missing = tuple(item for item in required if item not in available)
    if missing:
        _fail(f"IR dependencies are missing: {', '.join(missing)}")
    return required
