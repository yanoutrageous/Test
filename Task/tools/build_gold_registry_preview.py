from __future__ import annotations

import argparse
import hashlib
import json
import ntpath
import os
import re
import stat
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path, PureWindowsPath
from typing import Any, Iterable, Sequence


_IMPORT_PROJECT_ROOT = Path(
    ntpath.normpath(ntpath.abspath(os.fspath(Path(__file__).parents[2])))
)
if not any(
    ntpath.normcase(entry) == ntpath.normcase(str(_IMPORT_PROJECT_ROOT))
    for entry in sys.path
    if type(entry) is str
):
    sys.path.insert(0, str(_IMPORT_PROJECT_ROOT))

from app.gold_registry import (
    GOLD_REGISTRY_SCHEMA_ID,
    GOLD_SCHEMA_VERSION,
    TRUTH_ROLES,
    validate_gold_registry,
    validate_template_families,
)
from app.project_root import PROJECT_ROOT as VERIFIED_PROJECT_ROOT


RUN_ID_PATTERN = re.compile(r"RUN-[A-Z0-9][A-Z0-9-]{5,80}")
REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
PLAN_PATH = VERIFIED_PROJECT_ROOT / "gold" / "m0" / "gold-source-plan-v1.json"
TEMPLATE_PATH = VERIFIED_PROJECT_ROOT / "gold" / "m0" / "template-families-v1.json"
LOCAL_MAP_PATH = (
    VERIFIED_PROJECT_ROOT / "Task" / "local" / "GOLD_SOURCE_MAP.local.json"
)
PREVIEW_PARENT = VERIFIED_PROJECT_ROOT / "tmp" / "gold_registry_preview"
PLAN_ENTRY_FIELDS = frozenset(
    {
        "logical_id",
        "source_kind",
        "truth_roles",
        "template_family_ids",
        "requirement_ids",
        "risk_ids",
        "license_status",
        "pii_classification",
        "expected_outcome",
        "verification_status",
        "local_mapping_required",
        "copy_policy",
        "test_copy_ref",
    }
)
MEMBER_EXTENSIONS = frozenset({".docx", ".jpg", ".jpeg", ".pdf", ".svg", ".json"})
CONFIRMATION_FIELDS = frozenset(
    {
        "status",
        "actor_ref",
        "confirmed_on",
        "gold_revision",
        "change_reason",
        "previous_aggregate_sha256",
    }
)


class GoldPreviewStop(RuntimeError):
    pass


def _canonical_bytes(value: Any, *, pretty: bool = False) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2 if pretty else None,
            separators=None if pretty else (",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise GoldPreviewStop("gold preview contains non-canonical JSON") from exc
    if pretty:
        text += "\n"
    return text.encode("utf-8")


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise GoldPreviewStop(f"{label} cannot be read") from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GoldPreviewStop(f"{label} must be UTF-8 JSON") from exc
    if type(value) is not dict:
        raise GoldPreviewStop(f"{label} root must be an object")
    return value


def _absolute_lexical(path: str | os.PathLike[str]) -> Path:
    return Path(ntpath.normpath(ntpath.abspath(os.fspath(path))))


def _same_path(left: Path, right: Path) -> bool:
    return ntpath.normcase(str(left)) == ntpath.normcase(str(right))


def _relative_parts(candidate: Path, root: Path) -> tuple[str, ...] | None:
    candidate_parts = PureWindowsPath(str(candidate)).parts
    root_parts = PureWindowsPath(str(root)).parts
    if len(candidate_parts) < len(root_parts):
        return None
    if any(
        ntpath.normcase(actual) != ntpath.normcase(expected)
        for actual, expected in zip(candidate_parts, root_parts, strict=False)
    ):
        return None
    return tuple(candidate_parts[len(root_parts) :])


def _is_reparse(identity: os.stat_result) -> bool:
    return bool(
        stat.S_ISLNK(identity.st_mode)
        or int(getattr(identity, "st_file_attributes", 0)) & REPARSE_ATTRIBUTE
        or int(getattr(identity, "st_reparse_tag", 0))
    )


def _verify_existing_chain(path: Path) -> None:
    for component in (*reversed(path.parents), path):
        try:
            identity = os.lstat(component)
        except OSError as exc:
            raise GoldPreviewStop("required path cannot be inspected") from exc
        if _is_reparse(identity):
            raise GoldPreviewStop("required path chain contains a reparse object")
        if stat.S_ISREG(identity.st_mode) and int(identity.st_nlink) != 1:
            raise GoldPreviewStop("required path chain contains a hardlinked file")


def _verify_source_file(path: Path) -> os.stat_result:
    try:
        identity = os.lstat(path)
    except OSError as exc:
        raise GoldPreviewStop("a mapped gold member cannot be inspected") from exc
    if (
        _is_reparse(identity)
        or not stat.S_ISREG(identity.st_mode)
        or int(identity.st_nlink) != 1
    ):
        raise GoldPreviewStop(
            "a mapped gold member is not a single-link regular non-reparse file"
        )
    return identity


def _identity_tuple(identity: os.stat_result) -> tuple[int, int, int, int]:
    return (
        int(identity.st_dev),
        int(identity.st_ino),
        int(identity.st_size),
        int(identity.st_mtime_ns),
    )


def _hash_source(path: Path) -> tuple[str, int, tuple[int, int, int, int]]:
    before = _verify_source_file(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        opened = os.fstat(descriptor)
        if _identity_tuple(opened) != _identity_tuple(before):
            raise GoldPreviewStop("a mapped gold member changed before hashing")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        if _identity_tuple(after) != _identity_tuple(opened) or total != opened.st_size:
            raise GoldPreviewStop("a mapped gold member changed while hashing")
    finally:
        os.close(descriptor)
    final = _verify_source_file(path)
    if _identity_tuple(final) != _identity_tuple(before):
        raise GoldPreviewStop("a mapped gold member changed after hashing")
    return digest.hexdigest(), total, _identity_tuple(final)


def _parse_length_mm(value: str | None) -> float | None:
    if value is None:
        return None
    match = re.fullmatch(
        r"\s*([0-9]+(?:\.[0-9]+)?)\s*(mm|cm|in|pt)\s*",
        value,
        flags=re.IGNORECASE,
    )
    if match is None:
        return None
    number = float(match.group(1))
    unit = match.group(2).casefold()
    factors = {"mm": 1.0, "cm": 10.0, "in": 25.4, "pt": 25.4 / 72.0}
    return round(number * factors[unit], 3)


def _pdf_metadata(path: Path) -> tuple[int | None, list[list[float]], str]:
    try:
        import fitz

        with fitz.open(path) as document:
            page_count = int(document.page_count)
            if page_count < 1:
                return None, [], "invalid_expected"
            sizes = sorted(
                {
                    (
                        round(float(page.rect.width) * 25.4 / 72.0, 3),
                        round(float(page.rect.height) * 25.4 / 72.0, 3),
                    )
                    for page in document
                }
            )
        return page_count, [list(item) for item in sizes], "readable"
    except Exception:
        return None, [], "invalid_expected"


def _docx_metadata(path: Path) -> tuple[int | None, list[list[float]], str]:
    namespace = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    try:
        with zipfile.ZipFile(path, "r") as archive:
            if archive.testzip() is not None:
                return None, [], "invalid_expected"
            root = ET.fromstring(archive.read("word/document.xml"))
        sizes: set[tuple[float, float]] = set()
        for page_size in root.iter(f"{namespace}pgSz"):
            width = page_size.get(f"{namespace}w")
            height = page_size.get(f"{namespace}h")
            if width is None or height is None:
                continue
            sizes.add(
                (
                    round(int(width) * 25.4 / 1440.0, 3),
                    round(int(height) * 25.4 / 1440.0, 3),
                )
            )
        return None, [list(item) for item in sorted(sizes)], "readable"
    except (OSError, KeyError, ValueError, zipfile.BadZipFile, ET.ParseError):
        return None, [], "invalid_expected"


def _svg_metadata(path: Path) -> tuple[int | None, list[list[float]], str]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return None, [], "invalid_expected"
    if root.tag.rsplit("}", 1)[-1] != "svg":
        return None, [], "invalid_expected"
    forbidden = {"script", "foreignObject"}
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] in forbidden:
            return None, [], "invalid_expected"
        for key, value in element.attrib.items():
            if key.rsplit("}", 1)[-1] == "href" and re.match(
                r"(?i)^(?:https?|file|data):", value.strip()
            ):
                return None, [], "invalid_expected"
    width = _parse_length_mm(root.get("width"))
    height = _parse_length_mm(root.get("height"))
    sizes = [[width, height]] if width is not None and height is not None else []
    return None, sizes, "readable"


def _jpg_metadata(path: Path) -> tuple[int | None, list[list[float]], str]:
    try:
        import fitz

        with fitz.open(path) as document:
            if document.page_count != 1:
                return None, [], "invalid_expected"
            _ = document[0].rect
        return 1, [], "readable"
    except Exception:
        return None, [], "invalid_expected"


def _json_metadata(path: Path) -> tuple[int | None, list[list[float]], str]:
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None, [], "invalid_expected"
    return None, [], "readable"


def _structural_metadata(
    path: Path,
) -> tuple[int | None, list[list[float]], str]:
    extension = path.suffix.casefold()
    if extension == ".pdf":
        return _pdf_metadata(path)
    if extension == ".docx":
        return _docx_metadata(path)
    if extension == ".svg":
        return _svg_metadata(path)
    if extension in {".jpg", ".jpeg"}:
        return _jpg_metadata(path)
    if extension == ".json":
        return _json_metadata(path)
    raise GoldPreviewStop("mapped gold member format is unsupported")


def _member_descriptor(path: Path, expected_outcome: str) -> dict[str, Any]:
    digest, byte_count, identity = _hash_source(path)
    page_count, page_sizes, structural_status = _structural_metadata(path)
    after = _verify_source_file(path)
    if _identity_tuple(after) != identity:
        raise GoldPreviewStop("a mapped gold member changed during structural inspection")
    if expected_outcome == "reject" and structural_status != "invalid_expected":
        raise GoldPreviewStop("a reject gold member unexpectedly passed structural inspection")
    if expected_outcome == "pass" and structural_status != "readable":
        raise GoldPreviewStop("a pass gold member failed structural inspection")
    return {
        "sha256": digest,
        "bytes": byte_count,
        "format": path.suffix.casefold(),
        "page_count": page_count,
        "page_sizes_mm": page_sizes,
        "structural_status": structural_status,
        "extensions": {},
    }


def _directory_members(selector: dict[str, Any]) -> list[Path]:
    expected = {"kind", "path", "recursive", "extensions"}
    if set(selector) != expected:
        raise GoldPreviewStop("a directory selector has an invalid shape")
    root = _absolute_lexical(selector["path"])
    _verify_existing_chain(root)
    if not root.is_dir():
        raise GoldPreviewStop("a mapped gold directory is unavailable")
    recursive = selector["recursive"]
    extensions = selector["extensions"]
    if type(recursive) is not bool or type(extensions) is not list:
        raise GoldPreviewStop("a directory selector is invalid")
    normalized_extensions = {
        item.casefold()
        for item in extensions
        if type(item) is str and item.casefold() in MEMBER_EXTENSIONS
    }
    if len(normalized_extensions) != len(extensions):
        raise GoldPreviewStop("a directory selector extension is unsupported")
    result: list[Path] = []
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for directory_name in tuple(directory_names):
            child = current_path / directory_name
            identity = os.lstat(child)
            if _is_reparse(identity):
                raise GoldPreviewStop("a mapped gold directory contains a reparse object")
        if not recursive:
            directory_names.clear()
        for file_name in file_names:
            candidate = current_path / file_name
            if candidate.suffix.casefold() in normalized_extensions:
                result.append(candidate)
    if not result:
        raise GoldPreviewStop("a mapped gold directory selected no files")
    return result


def _selector_members(selector: Any) -> list[Path]:
    if type(selector) is not dict or type(selector.get("kind")) is not str:
        raise GoldPreviewStop("a private gold selector is invalid")
    kind = selector["kind"]
    if kind == "file":
        if set(selector) != {"kind", "path"} or type(selector["path"]) is not str:
            raise GoldPreviewStop("a file selector has an invalid shape")
        return [_absolute_lexical(selector["path"])]
    if kind == "files":
        if set(selector) != {"kind", "paths"} or type(selector["paths"]) is not list:
            raise GoldPreviewStop("a files selector has an invalid shape")
        if not selector["paths"] or any(type(item) is not str for item in selector["paths"]):
            raise GoldPreviewStop("a files selector must contain paths")
        return [_absolute_lexical(item) for item in selector["paths"]]
    if kind == "directory":
        return _directory_members(selector)
    raise GoldPreviewStop("a private gold selector kind is unsupported")


def _validate_plan(
    plan: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    if set(plan) != {
        "schema_id",
        "schema_version",
        "baseline_authority",
        "confirmation_policy",
        "entries",
        "extensions",
    }:
        raise GoldPreviewStop("gold source plan has an invalid shape")
    if (
        plan["schema_id"] != "LOCAL_EXAM_BANK_GOLD_SOURCE_PLAN"
        or plan["schema_version"] != GOLD_SCHEMA_VERSION
        or plan["baseline_authority"] != "Task/11_REFERENCE_BASELINE.md"
        or plan["extensions"] != {}
        or type(plan["entries"]) is not list
    ):
        raise GoldPreviewStop("gold source plan envelope is invalid")
    confirmation_policy = plan["confirmation_policy"]
    if (
        type(confirmation_policy) is not dict
        or set(confirmation_policy) != {"external", "synthetic"}
    ):
        raise GoldPreviewStop("gold source confirmation policy is invalid")
    for policy_name, confirmation in confirmation_policy.items():
        if type(confirmation) is not dict or set(confirmation) != CONFIRMATION_FIELDS:
            raise GoldPreviewStop(
                f"gold source {policy_name} confirmation has an invalid shape"
            )
    entries: list[dict[str, Any]] = []
    ids: list[str] = []
    for entry in plan["entries"]:
        if type(entry) is not dict or set(entry) != PLAN_ENTRY_FIELDS:
            raise GoldPreviewStop("a gold source plan entry has an invalid shape")
        for field in (
            "truth_roles",
            "template_family_ids",
            "requirement_ids",
            "risk_ids",
        ):
            if type(entry[field]) is not list or entry[field] != sorted(set(entry[field])):
                raise GoldPreviewStop(f"a gold source plan {field} must be sorted")
        ids.append(entry["logical_id"])
        entries.append(entry)
    if ids != sorted(set(ids)):
        raise GoldPreviewStop("gold source plan entries must be unique and sorted")
    return entries, confirmation_policy


def _validate_local_map(
    local_map: dict[str, Any],
    expected_ids: set[str],
) -> dict[str, dict[str, Any]]:
    if set(local_map) != {"schema_id", "schema_version", "entries"}:
        raise GoldPreviewStop("private gold source map has an invalid shape")
    if (
        local_map["schema_id"] != "LOCAL_EXAM_BANK_PRIVATE_GOLD_SOURCE_MAP"
        or local_map["schema_version"] != GOLD_SCHEMA_VERSION
        or type(local_map["entries"]) is not list
    ):
        raise GoldPreviewStop("private gold source map envelope is invalid")
    result: dict[str, dict[str, Any]] = {}
    for entry in local_map["entries"]:
        if type(entry) is not dict or set(entry) != {"logical_id", "selector"}:
            raise GoldPreviewStop("a private gold source map entry is invalid")
        logical_id = entry["logical_id"]
        if type(logical_id) is not str or logical_id in result:
            raise GoldPreviewStop("private gold source map ids are invalid")
        result[logical_id] = entry["selector"]
    if set(result) != expected_ids:
        raise GoldPreviewStop("private gold source map coverage differs from source plan")
    return result


def _entry_from_members(
    plan_entry: dict[str, Any],
    member_descriptors: Iterable[dict[str, Any]],
    *,
    confirmation: dict[str, Any],
) -> dict[str, Any]:
    ordered = sorted(
        member_descriptors,
        key=lambda item: _canonical_bytes(
            {key: value for key, value in item.items() if key != "extensions"}
        ),
    )
    members = [
        {"member_id": f"MEMBER-{index:03d}", **member}
        for index, member in enumerate(ordered, start=1)
    ]
    aggregate_payload = [
        {
            "bytes": member["bytes"],
            "format": member["format"],
            "page_count": member["page_count"],
            "page_sizes_mm": member["page_sizes_mm"],
            "sha256": member["sha256"],
            "structural_status": member["structural_status"],
        }
        for member in members
    ]
    page_counts = [member["page_count"] for member in members]
    page_count = (
        sum(int(item) for item in page_counts)
        if all(item is not None for item in page_counts)
        else None
    )
    page_sizes = sorted(
        {
            tuple(size)
            for member in members
            for size in member["page_sizes_mm"]
        }
    )
    return {
        **plan_entry,
        "member_count": len(members),
        "total_bytes": sum(member["bytes"] for member in members),
        "aggregate_sha256": hashlib.sha256(
            _canonical_bytes({"members": aggregate_payload})
        ).hexdigest(),
        "formats": sorted({member["format"] for member in members}),
        "page_count": page_count,
        "page_sizes_mm": [list(item) for item in page_sizes],
        "baseline_authority": "Task/11_REFERENCE_BASELINE.md",
        "confirmation": json.loads(
            _canonical_bytes(confirmation).decode("utf-8")
        ),
        "members": members,
        "extensions": {},
    }


def _build_registry() -> dict[str, Any]:
    plan_entries, confirmation_policy = _validate_plan(
        _load_object(PLAN_PATH, "gold source plan")
    )
    templates = validate_template_families(
        _load_object(TEMPLATE_PATH, "template-family catalog")
    )
    external_ids = {
        entry["logical_id"]
        for entry in plan_entries
        if entry["local_mapping_required"]
    }
    local_map = _validate_local_map(
        _load_object(LOCAL_MAP_PATH, "private gold source map"),
        external_ids,
    )
    entries: list[dict[str, Any]] = []
    for plan_entry in plan_entries:
        logical_id = plan_entry["logical_id"]
        if plan_entry["local_mapping_required"]:
            paths = _selector_members(local_map[logical_id])
        else:
            reference = plan_entry["test_copy_ref"]
            if type(reference) is not str:
                raise GoldPreviewStop("synthetic plan entry has no Test-local reference")
            path = _absolute_lexical(VERIFIED_PROJECT_ROOT / reference)
            if _relative_parts(path, VERIFIED_PROJECT_ROOT) is None:
                raise GoldPreviewStop("synthetic Test-local reference escaped project root")
            paths = [path]
        descriptors = [
            _member_descriptor(path, plan_entry["expected_outcome"]) for path in paths
        ]
        confirmation_kind = (
            "external" if plan_entry["local_mapping_required"] else "synthetic"
        )
        entries.append(
            _entry_from_members(
                plan_entry,
                descriptors,
                confirmation=confirmation_policy[confirmation_kind],
            )
        )
    template_ids = sorted(
        family["template_family_id"] for family in templates["families"]
    )
    registry_without_digest = {
        "schema_id": GOLD_REGISTRY_SCHEMA_ID,
        "schema_version": GOLD_SCHEMA_VERSION,
        "registry_id": "GOLD-REGISTRY-M0-V1",
        "baseline_authority": "Task/11_REFERENCE_BASELINE.md",
        "entries": entries,
        "required_truth_roles": sorted(TRUTH_ROLES),
        "required_template_family_ids": template_ids,
        "extensions": {},
    }
    registry = {
        **registry_without_digest,
        "registry_sha256": hashlib.sha256(
            _canonical_bytes(registry_without_digest)
        ).hexdigest(),
    }
    return validate_gold_registry(registry)


def _write_exclusive(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise GoldPreviewStop("gold preview write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    identity = os.lstat(path)
    if (
        not stat.S_ISREG(identity.st_mode)
        or int(identity.st_nlink) != 1
        or _is_reparse(identity)
        or path.read_bytes() != payload
    ):
        raise GoldPreviewStop("gold preview readback or identity check failed")


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a sanitized M0 gold registry in a new Test-local preview."
    )
    parser.add_argument("--run-id", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    if not RUN_ID_PATTERN.fullmatch(args.run_id):
        raise GoldPreviewStop("run ID contains unsupported syntax")
    project_root = _absolute_lexical(Path(__file__).parents[2])
    expected_root = _absolute_lexical(VERIFIED_PROJECT_ROOT)
    if not _same_path(project_root, expected_root):
        raise GoldPreviewStop("gold preview tool is outside the contracted project root")
    if not _same_path(_absolute_lexical(Path.cwd()), project_root):
        raise GoldPreviewStop("gold preview tool cwd must be the contracted project root")
    expected_python = project_root / ".venv" / "Scripts" / "python.exe"
    if not _same_path(_absolute_lexical(sys.executable), expected_python):
        raise GoldPreviewStop("gold preview tool requires the project virtual environment")
    _verify_existing_chain(project_root)
    if not PREVIEW_PARENT.exists():
        os.mkdir(PREVIEW_PARENT)
    _verify_existing_chain(PREVIEW_PARENT)
    preview_root = PREVIEW_PARENT / args.run_id
    if _relative_parts(preview_root, PREVIEW_PARENT) != (args.run_id,):
        raise GoldPreviewStop("gold preview root escaped its fixed parent")
    if os.path.lexists(preview_root):
        raise GoldPreviewStop("gold preview run already exists")
    os.mkdir(preview_root)
    _verify_existing_chain(preview_root)

    registry = _build_registry()
    registry_bytes = _canonical_bytes(registry, pretty=True)
    summary = {
        "run_id": args.run_id,
        "generation_status": "PREVIEW_VERIFIED_NOT_PUBLISHED",
        "registry_sha256": registry["registry_sha256"],
        "registry_file_sha256": hashlib.sha256(registry_bytes).hexdigest(),
        "entry_count": len(registry["entries"]),
        "member_count": sum(item["member_count"] for item in registry["entries"]),
        "fingerprinted_bytes": sum(item["total_bytes"] for item in registry["entries"]),
        "truth_roles": registry["required_truth_roles"],
        "template_family_count": len(registry["required_template_family_ids"]),
        "private_locator_fields_emitted": 0,
        "external_files_copied": 0,
    }
    _write_exclusive(preview_root / "gold-registry-v1.json", registry_bytes)
    _write_exclusive(
        preview_root / "preview-summary.json",
        _canonical_bytes(summary, pretty=True),
    )
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GoldPreviewStop as exc:
        raise SystemExit(f"GOLD_PREVIEW_STOP: {exc}") from None
