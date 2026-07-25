from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import sys
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_file,
)
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.serving import make_server

from .database_backup import DatabaseBackupError, validate_database
from .m2_pipeline import (
    BlueprintUIState,
    M2PipelineConfig,
    M2PipelineError,
    create_blueprint_app,
    load_candidate_pool,
)
from .m3_pipeline import M3PipelineConfig, M3WorkbenchState
from .m4_backup import (
    M4BackupService,
    M4Error,
    _runtime_workbench,
    create_m4_app,
)
from .project_root import PROJECT_ROOT, ProjectRootError, inspect_project_root
from .safety.workspace_io import WorkspaceIOError, get_workspace_io
from .web import create_app as create_library_app


M5_RELEASE_VERSION = "1.0.0-rc1"
M5_SESSION_SCHEMA_VERSION = "1.0"
M5_MAX_SESSION_FILES = 10_000
M5_MAX_SESSION_BYTES = 2 * 1024 * 1024
M5_MINIMUM_FREE_BYTES = 512 * 1024 * 1024
M5_RELEASE_MANIFEST_NAME = "release-manifest.json"
M5_SESSION_NAME = re.compile(r"session-(?P<sequence>[0-9]{8})\.json")
M5_REQUIRED_DISTRIBUTIONS = {
    "blinker": "1.9.0",
    "click": "8.4.2",
    "colorama": "0.4.6",
    "Flask": "3.1.3",
    "itsdangerous": "2.2.0",
    "Jinja2": "3.1.6",
    "MarkupSafe": "3.0.3",
    "PyMuPDF": "1.28.0",
    "Werkzeug": "3.1.8",
}


class M5Error(RuntimeError):
    pass


def _canonical_json_bytes(value: Any, *, pretty: bool = False) -> bytes:
    options: dict[str, Any] = {
        "allow_nan": False,
        "ensure_ascii": False,
        "sort_keys": True,
    }
    if pretty:
        options["indent"] = 2
        return (json.dumps(value, **options) + "\n").encode("utf-8")
    options["separators"] = (",", ":")
    return json.dumps(value, **options).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _safe_release_relative(value: object, *, field_name: str) -> str:
    if type(value) is not str:
        raise M5Error(f"{field_name} must be a relative UTF-8 path")
    candidate = PurePosixPath(value)
    if (
        candidate.is_absolute()
        or "\\" in value
        or ":" in value
        or not candidate.parts
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise M5Error(f"{field_name} is not a safe release-relative path")
    canonical = candidate.as_posix()
    if canonical != value:
        raise M5Error(f"{field_name} is not canonical")
    return canonical


def _blueprint_document(state: BlueprintUIState) -> dict[str, Any]:
    return {
        "excluded": copy.deepcopy(state.excluded),
        "history": copy.deepcopy(state.history),
        "locks": copy.deepcopy(state.locks),
        "selection": copy.deepcopy(state.selection),
        "status": state.status,
        "unsat": copy.deepcopy(state.unsat),
    }


def _workbench_document(state: M3WorkbenchState) -> dict[str, Any]:
    return {
        "active_template_revision_id": state.active_template_revision_id,
        "assertions": copy.deepcopy(state.assertions),
        "basket": copy.deepcopy(state.basket),
        "documents": copy.deepcopy(state.documents),
        "figures": copy.deepcopy(state.figures),
        "history": copy.deepcopy(state.history),
        "semantic_index": copy.deepcopy(state.semantic_index),
        "solution_overrides": copy.deepcopy(state.solution_overrides),
        "taxonomy": copy.deepcopy(state.taxonomy),
        "templates": copy.deepcopy(state.templates),
    }


def _blueprint_from_document(payload: object) -> BlueprintUIState:
    expected = {
        "excluded",
        "history",
        "locks",
        "selection",
        "status",
        "unsat",
    }
    if type(payload) is not dict or set(payload) != expected:
        raise M5Error("persisted blueprint state has an unexpected shape")
    for field_name in ("excluded", "locks", "selection", "unsat"):
        value = payload[field_name]
        if type(value) is not list or any(type(item) is not str for item in value):
            raise M5Error(f"persisted blueprint {field_name} is invalid")
    if type(payload["history"]) is not list or type(payload["status"]) is not str:
        raise M5Error("persisted blueprint history or status is invalid")
    return BlueprintUIState(
        selection=copy.deepcopy(payload["selection"]),
        locks=copy.deepcopy(payload["locks"]),
        excluded=copy.deepcopy(payload["excluded"]),
        history=copy.deepcopy(payload["history"]),
        status=payload["status"],
        unsat=copy.deepcopy(payload["unsat"]),
    )


def _workbench_from_document(payload: object) -> M3WorkbenchState:
    expected = {
        "active_template_revision_id",
        "assertions",
        "basket",
        "documents",
        "figures",
        "history",
        "semantic_index",
        "solution_overrides",
        "taxonomy",
        "templates",
    }
    if type(payload) is not dict or set(payload) != expected:
        raise M5Error("persisted workbench state has an unexpected shape")
    dictionary_fields = (
        "assertions",
        "documents",
        "figures",
        "semantic_index",
        "solution_overrides",
        "taxonomy",
        "templates",
    )
    if any(type(payload[field_name]) is not dict for field_name in dictionary_fields):
        raise M5Error("persisted workbench dictionaries are invalid")
    if (
        type(payload["basket"]) is not list
        or any(type(item) is not str for item in payload["basket"])
        or type(payload["history"]) is not list
        or type(payload["active_template_revision_id"]) is not str
    ):
        raise M5Error("persisted workbench list or revision fields are invalid")
    return M3WorkbenchState(
        figures=copy.deepcopy(payload["figures"]),
        taxonomy=copy.deepcopy(payload["taxonomy"]),
        assertions=copy.deepcopy(payload["assertions"]),
        documents=copy.deepcopy(payload["documents"]),
        semantic_index=copy.deepcopy(payload["semantic_index"]),
        templates=copy.deepcopy(payload["templates"]),
        active_template_revision_id=payload["active_template_revision_id"],
        history=copy.deepcopy(payload["history"]),
        basket=copy.deepcopy(payload["basket"]),
        solution_overrides=copy.deepcopy(payload["solution_overrides"]),
    )


@dataclass(frozen=True, slots=True)
class M5SessionStatus:
    sequence: int
    latest_sha256: str | None
    state_root_relative: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "latest_sha256": self.latest_sha256,
            "sequence": self.sequence,
            "state_root_relative": self.state_root_relative,
        }


class M5SessionStore:
    """Append-only persisted UI state included in subsequent M4 backups."""

    def __init__(self, state_root: Path) -> None:
        try:
            self._relative_root = state_root.resolve().relative_to(
                PROJECT_ROOT.resolve()
            )
        except ValueError as exc:
            raise M5Error("M5 session state escaped the product root") from exc
        self._root = state_root
        self._workspace = get_workspace_io()
        self._lock = threading.Lock()
        self._sequence = 0
        self._latest_sha256: str | None = None

    @property
    def status(self) -> M5SessionStatus:
        return M5SessionStatus(
            sequence=self._sequence,
            latest_sha256=self._latest_sha256,
            state_root_relative=self._relative_root.as_posix(),
        )

    def _session_paths(self) -> list[tuple[int, Path]]:
        if not os.path.lexists(self._root):
            return []
        try:
            approved_root = self._workspace.validate_directory_path(self._root)
        except WorkspaceIOError as exc:
            raise M5Error("M5 session root is not a valid product directory") from exc
        rows: list[tuple[int, Path]] = []
        for path in approved_root.iterdir():
            match = M5_SESSION_NAME.fullmatch(path.name)
            if match is None:
                raise M5Error("M5 session directory contains an unknown entry")
            if not path.is_file():
                raise M5Error("M5 session entry is not a regular file")
            rows.append((int(match.group("sequence")), path))
        rows.sort()
        if len(rows) > M5_MAX_SESSION_FILES:
            raise M5Error("M5 session history exceeds its fixed file limit")
        expected = list(range(1, len(rows) + 1))
        if [sequence for sequence, _ in rows] != expected:
            raise M5Error("M5 session history is not contiguous")
        return rows

    def load(
        self,
        base_blueprint: BlueprintUIState,
        base_workbench: M3WorkbenchState,
    ) -> tuple[BlueprintUIState, M3WorkbenchState]:
        blueprint = base_blueprint
        workbench = base_workbench
        previous_sha256: str | None = None
        session_paths = self._session_paths()
        for sequence, path in session_paths:
            try:
                payload = self._workspace.read_bytes(
                    path,
                    maximum_bytes=M5_MAX_SESSION_BYTES,
                )
                document = json.loads(payload.decode("utf-8"))
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                WorkspaceIOError,
            ) as exc:
                raise M5Error("M5 session revision is unreadable") from exc
            expected = {
                "blueprint",
                "content_sha256",
                "created_at",
                "previous_sha256",
                "schema_version",
                "sequence",
                "workbench",
            }
            if type(document) is not dict or set(document) != expected:
                raise M5Error("M5 session revision has an unexpected shape")
            claimed = document.pop("content_sha256")
            observed = _sha256(_canonical_json_bytes(document))
            if (
                document["schema_version"] != M5_SESSION_SCHEMA_VERSION
                or document["sequence"] != sequence
                or document["previous_sha256"] != previous_sha256
                or type(claimed) is not str
                or claimed != observed
            ):
                raise M5Error("M5 session revision chain is invalid")
            blueprint = _blueprint_from_document(document["blueprint"])
            workbench = _workbench_from_document(document["workbench"])
            previous_sha256 = observed
        self._sequence = len(session_paths)
        self._latest_sha256 = previous_sha256
        return blueprint, workbench

    def commit_revision(
        self,
        blueprint: BlueprintUIState,
        workbench: M3WorkbenchState,
    ) -> M5SessionStatus:
        with self._lock:
            if self._sequence >= M5_MAX_SESSION_FILES:
                raise M5Error("M5 session history reached its fixed file limit")
            sequence = self._sequence + 1
            document: dict[str, Any] = {
                "blueprint": _blueprint_document(blueprint),
                "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "previous_sha256": self._latest_sha256,
                "schema_version": M5_SESSION_SCHEMA_VERSION,
                "sequence": sequence,
                "workbench": _workbench_document(workbench),
            }
            content_sha256 = _sha256(_canonical_json_bytes(document))
            document["content_sha256"] = content_sha256
            payload = _canonical_json_bytes(document, pretty=True)
            if len(payload) > M5_MAX_SESSION_BYTES:
                raise M5Error("M5 session revision exceeds its fixed size limit")
            target = self._root / f"session-{sequence:08d}.json"
            try:
                self._workspace.create_new_bytes(target, payload)
            except WorkspaceIOError as exc:
                raise M5Error("M5 session revision could not be committed") from exc
            self._sequence = sequence
            self._latest_sha256 = content_sha256
            return self.status


def verify_release_manifest(
    project_root: Path = PROJECT_ROOT,
    *,
    quick: bool = False,
) -> dict[str, Any]:
    manifest_path = project_root / M5_RELEASE_MANIFEST_NAME
    if not manifest_path.is_file():
        return {
            "checked_file_count": 0,
            "mode": "development-checkout",
            "status": "NOT_APPLICABLE",
        }
    try:
        payload = get_workspace_io().read_bytes(
            manifest_path,
            maximum_bytes=16 * 1024 * 1024,
        )
        manifest = json.loads(payload.decode("utf-8"))
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        WorkspaceIOError,
    ) as exc:
        raise M5Error("release manifest is unreadable") from exc
    expected = {
        "build",
        "files",
        "manifest_schema_version",
        "mutable_paths",
        "product",
        "runtime",
        "tree_sha256",
    }
    if type(manifest) is not dict or set(manifest) != expected:
        raise M5Error("release manifest has an unexpected shape")
    files = manifest["files"]
    if (
        manifest["manifest_schema_version"] != "1.0"
        or type(files) is not list
        or not files
        or type(manifest["tree_sha256"]) is not str
        or manifest["tree_sha256"] != _sha256(_canonical_json_bytes(files))
    ):
        raise M5Error("release manifest inventory is invalid")
    mutable_paths = manifest["mutable_paths"]
    normalized_mutable_paths: list[str] = []
    if type(mutable_paths) is not list:
        raise M5Error("release manifest mutable-path policy is invalid")
    for index, value in enumerate(mutable_paths):
        if type(value) is not str or not value:
            raise M5Error("release manifest mutable-path policy is invalid")
        is_directory = value.endswith("/")
        candidate = value[:-1] if is_directory else value
        canonical = _safe_release_relative(
            candidate,
            field_name=f"mutable_paths[{index}]",
        )
        normalized = canonical + "/" if is_directory else canonical
        if normalized != value or normalized in normalized_mutable_paths:
            raise M5Error("release manifest mutable-path policy is invalid")
        normalized_mutable_paths.append(normalized)
    product = manifest["product"]
    if (
        type(product) is not dict
        or "version" not in product
        or type(product["version"]) is not str
        or not product["version"]
    ):
        raise M5Error("release manifest product identity is invalid")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, row in enumerate(files):
        if type(row) is not dict or set(row) != {
            "bytes",
            "relative_path",
            "role",
            "sha256",
        }:
            raise M5Error(f"release file row {index} has an unexpected shape")
        relative = _safe_release_relative(
            row["relative_path"],
            field_name=f"files[{index}].relative_path",
        )
        if (
            relative in seen
            or relative == M5_RELEASE_MANIFEST_NAME
            or type(row["bytes"]) is not int
            or row["bytes"] < 0
            or type(row["sha256"]) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
            or type(row["role"]) is not str
            or not row["role"]
        ):
            raise M5Error("release manifest file metadata is invalid")
        seen.add(relative)
        normalized.append(row)
    actual_immutable_files: set[str] = set()
    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    try:
        release_entries = project_root.rglob("*")
        for path in release_entries:
            identity = os.lstat(path)
            attributes = int(getattr(identity, "st_file_attributes", 0))
            reparse_tag = int(getattr(identity, "st_reparse_tag", 0))
            if (
                stat.S_ISLNK(identity.st_mode)
                or attributes & reparse_attribute
                or reparse_tag
            ):
                raise M5Error("release tree contains a reparse object")
            if stat.S_ISDIR(identity.st_mode):
                continue
            if not stat.S_ISREG(identity.st_mode):
                raise M5Error("release tree contains a non-regular file")
            relative = path.relative_to(project_root).as_posix()
            if relative == M5_RELEASE_MANIFEST_NAME:
                continue
            mutable = any(
                (
                    policy.endswith("/")
                    and relative.startswith(policy)
                )
                or (
                    not policy.endswith("/")
                    and relative == policy
                )
                for policy in normalized_mutable_paths
            )
            if not mutable:
                actual_immutable_files.add(relative)
    except OSError as exc:
        raise M5Error("release tree could not be safely inventoried") from exc
    if actual_immutable_files != seen:
        raise M5Error("release tree contains missing or unmanifested immutable files")
    selected = normalized
    if quick:
        required_roles = {
            "APPLICATION_SOURCE",
            "PRODUCT_ROOT_MARKER",
            "RUNTIME_ARCHIVE",
            "RUNTIME_MANIFEST",
        }
        selected = [
            row for row in normalized if row["role"] in required_roles
        ]
    checked: list[dict[str, Any]] = []
    for index, row in enumerate(selected):
        relative = _safe_release_relative(
            row["relative_path"],
            field_name=f"files[{index}].relative_path",
        )
        path = project_root.joinpath(*PurePosixPath(relative).parts)
        try:
            approved = get_workspace_io().validate_read_file_path(path)
            content = get_workspace_io().read_bytes(
                approved,
                maximum_bytes=max(1, int(row["bytes"])),
            )
        except (WorkspaceIOError, ValueError) as exc:
            raise M5Error(f"release file is missing or unsafe: {relative}") from exc
        if (
            len(content) != row["bytes"]
            or _sha256(content) != row["sha256"]
        ):
            raise M5Error(f"release file verification failed: {relative}")
        checked.append(
            {
                "relative_path": relative,
                "sha256": row["sha256"],
            }
        )
    return {
        "checked_file_count": len(checked),
        "mode": "quick" if quick else "full",
        "release_version": product["version"],
        "status": "PASS",
        "tree_sha256": manifest["tree_sha256"],
    }


def inspect_release_environment(
    service: M4BackupService | None = None,
    *,
    quick_manifest: bool = True,
) -> dict[str, Any]:
    service = service or M4BackupService()
    failures: list[str] = []
    try:
        root = inspect_project_root(
            PROJECT_ROOT,
            expected_module_path=Path(__file__).with_name("project_root.py"),
        )
    except ProjectRootError as exc:
        failures.append(str(exc))
        root = None
    dependencies: dict[str, dict[str, Any]] = {}
    for name, expected in M5_REQUIRED_DISTRIBUTIONS.items():
        try:
            observed = metadata.version(name)
        except metadata.PackageNotFoundError:
            observed = None
        dependencies[name] = {
            "expected": expected,
            "observed": observed,
            "status": "PASS" if observed == expected else "FAIL",
        }
        if observed != expected:
            failures.append(f"dependency {name} expected {expected}, observed {observed}")
    disk = shutil.disk_usage(PROJECT_ROOT)
    if disk.free < M5_MINIMUM_FREE_BYTES:
        failures.append("产品根可用空间低于 512 MiB，已阻止启动")
    root_writable = os.access(PROJECT_ROOT, os.W_OK)
    if not root_writable:
        failures.append("产品根不可写，无法安全保存用户状态")
    try:
        runtime = service.current_runtime()
        database = validate_database(
            runtime.resolve(runtime.layout.database_path, service.project_root),
            require_current=True,
        )
        workbench = _runtime_workbench(
            runtime.source_root(service.project_root),
            runtime.layout,
        )
        candidates = load_candidate_pool(
            M2PipelineConfig(
                data_source_root_relative=runtime.source_root_relative,
            )
        )
    except (
        DatabaseBackupError,
        M2PipelineError,
        M4Error,
        WorkspaceIOError,
        OSError,
        ValueError,
    ) as exc:
        raise M5Error("活动数据未通过启动完整性检查") from exc
    active_template = workbench.templates.get(
        workbench.active_template_revision_id,
    )
    if (
        len(candidates) != 19
        or len(workbench.documents) != 19
        or database.integrity_check != "ok"
        or database.foreign_key_violations != 0
        or type(active_template) is not dict
        or active_template.get("status") != "approved"
        or active_template.get("regression", {}).get("passed") is not True
    ):
        failures.append("活动数据库、题库或批准模板未通过启动一致性检查")
    manifest = verify_release_manifest(PROJECT_ROOT, quick=quick_manifest)
    return {
        "active_state_id": runtime.active_state_id,
        "approved_candidate_count": len(candidates),
        "approved_template_revision_id": workbench.active_template_revision_id,
        "database": {
            "foreign_key_violations": database.foreign_key_violations,
            "integrity_check": database.integrity_check,
            "schema_version": database.schema_version,
        },
        "dependencies": dependencies,
        "disk_free_bytes": disk.free,
        "filesystem": root.filesystem if root is not None else None,
        "loopback_only": True,
        "manifest": manifest,
        "offline": True,
        "product_root_writable": root_writable,
        "product_root_verified": root is not None,
        "release_version": M5_RELEASE_VERSION,
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
    }


_PORTAL_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>本地数学题库</title>
  <style>
    body { font-family: system-ui, "Microsoft YaHei", sans-serif; margin: 0;
           color: #15202b; background: #f4f7fb; }
    main { max-width: 960px; margin: 0 auto; padding: 32px 20px; }
    h1 { margin-bottom: 4px; }
    .status { padding: 12px 16px; background: #e8f5ec; border-radius: 10px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(230px,1fr));
            gap: 14px; margin-top: 24px; }
    a.card { display: block; color: inherit; text-decoration: none; background: white;
             border: 1px solid #dce3ea; border-radius: 12px; padding: 18px;
             box-shadow: 0 2px 8px rgb(35 55 80 / 8%); }
    a.card:hover { border-color: #2b6cb0; }
    .small { color: #52616f; font-size: 14px; }
  </style>
</head>
<body><main>
  <h1>本地数学题库</h1>
  <p class="small">版本 {{ version }} · 数据状态 {{ active_state }}</p>
  <p class="status">离线运行，只监听本机回环地址；当前已载入 {{ question_count }} 道审核题。</p>
  <section class="grid">
    <a class="card" href="/library/questions?status=all"><strong>题库与复核</strong><br>
      <span class="small">查看题面、原貌、来源和审核状态</span></a>
    <a class="card" href="/workbench/search?q=函数&limit=10"><strong>检索与相似题</strong><br>
      <span class="small">条件、关键词和本地混合检索</span></a>
    <a class="card" href="/planner/blueprints"><strong>蓝图与组卷</strong><br>
      <span class="small">求解、锁题、换题、排序和不可行诊断</span></a>
    <a class="card" href="/workbench/tags"><strong>标签审核</strong><br>
      <span class="small">证据、知识点和方法标签</span></a>
    <a class="card" href="/workbench/"><strong>图形与模板</strong><br>
      <span class="small">原图、SVG/TikZ 与模板状态</span></a>
    <a class="card" href="/documents"><strong>五类文档</strong><br>
      <span class="small">学生卷、教师卷、答案、解析和答题卡</span></a>
    <a class="card" href="/workbench/maintenance"><strong>备份与恢复</strong><br>
      <span class="small">全量/增量备份、暂存恢复和回滚</span></a>
    <a class="card" href="/status.json"><strong>运行状态</strong><br>
      <span class="small">根目录、依赖、空间和离线检查</span></a>
  </section>
</main></body></html>
"""


_DOCUMENT_TEMPLATE = """
<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>五类文档</title></head>
<body><h1>五类打印就绪 PDF</h1><ul>
{% for role, label in roles %}
  <li><a href="/workbench/runtime/bundles/{{ role }}">{{ label }}</a></li>
{% endfor %}
</ul><p>自动验收仅覆盖 PDF 预检、打开和打印预览，不宣称已操作真实打印机。</p>
</body></html>
"""


def create_m5_application(
    service: M4BackupService | None = None,
) -> DispatcherMiddleware:
    service = service or M4BackupService()
    runtime = service.current_runtime()
    source_root = runtime.source_root(service.project_root)
    base_workbench = _runtime_workbench(source_root, runtime.layout)
    state_root = runtime.resolve("data/state/m5", service.project_root)
    session_store = M5SessionStore(state_root)
    blueprint_state, workbench = session_store.load(
        BlueprintUIState(),
        base_workbench,
    )
    m2_config = M2PipelineConfig(
        data_source_root_relative=runtime.source_root_relative
    )
    candidates = load_candidate_pool(m2_config)

    def persist_state() -> None:
        session_store.commit_revision(blueprint_state, workbench)

    planner = create_blueprint_app(
        candidates,
        config=m2_config,
        state=blueprint_state,
    )
    workbench_app = create_m4_app(
        service,
        workbench=workbench,
    )
    workbench_app.config["TESTING"] = False

    @planner.after_request
    def persist_planner_response(response: Response) -> Response:
        if request.method == "POST" and response.status_code < 500:
            persist_state()
        return response

    @workbench_app.after_request
    def persist_workbench_response(response: Response) -> Response:
        if (
            request.method == "POST"
            and not request.path.startswith("/maintenance/")
            and response.status_code < 500
        ):
            persist_state()
        return response
    library = create_library_app(
        db_path=runtime.resolve(runtime.layout.database_path, service.project_root),
        project_root=service.project_root,
        asset_roots=(
            runtime.resolve(runtime.layout.m1_derived_root, service.project_root),
            runtime.resolve(runtime.layout.m3_state_root, service.project_root),
        ),
    )
    portal = Flask("local-exam-bank-m5")
    portal.config.update(JSON_AS_ASCII=False)
    portal.extensions["m5_service"] = service
    portal.extensions["m5_session_store"] = session_store
    portal.extensions["m5_blueprint_state"] = blueprint_state
    portal.extensions["m5_workbench_state"] = workbench

    @portal.get("/")
    def home() -> str:
        return render_template_string(
            _PORTAL_TEMPLATE,
            active_state=runtime.active_state_id,
            question_count=len(workbench.documents),
            version=M5_RELEASE_VERSION,
        )

    @portal.get("/status.json")
    def status() -> Response:
        try:
            environment = inspect_release_environment(service)
        except (M4Error, M5Error) as exc:
            return jsonify({"status": "FAIL", "message": str(exc)}), 503
        environment["session"] = session_store.status.to_dict()
        environment["question_count"] = len(workbench.documents)
        return jsonify(environment), 200 if environment["status"] == "PASS" else 503

    @portal.get("/documents")
    def documents() -> str:
        return render_template_string(
            _DOCUMENT_TEMPLATE,
            roles=(
                ("student", "学生卷"),
                ("teacher", "教师卷"),
                ("answer", "答案册"),
                ("detailed_solution", "解析册"),
                ("answer_sheet", "答题卡"),
            ),
        )

    @portal.get("/help")
    def help_page() -> Response:
        return redirect("/docs/用户操作手册.md", code=302)

    @portal.get("/docs/<path:name>")
    def documentation(name: str) -> Response:
        try:
            relative = _safe_release_relative(
                f"docs/{name}",
                field_name="documentation path",
            )
            path = PROJECT_ROOT.joinpath(*PurePosixPath(relative).parts)
            approved = get_workspace_io().validate_read_file_path(path)
        except (M5Error, WorkspaceIOError):
            abort(404)
        return send_file(approved, mimetype="text/markdown; charset=utf-8")

    application = DispatcherMiddleware(
        portal,
        {
            "/library": library,
            "/planner": planner,
            "/workbench": workbench_app,
        },
    )
    application.m5_portal = portal
    return application


_OFFLINE_AUDIT_INSTALLED = False


def _m5_network_audit_hook(event: str, arguments: tuple[Any, ...]) -> None:
    if event == "socket.connect":
        if len(arguments) != 2 or not isinstance(arguments[1], tuple):
            raise OSError("离线模式拒绝非 IP 网络目标")
        address = arguments[1]
        if not address:
            raise OSError("离线模式拒绝空网络目标")
        host = address[0]
    elif event in {
        "socket.getaddrinfo",
        "socket.gethostbyaddr",
        "socket.gethostbyname",
    }:
        if not arguments:
            raise OSError("离线模式拒绝空 DNS 目标")
        host = arguments[0]
    else:
        return
    if str(host).lower() == "localhost":
        return
    try:
        loopback = ipaddress.ip_address(str(host)).is_loopback
    except ValueError as exc:
        raise OSError("离线模式拒绝 DNS 或外部网络目标") from exc
    if not loopback:
        raise OSError("离线模式只允许本机回环通信")


def enforce_offline_network() -> None:
    global _OFFLINE_AUDIT_INSTALLED
    if _OFFLINE_AUDIT_INSTALLED:
        return
    sys.addaudithook(_m5_network_audit_hook)
    _OFFLINE_AUDIT_INSTALLED = True


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m app.m5_release")
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--quick", action="store_true")
    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8765)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.command == "verify":
        result = inspect_release_environment(quick_manifest=args.quick)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result["status"] == "PASS" else 2
    if args.host not in {"127.0.0.1", "::1"}:
        raise M5Error("正式服务只允许绑定 127.0.0.1 或 ::1")
    if not 1024 <= args.port <= 65535:
        raise M5Error("端口必须位于 1024—65535")
    readiness = inspect_release_environment(quick_manifest=True)
    if readiness["status"] != "PASS":
        raise M5Error("; ".join(readiness["failures"]))
    if os.environ.get("M5_OFFLINE_ENFORCED", "1") != "1":
        raise M5Error("正式启动必须启用离线网络门")
    enforce_offline_network()
    application = create_m5_application()
    try:
        server = make_server(args.host, args.port, application, threaded=False)
    except OSError as exc:
        raise M5Error(
            f"无法绑定本地端口 {args.port}；请关闭占用程序或选择其他端口"
        ) from exc
    print(
        json.dumps(
            {
                "host": args.host,
                "offline": True,
                "port": args.port,
                "status": "READY",
                "url": f"http://{args.host}:{args.port}/",
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (M4Error, M5Error) as exc:
        print(f"启动失败：{exc}", file=sys.stderr)
        raise SystemExit(2) from exc
