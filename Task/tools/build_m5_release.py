from __future__ import annotations

import argparse
import hashlib
import io
import ipaddress
import json
import os
import re
import subprocess
import sys
import zipfile
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

import fitz


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.m5_release import (  # noqa: E402
    M5_RELEASE_VERSION,
    M5_REQUIRED_DISTRIBUTIONS,
    _canonical_json_bytes,
    _safe_release_relative,
    verify_release_manifest,
)
from app.m4_backup import M4BackupService  # noqa: E402
from app.safety.workspace_io import get_workspace_io  # noqa: E402


RELEASE_ID = "LOCAL-EXAM-BANK-1.0.0-RC1"
RELEASE_ROOT = PROJECT_ROOT / "output" / "releases"
STAGING_ROOT = RELEASE_ROOT / f"{RELEASE_ID}.staging"
FINAL_ROOT = RELEASE_ROOT / RELEASE_ID
MAX_COPY_BYTES = 64 * 1024 * 1024
RUNTIME_ARCHIVE_RELATIVE = "runtime/python-runtime-win-amd64.zip"
RUNTIME_MANIFEST_RELATIVE = "runtime/runtime-manifest.json"
ZIP_TIMESTAMP = (2026, 7, 25, 0, 0, 0)
TEXT_SUFFIXES = {
    ".cmd",
    ".css",
    ".html",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".sql",
    ".txt",
}
SECRET_PATTERN = re.compile(
    rb"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    rb"gh[pousr]_[A-Za-z0-9_]{20,}|"
    rb"github_pat_[A-Za-z0-9_]{20,}|"
    rb"AKIA[0-9A-Z]{16})"
)
ABSOLUTE_PATH_PATTERN = re.compile(rb"(?i)(?:[A-Z]:\\|file://|\\\\\?\\)")
EMAIL_PATTERN = re.compile(
    rb"(?i)(?<![A-Z0-9._%+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![A-Z0-9.-])"
)
MAINLAND_MOBILE_PATTERN = re.compile(rb"(?<![0-9])1[3-9][0-9]{9}(?![0-9])")
LABELED_IDENTIFIER_PATTERN = re.compile(
    (
        r"(?i)(?:学号|身份证号|证件号|QQ(?:号)?)"
        r"\s*[:：]?\s*[A-Z0-9][A-Z0-9_-]{5,23}"
    ).encode("utf-8")
)
IPV4_PATTERN = re.compile(
    rb"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])"
)
KNOWN_LICENSES = {
    "Jinja2": "BSD-3-Clause",
    "blinker": "MIT",
    "colorama": "BSD-3-Clause",
    "itsdangerous": "BSD-3-Clause",
}


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _git_head() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=PROJECT_ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    value = completed.stdout.strip()
    if completed.returncode or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise RuntimeError("cannot resolve the source Git commit")
    return value


def _require_clean_source_commit(source_commit: str) -> None:
    if _git_head() != source_commit:
        raise RuntimeError("requested release commit is not the checked-out HEAD")
    completed = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=PROJECT_ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    if completed.returncode:
        raise RuntimeError("cannot verify that the release source tree is clean")
    if completed.stdout.strip():
        raise RuntimeError("release source tree must be clean before staging")


def _runtime_license_expression(name: str) -> str:
    dist = metadata.distribution(name)
    return (
        dist.metadata.get("License-Expression")
        or dist.metadata.get("License")
        or KNOWN_LICENSES.get(name)
        or "NOASSERTION"
    )


def _zip_write(
    archive: zipfile.ZipFile,
    archive_name: str,
    payload: bytes,
) -> None:
    info = zipfile.ZipInfo(archive_name, date_time=ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, payload, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def _portable_runtime_archive() -> tuple[bytes, dict[str, Any]]:
    base = Path(sys.base_prefix)
    site_packages = Path(metadata.distribution("Flask").locate_file(".")).resolve()
    if not (base / "python.exe").is_file() or not site_packages.is_dir():
        raise RuntimeError("the audited Python runtime source is unavailable")
    entries: dict[str, bytes] = {}

    def add(source: Path, archive_relative: str) -> None:
        if not source.is_file():
            raise RuntimeError(f"runtime source file is missing: {archive_relative}")
        if "__pycache__" in source.parts or source.suffix.lower() in {".pyc", ".pyo"}:
            return
        payload = source.read_bytes()
        existing = entries.get(archive_relative)
        if existing is not None and existing != payload:
            raise RuntimeError(f"runtime archive path collision: {archive_relative}")
        entries[archive_relative] = payload

    for name in (
        "LICENSE.txt",
        "python.exe",
        "pythonw.exe",
        "python3.dll",
        f"python{sys.version_info.major}{sys.version_info.minor}.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
    ):
        add(base / name, f"python/{name}")

    for path in sorted((base / "DLLs").rglob("*")):
        if not path.is_file() or path.name.startswith("_test"):
            continue
        relative = path.relative_to(base).as_posix()
        add(path, f"python/{relative}")

    excluded_stdlib_roots = {
        "__pycache__",
        "ensurepip",
        "idlelib",
        "site-packages",
        "test",
        "tkinter",
        "turtledemo",
    }
    for path in sorted((base / "Lib").rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(base / "Lib")
        if relative.parts[0] in excluded_stdlib_roots:
            continue
        add(path, f"python/Lib/{relative.as_posix()}")

    component_rows: list[dict[str, Any]] = []
    for name, expected_version in sorted(M5_REQUIRED_DISTRIBUTIONS.items()):
        dist = metadata.distribution(name)
        if dist.version != expected_version:
            raise RuntimeError(
                f"runtime dependency {name} expected {expected_version}, "
                f"observed {dist.version}"
            )
        copied = 0
        copied_bytes = 0
        for relative_file in sorted(dist.files or (), key=lambda item: str(item)):
            source = Path(dist.locate_file(relative_file)).resolve()
            try:
                relative = source.relative_to(site_packages)
            except ValueError:
                continue
            if (
                not source.is_file()
                or "__pycache__" in relative.parts
                or source.suffix.lower() in {".pyc", ".pyo"}
            ):
                continue
            payload = source.read_bytes()
            archive_relative = (
                f"python/Lib/site-packages/{relative.as_posix()}"
            )
            existing = entries.get(archive_relative)
            if existing is not None and existing != payload:
                raise RuntimeError(
                    f"dependency archive path collision: {archive_relative}"
                )
            entries[archive_relative] = payload
            copied += 1
            copied_bytes += len(payload)
        if not copied:
            raise RuntimeError(f"dependency {name} contributed no runtime files")
        component_rows.append(
            {
                "file_count": copied,
                "license": _runtime_license_expression(name),
                "name": name,
                "runtime_bytes": copied_bytes,
                "version": dist.version,
            }
        )

    memory = io.BytesIO()
    with zipfile.ZipFile(
        memory,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        allowZip64=False,
    ) as archive:
        for archive_name in sorted(entries):
            _zip_write(archive, archive_name, entries[archive_name])
    payload = memory.getvalue()
    if len(payload) > MAX_COPY_BYTES:
        raise RuntimeError("portable runtime archive exceeds the fixed writer limit")
    return payload, {
        "archive_file_count": len(entries),
        "archive_uncompressed_bytes": sum(len(value) for value in entries.values()),
        "components": component_rows,
        "implementation": sys.implementation.name,
        "platform": "windows-amd64",
        "python_version": (
            f"{sys.version_info.major}.{sys.version_info.minor}."
            f"{sys.version_info.micro}"
        ),
    }


START_PS1 = r"""param(
  [int]$Port = 8765,
  [switch]$CheckOnly
)
$ErrorActionPreference = "Stop"
$productRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$runtimeManifestPath = Join-Path $productRoot "runtime\runtime-manifest.json"
$runtimeArchivePath = Join-Path $productRoot "runtime\python-runtime-win-amd64.zip"
$runtimeRoot = Join-Path $productRoot ".runtime"
$runtimePython = Join-Path $runtimeRoot "python\python.exe"

if (-not (Test-Path -LiteralPath $runtimeManifestPath -PathType Leaf)) {
  throw "缺少 runtime manifest，请重新完整复制发布包。"
}
$runtimeManifest = Get-Content -LiteralPath $runtimeManifestPath -Raw -Encoding UTF8 |
  ConvertFrom-Json
$observedArchiveHash = (Get-FileHash -LiteralPath $runtimeArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($observedArchiveHash -ne $runtimeManifest.archive_sha256) {
  throw "离线 Python 运行时归档哈希不符，已拒绝启动。"
}

if (-not (Test-Path -LiteralPath $runtimePython -PathType Leaf)) {
  if (Test-Path -LiteralPath $runtimeRoot) {
    throw ".runtime 已存在但不完整；请按故障排查手册保留现场后重新复制发布包。"
  }
  $staging = Join-Path $productRoot (".runtime-install-" + $PID)
  if (Test-Path -LiteralPath $staging) {
    throw "本次运行时安装 staging 已存在，已拒绝覆盖。"
  }
  New-Item -ItemType Directory -Path $staging | Out-Null
  Expand-Archive -LiteralPath $runtimeArchivePath -DestinationPath $staging
  $stagingPython = Join-Path $staging "python\python.exe"
  if (-not (Test-Path -LiteralPath $stagingPython -PathType Leaf)) {
    throw "运行时归档解压后缺少 python.exe。"
  }
  & $stagingPython -B -c "import flask, fitz; print('RUNTIME_IMPORTS_OK')"
  if ($LASTEXITCODE -ne 0) {
    throw "离线运行时依赖导入失败。"
  }
  Move-Item -LiteralPath $staging -Destination $runtimeRoot
}

$env:PYTHONDONTWRITEBYTECODE = "1"
$env:M5_OFFLINE_ENFORCED = "1"
$exitCode = 2
Push-Location -LiteralPath $productRoot
try {
  if ($CheckOnly) {
    & $runtimePython -B -m app.m5_release verify
    $exitCode = $LASTEXITCODE
  } else {
    Write-Host ("本地题库即将启动：http://127.0.0.1:" + $Port + "/")
    Write-Host "结束服务请按 Ctrl+C。"
    & $runtimePython -B -m app.m5_release serve --host 127.0.0.1 --port $Port
    $exitCode = $LASTEXITCODE
  }
} finally {
  Pop-Location
}
exit $exitCode
"""


START_CMD = r"""@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*
exit /b %ERRORLEVEL%
"""


VERIFY_CMD = r"""@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" -CheckOnly
exit /b %ERRORLEVEL%
"""


def _qa_documents(source_commit: str) -> dict[str, bytes]:
    traceability = {
        "M1": {
            "contract": "contracts/m1/m1-acceptance-v1.json",
            "status": "ACCEPTED",
        },
        "M2": {
            "contract": "contracts/m2/m2-acceptance-v1.json",
            "status": "ACCEPTED",
        },
        "M3": {
            "contract": "contracts/m3/m3-acceptance-v1.json",
            "status": "ACCEPTED",
        },
        "M4": {
            "contract": "contracts/m4/m4-acceptance-v1.json",
            "status": "ACCEPTED_AND_REMOTE_VERIFIED",
        },
        "M5": {"status": "SEE_EXTERNAL_FRESH_USER_ACCEPTANCE_EVIDENCE"},
    }
    summary = f"""# 发布候选验收摘要

- 产品版本：{M5_RELEASE_VERSION}
- 源提交：`{source_commit}`
- M0—M4：已按仓库合同验收
- M5：发布前 fresh-user 离线客户流程由包外不可变验收报告记录
- 数据范围：一份 19 题、150 分代表卷
- 分发范围：源资料权利人私有本地使用，不得向第三方再分发来源派生资产
- 网络：应用只允许回环地址
- 打印：仅声明打印就绪 PDF，未操作真实打印机
"""
    visual = """# 视觉回归摘要

当前代表卷、五类文档和批准模板已通过 M1—M3 固定视觉门。发布候选保留原图、
SVG/TikZ 双轨和字体零静默替换策略。全目标集和第三方可分发字体尚未完成。
"""
    recovery = """# 恢复演练摘要

M4 已完成全量/增量备份、staging 恢复、显式激活、中断回退、回滚、重启和固定公开
旅程。M5 fresh-user 验收还将对本发布包再执行一次备份→恢复→重启→重渲染。
"""
    return {
        "qa/验收摘要.md": summary.encode("utf-8"),
        "qa/需求追踪矩阵.json": _canonical_json_bytes(traceability, pretty=True),
        "qa/视觉回归摘要.md": visual.encode("utf-8"),
        "qa/恢复演练摘要.md": recovery.encode("utf-8"),
    }


def _sbom(runtime: dict[str, Any], source_commit: str) -> bytes:
    components: list[dict[str, Any]] = [
        {
            "bom-ref": "pkg:generic/python@"
            + str(runtime["python_version"]),
            "name": "Python",
            "type": "application",
            "version": runtime["python_version"],
            "licenses": [{"license": {"name": "Python-2.0"}}],
        }
    ]
    for row in runtime["components"]:
        normalized = str(row["name"]).lower().replace("_", "-")
        components.append(
            {
                "bom-ref": f"pkg:pypi/{normalized}@{row['version']}",
                "name": row["name"],
                "type": "library",
                "version": row["version"],
                "licenses": [{"license": {"name": row["license"]}}],
                "purl": f"pkg:pypi/{normalized}@{row['version']}",
            }
        )
    document = {
        "bomFormat": "CycloneDX",
        "components": components,
        "metadata": {
            "component": {
                "bom-ref": f"pkg:generic/local-exam-bank@{M5_RELEASE_VERSION}",
                "name": "local-exam-bank",
                "type": "application",
                "version": M5_RELEASE_VERSION,
                "properties": [
                    {"name": "source.git.commit", "value": source_commit},
                    {
                        "name": "distribution.scope",
                        "value": "SOURCE_OWNER_PRIVATE_LOCAL_USE_ONLY",
                    },
                ],
            },
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        },
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000005",
        "specVersion": "1.5",
        "version": 1,
    }
    return _canonical_json_bytes(document, pretty=True)


def _privacy_scan_payload(relative: str, payload: bytes) -> bytes:
    if Path(relative).suffix.lower() != ".pdf":
        return payload
    try:
        with fitz.open(stream=payload, filetype="pdf") as document:
            extracted = "\n".join(page.get_text("text") for page in document)
    except Exception as exc:
        raise RuntimeError(
            f"release privacy scan could not parse PDF: {relative}"
        ) from exc
    return payload + b"\n" + extracted.encode("utf-8")


def _pii_reasons(payload: bytes) -> set[str]:
    reasons: set[str] = set()
    if EMAIL_PATTERN.search(payload):
        reasons.add("email-pattern")
    if MAINLAND_MOBILE_PATTERN.search(payload):
        reasons.add("mainland-mobile-pattern")
    if LABELED_IDENTIFIER_PATTERN.search(payload):
        reasons.add("labeled-identifier-pattern")
    for match in IPV4_PATTERN.finditer(payload):
        try:
            address = ipaddress.ip_address(match.group().decode("ascii"))
        except ValueError:
            continue
        if not address.is_loopback:
            reasons.add("non-loopback-ip-pattern")
            break
    return reasons


class ReleaseBuilder:
    def __init__(self, source_commit: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
            raise RuntimeError("source commit must be a full lowercase SHA-1")
        self.source_commit = source_commit
        self.workspace = get_workspace_io()
        self.service = M4BackupService()
        self.runtime = self.service.current_runtime()
        self.rows: list[dict[str, Any]] = []

    def _existing_release(
        self,
        root: Path,
        *,
        operation: str,
    ) -> dict[str, Any]:
        verification = verify_release_manifest(root)
        manifest_payload = self.workspace.read_bytes(
            root / "release-manifest.json",
            maximum_bytes=16 * 1024 * 1024,
        )
        manifest = json.loads(manifest_payload.decode("utf-8"))
        if (
            manifest["build"]["source_commit"] != self.source_commit
            or manifest["product"]["release_id"] != RELEASE_ID
        ):
            raise RuntimeError("existing release belongs to a different source identity")
        return {
            "manifest_sha256": _sha256(manifest_payload),
            "operation": operation,
            "release_root": root.relative_to(PROJECT_ROOT).as_posix(),
            "tree_sha256": verification["tree_sha256"],
            "verification": verification,
        }

    def _target(self, relative: str) -> Path:
        canonical = _safe_release_relative(relative, field_name="release path")
        return STAGING_ROOT.joinpath(*PurePosixPath(canonical).parts)

    def _write(self, relative: str, payload: bytes, *, role: str) -> None:
        if len(payload) > MAX_COPY_BYTES:
            raise RuntimeError(f"release file exceeds fixed limit: {relative}")
        receipt = self.workspace.create_new_bytes(self._target(relative), payload)
        self.rows.append(
            {
                "bytes": receipt.size_bytes,
                "relative_path": relative,
                "role": role,
                "sha256": receipt.sha256,
            }
        )

    def _copy(self, source: Path, relative: str, *, role: str) -> None:
        payload = self.workspace.read_bytes(source, maximum_bytes=MAX_COPY_BYTES)
        self._write(relative, payload, role=role)

    def _copy_tree(
        self,
        source_root: Path,
        target_root: str,
        *,
        role: str,
        suffixes: set[str] | None = None,
    ) -> None:
        approved = self.workspace.validate_directory_path(source_root)
        files = sorted(
            (path for path in approved.rglob("*") if path.is_file()),
            key=lambda path: path.relative_to(approved).as_posix(),
        )
        for source in files:
            if "__pycache__" in source.parts or source.suffix.lower() in {
                ".pyc",
                ".pyo",
            }:
                continue
            if suffixes is not None and source.suffix.lower() not in suffixes:
                continue
            relative = source.relative_to(approved).as_posix()
            self._copy(
                source,
                f"{target_root}/{relative}",
                role=role,
            )

    def _layout(self) -> None:
        for relative in (
            "Base",
            "Copy/source",
            "LICENSES",
            "SBOM",
            "backups",
            "data/snapshots",
            "data/state/m5",
            "docs",
            "examples",
            "fonts",
            "launcher",
            "qa",
            "runtime",
            "static",
            "templates",
            "tmp/jobs/INTERNAL",
        ):
            self.workspace.ensure_directory(self._target(relative))

    def _application(self) -> None:
        self._copy(
            PROJECT_ROOT / ".exam-bank-root.json",
            ".exam-bank-root.json",
            role="PRODUCT_ROOT_MARKER",
        )
        self._copy_tree(
            PROJECT_ROOT / "app",
            "app",
            role="APPLICATION_SOURCE",
            suffixes={".py", ".sql"},
        )

    def _accepted_data(self) -> None:
        source_root = self.runtime.source_root(self.service.project_root)
        layout = self.runtime.layout
        logical_database = layout.database_path
        database = self.runtime.resolve(logical_database, self.service.project_root)
        self._copy(database, logical_database, role="APPROVED_DATABASE")
        database_state_manifest = database.parent / "state-manifest.json"
        if database_state_manifest.is_file():
            state_relative = (
                PurePosixPath(logical_database).parent / "state-manifest.json"
            ).as_posix()
            self._copy(
                database_state_manifest,
                state_relative,
                role="APPROVED_DATABASE_MANIFEST",
            )
        for logical_root, role in (
            (layout.m1_derived_root, "APPROVED_M1_DATA"),
            (layout.m2_export_root, "APPROVED_M2_EXPORT"),
            (layout.m3_state_root, "APPROVED_M3_DATA"),
            (layout.templates_root, "APPROVED_TEMPLATE_CONFIGURATION"),
        ):
            physical = source_root.joinpath(*PurePosixPath(logical_root).parts)
            self._copy_tree(physical, logical_root, role=role)

    def _documentation(self) -> None:
        self._copy_tree(
            PROJECT_ROOT / "docs" / "m5",
            "docs",
            role="CUSTOMER_DOCUMENTATION",
            suffixes={".md"},
        )
        self._write(
            "examples/README.md",
            (
                "# 代表成品\n\n"
                "五类 PDF 位于 "
                "`data/exports/M2/EXPORT-M2-YANYAN-FULL-150-REV-002/documents/`。"
                "本目录不重复复制，避免额外占用空间。\n"
            ).encode("utf-8"),
            role="EXAMPLE_INDEX",
        )
        self._write(
            "fonts/README.md",
            (
                "# 字体\n\n"
                "本包不分发独立字体文件；具体限制见 `docs/模板与字体说明.md`。\n"
            ).encode("utf-8"),
            role="FONT_POLICY",
        )
        self._write(
            "static/README.md",
            (
                "# 本地静态资源\n\n"
                "当前界面资源随应用源码内置，不使用 CDN、遥测或远程字体。\n"
            ).encode("utf-8"),
            role="STATIC_POLICY",
        )
        self._write(
            "templates/README.md",
            (
                "# 模板\n\n"
                "批准模板及 manifest 位于 `data/derived/M3/` 与 `data/templates/`。\n"
            ).encode("utf-8"),
            role="TEMPLATE_INDEX",
        )
        for relative, payload in _qa_documents(self.source_commit).items():
            self._write(relative, payload, role="QA_SUMMARY")

    def _launcher(self) -> None:
        self._write(
            "launcher/start.ps1",
            START_PS1.encode("utf-8"),
            role="FORMAL_LAUNCHER",
        )
        self._write(
            "launcher/start.cmd",
            START_CMD.replace("\n", "\r\n").encode("utf-8"),
            role="FORMAL_LAUNCHER",
        )
        self._write(
            "launcher/verify.cmd",
            VERIFY_CMD.replace("\n", "\r\n").encode("utf-8"),
            role="FORMAL_LAUNCHER",
        )

    def _runtime(self) -> dict[str, Any]:
        archive, runtime = _portable_runtime_archive()
        archive_sha256 = _sha256(archive)
        runtime_manifest = {
            **runtime,
            "archive_bytes": len(archive),
            "archive_relative_path": RUNTIME_ARCHIVE_RELATIVE,
            "archive_sha256": archive_sha256,
            "bootstrap_writes_relative_path": ".runtime",
            "network_required": False,
            "runtime_schema_version": "1.0",
        }
        self._write(
            RUNTIME_ARCHIVE_RELATIVE,
            archive,
            role="RUNTIME_ARCHIVE",
        )
        self._write(
            RUNTIME_MANIFEST_RELATIVE,
            _canonical_json_bytes(runtime_manifest, pretty=True),
            role="RUNTIME_MANIFEST",
        )
        return runtime_manifest

    def _licenses(self, runtime: dict[str, Any]) -> None:
        base = Path(sys.base_prefix)
        self._write(
            "LICENSES/Python-LICENSE.txt",
            (base / "LICENSE.txt").read_bytes(),
            role="THIRD_PARTY_LICENSE",
        )
        notices: list[str] = [
            "# 第三方软件声明",
            "",
            "本发布候选只供源资料权利人私有本地使用。",
            "",
        ]
        for row in runtime["components"]:
            name = str(row["name"])
            dist = metadata.distribution(name)
            notices.append(
                f"- {name} {dist.version}: {row['license']}"
            )
            copied = 0
            for relative_file in sorted(dist.files or (), key=lambda item: str(item)):
                source = Path(dist.locate_file(relative_file)).resolve()
                filename = source.name.upper()
                if (
                    source.is_file()
                    and (
                        "LICENSE" in filename
                        or "COPYING" in filename
                        or "NOTICE" in filename
                    )
                    and source.stat().st_size <= 256 * 1024
                ):
                    self._write(
                        f"LICENSES/{name}/{source.name}",
                        source.read_bytes(),
                        role="THIRD_PARTY_LICENSE",
                    )
                    copied += 1
            if not copied:
                raise RuntimeError(f"dependency {name} has no packaged license notice")
        notices.extend(
            [
                "",
                "PyMuPDF 1.28.0 为 AGPL-3.0 或 Artifex 商业许可双许可。",
                "上游对应源码：https://github.com/pymupdf/PyMuPDF/tree/1.28.0",
                "本仓库应用源码已随包放在 `app/`；若向第三方传递本包，传递者必须自行",
                "确认并履行 AGPL 或商业许可、内容和字体许可义务。",
                "",
            ]
        )
        self._write(
            "LICENSES/THIRD_PARTY_NOTICES.md",
            ("\n".join(notices)).encode("utf-8"),
            role="THIRD_PARTY_NOTICE",
        )

    def _privacy_scan(self) -> dict[str, Any]:
        findings: list[dict[str, str]] = []
        scanned_pdf_count = 0
        host_markers = {
            str(PROJECT_ROOT).encode("utf-8"),
            str(PROJECT_ROOT).replace("\\", "/").encode("utf-8"),
            Path.home().name.encode("utf-8"),
        }
        for row in self.rows:
            relative = row["relative_path"]
            path = self._target(relative)
            payload = self.workspace.read_bytes(
                path,
                maximum_bytes=MAX_COPY_BYTES,
            )
            if SECRET_PATTERN.search(payload):
                findings.append({"path": relative, "reason": "secret-pattern"})
            if any(marker and marker in payload for marker in host_markers):
                findings.append({"path": relative, "reason": "host-identity-pattern"})
            if (
                row["role"]
                not in {
                    "APPLICATION_SOURCE",
                    "RUNTIME_ARCHIVE",
                    "THIRD_PARTY_LICENSE",
                }
                and Path(relative).suffix.lower() in TEXT_SUFFIXES
            ):
                if ABSOLUTE_PATH_PATTERN.search(payload):
                    findings.append(
                        {"path": relative, "reason": "absolute-path-pattern"}
                    )
            if row["role"] not in {
                "APPLICATION_SOURCE",
                "RUNTIME_ARCHIVE",
                "THIRD_PARTY_LICENSE",
            }:
                scan_payload = _privacy_scan_payload(relative, payload)
                if Path(relative).suffix.lower() == ".pdf":
                    scanned_pdf_count += 1
                for reason in sorted(_pii_reasons(scan_payload)):
                    findings.append({"path": relative, "reason": reason})
        if findings:
            raise RuntimeError(
                "release privacy scan failed: "
                + json.dumps(findings, ensure_ascii=False, sort_keys=True)
            )
        return {
            "absolute_path_findings": 0,
            "host_identity_findings": 0,
            "pii_findings": 0,
            "scanned_pdf_count": scanned_pdf_count,
            "secret_pattern_findings": 0,
            "status": "PASS",
        }

    def build(self) -> dict[str, Any]:
        if os.path.lexists(FINAL_ROOT):
            return self._existing_release(
                FINAL_ROOT,
                operation="ALREADY_PUBLISHED",
            )
        if os.path.lexists(STAGING_ROOT):
            return self._existing_release(
                STAGING_ROOT,
                operation="ALREADY_STAGED",
            )
        _require_clean_source_commit(self.source_commit)
        self.workspace.ensure_directory(RELEASE_ROOT)
        self.workspace.ensure_directory(STAGING_ROOT)
        self._layout()
        self._application()
        self._accepted_data()
        self._documentation()
        self._launcher()
        runtime = self._runtime()
        self._licenses(runtime)
        self._write(
            "SBOM/cyclonedx.json",
            _sbom(runtime, self.source_commit),
            role="SOFTWARE_BILL_OF_MATERIALS",
        )
        privacy = self._privacy_scan()
        ordered = sorted(self.rows, key=lambda row: row["relative_path"])
        tree_sha256 = _sha256(_canonical_json_bytes(ordered))
        manifest = {
            "build": {
                "built_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "distribution_scope": "SOURCE_OWNER_PRIVATE_LOCAL_USE_ONLY",
                "privacy_scan": privacy,
                "source_commit": self.source_commit,
            },
            "files": ordered,
            "manifest_schema_version": "1.0",
            "mutable_paths": [
                ".runtime/",
                "backups/",
                "data/db/active-state.json",
                "data/snapshots/",
                "data/state/",
                "tmp/",
            ],
            "product": {
                "name": "本地可搜索、可组卷的试卷题库系统",
                "release_id": RELEASE_ID,
                "version": M5_RELEASE_VERSION,
            },
            "runtime": {
                "archive_relative_path": RUNTIME_ARCHIVE_RELATIVE,
                "archive_sha256": runtime["archive_sha256"],
                "network_required": False,
                "platform": runtime["platform"],
                "python_version": runtime["python_version"],
            },
            "tree_sha256": tree_sha256,
        }
        self._write(
            "release-manifest.json",
            _canonical_json_bytes(manifest, pretty=True),
            role="RELEASE_MANIFEST",
        )
        staging_verification = verify_release_manifest(STAGING_ROOT)
        return {
            "file_count": len(ordered),
            "manifest_sha256": _sha256(
                (STAGING_ROOT / "release-manifest.json").read_bytes()
            ),
            "operation": "STAGED_FOR_FRESH_USER_ACCEPTANCE",
            "release_root": STAGING_ROOT.relative_to(PROJECT_ROOT).as_posix(),
            "runtime_archive_bytes": runtime["archive_bytes"],
            "runtime_archive_sha256": runtime["archive_sha256"],
            "staging_verification": staging_verification,
            "tree_sha256": tree_sha256,
        }

    def publish(self, acceptance_report_path: Path) -> dict[str, Any]:
        if os.path.lexists(FINAL_ROOT):
            return self._existing_release(
                FINAL_ROOT,
                operation="ALREADY_PUBLISHED",
            )
        if not STAGING_ROOT.is_dir():
            raise RuntimeError("verified release staging is missing")
        _require_clean_source_commit(self.source_commit)
        staging_verification = verify_release_manifest(STAGING_ROOT)
        manifest_payload = self.workspace.read_bytes(
            STAGING_ROOT / "release-manifest.json",
            maximum_bytes=16 * 1024 * 1024,
        )
        report_payload = self.workspace.read_bytes(
            acceptance_report_path,
            maximum_bytes=4 * 1024 * 1024,
        )
        try:
            report = json.loads(report_payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("fresh-user acceptance report is unreadable") from exc
        if type(report) is not dict:
            raise RuntimeError("fresh-user acceptance report is not an object")
        expected = {
            "acceptance_schema_version",
            "completed_at",
            "fresh_user_root_relative",
            "full_manifest_status",
            "journey_failure_count",
            "non_loopback_success_count",
            "outside_write_count",
            "release_id",
            "release_manifest_sha256",
            "source_commit",
            "staging_tree_sha256",
            "status",
            "test_report_sha256",
        }
        fresh_root = PurePosixPath(str(report.get("fresh_user_root_relative", "")))
        if (
            set(report) != expected
            or report["acceptance_schema_version"] != "1.0"
            or report["status"] != "PASS"
            or report["full_manifest_status"] != "PASS"
            or report["release_id"] != RELEASE_ID
            or report["source_commit"] != self.source_commit
            or report["staging_tree_sha256"]
            != staging_verification["tree_sha256"]
            or report["release_manifest_sha256"] != _sha256(manifest_payload)
            or report["journey_failure_count"] != 0
            or report["non_loopback_success_count"] != 0
            or report["outside_write_count"] != 0
            or type(report["completed_at"]) is not str
            or not report["completed_at"]
            or not re.fullmatch(r"[0-9a-f]{64}", report["test_report_sha256"])
            or len(fresh_root.parts) < 4
            or fresh_root.parts[:3] != ("tmp", "acceptance", "fresh-user")
            or any(part in {"", ".", ".."} for part in fresh_root.parts)
        ):
            raise RuntimeError("fresh-user acceptance report does not authorize publish")
        receipt = self.workspace.move_directory_no_replace(
            STAGING_ROOT,
            FINAL_ROOT,
        )
        final_verification = verify_release_manifest(FINAL_ROOT)
        return {
            "acceptance_report_sha256": _sha256(report_payload),
            "manifest_sha256": _sha256(manifest_payload),
            "operation": receipt.operation,
            "release_root": FINAL_ROOT.relative_to(PROJECT_ROOT).as_posix(),
            "tree_sha256": final_verification["tree_sha256"],
            "verification": final_verification,
        }


def _parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-commit", default=None)
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--acceptance-report", type=Path)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    source_commit = args.source_commit or _git_head()
    builder = ReleaseBuilder(source_commit)
    if args.publish:
        if args.acceptance_report is None:
            raise RuntimeError("--publish requires --acceptance-report")
        result = builder.publish(args.acceptance_report)
    else:
        if args.acceptance_report is not None:
            raise RuntimeError("--acceptance-report is only valid with --publish")
        result = builder.build()
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
