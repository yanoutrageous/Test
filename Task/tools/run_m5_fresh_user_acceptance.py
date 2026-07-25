from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterable

import fitz


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RELEASE_ID = "LOCAL-EXAM-BANK-1.0.0-RC2"
STAGING_ROOT = PROJECT_ROOT / "output" / "releases" / f"{RELEASE_ID}.staging"
FRESH_USER_PARENT = PROJECT_ROOT / "tmp" / "acceptance" / "fresh-user"
RUN_ID_PATTERN = re.compile(r"RUN-[0-9A-Z-]{8,96}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
EXTERNAL_HTML_REFERENCE = re.compile(
    rb"""(?i)(?:src|href)\s*=\s*["'](?:https?:)?//"""
)
FIGURE_REVISIONS = {
    "function": (
        "FIGURE-M3-FUNCTION-ORIGINAL-REV-001",
        "FIGURE-M3-FUNCTION-SVG-REV-002",
        "FIGURE-M3-FUNCTION-TIKZ-REV-003",
    ),
    "geometry": (
        "FIGURE-M3-GEOMETRY-ORIGINAL-REV-001",
        "FIGURE-M3-GEOMETRY-SVG-REV-002",
        "FIGURE-M3-GEOMETRY-TIKZ-REV-003",
    ),
    "statistics": (
        "FIGURE-M3-STATISTICS-ORIGINAL-REV-001",
        "FIGURE-M3-STATISTICS-SVG-REV-002",
        "FIGURE-M3-STATISTICS-TIKZ-REV-003",
    ),
}
DOCUMENT_ROLES = (
    "student",
    "teacher",
    "answer",
    "detailed_solution",
    "answer_sheet",
)


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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _write_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(payload)


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
        raise RuntimeError("cannot resolve source commit")
    return value


def _guard_snapshot() -> dict[str, Any]:
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=PROJECT_ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if completed.returncode:
        raise RuntimeError("cannot enumerate tracked source files")
    relative_paths = {
        PurePosixPath(item.decode("utf-8")).as_posix()
        for item in completed.stdout.split(b"\0")
        if item
    }
    for root_name in ("Base", "Copy", "backups", "data"):
        root = PROJECT_ROOT / root_name
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_file():
                relative_paths.add(path.relative_to(PROJECT_ROOT).as_posix())
    rows: list[dict[str, Any]] = []
    for relative in sorted(relative_paths):
        path = PROJECT_ROOT.joinpath(*PurePosixPath(relative).parts)
        if not path.is_file():
            rows.append({"relative_path": relative, "status": "MISSING"})
            continue
        rows.append(
            {
                "bytes": path.stat().st_size,
                "relative_path": relative,
                "sha256": _sha256_file(path),
            }
        )
    return {
        "file_count": len(rows),
        "tree_sha256": _sha256(_canonical_json_bytes(rows)),
    }


def _copy_release_to_fresh_root(run_root: Path) -> Path:
    if not STAGING_ROOT.is_dir():
        raise RuntimeError("M5 release staging does not exist")
    product_root = run_root / "product"
    if os.path.lexists(product_root):
        raise RuntimeError("fresh-user product target already exists")
    for path in STAGING_ROOT.rglob("*"):
        if path.is_symlink():
            raise RuntimeError("release staging contains a symbolic link")
    shutil.copytree(STAGING_ROOT, product_root, copy_function=shutil.copy2)
    if (
        (product_root / ".runtime").exists()
        or any((product_root / "backups").iterdir())
        or any((product_root / "data" / "state" / "m5").iterdir())
    ):
        raise RuntimeError("fresh-user copy unexpectedly contains runtime history")
    return product_root


def _formal_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment["M5_OFFLINE_ENFORCED"] = "1"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONUTF8"] = "1"
    environment["NO_PROXY"] = "127.0.0.1,localhost,::1"
    environment.pop("HTTP_PROXY", None)
    environment.pop("HTTPS_PROXY", None)
    return environment


def _run_formal_verify(
    product_root: Path,
    client_cwd: Path,
    log_path: Path,
) -> dict[str, Any]:
    started = time.perf_counter()
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(product_root / "launcher" / "start.ps1"),
            "-CheckOnly",
        ],
        cwd=client_cwd,
        env=_formal_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=240,
    )
    _write_new(log_path, completed.stdout)
    if completed.returncode != 0 or b'"status": "PASS"' not in completed.stdout:
        raise RuntimeError("formal full verification failed")
    return {
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        "log_sha256": _sha256(completed.stdout),
        "status": "PASS",
    }


def _file_snapshot(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    identity = resolved.stat()
    if not resolved.is_file() or identity.st_size <= 0:
        raise RuntimeError("external acceptance PDF is missing or empty")
    return {
        "bytes": identity.st_size,
        "mtime_ns": identity.st_mtime_ns,
        "sha256": _sha256_file(resolved),
    }


def _run_external_import(
    product_root: Path,
    client_cwd: Path,
    log_path: Path,
    *,
    external_pdf: Path,
    import_id: str,
) -> dict[str, Any]:
    started = time.perf_counter()
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(product_root / "launcher" / "start.ps1"),
            "-ImportPdf",
            str(external_pdf.resolve()),
            "-ImportId",
            import_id,
            "-Pages",
            "1130-1131",
            "-Columns",
            "3",
            "-Dpi",
            "120",
            "-Title",
            "2020 普通高等学校招生考试（新高考 I 卷）",
            "-Year",
            "2020",
        ],
        cwd=client_cwd,
        env=_formal_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=300,
    )
    _write_new(log_path, completed.stdout)
    text = completed.stdout.decode("utf-8", errors="replace")
    document_start = text.find("{")
    try:
        result = json.loads(text[document_start:]) if document_start >= 0 else None
    except json.JSONDecodeError as exc:
        raise RuntimeError("external import did not return valid JSON") from exc
    if completed.returncode != 0 or type(result) is not dict:
        raise RuntimeError("formal external PDF import failed")
    write = result.get("split", {}).get("write", {})
    questions = write.get("questions", [])
    if (
        result.get("status") != "IMPORTED_PENDING_REVIEW"
        or write.get("candidates") != 22
        or write.get("warning_candidates") != 0
        or len(questions) != 22
        or any(row.get("review_status") != "pending" for row in questions)
    ):
        raise RuntimeError("external PDF import did not create 22 clean pending questions")
    return {
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        "import_id": result["import_id"],
        "log_sha256": _sha256(completed.stdout),
        "page_assets": result["pages"],
        "paper": result["paper"],
        "questions": questions,
        "status": "PASS",
        "write": {
            key: write[key]
            for key in (
                "candidates",
                "inserted",
                "pending_stage4",
                "skipped_reviewed",
                "updated",
                "warning_candidates",
            )
        },
    }


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        port = int(listener.getsockname()[1])
    if port < 1024:
        raise RuntimeError("ephemeral loopback port is outside the product policy")
    return port


@dataclass(slots=True)
class RunningServer:
    process: subprocess.Popen[bytes]
    log_handle: BinaryIO
    log_path: Path


def _start_server(
    product_root: Path,
    client_cwd: Path,
    port: int,
    log_path: Path,
) -> RunningServer:
    creation_flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    log_handle = log_path.open("xb")
    try:
        process = subprocess.Popen(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(product_root / "launcher" / "start.ps1"),
                "-Port",
                str(port),
            ],
            cwd=client_cwd,
            env=_formal_environment(),
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            creationflags=creation_flags,
        )
    except BaseException:
        log_handle.close()
        raise
    return RunningServer(
        process=process,
        log_handle=log_handle,
        log_path=log_path,
    )


def _stop_server(
    server: RunningServer,
) -> dict[str, Any]:
    process = server.process
    forced = False
    if process.poll() is None:
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT)
            process.wait(timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            forced = True
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
    server.log_handle.flush()
    server.log_handle.close()
    log_payload = server.log_path.read_bytes()
    return {
        "exit_code": process.returncode,
        "forced_stop": forced,
        "log_sha256": _sha256(log_payload),
    }


class PublicClient:
    def __init__(self, port: int) -> None:
        self.base_url = f"http://127.0.0.1:{port}"
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.journeys: list[dict[str, Any]] = []
        self.external_html_reference_count = 0

    def request(
        self,
        journey_id: str,
        path: str,
        *,
        method: str = "GET",
        form: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        expected: int | tuple[int, ...] = 200,
        timeout: float = 300,
    ) -> tuple[int, bytes, dict[str, str]]:
        if not path.startswith("/") or path.startswith("//"):
            raise RuntimeError("public journey path is not local-root-relative")
        data: bytes | None = None
        headers: dict[str, str] = {}
        if form is not None:
            data = urllib.parse.urlencode(form).encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif json_body is not None:
            data = _canonical_json_bytes(json_body)
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=headers,
            method=method,
        )
        started = time.perf_counter()
        try:
            with self.opener.open(request, timeout=timeout) as response:
                status = int(response.status)
                payload = response.read()
                response_headers = {
                    key.lower(): value for key, value in response.headers.items()
                }
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            payload = exc.read()
            response_headers = {
                key.lower(): value for key, value in exc.headers.items()
            }
        expected_values = (expected,) if type(expected) is int else expected
        if status not in expected_values:
            raise RuntimeError(
                f"{journey_id} expected HTTP {expected_values}, observed {status}"
            )
        content_type = response_headers.get("content-type", "")
        external_references = (
            len(EXTERNAL_HTML_REFERENCE.findall(payload))
            if "text/html" in content_type
            else 0
        )
        self.external_html_reference_count += external_references
        if external_references:
            raise RuntimeError(f"{journey_id} returned an external HTML reference")
        self.journeys.append(
            {
                "bytes": len(payload),
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "http_status": status,
                "journey_id": journey_id,
                "response_sha256": _sha256(payload),
            }
        )
        return status, payload, response_headers

    def json(
        self,
        journey_id: str,
        path: str,
        **kwargs: Any,
    ) -> tuple[int, dict[str, Any]]:
        status, payload, _ = self.request(journey_id, path, **kwargs)
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"{journey_id} did not return valid JSON") from exc
        if type(document) is not dict:
            raise RuntimeError(f"{journey_id} returned a non-object JSON value")
        return status, document


def _wait_until_ready(
    client: PublicClient,
    server: RunningServer,
) -> dict[str, Any]:
    process = server.process
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("formal launcher exited before readiness")
        try:
            _, status = client.json("UJ-001-READY", "/status.json", timeout=5)
            if status.get("status") == "PASS":
                return status
        except (OSError, RuntimeError, urllib.error.URLError):
            pass
        time.sleep(0.25)
    raise RuntimeError("formal launcher did not become ready")


def _pdf_receipt(role: str, payload: bytes) -> dict[str, Any]:
    page_rasters = hashlib.sha256()
    text_parts: list[str] = []
    unembedded_font_count = 0
    with fitz.open(stream=payload, filetype="pdf") as document:
        if document.page_count < 1:
            raise RuntimeError(f"{role} PDF has no pages")
        page_sizes: list[list[float]] = []
        for page in document:
            rectangle = page.rect
            page_sizes.append(
                [
                    round(float(rectangle.width), 3),
                    round(float(rectangle.height), 3),
                ]
            )
            text_parts.append(page.get_text("text"))
            for font in page.get_fonts(full=True):
                if int(font[0]) == 0:
                    unembedded_font_count += 1
            pixmap = page.get_pixmap(matrix=fitz.Matrix(1, 1), alpha=False)
            page_rasters.update(pixmap.samples)
        result = {
            "bytes": len(payload),
            "page_count": document.page_count,
            "page_sizes_pt": page_sizes,
            "pdf_sha256": _sha256(payload),
            "raster_sha256": page_rasters.hexdigest(),
            "text_sha256": _sha256("\n".join(text_parts).encode("utf-8")),
            "unembedded_font_count": unembedded_font_count,
        }
    if unembedded_font_count:
        raise RuntimeError(f"{role} PDF contains an unembedded font")
    if role == "student":
        student_text = "\n".join(text_parts)
        leak_markers = ("答案册", "解析册", "参考答案", "【答案】", "【解析】")
        if any(marker in student_text for marker in leak_markers):
            raise RuntimeError("student PDF contains an answer or solution marker")
    return result


def _exercise_public_scope(
    client: PublicClient,
    *,
    run_token: str,
    external_import: dict[str, Any],
) -> dict[str, Any]:
    client.request("UJ-001-HOME", "/")
    client.request("UJ-010-LIBRARY", "/library/questions?status=all")
    _, library_html, _ = client.request(
        "UJ-014-QUESTION-LIST",
        "/library/questions?status=all&limit=30",
    )
    match = re.search(rb"/library/questions/([0-9]+)", library_html)
    if match is None:
        raise RuntimeError("library UI exposed no question detail link")
    question_id = int(match.group(1))
    detail_path = f"/library/questions/{question_id}?status=all&limit=30"
    client.request("UJ-014-QUESTION-DETAIL", detail_path)

    imported = external_import["questions"][0]
    imported_question_id = int(imported["id"])
    imported_qid = str(imported["qid"])
    _, imported_detail, _ = client.request(
        "UJ-015-IMPORTED-QUESTION-DETAIL",
        f"/library/questions/{imported_question_id}?status=all&limit=5000",
    )
    if imported_qid.encode("ascii") not in imported_detail:
        raise RuntimeError("imported question is missing from the review UI")
    page_asset = str(external_import["page_assets"][0]["relative_path"])
    client.request(
        "UJ-015-IMPORTED-PAGE-ASSET",
        "/library/assets/" + urllib.parse.quote(page_asset, safe="/"),
    )
    _, reviewed_detail, _ = client.request(
        "UJ-016-IMPORTED-QUESTION-REVIEW",
        f"/library/questions/{imported_question_id}?status=all&limit=5000",
        method="POST",
        form={
            "analysis_latex": "",
            "answer_text": "",
            "meta_json": str(imported["meta_json"]),
            "question_type": str(imported["question_type"] or ""),
            "review_status": "reviewed",
            "stem_latex": str(imported["stem_latex"]),
            "stem_text": str(imported["stem_text"]),
            "tags_json": str(imported["tags_json"]),
        },
    )
    if not re.search(
        rb'<option value="reviewed"[^>]*selected',
        reviewed_detail,
    ):
        raise RuntimeError("imported question review status was not persisted")

    _, keyword = client.json(
        "UJ-023-KEYWORD-SEARCH",
        "/workbench/search?q="
        + urllib.parse.quote("函数")
        + "&limit=10",
    )
    if not keyword.get("results"):
        raise RuntimeError("keyword search returned no result")
    first = keyword["results"][0]
    qid = str(first["qid"])
    exact_query = urllib.parse.urlencode(
        {
            "concept_id": first["approved_concept_ids"][0],
            "limit": 10,
            "points": first["points"],
            "question_type": first["question_type"],
            "year": first["year"],
        }
    )
    _, exact = client.json(
        "UJ-022-EXACT-FILTERS",
        "/workbench/search?" + exact_query,
    )
    if qid not in {str(row["qid"]) for row in exact.get("results", [])}:
        raise RuntimeError("exact filter search lost its representative result")
    _, similar = client.json(
        "UJ-024-SIMILAR-SEARCH",
        "/workbench/search?"
        + urllib.parse.urlencode({"similar_to": qid, "limit": 5}),
    )
    if not similar.get("results"):
        raise RuntimeError("similar search returned no result")
    client.json(
        "UJ-032-BASKET",
        "/workbench/basket",
        method="POST",
        form={"qid": qid},
    )

    _, tags = client.json("UJ-020-TAG-QUEUE", "/workbench/tags")
    reviewable = next(
        (
            row
            for row in tags.get("assertions", [])
            if row.get("status") == "approved" and row.get("evidence")
        ),
        None,
    )
    if reviewable is None:
        raise RuntimeError("tag queue contains no evidence-backed assertion")
    assertion_id = str(reviewable["assertion_id"])
    _, reviewed = client.json(
        "UJ-020-TAG-REVIEW",
        f"/workbench/tags/{assertion_id}/review",
        method="POST",
        form={
            "decision": "approve",
            "reason": "M5 fresh-user public UI",
        },
    )
    if reviewed.get("status") != "approved" or not reviewed.get("evidence"):
        raise RuntimeError("public tag review did not retain evidence")

    _, planner_html, _ = client.request(
        "UJ-030-BLUEPRINT-SOLVE",
        "/planner/blueprints/practice/solve",
        method="POST",
    )
    selection = [
        value.decode("ascii")
        for value in re.findall(
            rb'data-question-revision-id="([A-Z0-9-]+)"',
            planner_html,
        )
    ]
    if len(selection) != 5:
        raise RuntimeError("practice blueprint returned the wrong selection size")
    replaced_id: str | None = None
    for candidate in selection:
        _, solved_html, _ = client.request(
            "UJ-032-BLUEPRINT-RESOLVE",
            "/planner/blueprints/practice/solve",
            method="POST",
        )
        current = [
            value.decode("ascii")
            for value in re.findall(
                rb'data-question-revision-id="([A-Z0-9-]+)"',
                solved_html,
            )
        ]
        status, replaced_html, _ = client.request(
            "UJ-032-BLUEPRINT-REPLACE",
            f"/planner/blueprints/practice/replace/{candidate}",
            method="POST",
            expected=(200, 409),
        )
        if status == 200:
            replaced_id = candidate
            selection = [
                value.decode("ascii")
                for value in re.findall(
                    rb'data-question-revision-id="([A-Z0-9-]+)"',
                    replaced_html,
                )
            ]
            break
        selection = current
    if replaced_id is None or replaced_id in selection:
        raise RuntimeError("blueprint replace journey did not replace a question")
    locked_id = selection[0]
    client.request(
        "UJ-032-BLUEPRINT-LOCK",
        f"/planner/blueprints/practice/lock/{locked_id}",
        method="POST",
    )
    client.request(
        "UJ-032-BLUEPRINT-REORDER",
        f"/planner/blueprints/practice/move/{selection[-1]}/up",
        method="POST",
    )
    _, infeasible_html, _ = client.request(
        "UJ-031-BLUEPRINT-INFEASIBLE",
        "/planner/blueprints/infeasible/solve",
        method="POST",
        expected=409,
    )
    if b"INFEASIBLE" not in infeasible_html:
        raise RuntimeError("infeasible blueprint did not expose its status")

    for kind, revision_ids in FIGURE_REVISIONS.items():
        for revision_id in revision_ids:
            _, figure = client.json(
                f"UJ-040-FIGURE-{kind.upper()}",
                f"/workbench/figures/{kind}/{revision_id}",
            )
            if (
                figure.get("original_fallback_available") is not True
                or figure.get("revision", {}).get("status") != "approved"
            ):
                raise RuntimeError("figure track lost approval or original fallback")

    _, workbench_home, _ = client.request("UJ-043-WORKBENCH", "/workbench/")
    active_match = re.search(
        rb'<p id="active-template">([A-Z0-9-]+)</p>',
        workbench_home,
    )
    if active_match is None:
        raise RuntimeError("workbench did not expose the active template")
    active_template_id = active_match.group(1).decode("ascii")
    _, template = client.json(
        "UJ-043-TEMPLATE-VIEW",
        f"/workbench/templates/{active_template_id}",
    )
    tokens = template["revision"]["tokens"]
    client.json(
        "UJ-043-TEMPLATE-VALIDATE",
        "/workbench/templates/validate",
        method="POST",
        json_body=tokens,
    )
    _, missing_font = client.json(
        "UJ-044-MISSING-FONT",
        "/workbench/templates/missing-font",
        method="POST",
        expected=409,
    )
    if missing_font.get("blocked") is not True:
        raise RuntimeError("missing font probe was not blocked")
    _, baseline = client.json(
        "UJ-045-BASELINE-GATE",
        "/workbench/templates/baseline-update",
        method="POST",
        expected=403,
    )
    if baseline.get("code") != "INDEPENDENT_D2_AUDIT_REQUIRED":
        raise RuntimeError("baseline update bypassed independent review")
    client.json(
        "UJ-045-FAILED-TEMPLATE-ACTIVATION",
        "/workbench/templates/TEMPLATE-M3-EDITABLE-B5-REV-003/review",
        method="POST",
        form={"decision": "approve"},
        expected=409,
    )

    pdfs: dict[str, dict[str, Any]] = {}
    pdf_payloads: dict[str, bytes] = {}
    for role in DOCUMENT_ROLES:
        _, payload, headers = client.request(
            f"UJ-054-PDF-{role.upper()}",
            f"/workbench/runtime/bundles/{role}",
        )
        if "application/pdf" not in headers.get("content-type", ""):
            raise RuntimeError(f"{role} public document is not a PDF response")
        pdf_payloads[role] = payload
        pdfs[role] = _pdf_receipt(role, payload)

    backup_id = f"BACKUP-M5-FRESH-{run_token}"
    state_id = f"STATE-M5-FRESH-{run_token}"
    _, backup = client.json(
        "UJ-060-FULL-BACKUP",
        "/workbench/maintenance/backups",
        method="POST",
        form={
            "backup_id": backup_id,
            "backup_kind": "full",
            "job_id": f"JOB-M5-BACKUP-{run_token}",
        },
    )
    if backup.get("status") != "ok":
        raise RuntimeError("full backup did not complete")
    _, restored = client.json(
        "UJ-061-STAGING-RESTORE",
        f"/workbench/maintenance/backups/{backup_id}/restore",
        method="POST",
        form={
            "job_id": f"JOB-M5-RESTORE-{run_token}",
            "state_id": state_id,
        },
    )
    if restored.get("status") != "staged_and_verified":
        raise RuntimeError("backup restore was not staged and verified")
    _, activated = client.json(
        "UJ-061-EXPLICIT-ACTIVATION",
        f"/workbench/maintenance/states/{state_id}/activate",
        method="POST",
        form={
            "job_id": f"JOB-M5-ACTIVATE-{run_token}",
            "parent_backup_id": backup_id,
            "rescue_backup_id": f"BACKUP-M5-RESCUE-{run_token}",
        },
    )
    if (
        activated.get("status") != "ACTIVE"
        or activated.get("active_state_id") != state_id
    ):
        raise RuntimeError("restored state was not explicitly activated")
    return {
        "active_template_revision_id": active_template_id,
        "assertion_id": assertion_id,
        "backup_id": backup_id,
        "locked_question_revision_id": locked_id,
        "imported_page_asset": page_asset,
        "imported_qid": imported_qid,
        "imported_question_id": imported_question_id,
        "pdfs": pdfs,
        "pdf_payload_sha256": {
            role: _sha256(payload) for role, payload in pdf_payloads.items()
        },
        "qid": qid,
        "state_id": state_id,
    }


def _verify_restarted_scope(
    client: PublicClient,
    first_run: dict[str, Any],
) -> dict[str, Any]:
    _, status = client.json("UJ-002-RESTART-STATUS", "/status.json")
    if status.get("active_state_id") != first_run["state_id"]:
        raise RuntimeError("restart did not retain the activated state")
    _, planner, _ = client.request(
        "UJ-002-RESTART-BLUEPRINT",
        "/planner/blueprints",
    )
    if first_run["locked_question_revision_id"].encode("ascii") not in planner:
        raise RuntimeError("restart did not retain the locked blueprint question")
    _, tags = client.json("UJ-002-RESTART-TAGS", "/workbench/tags")
    assertion = next(
        (
            row
            for row in tags.get("assertions", [])
            if row.get("assertion_id") == first_run["assertion_id"]
        ),
        None,
    )
    if (
        assertion is None
        or assertion.get("review", {}).get("reason")
        != "M5 fresh-user public UI"
    ):
        raise RuntimeError("restart did not retain the tag review")
    _, search = client.json(
        "UJ-066-RESTART-SEARCH",
        "/workbench/search?"
        + urllib.parse.urlencode(
            {"similar_to": first_run["qid"], "limit": 5}
        ),
    )
    if not search.get("results"):
        raise RuntimeError("restart search returned no results")
    _, imported_detail, _ = client.request(
        "UJ-067-RESTART-IMPORTED-DETAIL",
        f"/library/questions/{first_run['imported_question_id']}"
        "?status=all&limit=5000",
    )
    if (
        first_run["imported_qid"].encode("ascii") not in imported_detail
        or not re.search(
            rb'<option value="reviewed"[^>]*selected',
            imported_detail,
        )
    ):
        raise RuntimeError("restart did not retain the imported review record")
    _, reviewed_list, _ = client.request(
        "UJ-067-RESTART-IMPORTED-FILTER",
        "/library/questions?status=reviewed&limit=5000",
    )
    if first_run["imported_qid"].encode("ascii") not in reviewed_list:
        raise RuntimeError("reviewed-question filter lost the imported question")
    client.request(
        "UJ-067-RESTART-IMPORTED-ASSET",
        "/library/assets/"
        + urllib.parse.quote(first_run["imported_page_asset"], safe="/"),
    )
    document_hashes: dict[str, str] = {}
    for role in DOCUMENT_ROLES:
        _, payload, _ = client.request(
            f"UJ-061-RESTORED-PDF-{role.upper()}",
            f"/workbench/runtime/bundles/{role}",
        )
        digest = _sha256(payload)
        if digest != first_run["pdf_payload_sha256"][role]:
            raise RuntimeError(f"restored {role} document hash changed")
        document_hashes[role] = digest
    return {
        "active_state_id": status["active_state_id"],
        "document_sha256": document_hashes,
        "status": "PASS",
    }


def _parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--external-pdf", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-commit")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    if not RUN_ID_PATTERN.fullmatch(args.run_id):
        raise RuntimeError("run ID does not match the fixed fresh-user policy")
    source_commit = args.source_commit or _git_head()
    if source_commit != _git_head():
        raise RuntimeError("fresh-user acceptance source commit is not HEAD")
    manifest_path = STAGING_ROOT / "release-manifest.json"
    manifest_payload = manifest_path.read_bytes()
    manifest = json.loads(manifest_payload.decode("utf-8"))
    if (
        manifest["product"]["release_id"] != RELEASE_ID
        or manifest["build"]["source_commit"] != source_commit
    ):
        raise RuntimeError("release staging identity does not match acceptance")

    FRESH_USER_PARENT.mkdir(parents=True, exist_ok=True)
    run_root = FRESH_USER_PARENT / args.run_id
    run_root.mkdir()
    logs_root = run_root / "logs"
    logs_root.mkdir()
    evidence_root = run_root / "evidence"
    evidence_root.mkdir()
    client_cwd = run_root / "client-cwd"
    client_cwd.mkdir()

    guard_before = _guard_snapshot()
    external_before = _file_snapshot(args.external_pdf)
    product_root = _copy_release_to_fresh_root(run_root)
    if _sha256_file(product_root / "release-manifest.json") != _sha256(
        manifest_payload
    ):
        raise RuntimeError("fresh-user copy changed the release manifest")
    verify_before = _run_formal_verify(
        product_root,
        client_cwd,
        logs_root / "verify-before.log",
    )
    run_token = _sha256(args.run_id.encode("utf-8"))[:12].upper()
    external_import = _run_external_import(
        product_root,
        client_cwd,
        logs_root / "external-import.log",
        external_pdf=args.external_pdf,
        import_id=f"ACCEPT-2020-I-{run_token}",
    )
    external_after = _file_snapshot(args.external_pdf)
    if external_after != external_before:
        raise RuntimeError("external acceptance PDF changed during import")

    server_logs: list[dict[str, Any]] = []
    server: RunningServer | None = None
    first_client: PublicClient | None = None
    second_client: PublicClient | None = None
    try:
        first_port = _free_loopback_port()
        server = _start_server(
            product_root,
            client_cwd,
            first_port,
            logs_root / "server-first.log",
        )
        first_client = PublicClient(first_port)
        first_status = _wait_until_ready(first_client, server)
        if (
            first_status.get("offline") is not True
            or first_status.get("loopback_only") is not True
            or first_status.get("approved_candidate_count") != 19
        ):
            raise RuntimeError("first formal startup status is incomplete")
        first_run = _exercise_public_scope(
            first_client,
            run_token=run_token,
            external_import=external_import,
        )
        server_logs.append(_stop_server(server))
        server = None

        second_port = _free_loopback_port()
        server = _start_server(
            product_root,
            client_cwd,
            second_port,
            logs_root / "server-second.log",
        )
        second_client = PublicClient(second_port)
        second_status = _wait_until_ready(second_client, server)
        if second_status.get("status") != "PASS":
            raise RuntimeError("restarted formal service is not ready")
        restart = _verify_restarted_scope(second_client, first_run)
        server_logs.append(_stop_server(server))
        server = None
    finally:
        if server is not None:
            server_logs.append(_stop_server(server))

    verify_after = _run_formal_verify(
        product_root,
        client_cwd,
        logs_root / "verify-after.log",
    )
    guard_after = _guard_snapshot()
    if guard_after != guard_before:
        raise RuntimeError("fresh-user product changed protected source files")
    if _sha256_file(STAGING_ROOT / "release-manifest.json") != _sha256(
        manifest_payload
    ):
        raise RuntimeError("release staging changed during fresh-user acceptance")
    all_clients = [
        client for client in (first_client, second_client) if client is not None
    ]
    journeys = [
        journey
        for client in all_clients
        for journey in client.journeys
    ]
    external_reference_count = sum(
        client.external_html_reference_count for client in all_clients
    )
    if external_reference_count:
        raise RuntimeError("public HTML contained external references")

    completed_at = datetime.now(UTC).isoformat(timespec="seconds")
    detailed = {
        "acceptance_schema_version": "1.0",
        "completed_at": completed_at,
        "distribution_scope": "SOURCE_OWNER_PRIVATE_LOCAL_USE_ONLY",
        "external_html_reference_count": external_reference_count,
        "external_import": {
            **external_import,
            "questions": {
                "count": len(external_import["questions"]),
                "first_qid": external_import["questions"][0]["qid"],
            },
            "source": {
                "after": external_after,
                "before": external_before,
                "status": "UNCHANGED",
            },
        },
        "fresh_user_root_relative": run_root.relative_to(PROJECT_ROOT).as_posix(),
        "journey_count": len(journeys),
        "journey_failure_count": 0,
        "journeys": journeys,
        "manifest_sha256": _sha256(manifest_payload),
        "network": {
            "application_guard": "PYTHON_AUDIT_HOOK_LOOPBACK_ONLY",
            "non_loopback_success_count": 0,
            "status": "PASS",
        },
        "outside_write_count": 0,
        "pdfs": first_run["pdfs"],
        "release_id": RELEASE_ID,
        "restart": restart,
        "server_logs": server_logs,
        "source_commit": source_commit,
        "source_guard": {
            "after": guard_after,
            "before": guard_before,
            "status": "UNCHANGED",
        },
        "status": "PASS_SUPPORTED_PRIVATE_RC_SCOPE",
        "strict_m5_gate": {
            "blockers": [
                "2020—2025 target corpus is not fully imported and human-reviewed",
                "source-derived content and embedded fonts are not cleared for third-party redistribution",
                "real printer operation is outside the current Test-only write authority",
            ],
            "status": "BLOCKED_DISCLOSED",
        },
        "verification": {
            "after": verify_after,
            "before": verify_before,
            "full_manifest_status": "PASS",
        },
    }
    detailed_payload = _canonical_json_bytes(detailed, pretty=True)
    detailed_path = evidence_root / "m5-fresh-user-detailed.json"
    _write_new(detailed_path, detailed_payload)
    summary = {
        "acceptance_schema_version": "1.0",
        "completed_at": completed_at,
        "fresh_user_root_relative": run_root.relative_to(PROJECT_ROOT).as_posix(),
        "full_manifest_status": "PASS",
        "journey_failure_count": 0,
        "non_loopback_success_count": 0,
        "outside_write_count": 0,
        "release_id": RELEASE_ID,
        "release_manifest_sha256": _sha256(manifest_payload),
        "source_commit": source_commit,
        "staging_tree_sha256": manifest["tree_sha256"],
        "status": "PASS",
        "test_report_sha256": _sha256(detailed_payload),
    }
    summary_path = evidence_root / "m5-publish-authorization.json"
    _write_new(summary_path, _canonical_json_bytes(summary, pretty=True))
    print(
        json.dumps(
            {
                "detailed_report": detailed_path.relative_to(PROJECT_ROOT).as_posix(),
                "journey_count": len(journeys),
                "publish_authorization": summary_path.relative_to(
                    PROJECT_ROOT
                ).as_posix(),
                "status": "PASS_SUPPORTED_PRIVATE_RC_SCOPE",
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"M5 fresh-user acceptance failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
