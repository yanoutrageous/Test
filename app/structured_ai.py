from __future__ import annotations

import json
import base64
import ipaddress
import mimetypes
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT, get_project_paths
from .database import connect_database, initialize_database
from .structured_content import (
    NORMALIZED_TYPES,
    STRUCTURED_ALGORITHM_VERSION,
    initialize_structured_contents,
    normalize_question_type,
    parse_json_field,
)


STRUCTURED_AI_PROMPT_VERSION = "stage9_structured_ai_v1"
MOCK_STRUCTURED_MODEL = "mock-structured-local"
WRITABLE_AI_STATUSES = ("unprocessed", "ai_draft", "needs_review", "failed")
ENV_PROVIDER = "EXAM_BANK_STRUCTURED_AI_PROVIDER"
ENV_BASE_URL = "EXAM_BANK_STRUCTURED_AI_BASE_URL"
ENV_MODEL = "EXAM_BANK_STRUCTURED_AI_MODEL"
ENV_TIMEOUT = "EXAM_BANK_STRUCTURED_AI_TIMEOUT"
ENV_API_KEY = "EXAM_BANK_STRUCTURED_AI_API_KEY"
ENV_INCLUDE_IMAGES = "EXAM_BANK_STRUCTURED_AI_INCLUDE_IMAGES"
LOCAL_OPENAI_PROVIDER = "local_openai_compatible"
DEFAULT_LOCAL_OPENAI_BASE_URL = "http://127.0.0.1:1234/v1"
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class StructuredAiError(RuntimeError):
    """Raised when structured AI correction cannot be queued or written."""


@dataclass(frozen=True)
class StructuredCorrectionInput:
    question_id: int
    qid: str
    source_text: str
    source_latex: str
    question_no: str
    page_no: int | None
    question_type_candidate: str | None
    normalized_type_candidate: str
    raw_crop_path: str | None
    page_image_path: str | None
    bbox_json: dict[str, Any]
    meta_json: dict[str, Any]

    def to_prompt_payload(self) -> dict[str, Any]:
        return {
            "question_id": self.question_id,
            "qid": self.qid,
            "source_text": self.source_text,
            "source_latex": self.source_latex,
            "question_no": self.question_no,
            "page_no": self.page_no,
            "question_type_candidate": self.question_type_candidate,
            "normalized_type_candidate": self.normalized_type_candidate,
            "raw_crop_path": self.raw_crop_path,
            "page_image_path": self.page_image_path,
            "bbox_json": self.bbox_json,
            "meta_json": self.meta_json,
        }


class StructuredCorrectionProvider:
    name = "base"
    model_name = "unconfigured"

    @property
    def configured(self) -> bool:
        return False

    def generate(self, correction_input: StructuredCorrectionInput) -> dict[str, Any]:
        raise StructuredAiError("Structured AI provider is not configured.")


class NoConfiguredProvider(StructuredCorrectionProvider):
    name = "unconfigured"
    model_name = "none"

    def __init__(self, reason: str = "Structured AI provider is not configured.") -> None:
        self.reason = reason


class MockStructuredProvider(StructuredCorrectionProvider):
    name = "mock"
    model_name = MOCK_STRUCTURED_MODEL

    @property
    def configured(self) -> bool:
        return True

    def generate(self, correction_input: StructuredCorrectionInput) -> dict[str, Any]:
        source = correction_input.source_latex or correction_input.source_text
        normalized_type = correction_input.normalized_type_candidate
        options = []
        blanks = []
        subquestions = []
        if normalized_type == "choice":
            options = [
                {"label": "A", "text_latex": "mock option A"},
                {"label": "B", "text_latex": "mock option B"},
                {"label": "C", "text_latex": "mock option C"},
                {"label": "D", "text_latex": "mock option D"},
            ]
        elif normalized_type == "blank":
            blanks = [{"index": 1, "placeholder_latex": "\\\\underline{\\\\hspace{2em}}"}]
        elif normalized_type == "solution":
            subquestions = [{"index": 1, "stem_latex": source, "answer_latex": ""}]

        return {
            "normalized_type": normalized_type,
            "stem_latex": source,
            "options_json": options,
            "blanks_json": blanks,
            "subquestions_json": subquestions,
            "answer_latex": "",
            "analysis_latex": "",
            "confidence": 0.5,
            "quality_flags": ["mock_ai_output"],
        }


class LocalOpenAICompatibleProvider(StructuredCorrectionProvider):
    name = LOCAL_OPENAI_PROVIDER

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        timeout_seconds: float,
        include_images: bool,
        api_key: str | None = None,
        project_root: Path = PROJECT_ROOT,
    ) -> None:
        self.base_url = _normalize_local_openai_base_url(base_url)
        self.model_name = model
        self.timeout_seconds = timeout_seconds
        self.include_images = include_images
        self.api_key = api_key
        self.project_root = project_root

    @property
    def configured(self) -> bool:
        return True

    @property
    def endpoint(self) -> str:
        if self.base_url.rstrip("/").endswith("/chat/completions"):
            return self.base_url.rstrip("/")
        return f"{self.base_url.rstrip('/')}/chat/completions"

    def generate(self, correction_input: StructuredCorrectionInput) -> dict[str, Any]:
        request_payload = {
            "model": self.model_name,
            "temperature": 0,
            "messages": _build_local_openai_messages(
                correction_input,
                project_root=self.project_root,
                include_images=self.include_images,
            ),
            "response_format": {"type": "json_object"},
        }
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(request_payload, ensure_ascii=False).encode("utf-8"),
            headers=_local_openai_headers(self.api_key),
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                response_data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise StructuredAiError(
                f"Local structured AI provider returned HTTP {exc.code}: {body[:500]}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise StructuredAiError(f"Local structured AI provider failed: {exc}") from exc

        content = _extract_openai_message_content(response_data)
        return _parse_provider_json_content(content)


def build_structured_correction_provider(
    *,
    mock: bool = False,
    project_root: Path = PROJECT_ROOT,
) -> StructuredCorrectionProvider:
    if mock:
        return MockStructuredProvider()

    provider_name = os.environ.get(ENV_PROVIDER, "").strip().lower()
    if not provider_name:
        return NoConfiguredProvider()
    if provider_name not in {LOCAL_OPENAI_PROVIDER, "openai_compatible_local"}:
        raise StructuredAiError(
            f"Unsupported structured AI provider: {provider_name}. "
            f"Supported provider: {LOCAL_OPENAI_PROVIDER}."
        )

    model = os.environ.get(ENV_MODEL, "").strip()
    if not model:
        raise StructuredAiError(f"{ENV_MODEL} is required for {LOCAL_OPENAI_PROVIDER}.")
    timeout = _parse_timeout(os.environ.get(ENV_TIMEOUT))
    return LocalOpenAICompatibleProvider(
        base_url=os.environ.get(ENV_BASE_URL, DEFAULT_LOCAL_OPENAI_BASE_URL),
        model=model,
        timeout_seconds=timeout,
        include_images=_env_flag(os.environ.get(ENV_INCLUDE_IMAGES)),
        api_key=os.environ.get(ENV_API_KEY) or None,
        project_root=project_root,
    )


def get_structured_ai_provider_status(
    *,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    try:
        provider = build_structured_correction_provider(project_root=project_root)
    except StructuredAiError as exc:
        return {
            "configured": False,
            "provider": os.environ.get(ENV_PROVIDER, "").strip() or "invalid",
            "reason": str(exc),
            "local_only": True,
        }

    status = {
        "configured": provider.configured,
        "provider": provider.name,
        "model": provider.model_name,
        "local_only": True,
    }
    if isinstance(provider, NoConfiguredProvider):
        status["reason"] = provider.reason
    if isinstance(provider, LocalOpenAICompatibleProvider):
        status.update(
            {
                "base_url": provider.base_url,
                "endpoint": provider.endpoint,
                "include_images": provider.include_images,
                "timeout_seconds": provider.timeout_seconds,
            }
        )
    return status


def run_structured_ai_corrections(
    *,
    db_path: Path | None = None,
    question_ids: tuple[int, ...] | None = None,
    limit: int = 25,
    mock: bool = False,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    initialize_database(db_path)
    initialize_structured_contents(db_path=db_path)
    if mock:
        _assert_mock_uses_non_default_database(db_path)
    provider = build_structured_correction_provider(mock=mock, project_root=project_root)

    with connect_database(db_path) as conn:
        rows = _load_correction_rows(conn, question_ids=question_ids, limit=limit)
        inputs = [_row_to_correction_input(row) for row in rows]
        if not provider.configured:
            skipped = []
            updated = []
            for item in inputs:
                if not _is_writable_ai_status(conn, item.question_id):
                    skipped.append({"question_id": item.question_id, "reason": "protected_ai_status"})
                    updated.append(False)
                    continue
                updated.append(_mark_provider_unavailable(conn, item, provider))
            conn.commit()
            return {
                "status": "skipped",
                "reason": getattr(provider, "reason", "Structured AI provider is not configured."),
                "provider": provider.name,
                "model": provider.model_name,
                "considered": len(inputs),
                "updated_unavailable": sum(1 for value in updated if value),
                "drafted": 0,
                "skipped": skipped,
            }

        drafted: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        for item in inputs:
            if not _is_writable_ai_status(conn, item.question_id):
                skipped.append({"question_id": item.question_id, "reason": "protected_ai_status"})
                continue
            payload = validate_ai_output_payload(provider.generate(item))
            _write_ai_draft(conn, item, payload, provider, project_root=project_root)
            drafted.append({"question_id": item.question_id, "qid": item.qid})
        conn.commit()

    return {
        "status": "ok",
        "provider": provider.name,
        "model": provider.model_name,
        "considered": len(inputs),
        "drafted": len(drafted),
        "updated_unavailable": 0,
        "drafts": drafted,
        "skipped": skipped,
    }


def validate_ai_output_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise StructuredAiError("AI output must be a JSON object.")
    normalized_type = str(payload.get("normalized_type") or "unknown").strip()
    if normalized_type not in NORMALIZED_TYPES:
        raise StructuredAiError(f"Unsupported normalized_type: {normalized_type}")

    stem_latex = str(payload.get("stem_latex") or "").strip()
    if not stem_latex:
        raise StructuredAiError("AI output stem_latex cannot be empty.")

    normalized = {
        "normalized_type": normalized_type,
        "stem_latex": stem_latex,
        "options_json": _require_list(payload.get("options_json", []), "options_json"),
        "blanks_json": _require_list(payload.get("blanks_json", []), "blanks_json"),
        "subquestions_json": _require_list(
            payload.get("subquestions_json", []), "subquestions_json"
        ),
        "answer_latex": _optional_text(payload.get("answer_latex")),
        "analysis_latex": _optional_text(payload.get("analysis_latex")),
        "confidence": _normalize_confidence(payload.get("confidence")),
        "quality_flags": _require_list(payload.get("quality_flags", []), "quality_flags"),
    }
    return normalized


def _assert_mock_uses_non_default_database(db_path: Path | None) -> None:
    if db_path is None:
        raise StructuredAiError("Mock structured AI requires an explicit --db-path.")
    default_db = get_project_paths(require_target_pdf=False).db_path.resolve()
    if Path(db_path).resolve() == default_db:
        raise StructuredAiError("Mock structured AI cannot run against the default real database.")


def _load_correction_rows(
    conn,
    *,
    question_ids: tuple[int, ...] | None,
    limit: int,
) -> list[dict[str, Any]]:
    params: list[Any] = []
    filter_sql = "WHERE sc.ai_status IN ('unprocessed', 'ai_draft', 'needs_review', 'failed')"
    if question_ids:
        placeholders = ", ".join("?" for _ in question_ids)
        filter_sql = f"WHERE q.id IN ({placeholders})"
        params.extend(question_ids)
    params.append(max(1, min(limit, 500)))

    rows = conn.execute(
        f"""
        SELECT q.id AS question_id,
               q.qid,
               q.question_no,
               q.question_type,
               q.bbox_json,
               q.meta_json,
               CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS page_no,
               sc.source_text,
               sc.source_latex,
               sc.normalized_type AS normalized_type_candidate,
               sc.ai_status,
               sc.quality_flags_json,
               sc.model_info,
               qa.relative_path AS raw_crop_path,
               spa.relative_path AS page_image_path
          FROM question_structured_contents sc
          JOIN questions q ON q.id = sc.question_id
          LEFT JOIN question_assets qa
            ON qa.id = (
                SELECT id
                  FROM question_assets
                 WHERE question_id = q.id
                   AND asset_kind = 'raw_crop'
                 ORDER BY id DESC
                 LIMIT 1
            )
          LEFT JOIN source_paper_assets spa
            ON spa.source_paper_id = q.source_paper_id
           AND spa.asset_kind = 'page_image'
           AND spa.page_no = CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
         {filter_sql}
         ORDER BY q.id
         LIMIT ?
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def _row_to_correction_input(row: dict[str, Any]) -> StructuredCorrectionInput:
    normalized_type = row["normalized_type_candidate"] or normalize_question_type(
        row["question_type"]
    )
    return StructuredCorrectionInput(
        question_id=int(row["question_id"]),
        qid=row["qid"],
        source_text=row["source_text"] or "",
        source_latex=row["source_latex"] or row["source_text"] or "",
        question_no=str(row["question_no"] or ""),
        page_no=row["page_no"],
        question_type_candidate=row["question_type"],
        normalized_type_candidate=normalized_type,
        raw_crop_path=row["raw_crop_path"],
        page_image_path=row["page_image_path"],
        bbox_json=parse_json_field(row["bbox_json"], {}),
        meta_json=parse_json_field(row["meta_json"], {}),
    )


def _mark_provider_unavailable(
    conn,
    correction_input: StructuredCorrectionInput,
    provider: StructuredCorrectionProvider,
) -> bool:
    row = conn.execute(
        """
        SELECT quality_flags_json, model_info
          FROM question_structured_contents
         WHERE question_id = ?
        """,
        (correction_input.question_id,),
    ).fetchone()
    if row is None:
        return False
    flags = parse_json_field(row["quality_flags_json"], [])
    if not isinstance(flags, list):
        flags = []
    if "ai_provider_unavailable" not in flags:
        flags.append("ai_provider_unavailable")
    model_info = parse_json_field(row["model_info"], {})
    if not isinstance(model_info, dict):
        model_info = {}
    model_info["last_ai_attempt"] = {
        "provider": provider.name,
        "model": provider.model_name,
        "prompt_version": STRUCTURED_AI_PROMPT_VERSION,
        "status": "unavailable",
        "created_at": _utc_now(),
    }
    conn.execute(
        """
        UPDATE question_structured_contents
           SET quality_flags_json = ?,
               model_info = ?,
               updated_at = CURRENT_TIMESTAMP
         WHERE question_id = ?
        """,
        (
            json.dumps(flags, ensure_ascii=False),
            json.dumps(model_info, ensure_ascii=False),
            correction_input.question_id,
        ),
    )
    return True


def _write_ai_draft(
    conn,
    correction_input: StructuredCorrectionInput,
    payload: dict[str, Any],
    provider: StructuredCorrectionProvider,
    *,
    project_root: Path,
) -> None:
    model_info = {
        "source": "structured_ai",
        "algorithm_version": STRUCTURED_ALGORITHM_VERSION,
        "provider": provider.name,
        "model": provider.model_name,
        "prompt_version": STRUCTURED_AI_PROMPT_VERSION,
        "created_at": _utc_now(),
        "input": {
            "qid": correction_input.qid,
            "question_no": correction_input.question_no,
            "page_no": correction_input.page_no,
            "question_type_candidate": correction_input.question_type_candidate,
            "normalized_type_candidate": correction_input.normalized_type_candidate,
            "raw_crop_path": correction_input.raw_crop_path,
            "page_image_path": correction_input.page_image_path,
        },
    }
    conn.execute(
        """
        UPDATE question_structured_contents
           SET normalized_type = ?,
               stem_latex = ?,
               options_json = ?,
               blanks_json = ?,
               subquestions_json = ?,
               answer_latex = ?,
               analysis_latex = ?,
               ai_status = 'ai_draft',
               quality_flags_json = ?,
               confidence = ?,
               model_info = ?,
               updated_at = CURRENT_TIMESTAMP
         WHERE question_id = ?
        """,
        (
            payload["normalized_type"],
            payload["stem_latex"],
            json.dumps(payload["options_json"], ensure_ascii=False),
            json.dumps(payload["blanks_json"], ensure_ascii=False),
            json.dumps(payload["subquestions_json"], ensure_ascii=False),
            payload["answer_latex"],
            payload["analysis_latex"],
            json.dumps(payload["quality_flags"], ensure_ascii=False),
            payload["confidence"],
            json.dumps(model_info, ensure_ascii=False),
            correction_input.question_id,
        ),
    )


def _is_writable_ai_status(conn, question_id: int) -> bool:
    row = conn.execute(
        "SELECT ai_status FROM question_structured_contents WHERE question_id = ?",
        (question_id,),
    ).fetchone()
    return row is not None and row["ai_status"] in WRITABLE_AI_STATUSES


def _require_list(value: Any, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise StructuredAiError(f"{field_name} must be a list.")
    return value


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_confidence(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        confidence = float(value)
    except (TypeError, ValueError) as exc:
        raise StructuredAiError("confidence must be a number between 0 and 1.") from exc
    if confidence < 0 or confidence > 1:
        raise StructuredAiError("confidence must be a number between 0 and 1.")
    return confidence


def _normalize_local_openai_base_url(base_url: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise StructuredAiError(f"{ENV_BASE_URL} must be an http(s) URL.")
    hostname = parsed.hostname or ""
    if not _is_loopback_host(hostname):
        raise StructuredAiError(
            f"{ENV_BASE_URL} must point to a loopback host; refusing non-local host: {hostname}"
        )
    return base_url.rstrip("/")


def _is_loopback_host(hostname: str) -> bool:
    normalized = hostname.lower()
    if normalized in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _parse_timeout(value: str | None) -> float:
    if not value:
        return 60.0
    try:
        timeout = float(value)
    except ValueError as exc:
        raise StructuredAiError(f"{ENV_TIMEOUT} must be a number of seconds.") from exc
    if timeout <= 0 or timeout > 600:
        raise StructuredAiError(f"{ENV_TIMEOUT} must be between 0 and 600 seconds.")
    return timeout


def _env_flag(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _local_openai_headers(api_key: str | None) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _build_local_openai_messages(
    correction_input: StructuredCorrectionInput,
    *,
    project_root: Path,
    include_images: bool,
) -> list[dict[str, Any]]:
    system = (
        "You convert Chinese exam question candidates into conservative structured JSON. "
        "Return JSON only. Do not invent missing content. Do not approve the question."
    )
    schema = {
        "normalized_type": "choice|multiple_choice|blank|solution|unknown",
        "stem_latex": "string",
        "options_json": [{"label": "A", "text_latex": "string"}],
        "blanks_json": [{"index": 1, "placeholder_latex": "string"}],
        "subquestions_json": [{"index": 1, "stem_latex": "string", "answer_latex": "string"}],
        "answer_latex": "string or null",
        "analysis_latex": "string or null",
        "confidence": "number 0..1 or null",
        "quality_flags": ["short_text|missing_image|uncertain_type|..."],
    }
    prompt_payload = correction_input.to_prompt_payload()
    user_text = (
        "Convert this question candidate to the exact JSON schema below. "
        "Keep source wording; normalize math as LaTeX where clear; leave uncertain fields empty "
        "and add quality_flags. JSON schema:\n"
        f"{json.dumps(schema, ensure_ascii=False)}\n\n"
        "Question candidate:\n"
        f"{json.dumps(prompt_payload, ensure_ascii=False, indent=2)}"
    )
    if not include_images:
        return [
            {"role": "system", "content": system},
            {"role": "user", "content": user_text},
        ]

    content: list[dict[str, Any]] = [{"type": "text", "text": user_text}]
    missing_images: list[str] = []
    image_labels: list[str] = []
    for label, relative_path in (
        ("raw_crop", correction_input.raw_crop_path),
        ("page_image", correction_input.page_image_path),
    ):
        if not relative_path:
            continue
        image_part = _local_image_content_part(
            project_root=project_root,
            relative_path=relative_path,
            label=label,
        )
        if image_part is None:
            missing_images.append(f"{label}:{relative_path}")
            continue
        image_labels.append(label)
        content.append(image_part)

    if image_labels:
        content[0]["text"] += "\n\nAttached local images in order: " + ", ".join(image_labels)
    if missing_images:
        content[0]["text"] += "\n\nMissing local images: " + ", ".join(missing_images)

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": content},
    ]


def _local_image_content_part(
    *,
    project_root: Path,
    relative_path: str,
    label: str,
) -> dict[str, Any] | None:
    candidate = Path(relative_path)
    if candidate.is_absolute():
        raise StructuredAiError(f"AI image input path must be relative: {relative_path}")
    image_path = (project_root / candidate).resolve()
    try:
        image_path.relative_to(project_root.resolve())
    except ValueError as exc:
        raise StructuredAiError(f"AI image input path is outside project root: {relative_path}") from exc
    if not image_path.is_file():
        return None

    mime_type = mimetypes.guess_type(image_path.name)[0] or "image/png"
    encoded = base64.b64encode(image_path.read_bytes()).decode("ascii")
    return {
        "type": "image_url",
        "image_url": {
            "url": f"data:{mime_type};base64,{encoded}",
            "detail": "high",
        },
    }


def _extract_openai_message_content(response_data: dict[str, Any]) -> str:
    try:
        content = response_data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise StructuredAiError("Local structured AI provider response missing choices[0].message.content.") from exc
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        text_parts = [
            str(part.get("text", ""))
            for part in content
            if isinstance(part, dict) and part.get("type") in {"text", "output_text"}
        ]
        return "\n".join(part for part in text_parts if part)
    raise StructuredAiError("Local structured AI provider response content must be text.")


def _parse_provider_json_content(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise StructuredAiError("Local structured AI provider did not return valid JSON.") from exc
    if not isinstance(parsed, dict):
        raise StructuredAiError("Local structured AI provider JSON response must be an object.")
    return parsed


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
