from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from werkzeug.test import Client
from werkzeug.wrappers import Response

from Task.tools.build_m5_release import (
    START_PS1,
    _pii_reasons,
    _privacy_scan_payload,
)
from app.m2_pipeline import (
    BlueprintUIState,
    M2PipelineConfig,
    M2PipelineError,
    create_blueprint_app,
    load_candidate_pool,
)
from app.m4_backup import M4BackupService, _role_for_path, _runtime_workbench
from app.m5_release import (
    M5Error,
    M5SessionStore,
    _canonical_json_bytes,
    _m5_network_audit_hook,
    _safe_release_relative,
    create_m5_application,
    verify_release_manifest,
)
from app.project_root import PROJECT_ROOT


def _runtime():
    service = M4BackupService()
    runtime = service.current_runtime()
    return service, runtime


def test_m5_portal_unifies_all_public_capability_surfaces_without_get_writes() -> None:
    service, runtime = _runtime()
    state_root = runtime.resolve("data/state/m5", service.project_root)
    existed_before = state_root.exists()
    client = Client(create_m5_application(service), Response)

    responses = {
        "home": client.get("/"),
        "status": client.get("/status.json"),
        "library": client.get("/library/questions?status=all"),
        "planner": client.get("/planner/blueprints"),
        "search": client.get("/workbench/search?q=函数&limit=3"),
        "documents": client.get("/documents"),
        "maintenance": client.get("/workbench/maintenance"),
    }

    assert {name: response.status_code for name, response in responses.items()} == {
        "home": 200,
        "status": 200,
        "library": 200,
        "planner": 200,
        "search": 200,
        "documents": 200,
        "maintenance": 200,
    }
    assert responses["status"].json["offline"] is True
    assert responses["status"].json["loopback_only"] is True
    assert responses["status"].json["question_count"] == 19
    assert responses["status"].json["approved_candidate_count"] == 19
    assert responses["status"].json["database"]["integrity_check"] == "ok"
    assert responses["status"].json["product_root_writable"] is True
    assert state_root.exists() is existed_before


def test_restored_runtime_is_a_valid_m2_candidate_source() -> None:
    service, runtime = _runtime()
    config = M2PipelineConfig(
        data_source_root_relative=runtime.source_root_relative
    )

    candidates = load_candidate_pool(config)

    assert len(candidates) == 19
    assert config.m1_database_path.is_file()
    assert config.bundle_target_root.is_dir()
    if runtime.source_root_relative != ".":
        assert all(
            row.question_ir_relative_path.startswith(
                runtime.source_root_relative + "/"
            )
            for row in candidates
        )
    with pytest.raises(M2PipelineError, match="data source root"):
        M2PipelineConfig(data_source_root_relative="../outside")


def test_blueprint_public_mutations_update_the_injected_session_state() -> None:
    service, runtime = _runtime()
    config = M2PipelineConfig(
        data_source_root_relative=runtime.source_root_relative
    )
    state = BlueprintUIState()
    app = create_blueprint_app(
        load_candidate_pool(config),
        config=config,
        state=state,
    )

    with app.test_client() as client:
        response = client.post("/blueprints/practice/solve")

    assert response.status_code == 200
    assert state.status == "FEASIBLE"
    assert len(state.selection) == 5


def test_session_store_round_trips_append_only_state(tmp_path: Path) -> None:
    service, runtime = _runtime()
    base = _runtime_workbench(
        runtime.source_root(service.project_root),
        runtime.layout,
    )
    blueprint = BlueprintUIState(
        selection=["QUESTION-YANYAN-001-REV-002"],
        status="LOCKED",
    )
    base.basket.append("Q-YANYAN-001")
    store = M5SessionStore(tmp_path / "state")

    first = store.commit_revision(blueprint, base)
    restored_blueprint, restored_workbench = M5SessionStore(
        tmp_path / "state"
    ).load(BlueprintUIState(), copy.deepcopy(base))

    assert first.sequence == 1
    assert first.latest_sha256
    assert restored_blueprint.selection == blueprint.selection
    assert restored_blueprint.status == "LOCKED"
    assert restored_workbench.basket[-1] == "Q-YANYAN-001"
    assert restored_workbench.basket == base.basket


def test_session_store_rejects_tampering(tmp_path: Path) -> None:
    service, runtime = _runtime()
    base = _runtime_workbench(
        runtime.source_root(service.project_root),
        runtime.layout,
    )
    store = M5SessionStore(tmp_path / "state")
    store.commit_revision(BlueprintUIState(), base)
    revision = tmp_path / "state" / "session-00000001.json"
    document = json.loads(revision.read_text(encoding="utf-8"))
    document["sequence"] = 2
    revision.write_text(
        json.dumps(document, ensure_ascii=False),
        encoding="utf-8",
    )

    with pytest.raises(M5Error, match="chain"):
        M5SessionStore(tmp_path / "state").load(
            BlueprintUIState(),
            base,
        )


@pytest.mark.parametrize(
    "value",
    (
        "../escape",
        "/absolute",
        "E:/outside",
        r"data\backslash",
        "data/file:stream",
    ),
)
def test_release_paths_reject_escape_and_platform_absolute_forms(value: str) -> None:
    with pytest.raises(M5Error):
        _safe_release_relative(value, field_name="probe")


def test_release_manifest_verifies_every_declared_file(tmp_path: Path) -> None:
    payload = b"print('portable')\n"
    target = tmp_path / "app" / "portable.py"
    target.parent.mkdir()
    target.write_bytes(payload)
    active_pointer = tmp_path / "data" / "db" / "active-state.json"
    active_pointer.parent.mkdir(parents=True)
    active_pointer.write_text("mutable", encoding="utf-8")
    files = [
        {
            "bytes": len(payload),
            "relative_path": "app/portable.py",
            "role": "APPLICATION_SOURCE",
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    ]
    manifest = {
        "build": {"source_commit": "a" * 40},
        "files": files,
        "manifest_schema_version": "1.0",
        "mutable_paths": ["data/db/active-state.json", "data/state/"],
        "product": {"version": "test"},
        "runtime": {},
        "tree_sha256": hashlib.sha256(
            _canonical_json_bytes(files)
        ).hexdigest(),
    }
    (tmp_path / "release-manifest.json").write_bytes(
        _canonical_json_bytes(manifest, pretty=True)
    )

    result = verify_release_manifest(tmp_path)

    assert result["status"] == "PASS"
    assert result["checked_file_count"] == 1


def test_release_manifest_rejects_unmanifested_immutable_file(tmp_path: Path) -> None:
    payload = b"declared"
    (tmp_path / "declared.txt").write_bytes(payload)
    (tmp_path / "unexpected.txt").write_text("extra", encoding="utf-8")
    files = [
        {
            "bytes": len(payload),
            "relative_path": "declared.txt",
            "role": "DOCUMENT",
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    ]
    manifest = {
        "build": {},
        "files": files,
        "manifest_schema_version": "1.0",
        "mutable_paths": ["tmp/"],
        "product": {"version": "test"},
        "runtime": {},
        "tree_sha256": hashlib.sha256(
            _canonical_json_bytes(files)
        ).hexdigest(),
    }
    (tmp_path / "release-manifest.json").write_bytes(
        _canonical_json_bytes(manifest, pretty=True)
    )

    with pytest.raises(M5Error, match="unmanifested"):
        verify_release_manifest(tmp_path)


def test_release_manifest_rejects_tree_inventory_tampering(tmp_path: Path) -> None:
    payload = b"x"
    (tmp_path / "file.txt").write_bytes(payload)
    manifest = {
        "build": {},
        "files": [
            {
                "bytes": 1,
                "relative_path": "file.txt",
                "role": "DOCUMENT",
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        ],
        "manifest_schema_version": "1.0",
        "mutable_paths": ["tmp/"],
        "product": {"version": "test"},
        "runtime": {},
        "tree_sha256": "0" * 64,
    }
    (tmp_path / "release-manifest.json").write_bytes(
        _canonical_json_bytes(manifest, pretty=True)
    )

    with pytest.raises(M5Error, match="inventory"):
        verify_release_manifest(tmp_path)


def test_offline_guard_allows_loopback_and_rejects_external_hosts() -> None:
    _m5_network_audit_hook("socket.connect", (object(), ("127.0.0.1", 8765)))
    _m5_network_audit_hook("socket.getaddrinfo", ("localhost", 8765))
    with pytest.raises(OSError, match="回环"):
        _m5_network_audit_hook(
            "socket.connect",
            (object(), ("8.8.8.8", 443)),
        )
    with pytest.raises(OSError, match="DNS"):
        _m5_network_audit_hook(
            "socket.getaddrinfo",
            ("example.com", 443),
        )


def test_release_builder_privacy_patterns_and_launcher_are_portable() -> None:
    assert _pii_reasons(b"contact owner@example.com") == {"email-pattern"}
    assert _pii_reasons(b"phone 13800138000") == {
        "mainland-mobile-pattern"
    }
    assert _pii_reasons(b"127.0.0.1") == set()
    assert _pii_reasons(b"203.0.113.9") == {"non-loopback-ip-pattern"}
    assert _pii_reasons(b"123.13800138000") == set()
    assert _pii_reasons("数学变量 qq15uunn".encode("utf-8")) == set()
    assert "Push-Location -LiteralPath $productRoot" in START_PS1
    assert "-m app.m5_release verify --quick" not in START_PS1


def test_release_privacy_scan_uses_visible_pdf_text_not_stream_bytes() -> None:
    import fitz

    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), "safe visible text")
    payload = document.tobytes()
    document.close()

    scanned = _privacy_scan_payload("sample.pdf", payload)

    assert b"safe visible text" in scanned
    assert b"endstream" not in scanned


def test_m4_assigns_persisted_m5_state_a_distinct_backup_role() -> None:
    assert (
        _role_for_path("data/state/m5/session-00000001.json")
        == "M5_PERSISTED_USER_STATE"
    )


def test_customer_docs_disclose_target_set_font_and_same_volume_limits() -> None:
    known_limits = (
        PROJECT_ROOT / "docs" / "m5" / "已知限制.md"
    ).read_text(encoding="utf-8")
    fonts = (
        PROJECT_ROOT / "docs" / "m5" / "模板与字体说明.md"
    ).read_text(encoding="utf-8")
    recovery = (
        PROJECT_ROOT / "docs" / "m5" / "备份与恢复.md"
    ).read_text(encoding="utf-8")

    assert "2020—2025" in known_limits
    assert "19 题" in known_limits
    assert "redistributable=false" in fonts
    assert "同一卷" in recovery
