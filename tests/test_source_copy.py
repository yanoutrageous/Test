from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from app.safety.context import DataClassification
from app.source_copy import (
    COPY_PAYLOAD_NAME,
    COPY_PROVENANCE_NAME,
    SourceCopyCode,
    SourceCopyError,
    copy_registered_external_file,
)
from tests.conftest import register_synthetic_source


@pytest.fixture
def registered_source() -> tuple[Path, bytes]:
    run_root = Path(os.environ["M0_TEST_LAB_ROOT"])
    reference = run_root / "external" / "REFERENCE"
    reference.mkdir(parents=True, exist_ok=True)
    payload = "函数图像：公开 Copy 入口\n".encode("utf-8")
    source = reference / "registered-source-copy.svg"
    if source.exists():
        assert source.read_bytes() == payload
    else:
        source.write_bytes(payload)
    register_synthetic_source(source)
    return source, payload


def test_registered_external_file_publishes_immutable_path_redacted_copy(
    registered_source: tuple[Path, bytes],
) -> None:
    source, payload = registered_source
    run_root = Path(os.environ["M0_TEST_LAB_ROOT"])

    receipt = copy_registered_external_file(
        source,
        logical_source_id="REF-UNIT-SOURCE-COPY",
        copy_id="COPY-UNIT-SOURCE-COPY",
        job_id="JOB-UNIT-SOURCE-COPY",
        purpose="M0-UNIT-COPY",
        classification=DataClassification.INTERNAL,
    )

    target = (
        run_root
        / "project"
        / "Copy"
        / "source"
        / "COPY-UNIT-SOURCE-COPY"
    )
    payload_path = target / COPY_PAYLOAD_NAME
    provenance_path = target / COPY_PROVENANCE_NAME
    provenance_bytes = provenance_path.read_bytes()
    provenance = json.loads(provenance_bytes.decode("ascii"))

    assert payload_path.read_bytes() == payload
    assert receipt.target_relative_path.endswith(
        "project/Copy/source/COPY-UNIT-SOURCE-COPY"
    )
    assert receipt.payload_sha256 == hashlib.sha256(payload).hexdigest()
    assert receipt.provenance_sha256 == hashlib.sha256(
        provenance_bytes
    ).hexdigest()
    assert provenance["source"]["logical_id"] == "REF-UNIT-SOURCE-COPY"
    assert provenance["source"]["sha256"] == receipt.payload_sha256
    assert provenance["source"]["default_stream_only"] is True
    exposed = provenance_bytes.decode("ascii") + repr(receipt)
    assert source.name not in exposed
    assert str(source) not in exposed


def test_registered_external_copy_never_overwrites_existing_revision(
    registered_source: tuple[Path, bytes],
) -> None:
    source, _payload = registered_source
    kwargs = {
        "logical_source_id": "REF-UNIT-NO-OVERWRITE",
        "copy_id": "COPY-UNIT-NO-OVERWRITE",
        "job_id": "JOB-UNIT-NO-OVERWRITE",
        "purpose": "M0-UNIT-COPY",
        "classification": DataClassification.INTERNAL,
    }
    first = copy_registered_external_file(source, **kwargs)

    with pytest.raises(SourceCopyError) as captured:
        copy_registered_external_file(source, **kwargs)

    assert captured.value.code is SourceCopyCode.TARGET_CONFLICT
    run_root = Path(os.environ["M0_TEST_LAB_ROOT"])
    payload_path = (
        run_root
        / "project"
        / "Copy"
        / "source"
        / "COPY-UNIT-NO-OVERWRITE"
        / COPY_PAYLOAD_NAME
    )
    assert hashlib.sha256(payload_path.read_bytes()).hexdigest() == (
        first.payload_sha256
    )
