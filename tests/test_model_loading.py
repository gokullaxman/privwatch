"""
Tests for PrivWatch 3.1 Model Loading, Integrity Verification & Serialization
"""

import json
import os
import pytest

from models.registry.model_registry import ModelRegistry, ModelMetadata
from models.baseline.baseline_detector import DeterministicBaselineModel
from ml.validation.validation_gate import ValidationReport


def test_model_registry_saves_and_loads_verified_model(temp_dir):
    reg = ModelRegistry(base_dir=temp_dir)
    baseline = DeterministicBaselineModel()

    val_rep = ValidationReport(
        model_id="baseline_test",
        approved=True,
        leakage_check_passed=True,
        schema_check_passed=True,
        integrity_hash_verified=True,
        validation_timestamp_iso="2026-11-04T00:00:00Z"
    )

    path, meta = reg.save_model(
        model_obj=baseline,
        model_id="baseline_test",
        version="3.1.0",
        algorithm="Deterministic Baseline",
        dataset_version="test_v1",
        hyperparameters={},
        metrics={"acc": 1.0},
        validation_report=val_rep
    )

    assert os.path.exists(path)
    loaded_obj, loaded_meta = reg.load_model("baseline_test", verify_hash=True)
    assert loaded_meta.model_id == "baseline_test"
    assert loaded_meta.validation_status == "APPROVED"


def test_model_registry_rejects_tampered_model_file(temp_dir):
    reg = ModelRegistry(base_dir=temp_dir)
    baseline = DeterministicBaselineModel()

    val_rep = ValidationReport(
        model_id="tamper_test",
        approved=True,
        leakage_check_passed=True,
        schema_check_passed=True,
        integrity_hash_verified=True
    )

    path, _ = reg.save_model(
        model_obj=baseline,
        model_id="tamper_test",
        version="3.1.0",
        algorithm="Deterministic Baseline",
        dataset_version="test_v1",
        hyperparameters={},
        metrics={},
        validation_report=val_rep
    )

    # Tamper with the saved pickle file by appending malicious byte
    with open(path, "ab") as f:
        f.write(b"\x00BAD_BYTES\x00")

    # Load must fail cryptographic integrity verification
    with pytest.raises(ValueError, match="integrity verification failed"):
        reg.load_model("tamper_test", verify_hash=True)


def test_model_registry_rejects_unvalidated_model(temp_dir):
    reg = ModelRegistry(base_dir=temp_dir)
    baseline = DeterministicBaselineModel()

    # Save WITHOUT approved validation report
    path, meta = reg.save_model(
        model_obj=baseline,
        model_id="unvalidated_test",
        version="3.1.0",
        algorithm="Unvalidated",
        dataset_version="test_v1",
        hyperparameters={},
        metrics={},
        validation_report=None  # Not approved
    )

    with pytest.raises(PermissionError, match="validation status is 'UNVALIDATED'"):
        reg.load_model("unvalidated_test", verify_hash=True)
