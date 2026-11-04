"""
Tests for PrivWatch 3.1 Dataset Validation & Leakage Prevention
"""

import os
import tempfile
import pytest

from ml.data.schema import LabeledTelemetryRecord, DetectionLabel
from ml.data.dataset_loader import LeakageFreeSplitter, LinuxDatasetLoader
from ml.data.curated_scenarios import generate_curated_telemetry_dataset
from ml.validation.validation_gate import ModelValidationGate


def test_labeled_telemetry_record_hashing_and_serialization():
    recs = generate_curated_telemetry_dataset()
    r = recs[0]
    h1 = r.record_hash()
    assert isinstance(h1, str) and len(h1) == 64

    # Serialization round-trip
    d = r.to_dict()
    r2 = LabeledTelemetryRecord.from_dict(d)
    assert r2.record_id == r.record_id
    assert r2.record_hash() == h1


def test_leakage_free_splitter_guarantees_zero_scenario_leakage():
    records = generate_curated_telemetry_dataset()
    train, val, test = LeakageFreeSplitter.split(records, test_ratio=0.3, val_ratio=0.1, seed=42)

    assert len(train) > 0
    assert len(test) > 0

    train_scenarios = set(r.scenario_id for r in train)
    val_scenarios = set(r.scenario_id for r in val)
    test_scenarios = set(r.scenario_id for r in test)

    # Cross-set intersection must be completely empty
    assert len(train_scenarios.intersection(test_scenarios)) == 0
    assert len(train_scenarios.intersection(val_scenarios)) == 0
    assert len(val_scenarios.intersection(test_scenarios)) == 0


def test_model_validation_gate_detects_data_leakage():
    records = generate_curated_telemetry_dataset()
    # Artificially inject common scenario into both train and test
    train = [records[0], records[1]]
    test = [records[0]]  # same record/scenario!

    assert ModelValidationGate.check_leakage(train, test) is False


def test_dataset_loader_roundtrip_jsonl(temp_dir):
    records = generate_curated_telemetry_dataset()
    jsonl_path = os.path.join(temp_dir, "dataset.jsonl")

    LinuxDatasetLoader.save_jsonl(records, jsonl_path)
    loaded = LinuxDatasetLoader.load_jsonl(jsonl_path)

    assert len(loaded) == len(records)
    assert loaded[0].record_id == records[0].record_id
