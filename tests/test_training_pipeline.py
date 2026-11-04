"""
Tests for PrivWatch 3.1 Training Pipeline & Comparative Baseline Benchmarking
"""

import os
import pytest

from ml.data.curated_scenarios import generate_curated_telemetry_dataset
from ml.training.trainer import LinuxMLTrainer
from models.registry.model_registry import ModelRegistry
from models.baseline.baseline_detector import DeterministicBaselineModel
from models.sequence.markov_sequence import MarkovPrivilegeSequenceModel


def test_baseline_deterministic_model_predictions():
    records = generate_curated_telemetry_dataset()
    baseline = DeterministicBaselineModel()
    preds, confs = baseline.predict([r.feature_vector for r in records])

    assert len(preds) == len(records)
    assert len(confs) == len(records)
    # Check that confirmed exploit was flagged by baseline
    exploit_rec = [r for r in records if r.scenario_id.startswith("scen_suid_exploit")][0]
    pred, conf, expl = baseline.predict_one(exploit_rec.feature_vector)
    assert pred in ["CONFIRMED_MALICIOUS", "PRIVILEGE_TRANSITION_ANOMALY"]
    assert conf >= 0.90


def test_markov_sequence_transition_anomaly_detection():
    markov = MarkovPrivilegeSequenceModel()

    # Normal sequence: unprivileged session -> sudo -> root execution
    benign_seq = ["UNPRIV_EXEC", "SUDO_INVOKE", "ROOT_EXEC"]
    b_score, _ = markov.score_sequence(benign_seq)

    # Malicious / anomalous jump: auth failure -> suid elevation -> sensitive config write
    mal_seq = ["AUTH_FAILURE", "SUID_ELEVATE", "CONFIG_TAMPER"]
    m_score, details = markov.score_sequence(mal_seq)

    # Anomalous sequence must have higher anomaly score than normal administrative workflow
    assert m_score > b_score
    assert any(d["is_rare"] for d in details)


def test_end_to_end_training_and_validation(temp_dir):
    reg = ModelRegistry(base_dir=temp_dir)
    trainer = LinuxMLTrainer(registry=reg)
    records = generate_curated_telemetry_dataset()

    res = trainer.train_and_validate(records, dataset_version="test_v1", test_ratio=0.3, seed=123)

    assert "validation_report" in res
    assert "baseline_metrics" in res
    assert "model_metrics" in res
    assert res["validation_report"]["approved"] is True
    assert "classifier" in res["registered_models"]
    assert "anomaly" in res["registered_models"]
    assert "sequence" in res["registered_models"]
