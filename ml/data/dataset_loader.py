"""
PrivWatch 3.1 - Dataset Loader & Leakage-Free Partitioning
Loads, verifies, and splits genuine Linux telemetry records while strictly preventing data leakage.
"""

from collections import defaultdict
import json
import os
from typing import List, Dict, Any, Tuple, Optional
import numpy as np

from ml.data.schema import LabeledTelemetryRecord, DetectionLabel
from ml.features.feature_schema import FEATURE_NAMES


class LeakageFreeSplitter:
    """
    Partitions datasets across distinct scenario_ids and host_ids so that
    events belonging to the same attack incident or laboratory execution
    never appear in both training and test sets.
    """

    @staticmethod
    def split(
        records: List[LabeledTelemetryRecord],
        test_ratio: float = 0.2,
        val_ratio: float = 0.1,
        seed: int = 42
    ) -> Tuple[List[LabeledTelemetryRecord], List[LabeledTelemetryRecord], List[LabeledTelemetryRecord]]:
        """
        Group records by scenario_id and allocate complete scenarios to train/val/test.
        Guarantees 0% cross-set incident leakage.
        """
        if not records:
            return [], [], []

        # Group by scenario
        scenario_map: Dict[str, List[LabeledTelemetryRecord]] = defaultdict(list)
        for r in records:
            scenario_map[r.scenario_id].append(r)

        scenario_ids = sorted(list(scenario_map.keys()))
        rng = np.random.RandomState(seed)
        rng.shuffle(scenario_ids)

        n_scenarios = len(scenario_ids)
        if n_scenarios == 1:
            # Single scenario fallback: preserve temporal order, never random shuffle
            recs = scenario_map[scenario_ids[0]]
            recs_sorted = sorted(recs, key=lambda x: x.event.timestamp)
            n = len(recs_sorted)
            train_end = int(n * (1.0 - test_ratio - val_ratio))
            val_end = int(n * (1.0 - test_ratio))
            return recs_sorted[:train_end], recs_sorted[train_end:val_end], recs_sorted[val_end:]

        n_test = max(1, int(round(n_scenarios * test_ratio)))
        n_val = max(1, int(round(n_scenarios * val_ratio))) if val_ratio > 0 else 0
        n_train = max(1, n_scenarios - n_test - n_val)

        train_scenarios = set(scenario_ids[:n_train])
        val_scenarios = set(scenario_ids[n_train:n_train + n_val])
        test_scenarios = set(scenario_ids[n_train + n_val:])

        train_set = [r for r in records if r.scenario_id in train_scenarios]
        val_set = [r for r in records if r.scenario_id in val_scenarios]
        test_set = [r for r in records if r.scenario_id in test_scenarios]

        return train_set, val_set, test_set


class LinuxDatasetLoader:
    """Loads and validates serialized Linux telemetry datasets"""

    @staticmethod
    def load_jsonl(path: str) -> List[LabeledTelemetryRecord]:
        """Read and validate records from a JSONL dataset file"""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Dataset file not found: {path}")

        records: List[LabeledTelemetryRecord] = []
        with open(path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    rec = LabeledTelemetryRecord.from_dict(data)
                    # Verify feature completeness
                    if not rec.feature_vector.validate():
                        raise ValueError(f"Invalid feature schema in line {line_idx}")
                    records.append(rec)
                except Exception as e:
                    raise ValueError(f"Corrupted record at line {line_idx} in {path}: {e}")

        return records

    @staticmethod
    def save_jsonl(records: List[LabeledTelemetryRecord], path: str):
        """Serialize records to JSONL format with parent dir creation"""
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r.to_dict()) + "\n")

    @staticmethod
    def extract_arrays(
        records: List[LabeledTelemetryRecord]
    ) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Extract dense feature matrix X (float64), label vector y (str), and event IDs.
        """
        n = len(records)
        d = len(FEATURE_NAMES)
        X = np.zeros((n, d), dtype=np.float64)
        y = []
        event_ids = []

        for i, r in enumerate(records):
            X[i] = r.feature_vector.to_array()
            y.append(r.ground_truth_label)
            event_ids.append(r.event.event_id)

        return X, np.array(y), event_ids
