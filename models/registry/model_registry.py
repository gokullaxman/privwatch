"""
PrivWatch 3.1 - Cryptographic Model Registry & Metadata Management
Stores serialized models with SHA-256 fingerprinting, versioning, and validation gating.
"""

from dataclasses import dataclass, field, asdict
import hashlib
import json
import os
import pickle
from typing import Dict, Any, Optional, Tuple

try:
    import joblib
    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False

from ml.features.feature_schema import FEATURE_NAMES
from ml.validation.validation_gate import ValidationReport


@dataclass
class ModelMetadata:
    """Standardized metadata card accompanying every registered model artifact"""
    model_id: str
    version: str
    algorithm: str
    trained_at_iso: str
    dataset_version: str
    feature_schema: list
    hyperparameters: Dict[str, Any]
    sha256_hash: str
    validation_status: str  # 'APPROVED', 'REJECTED', 'UNVALIDATED'
    metrics: Dict[str, Any] = field(default_factory=dict)
    validation_report: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ModelMetadata":
        return cls(**data)


class ModelRegistry:
    """Manages secure serialization, cryptographic verification, and loading of ML models"""

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.registry_dir = os.path.join(self.base_dir, "registry")
        self.metadata_dir = os.path.join(self.base_dir, "metadata")
        os.makedirs(self.registry_dir, exist_ok=True)
        os.makedirs(self.metadata_dir, exist_ok=True)

    def save_model(
        self,
        model_obj: Any,
        model_id: str,
        version: str,
        algorithm: str,
        dataset_version: str,
        hyperparameters: Dict[str, Any],
        metrics: Dict[str, Any],
        validation_report: Optional[ValidationReport] = None
    ) -> Tuple[str, ModelMetadata]:
        """
        Serialize model, compute SHA-256 hash, and record metadata card.
        """
        model_path = os.path.join(self.registry_dir, f"{model_id}.pkl")
        meta_path = os.path.join(self.metadata_dir, f"{model_id}.json")

        # Serialize
        if HAS_JOBLIB:
            joblib.dump(model_obj, model_path)
        else:
            with open(model_path, "wb") as f:
                pickle.dump(model_obj, f)

        # Compute file SHA-256
        with open(model_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        status = "APPROVED" if (validation_report and validation_report.approved) else "UNVALIDATED"

        metadata = ModelMetadata(
            model_id=model_id,
            version=version,
            algorithm=algorithm,
            trained_at_iso=validation_report.validation_timestamp_iso if validation_report else "",
            dataset_version=dataset_version,
            feature_schema=list(FEATURE_NAMES),
            hyperparameters=hyperparameters,
            sha256_hash=file_hash,
            validation_status=status,
            metrics=metrics,
            validation_report=validation_report.to_dict() if validation_report else None
        )

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata.to_dict(), f, indent=2)

        return model_path, metadata

    def load_model(self, model_id: str, verify_hash: bool = True) -> Tuple[Any, ModelMetadata]:
        """
        Load model and verify SHA-256 hash against metadata card.
        Raises ValueError if model is corrupted, tampered, or unapproved.
        """
        model_path = os.path.join(self.registry_dir, f"{model_id}.pkl")
        meta_path = os.path.join(self.metadata_dir, f"{model_id}.json")

        if not os.path.exists(meta_path):
            raise FileNotFoundError(f"Model metadata not found: {meta_path}")
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model weights file not found: {model_path}")

        with open(meta_path, "r", encoding="utf-8") as f:
            metadata = ModelMetadata.from_dict(json.load(f))

        # 1. Feature schema check
        if metadata.feature_schema != list(FEATURE_NAMES):
            raise ValueError(f"Incompatible feature schema in model {model_id}")

        # 2. Cryptographic integrity check
        if verify_hash:
            with open(model_path, "rb") as f:
                actual_hash = hashlib.sha256(f.read()).hexdigest()
            if actual_hash != metadata.sha256_hash:
                raise ValueError(
                    f"Model integrity verification failed for {model_id}! "
                    f"Recorded hash: {metadata.sha256_hash[:16]}, actual: {actual_hash[:16]}"
                )

        # 3. Validation status gate
        if metadata.validation_status != "APPROVED":
            raise PermissionError(
                f"Model {model_id} cannot be loaded: validation status is '{metadata.validation_status}'"
            )

        # 4. Deserialize
        if HAS_JOBLIB:
            model_obj = joblib.load(model_path)
        else:
            with open(model_path, "rb") as f:
                model_obj = pickle.load(f)

        return model_obj, metadata
