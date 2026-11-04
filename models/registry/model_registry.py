"""
PrivWatch 3.1 - Cryptographic Model Registry & Metadata Management
Stores serialized models with SHA-256 fingerprinting, versioning, and validation gating.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
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

    def load_model(
        self,
        model_id: str,
        verify_hash: bool = True,
        evaluation_mode: bool = False
    ) -> Tuple[Any, ModelMetadata]:
        """
        Load model and verify SHA-256 hash against metadata card and manifest.json.
        Raises ValueError if model is corrupted or tampered.
        Raises PermissionError if model is REVOKED or not APPROVED (unless evaluation_mode).
        """
        model_path = os.path.join(self.registry_dir, f"{model_id}.pkl")
        meta_path = os.path.join(self.metadata_dir, f"{model_id}.json")
        manifest_path = os.path.join(self.base_dir, "manifest.json")

        if not os.path.exists(meta_path):
            raise FileNotFoundError(f"Model metadata not found: {meta_path}")
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model weights file not found: {model_path}")

        with open(meta_path, "r", encoding="utf-8") as f:
            metadata = ModelMetadata.from_dict(json.load(f))

        # 1. Feature schema check
        if metadata.feature_schema != list(FEATURE_NAMES):
            raise ValueError(f"Incompatible feature schema in model {model_id}")

        # 2. Cryptographic integrity check against metadata card and manifest.json
        if verify_hash:
            with open(model_path, "rb") as f:
                actual_hash = hashlib.sha256(f.read()).hexdigest()
            if actual_hash != metadata.sha256_hash:
                raise ValueError(
                    f"Model integrity verification failed for {model_id}! "
                    f"Recorded hash: {metadata.sha256_hash[:16]}, actual: {actual_hash[:16]}"
                )

            # Check against manifest.json if present
            if os.path.exists(manifest_path):
                try:
                    with open(manifest_path, "r", encoding="utf-8") as mf:
                        manifest_data = json.load(mf)
                    manifest_models = manifest_data.get("models", {})
                    if model_id in manifest_models:
                        manifest_hash = manifest_models[model_id].get("sha256")
                        if manifest_hash and actual_hash != manifest_hash:
                            raise ValueError(
                                f"Model manifest checksum mismatch for {model_id}! "
                                f"Manifest: {manifest_hash[:16]}, actual: {actual_hash[:16]}"
                            )
                except json.JSONDecodeError:
                    pass

        # 3. Validation status gate
        if metadata.validation_status == "REVOKED":
            raise PermissionError(f"Model {model_id} has been REVOKED and cannot be loaded.")

        if metadata.validation_status != "APPROVED":
            if not evaluation_mode:
                raise PermissionError(
                    f"Model {model_id} cannot be loaded: validation status is '{metadata.validation_status}'. "
                    f"Only APPROVED models are permitted in production inference."
                )

        # 4. Deserialize
        if HAS_JOBLIB:
            model_obj = joblib.load(model_path)
        else:
            with open(model_path, "rb") as f:
                model_obj = pickle.load(f)

        return model_obj, metadata

    def revoke_model(self, model_id: str, operator: str = "admin", reason: str = "") -> ModelMetadata:
        """Revoke trust from a model, preventing further loading or inference."""
        meta_path = os.path.join(self.metadata_dir, f"{model_id}.json")
        if not os.path.exists(meta_path):
            raise FileNotFoundError(f"Model metadata not found: {meta_path}")

        with open(meta_path, "r", encoding="utf-8") as f:
            metadata = ModelMetadata.from_dict(json.load(f))

        metadata.validation_status = "REVOKED"
        if not metadata.validation_report:
            metadata.validation_report = {}
        metadata.validation_report["revocation"] = {
            "revoked_by": operator,
            "reason": reason,
            "revoked_at_iso": datetime.now(timezone.utc).isoformat()
        }

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata.to_dict(), f, indent=2)

        return metadata

    def approve_model(self, model_id: str, operator: str = "admin") -> ModelMetadata:
        """Approve model for production inference after validation."""
        meta_path = os.path.join(self.metadata_dir, f"{model_id}.json")
        if not os.path.exists(meta_path):
            raise FileNotFoundError(f"Model metadata not found: {meta_path}")

        with open(meta_path, "r", encoding="utf-8") as f:
            metadata = ModelMetadata.from_dict(json.load(f))

        metadata.validation_status = "APPROVED"
        if not metadata.validation_report:
            metadata.validation_report = {}
        metadata.validation_report["approval"] = {
            "approved_by": operator,
            "approved_at_iso": datetime.now(timezone.utc).isoformat()
        }

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata.to_dict(), f, indent=2)

        return metadata
