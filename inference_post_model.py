"""
inference_post_model.py
===========================
Loads the trained post-exploitation next-action model and exposes
predict_next_action(session_state) -> structured, explainable result.

Scope note: this classifies which CATEGORY of post-exploitation activity
to focus on next for an authorized lab session (e.g. "Privilege
Escalation" as an area, not a specific exploit or command). It does not
generate exploit code, payloads, or operational instructions.

Usage:
    from inference_post_model import predict_next_action

    session_state = {
        "os_type": "windows",
        "privilege_level": "low",
        "hashdump_success": 0,
        "sysinfo_success": 1,
        "network_enum": 0,
        "process_list": 1,
        "local_exploit_suggested": 1,
    }
    print(predict_next_action(session_state))
"""

from __future__ import annotations

import json
from functools import lru_cache

import joblib
import numpy as np
import pandas as pd

from feature_engineering_post_exploit import (
    BOOLEAN_COLUMNS,
    CATEGORICAL_COLUMNS,
    build_feature_matrix,
)

MODELS_DIR = "models"

LABEL_RATIONALE = {
    "System Information Gathering": "baseline system information has not yet been collected",
    "Process Enumeration": "running processes have not yet been enumerated",
    "Credential Harvesting": "credential material has not yet been collected",
    "Network Enumeration": "network configuration and connections have not yet been enumerated",
    "Privilege Escalation": "elevating privilege is the highest-priority open task for this session",
    "Lateral Movement Preparation": "recon and credential collection are complete at high privilege, so preparing for lateral movement is the next step",
}


@lru_cache(maxsize=1)
def _load_artifacts():
    model = joblib.load(f"{MODELS_DIR}/trained_post_model.pkl")
    one_hot_encoder = joblib.load(f"{MODELS_DIR}/one_hot_encoder.pkl")
    label_encoder = joblib.load(f"{MODELS_DIR}/label_encoder.pkl")
    metadata = joblib.load(f"{MODELS_DIR}/post_model_metadata.pkl")
    feature_names = metadata["feature_names"]

    importances = getattr(model, "feature_importances_", None)
    if importances is not None:
        global_importance = dict(zip(feature_names, importances.tolist()))
    else:
        global_importance = {name: 0.0 for name in feature_names}

    return model, one_hot_encoder, label_encoder, feature_names, global_importance


def _session_to_dataframe(session_state: dict) -> pd.DataFrame:
    required = CATEGORICAL_COLUMNS + BOOLEAN_COLUMNS
    missing = [c for c in required if c not in session_state]
    if missing:
        raise ValueError(f"Missing required fields in session_state: {missing}")
    return pd.DataFrame([{c: session_state[c] for c in required}])


def predict_next_action(session_state: dict, top_k_features: int = 5) -> dict:
    model, one_hot_encoder, label_encoder, feature_names, global_importance = _load_artifacts()

    df = _session_to_dataframe(session_state)
    X, _, _, _, _ = build_feature_matrix(df, one_hot_encoder=one_hot_encoder, label_encoder=None)

    probs = model.predict_proba(X)[0]
    pred_idx = int(np.argmax(probs))
    recommended_action = label_encoder.inverse_transform([pred_idx])[0]
    confidence = float(probs[pred_idx])

    encoded_row = pd.Series(X[0], index=feature_names)
    active_features = encoded_row[encoded_row > 0].index.tolist()
    ranked_active = sorted(
        active_features, key=lambda f: global_importance.get(f, 0.0), reverse=True
    )
    important_features = ranked_active[:top_k_features]

    base_reason = LABEL_RATIONALE.get(
        recommended_action, "this objective best matches the current session state"
    )
    if important_features:
        readable = ", ".join(f.replace("_", " ") for f in important_features)
        reason = f"Recommended because {base_reason}; most influential signals: {readable}."
    else:
        reason = f"Recommended because {base_reason}."

    return {
        "recommended_action": recommended_action,
        "confidence": round(confidence, 4),
        "reason": reason,
        "important_features": important_features,
    }


if __name__ == "__main__":
    demo_session = {
        "os_type": "windows",
        "privilege_level": "low",
        "hashdump_success": 0,
        "sysinfo_success": 1,
        "network_enum": 0,
        "process_list": 1,
        "local_exploit_suggested": 1,
    }
    print(json.dumps(predict_next_action(demo_session), indent=2))
