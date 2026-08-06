"""
inference.py
==============
Loads the trained model + encoders and exposes a single function,
predict_next_objective(session_state), that returns a structured,
explainable recommendation for an authorized lab assessment session.

This module performs classification only. It does not generate exploits,
payloads, attack chains, or any offensive/operational instructions -- its
output is limited to naming which broad category of information-gathering
the next step should focus on (e.g. "Network Assessment"), a confidence
score, a short natural-language rationale, and the features that most
influenced that recommendation.

Usage:
    from inference import predict_next_objective

    session_state = {
        "os_type": "windows",
        "architecture": "x64",
        "privilege_level": "low",
        "session_type": "interactive",
        "credential_indicator": "none",
        "domain_joined": 1,
        "multiple_users_logged_in": 0,
        "high_process_count": 0,
        "suspicious_process_present": 0,
        "multiple_network_interfaces": 0,
        "active_external_connections": 0,
        "security_software_present": 1,
        "remote_management_enabled": 0,
        "unusual_services_present": 0,
        "scheduled_tasks_present": 0,
        "unusual_scheduled_tasks": 0,
        "sensitive_files_indicator": 0,
        "system_info_collected": 0,
        "user_info_collected": 0,
        "process_info_collected": 0,
        "service_info_collected": 0,
        "network_info_collected": 0,
        "config_info_collected": 0,
        "security_controls_reviewed": 0,
        "account_info_collected": 0,
        "risk_assessment_done": 0,
    }

    result = predict_next_objective(session_state)
    print(result)
"""

from __future__ import annotations

import json
from functools import lru_cache

import joblib
import numpy as np
import pandas as pd

from feature_engineering import (
    BOOLEAN_COLUMNS,
    CATEGORICAL_COLUMNS,
    build_feature_matrix,
)

MODELS_DIR = "models"

LABEL_RATIONALE = {
    "System Discovery": "baseline system information has not been established for this session",
    "User Assessment": "logged-in user and session context has not yet been reviewed",
    "Process Analysis": "running process information has not yet been analyzed",
    "Service Analysis": "installed/running services have not yet been reviewed",
    "Network Assessment": "network interfaces and active connections have not yet been characterized",
    "Configuration Review": "host and file-system configuration has not yet been reviewed",
    "Security Control Review": "installed security controls have not yet been reviewed",
    "Account Assessment": "account and credential posture has not yet been assessed",
    "Risk Assessment": "collected findings should now be consolidated into an overall risk assessment",
    "Session Completion": "all standard assessment areas for this session appear to be covered",
}


@lru_cache(maxsize=1)
def _load_artifacts():
    model = joblib.load(f"{MODELS_DIR}/trained_model.pkl")
    one_hot_encoder = joblib.load(f"{MODELS_DIR}/one_hot_encoder.pkl")
    label_encoder = joblib.load(f"{MODELS_DIR}/label_encoder.pkl")
    metadata = joblib.load(f"{MODELS_DIR}/model_metadata.pkl")
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


def predict_next_objective(session_state: dict, top_k_features: int = 5) -> dict:
    """
    Parameters
    ----------
    session_state : dict
        Raw feature values for one endpoint session (see module docstring
        for the required keys).
    top_k_features : int
        How many contributing features to report in `important_features`.

    Returns
    -------
    dict with keys: recommended_objective, confidence, reason,
    important_features.
    """
    model, one_hot_encoder, label_encoder, feature_names, global_importance = _load_artifacts()

    df = _session_to_dataframe(session_state)
    X, _, _, _, _ = build_feature_matrix(df, one_hot_encoder=one_hot_encoder, label_encoder=None)

    probs = model.predict_proba(X)[0]
    pred_idx = int(np.argmax(probs))
    recommended_objective = label_encoder.inverse_transform([pred_idx])[0]
    confidence = float(probs[pred_idx])

    encoded_row = pd.Series(X[0], index=feature_names)
    active_features = encoded_row[encoded_row > 0].index.tolist()
    ranked_active = sorted(
        active_features, key=lambda f: global_importance.get(f, 0.0), reverse=True
    )
    important_features = ranked_active[:top_k_features]

    base_reason = LABEL_RATIONALE.get(
        recommended_objective, "this objective best matches the current session state"
    )
    if important_features:
        readable = ", ".join(f.replace("_", " ") for f in important_features)
        reason = f"Recommended because {base_reason}; most influential signals: {readable}."
    else:
        reason = f"Recommended because {base_reason}."

    return {
        "recommended_objective": recommended_objective,
        "confidence": round(confidence, 4),
        "reason": reason,
        "important_features": important_features,
    }


if __name__ == "__main__":
    demo_session = {
        "os_type": "windows",
        "architecture": "x64",
        "privilege_level": "low",
        "session_type": "interactive",
        "credential_indicator": "none",
        "domain_joined": 1,
        "multiple_users_logged_in": 0,
        "high_process_count": 0,
        "suspicious_process_present": 0,
        "multiple_network_interfaces": 0,
        "active_external_connections": 0,
        "security_software_present": 1,
        "remote_management_enabled": 0,
        "unusual_services_present": 0,
        "scheduled_tasks_present": 0,
        "unusual_scheduled_tasks": 0,
        "sensitive_files_indicator": 0,
        "system_info_collected": 0,
        "user_info_collected": 0,
        "process_info_collected": 0,
        "service_info_collected": 0,
        "network_info_collected": 0,
        "config_info_collected": 0,
        "security_controls_reviewed": 0,
        "account_info_collected": 0,
        "risk_assessment_done": 0,
    }
    print(json.dumps(predict_next_objective(demo_session), indent=2))
