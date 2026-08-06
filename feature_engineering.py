"""
feature_engineering.py
=======================
Turns the raw synthetic dataset (categorical + boolean columns, a text
label, and a human-readable explanation) into a numeric feature matrix
and encoded label vector suitable for scikit-learn / XGBoost / LightGBM.

Usage:
    from feature_engineering import build_feature_matrix, load_dataset
    df = load_dataset("data/training_data.csv")
    X, y, feature_names, label_encoder, one_hot_encoder = build_feature_matrix(df)
"""

from __future__ import annotations

import joblib
import pandas as pd
from sklearn.preprocessing import LabelEncoder, OneHotEncoder

CATEGORICAL_COLUMNS = [
    "os_type",
    "architecture",
    "privilege_level",
    "session_type",
    "credential_indicator",
]

BOOLEAN_COLUMNS = [
    "domain_joined",
    "multiple_users_logged_in",
    "high_process_count",
    "suspicious_process_present",
    "multiple_network_interfaces",
    "active_external_connections",
    "security_software_present",
    "remote_management_enabled",
    "unusual_services_present",
    "scheduled_tasks_present",
    "unusual_scheduled_tasks",
    "sensitive_files_indicator",
    "system_info_collected",
    "user_info_collected",
    "process_info_collected",
    "service_info_collected",
    "network_info_collected",
    "config_info_collected",
    "security_controls_reviewed",
    "account_info_collected",
    "risk_assessment_done",
]

LABEL_COLUMN = "label"
DROP_COLUMNS = ["explanation"]


def load_dataset(path: str) -> pd.DataFrame:
    return pd.read_csv(path)


def build_feature_matrix(df: pd.DataFrame, one_hot_encoder: OneHotEncoder | None = None,
                          label_encoder: LabelEncoder | None = None):
    """
    Returns (X, y, feature_names, one_hot_encoder, label_encoder).
    Pass a previously-fit encoder to transform new/held-out data
    consistently (e.g. at inference time).
    """
    df = df.copy()
    for col in DROP_COLUMNS:
        if col in df.columns:
            df = df.drop(columns=[col])

    fit_mode = one_hot_encoder is None
    if fit_mode:
        one_hot_encoder = OneHotEncoder(sparse_output=False, handle_unknown="ignore")
        cat_encoded = one_hot_encoder.fit_transform(df[CATEGORICAL_COLUMNS])
    else:
        cat_encoded = one_hot_encoder.transform(df[CATEGORICAL_COLUMNS])

    cat_feature_names = list(one_hot_encoder.get_feature_names_out(CATEGORICAL_COLUMNS))
    cat_df = pd.DataFrame(cat_encoded, columns=cat_feature_names, index=df.index)

    bool_df = df[BOOLEAN_COLUMNS].astype(int)

    X_df = pd.concat([cat_df, bool_df], axis=1)
    feature_names = list(X_df.columns)
    X = X_df.values

    y = None
    if LABEL_COLUMN in df.columns:
        if label_encoder is None:
            label_encoder = LabelEncoder()
            y = label_encoder.fit_transform(df[LABEL_COLUMN])
        else:
            y = label_encoder.transform(df[LABEL_COLUMN])

    return X, y, feature_names, one_hot_encoder, label_encoder


def save_encoders(one_hot_encoder, label_encoder, out_dir: str = "models"):
    joblib.dump(one_hot_encoder, f"{out_dir}/one_hot_encoder.pkl")
    joblib.dump(label_encoder, f"{out_dir}/label_encoder.pkl")


def load_encoders(out_dir: str = "models"):
    one_hot_encoder = joblib.load(f"{out_dir}/one_hot_encoder.pkl")
    label_encoder = joblib.load(f"{out_dir}/label_encoder.pkl")
    return one_hot_encoder, label_encoder


if __name__ == "__main__":
    df = load_dataset("data/training_data.csv")
    X, y, feature_names, ohe, le = build_feature_matrix(df)
    save_encoders(ohe, le)
    print(f"Feature matrix shape: {X.shape}")
    print(f"Number of features: {len(feature_names)}")
    print(f"Classes: {list(le.classes_)}")
