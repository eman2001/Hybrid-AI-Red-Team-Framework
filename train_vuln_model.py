"""
train_vuln_model.py
-------------------
Trains the Exploit Prioritizer ML model (Random Forest classifier).
Run this once before starting the main pipeline:

    python train_vuln_model.py

Outputs: models/vuln_model.pkl
"""

import pandas as pd
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report


def train():
    print("[*] Loading training data...")
    df = pd.read_csv("data/training_data.csv")

    # Encode categorical columns
    le_exploit  = LabelEncoder()
    le_service  = LabelEncoder()
    le_severity = LabelEncoder()

    df["exploit_enc"]  = le_exploit.fit_transform(df["exploit_name"])
    df["service_enc"]  = le_service.fit_transform(df["service"])
    df["severity_enc"] = le_severity.fit_transform(df["severity"])

    features = [
        "exploit_enc",
        "service_enc",
        "port",
        "auth_required",
        "remote",
        "severity_enc",
        "exploitability"
    ]

    X = df[features]
    y = df["label"]   # 1=high priority, 2=medium, 3=low

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print("[*] Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        random_state=42
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n[+] Classification Report:")
    print(classification_report(y_test, y_pred, zero_division=0))

    os.makedirs("models", exist_ok=True)
    model_data = {
        "model":           model,
        "le_exploit":      le_exploit,
        "le_service":      le_service,
        "le_severity":     le_severity,
        "feature_columns": features
    }
    with open("models/vuln_model.pkl", "wb") as f:
        pickle.dump(model_data, f)

    print("[+] Model saved to models/vuln_model.pkl")


if __name__ == "__main__":
    train()
