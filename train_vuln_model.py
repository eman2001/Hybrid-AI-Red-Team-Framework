"""
train_vuln_model.py (v2)
---------------------------
Trains the Vulnerability Prioritizer model on data/vuln_training_data.csv
(real, NVD/EDB/KEV-grounded), with class_weight="balanced" and stratified CV.

Run:
    python train_vuln_model.py --data data/vuln_training_data.csv
Outputs: models/vuln_model.pkl
"""
import argparse
import pickle
import os
from collections import Counter

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report


def train(data_path, model_out):
    print("[*] Loading training data...")
    df = pd.read_csv(data_path)
    print(f"  Loaded {len(df)} rows from {data_path}")
    print(f"  Label distribution: {Counter(df['label'])}")

    le_exploit = LabelEncoder()
    le_service = LabelEncoder()
    le_severity = LabelEncoder()

    df["exploit_enc"] = le_exploit.fit_transform(df["exploit_name"])
    df["service_enc"] = le_service.fit_transform(df["service"])
    df["severity_enc"] = le_severity.fit_transform(df["severity"])

    features = [
        "exploit_enc",
        "service_enc",
        "port",
        "auth_required",
        "remote",
        "severity_enc",
        "exploitability",
    ]

    X = df[features]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    model = RandomForestClassifier(
        n_estimators=100, max_depth=6, class_weight="balanced", random_state=42
    )

    cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="f1_macro")
    print(f"\n[*] 5-fold CV macro-F1: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")

    print("\n[*] Training Random Forest classifier on the full train split...")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print("\n[+] Classification Report (held-out test set):")
    print(classification_report(y_test, y_pred,
                                 target_names=["high", "medium", "low"],
                                 zero_division=0))

    final_model = RandomForestClassifier(
        n_estimators=100, max_depth=6, class_weight="balanced", random_state=42
    )
    final_model.fit(X, y)

    os.makedirs(os.path.dirname(model_out) or ".", exist_ok=True)
    model_data = {
        "model": final_model,
        "le_exploit": le_exploit,
        "le_service": le_service,
        "le_severity": le_severity,
        "feature_columns": features,
        "version": "2.0-real-data-balanced",
    }
    with open(model_out, "wb") as f:
        pickle.dump(model_data, f)

    print(f"\n[+] Model saved to {model_out}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/vuln_training_data.csv")
    ap.add_argument("--model-out", default="models/vuln_model.pkl")
    args = ap.parse_args()
    train(args.data, args.model_out)
