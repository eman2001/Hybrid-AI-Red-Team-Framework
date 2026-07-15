"""
train_post_model.py
-------------------
Trains the Post-Exploitation AI model (Random Forest classifier).
Run this once before starting the main pipeline:

    python train_post_model.py

Outputs: models/post_exploit_model.pkl
"""

import pandas as pd
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report


def train():
    print("[*] Loading post-exploitation training data...")
    df = pd.read_csv("data/post_exploit_training.csv")

    le_os   = LabelEncoder()
    le_priv = LabelEncoder()
    le_act  = LabelEncoder()

    df["os_enc"]   = le_os.fit_transform(df["os_type"])
    df["priv_enc"] = le_priv.fit_transform(df["privilege_level"])
    df["action_enc"] = le_act.fit_transform(df["action_label"])

    features = [
        "os_enc",
        "priv_enc",
        "hashdump_success",
        "sysinfo_success",
        "network_enum",
        "process_list",
        "local_exploit_suggested"
    ]

    X = df[features]
    y = df["action_enc"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print("[*] Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=5,
        random_state=42
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n[+] Classification Report:")
    print(classification_report(y_test, y_pred,
                                target_names=le_act.classes_,
                                zero_division=0))

    os.makedirs("models", exist_ok=True)
    model_data = {
        "model":    model,
        "le_os":    le_os,
        "le_priv":  le_priv,
        "le_act":   le_act,
        "features": features
    }
    with open("models/post_exploit_model.pkl", "wb") as f:
        pickle.dump(model_data, f)

    print("[+] Model saved to models/post_exploit_model.pkl")


if __name__ == "__main__":
    train()
