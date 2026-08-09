"""
train_model_v2.py
--------------------
Trains the exploit prioritizer on data/training_data_v2.csv (real,
KEV/EDB/NVD-grounded data) with class_weight="balanced".

Usage:
    python train_model_v2.py --data data/training_data_v2.csv
"""
import argparse
import pickle
from collections import Counter
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import accuracy_score, classification_report

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "engine" / "models" / "exploit_model.pkl"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/training_data_v2.csv")
    ap.add_argument("--model-out", default=str(DEFAULT_MODEL_PATH))
    args = ap.parse_args()

    data = pd.read_csv(args.data)
    print(f"[+] Loaded {len(data)} rows from {args.data}")
    print(f"[+] priority_label distribution: {Counter(data['priority_label'])}")
    print(f"[+] exploit_type distribution: {Counter(data['exploit_type'])}")

    exploit_types = sorted(data["exploit_type"].unique())
    exploit_map = {t: i for i, t in enumerate(exploit_types)}
    print(f"[+] exploit_type encoding: {exploit_map}")
    data["exploit_type_enc"] = data["exploit_type"].map(exploit_map)

    label_map = {"high": 2, "medium": 1, "low": 0}
    data["priority_label_enc"] = data["priority_label"].map(label_map)

    X = data[["cvss_score", "exploit_type_enc", "port"]]
    y = data["priority_label_enc"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    candidates = {
        "DecisionTree_balanced": DecisionTreeClassifier(
            max_depth=6, min_samples_leaf=5, class_weight="balanced", random_state=42
        ),
        "RandomForest_balanced": RandomForestClassifier(
            n_estimators=300, max_depth=10, min_samples_leaf=3,
            class_weight="balanced", random_state=42, n_jobs=-1
        ),
    }

    print("\n[*] Comparing candidates with 5-fold CV (balanced weights) ...")
    best_name, best_model, best_cv = None, None, -1
    for name, model in candidates.items():
        scores = cross_val_score(model, X_train, y_train, cv=cv,
                                  scoring="f1_macro", n_jobs=-1)
        print(f"    {name:<25} CV macro-F1: {scores.mean():.3f} (+/- {scores.std():.3f})")
        if scores.mean() > best_cv:
            best_name, best_model, best_cv = name, model, scores.mean()

    print(f"\n[+] Best model: {best_name}")
    best_model.fit(X_train, y_train)
    test_preds = best_model.predict(X_test)
    test_acc = accuracy_score(y_test, test_preds)
    print(f"\nHeld-out test accuracy: {test_acc:.3f}")
    print("\nClassification report (test set):")
    print(classification_report(y_test, test_preds,
                                 target_names=["low", "medium", "high"],
                                 zero_division=0))

    final_model = type(best_model)(**best_model.get_params())
    final_model.fit(X, y)

    model_out_path = Path(args.model_out)
    model_out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(model_out_path, "wb") as f:
        pickle.dump({
            "model": final_model,
            "exploit_type_map": exploit_map,
            "label_map": label_map,
            "model_type": best_name,
            "version": "2.0-real-data-balanced",
        }, f)

    print(f"\n[+] Final model saved -> {args.model_out}")


if __name__ == "__main__":
    main()
