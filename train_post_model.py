"""
train_post_model.py
=====================
Trains and compares classifiers for the post-exploitation next-action
model on the merged (generated + real) dataset, using the same
methodology as the Assessment-Objective model: stratified CV, macro F1
selection, persisted best model + encoders.

Class balance note: unlike the Assessment-Objective dataset, this
taxonomy's classes are NOT equally sized by construction -- full
enumeration of the 192-state space naturally produces more states that
resolve to "Privilege Escalation" / "System Information Gathering" than
to "Network Enumeration" (see generate_post_exploit_data.py for why).
This is a real property of the rule engine's decision boundaries, not an
artifact of sampling, so it is left as-is rather than artificially
rebalanced -- but class_weight="balanced" is used for the tree ensembles
so rare classes still get a fair training signal, and macro F1 (which
weights all classes equally regardless of size) is used for model
selection instead of accuracy.

Run:
    python train_post_model.py --data data/post_exploit_merged.csv --out models
"""

import argparse
import json
import time

import joblib
import numpy as np
from sklearn.ensemble import (
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

from feature_engineering_post_exploit import build_feature_matrix, load_dataset, save_encoders

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

try:
    from lightgbm import LGBMClassifier
    HAS_LGBM = True
except ImportError:
    HAS_LGBM = False


def get_candidate_models(random_state: int = 42) -> dict:
    models = {
        "RandomForest": RandomForestClassifier(
            n_estimators=300, class_weight="balanced", random_state=random_state, n_jobs=-1
        ),
        "ExtraTrees": ExtraTreesClassifier(
            n_estimators=300, class_weight="balanced", random_state=random_state, n_jobs=-1
        ),
        "GradientBoosting": GradientBoostingClassifier(
            n_estimators=200, max_depth=3, random_state=random_state
        ),
    }
    if HAS_XGB:
        models["XGBoost"] = XGBClassifier(
            n_estimators=250,
            max_depth=5,
            learning_rate=0.1,
            random_state=random_state,
            eval_metric="mlogloss",
            n_jobs=-1,
        )
    if HAS_LGBM:
        models["LightGBM"] = LGBMClassifier(
            n_estimators=250,
            max_depth=-1,
            learning_rate=0.1,
            class_weight="balanced",
            random_state=random_state,
            n_jobs=-1,
            verbosity=-1,
        )
    return models


def main():
    parser = argparse.ArgumentParser(description="Train and compare post-exploitation next-action classifiers")
    parser.add_argument("--data", type=str, default="data/post_exploit_merged.csv")
    parser.add_argument("--out", type=str, default="models")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    print("Loading dataset...")
    df = load_dataset(args.data)
    X, y, feature_names, ohe, le = build_feature_matrix(df)
    save_encoders(ohe, le, out_dir=args.out)

    with open(f"{args.out}/feature_names.json", "w") as f:
        json.dump(feature_names, f, indent=2)

    # Guard against a class being too small for the requested number of
    # CV folds / stratified test split (the smallest class here is only
    # ~24 generated rows before any real data is merged in).
    min_class_count = np.min(np.bincount(y))
    cv_folds = min(args.cv_folds, min_class_count)
    if cv_folds < args.cv_folds:
        print(f"Note: smallest class has {min_class_count} rows; reducing CV folds to {cv_folds}.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )

    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=args.seed)
    models = get_candidate_models(random_state=args.seed)

    results = {}
    print(f"\nComparing {len(models)} models with {cv_folds}-fold stratified CV (macro F1)...\n")

    for name, model in models.items():
        start = time.time()
        cv_scores = cross_val_score(
            model, X_train, y_train, cv=cv, scoring="f1_macro", n_jobs=-1
        )
        elapsed = time.time() - start
        results[name] = {
            "cv_macro_f1_mean": float(np.mean(cv_scores)),
            "cv_macro_f1_std": float(np.std(cv_scores)),
            "cv_scores": [float(s) for s in cv_scores],
            "train_time_sec": round(elapsed, 2),
        }
        print(
            f"  {name:<18} macro F1 = {np.mean(cv_scores):.4f} "
            f"(+/- {np.std(cv_scores):.4f})   [{elapsed:.1f}s]"
        )

    best_name = max(results, key=lambda k: results[k]["cv_macro_f1_mean"])
    print(f"\nBest model by CV macro F1: {best_name}")

    best_model = models[best_name]
    best_model.fit(X_train, y_train)

    joblib.dump(best_model, f"{args.out}/trained_post_model.pkl")
    joblib.dump(
        {"best_model_name": best_name, "feature_names": feature_names},
        f"{args.out}/post_model_metadata.pkl",
    )

    np.savez(
        f"{args.out}/post_test_split.npz",
        X_test=X_test,
        y_test=y_test,
        X_train=X_train,
        y_train=y_train,
    )

    with open(f"{args.out}/post_comparison_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nSaved: {args.out}/trained_post_model.pkl ({best_name})")
    print(f"Saved: {args.out}/label_encoder.pkl, {args.out}/one_hot_encoder.pkl")
    print(f"Saved: {args.out}/post_comparison_results.json")


if __name__ == "__main__":
    main()
