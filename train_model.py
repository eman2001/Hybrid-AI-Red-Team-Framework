"""
train_model.py
================
Trains and compares several classifiers on the assessment-objective
dataset, evaluates each with stratified cross-validation, and persists
the best-performing model (by macro F1) plus its encoders.

Algorithms compared:
    - Random Forest
    - Extra Trees
    - Gradient Boosting (sklearn)
    - XGBoost
    - LightGBM

Run:
    python train_model.py --data data/training_data.csv --out models/
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

from feature_engineering import build_feature_matrix, load_dataset, save_encoders

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
            n_estimators=300, max_depth=None, random_state=random_state, n_jobs=2
        ),
        "ExtraTrees": ExtraTreesClassifier(
            n_estimators=300, max_depth=None, random_state=random_state, n_jobs=2
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
            n_jobs=2,
        )
    if HAS_LGBM:
        models["LightGBM"] = LGBMClassifier(
            n_estimators=250,
            max_depth=-1,
            learning_rate=0.1,
            random_state=random_state,
            n_jobs=2,
            verbosity=-1,
        )
    return models


def main():
    parser = argparse.ArgumentParser(description="Train and compare assessment-objective classifiers")
    parser.add_argument("--data", type=str, default="data/training_data.csv")
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

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )

    cv = StratifiedKFold(n_splits=args.cv_folds, shuffle=True, random_state=args.seed)
    models = get_candidate_models(random_state=args.seed)

    results = {}
    print(f"\nComparing {len(models)} models with {args.cv_folds}-fold stratified CV "
          f"(macro F1)...\n")

    for name, model in models.items():
        start = time.time()
        cv_scores = cross_val_score(
            model, X_train, y_train, cv=cv, scoring="f1_macro", n_jobs=2
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

    joblib.dump(best_model, f"{args.out}/trained_model.pkl")
    joblib.dump(
        {"best_model_name": best_name, "feature_names": feature_names},
        f"{args.out}/model_metadata.pkl",
    )

    np.savez(
        f"{args.out}/test_split.npz",
        X_test=X_test,
        y_test=y_test,
        X_train=X_train,
        y_train=y_train,
    )

    with open(f"{args.out}/comparison_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nSaved: {args.out}/trained_model.pkl ({best_name})")
    print(f"Saved: {args.out}/label_encoder.pkl, {args.out}/one_hot_encoder.pkl")
    print(f"Saved: {args.out}/comparison_results.json")


if __name__ == "__main__":
    main()
