"""
train_model_v2.py
-----------------
Exploit Prioritization Model Training and Evaluation.

Dataset:
    data/training_data_v2.csv

Features:
    - cvss_score
    - exploit_type
    - port

Target:
    - priority_label: low / medium / high

Evaluation:
    - Dataset statistics
    - 80/20 stratified hold-out split
    - Dummy majority baseline
    - Simple rule-based baseline
    - Decision Tree
    - Random Forest
    - Accuracy
    - Macro Precision / Recall / F1
    - Classification report
    - Confusion matrix
    - 5-fold Stratified Cross-Validation
    - Grouped Cross-Validation by CVE ID

Usage:
    python train_model_v2.py --data data/training_data_v2.csv
"""

import argparse
import pickle
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.base import clone
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

from sklearn.model_selection import (
    train_test_split,
    cross_val_score,
    StratifiedKFold,
    StratifiedGroupKFold,
)

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)


# ============================================================
# Configuration
# ============================================================

DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parent
    / "engine"
    / "models"
    / "exploit_model.pkl"
)

LABEL_MAP = {
    "low": 0,
    "medium": 1,
    "high": 2,
}

REVERSE_LABEL_MAP = {
    0: "low",
    1: "medium",
    2: "high",
}

TARGET_NAMES = ["low", "medium", "high"]


# ============================================================
# Helper functions
# ============================================================

def print_section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def evaluate_predictions(name, y_true, y_pred):
    """
    Print classification metrics for a model.
    """

    accuracy = accuracy_score(y_true, y_pred)

    precision_macro = precision_score(
        y_true,
        y_pred,
        average="macro",
        zero_division=0,
    )

    recall_macro = recall_score(
        y_true,
        y_pred,
        average="macro",
        zero_division=0,
    )

    f1_macro = f1_score(
        y_true,
        y_pred,
        average="macro",
        zero_division=0,
    )

    print(f"\n{name}")
    print("-" * len(name))

    print(f"Accuracy        : {accuracy:.4f}")
    print(f"Macro Precision : {precision_macro:.4f}")
    print(f"Macro Recall    : {recall_macro:.4f}")
    print(f"Macro F1-score  : {f1_macro:.4f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_true,
            y_pred,
            labels=[0, 1, 2],
            target_names=TARGET_NAMES,
            zero_division=0,
            digits=4,
        )
    )

    cm = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1, 2],
    )

    print("Confusion Matrix:")
    print("Rows = Actual, Columns = Predicted")
    print("               LOW   MEDIUM   HIGH")

    for label, row in zip(
        ["LOW   ", "MEDIUM", "HIGH  "],
        cm,
    ):
        print(
            f"{label:>7} "
            f"{row[0]:>7} "
            f"{row[1]:>8} "
            f"{row[2]:>6}"
        )

    return {
        "accuracy": accuracy,
        "precision_macro": precision_macro,
        "recall_macro": recall_macro,
        "f1_macro": f1_macro,
        "confusion_matrix": cm.tolist(),
    }


def rule_based_baseline(data):
    """
    Simple baseline based only on exploit source.

    This is intentionally simple and is used only for comparison
    with the ML models.

    Rule:
      kev_only   -> high
      metasploit -> high
      exploitdb  -> medium

    It does NOT represent the full production Risk Engine.
    """

    predictions = []

    for exploit_type in data["exploit_type"]:

        exploit_type = str(exploit_type).lower()

        if exploit_type in {"kev_only", "metasploit"}:
            predictions.append(LABEL_MAP["high"])

        else:
            predictions.append(LABEL_MAP["medium"])

    return np.array(predictions)


# ============================================================
# Main
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--data",
        default="data/training_data_v2.csv",
    )

    parser.add_argument(
        "--model-out",
        default=str(DEFAULT_MODEL_PATH),
    )

    args = parser.parse_args()

    # ========================================================
    # Load dataset
    # ========================================================

    print_section("1. DATASET INFORMATION")

    data = pd.read_csv(args.data)

    required_columns = {
        "cve_id",
        "cvss_score",
        "exploit_type",
        "port",
        "priority_label",
    }

    missing = required_columns - set(data.columns)

    if missing:
        raise ValueError(
            f"Dataset is missing required columns: {sorted(missing)}"
        )

    print(f"Dataset file           : {args.data}")
    print(f"Total rows             : {len(data)}")
    print(f"Unique CVE identifiers : {data['cve_id'].nunique()}")

    exact_duplicates = data.duplicated().sum()

    duplicate_cve_rows = (
        len(data)
        - data["cve_id"].nunique()
    )

    print(f"Exact duplicate rows   : {exact_duplicates}")
    print(f"Repeated CVE rows      : {duplicate_cve_rows}")

    # --------------------------------------------------------
    # Class distribution
    # --------------------------------------------------------

    print("\nPriority label distribution:")

    label_counts = Counter(
        data["priority_label"].astype(str).str.lower()
    )

    for label in ["low", "medium", "high"]:

        count = label_counts.get(label, 0)

        percentage = (
            count / len(data) * 100
            if len(data)
            else 0
        )

        print(
            f"  {label:<8}: "
            f"{count:<6} "
            f"({percentage:.2f}%)"
        )

    # --------------------------------------------------------
    # Exploit-type distribution
    # --------------------------------------------------------

    print("\nExploit type distribution:")

    exploit_counts = Counter(
        data["exploit_type"].astype(str)
    )

    for exploit_type, count in sorted(
        exploit_counts.items()
    ):
        print(
            f"  {exploit_type:<15}: {count}"
        )

    # --------------------------------------------------------
    # Cross-tab between source and class
    # --------------------------------------------------------

    print("\nExploit Type vs Priority Label:")

    print(
        pd.crosstab(
            data["exploit_type"],
            data["priority_label"],
        )
    )

    # ========================================================
    # Feature engineering
    # ========================================================

    print_section("2. FEATURE ENGINEERING")

    exploit_types = sorted(
        data["exploit_type"]
        .dropna()
        .unique()
    )

    exploit_map = {
        exploit_type: index
        for index, exploit_type
        in enumerate(exploit_types)
    }

    print(
        "Exploit type encoding:",
        exploit_map,
    )

    data["exploit_type_enc"] = (
        data["exploit_type"]
        .map(exploit_map)
    )

    data["priority_label_enc"] = (
        data["priority_label"]
        .astype(str)
        .str.lower()
        .map(LABEL_MAP)
    )

    if data["priority_label_enc"].isna().any():
        invalid = data.loc[
            data["priority_label_enc"].isna(),
            "priority_label",
        ].unique()

        raise ValueError(
            f"Unknown priority labels: {invalid}"
        )

    X = data[
        [
            "cvss_score",
            "exploit_type_enc",
            "port",
        ]
    ]

    y = data["priority_label_enc"]

    groups = data["cve_id"]

    # ========================================================
    # Train/test split
    # ========================================================

    print_section("3. STRATIFIED HOLD-OUT SPLIT")

    (
        X_train,
        X_test,
        y_train,
        y_test,
        groups_train,
        groups_test,
    ) = train_test_split(
        X,
        y,
        groups,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print(
        f"Training samples : {len(X_train)} "
        f"({len(X_train) / len(data) * 100:.1f}%)"
    )

    print(
        f"Testing samples  : {len(X_test)} "
        f"({len(X_test) / len(data) * 100:.1f}%)"
    )

    print("\nTraining class distribution:")

    for label_id in [0, 1, 2]:

        count = int(
            (y_train == label_id).sum()
        )

        print(
            f"  {REVERSE_LABEL_MAP[label_id]:<8}: "
            f"{count}"
        )

    print("\nTesting class distribution:")

    for label_id in [0, 1, 2]:

        count = int(
            (y_test == label_id).sum()
        )

        print(
            f"  {REVERSE_LABEL_MAP[label_id]:<8}: "
            f"{count}"
        )

    # ========================================================
    # Baseline 1: Dummy majority
    # ========================================================

    print_section("4. BASELINE MODELS")

    dummy = DummyClassifier(
        strategy="most_frequent",
    )

    dummy.fit(
        X_train,
        y_train,
    )

    dummy_predictions = dummy.predict(
        X_test
    )

    dummy_metrics = evaluate_predictions(
        "Dummy Majority Baseline",
        y_test,
        dummy_predictions,
    )

    # ========================================================
    # Baseline 2: Simple rule baseline
    # ========================================================

    test_indices = X_test.index

    rule_test_data = data.loc[
        test_indices
    ]

    rule_predictions = rule_based_baseline(
        rule_test_data
    )

    rule_metrics = evaluate_predictions(
        "Simple Rule-Based Baseline",
        y_test,
        rule_predictions,
    )

    # ========================================================
    # Candidate ML models
    # ========================================================

    print_section(
        "5. MACHINE LEARNING MODEL COMPARISON"
    )

    candidates = {

        "DecisionTree_balanced":
            DecisionTreeClassifier(
                max_depth=6,
                min_samples_leaf=5,
                class_weight="balanced",
                random_state=42,
            ),

        "RandomForest_balanced":
            RandomForestClassifier(
                n_estimators=300,
                max_depth=10,
                min_samples_leaf=3,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            ),
    }

    # ========================================================
    # Stratified 5-fold CV
    # ========================================================

    stratified_cv = StratifiedKFold(
        n_splits=5,
        shuffle=True,
        random_state=42,
    )

    print(
        "\n5-Fold Stratified Cross-Validation "
        "(scoring = Macro-F1)"
    )

    cv_results = {}

    best_name = None
    best_model = None
    best_cv_score = -1

    for name, model in candidates.items():

        scores = cross_val_score(
            model,
            X_train,
            y_train,
            cv=stratified_cv,
            scoring="f1_macro",
            n_jobs=-1,
        )

        cv_results[name] = {
            "mean": scores.mean(),
            "std": scores.std(),
            "scores": scores.tolist(),
        }

        print(
            f"{name:<28} "
            f"Macro-F1 = "
            f"{scores.mean():.4f} "
            f"(+/- {scores.std():.4f})"
        )

        print(
            "  Fold scores:",
            " ".join(
                f"{score:.4f}"
                for score in scores
            ),
        )

        if scores.mean() > best_cv_score:

            best_name = name
            best_model = model
            best_cv_score = scores.mean()

    # ========================================================
    # Grouped CV by CVE
    # ========================================================

    print_section(
        "6. GROUPED CROSS-VALIDATION BY CVE ID"
    )

    print(
        "This evaluation prevents the same CVE identifier "
        "from appearing in both training and validation "
        "within a fold."
    )

    grouped_cv = StratifiedGroupKFold(
        n_splits=5,
        shuffle=True,
        random_state=42,
    )

    grouped_results = {}

    for name, model in candidates.items():

        try:

            scores = cross_val_score(
                model,
                X,
                y,
                groups=groups,
                cv=grouped_cv,
                scoring="f1_macro",
                n_jobs=-1,
            )

            grouped_results[name] = {
                "mean": scores.mean(),
                "std": scores.std(),
                "scores": scores.tolist(),
            }

            print(
                f"{name:<28} "
                f"Grouped Macro-F1 = "
                f"{scores.mean():.4f} "
                f"(+/- {scores.std():.4f})"
            )

            print(
                "  Fold scores:",
                " ".join(
                    f"{score:.4f}"
                    for score in scores
                ),
            )

        except Exception as exc:

            print(
                f"{name}: grouped CV could not be "
                f"computed: {exc}"
            )

    # ========================================================
    # Held-out evaluation
    # ========================================================

    print_section(
        "7. HELD-OUT TEST EVALUATION"
    )

    model_test_results = {}

    for name, model in candidates.items():

        fitted_model = clone(model)

        fitted_model.fit(
            X_train,
            y_train,
        )

        predictions = fitted_model.predict(
            X_test
        )

        metrics = evaluate_predictions(
            name,
            y_test,
            predictions,
        )

        model_test_results[name] = metrics

    # ========================================================
    # Best model
    # ========================================================

    print_section(
        "8. BEST MODEL SELECTION"
    )

    print(
        f"Selected model       : {best_name}"
    )

    print(
        f"Best CV Macro-F1     : "
        f"{best_cv_score:.4f}"
    )

    # ========================================================
    # Train final deployment model
    # ========================================================

    print_section(
        "9. FINAL MODEL TRAINING"
    )

    final_model = clone(
        best_model
    )

    final_model.fit(
        X,
        y,
    )

    model_out_path = Path(
        args.model_out
    )

    model_out_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    artifact = {

        "model":
            final_model,

        "exploit_type_map":
            exploit_map,

        "label_map":
            LABEL_MAP,

        "reverse_label_map":
            REVERSE_LABEL_MAP,

        "model_type":
            best_name,

        "version":
            "2.1-real-data-balanced-evaluated",

        "features": [
            "cvss_score",
            "exploit_type_enc",
            "port",
        ],

        "dataset_rows":
            len(data),

        "unique_cves":
            data["cve_id"].nunique(),

        "class_distribution":
            dict(label_counts),

        "best_cv_macro_f1":
            float(best_cv_score),

        "cv_results":
            cv_results,

        "grouped_cv_results":
            grouped_results,

        "held_out_results":
            model_test_results,

        "dummy_baseline":
            dummy_metrics,

        "rule_baseline":
            rule_metrics,
    }

    with open(
        model_out_path,
        "wb",
    ) as file:

        pickle.dump(
            artifact,
            file,
        )

    print(
        f"Final deployment model saved -> "
        f"{model_out_path}"
    )

    # ========================================================
    # Final concise summary
    # ========================================================

    print_section(
        "10. EXPERIMENT SUMMARY"
    )

    print(
        f"Dataset size           : {len(data)}"
    )

    print(
        f"Unique CVEs            : "
        f"{data['cve_id'].nunique()}"
    )

    print(
        f"Train/Test split       : "
        f"{len(X_train)}/{len(X_test)}"
    )

    print(
        f"Selected model         : {best_name}"
    )

    print(
        f"5-fold CV Macro-F1     : "
        f"{best_cv_score:.4f}"
    )

    best_test = model_test_results[
        best_name
    ]

    print(
        f"Held-out accuracy      : "
        f"{best_test['accuracy']:.4f}"
    )

    print(
        f"Held-out macro precision: "
        f"{best_test['precision_macro']:.4f}"
    )

    print(
        f"Held-out macro recall  : "
        f"{best_test['recall_macro']:.4f}"
    )

    print(
        f"Held-out macro F1      : "
        f"{best_test['f1_macro']:.4f}"
    )

    print(
        "\n[+] Training and evaluation completed."
    )


if __name__ == "__main__":
    main()
