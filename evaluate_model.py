"""
evaluate_model.py
===================
Loads the model trained by train_model.py and evaluates it on the
held-out test split: macro F1, precision, recall, per-class report,
confusion matrix, and feature importance.

Run:
    python evaluate_model.py --models-dir models --out reports
"""

import argparse
import json

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


def main():
    parser = argparse.ArgumentParser(description="Evaluate the trained assessment-objective model")
    parser.add_argument("--models-dir", type=str, default="models")
    parser.add_argument("--out", type=str, default="reports")
    args = parser.parse_args()

    model = joblib.load(f"{args.models_dir}/trained_model.pkl")
    label_encoder = joblib.load(f"{args.models_dir}/label_encoder.pkl")
    metadata = joblib.load(f"{args.models_dir}/model_metadata.pkl")
    feature_names = metadata["feature_names"]
    model_name = metadata["best_model_name"]

    split = np.load(f"{args.models_dir}/test_split.npz")
    X_test, y_test = split["X_test"], split["y_test"]

    y_pred = model.predict(X_test)
    class_names = label_encoder.classes_

    macro_f1 = f1_score(y_test, y_pred, average="macro")
    macro_precision = precision_score(y_test, y_pred, average="macro")
    macro_recall = recall_score(y_test, y_pred, average="macro")

    report = classification_report(
        y_test, y_pred, target_names=class_names, output_dict=True
    )

    print(f"Model: {model_name}")
    print(f"Macro F1:        {macro_f1:.4f}")
    print(f"Macro Precision: {macro_precision:.4f}")
    print(f"Macro Recall:    {macro_recall:.4f}\n")
    print(classification_report(y_test, y_pred, target_names=class_names))

    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(10, 9))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=class_names)
    disp.plot(ax=ax, xticks_rotation=45, cmap="Blues", colorbar=False)
    plt.title(f"Confusion Matrix — {model_name}")
    plt.tight_layout()
    plt.savefig(f"{args.out}/confusion_matrix.png", dpi=150)
    plt.close(fig)

    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        order = np.argsort(importances)[::-1]
        top_n = min(20, len(feature_names))
        fig, ax = plt.subplots(figsize=(9, 7))
        ax.barh(
            [feature_names[i] for i in order[:top_n]][::-1],
            [importances[i] for i in order[:top_n]][::-1],
            color="#3b6ea5",
        )
        ax.set_xlabel("Importance")
        ax.set_title(f"Top {top_n} Feature Importances — {model_name}")
        plt.tight_layout()
        plt.savefig(f"{args.out}/feature_importance.png", dpi=150)
        plt.close(fig)
        importance_table = sorted(
            zip(feature_names, importances.tolist()), key=lambda x: -x[1]
        )
    else:
        importance_table = []

    summary = {
        "model_name": model_name,
        "macro_f1": macro_f1,
        "macro_precision": macro_precision,
        "macro_recall": macro_recall,
        "per_class_report": report,
        "feature_importance": importance_table,
    }
    with open(f"{args.out}/evaluation_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\nSaved: {args.out}/confusion_matrix.png")
    print(f"Saved: {args.out}/feature_importance.png")
    print(f"Saved: {args.out}/evaluation_summary.json")


if __name__ == "__main__":
    main()
