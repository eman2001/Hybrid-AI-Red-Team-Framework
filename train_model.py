import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import accuracy_score, classification_report
import pickle
from pathlib import Path

data = pd.read_csv("training_data.csv")
data["exploit_type"] = data["exploit_type"].map({
    "metasploit": 3,
    "hydra": 2,
    "web": 1,
    "manual": 0
})
data["priority_label"] = data["priority_label"].map({
    "high": 2,
    "medium": 1,
    "low": 0
})

X = data[["cvss_score", "exploit_type", "port"]]
y = data["priority_label"]

# Honest hold-out split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Shallow tree -- guards against overfitting on a 50-row dataset
model = DecisionTreeClassifier(max_depth=4, min_samples_leaf=2, random_state=42)

# 5-fold cross-validation on the training portion
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(model, X_train, y_train, cv=cv)
print(f"Cross-validation accuracy: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")
print(f"Per-fold scores: {[round(s, 3) for s in cv_scores]}")

# Fit on train split, evaluate on held-out test set
model.fit(X_train, y_train)
test_preds = model.predict(X_test)
test_acc = accuracy_score(y_test, test_preds)
print(f"\nHeld-out test accuracy: {test_acc:.3f}")
print("\nClassification report (test set):")
print(classification_report(y_test, test_preds, target_names=["low", "medium", "high"], zero_division=0))

# Final model trained on the full dataset for deployment
final_model = DecisionTreeClassifier(max_depth=4, min_samples_leaf=2, random_state=42)
final_model.fit(X, y)

MODEL_PATH = Path(__file__).resolve().parent / "engine" / "models" / "exploit_model.pkl"
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

with open(MODEL_PATH, "wb") as f:
    pickle.dump(final_model, f)

print(f"\nFinal model saved to: {MODEL_PATH}")
