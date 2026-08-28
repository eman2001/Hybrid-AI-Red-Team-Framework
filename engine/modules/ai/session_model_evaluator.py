"""
ai/session_model_evaluator.py
--------------------------------
Evaluates a trained session-action-recommender bundle on a dataset.
"""
class SessionModelEvaluator:

    def evaluate(self, bundle: dict, rows: list[dict]) -> dict:
        from engine.modules.ai.session_feature_engineering import SessionFeatureEngineering
        from sklearn.metrics import accuracy_score, f1_score, classification_report

        fe = SessionFeatureEngineering()
        X = fe.transform_many(rows)
        true = [r["label"] for r in rows]

        pred = bundle["label_encoder"].inverse_transform(bundle["model"].predict(X))

        acc = accuracy_score(true, pred)
        macro_f1 = f1_score(true, pred, average="macro")
        print(f"  [SessionEvaluator] Accuracy: {acc:.2%}")
        print(f"  [SessionEvaluator] Macro-F1: {macro_f1:.4f}")
        print(classification_report(true, pred, zero_division=0))
        return {"accuracy": acc, "macro_f1": macro_f1}
