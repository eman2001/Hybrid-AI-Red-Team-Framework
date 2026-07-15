"""
ai/model_evaluator.py
----------------------
Evaluates a trained model bundle on a dataset.
"""

class ModelEvaluator:

    def evaluate(self, bundle: dict, rows: list[dict]) -> dict:
        from engine.modules.ai.feature_engineering import FeatureEngineering
        from sklearn.metrics import accuracy_score, classification_report

        fe    = FeatureEngineering()
        texts = [fe.transform_one(r) for r in rows]
        true  = [r["label"] for r in rows]

        X    = bundle["vectorizer"].transform(texts)
        pred = bundle["label_encoder"].inverse_transform(bundle["model"].predict(X))

        acc = accuracy_score(true, pred)
        print(f"  [Evaluator] Accuracy: {acc:.2%}")
        print(classification_report(true, pred, zero_division=0))
        return {"accuracy": acc}
