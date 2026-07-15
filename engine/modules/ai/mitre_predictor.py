"""
ai/mitre_predictor.py
----------------------
Wraps the trained classifier for single-sample MITRE tactic prediction.
"""
import pickle, os

class MitrePredictor:

    def __init__(self, model_path: str = "models/mitre_classifier.pkl"):
        self._bundle = None
        if os.path.exists(model_path):
            with open(model_path, "rb") as f:
                self._bundle = pickle.load(f)

    def predict(self, context: dict) -> dict | None:
        if not self._bundle:
            return None
        from engine.modules.ai.feature_engineering import FeatureEngineering
        text  = FeatureEngineering().transform_one(context)
        X     = self._bundle["vectorizer"].transform([text])
        idx   = self._bundle["model"].predict(X)[0]
        proba = self._bundle["model"].predict_proba(X)[0].max()
        label = self._bundle["label_encoder"].inverse_transform([idx])[0]
        return {"tactic": label, "confidence": round(float(proba), 3), "source": "ml"}
