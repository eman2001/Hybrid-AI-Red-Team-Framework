"""
ai/assessment_predictor.py
-----------------------------
Wraps the trained Assessment-Objective classifier for single-sample
"what's the next recommended assessment step" prediction. Mirrors
mitre_predictor.py's pattern exactly.

READ-ONLY / classification-only: returns a text recommendation +
confidence. Does not send any command to any session, tool, or target.
"""
import os
import joblib


class AssessmentPredictor:
    def __init__(
        self,
        model_path: str = "models/trained_model.pkl",
        ohe_path: str = "models/one_hot_encoder.pkl",
        le_path: str = "models/label_encoder.pkl",
    ):
        self._model = None
        self._ohe = None
        self._le = None
        if os.path.exists(model_path) and os.path.exists(ohe_path) and os.path.exists(le_path):
            self._model = joblib.load(model_path)
            self._ohe = joblib.load(ohe_path)
            self._le = joblib.load(le_path)

    def predict(self, context: dict) -> dict | None:
        if self._model is None:
            return None

        from feature_engineering import build_feature_matrix
        import pandas as pd

        df = pd.DataFrame([context])
        X, _, _, _, _ = build_feature_matrix(df, one_hot_encoder=self._ohe, label_encoder=self._le)

        idx = self._model.predict(X)[0]
        label = self._le.inverse_transform([idx])[0]

        confidence = None
        if hasattr(self._model, "predict_proba"):
            confidence = round(float(self._model.predict_proba(X)[0].max()), 3)

        return {"recommendation": label, "confidence": confidence, "source": "ml"}
