"""
ai/session_action_recommender.py
-----------------------------------
Advisory next-best-action recommender for post-exploitation sessions.
Does NOT execute actions automatically — returns a ranked suggestion only.
"""
import pickle
from engine.modules.ai.session_feature_engineering import SessionFeatureEngineering

MODEL_PATH = "engine/models/session_action_model.pkl"


class SessionActionRecommender:

    def __init__(self, model_path=MODEL_PATH):
        self.fe = SessionFeatureEngineering()
        try:
            with open(model_path, "rb") as f:
                bundle = pickle.load(f)
            self.model = bundle["model"]
            self.label_encoder = bundle["label_encoder"]
            self.available = True
        except FileNotFoundError:
            self.available = False

    def recommend(self, session_state: dict) -> dict | None:
        if not self.available:
            return None
        x = [self.fe.transform_one(session_state)]
        pred_idx = self.model.predict(x)[0]
        proba = self.model.predict_proba(x)[0]
        label = self.label_encoder.inverse_transform([pred_idx])[0]
        confidence = float(max(proba))
        return {
            "suggested_next_step": label,
            "confidence": round(confidence, 4),
            "note": "Experimental advisory suggestion — not an executed action.",
        }
