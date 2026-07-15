"""
ai/model_registry.py
---------------------
Central registry for all trained ML models.
"""
import os, pickle

class ModelRegistry:

    MODELS = {
        "mitre_classifier":  "models/mitre_classifier.pkl",
        "risk_model":        "models/risk_model.pkl",
        "attack_path_model": "models/attack_path_model.pkl",
        "vectorizer":        "models/vectorizer.pkl",
        "label_encoder":     "models/label_encoder.pkl",
    }

    def load(self, name: str):
        path = self.MODELS.get(name)
        if not path or not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            return pickle.load(f)

    def available(self) -> list[str]:
        return [n for n, p in self.MODELS.items() if os.path.exists(p)]

    def status(self) -> dict:
        return {n: os.path.exists(p) for n, p in self.MODELS.items()}
