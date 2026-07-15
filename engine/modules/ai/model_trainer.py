"""
ai/model_trainer.py
--------------------
TF-IDF + RandomForest trainer for MITRE tactic classification.
"""
import pickle, os

class ModelTrainer:

    def train(self, rows: list[dict]):
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import LabelEncoder
        from engine.modules.ai.feature_engineering import FeatureEngineering

        fe     = FeatureEngineering()
        texts  = [fe.transform_one(r) for r in rows]
        labels = [r["label"] for r in rows]

        le  = LabelEncoder()
        y   = le.fit_transform(labels)
        vec = TfidfVectorizer(max_features=500, ngram_range=(1,2))
        X   = vec.fit_transform(texts)

        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X, y)

        return {"model": clf, "vectorizer": vec, "label_encoder": le}

    def save(self, bundle: dict, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(bundle, f)
        print(f"  [Trainer] Model saved → {path}")
