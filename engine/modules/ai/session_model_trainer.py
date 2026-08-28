"""
ai/session_model_trainer.py
------------------------------
XGBoost trainer for the session-action recommender
(10-class next-best-action classifier for post-exploitation sessions).
"""
import pickle, os


class SessionModelTrainer:

    def train(self, rows: list[dict]):
        from xgboost import XGBClassifier
        from sklearn.preprocessing import LabelEncoder
        from engine.modules.ai.session_feature_engineering import SessionFeatureEngineering

        fe = SessionFeatureEngineering()
        X = fe.transform_many(rows)
        labels = [r["label"] for r in rows]

        le = LabelEncoder()
        y = le.fit_transform(labels)

        clf = XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            random_state=42,
            eval_metric="mlogloss",
        )
        clf.fit(X, y)

        return {"model": clf, "label_encoder": le, "feature_names": fe.feature_names()}

    def save(self, bundle: dict, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(bundle, f)
        print(f"  [SessionTrainer] Model saved → {path}")
