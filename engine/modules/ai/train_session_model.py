"""
Run: python -m engine.modules.ai.train_session_model
"""
import csv
from sklearn.model_selection import train_test_split

from engine.modules.ai.session_model_trainer import SessionModelTrainer
from engine.modules.ai.session_model_evaluator import SessionModelEvaluator


def main(dataset_path="data/training_data.csv",
         model_path="engine/models/session_action_model.pkl"):

    with open(dataset_path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    print(f"[*] Loaded {len(rows)} rows from {dataset_path}")

    train_rows, test_rows = train_test_split(
        rows, test_size=0.2, random_state=42,
        stratify=[r["label"] for r in rows],
    )

    trainer = SessionModelTrainer()
    bundle = trainer.train(train_rows)

    SessionModelEvaluator().evaluate(bundle, test_rows)

    trainer.save(bundle, model_path)


if __name__ == "__main__":
    main()
