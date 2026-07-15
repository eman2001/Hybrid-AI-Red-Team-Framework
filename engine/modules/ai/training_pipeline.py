"""
ai/training_pipeline.py
------------------------
End-to-end training pipeline: load data → features → train → evaluate → save.
"""
import os

class TrainingPipeline:

    def run(self, dataset_path: str = "data/training_dataset.csv",
            model_dir: str = "models"):
        import csv
        from engine.modules.ai.model_trainer   import ModelTrainer
        from engine.modules.ai.model_evaluator import ModelEvaluator

        if not os.path.exists(dataset_path):
            print(f"  [Pipeline] Dataset not found: {dataset_path}")
            return None

        rows = []
        with open(dataset_path, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

        if len(rows) < 10:
            print(f"  [Pipeline] Too few samples ({len(rows)}) — need ≥10.")
            return None

        trainer = ModelTrainer()
        model   = trainer.train(rows)
        evaluator = ModelEvaluator()
        metrics = evaluator.evaluate(model, rows)

        os.makedirs(model_dir, exist_ok=True)
        trainer.save(model, os.path.join(model_dir, "mitre_classifier.pkl"))
        print(f"  [Pipeline] Done. Accuracy: {metrics.get('accuracy', 0):.2%}")
        return model
