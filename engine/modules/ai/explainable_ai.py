"""
ai/explainable_ai.py
---------------------
Provides human-readable explanations for ML predictions (XAI).
"""

class ExplainableAI:

    def explain(self, context: dict, prediction: dict) -> str:
        tactic = prediction.get("tactic", "unknown")
        conf   = prediction.get("confidence", 0)
        source = prediction.get("source", "ml")

        signals = []
        if context.get("cve"):
            signals.append(f"CVE {context['cve']}")
        if context.get("edb_title"):
            signals.append(f"exploit title '{context['edb_title'][:40]}'")
        if context.get("service"):
            signals.append(f"service '{context['service']}'")

        sig_str = ", ".join(signals) or "available context"
        return (f"Prediction '{tactic}' (confidence {conf:.0%}) via [{source}] "
                f"based on: {sig_str}.")
