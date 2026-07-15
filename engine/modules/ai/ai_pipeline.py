"""
ai/ai_pipeline.py
------------------
AIPipeline — يجمع كل وظائف الذكاء الاصطناعي في مكان واحد.
"""
from engine.modules.ai.mitre_predictor       import MitrePredictor
from engine.modules.ai.adversary_similarity  import AdversarySimilarity
from engine.modules.ai.recommendation_engine import RecommendationEngine
from engine.modules.ai.explainable_ai        import ExplainableAI

class AIPipeline:

    def __init__(self):
        self.predictor       = MitrePredictor()
        self.adversary       = AdversarySimilarity()
        self.recommender     = RecommendationEngine()
        self.xai             = ExplainableAI()

    def enrich_findings(self, mapped_results: list, attack_chain: dict) -> dict:

        recommendations = []
        adversary_match = []
        explanations    = []

        # جمع التكتيكات من نتائج MITRE
        tactics = []
        technique_ids = []
        for result in mapped_results:
            for layer in result.get("layers", []):
                tactic = layer.get("tactic", "")
                tid    = layer.get("technique_id", "")
                if tactic and tactic not in tactics:
                    tactics.append(tactic)
                if tid and not tid.startswith("T-"):
                    technique_ids.append(tid)

        # توصيات بناءً على التكتيكات
        recommendations = self.recommender.recommend(tactics)

        for result in mapped_results:
            ctx = {'exploit': result.get('exploit',''), 'service': result.get('service',''), 'cve': result.get('cve',''), 'edb_title': result.get('edb_title','')}
            ml_pred = self.predictor.predict(ctx)
            if ml_pred:
                result['ai_tactic'] = ml_pred.get('tactic','')
                result['ai_confidence'] = ml_pred.get('confidence', 0.0)

        # مقارنة مع مجموعات هاكرز معروفة
        if technique_ids:
            adversary_match = self.adversary.score(technique_ids)

        # شرح القرارات
        for result in mapped_results:
            ctx = {
                "cve":       result.get("cve", ""),
                "service":   result.get("service", ""),
                "edb_title": result.get("edb_title", ""),
                "product":   result.get("product", ""),
            }
            prediction = ""
            confidence = 0.0
            for layer in result.get("layers", []):
                if layer.get("source") == "rule":
                    prediction = layer.get("tactic", "")
                    confidence = layer.get("confidence", 0.0)
                    break
            if prediction:
                explanation = self.xai.explain(ctx, prediction, confidence)
                explanations.append(explanation)

        return {
            "recommendations": recommendations,
            "adversary_match": adversary_match,
            "explanations":    explanations,
        }
