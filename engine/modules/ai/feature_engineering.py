"""
ai/feature_engineering.py
--------------------------
Transforms raw finding dicts into ML-ready feature vectors.
"""
import re

class FeatureEngineering:

    def transform_one(self, ctx: dict) -> str:
        parts = [
            # بيانات MITRE الجديدة
            ctx.get("name", ""),
            ctx.get("description", ""),
            ctx.get("platforms", ""),
            ctx.get("technique_id", ""),
            # بيانات النظام القديمة
            ctx.get("exploit", ""),
            ctx.get("service", ""),
            ctx.get("cve", ""),
            ctx.get("edb_title", ""),
            ctx.get("product", ""),
            ctx.get("version", ""),
            " ".join(ctx.get("post_commands", [])),
        ]
        text = " ".join(p for p in parts if p)
        text = re.sub(r"[/_\-\.]", " ", text.lower())
        return text

    def transform_batch(self, contexts: list[dict]) -> list[str]:
        return [self.transform_one(c) for c in contexts]
