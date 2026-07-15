"""
mitre_engine.py  —  Hybrid 3-Layer MITRE ATT&CK Engine
Replaces the simple hardcoded MitreMapper with a production-grade system.

Layer 1  rule_resolver   — deterministic, confidence 0.85–0.95
Layer 2  stix_resolver   — semantic keyword search, confidence 0.60–0.75
Layer 3  ml_classifier   — TF-IDF + RandomForest,  confidence 0.50–0.70

Decision policy:
  - Layer 1 wins if confidence ≥ 0.85
  - Layer 2 used as fallback/enrichment
  - Layer 3 only overrides when conf > current best + 0.10
  - Post-exploit techniques always appended as extra evidence

Usage (replaces the old MitreMapper):
    from engine.modules.mitre import MitreEngine
    engine = MitreEngine()
    mapped = engine.map_all(exploit_results, post_commands=["hashdump","sysinfo"])
    chain  = engine.build_chain(mapped)
    engine.save_heatmap(mapped, "reports/attack_layer.json")
    engine.save_chain(chain,    "reports/attack_chain.json")
"""

import json
import os
from datetime import datetime

from engine.modules.mitre.rule_resolver    import RuleResolver
from engine.modules.mitre.stix_resolver    import StixResolver
from engine.modules.mitre.ml_classifier    import MLClassifier
from engine.modules.mitre.chain_builder    import ChainBuilder
from engine.modules.mitre.confidence_fusion import ConfidenceFusion
from engine.modules.mitre.ml_resolver       import MLResolver
from engine.modules.mitre.heatmap_generator import HeatmapGenerator


class MitreEngine:

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        print("\n[MITRE Engine] Initialising 3-layer hybrid classifier...")

        self.rule_resolver = RuleResolver()
        self.stix_resolver = StixResolver()
        self.ml_classifier     = MLClassifier()
        self.confidence_fusion = ConfidenceFusion()
        self.chain_builder = ChainBuilder()
        self.heatmap_gen   = HeatmapGenerator()

        print("[MITRE Engine] Ready.\n")

    # ── Primary interface ─────────────────────────────────────────────

    def map_all(self, exploit_results: list[dict],
                post_commands: list[str] | None = None) -> list[dict]:
        """
        Classify every exploit result through all three layers.

        Parameters
        ----------
        exploit_results : list of dicts from ExploiterModule / VulnMapper
        post_commands   : Meterpreter session commands (e.g. ["sysinfo", "hashdump"])

        Returns
        -------
        Enriched list — each item gains a "layers" key (list of technique dicts)
        and a "primary_mitre" key (the winning result).
        """
        print(f"[MITRE Engine] Classifying {len(exploit_results)} result(s)...")
        all_mapped = []

        for result in exploit_results:
            context = self._build_context(result, post_commands or [])
            mapped  = self._classify(context)

            result["mitre"]         = mapped["primary"]
            result["layers"]        = mapped["layers"]
            result["attack_chain"]  = None   # filled later by build_chain
            all_mapped.append(result)

            self._print_result(result)

        # Post-exploit enrichment (session-level, not per exploit)
        if post_commands:
            post_techs = self.rule_resolver.resolve_post_commands(post_commands)
            for tech in post_techs:
                all_mapped.append({
                    "host":          all_mapped[0]["host"] if all_mapped else "",
                    "port":          0,
                    "exploit":       "post_exploit_session",
                    "success":       True,
                    "mitre":         tech,
                    "layers":        [tech],
                    "attack_chain":  None,
                    "_is_post":      True,
                })

        return all_mapped

    def build_chain(self, mapped_results: list[dict]) -> dict:
        """Reconstruct kill-chain from mapped results."""
        return self.chain_builder.build(mapped_results)

    def save_heatmap(self, mapped_results: list[dict], path: str):
        layer = self.heatmap_gen.generate(mapped_results)
        self.heatmap_gen.save(layer, path)
        return layer

    def save_chain(self, chain: dict, path: str):
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "generated":    datetime.now().isoformat(),
                "framework":    "MITRE ATT&CK v14",
                "attack_chain": chain,
            }, f, indent=2, ensure_ascii=False)
        print(f"  [Chain] Saved → {path}")

    # ── Drop-in replacement for old MitreMapper.map_techniques() ─────

    def map_techniques(self, exploit_results: list[dict]) -> list[dict]:
        """Backward-compatible wrapper (same signature as old MitreMapper)."""
        return self.map_all(exploit_results)

    # ── Classification logic ──────────────────────────────────────────

    def _classify(self, context: dict) -> dict:
        layers = []

        # Layer 1
        r1 = self.rule_resolver.resolve(context)
        if r1:
            layers.append(r1)

        # Layer 2
        r2 = self.stix_resolver.resolve(context)
        if r2:
            layers.append(r2)

        # Layer 3
        r3 = self.ml_classifier.predict(context)
        if r3:
            layers.append(r3)

        # ConfidenceFusion — weighted vote across all layers
        if layers:
            primary = self.confidence_fusion.fuse(layers)
        else:
            primary = {
                "technique_id":   "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic":         "initial-access",
                "confidence":     0.50,
                "source":         "default",
            }

        return {"primary": primary, "layers": layers}

    @staticmethod
    def _pick_best(r1, r2, r3) -> dict:
        """
        Confidence weighting:
          Rule = 0.85–0.95  (always wins above 0.85)
          STIX = 0.60–0.75  (fallback)
          ML   = 0.50–0.70  (only wins if > current + 0.10)
        """
        best = None

        for candidate in [r1, r2, r3]:
            if candidate is None:
                continue
            if best is None:
                best = candidate
                continue
            diff = candidate["confidence"] - best["confidence"]
            if diff > 0.10:
                best = candidate

        return best or {
            "technique_id":   "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic":         "initial-access",
            "confidence":     0.50,
            "source":         "default",
        }

    @staticmethod
    def _build_context(result: dict, post_commands: list[str]) -> dict:
        return {
            "exploit":       result.get("exploit", ""),
            "service":       result.get("service", ""),
            "cve":           result.get("cve", ""),
            "edb_title":     result.get("edb_title", ""),
            "product":       result.get("product", ""),
            "version":       result.get("version", ""),
            "host":          result.get("host", ""),
            "port":          result.get("port", 0),
            "post_commands": post_commands,
        }

    def _print_result(self, result: dict):
        if not self.verbose:
            return
        p  = result.get("mitre", {})
        ls = result.get("layers", [])
        print(f"  [+] {result.get('host')}:{result.get('port')}  "
              f"→  [{p.get('source','?')}]  "
              f"{p.get('tactic','?')}  |  "
              f"{p.get('technique_id','?')} {p.get('technique_name','?')}  "
              f"(conf={p.get('confidence',0):.0%})")
        if len(ls) > 1:
            for l in ls[1:]:
                print(f"       └ alt [{l.get('source','?')}] "
                      f"{l.get('technique_id','?')} "
                      f"{l.get('technique_name','?')} "
                      f"({l.get('confidence',0):.0%})")
