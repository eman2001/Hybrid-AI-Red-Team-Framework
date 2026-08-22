"""
mitre_engine.py  —  Hybrid 3-Layer MITRE ATT&CK Engine

Layer 0  CVE enricher     — CVE/CWE evidence-based mapping
Layer 1  rule_resolver    — deterministic, confidence 0.85–0.95
Layer 2  stix_resolver    — semantic keyword search, confidence 0.60–0.75
Layer 3  ml_classifier    — TF-IDF + RandomForest / fallback

Important design rule:
Strong deterministic evidence has priority.
STIX semantic results are treated as supporting evidence and are not allowed
to introduce an unrelated tactic when a stronger rule/CVE mapping exists.
"""

import json
import os
from datetime import datetime

from engine.modules.mitre.cve_enricher import CVEEnricher
from engine.modules.mitre.rule_resolver import RuleResolver
from engine.modules.mitre.stix_resolver import StixResolver
from engine.modules.mitre.ml_classifier import MLClassifier
from engine.modules.mitre.confidence_fusion import ConfidenceFusion
from engine.modules.mitre.chain_builder import ChainBuilder
from engine.modules.mitre.heatmap_generator import HeatmapGenerator


class MitreEngine:

    def __init__(self, verbose: bool = True):
        self.verbose = verbose

        print(
            "\n[MITRE Engine] Initialising "
            "hybrid ATT&CK classifier..."
        )

        self.cve_enricher = CVEEnricher()
        self.rule_resolver = RuleResolver()
        self.stix_resolver = StixResolver()
        self.ml_classifier = MLClassifier()

        self.confidence_fusion = ConfidenceFusion()
        self.chain_builder = ChainBuilder()
        self.heatmap_gen = HeatmapGenerator()

        print("[MITRE Engine] Ready.\n")

    # ------------------------------------------------------------------
    # Public mapping interface
    # ------------------------------------------------------------------

    def map_all(
        self,
        exploit_results: list[dict],
        post_commands: list[str] | None = None,
    ) -> list[dict]:

        print(
            f"[MITRE Engine] Classifying "
            f"{len(exploit_results)} result(s)..."
        )

        all_mapped = []

        for result in exploit_results:

            cmds = (
                post_commands or []
            ) if result.get("success", False) else []

            context = self._build_context(
                result,
                cmds,
            )

            mapped = self._classify(
                context
            )

            result["mitre"] = mapped["primary"]
            result["layers"] = mapped["layers"]
            result["attack_chain"] = None

            all_mapped.append(
                result
            )

            self._print_result(
                result
            )

        # --------------------------------------------------------------
        # Post-exploitation commands
        # --------------------------------------------------------------

        if post_commands:

            post_techs = (
                self.rule_resolver
                .resolve_post_commands(post_commands)
            )

            for tech in post_techs:

                all_mapped.append(
                    {
                        "host": (
                            all_mapped[0]["host"]
                            if all_mapped
                            else ""
                        ),
                        "port": 0,
                        "exploit": "post_exploit_session",
                        "success": True,
                        "mitre": tech,
                        "layers": [tech],
                        "attack_chain": None,
                        "_is_post": True,
                    }
                )

        return all_mapped

    # ------------------------------------------------------------------
    # Attack chain / heatmap
    # ------------------------------------------------------------------

    def build_chain(
        self,
        mapped_results: list[dict],
    ) -> dict:

        return self.chain_builder.build(
            mapped_results
        )

    def save_heatmap(
        self,
        mapped_results: list[dict],
        path: str,
    ):

        layer = self.heatmap_gen.generate(
            mapped_results
        )

        self.heatmap_gen.save(
            layer,
            path,
        )

        return layer

    def save_chain(
        self,
        chain: dict,
        path: str,
    ):

        directory = (
            os.path.dirname(path)
            if os.path.dirname(path)
            else "."
        )

        os.makedirs(
            directory,
            exist_ok=True,
        )

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as f:

            json.dump(
                {
                    "generated": datetime.now().isoformat(),
                    "framework": "MITRE ATT&CK v14",
                    "attack_chain": chain,
                },
                f,
                indent=2,
                ensure_ascii=False,
            )

        print(
            f"  [Chain] Saved → {path}"
        )

    def map_techniques(
        self,
        exploit_results: list[dict],
    ) -> list[dict]:

        return self.map_all(
            exploit_results
        )

    # ------------------------------------------------------------------
    # Internal classification
    # ------------------------------------------------------------------

    def _classify(
        self,
        context: dict,
    ) -> dict:

        layers: list[dict] = []

        # --------------------------------------------------------------
        # Layer 0 — CVE/CWE evidence
        # --------------------------------------------------------------

        r0 = self.cve_enricher.resolve(
            context
        )

        if r0:
            layers.append(
                r0
            )

        # --------------------------------------------------------------
        # Layer 1 — deterministic rule mapping
        # --------------------------------------------------------------

        r1 = self.rule_resolver.resolve(
            context
        )

        if r1:
            layers.append(
                r1
            )

        # Identify strongest deterministic evidence.
        deterministic = None

        if r0 and float(r0.get("confidence", 0.0)) >= 0.80:
            deterministic = r0

        if r1 and float(r1.get("confidence", 0.0)) >= 0.80:

            if (
                deterministic is None
                or float(r1.get("confidence", 0.0))
                > float(deterministic.get("confidence", 0.0))
            ):
                deterministic = r1

        # --------------------------------------------------------------
        # Layer 2 — STIX semantic mapping
        # --------------------------------------------------------------

        r2 = self.stix_resolver.resolve(
            context
        )

        if r2:

            stix_conf = float(
                r2.get(
                    "confidence",
                    0.0,
                )
            )

            # STIX must have a reasonable minimum confidence.
            stix_confident = (
                stix_conf >= 0.70
            )

            # If strong deterministic evidence exists,
            # STIX may support it only when the tactic agrees.
            if deterministic:

                deterministic_tactic = (
                    str(
                        deterministic.get(
                            "tactic",
                            ""
                        )
                    )
                    .strip()
                    .lower()
                )

                stix_tactic = (
                    str(
                        r2.get(
                            "tactic",
                            ""
                        )
                    )
                    .strip()
                    .lower()
                )

                same_tactic = (
                    deterministic_tactic
                    and stix_tactic
                    and deterministic_tactic == stix_tactic
                )

                same_technique = (
                    r2.get("technique_id")
                    == deterministic.get("technique_id")
                )

                if (
                    stix_confident
                    and (
                        same_tactic
                        or same_technique
                    )
                ):
                    r2["validation_status"] = (
                        "supporting_semantic_evidence"
                    )

                    layers.append(
                        r2
                    )

                else:
                    if self.verbose:
                        print(
                            "  [MITRE] Rejected STIX alternative: "
                            f"{r2.get('technique_id', '?')} "
                            f"{r2.get('technique_name', '?')} "
                            f"({r2.get('tactic', '?')}) "
                            "— inconsistent with stronger "
                            "deterministic evidence."
                        )

            # No strong rule/CVE mapping exists:
            # STIX may contribute if confidence is sufficient.
            elif stix_confident:

                r2["validation_status"] = (
                    "semantic_candidate"
                )

                layers.append(
                    r2
                )

        # --------------------------------------------------------------
        # Layer 3 — ML classifier
        # --------------------------------------------------------------

        r3 = self.ml_classifier.predict(
            context
        )

        if r3:

            ml_conf = float(
                r3.get(
                    "confidence",
                    0.0,
                )
            )

            # A keyword fallback must not override a strong rule.
            is_ml_fallback = (
                r3.get("source")
                == "ml_fallback"
            )

            if deterministic:

                ml_tactic = (
                    str(
                        r3.get(
                            "tactic",
                            ""
                        )
                    )
                    .strip()
                    .lower()
                )

                deterministic_tactic = (
                    str(
                        deterministic.get(
                            "tactic",
                            ""
                        )
                    )
                    .strip()
                    .lower()
                )

                if (
                    ml_conf >= 0.60
                    and ml_tactic
                    and ml_tactic == deterministic_tactic
                ):

                    r3["validation_status"] = (
                        "supporting_ml_evidence"
                    )

                    layers.append(
                        r3
                    )

                elif self.verbose and not is_ml_fallback:

                    print(
                        "  [MITRE] ML alternative ignored — "
                        "not consistent with stronger "
                        "deterministic evidence."
                    )

            else:

                if ml_conf >= 0.60:

                    r3["validation_status"] = (
                        "ml_candidate"
                    )

                    layers.append(
                        r3
                    )

        # --------------------------------------------------------------
        # Confidence fusion
        # --------------------------------------------------------------

        if layers:

            primary = (
                self.confidence_fusion
                .fuse(layers)
            )

        else:

            # Do NOT invent T1190 when no resolver has evidence.
            primary = {
                "technique_id": "N/A",
                "technique_name": "Unmapped",
                "tactic": "unknown",
                "confidence": 0.0,
                "source": "none",
                "validation_status": "no_supported_mapping",
            }

        return {
            "primary": primary,
            "layers": layers,
        }

    # ------------------------------------------------------------------
    # Context builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_context(
        result: dict,
        post_commands: list[str],
    ) -> dict:

        return {
            "exploit": result.get(
                "exploit",
                "",
            ),

            "service": result.get(
                "service",
                "",
            ),

            "cve": result.get(
                "cve",
                "",
            ),

            "edb_title": result.get(
                "edb_title",
                "",
            ),

            "product": result.get(
                "product",
                "",
            ),

            "version": result.get(
                "version",
                "",
            ),

            "host": result.get(
                "host",
                "",
            ),

            "port": result.get(
                "port",
                0,
            ),

            "post_commands": post_commands,

            "success": result.get(
                "success",
                False,
            ),

            # Evidence-quality metadata when available
            "match_confidence": result.get(
                "match_confidence",
                0.0,
            ),

            "validation_status": result.get(
                "validation_status",
                "",
            ),
        }

    # ------------------------------------------------------------------
    # Console output
    # ------------------------------------------------------------------

    def _print_result(
        self,
        result: dict,
    ):

        if not self.verbose:
            return

        p = result.get(
            "mitre",
            {},
        )

        layers = result.get(
            "layers",
            [],
        )

        print(
            f"  [+] "
            f"{result.get('host')}:{result.get('port')}  "
            f"→  [{p.get('source', '?')}]  "
            f"{p.get('tactic', '?')}  |  "
            f"{p.get('technique_id', '?')} "
            f"{p.get('technique_name', '?')}  "
            f"(conf={p.get('confidence', 0):.0%})"
        )

        # Print alternative supporting evidence only.
        for layer in layers:

            if (
                layer.get("technique_id")
                == p.get("technique_id")
                and layer.get("source")
                == p.get("source")
            ):
                continue

            print(
                f"       └ alt "
                f"[{layer.get('source', '?')}] "
                f"{layer.get('technique_id', '?')} "
                f"{layer.get('technique_name', '?')} "
                f"({layer.get('confidence', 0):.0%})"
            )
