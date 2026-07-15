"""
stix_resolver.py  —  Layer 2: STIX Semantic Keyword Lookup
Confidence: 0.60 – 0.75

Builds an inverted keyword index from enterprise-attack.json.
If the file is missing, auto-downloads from MITRE CTI on first use.
"""

import json
import os
import re
from collections import defaultdict

STIX_PATH = "data/enterprise-attack.json"
STIX_URL  = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


class StixResolver:

    def __init__(self):
        self._index: dict[str, list[dict]] = defaultdict(list)   # word → [technique, …]
        self._loaded = False
        self._load()

    # ── Public ────────────────────────────────────────────────────────

    def resolve(self, context: dict) -> dict | None:
        if not self._loaded:
            return None

        text = self._context_to_text(context)
        if not text:
            return None

        scores: dict[str, float] = defaultdict(float)
        hits:   dict[str, dict]  = {}

        for word in self._tokenize(text):
            for tech in self._index.get(word, []):
                tid = tech["technique_id"]
                scores[tid] += tech["idf"]
                hits[tid]    = tech

        if not scores:
            return None

        best_id = max(scores, key=lambda k: scores[k])
        best    = hits[best_id]

        # Normalise score → 0.60–0.75 confidence band
        raw_score  = scores[best_id]
        confidence = min(0.75, 0.60 + raw_score * 0.02)

        return {
            "technique_id":   best["technique_id"],
            "technique_name": best["technique_name"],
            "tactic":         best["tactic"],
            "confidence":     round(confidence, 3),
            "source":         "stix",
        }

    # ── Internal ──────────────────────────────────────────────────────

    def _load(self):
        path = self._ensure_file()
        if not path:
            print("  [STIX] enterprise-attack.json not available — layer 2 disabled.")
            return

        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)

            techniques = [
                obj for obj in data.get("objects", [])
                if obj.get("type") == "attack-pattern"
                and not obj.get("revoked", False)
                and not obj.get("x_mitre_deprecated", False)
            ]

            # Build index
            all_words: dict[str, int] = defaultdict(int)  # word → doc_freq

            tech_docs: list[tuple[dict, set]] = []
            for obj in techniques:
                tid   = next((r["external_id"] for r in obj.get("external_references", [])
                               if r.get("source_name") == "mitre-attack" and
                               r.get("external_id", "").startswith("T")), None)
                if not tid:
                    continue

                tactic_phases = obj.get("kill_chain_phases", [])
                tactic = tactic_phases[0]["phase_name"] if tactic_phases else "unknown"

                combined = f"{obj.get('name', '')} {obj.get('description', '')}"
                words    = set(self._tokenize(combined))

                for w in words:
                    all_words[w] += 1

                tech_docs.append(({
                    "technique_id":   tid,
                    "technique_name": obj.get("name", ""),
                    "tactic":         tactic,
                }, words))

            n_docs = len(tech_docs)
            import math
            for tech_info, words in tech_docs:
                for w in words:
                    idf = math.log(n_docs / (1 + all_words[w]))
                    self._index[w].append({**tech_info, "idf": idf})

            self._loaded = True
            print(f"  [STIX] Loaded {len(tech_docs)} techniques → index built.")

        except Exception as e:
            print(f"  [STIX] Failed to load: {e}")

    def _ensure_file(self) -> str | None:
        if os.path.exists(STIX_PATH):
            return STIX_PATH

        os.makedirs(os.path.dirname(STIX_PATH), exist_ok=True)
        print(f"  [STIX] enterprise-attack.json not found — downloading from MITRE CTI...")

        try:
            import urllib.request
            urllib.request.urlretrieve(STIX_URL, STIX_PATH)
            print(f"  [STIX] Downloaded → {STIX_PATH}")
            return STIX_PATH
        except Exception as e:
            print(f"  [STIX] Download failed: {e}")
            print(f"  [STIX] Manually place enterprise-attack.json in data/")
            return None

    @staticmethod
    def _context_to_text(ctx: dict) -> str:
        parts = [
            ctx.get("exploit", ""),
            ctx.get("service", ""),
            ctx.get("cve", ""),
            ctx.get("edb_title", ""),
            ctx.get("product", ""),
            ctx.get("version", ""),
        ]
        return " ".join(p for p in parts if p)

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        text = text.lower()
        text = re.sub(r"[/_\-\.0-9]", " ", text)
        words = text.split()
        stopwords = {"the", "a", "an", "and", "or", "of", "to", "in", "for",
                     "on", "with", "via", "from", "by", "at", "is", "this",
                     "that", "be", "are", "was", "as", "it", "its", "used"}
        return [w for w in words if len(w) > 2 and w not in stopwords]
