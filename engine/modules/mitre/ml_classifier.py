"""
ml_classifier.py  —  Layer 3: TF-IDF + RandomForest MITRE Classifier
Confidence: 0.50 – 0.70

Loads the trained model from models/mitre_classifier.pkl if it exists.
Falls back to a lightweight in-memory rule approximation if not.
"""

import os
import pickle
import re

MODEL_PATH = "models/mitre_classifier.pkl"

# ── Lightweight fallback (no model file needed) ───────────────────────
FALLBACK_KEYWORDS = [
    (["vsftpd", "backdoor", "irc", "unreal", "distcc", "drupal", "struts",
      "joomla", "phishing", "smtp"],                   "initial-access",        0.67),
    (["smb", "samba", "eternalblue", "ms17", "rdp", "bluekeep", "psexec",
      "lateral", "pivot"],                             "lateral-movement",      0.67),
    (["brute", "hydra", "credential", "password", "hashdump", "ntlm", "dump"],
                                                       "credential-access",     0.67),
    (["getsystem", "privesc", "sudo", "privilege", "escalat", "local exploit"],
                                                       "privilege-escalation",  0.65),
    (["sysinfo", "getuid", "discovery", "enum", "arp", "route", "ps ",
      "netstat", "whoami"],                            "discovery",             0.65),
    (["meterpreter", "shell", "powershell", "cmd", "exec", "interpreter",
      "bash", "jenkins"],                              "execution",             0.64),
    (["persist", "cron", "registry", "startup", "autorun", "scheduled"],
                                                       "persistence",           0.63),
    (["exfil", "upload", "c2", "transfer", "download all"],
                                                       "exfiltration",          0.62),
    (["ransomware", "encrypt", "wiper", "destroy"],    "impact",                0.65),
]


class MLClassifier:

    def __init__(self):
        self._model    = None
        self._fe       = None
        self._ready    = False
        self._fallback = True
        self._le       = None
        self._load()

    def predict(self, context: dict) -> dict | None:
        text = self._context_text(context)
        if not text:
            return None

        if self._ready:
            return self._model_predict(text, context)
        else:
            return self._fallback_predict(text)

    # ── Internal ──────────────────────────────────────────────────────

    def _load(self):
        if not os.path.exists(MODEL_PATH):
            print(f"  [ML] No model at {MODEL_PATH} — fallback keyword mode active.")
            print(f"       Run:  python train_mitre_model.py   to train the classifier.")
            return

        try:
            with open(MODEL_PATH, "rb") as f:
                bundle = pickle.load(f)

            self._model    = bundle["model"]
            self._fe       = bundle.get("feature_engineer") or bundle.get("vectorizer")
            self._ready    = True
            self._fallback = False
            self._le       = bundle.get("label_encoder")
            print(f"  [ML] Classifier loaded from {MODEL_PATH}.")
        except Exception as e:
            print(f"  [ML] Failed to load model: {e} — fallback active.")

    def _model_predict(self, text: str, context: dict) -> dict | None:
        try:
            if hasattr(self._fe, "transform_one"):
                X = self._fe.transform_one(context)
            else:
                X = self._fe.transform([text])

            pred   = self._model.predict(X)[0]
            if hasattr(self._model, 'predict_proba'):
                proba = self._model.predict_proba(X)[0]
                conf  = float(proba.max())
            elif hasattr(self._model, 'decision_function'):
                scores = self._model.decision_function(X)[0]
                scores = scores - scores.min()
                conf   = float(scores.max() / (scores.sum() + 1e-9))
                conf   = min(0.70, max(0.50, conf))
            else:
                conf = 0.60
            if getattr(self, "_le", None) is not None:
                try:
                    label = self._le.inverse_transform([pred])[0]
                except Exception:
                    label = self._le.inverse_transform([int(pred)])[0]
            else:
                label = str(pred)

            return {
                "technique_id":   "T-ML",
                "technique_name": f"ML predicted: {label}",
                "tactic":         label,
                "confidence":     round(min(0.70, max(0.50, conf)), 3),
                "source":         "ml",
            }
        except Exception as e:
            print(f"  [ML] Prediction error: {e}")
            return self._fallback_predict(text)

    def _fallback_predict(self, text: str) -> dict | None:
        text_lower = text.lower()
        text_lower = re.sub(r"[/_\-]", " ", text_lower)

        best_tactic = None
        best_conf   = 0.0
        best_count  = 0

        for keywords, tactic, base_conf in FALLBACK_KEYWORDS:
            count = sum(1 for kw in keywords if kw in text_lower)
            if count > best_count or (count == best_count and base_conf > best_conf):
                best_count  = count
                best_tactic = tactic
                best_conf   = base_conf

        if best_tactic and best_count > 0:
            conf = min(0.70, best_conf + best_count * 0.02)
            return {
                "technique_id":   "T-KW",
                "technique_name": f"Keyword inferred: {best_tactic}",
                "tactic":         best_tactic,
                "confidence":     round(conf, 3),
                "source":         "ml_fallback",
            }
        return None

    @staticmethod
    def _context_text(ctx: dict) -> str:
        parts = [
            ctx.get("exploit", ""),
            ctx.get("service", ""),
            ctx.get("cve", ""),
            ctx.get("edb_title", ""),
            " ".join(ctx.get("post_commands", [])),
        ]
        return " ".join(p for p in parts if p)
