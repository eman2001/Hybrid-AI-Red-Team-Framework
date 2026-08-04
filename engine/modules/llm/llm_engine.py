"""
llm_engine.py
--------------
Thin client for talking to a local Ollama instance (Qwen2.5).

Responsibility: take a prompt string -> return generated text.
This module knows NOTHING about JSON findings, PDF layout, or report
structure. That separation is intentional — swap the model or the
backend here without touching any other file.
"""

import os
import logging

import requests

logger = logging.getLogger(__name__)

OLLAMA_HOST      = os.getenv("OLLAMA_HOST", "http://192.168.56.1:11434")
OLLAMA_MODEL     = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
REQUEST_TIMEOUT  = int(os.getenv("LLM_TIMEOUT", "60"))


class LLMEngine:

    def __init__(self, host: str = None, model: str = None, timeout: int = None):
        self.host    = host or OLLAMA_HOST
        self.model   = model or OLLAMA_MODEL
        self.timeout = timeout or REQUEST_TIMEOUT
        self._available = None  # cached after first successful/failed call

    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        """Quick health check — does Ollama have the model loaded?"""
        try:
            r = requests.get(f"{self.host}/api/tags", timeout=5)
            r.raise_for_status()
            models = [m.get("name", "") for m in r.json().get("models", [])]
            ok = any(self.model.split(":")[0] in m for m in models)
            if not ok:
                logger.warning(
                    "[LLM] Model '%s' not found in Ollama. Available models: %s",
                    self.model, models
                )
            self._available = ok
            return ok
        except Exception as e:
            logger.warning("[LLM] Ollama unreachable at %s (%s)", self.host, e)
            self._available = False
            return False

    # ------------------------------------------------------------------
    def generate(
        self,
        prompt: str,
        system: str = None,
        temperature: float = 0.3,
        max_tokens: int = 500,
    ) -> str:
        """Send one prompt to Ollama and return the generated text.
        Never raises — falls back to a safe placeholder on any failure
        so a down/missing LLM can never crash the pipeline."""

        if not prompt or not prompt.strip():
            return ""

        payload = {
            "model":  self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict":  max_tokens,
            },
        }
        if system:
            payload["system"] = system

        try:
            resp = requests.post(f"{self.host}/api/generate", json=payload, timeout=self.timeout)
            resp.raise_for_status()
            text = resp.json().get("response", "").strip()
            if text:
                self._available = True
                return text
            logger.warning("[LLM] Ollama returned an empty response.")

        except requests.exceptions.ConnectionError:
            logger.warning(
                "[LLM] Could not connect to Ollama at %s. Is `ollama serve` running?",
                self.host,
            )
        except requests.exceptions.Timeout:
            logger.warning("[LLM] Ollama request timed out after %ss.", self.timeout)
        except Exception as e:
            logger.warning("[LLM] Ollama generation failed: %s", e)

        self._available = False
        return self._fallback(prompt)

    # ------------------------------------------------------------------
    @staticmethod
    def _fallback(prompt: str) -> str:
        """Used only when Ollama is unreachable, so the report is still
        generated (with a clear placeholder) instead of crashing."""
        return (
            "[AI narrative unavailable - could not reach the local LLM "
            "(Ollama / Qwen2.5). The rule-based findings in this report "
            "remain fully valid; only this narrative text is missing. "
            "Run `ollama serve` and `ollama run qwen2.5:3b` and retry.]"
        )
