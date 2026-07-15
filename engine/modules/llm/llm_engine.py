"""
llm_engine.py
--------------
Core LLM interface for security report generation.
"""

import os


class LLMEngine:

    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "local")

    def generate(self, prompt: str) -> str:
        """
        Generate text from LLM.

        Currently fallback mode.
        Later connect:
        - Ollama
        - OpenAI API
        - Local models
        """

        if self.provider == "local":
            return self._local_response(prompt)

        return "LLM provider not configured"


    def _local_response(self, prompt: str) -> str:
        """
        Temporary intelligent template.
        """

        return f"""
Security Analysis Summary:

{prompt}

The assessment identified security weaknesses requiring immediate attention.
Recommended actions include patching vulnerable services, reducing attack
surface, enforcing secure configurations, and monitoring suspicious activity.
"""
