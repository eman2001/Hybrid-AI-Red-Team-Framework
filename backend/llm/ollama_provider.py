import requests

from backend.llm.provider import LLMProvider


class OllamaProvider(LLMProvider):

    def __init__(
        self,
        model="llama3.1"
    ):
        self.model = model


    def generate(self, prompt: str):

        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False
            }
        )

        data = response.json()

        return data.get(
            "response",
            ""
        )
