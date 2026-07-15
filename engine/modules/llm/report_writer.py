from engine.modules.llm.llm_engine import LLMEngine
from engine.modules.llm.prompts import *


class ReportWriter:

    def __init__(self):
        self.llm = LLMEngine()


    def executive_summary(
        self,
        target,
        findings,
        risk,
        mitre,
        chain
    ):

        prompt = EXECUTIVE_PROMPT.format(
            target=target,
            findings=findings,
            risk=risk,
            mitre=mitre,
            chain=chain
        )

        return self.llm.generate(prompt)



    def attack_story(
        self,
        findings,
        chain
    ):

        prompt = ATTACK_PROMPT.format(
            findings=findings,
            chain=chain
        )

        return self.llm.generate(prompt)



    def recommendations(
        self,
        findings,
        risk,
        mitre
    ):

        prompt = RECOMMENDATION_PROMPT.format(
            findings=findings,
            risk=risk,
            mitre=mitre
        )

        return self.llm.generate(prompt)
