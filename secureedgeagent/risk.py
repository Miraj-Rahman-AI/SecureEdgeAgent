from __future__ import annotations

from secureedgeagent.config import AlgorithmConfig
from secureedgeagent.models import Task, clip


class RiskAnalyzer:
    """Implements the manuscript's intrinsic and task-node execution risk models."""

    def __init__(self, config: AlgorithmConfig) -> None:
        self.config = config

    def intrinsic_risk(self, task: Task) -> float:
        weights = self.config.risk_weights

        value = (
            weights["malicious_intent"] * task.malicious_intent
            + weights["prompt_injection"] * task.injection_probability
            + weights["adversarial_input"] * task.adversarial_input
            + weights["sensitivity"] * task.sensitivity
            + weights["tool_risk"] * task.tool_risk
        )
        return clip(value)

    def execution_risk(
        self,
        task: Task,
        trust_score: float,
        exposure: float,
        vulnerability: float,
    ) -> float:
        weights = self.config.execution_risk_weights
        intrinsic = self.intrinsic_risk(task)

        value = (
            weights["task_risk"] * intrinsic
            + weights["trust_deficit"] * (1.0 - trust_score)
            + weights["exposure"] * task.sensitivity * exposure
            + weights["vulnerability"] * vulnerability
        )
        return clip(value)

    @staticmethod
    def risk_level(risk: float) -> str:
        if risk < 0.25:
            return "low"
        if risk < 0.50:
            return "moderate"
        if risk < 0.75:
            return "high"
        return "critical"
