from __future__ import annotations

from secureedgeagent.config import AlgorithmConfig
from secureedgeagent.models import NodeState, TrustEvidence, clip


class TrustManager:
    """Dynamic node-trust evaluation and incident-driven penalties."""

    def __init__(self, config: AlgorithmConfig) -> None:
        self.config = config

    def instantaneous_evidence(self, evidence: TrustEvidence) -> float:
        weights = self.config.trust_weights

        return clip(
            weights["integrity"] * evidence.integrity
            + weights["availability"] * evidence.availability
            + weights["historical_behavior"] * evidence.historical_behavior
            + weights["policy_compliance"] * evidence.policy_compliance
            + weights["security_monitoring"] * evidence.security_monitoring
        )

    def update(
        self,
        node: NodeState,
        evidence: TrustEvidence,
        incident_penalty: float = 0.0,
    ) -> float:
        instantaneous = self.instantaneous_evidence(evidence)
        eta = self.config.trust_smoothing

        updated = eta * node.trust_score + (1.0 - eta) * instantaneous
        updated = max(0.0, updated - max(0.0, incident_penalty))

        node.trust_score = clip(updated)
        return node.trust_score

    def apply_incident(self, node: NodeState, severity: float) -> float:
        node.trust_score = clip(node.trust_score - max(0.0, severity))
        return node.trust_score

    @staticmethod
    def classify(trust: float) -> str:
        if trust < 0.40:
            return "untrusted"
        if trust < 0.60:
            return "restricted"
        if trust < 0.85:
            return "trusted"
        return "highly-trusted"
