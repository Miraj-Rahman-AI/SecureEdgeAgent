from __future__ import annotations

import random
from collections.abc import Callable
from typing import Any

from secureedgeagent.engine import STRATEGY_OPTIONS, Strategy
from secureedgeagent.models import (
    AttackType,
    DecisionStatus,
    ExecutionPlan,
    ExecutionResult,
    NodeState,
    SecurityClass,
    Task,
    TrustEvidence,
    clip,
)
from secureedgeagent.trust import TrustManager


ToolFunction = Callable[[dict[str, Any]], dict[str, Any]]


class ToolRegistry:
    """Allowlisted tool registry. It never executes arbitrary generated code."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolFunction] = {}

    def register(self, name: str, function: ToolFunction) -> None:
        if not name or not callable(function):
            raise ValueError("A tool requires a non-empty name and callable function.")
        self._tools[name] = function

    def contains(self, name: str) -> bool:
        return name in self._tools

    def call(self, name: str, payload: dict[str, Any]) -> dict[str, Any]:
        if name not in self._tools:
            raise PermissionError(f"Tool '{name}' is not registered.")

        result = self._tools[name](dict(payload))
        if not isinstance(result, dict):
            raise TypeError("Registered tools must return a dictionary.")

        return result


class SecureExecutor:
    """Deterministic experimental simulator with sandbox and policy events."""

    ATTACK_FACTORS = {
        AttackType.NONE: 0.0,
        AttackType.DIRECT_MALICIOUS_REQUEST: 0.90,
        AttackType.DIRECT_PROMPT_INJECTION: 1.00,
        AttackType.INDIRECT_PROMPT_INJECTION: 1.10,
        AttackType.UNAUTHORIZED_TOOL_INVOCATION: 0.85,
        AttackType.SENSITIVE_DATA_EXFILTRATION: 1.00,
        AttackType.ADVERSARIAL_CONTEXT_MANIPULATION: 0.95,
        AttackType.COMPROMISED_EDGE_NODE: 0.90,
        AttackType.RESOURCE_EXHAUSTION: 1.30,
    }

    def __init__(self, seed: int = 42) -> None:
        self.random = random.Random(seed)

    def execute(
        self,
        task: Task,
        plan: ExecutionPlan,
        strategy: Strategy,
        nodes: list[NodeState],
    ) -> ExecutionResult:
        options = STRATEGY_OPTIONS[strategy]

        if not plan.selected or plan.estimate is None:
            adversarial = task.security_class == SecurityClass.ADVERSARIAL

            return ExecutionResult(
                task_id=task.task_id,
                strategy=strategy.value,
                status=plan.status,
                correct=False,
                secure_completion=False,
                threat_detected=adversarial,
                attack_success=False,
                false_positive=not adversarial,
                privacy_leak=False,
                unauthorized_tool_execution=False,
                policy_violation=False,
                compromised_node_selected=False,
                latency_ms=0.0,
                energy_j=0.0,
                communication_mb=0.0,
                events=["automatic-execution-blocked"],
            )

        estimate = plan.estimate
        adversarial = task.security_class == SecurityClass.ADVERSARIAL

        correct_probability = clip(
            estimate.utility
            - 0.05 * adversarial
            - 0.03 * (estimate.latency_ms > task.deadline_ms)
        )
        correct = self.random.random() < correct_probability

        detection_probability = clip(
            0.40
            + 0.50 * options.security_strength
            + 0.10 * (1.0 - estimate.risk)
        )
        threat_detected = adversarial and (
            self.random.random() < detection_probability
        )

        attack_factor = self.ATTACK_FACTORS[task.attack_type]
        attack_probability = clip(
            estimate.risk
            * attack_factor
            * (1.0 - 0.78 * options.security_strength)
        )
        attack_success = adversarial and (
            self.random.random() < attack_probability
        )

        selected_nodes = {
            node.node_id: node
            for node in nodes
            if node.node_id in plan.node_ids
        }

        maximum_exposure = max(
            (node.exposure for node in selected_nodes.values()),
            default=0.0,
        )

        privacy_probability = clip(
            task.sensitivity
            * maximum_exposure
            * (1.0 - 0.88 * options.security_strength)
        )

        privacy_leak = (
            task.attack_type == AttackType.SENSITIVE_DATA_EXFILTRATION
            and attack_success
            and self.random.random() < privacy_probability
        )

        unauthorized_probability = clip(
            task.tool_risk
            * (1.0 - 0.90 * options.security_strength)
        )

        unauthorized_tool_execution = (
            task.attack_type == AttackType.UNAUTHORIZED_TOOL_INVOCATION
            and attack_success
            and self.random.random() < unauthorized_probability
        )

        compromised_node_selected = (
            task.attack_type == AttackType.COMPROMISED_EDGE_NODE
            and any(node.compromised for node in selected_nodes.values())
        )

        policy_violation = any(
            (
                attack_success,
                privacy_leak,
                unauthorized_tool_execution,
                compromised_node_selected,
            )
        )

        deadline_violation = estimate.latency_ms > task.deadline_ms

        false_positive_probability = 0.01 + 0.02 * options.security_strength
        false_positive = (
            not adversarial
            and self.random.random() < false_positive_probability
        )

        secure_completion = (
            correct
            and not deadline_violation
            and not policy_violation
            and not false_positive
        )

        events = [
            "sandbox-initialized",
            "permissions-checked",
            "runtime-monitoring-enabled",
        ]

        if threat_detected:
            events.append("threat-detected")
        if policy_violation:
            events.append("policy-violation")
        if secure_completion:
            events.append("validated-result-delivered")

        return ExecutionResult(
            task_id=task.task_id,
            strategy=strategy.value,
            status=DecisionStatus.SELECTED,
            correct=correct,
            secure_completion=secure_completion,
            threat_detected=threat_detected,
            attack_success=attack_success,
            false_positive=false_positive,
            privacy_leak=privacy_leak,
            unauthorized_tool_execution=unauthorized_tool_execution,
            policy_violation=policy_violation,
            compromised_node_selected=compromised_node_selected,
            latency_ms=estimate.latency_ms,
            energy_j=estimate.energy_j,
            communication_mb=estimate.communication_mb,
            node_ids=plan.node_ids,
            events=events,
        )


def apply_feedback(
    nodes: list[NodeState],
    plan: ExecutionPlan,
    result: ExecutionResult,
    trust_manager: TrustManager,
) -> None:
    """Feedback-driven trust adaptation after task execution."""

    if not plan.selected:
        return

    selected = {node.node_id: node for node in nodes if node.node_id in plan.node_ids}

    for node in selected.values():
        successful = result.secure_completion

        evidence = TrustEvidence(
            integrity=0.98 if successful else 0.35,
            availability=1.00 if node.available else 0.00,
            historical_behavior=0.95 if successful else 0.50,
            policy_compliance=1.00 if not result.policy_violation else 0.10,
            security_monitoring=0.95 if not result.attack_success else 0.25,
        )

        penalty = 0.0
        if result.attack_success:
            penalty += 0.15
        if result.privacy_leak:
            penalty += 0.10
        if result.unauthorized_tool_execution:
            penalty += 0.10
        if result.compromised_node_selected:
            penalty += 0.20

        trust_manager.update(node, evidence, incident_penalty=penalty)
