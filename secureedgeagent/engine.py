from __future__ import annotations

import math
import random
from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from secureedgeagent.config import AlgorithmConfig
from secureedgeagent.models import (
    CandidateEstimate,
    DecisionStatus,
    ExecutionPlan,
    NodeState,
    Task,
    Tier,
    clip,
)
from secureedgeagent.risk import RiskAnalyzer


class Strategy(str, Enum):
    DEVICE_ONLY = "device-only"
    EDGE_ONLY = "edge-only"
    CLOUD_ONLY = "cloud-only"
    RANDOM = "random-offloading"
    LATENCY_AWARE = "latency-aware"
    ENERGY_AWARE = "energy-aware"
    ACCURACY_AWARE = "accuracy-aware"
    CONVENTIONAL_MULTI_OBJECTIVE = "conventional-multi-objective"
    SECURITY_FILTERED = "security-filtered-heuristic"
    TRUST_AWARE = "trust-aware-offloading"
    WITHOUT_ADAPTATION = "secureedgeagent-without-adaptation"
    FULL = "full-secureedgeagent"


@dataclass(frozen=True, slots=True)
class StrategyOptions:
    restrict_tier: Tier | None = None
    random_selection: bool = False
    objective: str = "full"

    filter_risk: bool = False
    filter_trust: bool = False
    filter_privacy: bool = False
    filter_tools: bool = False
    filter_isolation: bool = False

    allow_hybrid: bool = False
    dynamic_trust: bool = False
    security_strength: float = 0.0


STRATEGY_OPTIONS: dict[Strategy, StrategyOptions] = {
    Strategy.DEVICE_ONLY: StrategyOptions(
        restrict_tier=Tier.DEVICE,
        objective="latency",
        security_strength=0.10,
    ),
    Strategy.EDGE_ONLY: StrategyOptions(
        restrict_tier=Tier.EDGE,
        objective="latency",
        security_strength=0.05,
    ),
    Strategy.CLOUD_ONLY: StrategyOptions(
        restrict_tier=Tier.CLOUD,
        objective="accuracy",
        security_strength=0.05,
    ),
    Strategy.RANDOM: StrategyOptions(
        random_selection=True,
        objective="random",
        security_strength=0.00,
    ),
    Strategy.LATENCY_AWARE: StrategyOptions(
        objective="latency",
        allow_hybrid=True,
        security_strength=0.05,
    ),
    Strategy.ENERGY_AWARE: StrategyOptions(
        objective="energy",
        allow_hybrid=True,
        security_strength=0.05,
    ),
    Strategy.ACCURACY_AWARE: StrategyOptions(
        objective="accuracy",
        allow_hybrid=True,
        security_strength=0.05,
    ),
    Strategy.CONVENTIONAL_MULTI_OBJECTIVE: StrategyOptions(
        objective="conventional",
        allow_hybrid=True,
        security_strength=0.10,
    ),
    Strategy.SECURITY_FILTERED: StrategyOptions(
        objective="full",
        filter_risk=True,
        filter_privacy=True,
        filter_tools=True,
        filter_isolation=True,
        allow_hybrid=True,
        security_strength=0.75,
    ),
    Strategy.TRUST_AWARE: StrategyOptions(
        objective="conventional",
        filter_trust=True,
        allow_hybrid=True,
        dynamic_trust=True,
        security_strength=0.65,
    ),
    Strategy.WITHOUT_ADAPTATION: StrategyOptions(
        objective="full",
        filter_risk=True,
        filter_trust=True,
        filter_privacy=True,
        filter_tools=True,
        filter_isolation=True,
        allow_hybrid=True,
        dynamic_trust=False,
        security_strength=0.88,
    ),
    Strategy.FULL: StrategyOptions(
        objective="full",
        filter_risk=True,
        filter_trust=True,
        filter_privacy=True,
        filter_tools=True,
        filter_isolation=True,
        allow_hybrid=True,
        dynamic_trust=True,
        security_strength=1.00,
    ),
}


class OffloadingEngine:
    """Two-stage security feasibility filtering and multi-objective selection."""

    def __init__(
        self,
        config: AlgorithmConfig,
        seed: int = 42,
    ) -> None:
        self.config = config
        self.risk = RiskAnalyzer(config)
        self.random = random.Random(seed)

    def select(
        self,
        task: Task,
        nodes: list[NodeState],
        strategy: Strategy = Strategy.FULL,
    ) -> ExecutionPlan:
        options = STRATEGY_OPTIONS[strategy]

        candidates = self._build_candidates(task, nodes, options)
        feasible = [candidate for candidate in candidates if candidate.feasible]

        if not feasible:
            return self._no_feasible_plan(task, strategy, candidates)

        weights = self._objective_weights(task, options.objective)

        if options.random_selection:
            selected = self.random.choice(feasible)
            selected.score = 0.0
        else:
            self._score_candidates(feasible, weights, options.objective)
            selected = min(
                feasible,
                key=lambda candidate: (
                    float("inf") if candidate.score is None else candidate.score
                ),
            )

        return ExecutionPlan(
            task_id=task.task_id,
            strategy=strategy.value,
            status=DecisionStatus.SELECTED,
            candidate_id=selected.candidate_id,
            tier=selected.tier,
            node_ids=selected.node_ids,
            partition=selected.partition,
            estimate=selected,
            objective_weights=weights,
            sandbox_policy={
                "process_isolation": True,
                "network_default_deny": True,
                "filesystem_read_only": True,
                "capability_allowlist": list(task.requested_tools),
                "maximum_execution_seconds": 30,
                "output_validation": True,
                "emergency_termination": True,
            },
            monitoring_policy={
                "log_tool_calls": True,
                "log_policy_events": True,
                "update_trust": options.dynamic_trust,
            },
        )

    def _build_candidates(
        self,
        task: Task,
        nodes: list[NodeState],
        options: StrategyOptions,
    ) -> list[CandidateEstimate]:
        candidates: list[CandidateEstimate] = []

        for node in nodes:
            if options.restrict_tier and node.tier != options.restrict_tier:
                continue

            estimate = self._estimate_single(task, node, fraction=1.0)
            self._apply_single_feasibility(task, node, estimate, options)
            candidates.append(estimate)

        if (
            options.allow_hybrid
            and options.restrict_tier is None
            and task.decomposable
        ):
            candidates.extend(self._hybrid_candidates(task, nodes, options))

        return candidates

    def _estimate_single(
        self,
        task: Task,
        node: NodeState,
        fraction: float,
    ) -> CandidateEstimate:
        fraction = max(0.0, min(1.0, fraction))
        compute = task.compute_demand * fraction

        input_mb = task.input_size_mb * fraction
        output_mb = task.output_size_mb * fraction

        if node.tier == Tier.DEVICE:
            upload_ms = 0.0
            download_ms = 0.0
            communication_mb = 0.0
        else:
            upload_ms = input_mb * 8.0 / max(node.uplink_mbps, 1e-6) * 1000.0
            download_ms = output_mb * 8.0 / max(node.downlink_mbps, 1e-6) * 1000.0
            communication_mb = input_mb + output_mb

        execution_ms = (
            compute / max(node.compute_capacity * node.efficiency, 1e-6) * 1000.0
        )

        security_ms = self.config.security_overhead_ms * (
            0.40 + 0.60 * self.risk.intrinsic_risk(task)
        )

        latency_ms = (
            upload_ms
            + node.queue_delay_ms
            + execution_ms
            + security_ms
            + download_ms
        )

        communication_seconds = (upload_ms + download_ms) / 1000.0
        energy_j = (
            node.energy_coefficient * compute
            + node.communication_power_w * communication_seconds
            + self.config.security_energy_j
        )

        service_cost = (
            node.service_cost * compute
            + 0.01 * communication_mb
            + 0.02 * len(task.requested_tools)
        )

        target_capability = max(task.required_quality, task.complexity())
        capability_gap = abs(node.model_capability - target_capability)
        utility = clip(
            node.model_capability
            - 0.35 * capability_gap
            - 0.08 * max(0.0, task.complexity() - node.model_capability)
        )

        execution_risk = self.risk.execution_risk(
            task=task,
            trust_score=node.trust_score,
            exposure=node.exposure,
            vulnerability=node.vulnerability,
        )

        return CandidateEstimate(
            candidate_id=node.node_id,
            tier=node.tier,
            node_ids=(node.node_id,),
            partition={node.node_id: 1.0},
            latency_ms=latency_ms,
            energy_j=energy_j,
            communication_mb=communication_mb,
            service_cost=service_cost,
            utility=utility,
            risk=execution_risk,
            effective_trust=node.trust_score,
            tool_node_id=node.node_id,
        )

    def _apply_single_feasibility(
        self,
        task: Task,
        node: NodeState,
        estimate: CandidateEstimate,
        options: StrategyOptions,
    ) -> None:
        reasons: list[str] = []

        if not node.available:
            reasons.append("node-unavailable")

        if task.compute_demand > node.compute_capacity:
            reasons.append("insufficient-compute")

        if task.memory_gb > node.memory_gb:
            reasons.append("insufficient-memory")

        if task.bandwidth_mbps > node.bandwidth_mbps:
            reasons.append("insufficient-bandwidth")

        if estimate.latency_ms > task.deadline_ms:
            reasons.append("deadline-infeasible")

        if options.filter_risk and estimate.risk > task.maximum_risk:
            reasons.append("execution-risk-threshold")

        if options.filter_trust and node.trust_score < task.minimum_trust:
            reasons.append("node-trust-threshold")

        if options.filter_privacy and task.sensitivity > node.maximum_sensitivity:
            reasons.append("privacy-placement-violation")

        if options.filter_tools:
            missing_tools = set(task.requested_tools) - node.authorized_tools
            if missing_tools:
                reasons.append(
                    "unauthorized-tools:" + ",".join(sorted(missing_tools))
                )

        if (
            options.filter_isolation
            and node.isolation_level < task.required_isolation
        ):
            reasons.append("insufficient-isolation")

        estimate.rejection_reasons = reasons
        estimate.feasible = not reasons

    def _hybrid_candidates(
        self,
        task: Task,
        nodes: list[NodeState],
        options: StrategyOptions,
    ) -> list[CandidateEstimate]:
        device = self._best_node(nodes, Tier.DEVICE)
        edge = self._best_node(nodes, Tier.EDGE)
        cloud = self._best_node(nodes, Tier.CLOUD)

        if not all((device, edge, cloud)):
            return []

        active_nodes = {
            Tier.DEVICE: device,
            Tier.EDGE: edge,
            Tier.CLOUD: cloud,
        }

        step = self.config.hybrid_partition_step
        points = [round(index * step, 6) for index in range(int(1 / step) + 1)]

        candidates: list[CandidateEstimate] = []

        for device_fraction in points:
            for edge_fraction in points:
                cloud_fraction = round(1.0 - device_fraction - edge_fraction, 6)

                if cloud_fraction < 0.0 or cloud_fraction > 1.0:
                    continue

                fractions = {
                    Tier.DEVICE: device_fraction,
                    Tier.EDGE: edge_fraction,
                    Tier.CLOUD: cloud_fraction,
                }

                if sum(value > 0.0 for value in fractions.values()) < 2:
                    continue

                if task.sensitivity >= 0.70 and device_fraction < step:
                    continue

                components: list[CandidateEstimate] = []
                for tier, fraction in fractions.items():
                    if fraction <= 0.0:
                        continue
                    components.append(
                        self._estimate_single(task, active_nodes[tier], fraction)
                    )

                estimate = self._aggregate_hybrid(
                    task,
                    active_nodes,
                    fractions,
                    components,
                )
                self._apply_hybrid_feasibility(
                    task,
                    active_nodes,
                    fractions,
                    estimate,
                    options,
                )
                candidates.append(estimate)

        return candidates

    def _aggregate_hybrid(
        self,
        task: Task,
        nodes: dict[Tier, NodeState],
        fractions: dict[Tier, float],
        components: list[CandidateEstimate],
    ) -> CandidateEstimate:
        active_count = len(components)

        latency_ms = (
            sum(component.latency_ms for component in components)
            + self.config.handoff_overhead_ms * max(0, active_count - 1)
        )
        energy_j = sum(component.energy_j for component in components)
        communication_mb = sum(
            component.communication_mb for component in components
        )
        service_cost = sum(component.service_cost for component in components)

        utility = clip(
            sum(
                component.utility
                * fractions[nodes_by_id(nodes)[component.node_ids[0]].tier]
                for component in components
            )
            + 0.03
        )

        effective_trust = sum(
            nodes[tier].trust_score * fraction
            for tier, fraction in fractions.items()
        )

        device_fraction = fractions[Tier.DEVICE]
        exposure = sum(
            nodes[tier].exposure
            * fraction
            * (1.0 - 0.80 * device_fraction if tier != Tier.DEVICE else 1.0)
            for tier, fraction in fractions.items()
        )

        vulnerability = sum(
            nodes[tier].vulnerability * fraction
            for tier, fraction in fractions.items()
        )

        risk = self.risk.execution_risk(
            task,
            trust_score=effective_trust,
            exposure=exposure,
            vulnerability=vulnerability,
        )

        tool_node = None
        for tier in (Tier.EDGE, Tier.CLOUD, Tier.DEVICE):
            if fractions[tier] > 0.0:
                tool_node = nodes[tier].node_id
                break

        partition = {
            nodes[tier].node_id: fraction
            for tier, fraction in fractions.items()
            if fraction > 0.0
        }

        identifier = "hybrid[" + ",".join(
            f"{tier.value}={fractions[tier]:.2f}"
            for tier in (Tier.DEVICE, Tier.EDGE, Tier.CLOUD)
        ) + "]"

        return CandidateEstimate(
            candidate_id=identifier,
            tier=Tier.HYBRID,
            node_ids=tuple(partition),
            partition=partition,
            latency_ms=latency_ms,
            energy_j=energy_j,
            communication_mb=communication_mb,
            service_cost=service_cost,
            utility=utility,
            risk=risk,
            effective_trust=effective_trust,
            tool_node_id=tool_node,
        )

    def _apply_hybrid_feasibility(
        self,
        task: Task,
        nodes: dict[Tier, NodeState],
        fractions: dict[Tier, float],
        estimate: CandidateEstimate,
        options: StrategyOptions,
    ) -> None:
        reasons: list[str] = []

        for tier, fraction in fractions.items():
            if fraction <= 0.0:
                continue

            node = nodes[tier]

            if not node.available:
                reasons.append(f"{node.node_id}:unavailable")

            if task.compute_demand * fraction > node.compute_capacity:
                reasons.append(f"{node.node_id}:compute")

            if task.memory_gb * fraction > node.memory_gb:
                reasons.append(f"{node.node_id}:memory")

            if task.bandwidth_mbps * fraction > node.bandwidth_mbps:
                reasons.append(f"{node.node_id}:bandwidth")

            if options.filter_trust and node.trust_score < task.minimum_trust:
                reasons.append(f"{node.node_id}:trust")

            if options.filter_isolation and (
                node.isolation_level < task.required_isolation
            ):
                reasons.append(f"{node.node_id}:isolation")

        if estimate.latency_ms > task.deadline_ms:
            reasons.append("deadline-infeasible")

        if options.filter_risk and estimate.risk > task.maximum_risk:
            reasons.append("execution-risk-threshold")

        device_fraction = fractions[Tier.DEVICE]
        sanitized_sensitivity = task.sensitivity * (1.0 - 0.80 * device_fraction)

        if options.filter_privacy:
            for tier in (Tier.EDGE, Tier.CLOUD):
                if (
                    fractions[tier] > 0.0
                    and sanitized_sensitivity > nodes[tier].maximum_sensitivity
                ):
                    reasons.append(f"{nodes[tier].node_id}:privacy")

        if options.filter_tools and task.requested_tools:
            tool_node = next(
                node
                for node in nodes.values()
                if node.node_id == estimate.tool_node_id
            )
            missing = set(task.requested_tools) - tool_node.authorized_tools
            if missing:
                reasons.append(
                    "unauthorized-tools:" + ",".join(sorted(missing))
                )

        estimate.rejection_reasons = sorted(set(reasons))
        estimate.feasible = not estimate.rejection_reasons

    @staticmethod
    def _best_node(
        nodes: Iterable[NodeState],
        tier: Tier,
    ) -> NodeState | None:
        tier_nodes = [
            node for node in nodes if node.tier == tier and node.available
        ]
        if not tier_nodes:
            return None

        return max(
            tier_nodes,
            key=lambda node: (
                node.trust_score,
                node.model_capability,
                node.compute_capacity,
            ),
        )

    def _objective_weights(
        self,
        task: Task,
        objective: str,
    ) -> dict[str, float]:
        if objective == "latency":
            return {
                "latency": 1.0,
                "energy": 0.0,
                "communication": 0.0,
                "utility": 0.0,
                "risk": 0.0,
            }

        if objective == "energy":
            return {
                "latency": 0.0,
                "energy": 1.0,
                "communication": 0.0,
                "utility": 0.0,
                "risk": 0.0,
            }

        if objective == "accuracy":
            return {
                "latency": 0.0,
                "energy": 0.0,
                "communication": 0.0,
                "utility": 1.0,
                "risk": 0.0,
            }

        if objective == "conventional":
            return {
                "latency": 0.35,
                "energy": 0.20,
                "communication": 0.15,
                "utility": 0.30,
                "risk": 0.0,
            }

        weights = dict(self.config.objective_weights)

        if not self.config.dynamic_objective_weights:
            return normalize_weights(weights)

        intrinsic_risk = self.risk.intrinsic_risk(task)
        complexity = task.complexity()

        if task.deadline_ms <= 500:
            weights["latency"] += 0.10

        if task.metadata.get("energy_constrained", False):
            weights["energy"] += 0.10

        if complexity >= 0.70:
            weights["utility"] += 0.10

        if task.sensitivity >= 0.70 or intrinsic_risk >= 0.60:
            weights["risk"] += 0.12

        return normalize_weights(weights)

    def _score_candidates(
        self,
        candidates: list[CandidateEstimate],
        weights: dict[str, float],
        objective: str,
    ) -> None:
        latency_values = [item.latency_ms for item in candidates]
        energy_values = [item.energy_j for item in candidates]
        communication_values = [
            item.communication_mb + item.service_cost for item in candidates
        ]
        utility_values = [item.utility for item in candidates]
        risk_values = [item.risk for item in candidates]

        for candidate in candidates:
            latency = minmax(candidate.latency_ms, latency_values)
            energy = minmax(candidate.energy_j, energy_values)
            communication = minmax(
                candidate.communication_mb + candidate.service_cost,
                communication_values,
            )
            utility = minmax(candidate.utility, utility_values)
            risk = minmax(candidate.risk, risk_values)

            candidate.score = (
                weights["latency"] * latency
                + weights["energy"] * energy
                + weights["communication"] * communication
                - weights["utility"] * utility
                + weights["risk"] * risk
            )

            if objective == "accuracy":
                candidate.score = -candidate.utility

    def _no_feasible_plan(
        self,
        task: Task,
        strategy: Strategy,
        candidates: list[CandidateEstimate],
    ) -> ExecutionPlan:
        intrinsic = self.risk.intrinsic_risk(task)

        if intrinsic >= 0.75:
            status = DecisionStatus.REJECTED
        elif intrinsic >= 0.50:
            status = DecisionStatus.HUMAN_ESCALATION
        elif task.sensitivity >= 0.70:
            status = DecisionStatus.SANITIZE_REQUIRED
        else:
            status = DecisionStatus.DELAYED

        reasons = sorted(
            {
                reason
                for candidate in candidates
                for reason in candidate.rejection_reasons
            }
        )

        return ExecutionPlan(
            task_id=task.task_id,
            strategy=strategy.value,
            status=status,
            rejection_reasons=reasons or ["no-candidate-generated"],
        )


def nodes_by_id(nodes: dict[Tier, NodeState]) -> dict[str, NodeState]:
    return {node.node_id: node for node in nodes.values()}


def minmax(value: float, values: list[float], epsilon: float = 1e-9) -> float:
    minimum = min(values)
    maximum = max(values)

    if math.isclose(minimum, maximum, abs_tol=epsilon):
        return 0.0

    return (value - minimum) / (maximum - minimum + epsilon)


def normalize_weights(weights: dict[str, float]) -> dict[str, float]:
    positive = {key: max(0.0, value) for key, value in weights.items()}
    total = sum(positive.values())

    if total <= 0.0:
        raise ValueError("At least one objective weight must be positive.")

    return {key: value / total for key, value in positive.items()}
