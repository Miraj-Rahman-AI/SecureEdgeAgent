from __future__ import annotations

import copy
import json

from secureedgeagent.config import AlgorithmConfig, load_nodes
from secureedgeagent.engine import OffloadingEngine, Strategy
from secureedgeagent.models import SecurityClass, Task, Tier


def main() -> None:
    config = AlgorithmConfig.from_yaml("configs/algorithm.yaml")
    nodes = load_nodes("configs/tiers.yaml")

    nearest_edge = next(node for node in nodes if node.tier == Tier.EDGE)
    nearest_edge.node_id = "nearest-edge"
    nearest_edge.trust_score = 0.41

    alternative_edge = copy.deepcopy(nearest_edge)
    alternative_edge.node_id = "alternative-edge"
    alternative_edge.trust_score = 0.88
    alternative_edge.vulnerability = 0.08
    alternative_edge.queue_delay_ms = 12.0
    nodes.append(alternative_edge)

    cloud = next(node for node in nodes if node.tier == Tier.CLOUD)
    cloud.trust_score = 0.93

    task = Task(
        task_id="connected-vehicle-case-study",
        category="connected-vehicle-hazard-response",
        security_class=SecurityClass.POLICY_SENSITIVE,
        input_size_mb=0.50,
        output_size_mb=0.08,
        compute_demand=5.0,
        memory_gb=2.0,
        bandwidth_mbps=5.0,
        deadline_ms=650.0,
        required_quality=0.90,
        sensitivity=0.71,
        requested_tools=("send_notification",),
        reasoning_score=0.82,
        context_score=0.80,
        tool_score=0.78,
        multimodal_score=0.70,
        malicious_intent=0.40,
        injection_probability=0.35,
        adversarial_input=0.35,
        tool_risk=0.55,
        minimum_trust=0.70,
        maximum_risk=0.40,
        required_isolation=3,
        decomposable=True,
        metadata={
            "scenario": "sensor anomaly and emergency notification",
            "privacy_control": (
                "location generalization and identifier removal"
            ),
        },
    )

    engine = OffloadingEngine(config, seed=42)
    plan = engine.select(task, nodes, strategy=Strategy.FULL)

    output = {
        "task_id": plan.task_id,
        "status": plan.status.value,
        "candidate": plan.candidate_id,
        "tier": plan.tier.value if plan.tier else None,
        "nodes": list(plan.node_ids),
        "partition": plan.partition,
        "score": (
            plan.estimate.score
            if plan.estimate is not None
            else None
        ),
        "estimated_latency_ms": (
            plan.estimate.latency_ms
            if plan.estimate is not None
            else None
        ),
        "estimated_risk": (
            plan.estimate.risk
            if plan.estimate is not None
            else None
        ),
        "rejection_reasons": plan.rejection_reasons,
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
