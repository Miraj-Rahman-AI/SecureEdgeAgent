from collections import Counter

import pytest

from secureedgeagent.config import AlgorithmConfig
from secureedgeagent.engine import OffloadingEngine, Strategy
from secureedgeagent.models import (
    AttackType,
    NodeState,
    SecurityClass,
    Task,
    Tier,
    TrustEvidence,
)
from secureedgeagent.risk import RiskAnalyzer
from secureedgeagent.trust import TrustManager
from secureedgeagent.workload import generate_workload


@pytest.fixture
def config() -> AlgorithmConfig:
    return AlgorithmConfig(dynamic_objective_weights=False)


@pytest.fixture
def task() -> Task:
    return Task(
        task_id="test-task",
        category="tool-based-action-execution",
        security_class=SecurityClass.POLICY_SENSITIVE,
        input_size_mb=0.1,
        output_size_mb=0.02,
        compute_demand=2.0,
        memory_gb=1.0,
        bandwidth_mbps=2.0,
        deadline_ms=1000.0,
        required_quality=0.75,
        sensitivity=0.75,
        requested_tools=("send_notification",),
        reasoning_score=0.7,
        context_score=0.6,
        tool_score=0.8,
        multimodal_score=0.1,
        malicious_intent=0.1,
        injection_probability=0.1,
        adversarial_input=0.1,
        tool_risk=0.3,
        minimum_trust=0.7,
        maximum_risk=0.4,
        required_isolation=2,
        decomposable=True,
        attack_type=AttackType.NONE,
    )


def make_node(
    node_id: str,
    tier: Tier,
    trust: float,
    tools: set[str],
    sensitivity: float = 1.0,
) -> NodeState:
    return NodeState(
        node_id=node_id,
        tier=tier,
        model_name="test-model",
        compute_capacity=20.0,
        memory_gb=16.0,
        bandwidth_mbps=100.0,
        uplink_mbps=100.0,
        downlink_mbps=100.0,
        queue_delay_ms=1.0,
        model_capability=0.8,
        efficiency=0.9,
        trust_score=trust,
        energy_coefficient=0.1,
        communication_power_w=0.2,
        service_cost=0.01,
        exposure=0.1,
        vulnerability=0.05,
        isolation_level=3,
        maximum_sensitivity=sensitivity,
        authorized_tools=tools,
    )


def test_intrinsic_risk_is_bounded(
    config: AlgorithmConfig,
    task: Task,
) -> None:
    risk = RiskAnalyzer(config).intrinsic_risk(task)
    assert 0.0 <= risk <= 1.0


def test_incident_reduces_trust(config: AlgorithmConfig) -> None:
    node = make_node("edge", Tier.EDGE, 0.9, {"send_notification"})
    manager = TrustManager(config)

    before = node.trust_score
    manager.update(
        node,
        TrustEvidence(
            integrity=0.2,
            availability=0.8,
            historical_behavior=0.4,
            policy_compliance=0.1,
            security_monitoring=0.2,
        ),
        incident_penalty=0.1,
    )

    assert node.trust_score < before


def test_full_strategy_rejects_unauthorized_tool(
    config: AlgorithmConfig,
    task: Task,
) -> None:
    node = make_node("edge", Tier.EDGE, 0.9, set())
    engine = OffloadingEngine(config)

    plan = engine.select(task, [node], Strategy.FULL)

    assert not plan.selected
    assert any(
        "unauthorized-tools" in reason
        for reason in plan.rejection_reasons
    )


def test_full_strategy_avoids_low_trust_node(
    config: AlgorithmConfig,
    task: Task,
) -> None:
    low_trust = make_node(
        "edge-low-trust",
        Tier.EDGE,
        0.3,
        {"send_notification"},
    )
    trusted = make_node(
        "edge-trusted",
        Tier.EDGE,
        0.9,
        {"send_notification"},
    )

    engine = OffloadingEngine(config)
    plan = engine.select(
        task,
        [low_trust, trusted],
        Strategy.FULL,
    )

    assert plan.selected
    assert plan.candidate_id == "edge-trusted"


def test_evaluation_workload_distribution() -> None:
    tasks = generate_workload("evaluation", seed=42)

    assert len(tasks) == 3000

    categories = Counter(task.category for task in tasks)
    assert set(categories.values()) == {500}

    security = Counter(task.security_class for task in tasks)
    assert security[SecurityClass.BENIGN] == 900
    assert security[SecurityClass.POLICY_SENSITIVE] == 500
    assert security[SecurityClass.ADVERSARIAL] == 1600

    attacks = Counter(
        task.attack_type
        for task in tasks
        if task.security_class == SecurityClass.ADVERSARIAL
    )
    assert set(attacks.values()) == {200}


def test_complete_workload_contains_12000_tasks() -> None:
    train = generate_workload("train", seed=42)
    validation = generate_workload("validation", seed=42)
    evaluation = generate_workload("evaluation", seed=42)

    assert len(train) == 7200
    assert len(validation) == 1800
    assert len(evaluation) == 3000
    assert len(train) + len(validation) + len(evaluation) == 12000
