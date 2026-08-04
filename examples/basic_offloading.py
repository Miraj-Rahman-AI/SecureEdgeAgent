from secureedgeagent import (
    AlgorithmConfig,
    OffloadingEngine,
    SecurityClass,
    Strategy,
    Task,
    load_nodes,
)


def main() -> None:
    config = AlgorithmConfig.from_yaml("configs/algorithm.yaml")
    nodes = load_nodes("configs/tiers.yaml")

    task = Task(
        task_id="example-task",
        category="privacy-sensitive-reasoning",
        security_class=SecurityClass.POLICY_SENSITIVE,
        input_size_mb=1.2,
        output_size_mb=0.1,
        compute_demand=4.0,
        memory_gb=2.0,
        bandwidth_mbps=10.0,
        deadline_ms=900.0,
        required_quality=0.82,
        sensitivity=0.86,
        requested_tools=("database_read",),
        reasoning_score=0.70,
        context_score=0.75,
        tool_score=0.50,
        multimodal_score=0.10,
        malicious_intent=0.05,
        injection_probability=0.10,
        adversarial_input=0.05,
        tool_risk=0.25,
        minimum_trust=0.70,
        maximum_risk=0.40,
        required_isolation=2,
        decomposable=True,
    )

    engine = OffloadingEngine(config)
    plan = engine.select(task, nodes, strategy=Strategy.FULL)

    print("Status:", plan.status.value)
    print("Candidate:", plan.candidate_id)
    print("Partition:", plan.partition)

    if plan.estimate:
        print("Latency:", round(plan.estimate.latency_ms, 3), "ms")
        print("Risk:", round(plan.estimate.risk, 4))
        print("Utility:", round(plan.estimate.utility, 4))
        print("Score:", round(plan.estimate.score or 0.0, 4))


if __name__ == "__main__":
    main()
