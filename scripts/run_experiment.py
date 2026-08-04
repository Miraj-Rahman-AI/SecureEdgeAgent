from __future__ import annotations

import argparse
import copy
import csv
from pathlib import Path
from statistics import mean

from secureedgeagent.config import AlgorithmConfig, load_nodes
from secureedgeagent.engine import STRATEGY_OPTIONS, OffloadingEngine, Strategy
from secureedgeagent.execution import SecureExecutor, apply_feedback
from secureedgeagent.metrics import MetricAccumulator
from secureedgeagent.models import AttackType, TrustEvidence
from secureedgeagent.trust import TrustManager
from secureedgeagent.workload import load_jsonl


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run SecureEdgeAgent and baseline simulations."
    )
    parser.add_argument(
        "--workload",
        default="data/generated/evaluation.jsonl",
    )
    parser.add_argument(
        "--algorithm-config",
        default="configs/algorithm.yaml",
    )
    parser.add_argument(
        "--tier-config",
        default="configs/tiers.yaml",
    )
    parser.add_argument(
        "--output",
        default="results/generated/experiment_summary.csv",
    )
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--strategies",
        nargs="*",
        choices=[strategy.value for strategy in Strategy],
        default=None,
    )
    return parser.parse_args()


def run_once(
    strategy: Strategy,
    tasks,
    base_nodes,
    config: AlgorithmConfig,
    seed: int,
) -> dict[str, float]:
    nodes = copy.deepcopy(base_nodes)

    engine = OffloadingEngine(config, seed=seed)
    executor = SecureExecutor(seed=seed)
    trust_manager = TrustManager(config)
    metrics = MetricAccumulator()

    options = STRATEGY_OPTIONS[strategy]
    simulated_seconds = 0.0

    for task in tasks:
        edge_nodes = [node for node in nodes if node.tier.value == "edge"]

        for node in edge_nodes:
            node.compromised = False
            node.vulnerability = float(
                node.metadata.get("normal_vulnerability", node.vulnerability)
            )

        if (
            task.attack_type == AttackType.COMPROMISED_EDGE_NODE
            and edge_nodes
        ):
            target = edge_nodes[0]
            target.metadata.setdefault(
                "normal_vulnerability",
                target.vulnerability,
            )
            target.compromised = True
            target.vulnerability = 0.95

            if options.dynamic_trust:
                trust_manager.update(
                    target,
                    TrustEvidence(
                        integrity=0.15,
                        availability=0.80,
                        historical_behavior=0.40,
                        policy_compliance=0.10,
                        security_monitoring=0.20,
                    ),
                    incident_penalty=0.12,
                )

        plan = engine.select(task, nodes, strategy=strategy)
        result = executor.execute(task, plan, strategy, nodes)

        metrics.add(task, result)
        simulated_seconds += max(result.latency_ms / 1000.0, 0.001)

        if options.dynamic_trust:
            apply_feedback(nodes, plan, result, trust_manager)

    return metrics.finalize(simulated_seconds)


def average_runs(rows: list[dict[str, float]]) -> dict[str, float]:
    keys = rows[0].keys()
    return {
        key: mean(float(row[key]) for row in rows)
        for key in keys
    }


def main() -> None:
    args = parse_args()

    config = AlgorithmConfig.from_yaml(args.algorithm_config)
    nodes = load_nodes(args.tier_config)
    tasks = load_jsonl(args.workload)

    strategies = (
        [Strategy(value) for value in args.strategies]
        if args.strategies
        else list(Strategy)
    )

    output_rows: list[dict[str, float | str]] = []

    for strategy in strategies:
        run_rows = [
            run_once(
                strategy=strategy,
                tasks=tasks,
                base_nodes=nodes,
                config=config,
                seed=args.seed + run_index,
            )
            for run_index in range(args.runs)
        ]

        summary = average_runs(run_rows)
        output_rows.append({"strategy": strategy.value, **summary})

        print(
            f"{strategy.value:38s} "
            f"latency={summary['average_latency_ms']:.2f} ms, "
            f"STCR={summary['secure_completion_percent']:.2f}%, "
            f"ASR={summary['attack_success_percent']:.2f}%"
        )

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(output_rows[0].keys()))
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"\nGenerated results saved to {output}")
    print(
        "These are simulator-generated results and must not replace "
        "results/reported manuscript values."
    )


if __name__ == "__main__":
    main()
