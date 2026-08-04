from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from secureedgeagent.models import NodeState, Tier


@dataclass(slots=True)
class AlgorithmConfig:
    complexity_weights: dict[str, float] = field(
        default_factory=lambda: {
            "reasoning": 0.30,
            "context": 0.30,
            "tool": 0.20,
            "multimodal": 0.20,
        }
    )

    risk_weights: dict[str, float] = field(
        default_factory=lambda: {
            "malicious_intent": 0.25,
            "prompt_injection": 0.25,
            "adversarial_input": 0.15,
            "sensitivity": 0.20,
            "tool_risk": 0.15,
        }
    )

    execution_risk_weights: dict[str, float] = field(
        default_factory=lambda: {
            "task_risk": 0.40,
            "trust_deficit": 0.25,
            "exposure": 0.20,
            "vulnerability": 0.15,
        }
    )

    trust_weights: dict[str, float] = field(
        default_factory=lambda: {
            "integrity": 0.25,
            "availability": 0.15,
            "historical_behavior": 0.20,
            "policy_compliance": 0.20,
            "security_monitoring": 0.20,
        }
    )

    objective_weights: dict[str, float] = field(
        default_factory=lambda: {
            "latency": 0.25,
            "energy": 0.15,
            "communication": 0.10,
            "utility": 0.20,
            "risk": 0.30,
        }
    )

    trust_smoothing: float = 0.80
    default_minimum_trust: float = 0.60
    default_maximum_risk: float = 0.40
    normalization_epsilon: float = 1e-9

    security_overhead_ms: float = 8.5
    security_energy_j: float = 0.05
    handoff_overhead_ms: float = 6.0

    hybrid_partition_step: float = 0.25
    dynamic_objective_weights: bool = True

    @classmethod
    def from_yaml(cls, path: str | Path) -> "AlgorithmConfig":
        with Path(path).open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}

        return cls(
            complexity_weights=data.get("complexity_weights", cls().complexity_weights),
            risk_weights=data.get("risk_weights", cls().risk_weights),
            execution_risk_weights=data.get(
                "execution_risk_weights", cls().execution_risk_weights
            ),
            trust_weights=data.get("trust_weights", cls().trust_weights),
            objective_weights=data.get("objective_weights", cls().objective_weights),
            trust_smoothing=float(data.get("trust_smoothing", 0.80)),
            default_minimum_trust=float(data.get("default_minimum_trust", 0.60)),
            default_maximum_risk=float(data.get("default_maximum_risk", 0.40)),
            normalization_epsilon=float(data.get("normalization_epsilon", 1e-9)),
            security_overhead_ms=float(data.get("security_overhead_ms", 8.5)),
            security_energy_j=float(data.get("security_energy_j", 0.05)),
            handoff_overhead_ms=float(data.get("handoff_overhead_ms", 6.0)),
            hybrid_partition_step=float(data.get("hybrid_partition_step", 0.25)),
            dynamic_objective_weights=bool(
                data.get("dynamic_objective_weights", True)
            ),
        )


def load_yaml(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def load_nodes(path: str | Path) -> list[NodeState]:
    data = load_yaml(path)
    nodes: list[NodeState] = []

    for item in data.get("nodes", []):
        nodes.append(
            NodeState(
                node_id=str(item["node_id"]),
                tier=Tier(item["tier"]),
                model_name=str(item["model_name"]),
                compute_capacity=float(item["compute_capacity"]),
                memory_gb=float(item["memory_gb"]),
                bandwidth_mbps=float(item["bandwidth_mbps"]),
                uplink_mbps=float(item["uplink_mbps"]),
                downlink_mbps=float(item["downlink_mbps"]),
                queue_delay_ms=float(item["queue_delay_ms"]),
                model_capability=float(item["model_capability"]),
                efficiency=float(item["efficiency"]),
                trust_score=float(item["trust_score"]),
                energy_coefficient=float(item["energy_coefficient"]),
                communication_power_w=float(item["communication_power_w"]),
                service_cost=float(item["service_cost"]),
                exposure=float(item["exposure"]),
                vulnerability=float(item["vulnerability"]),
                isolation_level=int(item["isolation_level"]),
                maximum_sensitivity=float(item["maximum_sensitivity"]),
                authorized_tools=set(item.get("authorized_tools", [])),
                available=bool(item.get("available", True)),
                compromised=bool(item.get("compromised", False)),
                metadata=dict(item.get("metadata", {})),
            )
        )

    if not nodes:
        raise ValueError(f"No execution nodes were found in {path}")

    return nodes
