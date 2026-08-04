from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Tier(str, Enum):
    DEVICE = "device"
    EDGE = "edge"
    CLOUD = "cloud"
    HYBRID = "hybrid"


class SecurityClass(str, Enum):
    BENIGN = "benign"
    POLICY_SENSITIVE = "policy-sensitive"
    ADVERSARIAL = "adversarial"


class AttackType(str, Enum):
    NONE = "none"
    DIRECT_MALICIOUS_REQUEST = "direct-malicious-request"
    DIRECT_PROMPT_INJECTION = "direct-prompt-injection"
    INDIRECT_PROMPT_INJECTION = "indirect-prompt-injection"
    UNAUTHORIZED_TOOL_INVOCATION = "unauthorized-tool-invocation"
    SENSITIVE_DATA_EXFILTRATION = "sensitive-data-exfiltration"
    ADVERSARIAL_CONTEXT_MANIPULATION = "adversarial-context-manipulation"
    COMPROMISED_EDGE_NODE = "compromised-edge-node"
    RESOURCE_EXHAUSTION = "resource-exhaustion"


class DecisionStatus(str, Enum):
    SELECTED = "selected"
    REJECTED = "rejected"
    SANITIZE_REQUIRED = "sanitize-required"
    DELAYED = "delayed"
    HUMAN_ESCALATION = "human-escalation"


@dataclass(slots=True)
class Task:
    task_id: str
    category: str
    security_class: SecurityClass

    input_size_mb: float
    output_size_mb: float
    compute_demand: float
    memory_gb: float
    bandwidth_mbps: float
    deadline_ms: float
    required_quality: float
    sensitivity: float

    requested_tools: tuple[str, ...] = ()

    reasoning_score: float = 0.0
    context_score: float = 0.0
    tool_score: float = 0.0
    multimodal_score: float = 0.0

    malicious_intent: float = 0.0
    injection_probability: float = 0.0
    adversarial_input: float = 0.0
    tool_risk: float = 0.0

    minimum_trust: float = 0.60
    maximum_risk: float = 0.40
    required_isolation: int = 1
    decomposable: bool = False

    attack_type: AttackType = AttackType.NONE
    metadata: dict[str, Any] = field(default_factory=dict)

    def complexity(
        self,
        weights: tuple[float, float, float, float] = (0.30, 0.30, 0.20, 0.20),
    ) -> float:
        values = (
            self.reasoning_score,
            self.context_score,
            self.tool_score,
            self.multimodal_score,
        )
        return clip(sum(weight * value for weight, value in zip(weights, values)))

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["security_class"] = self.security_class.value
        data["attack_type"] = self.attack_type.value
        data["requested_tools"] = list(self.requested_tools)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Task":
        item = dict(data)
        item["security_class"] = SecurityClass(item["security_class"])
        item["attack_type"] = AttackType(item.get("attack_type", "none"))
        item["requested_tools"] = tuple(item.get("requested_tools", []))
        item.setdefault("metadata", {})
        return cls(**item)


@dataclass(slots=True)
class NodeState:
    node_id: str
    tier: Tier
    model_name: str

    compute_capacity: float
    memory_gb: float
    bandwidth_mbps: float
    uplink_mbps: float
    downlink_mbps: float
    queue_delay_ms: float

    model_capability: float
    efficiency: float
    trust_score: float

    energy_coefficient: float
    communication_power_w: float
    service_cost: float

    exposure: float
    vulnerability: float
    isolation_level: int
    maximum_sensitivity: float
    authorized_tools: set[str] = field(default_factory=set)

    available: bool = True
    compromised: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class TrustEvidence:
    integrity: float
    availability: float
    historical_behavior: float
    policy_compliance: float
    security_monitoring: float


@dataclass(slots=True)
class CandidateEstimate:
    candidate_id: str
    tier: Tier
    node_ids: tuple[str, ...]
    partition: dict[str, float]

    latency_ms: float
    energy_j: float
    communication_mb: float
    service_cost: float
    utility: float
    risk: float
    effective_trust: float

    tool_node_id: str | None = None
    feasible: bool = True
    rejection_reasons: list[str] = field(default_factory=list)
    score: float | None = None


@dataclass(slots=True)
class ExecutionPlan:
    task_id: str
    strategy: str
    status: DecisionStatus

    candidate_id: str | None = None
    tier: Tier | None = None
    node_ids: tuple[str, ...] = ()
    partition: dict[str, float] = field(default_factory=dict)

    estimate: CandidateEstimate | None = None
    objective_weights: dict[str, float] = field(default_factory=dict)
    rejection_reasons: list[str] = field(default_factory=list)

    sandbox_policy: dict[str, Any] = field(default_factory=dict)
    monitoring_policy: dict[str, Any] = field(default_factory=dict)

    @property
    def selected(self) -> bool:
        return self.status == DecisionStatus.SELECTED and self.estimate is not None


@dataclass(slots=True)
class ExecutionResult:
    task_id: str
    strategy: str
    status: DecisionStatus

    correct: bool
    secure_completion: bool
    threat_detected: bool
    attack_success: bool
    false_positive: bool

    privacy_leak: bool
    unauthorized_tool_execution: bool
    policy_violation: bool
    compromised_node_selected: bool

    latency_ms: float
    energy_j: float
    communication_mb: float
    node_ids: tuple[str, ...] = ()

    events: list[str] = field(default_factory=list)


def clip(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, float(value)))
