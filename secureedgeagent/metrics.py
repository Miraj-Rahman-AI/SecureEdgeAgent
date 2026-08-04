from __future__ import annotations

from dataclasses import dataclass

from secureedgeagent.models import ExecutionResult, SecurityClass, Task


@dataclass(slots=True)
class MetricAccumulator:
    total_tasks: int = 0
    legitimate_tasks: int = 0
    adversarial_tasks: int = 0

    correct_tasks: int = 0
    secure_tasks: int = 0
    deadline_violations: int = 0

    attack_attempts: int = 0
    successful_attacks: int = 0

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    sensitive_tasks: int = 0
    privacy_leaks: int = 0

    unauthorized_requests: int = 0
    unauthorized_executions: int = 0

    compromise_tasks: int = 0
    compromised_node_selections: int = 0

    total_latency_ms: float = 0.0
    total_energy_j: float = 0.0
    total_communication_mb: float = 0.0

    def add(self, task: Task, result: ExecutionResult) -> None:
        self.total_tasks += 1
        adversarial = task.security_class == SecurityClass.ADVERSARIAL

        if adversarial:
            self.adversarial_tasks += 1
            self.attack_attempts += 1

            if result.attack_success:
                self.successful_attacks += 1

            if result.threat_detected:
                self.true_positives += 1
            else:
                self.false_negatives += 1
        else:
            self.legitimate_tasks += 1

            if result.correct:
                self.correct_tasks += 1

            if result.secure_completion:
                self.secure_tasks += 1

            if result.false_positive:
                self.false_positives += 1

        if result.latency_ms > task.deadline_ms:
            self.deadline_violations += 1

        if task.sensitivity >= 0.70:
            self.sensitive_tasks += 1
            if result.privacy_leak:
                self.privacy_leaks += 1

        if task.attack_type.value == "unauthorized-tool-invocation":
            self.unauthorized_requests += 1
            if result.unauthorized_tool_execution:
                self.unauthorized_executions += 1

        if task.attack_type.value == "compromised-edge-node":
            self.compromise_tasks += 1
            if result.compromised_node_selected:
                self.compromised_node_selections += 1

        self.total_latency_ms += result.latency_ms
        self.total_energy_j += result.energy_j
        self.total_communication_mb += result.communication_mb

    def finalize(self, simulated_seconds: float) -> dict[str, float]:
        precision = safe_div(
            self.true_positives,
            self.true_positives + self.false_positives,
        )
        recall = safe_div(
            self.true_positives,
            self.true_positives + self.false_negatives,
        )
        f1 = safe_div(2.0 * precision * recall, precision + recall)

        return {
            "tasks": float(self.total_tasks),
            "average_latency_ms": safe_div(
                self.total_latency_ms,
                self.total_tasks,
            ),
            "average_energy_j": safe_div(
                self.total_energy_j,
                self.total_tasks,
            ),
            "average_communication_mb": safe_div(
                self.total_communication_mb,
                self.total_tasks,
            ),
            "task_success_percent": 100.0
            * safe_div(self.correct_tasks, self.legitimate_tasks),
            "secure_completion_percent": 100.0
            * safe_div(self.secure_tasks, self.legitimate_tasks),
            "deadline_violation_percent": 100.0
            * safe_div(self.deadline_violations, self.total_tasks),
            "throughput_tasks_s": safe_div(
                self.total_tasks,
                simulated_seconds,
            ),
            "attack_success_percent": 100.0
            * safe_div(self.successful_attacks, self.attack_attempts),
            "detection_precision_percent": 100.0 * precision,
            "detection_recall_percent": 100.0 * recall,
            "detection_f1_percent": 100.0 * f1,
            "privacy_leakage_percent": 100.0
            * safe_div(self.privacy_leaks, self.sensitive_tasks),
            "unauthorized_tool_execution_percent": 100.0
            * safe_div(
                self.unauthorized_executions,
                self.unauthorized_requests,
            ),
            "false_positive_percent": 100.0
            * safe_div(self.false_positives, self.legitimate_tasks),
            "compromised_node_selection_percent": 100.0
            * safe_div(
                self.compromised_node_selections,
                self.compromise_tasks,
            ),
        }


def safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0
