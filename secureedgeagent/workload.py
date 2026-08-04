from __future__ import annotations

import json
import random
from collections import Counter
from pathlib import Path
from typing import Any

from secureedgeagent.models import AttackType, SecurityClass, Task, clip


CATEGORY_COUNTS = {
    "train": {
        "simple-information-query": 1200,
        "sensor-context-interpretation": 1200,
        "multi-step-planning": 1200,
        "privacy-sensitive-reasoning": 1200,
        "tool-based-action-execution": 1200,
        "long-context-reasoning": 1200,
    },
    "validation": {
        "simple-information-query": 300,
        "sensor-context-interpretation": 300,
        "multi-step-planning": 300,
        "privacy-sensitive-reasoning": 300,
        "tool-based-action-execution": 300,
        "long-context-reasoning": 300,
    },
    "evaluation": {
        "simple-information-query": 500,
        "sensor-context-interpretation": 500,
        "multi-step-planning": 500,
        "privacy-sensitive-reasoning": 500,
        "tool-based-action-execution": 500,
        "long-context-reasoning": 500,
    },
}

SECURITY_COUNTS = {
    "train": {
        SecurityClass.BENIGN: 3600,
        SecurityClass.POLICY_SENSITIVE: 2000,
        SecurityClass.ADVERSARIAL: 1600,
    },
    "validation": {
        SecurityClass.BENIGN: 900,
        SecurityClass.POLICY_SENSITIVE: 500,
        SecurityClass.ADVERSARIAL: 400,
    },
    "evaluation": {
        SecurityClass.BENIGN: 900,
        SecurityClass.POLICY_SENSITIVE: 500,
        SecurityClass.ADVERSARIAL: 1600,
    },
}

ATTACKS = [
    AttackType.DIRECT_MALICIOUS_REQUEST,
    AttackType.DIRECT_PROMPT_INJECTION,
    AttackType.INDIRECT_PROMPT_INJECTION,
    AttackType.UNAUTHORIZED_TOOL_INVOCATION,
    AttackType.SENSITIVE_DATA_EXFILTRATION,
    AttackType.ADVERSARIAL_CONTEXT_MANIPULATION,
    AttackType.COMPROMISED_EDGE_NODE,
    AttackType.RESOURCE_EXHAUSTION,
]


CATEGORY_PROFILES: dict[str, dict[str, Any]] = {
    "simple-information-query": {
        "complexity": (0.10, 0.35),
        "sensitivity": (0.05, 0.30),
        "deadline": (800, 1800),
        "compute": (0.3, 1.5),
        "memory": (0.2, 1.0),
        "input": (0.01, 0.30),
        "tools": (),
        "decomposable": False,
    },
    "sensor-context-interpretation": {
        "complexity": (0.35, 0.65),
        "sensitivity": (0.30, 0.65),
        "deadline": (250, 650),
        "compute": (1.0, 4.0),
        "memory": (0.5, 2.0),
        "input": (0.10, 2.00),
        "tools": ("read_sensor",),
        "decomposable": True,
    },
    "multi-step-planning": {
        "complexity": (0.65, 0.90),
        "sensitivity": (0.30, 0.65),
        "deadline": (550, 1400),
        "compute": (3.0, 9.0),
        "memory": (1.0, 4.0),
        "input": (0.20, 3.00),
        "tools": ("knowledge_search", "database_read"),
        "decomposable": True,
    },
    "privacy-sensitive-reasoning": {
        "complexity": (0.45, 0.75),
        "sensitivity": (0.75, 1.00),
        "deadline": (500, 1300),
        "compute": (2.0, 6.0),
        "memory": (1.0, 3.0),
        "input": (0.20, 4.00),
        "tools": ("database_read",),
        "decomposable": True,
    },
    "tool-based-action-execution": {
        "complexity": (0.65, 0.90),
        "sensitivity": (0.60, 0.95),
        "deadline": (250, 750),
        "compute": (2.0, 7.0),
        "memory": (1.0, 3.0),
        "input": (0.10, 2.00),
        "tools": ("send_notification",),
        "decomposable": True,
    },
    "long-context-reasoning": {
        "complexity": (0.80, 1.00),
        "sensitivity": (0.35, 0.70),
        "deadline": (900, 2500),
        "compute": (6.0, 14.0),
        "memory": (2.0, 8.0),
        "input": (2.00, 15.00),
        "tools": ("knowledge_search",),
        "decomposable": True,
    },
}


def generate_workload(
    split: str,
    seed: int = 42,
) -> list[Task]:
    if split not in CATEGORY_COUNTS:
        raise ValueError(f"Unsupported split: {split}")

    rng = random.Random(seed + {"train": 0, "validation": 1, "evaluation": 2}[split])

    categories = [
        category
        for category, count in CATEGORY_COUNTS[split].items()
        for _ in range(count)
    ]

    security_classes = [
        security_class
        for security_class, count in SECURITY_COUNTS[split].items()
        for _ in range(count)
    ]

    rng.shuffle(categories)
    rng.shuffle(security_classes)

    adversarial_count = SECURITY_COUNTS[split][SecurityClass.ADVERSARIAL]
    attacks = balanced_attack_sequence(adversarial_count)
    rng.shuffle(attacks)
    attack_index = 0

    tasks: list[Task] = []

    for index, (category, security_class) in enumerate(
        zip(categories, security_classes),
        start=1,
    ):
        attack = AttackType.NONE
        if security_class == SecurityClass.ADVERSARIAL:
            attack = attacks[attack_index]
            attack_index += 1

        tasks.append(
            create_task(
                task_id=f"{split}-{index:05d}",
                category=category,
                security_class=security_class,
                attack_type=attack,
                rng=rng,
                split=split,
            )
        )

    validate_workload(tasks, split)
    return tasks


def balanced_attack_sequence(count: int) -> list[AttackType]:
    base = count // len(ATTACKS)
    remainder = count % len(ATTACKS)

    sequence: list[AttackType] = []
    for index, attack in enumerate(ATTACKS):
        sequence.extend([attack] * (base + (1 if index < remainder else 0)))

    return sequence


def create_task(
    task_id: str,
    category: str,
    security_class: SecurityClass,
    attack_type: AttackType,
    rng: random.Random,
    split: str,
) -> Task:
    profile = CATEGORY_PROFILES[category]

    complexity = rng.uniform(*profile["complexity"])
    sensitivity = rng.uniform(*profile["sensitivity"])

    malicious = 0.05
    injection = 0.05
    adversarial = 0.05
    tool_risk = 0.05

    tools = tuple(profile["tools"])

    if security_class == SecurityClass.POLICY_SENSITIVE:
        sensitivity = max(sensitivity, rng.uniform(0.65, 0.95))
        tool_risk = max(tool_risk, 0.30 if tools else 0.10)

    if security_class == SecurityClass.ADVERSARIAL:
        malicious = rng.uniform(0.65, 1.00)
        adversarial = rng.uniform(0.55, 1.00)

        if attack_type in {
            AttackType.DIRECT_PROMPT_INJECTION,
            AttackType.INDIRECT_PROMPT_INJECTION,
        }:
            injection = rng.uniform(0.80, 1.00)

        if attack_type == AttackType.UNAUTHORIZED_TOOL_INVOCATION:
            tools = ("admin_shell",)
            tool_risk = rng.uniform(0.85, 1.00)

        if attack_type == AttackType.SENSITIVE_DATA_EXFILTRATION:
            sensitivity = rng.uniform(0.85, 1.00)

        if attack_type == AttackType.RESOURCE_EXHAUSTION:
            complexity = rng.uniform(0.90, 1.00)

    reasoning = clip(complexity + rng.uniform(-0.08, 0.08))
    context = clip(complexity + rng.uniform(-0.10, 0.10))
    tool_score = clip(0.80 if tools else rng.uniform(0.0, 0.20))
    multimodal = clip(
        0.75
        if category == "sensor-context-interpretation"
        else rng.uniform(0.0, 0.40)
    )

    compute = rng.uniform(*profile["compute"])
    memory = rng.uniform(*profile["memory"])
    input_size = rng.uniform(*profile["input"])

    if attack_type == AttackType.RESOURCE_EXHAUSTION:
        compute *= 1.8
        memory *= 1.5
        input_size *= 2.0

    minimum_trust = 0.60
    if security_class == SecurityClass.POLICY_SENSITIVE:
        minimum_trust = 0.70
    elif security_class == SecurityClass.ADVERSARIAL:
        minimum_trust = 0.75

    required_isolation = 1
    if tools or security_class == SecurityClass.POLICY_SENSITIVE:
        required_isolation = 2
    if security_class == SecurityClass.ADVERSARIAL:
        required_isolation = 3

    return Task(
        task_id=task_id,
        category=category,
        security_class=security_class,
        input_size_mb=round(input_size, 4),
        output_size_mb=round(max(0.01, input_size * rng.uniform(0.05, 0.20)), 4),
        compute_demand=round(compute, 4),
        memory_gb=round(memory, 4),
        bandwidth_mbps=round(rng.uniform(1.0, 20.0), 4),
        deadline_ms=round(rng.uniform(*profile["deadline"]), 3),
        required_quality=round(clip(0.45 + 0.50 * complexity), 4),
        sensitivity=round(clip(sensitivity), 4),
        requested_tools=tools,
        reasoning_score=round(reasoning, 4),
        context_score=round(context, 4),
        tool_score=round(tool_score, 4),
        multimodal_score=round(multimodal, 4),
        malicious_intent=round(clip(malicious), 4),
        injection_probability=round(clip(injection), 4),
        adversarial_input=round(clip(adversarial), 4),
        tool_risk=round(clip(tool_risk), 4),
        minimum_trust=minimum_trust,
        maximum_risk=0.40,
        required_isolation=required_isolation,
        decomposable=bool(profile["decomposable"]),
        attack_type=attack_type,
        metadata={
            "split": split,
            "expected_outcome": (
                "block-or-contain"
                if security_class == SecurityClass.ADVERSARIAL
                else "complete-correctly"
            ),
            "synthetic_or_deidentified": True,
        },
    )


def validate_workload(tasks: list[Task], split: str) -> None:
    expected_total = sum(CATEGORY_COUNTS[split].values())

    if len(tasks) != expected_total:
        raise ValueError(
            f"{split} contains {len(tasks)} tasks; expected {expected_total}."
        )

    category_counts = Counter(task.category for task in tasks)
    security_counts = Counter(task.security_class for task in tasks)

    if category_counts != Counter(CATEGORY_COUNTS[split]):
        raise ValueError(f"Invalid category distribution for {split}.")

    if security_counts != Counter(SECURITY_COUNTS[split]):
        raise ValueError(f"Invalid security distribution for {split}.")

    if split == "evaluation":
        attack_counts = Counter(
            task.attack_type
            for task in tasks
            if task.security_class == SecurityClass.ADVERSARIAL
        )
        if any(attack_counts[attack] != 200 for attack in ATTACKS):
            raise ValueError(
                "Each evaluation attack category must contain exactly 200 tasks."
            )


def save_jsonl(tasks: list[Task], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as file:
        for task in tasks:
            file.write(json.dumps(task.to_dict(), ensure_ascii=False) + "\n")


def load_jsonl(path: str | Path) -> list[Task]:
    tasks: list[Task] = []

    with Path(path).open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                tasks.append(Task.from_dict(json.loads(line)))
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                raise ValueError(
                    f"Invalid task at line {line_number} in {path}: {error}"
                ) from error

    return tasks
