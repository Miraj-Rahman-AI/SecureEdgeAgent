from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from secureedgeagent.workload import generate_workload, save_jsonl


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate the SecureEdgeAgent synthetic workload."
    )
    parser.add_argument(
        "--output-dir",
        default="data/generated",
        help="Directory for train, validation, and evaluation JSONL files.",
    )
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    for split in ("train", "validation", "evaluation"):
        tasks = generate_workload(split, seed=args.seed)
        output_path = output_dir / f"{split}.jsonl"
        save_jsonl(tasks, output_path)

        security_counts = Counter(task.security_class.value for task in tasks)

        print(
            f"{split:10s}: {len(tasks):5d} tasks -> {output_path} | "
            f"{dict(security_counts)}"
        )


if __name__ == "__main__":
    main()
