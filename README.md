# SecureEdgeAgent

**Security- and Trust-Aware Adaptive Edge-Cloud Orchestration for Autonomous AI Agents in 6G Networks**

SecureEdgeAgent is a research-oriented implementation scaffold for security-first autonomous-agent execution across device, edge, cloud, and hybrid environments. It integrates task profiling, task-risk analysis, dynamic node-trust evaluation, privacy-aware placement, tool authorization, secure-sandbox policy checks, multi-objective offloading, runtime monitoring, and feedback-driven adaptation.

<p align="center">
  <img src="docs/assets/SecureEdgeAgent architecture.png" alt="SecureEdgeAgent architecture" width="900"/>
</p>

## Release status

This repository contains:

- a functional reference simulator implementing the manuscript's two-stage offloading procedure;
- a deterministic generator for a **12,000-task synthetic reference workload** with the manuscript's category and split distributions;
- configuration files representing the device-edge-cloud testbed;
- baseline policies, metrics, tests, and experiment scripts;
- CSV files containing the **results reported in the manuscript**.

> **Reproducibility note:** `results/reported/` records manuscript-reported values. The included simulator and generated workload are a transparent reference implementation, not proof that the original hardware measurements have been independently reproduced. Replace the reference workload and estimator parameters with the actual experimental traces before claiming exact replication.

## Core method

For each task, SecureEdgeAgent:

1. extracts complexity, deadline, input size, memory, bandwidth, sensitivity, required quality, and tool demand;
2. estimates intrinsic task risk and current node trust;
3. filters candidates violating resource, latency, risk, trust, privacy, authorization, or isolation constraints;
4. normalizes the retained candidates' latency, energy, cost, utility, and risk indicators;
5. minimizes the security-aware multi-objective score;
6. executes the selected plan under policy and sandbox controls;
7. updates node trust and orchestration state from observed outcomes.

## Repository structure

```text
SecureEdgeAgent/
├── secureedgeagent/          # Core Python package
├── configs/                  # Algorithm, tier, and experiment configuration
├── scripts/                  # Workload generation and experiment entry points
├── data/                     # Schema, samples, and generated workload location
├── results/
│   ├── reported/             # Values reported in the manuscript
│   └── generated/            # Outputs produced by local runs
├── tests/                    # Unit tests
├── docs/                     # Architecture, mapping, and reproducibility notes
├── examples/                 # Minimal executable example
└── .github/workflows/        # Continuous integration
```

## Quick start

Python 3.11 is recommended.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -U pip
pip install -e .
```

Generate the 12,000-task reference workload:

```bash
python scripts/generate_workload.py --output-dir data/generated --seed 42
```

Run the reference simulation:

```bash
python scripts/run_experiment.py \
  --config configs/default.yaml \
  --workload data/generated/evaluation.jsonl \
  --output results/generated/full_secureedgeagent.jsonl
```

Calculate metrics:

```bash
python scripts/evaluate.py \
  --input results/generated/full_secureedgeagent.jsonl \
  --output results/generated/summary.json
```

Run tests:

```bash
pytest -q
```

A convenience script is also provided:

```bash
bash scripts/run_all.sh
```

## Reference testbed mapping

| Tier | Hardware | Model | Main role |
|---|---|---|---|
| Device | NVIDIA Jetson Orin Nano, 8 GB shared LPDDR5 | Qwen2.5-1.5B-Instruct, 4-bit | Local preprocessing, privacy-sensitive and latency-critical tasks |
| Edge/MEC | 1x NVIDIA RTX 4090, 24 GB; 128 GB RAM | Qwen2.5-7B-Instruct, BF16 | Low-latency reasoning, retrieval, memory, controlled tools |
| Cloud | 8x NVIDIA A100 PCIe, 40 GB each | Qwen2.5-72B-Instruct, BF16, 8-way TP | Long-context and compute-intensive reasoning, global retrieval, planning |

The manuscript environment also specifies Ubuntu Server 24.04 LTS, Python 3.11, PyTorch 2.5.1, CUDA 12.4, Transformers, vLLM, LangGraph, Mininet 2.3.0, Docker, TLS 1.3/DTLS 1.2, NCCL, capability-based access control, runtime monitoring, and audit logging.

## Workload organization

The reference generator follows the stated distributions:

- 12,000 tasks across six categories, 2,000 tasks per category;
- 7,200 training, 1,800 validation, and 3,000 evaluation tasks;
- 5,400 benign, 3,000 policy-sensitive, and 3,600 adversarial tasks;
- 1,600 adversarial evaluation requests across eight attack categories.

Only synthetic or de-identified content is generated. Task groups derived from the same scenario/template are assigned to one split to reduce leakage.

## Reported headline results

The manuscript reports 285 ms average latency, 92.1% task success, 91.3% secure task completion, 5.1% deadline violations, 28.4 tasks/s throughput, 4.9% attack success, and 95.5% threat-detection F1 for the full framework. Detailed reported tables are stored under `results/reported/`.

## Security

This is research code. The sandbox module provides policy interfaces and safe reference checks; it is **not** a hardened containment boundary. Do not execute untrusted code or connect actuators, production credentials, personal data, or safety-critical systems without independent security review. See [SECURITY.md](SECURITY.md).

## Paper and citation

Add the final public manuscript or preprint to `paper/` after checking publisher and institutional policies. A citation template is available in `CITATION.cff.template`.

Expected repository URL:

```text
https://github.com/Miraj-Rahman-AI/SecureEdgeAgent
```

## License

The original source code in this repository is licensed under the [MIT License](LICENSE). Third-party models, datasets, software, and other external resources remain subject to their respective licenses and terms of use.
