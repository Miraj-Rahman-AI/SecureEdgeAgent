# Manuscript-to-Code Mapping

| Manuscript component | Implementation |
|---|---|
| Task model and profile | `secureedgeagent.models.Task` |
| Complexity score | `Task.complexity()` |
| Intrinsic task risk | `RiskAnalyzer.intrinsic_risk()` |
| Task-node execution risk | `RiskAnalyzer.execution_risk()` |
| Dynamic node trust | `TrustManager.update()` |
| Incident penalty | `TrustManager.apply_incident()` |
| Latency, energy, communication and utility estimation | `OffloadingEngine._estimate_single()` |
| Security feasibility filtering | `OffloadingEngine._apply_single_feasibility()` |
| Hybrid partitioning | `OffloadingEngine._hybrid_candidates()` |
| Min-max normalization | `engine.minmax()` |
| Multi-objective score | `OffloadingEngine._score_candidates()` |
| Secure execution policy | `ExecutionPlan.sandbox_policy` |
| Runtime security simulation | `SecureExecutor.execute()` |
| Feedback-driven adaptation | `execution.apply_feedback()` |
| Evaluation metrics | `MetricAccumulator` |
| Workload construction | `secureedgeagent.workload` |
| Algorithm and baseline entry point | `scripts/run_experiment.py` |

The code implements the mathematical and algorithmic structure presented in
the manuscript. Normalized simulator capacities and unspecified coefficients
are declared in configuration files and should not be interpreted as measured
hardware specifications.
