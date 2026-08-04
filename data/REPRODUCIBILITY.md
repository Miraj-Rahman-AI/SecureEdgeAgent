# Reproducibility Notes

## Result separation

- `results/reported/` stores values reported in the manuscript.
- `results/generated/` stores outputs produced by this repository.
- Generated simulator values must not be presented as reproduction of the
  manuscript results unless the original execution traces, workload prompts,
  model checkpoints, network traces and hardware measurements are used.

## Generate the workload

```bash
python -m scripts.generate_workload
python -m scripts.run_experiment --runs 5
```

```
python -m scripts.run_experiment \
  --strategies full-secureedgeagent \
  --runs 5
```

```
pytest
```


## `results/reported/README.md`

```markdown
# Manuscript-Reported Results

This directory contains CSV values reported in the SecureEdgeAgent manuscript.

These files are preserved separately from simulator-generated results. They must
not be silently overwritten by experiment scripts.

Place the separate manuscript performance CSV files here, including:

- overall performance comparison;
- aggregate security evaluation;
- attack-specific success rates;
- dynamic network results;
- dynamic trust results;
- ablation study;
- security-weight sensitivity;
- risk-threshold sensitivity;
- scalability and overhead; and
- connected-vehicle case-study values.

