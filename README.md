# TB-Guard: Runtime Detection of Cross-Agent Trust Boundary Violations in Tool-Augmented AI Systems

Code and released results for the paper *"Runtime Detection of Cross-Agent Trust Boundary Violations in
Tool-Augmented AI Systems"*.

TB-Guard is a runtime monitor that checks every privileged tool call of an LLM agent before the call executes.
It annotates the trace prefix with a three-level integrity lattice (HIGH: system/user; MEDIUM: agent and the user's
own data; LOW: third-party content) and a sink-privilege map. It then builds a causal provenance graph that links
each argument value to its sources through exact and fuzzy derivation edges and user-endorsement edges, and scores
the call with a relational GraphSAGE network over the graph plus 47 call features. The monitor needs no change to
the model, prompts or tools and no extra LLM call. We evaluate it on 26,009 real AgentDojo execution traces of
22 LLMs under three splits: E1, grouped 5-fold cross-validation; E2, leave-one-suite-out; and E3,
leave-one-model-family-out. We compare it with signature, content-classifier, strict-taint, anomaly, rule-based
and flat-MLP baselines using paired McNemar and permutation tests. On E1, TB-Guard reaches **AUPRC 0.986** and
**F1 0.944** at a 1% validation FPR. It cuts the attack success rate from 17.8% to 1.5% while leaving 99.7% of
benign traces unblocked, at 7.9 ms per check on a single CPU thread.

## Citation

```bibtex
@article{tbguard,
  title   = {Runtime Detection of Cross-Agent Trust Boundary Violations in Tool-Augmented AI Systems},
  author  = {[Author names]},
  journal = {[Venue]},
  year    = {[Year]},
  doi     = {[DOI]}
}
```

See also `CITATION.cff`.

## Repository structure

```
tb-guard/
├── src/
│   ├── common.py          paths, seed, corpus rules, trust lattice (tool -> integrity), sink-privilege map, normalisation
│   ├── parse_traces.py    AgentDojo run JSONs -> data/traces.pkl
│   ├── labels.py          corpus selection, call-level ground truth (matching rules: make_matcher), label validation
│   ├── build_graphs.py    causal provenance graphs + 47 call features per trace -> data/graphs_tau{tau}.pkl
│   ├── models.py          relational GraphSAGE (TB-Guard), flat MLP (B5), TF-IDF line classifier (B2), signatures (B1)
│   ├── experiment.py      E1/E2/E3 splits, training, threshold selection, per-call predictions
│   ├── analysis.py        metrics, trace-bootstrap CIs, McNemar exact tests, permutation tests, breakdowns
│   ├── make_tables.py     renders all result CSVs into results/tables_autogen.md
│   ├── figures.py         paper figures (PNG 300 dpi + PDF)
│   ├── fig_framework.py   Fig. 1 (schematic overview)
│   ├── latency.py         per-check latency on CPU
│   ├── error_analysis.py  categorised TB-Guard false positives / negatives
│   ├── tau_sens.py        sensitivity to the fuzzy-derivation threshold tau
│   └── litcomp.py         comparison with AgentDojo's built-in defences (gpt-4o)
├── scripts/run_rest.sh    the latency + tau-sensitivity half of the pipeline, as run for the paper
├── data/                  (git-ignored except the three small derived tables below)
│   ├── trace_table.csv.gz one row per trace: model, suite, tasks, attack, security/utility flags, #violations
│   ├── call_table.csv.gz  one row per tool call: function, privilege, call-level label, truncated arguments
│   └── trace_info.csv.gz  first LOW-integrity read and call counts per corpus trace
└── results/
    ├── ALL_predictions_{E1,E2,E3,E1_tau0.4,E1_tau0.8}.csv.gz  per-call out-of-fold scores, labels, fold thresholds
    ├── ALL_metrics_*.csv, ALL_stats_*.csv, ALL_perfold_*.csv, ALL_breakdown_*.csv, ALL_fpr_sensitivity_*.csv,
    │   ALL_tau_sensitivity.csv, ALL_literature_comparison.csv, ALL_latency_{raw,summary}.csv,
    │   ALL_error_analysis.csv, ALL_errors_TBGuard_E1.csv.gz
    ├── thresholds_*.csv, trainlog_*.json      fold-wise thresholds and training curves
    ├── label_validation.txt                   call labels vs. AgentDojo security flag
    ├── tables_autogen.md                      all tables rendered from the CSVs
    ├── results_summary.md                     full technical write-up (corpus rules, label-matching table, results)
    ├── models/tbguard_E1_fold0.{pt,_aux.pkl}  E1 fold-0 model, used by latency.py
    ├── figures/                               fig0-fig7 (PNG + PDF)
    └── logs/                                  stdout of the original runs (timings)
```

The integrity lattice and the sink-privilege map are in `src/common.py` (`LOW_TOOLS`, `HIGH_TOOLS`, `PRIV2`,
`PRIV1`). The call-level matching rules for every (suite, injection task) are in `src/labels.py` (`make_matcher`),
and they are tabulated in `results/results_summary.md` §1. They are code rather than separate label files, so
there is no `labels/` directory.

All paths are relative to the repository root. You can override them with the environment variables
`TBG_DATA`, `TBG_RESULTS` and `AGENTDOJO_RUNS`, or with `--runs` for `parse_traces.py`.

## Environment

Use Python 3.13 (the results were produced with 3.13.18). Only a CPU is needed.

```bash
python -m venv .venv && . .venv/bin/activate
pip install torch==2.15.0 --index-url https://download.pytorch.org/whl/cpu   # CPU-only wheel
pip install -r requirements.txt
```

`src/labels.py` also needs the `agentdojo` package (v0.1.35) from the same checkout as the traces (see below).
No other script imports it.

## Obtaining the AgentDojo traces

The raw traces are not redistributed here. They are public in the AgentDojo repository (`runs/`, 29 pipeline
folders, 36,679 JSON traces, about 525 MB), and we used commit `089ed46`:

```bash
git clone https://github.com/ethz-spylab/agentdojo.git data/agentdojo
git -C data/agentdojo checkout 089ed468cf3ed0322acc66b0211f26d9d90dbf60
pip install -e data/agentdojo          # agentdojo 0.1.35: injection-task ground truth for labels.py
```

`parse_traces.py` expects the traces at `data/agentdojo/runs/<pipeline>/<suite>/<user_task>/<attack>/<inj_task>.json`.
For a checkout elsewhere, use `python src/parse_traces.py --runs /path/to/agentdojo/runs`.

## Pipeline

Run every command from the repository root. The order is
`parse_traces` → `labels` → `build_graphs` → `experiment` →
`analysis` / `make_tables` / `figures` / `latency` / `error_analysis` / `tau_sens` / `litcomp`.

```bash
mkdir -p results/logs
# 1. traces and labels
python src/parse_traces.py                      # -> data/traces.pkl (all 36,679 traces, normalised)
python src/labels.py                            # -> data/traces_main.pkl, data/trace_table.csv, data/call_table.csv,
                                                #    results/label_validation.txt
# 2. provenance graphs and features (tau = fuzzy-derivation threshold; 0.6 is the default)
python src/build_graphs.py 0.6                  # -> data/graphs_tau0.6.pkl
# 3. detectors under the three splits -> results/ALL_predictions_*.csv, thresholds_*.csv, trainlog_*.json
python src/experiment.py E1 --ablate  > results/logs/log_E1.txt   # grouped 5-fold CV, all methods + 4 ablations
python src/experiment.py E2           > results/logs/log_E2.txt   # leave-one-suite-out
python src/experiment.py E3           > results/logs/log_E3.txt   # leave-one-model-family-out
# 4. metrics, bootstrap CIs, McNemar + permutation tests, breakdowns
python src/analysis.py E1 --stats; python src/analysis.py E2 --stats; python src/analysis.py E3 --stats
# 5. remaining analyses (scripts/run_rest.sh runs latency + the two tau variants + tau_sens)
python src/litcomp.py                           # -> results/ALL_literature_comparison.csv
python src/latency.py                           # -> results/ALL_latency_{raw,summary}.csv
python src/build_graphs.py 0.4; python src/experiment.py E1 --tau 0.4 --only tbguard --tag _tau0.4
python src/build_graphs.py 0.8; python src/experiment.py E1 --tau 0.8 --only tbguard --tag _tau0.8
python src/tau_sens.py                          # -> results/ALL_tau_sensitivity.csv
python src/error_analysis.py                    # -> results/ALL_error_analysis.csv, ALL_errors_TBGuard_E1.csv
# 6. tables and figures
python src/make_tables.py                       # -> results/tables_autogen.md
python src/figures.py                           # -> results/figures/fig1..fig7
python src/fig_framework.py                     # -> results/figures/fig0_framework
```

`analysis.py` writes `data/trace_info.csv` from `graphs_tau0.6.pkl` the first time it runs, if neither that
file nor the shipped `.gz` is present.

### Rebuilding tables and figures without retraining

The released `results/` and `data/*.csv.gz` are enough to rebuild most outputs with no traces and no training.
The scripts read `X.csv.gz` whenever `X.csv` is absent.

```bash
python src/make_tables.py                  # seconds; reproduces results/tables_autogen.md byte for byte
python src/figures.py 1 2 3 4 5 6          # seconds; figures 1-6 (fig7 needs data/traces_main.pkl)
python src/fig_framework.py
python src/analysis.py E1 --stats          # ~5 min; recomputes metrics, CIs, McNemar/permutation tests from predictions
python src/tau_sens.py; python src/litcomp.py
```

`latency.py` and `error_analysis.py` and `figures.py 7` need the derived pickles (`traces_main.pkl` or
`graphs_tau0.6.pkl`), so you must run steps 1 and 2 first.

## Paper tables and figures

| Paper | Content | Script | Output |
|---|---|---|---|
| Table 1 | Principals and integrity levels | `src/common.py` (`LOW_TOOLS`, `HIGH_TOOLS`, `tool_integrity`) | (in code) |
| Table 2 | 47 call features | `src/build_graphs.py` (feature construction), `src/models.py` (`CI` column index) | `data/graphs_tau0.6.pkl` |
| Table 3 | Corpus | `src/labels.py` | `data/trace_table.csv(.gz)`, `data/call_table.csv(.gz)`, `results/label_validation.txt` |
| Table 4 | Compared methods | `src/experiment.py`, `src/models.py` | (descriptive) |
| Table 5 | Call-level detection, E1 | `src/analysis.py E1` | `results/ALL_metrics_E1.csv` |
| Table 6 | Paired tests, E1 | `src/analysis.py E1 --stats` | `results/ALL_stats_E1.csv` |
| Table 7 | Runtime outcome (ASR, utility), E1 | `src/analysis.py E1` | `results/ALL_metrics_E1.csv` (trace-level columns) |
| Table 8 | Generalisation, E2 / E3 | `src/analysis.py E2/E3 --stats` | `results/ALL_metrics_E2.csv`, `ALL_metrics_E3.csv`, `ALL_perfold_E{2,3}.csv`, `ALL_stats_E{2,3}.csv` |
| Table 9 | Ablation | `src/experiment.py E1 --ablate`, `src/analysis.py E1 --stats` | `results/ALL_metrics_E1.csv` (`TB_Guard_no_*`, `TB_Guard_lex_only` rows), `ALL_stats_E1.csv` |
| Table 10 | Sensitivity (FPR target, tau) | `src/analysis.py`, `src/tau_sens.py` | `results/ALL_fpr_sensitivity_E1.csv`, `ALL_fpr_sensitivity_E2.csv`, `ALL_tau_sensitivity.csv` |
| Table 11 | Latency per check | `src/latency.py` | `results/ALL_latency_summary.csv` |
| Table 12 | vs. AgentDojo built-in defences (gpt-4o) | `src/litcomp.py` | `results/ALL_literature_comparison.csv` |
| Table 13 | Published AgentDojo results | compiled from the cited papers | (not generated) |
| Table 14 | Error analysis | `src/error_analysis.py` | `results/ALL_error_analysis.csv` |
| Tables 15-16 | Related work, capability matrix | literature review | (not generated) |
| Fig. 1 | Overview of TB-Guard | `src/fig_framework.py` | `results/figures/fig0_framework.{png,pdf}` |
| Fig. 2 | Provenance graph of a real trace | `src/figures.py 7` | `results/figures/fig7_provenance_example.*` |
| Fig. 3 | Corpus overview | `src/figures.py 1` | `results/figures/fig1_dataset_overview.*` |
| Fig. 4 | Precision-recall curves, E1 | `src/figures.py 2` | `results/figures/fig2_pr_curves_E1.*` |
| Fig. 5 | Security-utility trade-off | `src/figures.py 3` | `results/figures/fig3_security_utility.*` |
| Fig. 6 | AUPRC per held-out unit (E2, E3) | `src/figures.py 4` | `results/figures/fig4_generalisation_heatmap.*` |
| Fig. 7 | Ablation | `src/figures.py 5` | `results/figures/fig5_ablation.*` |
| Fig. 8 | Runtime overhead | `src/figures.py 6` | `results/figures/fig6_latency.*` |

The figure file names follow the order in which the figures were produced, not the paper's numbering. The table
above gives the mapping. `results/tables_autogen.md` contains every table in rendered form.

## Seeds, hardware and runtime

- **Seed.** `common.SEED = 20240611`. The E1 fold assignment, the validation split (`SEED + fold`), the torch
  and numpy initialisation of each model (`SEED + fold`), the IsolationForest, the logistic regression, the
  bootstrap (1,000 trace resamples) and the permutation tests (1,000 permutations) all derive from it.
- **Operating point.** The threshold is the 99th percentile of validation negatives (1% FPR). The 0.5%, 2% and
  5% thresholds and the "clean-calibrated" threshold are stored alongside it in the predictions.
- **Hardware.** CPU only: 2 vCPU (Intel Xeon @ 2.10 GHz), 7 GB RAM, no GPU.
- **Runtime** (from `results/logs/`):

  | Step | Wall time |
  |---|---|
  | `experiment.py E1 --ablate` | 1,219 s (5 folds, 12 methods) |
  | `experiment.py E2` | 435 s |
  | `experiment.py E3` | 450 s |
  | `experiment.py E1 --tau 0.4 / 0.8 --only tbguard` | 311 s / 222 s |
  | `analysis.py E1 --stats` | 270 s |
  | `latency.py` | 500 checks, about 7.9 ms each |
  | full pipeline | about 45 min |

  The derived pickles need about 1.1 GB of disk space, and the AgentDojo checkout needs about 0.6 GB.

## CPU-only notes

- Nothing needs a GPU. `models.py` builds every tensor on the CPU, and the GNN is small (3 layers, hidden size 48).
- `latency.py` calls `torch.set_num_threads(1)` and measures a full rebuild of the prefix graph at every check.
  The numbers are therefore upper bounds, and they depend on the machine and on its load (the paper's numbers were
  measured while another job shared the CPU).
- `parse_traces.py` and `build_graphs.py` use `multiprocessing.Pool(2)`.
- Training on a different CPU, a different BLAS or a different torch version can change the GNN and MLP scores in
  the last digits. The released predictions are the ones behind the paper.

## Reproduction caveats

- `results/models/*_aux.pkl` and the derived `data/*.pkl` files are Python pickles. They contain scikit-learn
  objects, so load them only with the pinned versions, and only from a source you trust.
- Only the E1 fold-0 checkpoint is shipped, because it is the one `latency.py` uses. `experiment.py` writes the
  other checkpoints (E2, E3, tau variants) to `results/models/`.
- Tables 13, 15 and 16 come from the literature and are not produced by code.
