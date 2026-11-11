"""Aggregate fuzzy-threshold sensitivity (E1) for TB-Guard and TB-Policy."""
import sys, os
import pandas as pd
sys.path.insert(0, os.path.dirname(__file__))
from common import *
from analysis import call_metrics, trace_outcomes, trace_metrics, trace_info
TR = read_csv(os.path.join(DATA, 'trace_table.csv')).set_index('tid')
TI = trace_info(); traces = TR.loc[TI.index]
rows = []
for tau, f in [(0.4, 'ALL_predictions_E1_tau0.4.csv'), (0.6, 'ALL_predictions_E1.csv'), (0.8, 'ALL_predictions_E1_tau0.8.csv')]:
    p = resolve(os.path.join(RES, f))
    if not os.path.exists(p):
        continue
    P = pd.read_csv(p)
    for m in ['TB_Guard', 'TB_Policy']:
        Pm = P[P.method == m]
        cm = call_metrics(Pm.label.values, Pm.score.values, (Pm.score > Pm.thr).values)
        tm = trace_metrics(trace_outcomes(Pm, traces))
        rows.append({'tau': tau, 'method': m, **cm, **tm})
S = pd.DataFrame(rows); S.to_csv(os.path.join(RES, 'ALL_tau_sensitivity.csv'), index=False)
print(S[['tau', 'method', 'AUPRC', 'F1', 'recall', 'FPR', 'ASR_after', 'utility_retained']].round(3))
