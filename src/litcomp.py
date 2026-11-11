"""Literature comparison: AgentDojo's own defended gpt-4o pipelines (from their published traces) vs.
TB-Guard / baselines simulated on the undefended gpt-4o traces (E1 out-of-fold predictions).
Attack = important_instructions; benign = attack 'none' (user tasks only)."""
import sys, os
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(__file__))
from common import *
from analysis import trace_outcomes, load

P, TR, TI = load('E1')
rng = np.random.RandomState(SEED)


def boot_ci(vals, n=1000):
    vals = np.asarray(vals, float)
    bs = [vals[rng.randint(0, len(vals), len(vals))].mean() for _ in range(n)]
    return np.quantile(bs, [0.025, 0.975])


rows = []
base = 'gpt-4o-2024-05-13'
for pipe in [base] + [base + s for s in ['-tool_filter', '-spotlighting_with_delimiting', '-transformers_pi_detector', '-repeat_user_prompt']]:
    sub = TR[(TR.pipe_dir == pipe)]
    for scope, att in [('call-goal tasks', sub[(sub.attack == 'important_instructions') & ~sub.textonly_goal]),
                       ('all tasks', sub[sub.attack == 'important_instructions'])]:
        none = sub[sub.attack == 'none']
        a_lo, a_hi = boot_ci(att.security)
        u_lo, u_hi = boot_ci(none.utility)
        ua_lo, ua_hi = boot_ci(att.utility)
        rows.append({'defence': 'none (undefended)' if pipe == base else pipe.replace(base + '-', 'AgentDojo: '),
                     'scope': scope, 'n_attack': len(att), 'n_benign': len(none),
                     'ASR': att.security.mean(), 'ASR_lo': a_lo, 'ASR_hi': a_hi,
                     'benign_utility': none.utility.mean(), 'BU_lo': u_lo, 'BU_hi': u_hi,
                     'utility_under_attack': att.utility.mean(), 'UA_lo': ua_lo, 'UA_hi': ua_hi})
# simulated monitors on undefended gpt-4o traces (call-goal tasks; text-only goal excluded from corpus)
traces = TR.loc[TI.index]
g4 = traces[(traces.pipe_dir == base) & traces.attack.isin(['important_instructions', 'none'])]
for m in ['TB_Guard', 'B5_flat_MLP', 'TB_Policy', 'B1_signature', 'B2_content_clf', 'B3_strict_taint', 'B4_anomaly']:
    for thrcol in ['thr', 'thr_clean']:
        Pm = P[(P.method == m) & P.tid.isin(g4.index)]
        o = trace_outcomes(Pm, g4, thrcol)
        att = o[o.is_attack]; none = o[~o.is_attack]
        sa = att.succ_after.values; bu = (none.utility & ~none.any_block).values; ua = (att.utility & ~att.any_block).values
        rows.append({'defence': f'simulated {m}' + (' (clean-calibrated)' if thrcol == 'thr_clean' else ''),
                     'scope': 'call-goal tasks', 'n_attack': len(att), 'n_benign': len(none),
                     'ASR': sa.mean(), 'ASR_lo': boot_ci(sa)[0], 'ASR_hi': boot_ci(sa)[1],
                     'benign_utility': bu.mean(), 'BU_lo': boot_ci(bu)[0], 'BU_hi': boot_ci(bu)[1],
                     'utility_under_attack': ua.mean(), 'UA_lo': boot_ci(ua)[0], 'UA_hi': boot_ci(ua)[1]})
L = pd.DataFrame(rows)
L.to_csv(os.path.join(RES, 'ALL_literature_comparison.csv'), index=False)
print(L.round(3).to_string())
