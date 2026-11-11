"""Error analysis of TB-Guard (E1 out-of-fold) false positives / negatives with categories and short examples."""
import sys, os, pickle, re, json
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(__file__))
from common import *
from models import CI

P = read_csv(os.path.join(RES, 'ALL_predictions_E1.csv'))
A = P[P.method == 'TB_Guard'].copy()
D = pickle.load(open(os.path.join(DATA, 'graphs_tau0.6.pkl'), 'rb'))
cf = {}
ut = {}
for g in D['G']:
    ut[g['tid']] = g['user_text']
    for k in range(len(g['labels'])):
        cf[(g['tid'], k)] = g['CF'][k]
TR = read_csv(os.path.join(DATA, 'trace_table.csv')).set_index('tid')
calls = read_csv(os.path.join(DATA, 'call_table.csv')).set_index(['tid', 'ci'])
A['dec'] = A.score > A.thr
A = A.join(TR[['attack', 'suite', 'pipe_dir', 'security']], on='tid')


def cat_fp(r):
    f = cf[(r.tid, r.k)]
    if r.attack == 'none':
        if f[CI['any_low']] and f[CI['delegated']]:
            return 'benign trace: user-delegated action on LOW data (e.g. bill/file/email content)'
        if f[CI['any_low']]:
            return 'benign trace: argument derived from LOW data, no explicit delegation'
        return 'benign trace: no LOW derivation (behavioural features)'
    if f[CI['any_low']] and f[CI['srclex10']] > 0.2:
        return 'injected trace: benign call deriving from instruction-like LOW segment'
    if f[CI['log_n_low_res']] > 0:
        return 'injected trace: benign call after injection was read (collateral)'
    return 'injected trace: other'


def cat_fn(r):
    f = cf[(r.tid, r.k)]
    if not f[CI['any_low']]:
        if f[CI['frac_underived']] > 0.99:
            return 'no argument derivable from any source (paraphrased/hallucinated values)'
        return 'arguments derived only from MED/HIGH content (e.g. via agent text, or self-owned data)'
    if f[CI['frac_endorsed']] > 0:
        return 'attacker value also present in user/system content (endorsed)'
    return 'LOW-derived but scored below threshold'


fp = A[A.dec & (A.label == 0)].copy(); fp['category'] = fp.apply(cat_fp, axis=1)
fn = A[~A.dec & (A.label == 1)].copy(); fn['category'] = fn.apply(cat_fn, axis=1)


def anon(s):
    s = re.sub(r'[\w.\-]+@[\w.\-]+', '<email>', str(s))
    s = re.sub(r'\b[A-Z]{2}\d{10,30}\b', '<IBAN>', s)
    return s


rows = []
for name, df in [('FP', fp), ('FN', fn)]:
    for c, sub in df.groupby('category'):
        ex = sub.sample(min(2, len(sub)), random_state=SEED)
        exs = []
        for _, r in ex.iterrows():
            a = calls.loc[(r.tid, r.ci), 'args'] if (r.tid, r.ci) in calls.index else ''
            exs.append(f"[{r.pipe_dir} | {r.suite} | {r.attack}] user: \"{anon(ut[r.tid])[:110]}\" -> {r.fn}({anon(a)[:110]}) score={r.score:.2f}")
        rows.append({'type': name, 'category': c, 'count': len(sub), 'share': len(sub) / len(df), 'examples': ' || '.join(exs)})
E = pd.DataFrame(rows).sort_values(['type', 'count'], ascending=[True, False])
E.to_csv(os.path.join(RES, 'ALL_error_analysis.csv'), index=False)
pd.concat([fp, fn]).to_csv(os.path.join(RES, 'ALL_errors_TBGuard_E1.csv'), index=False)
for _, r in E.iterrows():
    print(r.type, r['count'], f'{r.share:.2f}', r.category)
    print('   ', r.examples[:600])
