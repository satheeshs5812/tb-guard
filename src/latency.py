"""Per-check latency of TB-Guard (prefix provenance-graph construction + line scoring + GNN forward) and baselines
on CPU. Measures the full (non-incremental) recomputation for the trace prefix before each privileged call,
i.e. an upper bound for an incremental implementation."""
import pickle, sys, os, time, copy, re
import numpy as np, pandas as pd, torch
sys.path.insert(0, os.path.dirname(__file__))
from common import *
import build_graphs as BG
from models import TBGNN, ETYPE_GROUPS, signature_scores, CI

torch.set_num_threads(1)
aux = pickle.load(open(os.path.join(MODELS, 'tbguard_E1_fold0_aux.pkl'), 'rb'))
model = TBGNN(aux['din']); model.load_state_dict(torch.load(os.path.join(MODELS, 'tbguard_E1_fold0.pt'))); model.eval()
lc, mu, sd = aux['lc'], aux['mu'], aux['sd']
T = pickle.load(open(os.path.join(DATA, 'traces_main.pkl'), 'rb'))
tr = read_csv(os.path.join(DATA, 'trace_table.csv')).set_index('tid')
T = [t for t in T if not t['defended'] and not tr.loc[t['tid'], 'textonly_goal']]
rng = np.random.RandomState(SEED)
cands = []
for t in T:
    for mi, m in enumerate(t['msgs']):
        if m['role'] == 'assistant':
            for j, c in enumerate(m.get('calls') or []):
                if privilege(c['fn']) > 0:
                    cands.append((t, mi, j))
sel = [cands[i] for i in rng.choice(len(cands), 500, replace=False)]


def prefix(t, mi, j):
    p = copy.copy(t)
    msgs = [dict(m) for m in t['msgs'][:mi + 1]]
    msgs[-1]['calls'] = msgs[-1]['calls'][:j + 1]
    p['msgs'] = msgs
    p['attack'] = 'none'; p['injections'] = {}
    return p


lat = {'TB_Guard_total': [], 'TB_graph_build': [], 'TB_line_scoring': [], 'TB_gnn_forward': [],
       'B1_signature': [], 'B2_content_clf': [], 'n_nodes': []}
for t, mi, j in sel:
    p = prefix(t, mi, j)
    t0 = time.perf_counter()
    g = BG.build(p)
    t1 = time.perf_counter()
    S_lines = lc.score(g['out_lines']) if g['out_lines'] else np.zeros(0)
    t2 = time.perf_counter()
    k = len(g['labels']) - 1
    n = g['n_out_lines'][k]
    s = S_lines
    s_low = np.where(g['out_low'], s, 0) if len(s) else s
    ctx = s_low[:n].max() if n > 0 else 0.0
    # derivation lines are local indices here (no global vocab)
    dl = g['deriv_lines'][k]
    src = s[np.array(dl, dtype=int)].max() if len(dl) else 0.0
    CF = np.concatenate([g['CF'][k], [src, ctx]]).astype(np.float32)
    CFn = (CF - mu) / sd
    xs = np.zeros(len(g['X']), np.float32)
    if len(s):
        np.maximum.at(xs, g['out_resnode'], s.astype(np.float32))
    for seg, li in g['line_nodes']:
        xs[seg] = s[li]
    X = np.concatenate([g['X'], xs[:, None], np.zeros((len(g['X']), len(CF)), np.float32)], 1)
    X[g['call_nodes'][k], -len(CF):] = CFn
    e = g['edges']
    rel = np.array([ETYPE_GROUPS[int(x)] for x in e[2]], dtype=np.int64)
    with torch.no_grad():
        sc = torch.sigmoid(model(torch.from_numpy(X.astype(np.float32)), torch.from_numpy(e[0]), torch.from_numpy(e[1]),
                                 torch.from_numpy(rel), torch.tensor([g['call_nodes'][k]]))).item()
    t3 = time.perf_counter()
    lat['TB_Guard_total'].append(1000 * (t3 - t0)); lat['TB_graph_build'].append(1000 * (t1 - t0))
    lat['TB_line_scoring'].append(1000 * (t2 - t1)); lat['TB_gnn_forward'].append(1000 * (t3 - t2))
    lat['n_nodes'].append(len(g['X']))
    # baselines on the same prefix (outputs only)
    outs = [m['text'] for m in p['msgs'] if m['role'] == 'tool']
    lines = [l for o in outs for l in BG.split_lines(o)]
    a = time.perf_counter(); signature_scores(lines).sum(); b = time.perf_counter()
    (lc.score(lines).max() if lines else 0); c = time.perf_counter()
    lat['B1_signature'].append(1000 * (b - a)); lat['B2_content_clf'].append(1000 * (c - b))
L = pd.DataFrame(lat)
L.to_csv(os.path.join(RES, 'ALL_latency_raw.csv'), index=False)
summ = pd.DataFrame({'mean_ms': L.mean(), 'median_ms': L.median(), 'p95_ms': L.quantile(0.95), 'max_ms': L.max()})
summ.to_csv(os.path.join(RES, 'ALL_latency_summary.csv'))
print(summ.round(3))
