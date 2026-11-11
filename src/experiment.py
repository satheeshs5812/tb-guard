"""Run detectors under E1 (grouped 5-fold CV by (suite,user_task,injection_task)), E2 (leave-one-suite-out),
E3 (leave-one-model-family-out). Saves per-call predictions with fold-wise thresholds.

usage: python src/experiment.py E1|E2|E3 [--tau 0.6] [--ablate] [--only tbguard,mlp] [--tag _X] [--fpr 0.01]
"""
import pickle, sys, os, time, json, argparse
import numpy as np, pandas as pd, torch
from sklearn.model_selection import GroupKFold
from sklearn.ensemble import IsolationForest
sys.path.insert(0, os.path.dirname(__file__))
from common import *
from models import *

ap = argparse.ArgumentParser()
ap.add_argument('exp')
ap.add_argument('--tau', type=float, default=0.6)
ap.add_argument('--ablate', action='store_true')
ap.add_argument('--only', default='')  # restrict methods, e.g. 'tbguard,policy,mlp'
ap.add_argument('--tag', default='')
ap.add_argument('--fpr', type=float, default=0.01)
args = ap.parse_args()

t0 = time.time()
D = pickle.load(open(os.path.join(DATA, f'graphs_tau{args.tau}.pkl'), 'rb'))
G, LINES = D['G'], D['lines']
TR = read_csv(os.path.join(DATA, 'trace_table.csv')).set_index('tid')
tids = np.array([g['tid'] for g in G])
meta = TR.loc[tids]
SIG = signature_scores(LINES)
print('loaded', len(G), 'traces', time.time() - t0, flush=True)

# --------------- call table ---------------
rows = []
for gi, g in enumerate(G):
    for k in range(len(g['labels'])):
        rows.append((gi, g['tid'], k, int(g['ci'][k]), g['fn'][k], int(g['labels'][k]), int(g['step'][k])))
CALLS = pd.DataFrame(rows, columns=['gi', 'tid', 'k', 'ci', 'fn', 'label', 'step'])
CALLS = CALLS.join(meta[['pipe_dir', 'family', 'suite', 'user_task', 'inj_task', 'attack', 'security', 'utility']], on='tid')
CF_BASE = np.concatenate([g['CF'] for g in G if len(g['labels'])]).astype(np.float32)
assert len(CF_BASE) == len(CALLS)
call_off = np.cumsum([0] + [len(g['labels']) for g in G])


def groups_for(exp):
    m = meta.reset_index()
    if exp == 'E1':
        grp = (m.suite + '|' + m.user_task + '|' + m.inj_task).values
        uniq = np.unique(grp)
        rng = np.random.RandomState(SEED)
        perm = rng.permutation(len(uniq))
        fold_of = {u: perm[i] % 5 for i, u in enumerate(uniq)}
        f = np.array([fold_of[x] for x in grp])
        return [(f'fold{k}', f == k) for k in range(5)], grp
    if exp == 'E2':
        return [(s, (m.suite == s).values) for s in ['banking', 'slack', 'travel', 'workspace']], \
            (m.suite + '|' + m.user_task + '|' + m.inj_task).values
    if exp == 'E3':
        return [(f, (m.family == f).values) for f in ['GPT', 'Claude', 'Gemini', 'Llama', 'Cohere']], \
            (m.suite + '|' + m.user_task + '|' + m.inj_task).values


def val_split(train_mask, grp, seed):
    idx = np.where(train_mask)[0]
    ug = np.unique(grp[idx])
    rng = np.random.RandomState(seed)
    vg = set(rng.choice(ug, size=max(1, int(0.15 * len(ug))), replace=False))
    va = np.array([i for i in idx if grp[i] in vg])
    tr = np.array([i for i in idx if grp[i] not in vg])
    return tr, va


def fold_features(S):
    """Given per-unique-line instruction score S, compute fold-specific call features and node features."""
    tf_src, tf_ctx, b2, b1 = [], [], [], []
    Xs = []
    for g in G:
        lid = g['line_ids']
        s = S[lid] if len(lid) else np.zeros(0)
        sig = SIG[lid] if len(lid) else np.zeros(0)
        cm_all = np.maximum.accumulate(s) if len(s) else s
        s_low = np.where(g['out_low'], s, 0) if len(s) else s
        cm_low = np.maximum.accumulate(s_low) if len(s) else s
        cs_sig = np.cumsum(sig) if len(sig) else sig
        for k in range(len(g['labels'])):
            n = g['n_out_lines'][k]
            b2.append(cm_all[n - 1] if n > 0 else 0.0)
            tf_ctx.append(cm_low[n - 1] if n > 0 else 0.0)
            b1.append(cs_sig[n - 1] if n > 0 else 0.0)
            dl = g['deriv_lines'][k]
            tf_src.append(S[dl].max() if len(dl) else 0.0)
        # node feature: S for segment nodes and result nodes (max over its lines)
        xs = np.zeros(len(g['X']), dtype=np.float32)
        if len(lid):
            np.maximum.at(xs, g['out_resnode'], s.astype(np.float32))
        for seg, l in g['line_nodes']:
            xs[seg] = S[l]
        Xs.append(xs)
    return np.array(tf_src, np.float32), np.array(tf_ctx, np.float32), np.array(b2), np.array(b1), Xs


def make_store(CF, Xs, variant, mu, sd):
    items = []
    CFn = (CF - mu) / sd
    for gi, g in enumerate(G):
        X = np.concatenate([g['X'], Xs[gi][:, None]], 1)
        e = g['edges']
        rel = np.array([ETYPE_GROUPS[int(t)] for t in e[2]], dtype=np.int64) if e.shape[1] else np.zeros(0, np.int64)
        if variant == 'no_deriv':
            keep = ~np.isin(rel, [3, 4])
            e, rel = e[:, keep], rel[keep]
        if variant == 'no_endorse':
            keep = rel != 5
            e, rel = e[:, keep], rel[keep]
            X[:, X_ENDORSE] = 0
        if variant == 'no_instr':
            X[:, X_LEX] = 0; X[:, -1] = 0
        if variant == 'lex_only':
            X[:, -1] = 0
        pad = np.zeros((len(X), CF.shape[1]), np.float32)
        c0, c1 = call_off[gi], call_off[gi + 1]
        if c1 > c0:
            pad[g['call_nodes']] = CFn[c0:c1]
        items.append({'X': np.concatenate([X, pad], 1).astype(np.float32), 'edges': e[:2], 'rel': rel,
                      'call_nodes': g['call_nodes'], 'y': g['labels']})
    return GraphStore(items)


def variant_cf(CF, variant):
    CF = CF.copy()
    if variant == 'no_deriv':
        CF[:, DERIV_COLS] = 0
    if variant == 'no_instr':
        CF[:, INSTR_COLS] = 0
    if variant == 'no_endorse':
        CF[:, ENDORSE_COLS] = 0
        CF[:, CI['tgt_low_unendorsed']] = CF[:, CI['any_low']]
        CF[:, CI['any_low_unendorsed']] = CF[:, CI['any_low']]
    if variant == 'lex_only':
        CF[:, [CI['tfidf_src_max'], CI['tfidf_ctx_low_max']]] = 0
    return CF


def thr_at_fpr(neg_scores, target):
    if len(neg_scores) == 0:
        return 0.5
    return float(np.quantile(neg_scores, 1 - target, method='higher'))


def markov_b4(train_g, test_calls_g):
    """B4: suite-conditional bigram surprisal of the call given the previous call + IsolationForest."""
    cnt, ctx, vocab = {}, {}, set()
    for gi in train_g:
        g = G[gi]
        if meta.iloc[gi].attack != 'none':
            continue
        s = meta.iloc[gi].suite
        seq = ['<s>'] + g['call_seq']
        for a, b in zip(seq[:-1], seq[1:]):
            cnt[(s, a, b)] = cnt.get((s, a, b), 0) + 1
            ctx[(s, a)] = ctx.get((s, a), 0) + 1
            vocab.add(b)
    V = len(vocab) + 1
    out = []
    for gi, k in test_calls_g:
        g = G[gi]
        s = meta.iloc[gi].suite
        ci = g['ci'][k]
        prev = g['call_seq'][ci - 1] if ci > 0 else '<s>'
        fn = g['call_seq'][ci]
        p = (cnt.get((s, prev, fn), 0) + 0.1) / (ctx.get((s, prev), 0) + 0.1 * V)
        out.append(-np.log(p))
    return np.array(out)


B4_COLS = [CI[c] for c in ['priv1', 'priv2'] + [f'sink{k}' for k in range(6)] +
           ['log_nargs', 'log_n_low_res', 'no_low_res', 'novelty', 'verb_requested', 'prior_same', 'log_step']]


def run():
    folds, grp = groups_for(args.exp)
    all_rows = []
    thr_rows = []
    logs = {}
    variants = ['full']
    if args.ablate:
        variants += ['no_deriv', 'no_instr', 'no_endorse', 'lex_only']
    only = set(args.only.split(',')) if args.only else None
    for fi, (fname, test_mask) in enumerate(folds):
        tf0 = time.time()
        tr_g, va_g = val_split(~test_mask, grp, SEED + fi)
        te_g = np.where(test_mask)[0]
        # ---- line classifier on TRAINING traces only (labels from their `injections` field) ----
        lab = {}
        for gi in tr_g:
            g = G[gi]
            for l, y in zip(g['line_ids'], g['inj_line']):
                lab[l] = max(lab.get(l, 0), int(y))
        lids = np.array(sorted(lab))
        ys = np.array([lab[l] for l in lids])
        lc = LineClassifier().fit([LINES[i] for i in lids], ys)
        S = lc.score(LINES)
        tf_src, tf_ctx, b2, b1, Xs = fold_features(S)
        CF = np.concatenate([CF_BASE, tf_src[:, None], tf_ctx[:, None]], 1)

        def callmask(gs):
            m = np.zeros(len(CALLS), bool)
            for gi in gs:
                m[call_off[gi]:call_off[gi + 1]] = True
            return m
        mtr, mva, mte = callmask(tr_g), callmask(va_g), callmask(te_g)
        y = CALLS.label.values
        scores = {}
        # ---- baselines ----
        scores['B1_signature'] = b1
        scores['B2_content_clf'] = b2
        scores['B3_strict_taint'] = (CF[:, CI['no_low_res']] == 0).astype(float)
        scores['TB_Policy'] = CF[:, CI['any_low_unendorsed']].astype(float)
        scores['TB_Policy_deleg'] = (CF[:, CI['any_low_unendorsed']] * (1 - CF[:, CI['delegated']])).astype(float)
        # B4
        all_calls_g = [(gi, k) for gi in range(len(G)) for k in range(len(G[gi]['labels']))]
        mk = markov_b4(tr_g, all_calls_g)
        ben_tr = mtr & (CALLS.attack.values == 'none')
        iso = IsolationForest(n_estimators=200, random_state=SEED).fit(CF[ben_tr][:, B4_COLS])
        ifs = -iso.score_samples(CF[:, B4_COLS])
        ecdf = lambda ref, x: np.searchsorted(np.sort(ref), x, side='right') / len(ref)
        scores['B4_anomaly'] = 0.5 * ecdf(mk[ben_tr], mk) + 0.5 * ecdf(ifs[ben_tr], ifs)
        # ---- B5 flat MLP and TB-Guard GNN variants ----
        mu = CF[mtr].mean(0); sd = CF[mtr].std(0) + 1e-6
        for v in variants:
            CFv = variant_cf(CF, v)
            if v == 'full' and (only is None or 'mlp' in only):
                Xn = ((CFv - mu) / sd).astype(np.float32)
                mlp = train_nn('mlp', (Xn[mtr], Xn[mva]), None, None, Xn.shape[1], seed=SEED + fi,
                               y_tr=y[mtr], y_va=y[mva], max_epochs=60, patience=6)
                with torch.no_grad():
                    scores['B5_flat_MLP'] = torch.sigmoid(mlp(torch.from_numpy(Xn))).numpy()
            if only is not None and 'tbguard' not in only:
                continue
            store = make_store(CFv, Xs, v, mu, sd)
            din = store.items[0]['X'].shape[1]
            log = []
            model = train_nn('gnn', store, tr_g, va_g, din, seed=SEED + fi, log=log)
            logs[f'{fname}_{v}'] = log
            allg = np.arange(len(G))
            sc, _ = predict_nn('gnn', model, store, allg)
            name = 'TB_Guard' if v == 'full' else f'TB_Guard_{v}'
            scores[name] = sc
            if v == 'full' and fi == 0:
                os.makedirs(MODELS, exist_ok=True)
                torch.save(model.state_dict(), os.path.join(MODELS, f'tbguard_{args.exp}{args.tag}_fold0.pt'))
                pickle.dump({'mu': mu, 'sd': sd, 'lc': lc, 'din': din}, open(os.path.join(MODELS, f'tbguard_{args.exp}{args.tag}_fold0_aux.pkl'), 'wb'))
        # ---- thresholds on validation negatives ----
        binary = {'B3_strict_taint', 'TB_Policy', 'TB_Policy_deleg'}
        for mname, sc in scores.items():
            if mname in binary:
                thr = 0.5
            elif mname == 'B1_signature':
                thr = 0.5  # classic signature semantics: any match
            else:
                thr = thr_at_fpr(sc[mva & (y == 0)], args.fpr)
            thr_rows.append({'exp': args.exp, 'fold': fname, 'method': mname, 'thr': thr})
            d = CALLS[mte][['tid', 'k', 'ci', 'fn', 'label']].copy()
            d['fold'] = fname; d['method'] = mname; d['score'] = sc[mte]; d['thr'] = thr
            # extra thresholds for sensitivity to FPR target (continuous scores)
            nonem = (CALLS.attack.values == 'none')
            d['thr_clean'] = thr if (mname in binary or mname == 'B1_signature') else thr_at_fpr(sc[mva & (y == 0) & nonem], args.fpr)
            for tgt in [0.005, 0.02, 0.05]:
                d[f'thr_{tgt}'] = thr if (mname in binary or mname == 'B1_signature') else thr_at_fpr(sc[mva & (y == 0)], tgt)
            all_rows.append(d)
        print(f'[{args.exp}] fold {fname}: train={len(tr_g)} val={len(va_g)} test={len(te_g)} '
              f'test_calls={mte.sum()} viol={y[mte].sum()} time={time.time() - tf0:.0f}s', flush=True)
    P = pd.concat(all_rows)
    P.to_csv(os.path.join(RES, f'ALL_predictions_{args.exp}{args.tag}.csv'), index=False)
    pd.DataFrame(thr_rows).to_csv(os.path.join(RES, f'thresholds_{args.exp}{args.tag}.csv'), index=False)
    json.dump(logs, open(os.path.join(RES, f'trainlog_{args.exp}{args.tag}.json'), 'w'))
    print('done', time.time() - t0)


if __name__ == '__main__':
    run()
