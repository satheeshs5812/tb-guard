"""Metrics, bootstrap CIs, McNemar exact tests, permutation tests, breakdowns.

usage: python src/analysis.py E1 [--tag X] [--nboot 1000] [--nperm 1000] [--stats]
"""
import sys, os, json, pickle, argparse, time
import numpy as np, pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score
from scipy.stats import binomtest
sys.path.insert(0, os.path.dirname(__file__))
from common import *

METHOD_ORDER = ['TB_Guard', 'TB_Policy', 'TB_Policy_deleg', 'B1_signature', 'B2_content_clf', 'B3_strict_taint',
                'B4_anomaly', 'B5_flat_MLP', 'TB_Guard_no_deriv', 'TB_Guard_no_instr', 'TB_Guard_no_endorse',
                'TB_Guard_lex_only']


def trace_info():
    p = os.path.join(DATA, 'trace_info.csv')
    if os.path.exists(resolve(p)):
        return read_csv(p).set_index('tid')
    D = pickle.load(open(os.path.join(DATA, 'graphs_tau0.6.pkl'), 'rb'))
    rows = [{'tid': g['tid'], 'first_low_step': g['first_low_step'] if g['first_low_step'] is not None else -1,
             'n_calls': g['n_calls_total'], 'n_priv': len(g['labels'])} for g in D['G']]
    df = pd.DataFrame(rows)
    df.to_csv(p, index=False)
    return df.set_index('tid')


def load(exp, tag=''):
    P = read_csv(os.path.join(RES, f'ALL_predictions_{exp}{tag}.csv'))
    TR = read_csv(os.path.join(DATA, 'trace_table.csv')).set_index('tid')
    TI = trace_info()
    return P, TR, TI


def trace_outcomes(Pm, traces, thrcol='thr'):
    """Pm: predictions for one method (calls of test traces). traces: DataFrame of test traces (index tid)."""
    d = Pm.assign(dec=Pm.score > Pm[thrcol])
    blk = d[d.dec].groupby('tid').k.min()
    vio = d[d.label == 1].groupby('tid').k.min()
    step_blk = d[d.dec].sort_values('k').groupby('tid').ci.first()
    out = traces[['attack', 'security', 'utility', 'suite', 'pipe_dir', 'family']].copy()
    out['blocked_k'] = blk.reindex(out.index)
    out['viol_k'] = vio.reindex(out.index)
    out['any_block'] = out.blocked_k.notna()
    out['is_attack'] = out.attack != 'none'
    out['prevented'] = out.security & out.is_attack & out.viol_k.notna() & out.any_block & (out.blocked_k <= out.viol_k)
    out['succ_after'] = out.security & out.is_attack & ~out.prevented
    out['block_ci'] = step_blk.reindex(out.index)
    return out


def call_metrics(y, s, dec, w=None, none_mask=None):
    if w is None:
        w = np.ones(len(y))
    tp = (w * (dec & (y == 1))).sum(); fp = (w * (dec & (y == 0))).sum()
    fn = (w * (~dec & (y == 1))).sum(); tn = (w * (~dec & (y == 0))).sum()
    prec = tp / (tp + fp) if tp + fp > 0 else 0.0
    rec = tp / (tp + fn) if tp + fn > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec > 0 else 0.0
    fpr = fp / (fp + tn) if fp + tn > 0 else 0.0
    m = {'precision': prec, 'recall': rec, 'F1': f1, 'FPR': fpr}
    try:
        m['AUROC'] = roc_auc_score(y, s, sample_weight=w)
        m['AUPRC'] = average_precision_score(y, s, sample_weight=w)
    except ValueError:
        m['AUROC'] = m['AUPRC'] = np.nan
    if none_mask is not None:
        wn = w * none_mask
        m['FPR_benign_traces'] = (wn * dec).sum() / wn.sum() if wn.sum() > 0 else np.nan
    return m


def trace_metrics(o, w=None):
    if w is None:
        w = np.ones(len(o))
    att = o.is_attack.values; none = ~att
    sec = o.security.values; util = o.utility.values; blk = o.any_block.values
    wa, wn = w * att, w * none
    m = {}
    m['ASR_before'] = (wa * sec).sum() / wa.sum()
    m['ASR_after'] = (wa * o.succ_after.values).sum() / wa.sum()
    m['prevention_rate'] = (wa * o.prevented.values).sum() / max(1e-9, (wa * sec).sum())
    m['utility_retained'] = (wn * ~blk).sum() / wn.sum()
    m['false_block_rate'] = 1 - m['utility_retained']
    m['utility_before'] = (wn * util).sum() / wn.sum()
    m['utility_after'] = (wn * (util & ~blk)).sum() / wn.sum()
    m['util_under_attack_before'] = (wa * util).sum() / wa.sum()
    m['util_under_attack_after'] = (wa * (util & ~blk)).sum() / wa.sum()
    return m


def bootstrap(P, traces, methods, nboot, seed=SEED, thrcol='thr'):
    """Trace-level bootstrap: resample test traces with replacement."""
    rng = np.random.RandomState(seed)
    tids = traces.index.values
    pos = {t: i for i, t in enumerate(tids)}
    res = {m: [] for m in methods}
    pre = {}
    for m in methods:
        Pm = P[P.method == m]
        ti = Pm.tid.map(pos).values
        o = trace_outcomes(Pm, traces, thrcol)
        pre[m] = (Pm.label.values, Pm.score.values, (Pm.score > Pm[thrcol]).values, ti, o,
                  (Pm.tid.map(traces.attack) == 'none').values.astype(float))
    for b in range(nboot):
        cnt = np.bincount(rng.randint(0, len(tids), len(tids)), minlength=len(tids)).astype(float)
        for m in methods:
            y, s, dec, ti, o, nm = pre[m]
            w = cnt[ti]
            cm = call_metrics(y, s, dec, w, nm)
            tm = trace_metrics(o, cnt)
            res[m].append({**cm, **tm})
    out = {}
    for m in methods:
        df = pd.DataFrame(res[m])
        out[m] = (df.quantile(0.025), df.quantile(0.975), df)
    return out


def mcnemar(a, b):
    """a, b boolean arrays: correctness of method A / method B on the same items."""
    n01 = int((a & ~b).sum()); n10 = int((~a & b).sum())
    p = binomtest(n01, n01 + n10, 0.5).pvalue if n01 + n10 > 0 else 1.0
    orr = (n01 + 0.5) / (n10 + 0.5)
    return n01, n10, p, orr


def perm_test_auprc(PA, PB, nperm, seed=SEED):
    """Paired permutation test (trace-clustered) for AUPRC difference A-B using within-method percentile ranks."""
    rng = np.random.RandomState(seed)
    PA = PA.sort_values(['tid', 'k']); PB = PB.sort_values(['tid', 'k'])
    y = PA.label.values
    ra = PA.score.rank(pct=True).values; rb = PB.score.rank(pct=True).values
    obs = average_precision_score(y, ra) - average_precision_score(y, rb)
    codes, uniq = pd.factorize(PA.tid)
    ge = 0
    for _ in range(nperm):
        sw = rng.rand(len(uniq)) < 0.5
        s = sw[codes]
        a2 = np.where(s, rb, ra); b2 = np.where(s, ra, rb)
        d = average_precision_score(y, a2) - average_precision_score(y, b2)
        ge += abs(d) >= abs(obs) - 1e-12
    return obs, (ge + 1) / (nperm + 1)


def fmt(v, lo, hi, pct=False):
    if pct:
        return f'{100 * v:.1f} [{100 * lo:.1f}, {100 * hi:.1f}]'
    return f'{v:.3f} [{lo:.3f}, {hi:.3f}]'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('exp')
    ap.add_argument('--tag', default='')
    ap.add_argument('--nboot', type=int, default=1000)
    ap.add_argument('--nperm', type=int, default=1000)
    ap.add_argument('--stats', action='store_true')
    a = ap.parse_args()
    t0 = time.time()
    P, TR, TI = load(a.exp, a.tag)
    traces = TR.loc[TI.index]  # all corpus traces are test exactly once in E1/E2/E3
    methods = [m for m in METHOD_ORDER if m in set(P.method)]
    for thrcol, suffix in [('thr_clean', '_cleancal'), ('thr', '')]:
        M = main_table(P, traces, TI, methods, thrcol, a)
        M.to_csv(os.path.join(RES, f'ALL_metrics_{a.exp}{a.tag}{suffix}.csv'), index=False)
        print(thrcol)
        print(M[['method', 'precision', 'recall', 'F1', 'FPR', 'FPR_benign_traces', 'AUPRC', 'ASR_before', 'ASR_after',
                 'prevention_rate', 'utility_retained', 'util_under_attack_before', 'util_under_attack_after']].round(3).to_string())
    _rest(P, traces, TI, methods, a, t0)


def main_table(P, traces, TI, methods, thrcol, a):
    rows = []
    for m in methods:
        Pm = P[P.method == m]
        cm = call_metrics(Pm.label.values, Pm.score.values, (Pm.score > Pm[thrcol]).values, None,
                          (Pm.tid.map(traces.attack) == 'none').values.astype(float))
        o = trace_outcomes(Pm, traces, thrcol)
        tm = trace_metrics(o)
        # timeliness
        prev = o[o.prevented]
        fl = TI.loc[prev.index, 'first_low_step']
        gap = (prev.block_ci.values + 1 - fl.values)
        tm['blocked_before_exec'] = 1.0 if len(prev) else np.nan
        tm['calls_from_first_untrusted_to_block'] = float(np.mean(gap[fl.values >= 0])) if len(prev) else np.nan
        rows.append({'exp': a.exp, 'method': m, **cm, **tm})
    M = pd.DataFrame(rows)
    # bootstrap
    B = bootstrap(P, traces, methods, a.nboot, thrcol=thrcol)
    for col in ['precision', 'recall', 'F1', 'FPR', 'AUROC', 'AUPRC', 'FPR_benign_traces', 'ASR_after',
                'prevention_rate', 'utility_retained', 'utility_after', 'false_block_rate', 'util_under_attack_after']:
        M[col + '_lo'] = [B[m][0][col] for m in methods]
        M[col + '_hi'] = [B[m][1][col] for m in methods]
    if thrcol == 'thr':
        global BOOT
        BOOT = B
    return M


def _rest(P, traces, TI, methods, a, t0):
    # per-fold metrics (generalisation heatmaps)
    fr = []
    for (m, f), Pf in P.groupby(['method', 'fold']):
        cm = call_metrics(Pf.label.values, Pf.score.values, (Pf.score > Pf.thr).values)
        tt = traces.loc[traces.index.isin(Pf.tid.unique()) | False]
        fr.append({'exp': a.exp, 'method': m, 'fold': f, **cm})
    pd.DataFrame(fr).to_csv(os.path.join(RES, f'ALL_perfold_{a.exp}{a.tag}.csv'), index=False)
    # FPR-target sensitivity
    sens = []
    for m in methods:
        Pm = P[P.method == m]
        for tc, tgt in [('thr_0.005', 0.005), ('thr', 0.01), ('thr_0.02', 0.02), ('thr_0.05', 0.05)]:
            dec = (Pm.score > Pm[tc]).values
            cm = call_metrics(Pm.label.values, Pm.score.values, dec)
            tm = trace_metrics(trace_outcomes(Pm, traces, tc))
            sens.append({'method': m, 'fpr_target': tgt, **{k: cm[k] for k in ['precision', 'recall', 'F1', 'FPR']},
                         **{k: tm[k] for k in ['ASR_after', 'prevention_rate', 'utility_retained']}})
    pd.DataFrame(sens).to_csv(os.path.join(RES, f'ALL_fpr_sensitivity_{a.exp}{a.tag}.csv'), index=False)
    if not a.stats:
        print('done', time.time() - t0)
        return
    # statistical tests: TB-Guard vs each other method
    st = []
    A = P[P.method == 'TB_Guard'].sort_values(['tid', 'k'])
    oA = trace_outcomes(A, traces)
    for m in methods:
        if m == 'TB_Guard':
            continue
        Bm = P[P.method == m].sort_values(['tid', 'k'])
        ca = ((A.score > A.thr).values == (A.label == 1).values)
        cb = ((Bm.score > Bm.thr).values == (Bm.label == 1).values)
        n01, n10, p, orr = mcnemar(ca, cb)
        oB = trace_outcomes(Bm, traces)
        succ = oA.security & oA.is_attack
        t01, t10, tp_, tor = mcnemar(oA.prevented[succ].values, oB.prevented[succ].values)
        nn_ = ~oA.is_attack
        u01, u10, up_, uor = mcnemar(~oA.any_block[nn_].values, ~oB.any_block[nn_].values)
        dAP, pperm = perm_test_auprc(A, Bm, a.nperm)
        dlo = np.quantile(BOOT['TB_Guard'][2].AUPRC.values - BOOT[m][2].AUPRC.values, [0.025, 0.975])
        st.append({'exp': a.exp, 'vs': m, 'call_TB_only_correct': n01, 'call_other_only_correct': n10,
                   'call_mcnemar_p': p, 'call_discordant_OR': orr,
                   'prev_TB_only': t01, 'prev_other_only': t10, 'prev_mcnemar_p': tp_, 'prev_OR': tor,
                   'benign_kept_TB_only': u01, 'benign_kept_other_only': u10, 'benign_mcnemar_p': up_,
                   'dAUPRC_rank': dAP, 'dAUPRC_boot_lo': dlo[0], 'dAUPRC_boot_hi': dlo[1], 'perm_p': pperm})
    S = pd.DataFrame(st)
    S.to_csv(os.path.join(RES, f'ALL_stats_{a.exp}{a.tag}.csv'), index=False)
    print(S.round(4).to_string())
    # breakdowns
    br = []
    for m in methods:
        Pm = P[P.method == m]
        o = trace_outcomes(Pm, traces)
        Pm = Pm.join(traces[['attack', 'suite', 'pipe_dir']], on='tid')
        for key in ['attack', 'suite', 'pipe_dir']:
            for val, sub in o.groupby(key):
                cs = Pm[Pm[key] == val]
                cm = call_metrics(cs.label.values, cs.score.values, (cs.score > cs.thr).values) if len(cs) else {}
                att = sub[sub.is_attack]; nn_ = sub[~sub.is_attack]
                br.append({'method': m, 'by': key, 'value': val, 'n_traces': len(sub), 'n_calls': len(cs),
                           'n_viol': int(cs.label.sum()) if len(cs) else 0,
                           'ASR_before': att.security.mean() if len(att) else np.nan,
                           'ASR_after': att.succ_after.mean() if len(att) else np.nan,
                           'prevention_rate': att.prevented.sum() / max(1, att.security.sum()) if len(att) else np.nan,
                           'utility_retained': (~nn_.any_block).mean() if len(nn_) else np.nan,
                           **{k: cm.get(k, np.nan) for k in ['precision', 'recall', 'F1', 'FPR', 'AUPRC']}})
    pd.DataFrame(br).to_csv(os.path.join(RES, f'ALL_breakdown_{a.exp}{a.tag}.csv'), index=False)
    print('done', time.time() - t0)


if __name__ == '__main__':
    main()
