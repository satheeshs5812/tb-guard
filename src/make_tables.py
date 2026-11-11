"""Render result CSVs into markdown tables (results/tables_autogen.md)."""
import sys, os
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(__file__))
from common import *

out = []
LBL = {'TB_Guard': 'TB-Guard (GNN)', 'B5_flat_MLP': 'B5 flat MLP', 'TB_Policy': 'TB-Policy', 'TB_Policy_deleg': 'TB-Policy+deleg',
       'B1_signature': 'B1 signature', 'B2_content_clf': 'B2 content clf', 'B3_strict_taint': 'B3 strict taint',
       'B4_anomaly': 'B4 anomaly', 'TB_Guard_no_deriv': 'TB-Guard - derivation', 'TB_Guard_no_instr': 'TB-Guard - instruction-lik.',
       'TB_Guard_no_endorse': 'TB-Guard - endorsement', 'TB_Guard_lex_only': 'TB-Guard - TF-IDF (lexical only)'}


def ci(r, c, pct=False):
    if pct:
        return f"{100*r[c]:.1f} [{100*r[c+'_lo']:.1f}, {100*r[c+'_hi']:.1f}]"
    return f"{r[c]:.3f} [{r[c+'_lo']:.3f}, {r[c+'_hi']:.3f}]"


def main_tables(exp, suffix='', methods=None):
    p = os.path.join(RES, f'ALL_metrics_{exp}{suffix}.csv')
    if not os.path.exists(p):
        return
    M = pd.read_csv(p)
    if methods:
        M = M[M.method.isin(methods)]
    out.append(f'\n#### {exp}{suffix}: call level (privileged calls; mean [95% bootstrap CI])\n')
    out.append('| method | precision | recall | F1 | FPR (all benign calls) | FPR (calls in benign traces) | AUROC | AUPRC |')
    out.append('|---|---|---|---|---|---|---|---|')
    for _, r in M.iterrows():
        out.append(f"| {LBL.get(r.method, r.method)} | {ci(r,'precision')} | {ci(r,'recall')} | {ci(r,'F1')} | {ci(r,'FPR')} | "
                   f"{ci(r,'FPR_benign_traces')} | {ci(r,'AUROC')} | {ci(r,'AUPRC')} |")
    out.append(f'\n#### {exp}{suffix}: trace level under the runtime blocking protocol (%)\n')
    out.append(f"ASR without monitor = {100*M.ASR_before.iloc[0]:.1f}%; benign utility without monitor = {100*M.utility_before.iloc[0]:.1f}%; utility under attack without monitor = {100*M.util_under_attack_before.iloc[0]:.1f}%\n")
    out.append('| method | ASR after | prevention rate | benign traces unblocked (utility retained) | benign utility after | utility under attack after | calls from 1st untrusted read to block |')
    out.append('|---|---|---|---|---|---|---|')
    for _, r in M.iterrows():
        out.append(f"| {LBL.get(r.method, r.method)} | {ci(r,'ASR_after',1)} | {ci(r,'prevention_rate',1)} | {ci(r,'utility_retained',1)} | "
                   f"{ci(r,'utility_after',1)} | {ci(r,'util_under_attack_after',1)} | {r.calls_from_first_untrusted_to_block:.2f} |")


def stats(exp):
    p = os.path.join(RES, f'ALL_stats_{exp}.csv')
    if not os.path.exists(p):
        return
    S = pd.read_csv(p)
    out.append(f'\n#### {exp}: TB-Guard vs. each method (McNemar exact; paired permutation test on AUPRC)\n')
    out.append('| vs | call-level: TB-only correct / other-only correct | McNemar p | discordant OR | prevention: TB-only / other-only | p | benign kept: TB-only / other-only | p | dAUPRC (rank-based) | 95% boot CI | perm. p |')
    out.append('|---|---|---|---|---|---|---|---|---|---|---|')
    for _, r in S.iterrows():
        out.append(f"| {LBL.get(r.vs, r.vs)} | {r.call_TB_only_correct} / {r.call_other_only_correct} | {r.call_mcnemar_p:.2e} | {r.call_discordant_OR:.2f} | "
                   f"{r.prev_TB_only} / {r.prev_other_only} | {r.prev_mcnemar_p:.2e} | {r.benign_kept_TB_only} / {r.benign_kept_other_only} | {r.benign_mcnemar_p:.2e} | "
                   f"{r.dAUPRC_rank:+.3f} | [{r.dAUPRC_boot_lo:+.3f}, {r.dAUPRC_boot_hi:+.3f}] | {r.perm_p:.4f} |")


def perfold(exp):
    p = os.path.join(RES, f'ALL_perfold_{exp}.csv')
    if not os.path.exists(p):
        return
    F = pd.read_csv(p)
    for met in ['AUPRC', 'F1', 'recall', 'FPR']:
        T = F.pivot(index='method', columns='fold', values=met)
        out.append(f'\n#### {exp}: {met} per held-out fold\n')
        out.append('| method | ' + ' | '.join(T.columns) + ' |')
        out.append('|---' * (len(T.columns) + 1) + '|')
        for m, r in T.iterrows():
            out.append(f'| {LBL.get(m, m)} | ' + ' | '.join(f'{v:.3f}' for v in r.values) + ' |')


def breakdown(exp, by, methods=('TB_Guard', 'B5_flat_MLP', 'B1_signature', 'B2_content_clf', 'B3_strict_taint')):
    p = os.path.join(RES, f'ALL_breakdown_{exp}.csv')
    if not os.path.exists(p):
        return
    B = pd.read_csv(p)
    B = B[(B.by == by) & B.method.isin(methods)]
    out.append(f'\n#### {exp}: breakdown by {by}\n')
    out.append('| ' + by + ' | method | traces | priv. calls | violations | AUPRC | recall | FPR | ASR before | ASR after | utility retained |')
    out.append('|---|---|---|---|---|---|---|---|---|---|---|')
    for _, r in B.sort_values(['value', 'method']).iterrows():
        f = lambda v, pct=False: ('-' if pd.isna(v) else (f'{100*v:.1f}' if pct else f'{v:.3f}'))
        out.append(f"| {r.value} | {LBL.get(r.method, r.method)} | {r.n_traces} | {r.n_calls} | {r.n_viol} | {f(r.AUPRC)} | {f(r.recall)} | {f(r.FPR)} | "
                   f"{f(r.ASR_before, 1)} | {f(r.ASR_after, 1)} | {f(r.utility_retained, 1)} |")


def sens():
    p = os.path.join(RES, 'ALL_fpr_sensitivity_E1.csv')
    if os.path.exists(p):
        S = pd.read_csv(p)
        S = S[S.method.isin(['TB_Guard', 'B5_flat_MLP', 'B2_content_clf', 'B4_anomaly'])]
        out.append('\n#### E1: sensitivity to the validation FPR target\n')
        out.append('| method | FPR target | precision | recall | F1 | test FPR | ASR after (%) | prevention (%) | utility retained (%) |')
        out.append('|---|---|---|---|---|---|---|---|---|')
        for _, r in S.iterrows():
            out.append(f"| {LBL.get(r.method)} | {r.fpr_target} | {r.precision:.3f} | {r.recall:.3f} | {r.F1:.3f} | {r.FPR:.3f} | {100*r.ASR_after:.1f} | {100*r.prevention_rate:.1f} | {100*r.utility_retained:.1f} |")
    p = os.path.join(RES, 'ALL_tau_sensitivity.csv')
    if os.path.exists(p):
        S = pd.read_csv(p)
        out.append('\n#### E1: sensitivity to the fuzzy-derivation threshold tau\n')
        out.append('| tau | method | AUPRC | F1 | recall | FPR | ASR after (%) | utility retained (%) |')
        out.append('|---|---|---|---|---|---|---|---|')
        for _, r in S.iterrows():
            out.append(f"| {r.tau} | {LBL.get(r.method, r.method)} | {r.AUPRC:.3f} | {r.F1:.3f} | {r.recall:.3f} | {r.FPR:.3f} | {100*r.ASR_after:.1f} | {100*r.utility_retained:.1f} |")


def lit():
    p = os.path.join(RES, 'ALL_literature_comparison.csv')
    if not os.path.exists(p):
        return
    L = pd.read_csv(p)
    out.append('\n#### Literature comparison (gpt-4o-2024-05-13, important_instructions; %, 95% bootstrap CI)\n')
    out.append('| defence | scope | n attack | n benign | ASR | benign utility | utility under attack |')
    out.append('|---|---|---|---|---|---|---|')
    for _, r in L.iterrows():
        out.append(f"| {r.defence} | {r.scope} | {r.n_attack} | {r.n_benign} | {100*r.ASR:.1f} [{100*r.ASR_lo:.1f}, {100*r.ASR_hi:.1f}] | "
                   f"{100*r.benign_utility:.1f} [{100*r.BU_lo:.1f}, {100*r.BU_hi:.1f}] | {100*r.utility_under_attack:.1f} [{100*r.UA_lo:.1f}, {100*r.UA_hi:.1f}] |")


def latency():
    p = os.path.join(RES, 'ALL_latency_summary.csv')
    if os.path.exists(p):
        L = pd.read_csv(p, index_col=0)
        out.append('\n#### Latency per check (ms, CPU, 1 thread, n=500 privileged calls)\n')
        out.append('| component | mean | median | p95 | max |')
        out.append('|---|---|---|---|---|')
        for k, r in L.iterrows():
            out.append(f'| {k} | {r.mean_ms:.2f} | {r.median_ms:.2f} | {r.p95_ms:.2f} | {r.max_ms:.2f} |')


main_tables('E1')
main_tables('E1', '_cleancal')
stats('E1')
main_tables('E2'); stats('E2'); perfold('E2')
main_tables('E3'); stats('E3'); perfold('E3')
perfold('E1')
for by in ['attack', 'suite', 'pipe_dir']:
    breakdown('E1', by)
sens(); lit(); latency()
open(os.path.join(RES, 'tables_autogen.md'), 'w').write('\n'.join(out) + '\n')
print('\n'.join(out)[:3000])
