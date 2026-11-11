"""All paper figures (300 dpi PNG + PDF)."""
import sys, os, json, pickle
import numpy as np, pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.metrics import precision_recall_curve, average_precision_score
sys.path.insert(0, os.path.dirname(__file__))
from common import *

plt.rcParams.update({'font.size': 9, 'axes.titlesize': 10, 'axes.labelsize': 9, 'legend.fontsize': 7.5,
                     'axes.spines.top': False, 'axes.spines.right': False, 'axes.grid': True,
                     'grid.color': '#e6e6e6', 'grid.linewidth': 0.6, 'axes.axisbelow': True,
                     'font.family': 'DejaVu Sans', 'savefig.bbox': 'tight'})
PAL = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#6250d6', '#e34948']
METH = ['TB_Guard', 'B5_flat_MLP', 'TB_Policy', 'B1_signature', 'B2_content_clf', 'B3_strict_taint', 'B4_anomaly']
LABEL = {'TB_Guard': 'TB-Guard (GNN)', 'B5_flat_MLP': 'B5 flat MLP', 'TB_Policy': 'TB-Policy (rule)',
         'B1_signature': 'B1 signature', 'B2_content_clf': 'B2 content clf.', 'B3_strict_taint': 'B3 strict taint',
         'B4_anomaly': 'B4 anomaly', 'TB_Policy_deleg': 'TB-Policy+deleg.'}
COL = {m: PAL[i] for i, m in enumerate(METH)}
MARK = {m: mk for m, mk in zip(METH, ['o', 's', 'D', '^', 'v', 'P', 'X'])}


def save(fig, name):
    for ext in ['png', 'pdf']:
        fig.savefig(os.path.join(FIG, f'{name}.{ext}'), dpi=300)
    plt.close(fig)


def fig1():
    tr = read_csv(os.path.join(DATA, 'trace_table.csv'))
    TI = read_csv(os.path.join(DATA, 'trace_info.csv'))
    c = tr[tr.tid.isin(TI.tid)]
    fig, ax = plt.subplots(1, 3, figsize=(11, 3.4), gridspec_kw={'width_ratios': [1, 1.3, 2.2]})
    s = c.assign(kind=np.where(c.attack == 'none', 'benign (none)', 'injected')).groupby(['suite', 'kind']).size().unstack(fill_value=0)
    x = np.arange(len(s))
    ax[0].bar(x, s['injected'], color=PAL[0], width=0.6, label='injected', edgecolor='white', linewidth=1)
    ax[0].bar(x, s['benign (none)'], bottom=s['injected'], color=PAL[3], width=0.6, label='benign (none)', edgecolor='white', linewidth=1)
    ax[0].set_xticks(x, s.index, rotation=30); ax[0].set_ylabel('traces'); ax[0].set_title('(a) Traces per suite'); ax[0].legend(frameon=False, loc='upper left')
    ax[0].set_ylim(0, 1.25 * s.sum(1).max())
    a = c[c.attack != 'none'].groupby('attack').size().sort_values()
    lab = [l.replace('important_instructions', 'imp_instr') for l in a.index]
    ax[1].barh(lab, a.values, color=PAL[0], height=0.6)
    ax[1].set_xscale('log'); ax[1].set_xlabel('traces (log)'); ax[1].set_title('(b) Injected traces per attack type')
    ii = c[c.attack == 'important_instructions'].groupby('pipe_dir').security.mean().sort_values()
    fam = [model_family(p) for p in ii.index]
    famcol = {'GPT': PAL[0], 'Claude': PAL[1], 'Gemini': PAL[2], 'Llama': PAL[6], 'Cohere': PAL[3]}
    ax[2].barh(np.arange(len(ii)), 100 * ii.values, color=[famcol[f] for f in fam], height=0.65)
    ax[2].set_yticks(np.arange(len(ii)), [p.replace('meta-llama_', '').replace('-Instruct', '') for p in ii.index], fontsize=6.5)
    ax[2].set_xlabel('ASR (%) - important_instructions'); ax[2].set_title('(c) Attack success rate per LLM (undefended)')
    from matplotlib.patches import Patch
    ax[2].legend(handles=[Patch(color=v, label=k) for k, v in famcol.items()], frameon=False, loc='lower right')
    fig.tight_layout()
    save(fig, 'fig1_dataset_overview')


def fig2():
    P = read_csv(os.path.join(RES, 'ALL_predictions_E1.csv'))
    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    for m in METH:
        Pm = P[P.method == m]
        p, r, _ = precision_recall_curve(Pm.label, Pm.score)
        ap = average_precision_score(Pm.label, Pm.score)
        ax.plot(r, p, color=COL[m], lw=2 if m == 'TB_Guard' else 1.4, label=f'{LABEL[m]} (AP={ap:.3f})',
                drawstyle='steps-post')
        d = (Pm.score > Pm.thr)
        tp = (d & (Pm.label == 1)).sum()
        ax.plot(tp / max(1, Pm.label.sum()), tp / max(1, d.sum()), MARK[m], color=COL[m], ms=7, mec='white', mew=1.2)
    base = P[P.method == 'TB_Guard'].label.mean()
    ax.axhline(base, color='#888', ls=':', lw=1)
    ax.text(0.6, base - 0.045, f'prevalence {base:.2f}', color='#666', fontsize=7)
    ax.set_xlabel('recall'); ax.set_ylabel('precision'); ax.set_xlim(0, 1.01); ax.set_ylim(0, 1.02)
    ax.set_title('Call-level precision-recall (E1, pooled out-of-fold)\nmarkers = operating point at 1% val. FPR')
    ax.legend(frameon=False, loc='center left', bbox_to_anchor=(1.01, 0.5), fontsize=7.5)
    save(fig, 'fig2_pr_curves_E1')


def fig3():
    M = read_csv(os.path.join(RES, 'ALL_metrics_E1.csv')).set_index('method')
    L = read_csv(os.path.join(RES, 'ALL_literature_comparison.csv'))
    fig, ax = plt.subplots(1, 2, figsize=(10, 4))
    for m in METH:
        r = M.loc[m]
        ax[0].errorbar(100 * r.utility_retained, 100 * r.ASR_after,
                       xerr=[[100 * (r.utility_retained - r.utility_retained_lo)], [100 * (r.utility_retained_hi - r.utility_retained)]],
                       yerr=[[100 * (r.ASR_after - r.ASR_after_lo)], [100 * (r.ASR_after_hi - r.ASR_after)]],
                       fmt=MARK[m], color=COL[m], ms=7, mec='white', mew=1, label=LABEL[m], capsize=2, lw=1)
    ax[0].axhline(100 * M.ASR_before.iloc[0], color='#888', ls=':', lw=1)
    ax[0].text(56, 100 * M.ASR_before.iloc[0] + 0.4, 'no monitor', color='#666', fontsize=7)
    ax[0].set_xlabel('benign traces with no blocked call (%)'); ax[0].set_ylabel('ASR after monitoring (%)')
    ax[0].set_title('(a) All undefended LLMs (E1, 95% bootstrap CI)')
    ax[0].legend(frameon=False, fontsize=7, loc='center left')
    sub = L[L.scope == 'call-goal tasks']
    defs = sub[~sub.defence.str.startswith('simulated')]
    for i, (_, r) in enumerate(defs.iterrows()):
        ax[1].errorbar(100 * r.benign_utility, 100 * r.ASR, xerr=[[100 * (r.benign_utility - r.BU_lo)], [100 * (r.BU_hi - r.benign_utility)]],
                       yerr=[[100 * (r.ASR - r.ASR_lo)], [100 * (r.ASR_hi - r.ASR)]], fmt='*' if i == 0 else 'h',
                       color='#555' if i == 0 else PAL[7], ms=10 if i == 0 else 7, capsize=2, lw=1, mec='white')
        ax[1].annotate(r.defence.replace('AgentDojo: ', ''), (100 * r.benign_utility, 100 * r.ASR), fontsize=6.5,
                       xytext=(5, 4), textcoords='offset points', color='#333')
    for m in ['TB_Guard', 'B5_flat_MLP', 'TB_Policy', 'B1_signature', 'B3_strict_taint']:
        r = sub[sub.defence == f'simulated {m}'].iloc[0]
        ax[1].errorbar(100 * r.benign_utility, 100 * r.ASR, xerr=[[100 * (r.benign_utility - r.BU_lo)], [100 * (r.BU_hi - r.benign_utility)]],
                       yerr=[[100 * (r.ASR - r.ASR_lo)], [100 * (r.ASR_hi - r.ASR)]], fmt=MARK[m], color=COL[m], ms=7,
                       capsize=2, lw=1, mec='white', label=f'{LABEL[m]} (simulated)')
    ax[1].set_xlabel('benign utility (%)'); ax[1].set_ylabel('attack success rate (%)')
    ax[1].set_title('(b) gpt-4o-2024-05-13, important_instructions:\nAgentDojo defences (red hexagons) vs simulated monitors')
    ax[1].legend(frameon=False, fontsize=6.5, loc='upper left')
    fig.tight_layout()
    save(fig, 'fig3_security_utility')


def fig4():
    fig, ax = plt.subplots(1, 2, figsize=(11, 3.6), gridspec_kw={'wspace': 0.08})
    for i, e in enumerate(['E2', 'E3']):
        F = read_csv(os.path.join(RES, f'ALL_perfold_{e}.csv'))
        F = F[F.method.isin(METH)].pivot(index='method', columns='fold', values='AUPRC').loc[METH]
        im = ax[i].imshow(F.values, cmap='Blues', vmin=0, vmax=1, aspect='auto')
        ax[i].set_xticks(range(F.shape[1]), F.columns); ax[i].set_yticks(range(len(METH)), [LABEL[m] for m in METH] if i == 0 else [])
        ax[i].grid(False)
        for a in range(F.shape[0]):
            for b in range(F.shape[1]):
                v = F.values[a, b]
                ax[i].text(b, a, f'{v:.2f}', ha='center', va='center', fontsize=7, color='white' if v > 0.6 else '#222')
        ax[i].set_title(['(a) E2 leave-one-suite-out (AUPRC)',
                         '(b) E3 leave-one-model-family-out (AUPRC)'][i])
    fig.colorbar(im, ax=ax, shrink=0.8, label='AUPRC')
    save(fig, 'fig4_generalisation_heatmap')


def fig5():
    M = read_csv(os.path.join(RES, 'ALL_metrics_E1.csv')).set_index('method')
    vs = ['TB_Guard', 'TB_Guard_no_deriv', 'TB_Guard_no_instr', 'TB_Guard_no_endorse', 'TB_Guard_lex_only',
          'B5_flat_MLP', 'TB_Policy']
    vs = [v for v in vs if v in M.index]
    lab = {'TB_Guard': 'full', 'TB_Guard_no_deriv': '- derivation', 'TB_Guard_no_instr': '- instruction-lik.',
           'TB_Guard_no_endorse': '- endorsement', 'TB_Guard_lex_only': '- TF-IDF (lexical only)',
           'B5_flat_MLP': 'no graph (flat MLP)', 'TB_Policy': 'policy only'}
    fig, ax = plt.subplots(1, 3, figsize=(11, 3.4), sharey=True)
    for j, (col, t) in enumerate([('AUPRC', 'AUPRC'), ('prevention_rate', 'attack prevention rate'),
                                  ('utility_retained', 'benign traces unblocked')]):
        y = np.arange(len(vs))
        v = M.loc[vs, col].values
        lo = M.loc[vs, col + '_lo'].values; hi = M.loc[vs, col + '_hi'].values
        ax[j].barh(y, v, color=[PAL[0]] + [PAL[0]] * 4 + [PAL[1], PAL[2]], height=0.6, alpha=0.9)
        ax[j].errorbar(v, y, xerr=[v - lo, hi - v], fmt='none', ecolor='#222', capsize=2, lw=1)
        for yy, vv in zip(y, v):
            ax[j].text(min(vv, 1.0) - 0.01, yy, f'{vv:.3f}', va='center', ha='right', fontsize=6.5, color='white')
        ax[j].set_title(t); ax[j].set_xlim(0, 1.0)
    ax[0].set_yticks(np.arange(len(vs)), [lab[v] for v in vs]); ax[0].invert_yaxis()
    fig.suptitle('Ablations of TB-Guard (E1, 95% bootstrap CI)', y=1.02)
    fig.tight_layout()
    save(fig, 'fig5_ablation')


def fig6():
    L = read_csv(os.path.join(RES, 'ALL_latency_raw.csv'))
    cols = ['TB_graph_build', 'TB_line_scoring', 'TB_gnn_forward', 'TB_Guard_total', 'B1_signature', 'B2_content_clf']
    fig, ax = plt.subplots(1, 2, figsize=(10, 3.4), gridspec_kw={'width_ratios': [1.4, 1]})
    bp = ax[0].boxplot([L[c] for c in cols], vert=False, showfliers=True, widths=0.55, patch_artist=True,
                       flierprops={'markersize': 2, 'markeredgecolor': '#999'})
    for p, c in zip(bp['boxes'], [PAL[0]] * 4 + [COL['B1_signature'], COL['B2_content_clf']]):
        p.set_facecolor(c); p.set_alpha(0.7)
    ax[0].set_yticks(range(1, len(cols) + 1), ['TB: graph build', 'TB: line scoring', 'TB: GNN forward', 'TB-Guard total',
                                              'B1 signature', 'B2 content clf.'])
    ax[0].set_xscale('log'); ax[0].set_xlabel('latency per check (ms, log; 1 CPU thread)')
    ax[0].set_title('(a) Per-check latency (500 random privileged calls)')
    ax[1].scatter(L.n_nodes, L.TB_Guard_total, s=8, color=PAL[0], alpha=0.6)
    ax[1].set_xlabel('provenance-graph nodes in prefix'); ax[1].set_ylabel('TB-Guard total (ms)')
    ax[1].set_title('(b) Latency vs graph size')
    fig.tight_layout()
    save(fig, 'fig6_latency')


def fig7():
    import networkx as nx
    import build_graphs as BG
    T = pickle.load(open(os.path.join(DATA, 'traces_main.pkl'), 'rb'))
    # pick a short successful gpt-4o banking injected trace with a violation (deterministic choice)
    cand = [t for t in T if t['pipe_dir'] == 'gpt-4o-2024-05-13' and t['suite'] == 'banking' and t['attack'] == 'important_instructions'
            and t['security'] and t['user_task'] == 'user_task_0' and t['inj_task'] == 'injection_task_0']
    t = cand[0]
    g = BG.build(dict(t))
    X, E = g['X'], g['edges']
    types = X[:, :7].argmax(1)
    txt = g['node_text']
    G = nx.DiGraph()
    for i in range(len(X)):
        G.add_node(i)
    for s, d, e in E.T:
        G.add_edge(int(s), int(d), et=int(e))
    # layout: x = creation order, y = lane by principal/type
    lane = {0: 4, 1: 4, 2: 3, 3: 1, 4: 0, 5: 2.2, 6: 2.9}
    order = {}
    xs = 0
    for i in range(len(X)):
        if types[i] in (0, 1, 2, 3, 5):
            xs += 1
        order[i] = xs + (0.0 if types[i] not in (4, 6) else 0.0)
    # place args near their call; segments near their result
    seg_par = {int(d): int(s) for s, d, e in E.T if e == 2}
    arg_call = {int(s): int(d) for s, d, e in E.T if e == 1}
    pos = {}
    argcount, segcount = {}, {}
    for i in range(len(X)):
        if types[i] == 6:
            c = arg_call[i]; k = argcount.get(c, 0); argcount[c] = k + 1
            pos[i] = (order[c] + 0.3 * (k - 1.5), lane[6])
        elif types[i] == 4:
            r = seg_par[i]; k = segcount.get(r, 0); segcount[r] = k + 1
            pos[i] = (order[r] + 0.5 * k, lane[4] - 0.3 * k)
        else:
            pos[i] = (order[i], lane[types[i]])
    integ = X[:, 7:10].argmax(1)
    ncol = {2: '#2a78d6', 1: '#bdbdbd', 0: '#e34948'}  # HIGH blue, MED grey, LOW red
    fig, ax = plt.subplots(figsize=(12, 5.2))
    viol = g['call_nodes'][g['labels'] == 1]
    ecol = {0: '#cccccc', 7: '#cccccc', 8: '#e0e0e0', 1: '#888888', 2: '#bbbbbb', 3: '#bbbbbb', 4: '#e34948', 5: '#eb6834', 6: '#2a78d6'}
    for et_ in [0, 7, 8, 1, 2, 3, 6, 4, 5]:
        es = [(u, v) for u, v, d in G.edges(data=True) if d['et'] == et_]
        if et_ == 3:
            continue
        nx.draw_networkx_edges(G, pos, edgelist=es, edge_color=ecol[et_], width=2.2 if et_ in (4, 5) else 0.9,
                               arrows=True, arrowsize=8, ax=ax, connectionstyle='arc3,rad=0.12' if et_ in (4, 5, 6, 8) else 'arc3,rad=0',
                               style='dashed' if et_ == 6 else 'solid')
    shapes = {0: 's', 1: 's', 2: 'o', 3: 'h', 4: 'd', 5: 'o', 6: '.'}
    for ty in range(7):
        nodes = [i for i in range(len(X)) if types[i] == ty]
        if not nodes:
            continue
        nx.draw_networkx_nodes(G, pos, nodelist=nodes, node_color=[ncol[integ[i]] for i in nodes],
                               node_shape=shapes[ty] if ty != 6 else 'o', node_size=60 if ty == 6 else 260, ax=ax,
                               edgecolors=['#000' if i in viol else 'white' for i in nodes], linewidths=[2.5 if i in viol else 1 for i in nodes])
    labels = {}
    for i in range(len(X)):
        tx = txt[i]
        if types[i] == 0: labels[i] = 'SYSTEM'
        elif types[i] == 1: labels[i] = 'USER: "pay the bill\n\'bill-december-2023.txt\'"'
        elif types[i] == 5: labels[i] = tx + ('\n[VIOLATION]' if i in viol else '')
        elif types[i] == 3: labels[i] = 'result:\n' + tx
        elif types[i] == 6 and tx.startswith('recipient'): labels[i] = tx[:34]
        elif types[i] == 2: labels[i] = 'agent text'
        elif types[i] == 4: labels[i] = '"' + tx[:30] + '..."'
    for i, (x, y) in pos.items():
        if i in labels:
            dy = {0: 0.28, 1: 0.32, 2: 0.3, 3: -0.42, 4: -0.25 - 0.0, 5: 0.32, 6: 0.25}[types[i]]
            if types[i] == 5:
                x = x - 0.35; dy = -0.3
            if types[i] == 4:
                segk = sum(1 for j in labels if types[j] == 4 and j < i)
                dy = -0.25 - 0.25 * (segk % 2)
            if types[i] == 0:
                dy = -0.3
            ax.text(x, y + dy, labels[i], fontsize=6.2 if types[i] in (4, 6) else 7, ha='center',
                    va='bottom' if dy > 0 else 'top', color='#b00' if i in viol else '#222')
    from matplotlib.lines import Line2D
    h = [Line2D([], [], marker='o', ls='', color=ncol[2], label='HIGH integrity (system/user)'),
         Line2D([], [], marker='o', ls='', color=ncol[1], label='MEDIUM (agent / self-owned data)'),
         Line2D([], [], marker='o', ls='', color=ncol[0], label='LOW (third-party content)'),
         Line2D([], [], color='#e34948', lw=2.2, label='data derivation (exact)'),
         Line2D([], [], color='#eb6834', lw=2.2, label='data derivation (fuzzy)'),
         Line2D([], [], color='#2a78d6', lw=1, ls='--', label='user endorsement'),
         Line2D([], [], color='#888', lw=1, label='argument -> call'),
         Line2D([], [], color='#ccc', lw=1, label='temporal / call -> result')]
    ax.legend(handles=h, loc='upper center', fontsize=7, frameon=False, ncol=4, bbox_to_anchor=(0.5, -0.07))
    ax.set_title('Provenance graph of a real AgentDojo trace (gpt-4o, banking user_task_0 x injection_task_0): '
                 '\nthe violating send_money recipient derives (exactly) from a LOW-integrity bill segment and is not endorsed by the user',
                 fontsize=9, loc='left', pad=22)
    ax.axis('off')
    ax.margins(0.06)
    save(fig, 'fig7_provenance_example')


if __name__ == '__main__':
    which = sys.argv[1:] or ['1', '2', '3', '4', '5', '6', '7']
    for w in which:
        globals()['fig' + w]()
        print('fig', w)
