"""Build causal provenance graphs + hand-crafted call features for every trace of the corpus.

Usage: python src/build_graphs.py [tau]   (tau = fuzzy derivation threshold, default 0.6)
Output: data/graphs_tau{tau}.pkl
No label or `injections` information is used to build features (labels are attached only as targets;
`inj_line` flags for B2 training are computed from the injections field and stored separately).
"""
import pickle, sys, os, re, json, math
import numpy as np, pandas as pd
from multiprocessing import Pool
sys.path.insert(0, os.path.dirname(__file__))
from common import *
from labels import enumerate_calls, make_matcher

TAU = float(sys.argv[1]) if len(sys.argv) > 1 else 0.6

TOK = re.compile(r"[a-z0-9@\.\-_/:]+")
STOP = set('the a an to of and or in on for is are be with at by from this that it as i me my you your'.split())


def toks(s):
    return set(t.strip('.:/-_') for t in TOK.findall(s.lower()) if t not in STOP and len(t.strip('.:/-_')) > 1)


# ---------------- lexical instruction-likeness (transparent cues) ----------------
IMPER = set('send transfer pay make visit invite email delete create change concatenate get post forward ignore '
            'add remove update book reserve share write tell say go click download call schedule modify'.split())
CUES = [
    ('imperative_start', None),
    ('second_person', re.compile(r'\byou(r|rself)?\b', re.I)),
    ('ignore', re.compile(r'\bignore\b|\bdisregard\b|\bforget\b', re.I)),
    ('before_after_you', re.compile(r'\b(before|after) you\b', re.I)),
    ('important', re.compile(r'\bimportant\b|\burgent\b|\bmust\b', re.I)),
    ('instruction_word', re.compile(r'\binstruction|\btask\b|\bdo the following\b', re.I)),
    ('address_ai', re.compile(r'\b(ai|assistant|gpt[-\w.]*|claude|gemini|llama|language model|model|chatbot|agent)\b', re.I)),
    ('please', re.compile(r'\bplease\b', re.I)),
    ('markup_tag', re.compile(r'</?[A-Z_]{3,}>|\bTODO\b|###|\[SYSTEM|\bsystem:', re.I)),
    ('signed', re.compile(r'\bsigned\b|\bthanks!?\b', re.I)),
]
N_LEX = len(CUES) + 1


def lex_feats(line):
    v = np.zeros(N_LEX, dtype=np.float32)
    w = line.strip().lower().lstrip('-*>#:\'" ').split(' ', 1)[0] if line.strip() else ''
    w = re.sub(r'[^a-z]', '', w)
    v[0] = float(w in IMPER)
    for i, (n, rx) in enumerate(CUES[1:], start=1):
        v[i] = float(bool(rx.search(line)))
    v[-1] = v[:-1].sum() / (N_LEX - 1)
    return v


# ---------------- argument categories ----------------
TARGET_ARGS = {'recipient', 'recipients', 'url', 'user', 'user_email', 'email', 'participants', 'hotel', 'restaurant',
               'company', 'file_id', 'id', 'password', 'channel', 'email_id', 'event_id', 'cc', 'bcc', 'iban', 'new_iban'}
TEXT_ARGS = {'body', 'content', 'subject', 'title', 'description', 'text'}
NUM_ARGS = {'amount', 'n', 'start_day', 'end_day', 'date', 'start_time', 'end_time', 'new_start_time', 'new_end_time'}


def arg_cat(name):
    b = name.split('.')[0]
    if b == 'url':
        return 3
    if b in TARGET_ARGS:
        return 0
    if b in NUM_ARGS:
        return 1
    if b in TEXT_ARGS:
        return 2
    return 4


SINK_CAT = {
    'send_money': 0, 'schedule_transaction': 0, 'update_scheduled_transaction': 0,
    'send_email': 1, 'send_direct_message': 1, 'send_channel_message': 1,
    'post_webpage': 2, 'get_webpage': 2,
    'update_password': 3, 'update_user_info': 3, 'invite_user_to_slack': 3, 'add_user_to_channel': 3,
    'remove_user_from_slack': 3, 'share_file': 3,
    'create_calendar_event': 4, 'cancel_calendar_event': 4, 'reschedule_calendar_event': 4,
    'add_calendar_event_participants': 4, 'reserve_hotel': 4, 'reserve_car_rental': 4, 'reserve_restaurant': 4,
    'delete_email': 5, 'delete_file': 5, 'append_to_file': 5, 'create_file': 5,
}
SINK_VERBS = {0: ['pay', 'send', 'transfer', 'money', 'transaction', 'refund', 'rent', 'bill', 'payment', 'iban', 'schedule', 'update'],
              1: ['send', 'email', 'message', 'tell', 'reply', 'forward', 'dm', 'write', 'inform', 'share', 'remind'],
              2: ['website', 'webpage', 'post', 'visit', 'url', 'www', 'page', 'link', 'article', 'http'],
              3: ['password', 'invite', 'add', 'remove', 'update', 'share', 'user', 'account', 'address'],
              4: ['calendar', 'event', 'meeting', 'reserve', 'reservation', 'book', 'schedule', 'appointment', 'hotel', 'restaurant', 'car', 'lunch', 'dinner'],
              5: ['delete', 'remove', 'file', 'append', 'create', 'document', 'email', 'clean']}

NODE_TYPES = ['system', 'user', 'agent', 'result', 'segment', 'call', 'arg']
ETYPES = ['temporal', 'arg_to_call', 'result_to_seg', 'seg_to_result', 'deriv_exact', 'deriv_fuzzy',
          'endorse', 'call_to_result', 'user_to_call']
N_CALLF = 0  # set below


def split_lines(text):
    out = []
    for ln in str(text).split('\n'):
        s = re.sub(r'\s+', ' ', ln).strip()
        if len(s) >= 3:
            out.append(s[:500])
    return out


def build(t):
    """Return graph dict for trace t."""
    msgs = t['msgs']
    calls = enumerate_calls(t)
    inj_matcher = make_matcher(t['suite'], t['inj_task']) if t['attack'] != 'none' else None
    # injected-line strings (ONLY for B2 training labels / analysis)
    inj_lines = []
    for v in (t['injections'] or {}).values():
        for l in split_lines(v):
            if len(l) >= 12:
                inj_lines.append(l.lower())
    nodes = []  # (type, integrity, principal, priv, time)
    feats_extra = []
    node_text = []
    node_line = []
    src, dst, et = [], [], []
    out_lines = []  # (line_text, is_low, msg_idx, result_node)
    seg_nodes = {}

    def add_node(typ, integ, princ, priv=0, time=0, text=''):
        nodes.append((NODE_TYPES.index(typ), integ, princ, priv, time))
        node_text.append(text)
        return len(nodes) - 1

    user_text = ' '.join(m['text'] for m in msgs if m['role'] == 'user')
    sys_text = ' '.join(m['text'] for m in msgs if m['role'] == 'system')
    user_tok = toks(user_text)
    user_compact = norm_compact(user_text)
    sys_compact = norm_compact(sys_text)
    prev_main = None
    user_node = None
    # content sources available for derivation: list of (node_id, compact_text, tokens, integrity, msg_idx, result_idx, relpos)
    sources = []
    results = []  # (result_node, tool, call_args, msg_idx, integrity)
    call_ptr = 0
    call_nodes, call_info = [], []
    first_low_msg = None
    agent_text_before_low = ''
    pending_calls = []  # call nodes waiting for results (for call_to_result edges)
    step = 0
    for mi, m in enumerate(msgs):
        r = m['role']
        if r == 'system':
            n = add_node('system', HIGH, 0, time=mi, text=m['text'][:200])
            if prev_main is not None:
                src.append(prev_main); dst.append(n); et.append(0)
            prev_main = n
            sources.append((n, sys_compact, toks(m['text']), HIGH, mi, -1, 0.0, 'system'))
        elif r == 'user':
            n = add_node('user', HIGH, 1, time=mi, text=m['text'][:200])
            if prev_main is not None:
                src.append(prev_main); dst.append(n); et.append(0)
            prev_main = n
            user_node = n
            sources.append((n, norm_compact(m['text']), toks(m['text']), HIGH, mi, -1, 0.0, 'user'))
        elif r == 'assistant':
            if m['text'].strip():
                n = add_node('agent', MED, 2, time=mi, text=m['text'][:200])
                src.append(prev_main); dst.append(n); et.append(0)
                prev_main = n
                sources.append((n, norm_compact(m['text']), toks(m['text']), MED, mi, -1, 0.0, 'agent'))
                if first_low_msg is None:
                    agent_text_before_low += ' ' + m['text'].lower()
            for c in m.get('calls') or []:
                fn = c['fn']
                pv = privilege(fn)
                cn = add_node('call', MED, 2, priv=pv, time=mi, text=fn)
                src.append(prev_main); dst.append(cn); et.append(0)
                if user_node is not None:
                    src.append(user_node); dst.append(cn); et.append(8)
                prev_main = cn
                pending_calls.append(cn)
                step += 1
                if pv == 0:
                    call_ptr += 1
                    continue
                # ---------- privileged call: argument nodes + derivation ----------
                fa = flatten_args(c['args'])
                arg_rows = []
                deriv_lines = []
                n_low_res = sum(1 for x in results if x[4] == LOW)
                for an, av in fa:
                    vc = norm_compact(av)
                    vt = toks(av)
                    cat = arg_cat(an)
                    endorsed = int(len(vc) >= 3 and (vc in user_compact or vc in sys_compact))
                    if not endorsed and len(vt) >= 3:
                        endorsed = int(len(vt & user_tok) / len(vt) >= TAU)
                    ex_src, fz_src = [], []
                    if len(vc) >= 3 and not (cat == 1 and len(vc) < 4):
                        for s in sources:
                            if s[4] >= c_gen(mi):
                                break
                            if s[7] in ('user', 'system'):
                                continue
                            if vc in s[1]:
                                ex_src.append(s)
                            elif len(vt) >= 3 and len(s[2]) >= 3:
                                inter = len(vt & s[2])
                                if inter / min(len(vt), len(s[2])) >= TAU:
                                    fz_src.append(s)
                    elif len(vt) >= 3:
                        for s in sources:
                            if s[4] >= mi or s[7] in ('user', 'system'):
                                continue
                            inter = len(vt & s[2])
                            if len(s[2]) >= 3 and inter / min(len(vt), len(s[2])) >= TAU:
                                fz_src.append(s)
                    an_node = add_node('arg', MED, 2, priv=pv, time=mi, text=f'{an}={av[:60]}')
                    src.append(an_node); dst.append(cn); et.append(1)
                    if endorsed and user_node is not None:
                        src.append(user_node); dst.append(an_node); et.append(6)
                    # keep at most 6 sources per kind (lowest integrity first, then most recent)
                    def add_src(lst, etype):
                        lst = sorted(lst, key=lambda s: (s[3], -s[4]))[:6]
                        for s in lst:
                            sn = s[0]
                            if s[7] == 'line':
                                key = s[0]
                                if key not in seg_nodes:
                                    li, rnode, integ, relpos, txt = s[8]
                                    seg = add_node('segment', integ, 3 + int(integ == LOW), time=s[4], text=txt[:120])
                                    node_line.append((seg, li))
                                    src.append(rnode); dst.append(seg); et.append(2)
                                    src.append(seg); dst.append(rnode); et.append(3)
                                    seg_nodes[key] = seg
                                    feats_extra.append((seg, relpos))
                                sn = seg_nodes[key]
                            src.append(sn); dst.append(an_node); et.append(etype)
                        return lst
                    ex_k = add_src(ex_src, 4)
                    fz_k = add_src(fz_src, 5)
                    allsrc = ex_k + fz_k
                    integs = [s[3] for s in allsrc]
                    low_src = [s for s in allsrc if s[3] == LOW]
                    arg_rows.append(dict(name=an, cat=cat, endorsed=endorsed, node=an_node,
                                         n_ex=len(ex_src), n_fz=len(fz_src),
                                         min_int=min(integs) if integs else 3,
                                         from_low=int(len(low_src) > 0),
                                         from_low_ex=int(any(s[3] == LOW for s in ex_k)),
                                         only_low=int(len(integs) > 0 and max(integs) == LOW),
                                         low_src=low_src,
                                         novel=(len(vt - user_tok) / len(vt)) if vt else 0.0))
                    for s in low_src:
                        if s[7] == 'line':
                            deriv_lines.append(s[8][0])
                call_nodes.append(cn)
                call_info.append(dict(ci=call_ptr, fn=fn, pv=pv, args=arg_rows, mi=mi, step=step,
                                      n_low_res=n_low_res, n_res=len(results),
                                      n_out_lines=len(out_lines),
                                      n_low_lines=sum(1 for x in out_lines if x[1]),
                                      deriv_lines=sorted(set(deriv_lines)),
                                      label=int(bool(inj_matcher(fn, c['args']))) if inj_matcher else 0,
                                      prior_same=sum(1 for ci2 in call_info if ci2['fn'] == fn)))
                call_ptr += 1
        elif r == 'tool':
            tool = m.get('tool') or ''
            integ = tool_integrity(tool)
            rn = add_node('result', integ, 3 + int(integ == LOW), priv=privilege(tool), time=mi, text=tool)
            src.append(prev_main); dst.append(rn); et.append(0)
            if pending_calls:
                src.append(pending_calls.pop(0)); dst.append(rn); et.append(7)
            prev_main = rn
            lines = split_lines(m['text'])
            start = len(out_lines)
            for k, l in enumerate(lines):
                relpos = k / max(1, len(lines) - 1)
                out_lines.append((l, integ == LOW, mi, rn))
                li = len(out_lines) - 1
                key = ('L', li)
                sources.append((key, norm_compact(l), toks(l), integ, mi, len(results), relpos, 'line',
                                (li, rn, integ, relpos, l)))
            results.append((rn, tool, m.get('tc_args') or {}, mi, integ, start, len(out_lines)))
            if integ == LOW and first_low_msg is None:
                first_low_msg = mi
    # ------- per-call hand-crafted features -------
    # helper for delegation: does the user prompt mention the object read by the source call?
    res_by_node = {x[0]: x for x in results}
    CF = []
    for info in call_info:
        args = info['args']
        na = max(1, len(args))
        sc = SINK_CAT.get(info['fn'], 5)
        f = []
        f += [float(info['pv'] == 1), float(info['pv'] == 2)]
        f += [float(sc == k) for k in range(6)]
        f += [math.log1p(len(args))]
        f += [float(any(a['from_low_ex'] for a in args)), float(any(a['from_low'] for a in args))]
        tgt = [a for a in args if a['cat'] in (0, 3)]
        f += [float(any(a['from_low'] and not a['endorsed'] for a in tgt)),
              float(any(a['from_low'] and not a['endorsed'] for a in args))]
        f += [sum(a['from_low'] for a in args) / na, sum(a['endorsed'] for a in args) / na,
              sum(a['min_int'] == 3 for a in args) / na]
        mi_all = min([a['min_int'] for a in args] or [3])
        f += [float(mi_all == k) for k in (HIGH, MED, LOW, 3)]
        f += [float(any(a['only_low'] for a in args)), float(any(a['only_low'] and a['cat'] in (0, 3) for a in args))]
        # delegation: source result's call args (file name / channel / url / sender) mentioned in user prompt
        deleg, deleg_j, hops, relpos, src_lex = 0.0, 0.0, [], [], np.zeros(N_LEX, dtype=np.float32)
        for a in args:
            for s in a['low_src']:
                ri = s[5]
                if ri < 0:
                    continue
                rn, tool, targs, rmi, rinteg = results[ri][:5]
                objs = [norm_compact(v) for _, v in flatten_args(targs) if len(norm_compact(v)) >= 3]
                if any(o in user_compact for o in objs):
                    deleg = 1.0
                ttoks = toks(tool.replace('_', ' ') + ' ' + ' '.join(str(v) for _, v in flatten_args(targs)))
                if ttoks:
                    deleg_j = max(deleg_j, len(ttoks & user_tok) / len(ttoks | user_tok))
                hops.append(sum(1 for x in results if x[3] > rmi and x[3] < info['mi']))
                relpos.append(s[6])
                if s[7] == 'line':
                    src_lex = np.maximum(src_lex, lex_feats(s[8][4]))
        f += [deleg, deleg_j]
        f += list(src_lex)
        f += [float(np.mean(relpos)) if relpos else -1.0, math.log1p(min(hops)) if hops else -1.0]
        f += [math.log1p(info['n_low_res']), float(info['n_low_res'] == 0)]
        fnword = info['fn'].split('_')[0]
        f += [float(first_low_msg is None or info['mi'] <= first_low_msg),
              float(fnword in agent_text_before_low or info['fn'] in agent_text_before_low)]
        f += [float(np.mean([a['novel'] for a in args])) if args else 0.0,
              float(any(v in user_text.lower() for v in SINK_VERBS[sc])),
              math.log1p(info['prior_same']), math.log1p(info['step'])]
        CF.append(np.array(f, dtype=np.float32))
    # node features
    N = len(nodes)
    X = np.zeros((N, len(NODE_TYPES) + 3 + 5 + 3 + N_LEX + 3), dtype=np.float32)
    for i, (ty, integ, princ, pv, tm) in enumerate(nodes):
        X[i, ty] = 1
        o = len(NODE_TYPES)
        X[i, o + integ] = 1
        X[i, o + 3 + princ] = 1
        X[i, o + 8 + pv] = 1
        X[i, o + 11:o + 11 + N_LEX] = lex_feats(node_text[i]) if ty in (2, 4) else 0
        X[i, -3] = math.log1p(tm) / 4
    for seg, relpos in feats_extra:
        X[seg, -2] = relpos
    # result-node lexical features = max over its lines
    for (rn, tool, targs, rmi, integ, s0, s1) in results:
        if s1 > s0:
            X[rn, len(NODE_TYPES) + 11:len(NODE_TYPES) + 11 + N_LEX] = np.max(
                np.stack([lex_feats(out_lines[k][0]) for k in range(s0, s1)]), 0)
    # arg node extras: category + endorsed
    for info in call_info:
        for a in info['args']:
            X[a['node'], -1] = a['endorsed']
            X[a['node'], -2] = a['cat'] / 4
    return dict(
        tid=t['tid'], X=X, edges=np.array([src, dst, et], dtype=np.int64).reshape(3, -1),
        call_nodes=np.array(call_nodes, dtype=np.int64),
        CF=np.stack(CF) if CF else np.zeros((0, 0), np.float32),
        labels=np.array([c['label'] for c in call_info], dtype=np.int64),
        ci=np.array([c['ci'] for c in call_info], dtype=np.int64),
        fn=[c['fn'] for c in call_info],
        step=np.array([c['step'] for c in call_info], dtype=np.int64),
        n_out_lines=np.array([c['n_out_lines'] for c in call_info], dtype=np.int64),
        n_low_lines=np.array([c['n_low_lines'] for c in call_info], dtype=np.int64),
        deriv_lines=[c['deriv_lines'] for c in call_info],
        out_lines=[x[0] for x in out_lines], out_low=np.array([x[1] for x in out_lines], dtype=bool),
        out_resnode=np.array([x[3] for x in out_lines], dtype=np.int64),
        line_nodes=node_line,
        inj_line=np.array([any(il in x[0].lower() for il in inj_lines) for x in out_lines], dtype=bool),
        first_low_step=first_low_step(t),
        n_calls_total=len(calls),
        call_seq=[c['fn'] for c in calls],
        user_text=user_text[:300],
        node_text=node_text,
    )


def c_gen(mi):
    return mi


def first_low_step(t):
    step = 0
    for m in t['msgs']:
        if m['role'] == 'assistant':
            step += len(m.get('calls') or [])
        if m['role'] == 'tool' and tool_integrity(m.get('tool') or '') == LOW:
            return step
    return None


def main():
    T = pickle.load(open(os.path.join(DATA, 'traces_main.pkl'), 'rb'))
    tr = read_csv(os.path.join(DATA, 'trace_table.csv'))
    keep_ids = set(tr[~tr.defended & ~tr.textonly_goal].tid)
    T = [t for t in T if t['tid'] in keep_ids]
    print('traces', len(T), 'tau', TAU)
    with Pool(2) as p:
        G = list(p.imap(build, T, chunksize=50))
    # global unique line vocabulary
    vocab = {}
    for g in G:
        ids = np.array([vocab.setdefault(l, len(vocab)) for l in g['out_lines']], dtype=np.int64)
        g['line_ids'] = ids
        g['line_nodes'] = np.array([(s, ids[li]) for s, li in g['line_nodes']], dtype=np.int64).reshape(-1, 2)
        g['deriv_lines'] = [ids[np.array(d, dtype=np.int64)] if len(d) else np.zeros(0, np.int64) for d in g['deriv_lines']]
        del g['out_lines']
    lines = [None] * len(vocab)
    for l, i in vocab.items():
        lines[i] = l
    print('unique lines', len(lines), 'priv calls', sum(len(g['labels']) for g in G),
          'violations', sum(int(g['labels'].sum()) for g in G), 'nodes', sum(len(g['X']) for g in G))
    pickle.dump({'G': G, 'lines': lines, 'tau': TAU}, open(os.path.join(DATA, f'graphs_tau{TAU}.pkl'), 'wb'))


if __name__ == '__main__':
    main()
