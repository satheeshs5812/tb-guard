"""Detectors: TB-Guard (relational GraphSAGE), flat MLP (B5), TF-IDF line classifier (B2 / instruction-likeness),
signature rules (B1), strict taint (B3), behavioural anomaly (B4), TB-Policy."""
import re, math, time, sys, os
import numpy as np, torch, torch.nn as nn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score
from scipy.sparse import hstack
sys.path.insert(0, os.path.dirname(__file__))
from common import SEED

torch.set_num_threads(2)

# ---------------- CF column layout (see build_graphs.py) ----------------
CF_NAMES = (['priv1', 'priv2'] + [f'sink{k}' for k in range(6)] + ['log_nargs', 'any_low_exact', 'any_low',
            'tgt_low_unendorsed', 'any_low_unendorsed', 'frac_low', 'frac_endorsed', 'frac_underived',
            'minint_high', 'minint_med', 'minint_low', 'minint_none', 'only_low', 'only_low_tgt', 'delegated',
            'deleg_jacc'] + [f'srclex{k}' for k in range(11)] + ['src_relpos', 'hops', 'log_n_low_res', 'no_low_res',
            'pre_low', 'planned_in_text', 'novelty', 'verb_requested', 'prior_same', 'log_step']
            + ['tfidf_src_max', 'tfidf_ctx_low_max'])
CI = {n: i for i, n in enumerate(CF_NAMES)}
DERIV_COLS = list(range(CI['any_low_exact'], CI['hops'] + 1)) + [CI['tfidf_src_max']]
INSTR_COLS = [CI[f'srclex{k}'] for k in range(11)] + [CI['tfidf_src_max'], CI['tfidf_ctx_low_max']]
ENDORSE_COLS = [CI['frac_endorsed'], CI['delegated'], CI['deleg_jacc']]
X_LEX = list(range(18, 29))  # lexical cue columns in node features
X_ENDORSE = [31]
ETYPE_GROUPS = {0: 0, 7: 0, 8: 0, 1: 1, 2: 2, 3: 2, 4: 3, 5: 4, 6: 5}
N_REL = 6

# ---------------- B1 signature rules ----------------
SIGS = [r'ignore (all |any )?(the |your )?(previous|prior|above|earlier) (instructions|prompts?)',
        r'important (message|instructions?)', r'<information>', r'before you (can )?(solve|do|continue|answer)',
        r'new instructions?', r'\btodo\b', r'you are now', r'forget (all|everything|your)', r'disregard',
        r'this is an important', r'system (prompt|override|message)', r'do not tell the user',
        r'instead,? (please )?(do|send|transfer)', r'override', r'\[system', r'###']
SIG_RX = re.compile('|'.join(SIGS), re.I)


def signature_scores(lines):
    return np.array([len(SIG_RX.findall(l)) for l in lines], dtype=np.float32)


# ---------------- B2 / instruction-likeness line classifier ----------------
class LineClassifier:
    def fit(self, texts, y, seed=SEED):
        self.vw = TfidfVectorizer(analyzer='word', ngram_range=(1, 2), min_df=2, max_features=50000, sublinear_tf=True)
        self.vc = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5), min_df=2, max_features=100000, sublinear_tf=True)
        Xw = self.vw.fit_transform(texts)
        Xc = self.vc.fit_transform(texts)
        self.lr = LogisticRegression(C=1.0, class_weight='balanced', max_iter=2000, random_state=seed)
        self.lr.fit(hstack([Xw, Xc]).tocsr(), y)
        return self

    def score(self, texts):
        return self.lr.predict_proba(hstack([self.vw.transform(texts), self.vc.transform(texts)]).tocsr())[:, 1]


# ---------------- Relational GraphSAGE ----------------
class RSAGELayer(nn.Module):
    def __init__(self, din, dout, nrel):
        super().__init__()
        self.self_lin = nn.Linear(din, dout)
        self.rel_lin = nn.Linear(din * nrel, dout, bias=False)
        self.nrel = nrel

    def forward(self, h, src, dst, rel, inv_deg):
        N, d = h.shape
        agg = torch.zeros(N * self.nrel, d)
        idx = dst * self.nrel + rel
        agg.index_add_(0, idx, h[src])
        agg = agg * inv_deg.unsqueeze(1)
        return self.self_lin(h) + self.rel_lin(agg.view(N, self.nrel * d))


class TBGNN(nn.Module):
    def __init__(self, din, hid=48, layers=3, nrel=N_REL, dropout=0.2):
        super().__init__()
        self.inp = nn.Linear(din, hid)
        self.layers = nn.ModuleList([RSAGELayer(hid, hid, nrel) for _ in range(layers)])
        self.norms = nn.ModuleList([nn.LayerNorm(hid) for _ in range(layers)])
        self.drop = nn.Dropout(dropout)
        self.out = nn.Sequential(nn.Linear(hid + din, hid), nn.ReLU(), nn.Dropout(dropout), nn.Linear(hid, 1))
        self.nrel = nrel

    def forward(self, x, src, dst, rel, call_idx):
        N = x.shape[0]
        deg = torch.zeros(N * self.nrel)
        deg.index_add_(0, dst * self.nrel + rel, torch.ones(len(dst)))
        inv = 1.0 / deg.clamp(min=1)
        h = torch.relu(self.inp(x))
        for L, nm in zip(self.layers, self.norms):
            h = h + self.drop(torch.relu(nm(L(h, src, dst, rel, inv))))
        return self.out(torch.cat([h[call_idx], x[call_idx]], 1)).squeeze(1)


class MLP(nn.Module):
    def __init__(self, din, hid=64, dropout=0.2):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(din, hid), nn.ReLU(), nn.Dropout(dropout), nn.Linear(hid, hid), nn.ReLU(),
                                 nn.Dropout(dropout), nn.Linear(hid, 1))

    def forward(self, x):
        return self.net(x).squeeze(1)


class GraphStore:
    """Holds per-trace node features / edges and assembles mini-batches (disjoint unions)."""

    def __init__(self, items):
        # items: list of dicts with X (n,d) np, edges (3,e), call_nodes (k,), y (k,)
        self.items = items

    def batch(self, idxs):
        Xs, S, D, R, C, Y = [], [], [], [], [], []
        off = 0
        for i in idxs:
            it = self.items[i]
            Xs.append(it['X'])
            e = it['edges']
            if e.shape[1]:
                S.append(e[0] + off); D.append(e[1] + off); R.append(it['rel'])
            C.append(it['call_nodes'] + off)
            Y.append(it['y'])
            off += len(it['X'])
        cat = lambda L: torch.from_numpy(np.concatenate(L)) if L else torch.zeros(0, dtype=torch.long)
        return (torch.from_numpy(np.concatenate(Xs)), cat(S), cat(D), cat(R), cat(C),
                torch.from_numpy(np.concatenate(Y).astype(np.float32)))


def train_nn(kind, store_or_X, tr_idx, va_idx, din, seed=SEED, max_epochs=40, patience=5, bs=256, lr=3e-3,
             log=None, y_tr=None, y_va=None):
    """kind='gnn' (store) or 'mlp' (X arrays). Returns trained model."""
    torch.manual_seed(seed)
    rng = np.random.RandomState(seed)
    model = TBGNN(din) if kind == 'gnn' else MLP(din)
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    if kind == 'gnn':
        ytr = np.concatenate([store_or_X.items[i]['y'] for i in tr_idx])
    else:
        ytr = y_tr
    pw = torch.tensor((len(ytr) - ytr.sum()) / max(1, ytr.sum()), dtype=torch.float32)
    lossf = nn.BCEWithLogitsLoss(pos_weight=pw)
    best, best_state, bad = -1, None, 0
    for ep in range(max_epochs):
        model.train()
        if kind == 'gnn':
            order = rng.permutation(tr_idx)
            for b in range(0, len(order), bs):
                x, s, d, r, c, y = store_or_X.batch(order[b:b + bs])
                if len(c) == 0:
                    continue
                opt.zero_grad()
                loss = lossf(model(x, s, d, r, c), y)
                loss.backward(); opt.step()
        else:
            Xtr = store_or_X[0]
            order = rng.permutation(len(Xtr))
            for b in range(0, len(order), 512):
                ii = order[b:b + 512]
                opt.zero_grad()
                loss = lossf(model(torch.from_numpy(Xtr[ii])), torch.from_numpy(ytr[ii].astype(np.float32)))
                loss.backward(); opt.step()
        sc, yv = predict_nn(kind, model, store_or_X, va_idx, y_va)
        ap = average_precision_score(yv, sc) if yv.sum() > 0 else 0
        if log is not None:
            log.append((ep, float(ap)))
        if ap > best + 1e-4:
            best, bad = ap, 0
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= patience:
                break
    model.load_state_dict(best_state)
    model.eval()
    return model


@torch.no_grad()
def predict_nn(kind, model, store_or_X, idx, y=None, bs=1024):
    model.eval()
    if kind == 'gnn':
        out, ys = [], []
        for b in range(0, len(idx), bs):
            x, s, d, r, c, yy = store_or_X.batch(idx[b:b + bs])
            if len(c) == 0:
                continue
            out.append(torch.sigmoid(model(x, s, d, r, c)).numpy()); ys.append(yy.numpy())
        return np.concatenate(out), np.concatenate(ys)
    X = store_or_X[1] if y is not None else store_or_X
    return torch.sigmoid(model(torch.from_numpy(X))).numpy(), y
