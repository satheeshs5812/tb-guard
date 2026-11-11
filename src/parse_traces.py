"""Parse AgentDojo run JSONs into a compact normalised pickle.

Usage: python src/parse_traces.py [--runs PATH_TO_AGENTDOJO_RUNS]   (default: data/agentdojo/runs)
Output: data/traces.pkl  (list of dicts)
Each trace: meta fields + 'msgs': list of {role, text, calls:[{fn,args}], tool (for tool msgs), error}
"""
import json, os, sys, glob, pickle, argparse
from multiprocessing import Pool
sys.path.insert(0, os.path.dirname(__file__))
from common import DATA, AGENTDOJO_RUNS

ROOT = AGENTDOJO_RUNS  # overridden by --runs (exported via $AGENTDOJO_RUNS so worker processes see it too)
OUT = os.path.join(DATA, 'traces.pkl')


def _text(c):
    if c is None:
        return ''
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        out = []
        for b in c:
            if isinstance(b, dict):
                out.append(str(b.get('content') or b.get('text') or ''))
            else:
                out.append(str(b))
        return '\n'.join(out)
    return str(c)


def parse(path):
    try:
        d = json.load(open(path))
    except Exception as e:
        return None
    msgs = []
    for m in d.get('messages') or []:
        role = m.get('role')
        rec = {'role': role, 'text': _text(m.get('content'))}
        if role == 'assistant':
            calls = []
            for tc in (m.get('tool_calls') or []):
                calls.append({'fn': tc.get('function'), 'args': tc.get('args') or {}})
            rec['calls'] = calls
        elif role == 'tool':
            tc = m.get('tool_call') or {}
            rec['tool'] = tc.get('function')
            rec['tc_args'] = tc.get('args') or {}
            rec['error'] = m.get('error')
        msgs.append(rec)
    # Some pipelines (e.g. Meta-SecAlign) may store calls only in tool messages;
    # reconstruct assistant calls if an assistant message lacks them but tool results follow.
    fixed = []
    i = 0
    while i < len(msgs):
        m = msgs[i]
        fixed.append(m)
        if m['role'] == 'assistant' and not m.get('calls'):
            j = i + 1
            rec = []
            while j < len(msgs) and msgs[j]['role'] == 'tool':
                rec.append({'fn': msgs[j]['tool'], 'args': msgs[j]['tc_args']})
                j += 1
            if rec:
                m['calls'] = rec
                m['reconstructed'] = True
        i += 1
    rel = os.path.relpath(path, ROOT).split(os.sep)
    return {
        'path': os.path.relpath(path, ROOT),
        'pipeline': d.get('pipeline_name') or rel[0],
        'pipe_dir': rel[0],
        'suite': d.get('suite_name'),
        'user_task': d.get('user_task_id'),
        'inj_task': d.get('injection_task_id'),
        'attack': d.get('attack_type') or rel[3],
        'injections': d.get('injections') or {},
        'utility': d.get('utility'),
        'security': d.get('security'),
        'duration': d.get('duration'),
        'error': d.get('error'),
        'bver': d.get('benchmark_version'),
        'msgs': msgs,
    }


if __name__ == '__main__':
    _ap = argparse.ArgumentParser()
    _ap.add_argument('--runs', default=AGENTDOJO_RUNS, help='AgentDojo runs/ directory (commit 089ed46)')
    ROOT = os.path.abspath(_ap.parse_args().runs)
    os.environ['AGENTDOJO_RUNS'] = ROOT
    files = sorted(glob.glob(os.path.join(ROOT, '*', '*', '*', '*', '*.json')))
    print('files', len(files))
    with Pool(2) as p:
        out = [t for t in p.imap(parse, files, chunksize=200) if t is not None]
    print('parsed', len(out))
    pickle.dump(out, open(OUT, 'wb'))
