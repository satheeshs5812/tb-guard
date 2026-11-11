"""Shared definitions: corpus selection, trust lattice, privilege map, normalisation."""
import re, os

# All paths are relative to the repository root; override with environment variables if needed.
BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DATA = os.environ.get('TBG_DATA', os.path.join(BASE, 'data'))
RES = os.environ.get('TBG_RESULTS', os.path.join(BASE, 'results'))
FIG = os.path.join(RES, 'figures')
MODELS = os.path.join(RES, 'models')
AGENTDOJO_RUNS = os.environ.get('AGENTDOJO_RUNS', os.path.join(DATA, 'agentdojo', 'runs'))
SEED = 20240611


def resolve(path):
    """Return `path` if it exists, else `path + '.gz'` if that exists (the repository ships large CSVs gzipped)."""
    if not os.path.exists(path) and os.path.exists(path + '.gz'):
        return path + '.gz'
    return path


def read_csv(path, **kw):
    import pandas as pd
    return pd.read_csv(resolve(path), **kw)

DEFENCE_SUFFIXES = ['-tool_filter', '-spotlighting_with_delimiting', '-transformers_pi_detector', '-repeat_user_prompt']
DOS_ATTACKS = {'dos', 'captcha_dos', 'felony_dos', 'offensive_email_dos', 'swearwords_dos'}


def is_defended(pipe_dir):
    return any(pipe_dir.endswith(s) for s in DEFENCE_SUFFIXES)


def model_family(pipe_dir):
    p = pipe_dir.lower()
    if p.startswith('gpt'):
        return 'GPT'
    if p.startswith('claude'):
        return 'Claude'
    if p.startswith('gemini'):
        return 'Gemini'
    if 'llama' in p or 'secalign' in p:
        return 'Llama'
    if p.startswith('command'):
        return 'Cohere'
    return 'other'


# ---------------- Trust lattice: integrity of tool outputs ----------------
HIGH, MED, LOW = 2, 1, 0
# Tool outputs whose content can be authored/controlled by third parties = LOW.
LOW_TOOLS = {
    # banking: bill/landlord files, transaction subjects written by counterparties
    'read_file', 'get_most_recent_transactions',
    # slack: channel messages, inbox DMs, arbitrary web pages
    'read_channel_messages', 'read_inbox', 'get_webpage',
    # travel: user-generated reviews
    'get_rating_reviews_for_hotels', 'get_rating_reviews_for_restaurants', 'get_rating_reviews_for_car_rental',
    # workspace: received emails, calendar events (invites by others), cloud files (shared/owned by others)
    'get_unread_emails', 'get_received_emails', 'search_emails',
    'search_calendar_events', 'get_day_calendar_events',
    'search_files_by_filename', 'get_file_by_id', 'list_files', 'search_files',
}
HIGH_TOOLS = {'get_current_day'}
# everything else (self-owned account data, provider listings, action confirmations) = MED


def tool_integrity(tool):
    if tool in LOW_TOOLS:
        return LOW
    if tool in HIGH_TOOLS:
        return HIGH
    return MED


# Data-ownership split used in the mapping table
SELF_OWNED_NOTE = 'self-owned account data / provider listings / action confirmations'

# ---------------- Sink privilege ----------------
PRIV2 = {  # state-changing or exfiltrating
    'send_money', 'schedule_transaction', 'update_scheduled_transaction', 'update_password', 'update_user_info',
    'add_user_to_channel', 'send_direct_message', 'send_channel_message', 'invite_user_to_slack',
    'remove_user_from_slack', 'post_webpage',
    'create_calendar_event', 'cancel_calendar_event', 'reserve_hotel', 'reserve_car_rental', 'reserve_restaurant',
    'send_email', 'delete_email', 'reschedule_calendar_event', 'add_calendar_event_participants',
    'append_to_file', 'create_file', 'delete_file', 'share_file',
}
PRIV1 = {'get_webpage'}  # network egress: URL can carry data to attacker-chosen host


def privilege(fn):
    if fn in PRIV2:
        return 2
    if fn in PRIV1:
        return 1
    return 0


PRIV_FNS = sorted(PRIV2 | PRIV1)

# ---------------- Normalisation ----------------
_ws = re.compile(r'\s+')


def norm(s):
    s = str(s).lower().strip()
    s = s.replace('https://', '').replace('http://', '')
    s = _ws.sub(' ', s)
    return s


def norm_compact(s):
    """canonical form for IBAN/emails/urls/numbers: remove spaces, quotes, trailing slashes."""
    s = norm(s)
    s = s.replace(' ', '').strip('\'"/.,;')
    if s.startswith('www.'):
        s = s[4:]
    try:
        f = float(s)
        s = ('%g' % f)
    except Exception:
        pass
    return s


def flatten_args(args):
    """yield (argname, scalar value string) pairs"""
    out = []
    for k, v in (args or {}).items():
        if isinstance(v, (list, tuple)):
            for x in v[:20]:
                out.append((k, str(x)))
        elif isinstance(v, dict):
            for kk, x in list(v.items())[:20]:
                out.append((k + '.' + str(kk), str(x)))
        elif v is None:
            continue
        else:
            out.append((k, str(v)))
    return out
