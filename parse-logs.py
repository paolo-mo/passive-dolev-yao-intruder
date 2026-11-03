#!/usr/bin/env python3
"""
Parse AnBx protocol logs to extract evaluation statistics.

Compatible with run_test.py's candidate-enumeration section.  Both the legacy
"--- Stage 4-6: Candidate enumeration ---" banner and the current
"--- Stage 5: Candidate enumeration ---" banner are accepted, so older log
files remain parseable.

Emits one CSV row per (protocol, candidate) pair.

The pipeline emits `ExpectedActions: <N>` and `ExpectedChecks: <M>` after
Stage 4 (session build), before Stage 5 (candidate enumeration).  The parser
reads those lines when present and falls back to re-parsing the pretty-printed
spec otherwise.

Usage:
    python parse-logs.py <log_file_or_directory> [--csv <output_csv>]
                        [--no-summary] [--debug]
"""

import re
import os
import sys
import csv
import argparse
from collections import defaultdict

DEBUG = False


def debug_print(*args, **kwargs):
    if DEBUG:
        print(*args, **kwargs)


# ----------------------------------------------------------------------
# Regexes
# ----------------------------------------------------------------------

PROTO_BANNER = re.compile(
    r'^={60}\s*\nProtocol:\s*([A-Za-z0-9_]+)\s*\n={60}\s*$',
    re.MULTILINE
)

# Accept both the legacy "Stage 4-6" banner and the current "Stage 5" banner,
# so older log files remain parseable after the stage-renumbering change.
STAGE_ENUM = re.compile(r'--- Stage (?:4-6|5): Candidate enumeration ---')
NEXT_STAGE = re.compile(r'--- Stage \d')

SESSIONS_INFO = re.compile(
    r'Read sessions from .+?:\s*\[([^\]]*)\]\s*'
    r'\((\d+)\s+sessions?,\s*up to\s+(\d+)\s+candidates?\s+each\)'
)

CAND_SCORE = re.compile(
    r'Candidate (\d+) score:\s*\(\s*(\d+)\s*,\s*(-?\d+)\s*,\s*(\d+)\s*\)'
)

SELECTED = re.compile(
    r'Selected candidate (\d+) with score\s*'
    r'\(\s*(\d+)\s*,\s*(-?\d+)\s*,\s*(\d+)\s*\)'
)

SKIP_NO_TXT  = re.compile(
    r'Candidate TXT not found:\s*\S+_session_meta_c(\d+)\.txt'
)
SKIP_NO_STEP = re.compile(r'No STEP files for candidate (\d+); skipping')

STAGE_START = re.compile(r'(?:^|\n)  -> (.+?) \.\.\.\n')
STAGE_END   = re.compile(r'\n\s+\[(OK|FAIL)\] \((\d+(?:\.\d+)?) ms\)')

CAND_OBJCHECK_RE = re.compile(r'ObjCheck \(candidate (\d+)\)')
CAND_INTRUDER_RE = re.compile(
    r'Java execution \(session (\d+), candidate (\d+)\)'
)

SAVED_STEP  = re.compile(
    r'Saved\s+([A-Za-z0-9_]+)_(\d+)_STEP_(\d+)\.ser'
)
STREAM_READ = re.compile(
    r'Read object from\s+([A-Za-z0-9_]+)_STREAM_(\d+)_(\d+)\.ser'
)

WARNING_LINE = re.compile(
    r'^\s*(?:\[WARNING\]|Warning:).*$',
    re.MULTILINE
)

CHECK_LINE   = re.compile(r'CHECK\s*#\s*(\d+\.\d+)\s+(\w+)')
CHECK_FAILED = re.compile(r'\bcheck FAILED\b', re.IGNORECASE)

SESSION_ASSIGNMENT = re.compile(
    r'^\s+Session (\d+): connections \[([^\]]+)\]\s*$',
    re.MULTILINE
)

# ---- Session completion / execution-mode markers ----
# Emitted by the AnBxJ runtime during Docker execution, one line per role, e.g.:
#   [ROLE_s-ALWAYS] - All sessions completed: 3/3 - Multithreaded Server
#   [ROLE_A-ALWAYS] - All sessions completed: 3/3 - Parallel clients: 3
#   [ROLE_s-ALWAYS] - All sessions completed: 1/1 - Sequential
SESSION_COMPLETION = re.compile(
    r'\[ROLE_([A-Za-z0-9_]+)-ALWAYS\]\s*-\s*'
    r'All sessions completed:\s*(\d+)\s*/\s*(\d+)\s*-\s*(.+?)\s*$',
    re.MULTILINE,
)
SEQ_MARKER = re.compile(r'\bSequential\b', re.IGNORECASE)
PAR_MARKER = re.compile(r'\b(?:Parallel|Multithreaded|Concurrent|Threaded)\b',
                        re.IGNORECASE)

# ---- Preferred sources for expected counts ----
EXPECTED_ACTIONS_LINE = re.compile(
    r'^ExpectedActions:\s*(\d+)\s*$', re.MULTILINE
)
EXPECTED_CHECKS_LINE  = re.compile(
    r'^ExpectedChecks:\s*(\d+)\s*$',  re.MULTILINE
)

# ---- Fallback: pretty-printed .AnB spec ----
ANB_SPEC_BLOCK = re.compile(
    r'--- Protocol specification \([^)]+\) ---\n(.*?)\n'
    r'--- End of protocol specification ---',
    re.DOTALL,
)
ANB_ACTIONS_BLOCK = re.compile(
    r'^\s*Actions:\s*\n(.*?)(?=^\s*\w+:\s*$|\Z)',
    re.MULTILINE | re.DOTALL,
)
ANB_ACTION_LINE = re.compile(r'^\s*\w+\s*->\s*\w+\s*:', re.MULTILINE)

K_VALUE = re.compile(r'K \(connections per session\)\s*=\s*(\d+)')

# Emitted by run_test.py inside each protocol section, after the
# Stage 1 banner, e.g.:
#   Provider: BC
#   Provider: default
# The value is the anbxc -securityProvider argument, not the CLI --provider
# value, so 'default' must be mapped back to 'JDK'.
PROVIDER_LINE = re.compile(r'^Provider:\s*(\S+)\s*$', re.MULTILINE)

def _normalise_provider(raw):
    """
    Map the anbxc -securityProvider argument to the CLI provider label.

      'BC', 'bc'          -> 'BC'
      'default', 'jdk'    -> 'JDK'
      anything else       -> the raw value (kept so unexpected providers
                             are visible rather than silently dropped)
    """
    if not raw:
        return 'unknown'
    low = raw.strip().lower()
    if low == 'bc':
        return 'BC'
    if low in ('default', 'jdk'):
        return 'JDK'
    return raw

def classify_execution_mode(content):
    """
    Returns (mode, min_completed, min_declared).

    Only markers from honest agents are considered.  The passive intruder
    (ROLE_intr) always reports 'Sequential' because it reads step files one
    at a time during reconstruction; that is a property of the intruder, not
    of the protocol being analysed.

    mode is one of:
      'parallel'      - every honest role emitted a parallel marker
      'sequential'    - every honest role emitted a sequential marker
      'mixed'         - honest roles disagree
      'unknown'       - no honest-agent markers
    """
    modes = []
    min_completed = None
    min_declared  = None
    for m in SESSION_COMPLETION.finditer(content):
        role      = m.group(1)
        completed = int(m.group(2))
        declared  = int(m.group(3))
        suffix    = m.group(4)

        # The intruder reconstruction run is always sequential; it is not
        # the mode under which the PCAP was captured.
        if role == 'intr':
            continue

        if min_completed is None or completed < min_completed:
            min_completed = completed
        if min_declared is None or declared < min_declared:
            min_declared = declared

        is_seq = bool(SEQ_MARKER.search(suffix))
        is_par = bool(PAR_MARKER.search(suffix))
        if is_par and is_seq:
            modes.append('mixed')
        elif is_par:
            modes.append('parallel')
        elif is_seq:
            modes.append('sequential')
        else:
            modes.append('unknown')

    if not modes:
        return 'unknown', 0, 0
    distinct = set(modes)
    if distinct == {'parallel'}:                              return 'parallel',   min_completed or 0, min_declared or 0
    if distinct == {'sequential'}:                            return 'sequential', min_completed or 0, min_declared or 0
    if 'parallel' in distinct and 'sequential' in distinct:   return 'mixed',      min_completed or 0, min_declared or 0
    if distinct == {'mixed'}:                                 return 'mixed',      min_completed or 0, min_declared or 0
    return 'unknown', min_completed or 0, min_declared or 0
    
def expected_actions_from_log(content):
    """Prefer 'ExpectedActions: N' from the pipeline; fall back to spec."""
    m = EXPECTED_ACTIONS_LINE.search(content)
    if m:
        return int(m.group(1)), 'log'
    spec = ANB_SPEC_BLOCK.search(content)
    if spec:
        a = ANB_ACTIONS_BLOCK.search(spec.group(1))
        if a:
            return len(ANB_ACTION_LINE.findall(a.group(1))), 'spec'
    return 0, 'unknown'


def expected_checks_from_log(content):
    """Prefer 'ExpectedChecks: N' from the pipeline; 0 otherwise."""
    m = EXPECTED_CHECKS_LINE.search(content)
    if m:
        return int(m.group(1)), 'log'
    return 0, 'unknown'


# ----------------------------------------------------------------------
# Section extraction
# ----------------------------------------------------------------------

def extract_protocol_sections(content):
    matches = list(PROTO_BANNER.finditer(content))
    sections = []
    for i, m in enumerate(matches):
        name = m.group(1)
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
        sections.append((name, content[start:end]))
    return sections


def find_stage_enum(content):
    """Return the slice of the log covering the candidate-enumeration stage.

    Accepts both the legacy `--- Stage 4-6:` banner and the current
    `--- Stage 5:` banner (see STAGE_ENUM).  The slice runs from the banner to
    the next `--- Stage N` banner, or to the end of the section.
    """
    m = STAGE_ENUM.search(content)
    if not m:
        return None
    start = m.end()
    nxt = NEXT_STAGE.search(content, start)
    end = nxt.start() if nxt else len(content)
    return content[start:end]

def parse_stage_blocks(stage_content):
    starts = list(STAGE_START.finditer(stage_content))
    ends   = list(STAGE_END.finditer(stage_content))
    blocks = []
    e_idx = 0
    for start_m in starts:
        body_start = start_m.end()
        while e_idx < len(ends) and ends[e_idx].start() <= body_start:
            e_idx += 1
        if e_idx >= len(ends):
            continue
        end_m = ends[e_idx]
        body = stage_content[body_start:end_m.start()]
        blocks.append((start_m.group(1), body, end_m.group(1)))
        e_idx += 1
    return blocks


# ----------------------------------------------------------------------
# Per-candidate parsing
# ----------------------------------------------------------------------

def _new_candidate_record():
    return {
        'objcheck_ok':      False,
        'objcheck_streams': set(),
        'objcheck_steps_per_session': defaultdict(set),
        'warnings':         [],
        'session_checks':   {},
    }


def parse_stage_blocks_per_candidate(blocks):
    per_cand = defaultdict(_new_candidate_record)

    for desc, body, status in blocks:
        m = CAND_OBJCHECK_RE.match(desc)
        if m:
            idx = int(m.group(1))
            c = per_cand[idx]
            c['objcheck_ok'] = (status == 'OK')
            for sm in STREAM_READ.finditer(body):
                c['objcheck_streams'].add(int(sm.group(2)))
            for sm in SAVED_STEP.finditer(body):
                session = int(sm.group(2))
                step    = int(sm.group(3))
                c['objcheck_steps_per_session'][session].add(step)
            for wm in WARNING_LINE.finditer(body):
                c['warnings'].append(wm.group(0).strip())
            continue

        m = CAND_INTRUDER_RE.match(desc)
        if m:
            session_id = int(m.group(1))
            idx        = int(m.group(2))
            c = per_cand[idx]
            checks = c['session_checks'].setdefault(session_id, {})
            current_check = None
            for line in body.splitlines():
                cm = CHECK_LINE.search(line)
                if cm:
                    cid   = cm.group(1)
                    ctype = cm.group(2).upper()
                    current_check = cid
                    if cid not in checks:
                        checks[cid] = {'type': ctype, 'status': 'ok'}
                    continue
                if current_check and CHECK_FAILED.search(line):
                    if current_check in checks:
                        checks[current_check]['status'] = 'failed'

    return per_cand


def summarize_checks(session_checks):
    total = 0
    failed = 0
    types = defaultdict(int)
    for checks in session_checks.values():
        for cid, info in checks.items():
            total += 1
            if info['status'] == 'failed':
                failed += 1
            types[info['type']] += 1
    return total, failed, types


# ----------------------------------------------------------------------
# Per-protocol parsing
# ----------------------------------------------------------------------

def parse_protocol(name, content, run_index):
    """Return a list of row dicts, one per candidate, tagged with run_index."""
    stage = find_stage_enum(content)
    if stage is None:
        debug_print(f"[{name}/run{run_index}] no candidate-enumeration section")
        return []

    # --- sessions info (searched on section content, not stage slice) ---
    sessions_count = 0
    max_candidates = 1
    sm = SESSIONS_INFO.search(content)
    if sm:
        sessions_count = int(sm.group(2))
        max_candidates = int(sm.group(3))

    
    # --- K (connections per session), emitted by sessionbuild.py ---
    km = K_VALUE.search(content)
    k_value = int(km.group(1)) if km else 0
    
    # --- provider, emitted by run_test.py inside this protocol section ---
    pm = PROVIDER_LINE.search(content)
    provider = _normalise_provider(pm.group(1)) if pm else 'unknown'
    
    # --- expected counts ---
    expected_actions, actions_src = expected_actions_from_log(content)
    expected_checks,  checks_src  = expected_checks_from_log(content)
    exec_mode, min_completed, min_declared = classify_execution_mode(content)
    parallel_capable = 1 if (exec_mode == 'parallel' and min_completed == min_declared) else 0
    debug_print(
        f"[{name}/run{run_index}] execution mode = {exec_mode} "
        f"({min_completed}/{min_declared} sessions), "
        f"expected_actions={expected_actions} ({actions_src}), "
        f"expected_checks={expected_checks} ({checks_src})"
    )

    # Total expected messages across all parallel sessions of this run
    expected_messages = sessions_count * expected_actions

    # --- per-candidate scores ---
    scores = {}
    for m in CAND_SCORE.finditer(stage):
        idx = int(m.group(1))
        scores[idx] = {
            'n_clean':      int(m.group(2)),
            'neg_failed':   int(m.group(3)),
            'total_checks': int(m.group(4)),
        }

    # --- winner (per run) ---
    winner = None
    wm = SELECTED.search(stage)
    if wm:
        winner = int(wm.group(1))

    # --- skipped candidates (per run) ---
    skipped = set()
    for m in SKIP_NO_TXT.finditer(stage):
        skipped.add(int(m.group(1)))
    for m in SKIP_NO_STEP.finditer(stage):
        skipped.add(int(m.group(1)))

    # --- per-candidate stage-block data ---
    blocks   = parse_stage_blocks(stage)
    per_cand = parse_stage_blocks_per_candidate(blocks)

    # --- winning assignment (per run) ---
    winning_assignment = {}
    if winner is not None:
        for m in SESSION_ASSIGNMENT.finditer(stage):
            sid   = int(m.group(1))
            conns = [c.strip() for c in m.group(2).split(',')]
            winning_assignment[sid] = conns

    candidate_indices = set(scores) | set(per_cand) | skipped
    if not candidate_indices:
        candidate_indices = {0}

    rows = []
    for idx in sorted(candidate_indices):
        c     = per_cand.get(idx, _new_candidate_record())
        score = scores.get(idx)
        is_selected = 1 if winner == idx else 0
        is_skipped  = 1 if idx in skipped else 0

        parsed_total, parsed_failed, check_types = \
            summarize_checks(c['session_checks'])

        if score is not None:
            total_checks = score['total_checks']
            failed       = -score['neg_failed']
            clean        = score['n_clean']
            score_str    = f"{clean},{score['neg_failed']},{total_checks}"
        else:
            total_checks = parsed_total
            failed       = parsed_failed
            clean        = -1
            score_str    = ''

        successful = total_checks - failed

        # Recovered messages: sum across sessions
        recovered = sum(len(steps)
                        for steps in c['objcheck_steps_per_session'].values())

        # Percentages
        if expected_messages > 0:
            recovered_pct = round(recovered / expected_messages * 100, 1)
        else:
            recovered_pct = ''
        if total_checks > 0:
            checks_pct = round(successful / total_checks * 100, 1)
        else:
            checks_pct = ''

        assignment_str = ''
        if is_selected and winning_assignment:
            parts = [f"S{sid}=[{'|'.join(winning_assignment[sid])}]"
                     for sid in sorted(winning_assignment)]
            assignment_str = '; '.join(parts)

        # Derived completion flags (1/0)
        has_baseline      = expected_messages > 0
        objects_complete  = 1 if (has_baseline and recovered == expected_messages) else 0
        passive_dy_complete = 1 if (total_checks > 0 and failed == 0) else 0
        overall_success   = 1 if (c['objcheck_ok'] and objects_complete
                                  and passive_dy_complete) else 0
        objects_missing   = max(0, expected_messages - recovered) if has_baseline else 0      
        
        rows.append({
            'Protocol':          name,
            'Run':               run_index,
            'Candidate':         idx,
            'Selected':          is_selected,
            'Skipped':           is_skipped,
            'Sessions':          sessions_count,
            'Provider':          provider,
            'K':                 k_value,
            'MaxCandidates':     max_candidates,
            'Score':             score_str,
            'CleanSessions':     clean,
            'ObjCheckOK':        1 if c['objcheck_ok'] else 0,
            'ObjectsComplete':   objects_complete,
            'PassiveDYComplete': passive_dy_complete,
            'OverallSuccess':    overall_success,
            'ExpectedActions':   expected_actions,
            'ExpectedMessages':  expected_messages,
            'StepsRecovered':    recovered,
            'StepsRecoveredPct': recovered_pct,
            'ObjectsMissing':    objects_missing,
            'ExpectedChecks':    expected_checks,
            'TotalChecks':       total_checks,
            'SuccessfulChecks':  successful,
            'FailedChecks':      failed,
            'ChecksSuccessPct':  checks_pct,
            'EqChecks':          check_types.get('EQ',    0),
            'WffChecks':         check_types.get('WFF',   0),
            'InvChecks':         check_types.get('INV',   0),
            'NoteqChecks':       check_types.get('NOTEQ', 0),
            'SeenChecks':        check_types.get('SEEN',  0),
            'Streams':           len(c['objcheck_streams']),
            'SessionAssignment': assignment_str,
            'Warnings':          '; '.join(c['warnings']) if c['warnings'] else '',
            'ExecutionMode':     exec_mode,
            'ParallelCapable':   parallel_capable,
            'SessionsCompleted': min_completed, 
            'SessionsDeclared': min_declared,
            '_n_candidates_in_run': len(candidate_indices),
            '_n_skipped_in_run':    len(skipped),
        })
    return rows


def parse_log_file(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    sections = extract_protocol_sections(content)
    debug_print(f"{filepath}: {len(sections)} protocol run(s) detected")

    if not sections:
        m = re.search(r'Protocol:\s*([A-Za-z0-9_]+)', content)
        name = m.group(1) if m else 'Unknown'
        sections = [(name, content)]

    run_counters = defaultdict(int)
    rows = []
    for name, body in sections:
        run_counters[name] += 1
        rows.extend(parse_protocol(name, body, run_counters[name]))
    return rows


def process_files(input_path):
    if os.path.isfile(input_path):
        files = [input_path]
    elif os.path.isdir(input_path):
        files = [
            os.path.join(input_path, f)
            for f in sorted(os.listdir(input_path))
            if f.endswith('.txt') or f.endswith('.log')
        ]
    else:
        print(f"Error: {input_path} is not a file or directory.")
        sys.exit(1)

    rows = []
    for f in files:
        rows.extend(parse_log_file(f))
    return rows


# ----------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------

def _print_success_block(winner_rows, label=None):
    """
    Print the RECONSTRUCTION SUCCESS AND OBJECT ACCURACY block for a given
    list of winner rows.  label is an optional header to distinguish the
    overall totals from the parallel/sequential subsets.
    """
    if not winner_rows:
        return

    if label:
        print("\n" + "=" * 70)
        print(f" {label}")
        print("=" * 70)

    n = len(winner_rows)

    objcheck_complete   = sum(1 for r in winner_rows if r['ObjCheckOK']        == 1)
    objects_recovered   = sum(1 for r in winner_rows if r['ObjectsComplete']   == 1)
    passive_dy_complete = sum(1 for r in winner_rows if r['PassiveDYComplete'] == 1)
    overall_success     = sum(1 for r in winner_rows if r['OverallSuccess']    == 1)

    prot_missing = sum(1 for r in winner_rows if r['ObjectsMissing'] > 0)
    prot_failed  = sum(1 for r in winner_rows if r['FailedChecks']   > 0)

    tot_expected  = sum(r['ExpectedMessages'] for r in winner_rows)
    tot_recovered = sum(r['StepsRecovered']   for r in winner_rows)
    tot_missing   = sum(r['ObjectsMissing']   for r in winner_rows)

    tot_checks   = sum(r['TotalChecks']      for r in winner_rows)
    tot_passed   = sum(r['SuccessfulChecks'] for r in winner_rows)
    tot_failed   = sum(r['FailedChecks']     for r in winner_rows)

    tot_eq    = sum(r['EqChecks']    for r in winner_rows)
    tot_wff   = sum(r['WffChecks']   for r in winner_rows)
    tot_inv   = sum(r['InvChecks']   for r in winner_rows)
    tot_seen  = sum(r['SeenChecks']  for r in winner_rows)

    def pct(a, b):
        return f"{a / b * 100:.1f}%" if b else "n/a"

    n_total_candidates = sum(
        r.get('_n_candidates_in_run', 1) for r in winner_rows
    )
    n_selected = n
    n_skipped  = sum(r.get('_n_skipped_in_run', 0) for r in winner_rows)
    n_scored   = n_total_candidates - n_skipped

    print("-" * 70)
    print(f"  Protocols in scope             : {n:4d}")
    print("-" * 70)
    print(f"  ObjCheck completion            : {objcheck_complete:4d}/{n:<4d} "
          f"({pct(objcheck_complete, n)})")
    print(f"  All objects recovered          : {objects_recovered:4d}/{n:<4d} "
          f"({pct(objects_recovered, n)})")
    print(f"  Passive DY completion          : {passive_dy_complete:4d}/{n:<4d} "
          f"({pct(passive_dy_complete, n)})")
    print(f"  Overall success                : {overall_success:4d}/{n:<4d} "
          f"({pct(overall_success, n)})")
    print("-" * 70)
    print(f"  Protocols with missing objects : {prot_missing:4d}")
    print(f"  Protocols with failed checks   : {prot_failed:4d}")
    print("-" * 70)
    print(f"  Expected steps (objects)       : {tot_expected:4d}")
    print(f"  Objects recovered              : {tot_recovered:4d} "
          f"({pct(tot_recovered, tot_expected)})")
    print(f"  Objects missing                : {tot_missing:4d} "
          f"({pct(tot_missing, tot_expected)})")
    print("-" * 70)
    print(f"  Total consistency checks       : {tot_checks:4d}")
    print(f"  Checks passed                  : {tot_passed:4d} "
          f"({pct(tot_passed, tot_checks)})")
    print(f"  Checks failed                  : {tot_failed:4d} "
          f"({pct(tot_failed, tot_checks)})")
    print(f"  Equality checks                : {tot_eq:4d}")
    print(f"  Well-formedness checks         : {tot_wff:4d}")
    print(f"  Inversion checks               : {tot_inv:4d}")
    print(f"  Seen checks                    : {tot_seen:4d}")
    print("-" * 70)

    if prot_missing:
        print("\n  Protocols with missing objects:")
        for r in sorted(winner_rows, key=lambda x: x['Protocol']):
            if r['ObjectsMissing'] > 0:
                print(f"    {r['Protocol']:40s}  "
                      f"missing {r['ObjectsMissing']} of {r['ExpectedMessages']}")
    if prot_failed:
        print("\n  Protocols with failed checks:")
        for r in sorted(winner_rows, key=lambda x: x['Protocol']):
            if r['FailedChecks'] > 0:
                print(f"    {r['Protocol']:40s}  "
                      f"{r['FailedChecks']} failed of {r['TotalChecks']}")

def print_summary(rows):
    if not rows:
        print("No rows to summarize.")
        return

    runs = defaultdict(list)
    for r in rows:
        runs[(r['Protocol'], r['Run'])].append(r)

    n_runs      = len(runs)
    n_protocols = len({k[0] for k in runs})
    n_success   = sum(1 for c in runs.values()
                      if any(r['Selected'] == 1 for r in c))

    print("\n" + "=" * 70)
    print("SUMMARY STATISTICS")
    print("=" * 70)
    print(f"Unique protocols:                   {n_protocols:4d}")
    print(f"Total runs (protocol invocations):  {n_runs:4d}")
    print(f"Runs with a selected candidate:     {n_success:4d}  "
          f"({n_success / n_runs * 100:.1f}%)")

    session_dist = defaultdict(int)
    for run_rows in runs.values():
        session_dist[run_rows[0]['Sessions']] += 1
    if session_dist:
        print("\nSession distribution (per run):")
        for s in sorted(session_dist):
            print(f"  {s} session(s): {session_dist[s]} run(s)")

    mode_dist = defaultdict(int)
    parallel_protos = set()
    sequential_protos = set()
    mixed_protos = set()
    unknown_protos = set()
    for (proto, run), run_rows in runs.items():
        mode = run_rows[0].get('ExecutionMode', 'unknown')
        mode_dist[mode] += 1
        if mode == 'parallel':
            parallel_protos.add(proto)
        elif mode == 'sequential':
            sequential_protos.add(proto)
        elif mode == 'mixed':
            mixed_protos.add(proto)
        else:
            unknown_protos.add(proto)

    if mode_dist:
        print("\nExecution mode (per run):")
        for mode in ('parallel', 'sequential', 'mixed', 'unknown'):
            if mode_dist.get(mode):
                print(f"  {mode:11s}: {mode_dist[mode]:4d} run(s)")

    # Protocols that are parallel-capable on every run observed
    parallel_always = parallel_protos - sequential_protos - mixed_protos
    sequential_always = sequential_protos - (parallel_protos | mixed_protos | unknown_protos)

    if parallel_always:
        print(f"\n  Parallel-capable protocols "
              f"({len(parallel_always)} unique):")
        by_k = defaultdict(list)
        for proto in sorted(parallel_always):
            # take the K from any winner row for that protocol
            for (p, run), run_rows in runs.items():
                if p == proto:
                    by_k[run_rows[0].get('K', 0)].append(proto)
                    break
        for k in sorted(by_k):
            print(f"    K={k} ({len(by_k[k])}):")
            for proto in by_k[k]:
                print(f"      {proto}")
    if sequential_always:
        print(f"\n  Sequential-only protocols "
              f"({len(sequential_always)} unique):")
        for proto in sorted(sequential_always):
            print(f"    {proto}")
    if mixed_protos or unknown_protos:
        print(f"\n  Inconsistent or undetermined mode "
              f"({len(mixed_protos | unknown_protos)} unique):")
        for proto in sorted(mixed_protos | unknown_protos):
            print(f"    {proto}")

    print("\nCandidate enumeration (per run):")
    for (proto, run), run_rows in sorted(runs.items()):
        run_rows = sorted(run_rows, key=lambda x: x['Candidate'])
        parts = []
        for c in run_rows:
            marker = '*' if c['Selected'] else ' '
            tag = c['Score'] if c['Score'] else ('skip' if c['Skipped'] else '—')
            parts.append(f"{marker}{c['Candidate']}={tag}")
        winner = next((r['Candidate'] for r in run_rows if r['Selected']), None)
        win_str = f" -> selected {winner}" if winner is not None else " -> no winner"
        print(f"  {proto} (run {run}): {'  '.join(parts)}{win_str}")

    print("\nSteps and checks (selected candidate per run):")
    for (proto, run), run_rows in sorted(runs.items()):
        winner = next((r for r in run_rows if r['Selected']), None)
        if not winner:
            print(f"  {proto} (run {run}): no winner")
            continue
        em   = winner['ExpectedMessages']
        rec  = winner['StepsRecovered']
        recp = winner['StepsRecoveredPct']
        tc   = winner['TotalChecks']
        sc   = winner['SuccessfulChecks']
        ccp  = winner['ChecksSuccessPct']
        ec   = winner['ExpectedChecks']
        recp_s = f"{recp}%" if recp != '' else "n/a"
        ccp_s  = f"{ccp}%" if ccp  != '' else "n/a"
        ec_s   = f" of {ec}" if ec > 0 else ""
        k    = winner.get('K', 0)
        mode = winner.get('ExecutionMode', 'unknown')
        prov = winner.get('Provider', 'unknown')
        print(f"  {proto:40s} (run {run}, {prov}): "
              f"K={k}, "
              f"steps {rec}/{em} ({recp_s}), "
              f"checks {sc}/{tc}{ec_s} ({ccp_s}), "
              f"[{mode}]")
    selected = sum(1 for r in rows if r['Selected'] == 1)
    print(f"\nSelected rows:                      {selected:4d}")

    winner_rows = [r for r in rows if r['Selected'] == 1]
    if not winner_rows:
        return

    max_sessions = max(r['Sessions'] for r in winner_rows)

    if max_sessions == 1:
        # Single-session run: one block, no split.
        _print_success_block(winner_rows, "ALL PROTOCOLS")
    else:
        # Multi-session run: overall, then split by execution mode.
        _print_success_block(winner_rows, "ALL PROTOCOLS")

        parallel_rows = [r for r in winner_rows
                         if r.get('ExecutionMode') == 'parallel']
        sequential_rows = [r for r in winner_rows
                           if r.get('ExecutionMode') == 'sequential']
        other_rows = [r for r in winner_rows
                      if r.get('ExecutionMode') not in ('parallel', 'sequential')]

        if parallel_rows:
            _print_success_block(
                parallel_rows,
                f"PARALLEL PROTOCOLS (N={max_sessions}) — multi-session scope"
            )
        if sequential_rows:
            _print_success_block(
                sequential_rows,
                f"SEQUENTIAL PROTOCOLS (N={max_sessions}) — captured as a "
                f"single session, excluded from multi-session claim"
            )
        if other_rows:
            _print_success_block(
                other_rows,
                f"OTHER PROTOCOLS (N={max_sessions}) — execution mode unknown"
            )

# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

COLUMN_ORDER = [
    'Protocol', 'Run', 'Provider', 'Candidate', 'Selected', 'Skipped',
    'Sessions', 'K', 'MaxCandidates',
    'Score', 'CleanSessions',
    'ObjCheckOK', 'ObjectsComplete', 'PassiveDYComplete', 'OverallSuccess',
    'ExpectedActions', 'ExpectedMessages',
    'StepsRecovered', 'StepsRecoveredPct', 'ObjectsMissing',
    'ExpectedChecks', 'TotalChecks', 'SuccessfulChecks', 'FailedChecks',
    'ChecksSuccessPct',
    'EqChecks', 'WffChecks', 'InvChecks', 'NoteqChecks', 'SeenChecks',
    'Streams',
    'SessionAssignment', 'Warnings',
    'ExecutionMode', 'ParallelCapable', 'SessionsCompleted', 'SessionsDeclared','_n_candidates_in_run','_n_skipped_in_run'
]


def main():
    parser = argparse.ArgumentParser(
        description="Parse AnBx protocol logs (per-candidate format).",
        epilog="Example: python parse-logs.py ./logs/ --csv results.csv"
    )
    parser.add_argument(
        'input_path',
        help='Path to a log file or directory containing .txt/.log files'
    )
    parser.add_argument(
        '--csv', default='protocol_stats.csv',
        help='Output CSV filename (default: protocol_stats.csv)'
    )
    parser.add_argument(
        '--no-summary', action='store_true',
        help='Suppress the console summary'
    )
    parser.add_argument(
        '--debug', action='store_true',
        help='Print parser debug information'
    )
    args = parser.parse_args()

    global DEBUG
    DEBUG = args.debug

    rows = process_files(args.input_path)
    if not rows:
        print("No data found.")
        return

    with open(args.csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=COLUMN_ORDER)
        writer.writeheader()
        writer.writerows(rows)

    print(f"CSV written to {args.csv}  ({len(rows)} rows)")

    if not args.no_summary:
        print_summary(rows)


if __name__ == '__main__':
    main()