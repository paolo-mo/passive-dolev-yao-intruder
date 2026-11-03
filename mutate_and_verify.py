#!/usr/bin/env python3
"""
mutate_and_verify.py — Rejection of mutated captures experiment.

Runs the passive intruder on deliberately modified per-step files and
records whether the intruder rejects each mutation.

Mutations:
    deletion        remove one STEP file.
    duplication     copy one STEP file over another in the same session.
    cross_session   copy a STEP file from one session over the same step
                    in another session (requires N >= 2).

Rejection is defined as: the intruder emits at least one `check FAILED!`
marker, or the `runagents` process exits non-zero (a missing STEP file
produces a FileNotFoundException, which is a rejection for our purposes).

Prerequisites:
    The pipeline must have been run successfully for the target protocol:
        python run_test.py <Protocol> --sessions <N> --provider JDK
    so that the snapshot directory
        {BASE_PATH}/<protocol>/<Protocol>_step_snapshots/c<winner>/
    contains the winning reconstruction's STEP files.

Usage:
    python mutate_and_verify.py Carlsen --sessions 1
    python mutate_and_verify.py Carlsen --sessions 2
    python mutate_and_verify.py --protocols Carlsen,WooLam --sessions 2
    python mutate_and_verify.py --all --sessions 1 --csv mutations.csv
"""

import argparse
import configparser
import csv
import re
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

# ----------------------------------------------------------------------
# Configuration (mirrors run_test.py)
# ----------------------------------------------------------------------
_cfg = configparser.ConfigParser()
_cfg.read(SCRIPT_DIR / "jpcap2ser.cfg")

def _resolve(key, default=""):
    val = _cfg['DEFAULT'].get(key, default)
    if val and not Path(val).is_absolute():
        val = str((SCRIPT_DIR / val).resolve())
    return val

BASE_PATH    = Path(_resolve('BASE_PATH'))
PROT_FOLDER  = Path(_resolve('PROT_FOLDER'))
BASEDIR      = Path(_resolve('BASEDIR'))
ANT_CMD      = _cfg['DEFAULT'].get('ANT_CMD', 'ant')
if ' ' in ANT_CMD:
    ANT_CMD = f'"{ANT_CMD}"'
PROVIDER_FLAG = 'default'   # JDK

# ----------------------------------------------------------------------
# Intruder log parsing (same markers as run_test.py)
# ----------------------------------------------------------------------
_CHECK_START  = re.compile(r'CHECK # ([\d.]+)')
_CHECK_FAILED = re.compile(r'check FAILED!')
_INTRUDER     = re.compile(r'\[ROLE_intr-')

def parse_intruder_log(text):
    """Return (total_checks, failed_checks) from a captured runagents log."""
    per_check = {}
    current = None
    for line in text.splitlines():
        if not _INTRUDER.search(line):
            continue
        m = _CHECK_START.search(line)
        if m:
            current = m.group(1)
            per_check.setdefault(current, 'ok')
            continue
        if current is not None and _CHECK_FAILED.search(line):
            per_check[current] = 'failed'
    total  = len(per_check)
    failed = sum(1 for v in per_check.values() if v == 'failed')
    return total, failed

# ----------------------------------------------------------------------
# Snapshot handling
# ----------------------------------------------------------------------
def read_winner(src_folder, protocol):
    """Read the winning candidate index from {Protocol}_session_meta.txt."""
    meta = src_folder / f"{protocol}_session_meta.txt"
    if not meta.exists():
        return None
    for line in meta.read_text().splitlines():
        if line.startswith("selected_candidate="):
            try:
                return int(line.split("=", 1)[1].strip())
            except ValueError:
                return None
    return None

def restore_winner(src_folder, protocol, winner):
    """Copy the winning candidate's STEP files into src_folder."""
    snap = src_folder / f"{protocol}_step_snapshots" / f"c{winner}"
    if not snap.exists():
        raise FileNotFoundError(f"Winner snapshot not found: {snap}")
    for f in src_folder.glob(f"{protocol}_*_STEP_*.ser"):
        f.unlink()
    for f in snap.glob(f"{protocol}_*_STEP_*.ser"):
        shutil.copyfile(f, src_folder / f.name)

def discover_steps(src_folder, protocol, sid):
    """Return sorted step numbers for a given session."""
    pat = re.compile(rf'^{re.escape(protocol)}_{sid}_STEP_(\d+)\.ser$')
    nums = []
    for f in src_folder.glob(f"{protocol}_{sid}_STEP_*.ser"):
        m = pat.match(f.name)
        if m:
            nums.append(int(m.group(1)))
    return sorted(nums)

# ----------------------------------------------------------------------
# Mutations
# ----------------------------------------------------------------------
def mutate_deletion(src_folder, protocol, sid, step):
    target = src_folder / f"{protocol}_{sid}_STEP_{step}.ser"
    if not target.exists():
        return False
    target.unlink()
    return True

def mutate_duplication(src_folder, protocol, sid, src_step, dst_step):
    src = src_folder / f"{protocol}_{sid}_STEP_{src_step}.ser"
    dst = src_folder / f"{protocol}_{sid}_STEP_{dst_step}.ser"
    if not (src.exists() and dst.exists()):
        return False
    shutil.copyfile(src, dst)
    return True

def mutate_cross_session(src_folder, protocol, from_sid, to_sid, step):
    src = src_folder / f"{protocol}_{from_sid}_STEP_{step}.ser"
    dst = src_folder / f"{protocol}_{to_sid}_STEP_{step}.ser"
    if not (src.exists() and dst.exists()):
        return False
    shutil.copyfile(src, dst)
    return True

# ----------------------------------------------------------------------
# Intruder execution
# ----------------------------------------------------------------------

def run_intruders(src_folder, session_ids, anbx_file):
    """
    Run `ant runagents` once per session.  anbxc overwrites the
    ROLE_intr class with each invocation, so each session's intruder must
    be regenerated and executed in turn; generating all of them first
    would leave only the last one in place.
    """
    logs = []
    for sid in session_ids:
        cmd_gen = (f'anbxc "{anbx_file}" -out:Java -objcheck '
                   f'-nocfgmsg -silent '
                   f'-securityProvider {PROVIDER_FLAG} '
                   f'-objchecksession {sid}')
        r_gen = subprocess.run(cmd_gen, cwd=BASEDIR, shell=True,
                               capture_output=True, text=True)
        if r_gen.returncode != 0:
            logs.append({'session': sid, 'rc': r_gen.returncode,
                         'stdout': r_gen.stdout or '',
                         'stderr': r_gen.stderr or ''})
            continue
        cmd_run = f'{ANT_CMD} -buildfile "{src_folder}/build.xml" runagents'
        r_run = subprocess.run(cmd_run, cwd=BASEDIR, shell=True,
                               capture_output=True, text=True, timeout=600)
        logs.append({'session': sid, 'rc': r_run.returncode,
                     'stdout': r_run.stdout or '',
                     'stderr': r_run.stderr or ''})
    return logs

def evaluate(logs, baseline_total=None):
    """
    Return (rejected_intruder, rejected_completeness,
            total_checks, failed_checks, reason).

    rejected_intruder     : at least one check FAILED, or runagents rc != 0
    rejected_completeness : fewer checks ran than in the baseline, i.e. a
                            step was skipped and its checks suppressed

    A mutation is rejected overall if either flag is set. The two flags
    identify different failure modes and are reported separately so the
    experiment can attribute each rejection to its mechanism.
    """
    total = 0
    failed = 0
    any_rc = False
    for l in logs:
        t, f = parse_intruder_log(l['stdout'] + '\n' + l['stderr'])
        total  += t
        failed += f
        if l['rc'] != 0:
            any_rc = True

    if any_rc:
        rcs = [l['rc'] for l in logs]
        return True, False, total, failed, f"runagents rc={rcs}"
    if failed > 0:
        return True, False, total, failed, f"{failed}/{total} checks failed"
    if baseline_total is not None and total < baseline_total:
        return False, True, total, failed, \
               f"only {total} of {baseline_total} checks ran"
    return False, False, total, failed, f"all {total} checks passed"

# ----------------------------------------------------------------------
# Experiment driver
# ----------------------------------------------------------------------
def run_one(protocol, sessions, src_folder, anbx_file, verbose=False):
    """Run the three mutations on a single protocol. Returns list of row dicts."""
    winner = read_winner(src_folder, protocol)
    if winner is None:
        return [_skip_row(protocol, sessions,
                          'no selected_candidate in session_meta.txt')]

    try:
        restore_winner(src_folder, protocol, winner)
    except FileNotFoundError as e:
        return [_skip_row(protocol, sessions, str(e))]

    # Session IDs to drive per-session intruder generation and execution.
    session_ids = list(range(1, sessions + 1))
    
    # ---------- Baseline ----------
    # Run the intruder on the unmutated winning reconstruction. This
    # provides two reference quantities:
    #   baseline_checks : the number of checks a complete, valid
    #                     reconstruction executes (used to detect a
    #                     suppressed-check mutation such as deletion).
    # The baseline must be accepted by both mechanisms, otherwise the
    # reconstruction state is not clean and the mutations would not be
    # interpretable.
    logs = run_intruders(src_folder, session_ids, anbx_file)
    base_rej_i, base_rej_c, base_total, base_failed, base_reason = evaluate(logs)
    
    # Sanity: each session's log must reference that session's STEP files.
    # If all logs reference the same session prefix, the intruder was not
    # regenerated per session (the bug fixed in this version of the script).
    if sessions >= 2:
        prefixes = set()
        for entry in logs:
            for m in re.finditer(rf'{re.escape(protocol)}_(\d+)_STEP_',
                                 entry['stdout'] + entry['stderr']):
                prefixes.add(int(m.group(1)))
        expected = set(session_ids)
        if prefixes != expected:
            print(f"  [warn] baseline logs reference session prefixes "
                  f"{sorted(prefixes)}, expected {sorted(expected)}; "
                  f"the intruder may not have been regenerated per session")

    if verbose:
        print(f"  [baseline] rejected_intruder={base_rej_i}  "
              f"rejected_completeness={base_rej_c}  {base_reason}")

    if base_rej_i or base_rej_c:
        return [{
            'protocol': protocol, 'sessions': sessions,
            'mutation': 'baseline', 'applied': 1,
            'rejected_intruder':     1 if base_rej_i else 0,
            'rejected_completeness': 1 if base_rej_c else 0,
            'rejected_any':          1,
            'checks_total':          base_total,
            'checks_failed':         base_failed,
            'baseline_checks':       base_total,
            'reason': f'baseline unexpectedly rejected: {base_reason}',
        }]

    baseline_checks = base_total

    # ---------- Plan ----------
    steps = {sid: discover_steps(src_folder, protocol, sid)
             for sid in session_ids}

    plan = []

    # Deletion: middle step of session 1.
    s1 = steps.get(1, [])
    if len(s1) >= 2:
        plan.append(('deletion', dict(sid=1, step=s1[len(s1) // 2])))

    # Duplication: copy step 1 over step 2 in session 1.
    if len(s1) >= 2:
        plan.append(('duplication',
                     dict(sid=1, src_step=s1[0], dst_step=s1[1])))

    # Cross-session: copy a middle step of session 2 over the same step
    # in session 1.  The middle of the sequence is more likely to carry
    # observable session-specific content than the last step, which is
    # often an encrypted acknowledgement.
    s2 = steps.get(2, [])
    if sessions >= 2 and len(s2) >= 2:
        plan.append(('cross_session',
                     dict(from_sid=2, to_sid=1, step=s2[len(s2) // 2])))

    # ---------- Apply mutations ----------
    rows = []
    for kind, params in plan:
        restore_winner(src_folder, protocol, winner)

        if kind == 'deletion':
            applied = mutate_deletion(src_folder, protocol,
                                      params['sid'], params['step'])
        elif kind == 'duplication':
            applied = mutate_duplication(src_folder, protocol,
                                         params['sid'],
                                         params['src_step'],
                                         params['dst_step'])
        elif kind == 'cross_session':
            applied = mutate_cross_session(src_folder, protocol,
                                           params['from_sid'],
                                           params['to_sid'],
                                           params['step'])
        else:
            applied = False

        if not applied:
            rows.append({
                'protocol': protocol, 'sessions': sessions,
                'mutation': kind, 'applied': 0,
                'rejected_intruder': 0, 'rejected_completeness': 0,
                'rejected_any': 0,
                'checks_total': 0, 'checks_failed': 0,
                'baseline_checks': baseline_checks,
                'reason': 'mutation could not be applied',
            })
            continue

        logs = run_intruders(src_folder, session_ids, anbx_file)
        rej_i, rej_c, tot, fail, reason = evaluate(logs,
                                                   baseline_total=baseline_checks)

        rows.append({
            'protocol': protocol, 'sessions': sessions,
            'mutation': kind, 'applied': 1,
            'rejected_intruder':     1 if rej_i else 0,
            'rejected_completeness': 1 if rej_c else 0,
            'rejected_any':          1 if (rej_i or rej_c) else 0,
            'checks_total':          tot,
            'checks_failed':         fail,
            'baseline_checks':       baseline_checks,
            'reason': reason,
        })

        if verbose:
            tag = 'REJECTED' if (rej_i or rej_c) else 'ACCEPTED'
            mech = []
            if rej_i: mech.append('intruder')
            if rej_c: mech.append('completeness')
            mech_s = f" via {'+'.join(mech)}" if mech else ""
            print(f"  [{kind:14s}] {tag:9s}{mech_s}  {reason}")

    # Leave src_folder in the winner state.
    restore_winner(src_folder, protocol, winner)
    return rows


def _skip_row(protocol, sessions, reason):
    """Row emitted when the experiment cannot run for a protocol."""
    return {
        'protocol': protocol, 'sessions': sessions,
        'mutation': 'all', 'applied': 0,
        'rejected_intruder': -1, 'rejected_completeness': -1,
        'rejected_any': -1,
        'checks_total': 0, 'checks_failed': 0,
        'baseline_checks': 0,
        'reason': reason,
    }

# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('protocol', nargs='?', help='Single protocol name')
    ap.add_argument('--protocols', default=None,
                    help='Comma-separated list of protocols')
    ap.add_argument('--all', action='store_true',
                    help='All protocols in PROT_FOLDER')
    ap.add_argument('--sessions', type=int, default=1,
                    help='Number of sessions used in the pipeline run')
    ap.add_argument('--csv', default='mutations.csv',
                    help='Output CSV (default: mutations.csv)')
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    if args.protocols:
        protocols = [p.strip() for p in args.protocols.split(',') if p.strip()]
    elif args.all:
        protocols = sorted(f.stem for f in PROT_FOLDER.glob('*.AnBx')
                           if not f.stem.endswith('_intr'))
    elif args.protocol:
        protocols = [args.protocol]
    else:
        ap.error('Specify a protocol, --protocols, or --all.')

    all_rows = []
    for proto in protocols:
        src_folder = BASE_PATH / proto.lower()
        anbx_file  = PROT_FOLDER / f"{proto}.AnBx"

        if not src_folder.exists():
            print(f"[skip] {proto}: {src_folder} does not exist")
            continue
        if not anbx_file.exists():
            print(f"[skip] {proto}: {anbx_file} does not exist")
            continue
        if not any(src_folder.glob(f"{proto}_*_STEP_*.ser")):
            print(f"[skip] {proto}: no STEP files (run the pipeline first)")
            continue

        print(f"=== {proto} (N={args.sessions}) ===")
        rows = run_one(proto, args.sessions, src_folder, anbx_file,
                       verbose=args.verbose)
        all_rows.extend(rows)

    if not all_rows:
        print("No rows produced.")
        return

    fieldnames = [
        'protocol', 'sessions', 'mutation', 'applied',
        'rejected_intruder', 'rejected_completeness', 'rejected_any',
        'checks_total', 'checks_failed', 'baseline_checks', 'reason',
    ]
    with open(args.csv, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in all_rows:
            w.writerow({k: r.get(k, '') for k in fieldnames})
    print(f"\nWrote {len(all_rows)} rows to {args.csv}")

    # ---- Summary ----
    applied = [r for r in all_rows
               if r['applied'] == 1 and r['mutation'] != 'baseline']
    if not applied:
        return

    by_mut = {}
    for r in applied:
        m = r['mutation']
        by_mut.setdefault(m, {'n': 0, 'ri': 0, 'rc': 0, 'ra': 0})
        by_mut[m]['n']  += 1
        by_mut[m]['ri'] += r['rejected_intruder']
        by_mut[m]['rc'] += r['rejected_completeness']
        by_mut[m]['ra'] += r['rejected_any']

    print()
    print(f"  {'Mutation':<16s} {'N':>4s}  "
          f"{'by intruder':>12s}  {'by completeness':>15s}  "
          f"{'any':>10s}")
    print(f"  {'-'*16} {'-'*4}  {'-'*12}  {'-'*15}  {'-'*10}")
    for m in ('deletion', 'duplication', 'cross_session'):
        if m not in by_mut:
            continue
        s = by_mut[m]
        print(f"  {m:<16s} {s['n']:>4d}  "
              f"{s['ri']:>4d}/{s['n']:<4d}     "
              f"{s['rc']:>4d}/{s['n']:<4d}        "
              f"{s['ra']:>4d}/{s['n']:<4d}")
    print()

    total_n  = sum(s['n'] for s in by_mut.values())
    total_ra = sum(s['ra'] for s in by_mut.values())
    print(f"  Total applied mutations: {total_n}")
    print(f"  Rejected (any mechanism): {total_ra} "
          f"({total_ra / total_n * 100:.1f}%)")

if __name__ == '__main__':
    main()