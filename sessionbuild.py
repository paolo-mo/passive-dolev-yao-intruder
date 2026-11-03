#!/usr/bin/env python3
"""
sessionbuild.py — Step 2 of the multi-session reconstruction pipeline.

Reads {Protocol}_streams.json (Step 1 output) and the .properties file,
pairs bidirectional TCP streams into connections, groups connections
into sessions, maps each session's connections to protocol channels,
and writes {Protocol}_session_meta.json plus one TXT file per candidate
arrangement ({Protocol}_session_meta_c0.txt, _c1.txt, ...).

Usage:
    python sessionbuild.py --streams PGP_Auth_streams.json \
                          --properties PGP_Auth.properties \
                          --output PGP_Auth_session_meta.json \
                          [--strict]
"""

import argparse
import json
import sys
import os
import re
import datetime
import itertools
import math
from collections import defaultdict

MAX_ARRANGEMENTS = 120 # max number of candidates N! <= 120 (N = 5) N: number of parallel sessions

# ============================================================
# Logging
# ============================================================

LOG_LEVEL = 'info'   # one of: 'quiet', 'info', 'verbose'

def _log(level, msg, reason=None):
    """Emit a message at the given level, optionally with a reason."""
    if LOG_LEVEL == 'quiet' and level != 'error':
        return
    if LOG_LEVEL == 'info' and level == 'verbose':
        return

    prefix = {
        'error':   'ERROR',
        'warning': 'WARNING',
        'info':    'INFO',
        'verbose': 'DEBUG',
    }.get(level, level.upper())

    if reason:
        print(f"[{prefix}] {msg} (reason: {reason})")
    else:
        print(f"[{prefix}] {msg}")


def warn(msg, reason=None):
    _log('warning', msg, reason)


def info(msg):
    _log('info', msg)


def verbose(msg):
    _log('verbose', msg)


# ============================================================
# File checks
# ============================================================

def require_file(path, kind="input"):
    """Check that a file exists and is readable; exit cleanly otherwise."""
    if not path:
        _log('error', f"No {kind} file specified")
        sys.exit(2)
    if not os.path.isfile(path):
        _log('error', f"{kind.capitalize()} file not found: {path}")
        _log('error', f"Current working directory: {os.getcwd()}")
        sys.exit(2)
    if not os.access(path, os.R_OK):
        _log('error', f"{kind.capitalize()} file is not readable: {path}")
        sys.exit(2)


def require_writable_dir(path):
    """Check that the parent directory of `path` exists and is writable."""
    parent = os.path.dirname(os.path.abspath(path)) or os.getcwd()
    if not os.path.isdir(parent):
        _log('error', f"Output directory does not exist: {parent}")
        sys.exit(2)
    if not os.access(parent, os.W_OK):
        _log('error', f"Output directory is not writable: {parent}")
        sys.exit(2)


# ============================================================
# .properties parsing
# ============================================================

def parse_properties_full(properties_file):
    """
    Parse a .properties file to extract order_map and channels.
    Raises FileNotFoundError if the file cannot be read.
    """
    order_map = {}
    channels = []
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    port_pattern = re.compile(r':(\d+)(?=\s|$)')

    with open(properties_file, 'r') as f:
        lines = f.readlines()

    comment = None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('#'):
            comment = stripped
        elif '_role' in stripped and '=' in stripped and not stripped.startswith('#'):
            if comment:
                ips = ip_pattern.findall(comment)
                if len(ips) >= 2:
                    addr_pair = f"{ips[0]},{ips[1]}"
                    if addr_pair not in order_map:
                        order_map[addr_pair] = len(order_map)

                    key = stripped.split('=')[0].strip()
                    name = key[:-len('_role')] if key.endswith('_role') else key
                    role = stripped.split('=', 1)[1].strip()

                    ports = port_pattern.findall(comment)
                    port = int(ports[-1]) if ports else 0

                    channels.append({
                        'name':   name,
                        'src_ip': ips[0],
                        'dst_ip': ips[1],
                        'port':   port,
                        'role':   role,
                    })
            comment = None

    if not channels:
        raise ValueError(
            f"No channels found in {properties_file}. "
            f"Expected lines like 'ROLE_x_channel_ROLE_y_..._role = ...' "
            f"preceded by a '# src -> dst - ip1 -> ip2:port' comment."
        )

    return order_map, channels


# ============================================================
# Connection pairing
# ============================================================

def pair_connections(streams):
    """
    Pair bidirectional TCP streams into connections.
    """
    by_key = defaultdict(list)
    for s in streams:
        key = (s['src_ip'], s['src_port'], s['dst_ip'], s['dst_port'])
        by_key[key].append(s)

    paired = set()
    connections = []
    cid = 0

    for s in streams:
        if s['file'] in paired:
            continue
        rev = (s['dst_ip'], s['dst_port'], s['src_ip'], s['src_port'])
        peers = [p for p in by_key.get(rev, []) if p['file'] not in paired]
        if not peers:
            print(f"Warning: no reverse stream for {s['file']}; skipping")
            paired.add(s['file'])
            continue

        peer = min(peers, key=lambda p: abs(p['t_first'] - s['t_first']))
        paired.add(s['file'])
        paired.add(peer['file'])

        if s['t_first'] <= peer['t_first']:
            ab, ba = s, peer
        else:
            ab, ba = peer, s

        cid += 1
        connections.append({
            'conn_id':   f'C{cid}',
            'stream_ab': ab['file'],
            'stream_ba': ba['file'],
            'ip_a':      ab['src_ip'],
            'port_a':    ab['src_port'],
            'ip_b':      ab['dst_ip'],
            'port_b':    ab['dst_port'],
            't_start':   min(ab['t_first'], ba['t_first']),
            't_end':     max(ab['t_last'],  ba['t_last']),
        })

    return connections


# ============================================================
# Session grouping
# ============================================================

def connection_signature(conn):
    """Canonical signature of a connection: unordered IPs + server port."""
    return (frozenset({conn['ip_a'], conn['ip_b']}), conn['port_b'])


def channel_signature(channel):
    """Canonical signature of a channel: unordered IPs + port."""
    return (frozenset({channel['src_ip'], channel['dst_ip']}), channel['port'])


def compute_k(channels):
    """Number of distinct connections per session (from the channel list)."""
    return len({channel_signature(ch) for ch in channels})


def connected_components(connections):
    """Partition connections into components sharing agent IPs."""
    ip_to_conns = defaultdict(list)
    for c in connections:
        ip_to_conns[c['ip_a']].append(c)
        ip_to_conns[c['ip_b']].append(c)

    visited = set()
    components = []
    for c in connections:
        if c['conn_id'] in visited:
            continue
        comp = []
        stack = [c]
        while stack:
            cur = stack.pop()
            if cur['conn_id'] in visited:
                continue
            visited.add(cur['conn_id'])
            comp.append(cur)
            for ip in (cur['ip_a'], cur['ip_b']):
                for n in ip_to_conns[ip]:
                    if n['conn_id'] not in visited:
                        stack.append(n)
        components.append(comp)
    return components


def split_component(component, channels, strict):
    """
    Split a component containing multiple sessions into individual sessions,
    enumerating candidate arrangements for each.

    Connections whose signature does not match any channel in `channels`
    are discarded first. This is typically the case for intruder relays
    on ephemeral ports, health checks, or other traffic that happens to
    share endpoints with the protocol connections.
    """
    known_sigs = {channel_signature(ch) for ch in channels}

    kept = [c for c in component if connection_signature(c) in known_sigs]
    if len(kept) != len(component):
        info(f"Discarded {len(component) - len(kept)} connection(s) "
             f"whose signature does not match any channel")
    component = kept

    K = compute_k(channels)
    if K <= 0:
        warn("Invalid channel count", f"K={K}")
        if strict: sys.exit(1)
        return []

    if len(component) % K != 0:
        warn("Cannot split component",
             f"component has {len(component)} connections, not a multiple of K={K}")
        if strict: sys.exit(1)
        return []

    N = len(component) // K

    by_sig = defaultdict(list)
    for c in component:
        by_sig[connection_signature(c)].append(c)

    # The observed signatures must match exactly the declared channels.
    # If any declared channel is missing, or any undeclared signature
    # survived the filter, we cannot build complete sessions.
    missing = known_sigs - set(by_sig.keys())
    extra   = set(by_sig.keys()) - known_sigs
    if missing or extra:
        if missing:
            warn("Missing channel signatures",
                 f"{len(missing)} declared channel(s) not observed")
        if extra:
            warn("Unexpected channel signatures",
                 f"{len(extra)} undeclared signature(s) observed")
        if strict: sys.exit(1)
        return []

    # Every channel must appear exactly N times. Bail out cleanly
    # rather than continuing with incomplete data.
    for sig, conns in by_sig.items():
        if len(conns) != N:
            warn("Signature count mismatch",
                 f"signature {sig} appears {len(conns)} times, expected N={N}")
            if strict: sys.exit(1)
            return []
        conns.sort(key=lambda c: c['t_start'])

    sigs = list(by_sig.keys())

    if K <= 1:
        arrangements = [tuple()]
    else:
        total = math.factorial(N) ** (K - 1)
        if total <= MAX_ARRANGEMENTS:
            arrangements = list(itertools.product(
                *[itertools.permutations(range(N)) for _ in range(K - 1)]
            ))
        else:
            base = tuple(range(N))
            arrangements = [tuple([base] * (K - 1))]
            for shift in range(1, min(N, 20)):
                perm = tuple((i + shift) % N for i in range(N))
                arrangements.append(tuple([perm] * (K - 1)))
            info(f"Arrangement space capped at {MAX_ARRANGEMENTS} "
                 f"(raw = {total}); using {len(arrangements)} heuristics")

    sessions = []
    for session_idx in range(N):
        session_candidates = []
        for arr_idx, perms in enumerate(arrangements):
            conns = [by_sig[sigs[0]][session_idx]]
            for k, sig in enumerate(sigs[1:]):
                conns.append(by_sig[sig][perms[k][session_idx]])
            session_candidates.append({
                'candidate_id': arr_idx,
                'conns': conns,
            })
        sessions.append({
            'session_id':        session_idx + 1,
            'confidence':        'medium',
            'confidence_reason': f'signature-split ({len(arrangements)} arrangements)',
            'candidates':        session_candidates,
        })

    info(f"Split component of {len(component)} connections into {N} sessions "
         f"with {len(arrangements)} candidate arrangement(s) each")
    return sessions


def group_sessions(connections, channels, strict):
    if not channels:
        _log('error', "No channels parsed; aborting session grouping")
        sys.exit(1)

    K = compute_k(channels)
    known_sigs = {channel_signature(ch) for ch in channels}

    kept = [c for c in connections if connection_signature(c) in known_sigs]
    if len(kept) != len(connections):
        info(f"Discarded {len(connections) - len(kept)} connection(s) "
             f"with unknown channel signature")
    connections = kept

    components = connected_components(connections)
    sessions = []
    sid = 0

    for comp in components:
        M = len(comp)
        if M == K:
            sid += 1
            sessions.append({
                'session_id':        sid,
                'confidence':        'high',
                'confidence_reason': 'single-component',
                'candidates': [
                    {'candidate_id': 0, 'conns': comp}
                ],
            })
            info(f"Session {sid}: single component with K={K} connections")
        elif M < K:
            warn("Incomplete component",
                 f"component has {M} connections, spec requires K={K}")
            if strict: sys.exit(1)
        else:
            subs = split_component(comp, channels, strict)
            for sub in subs:
                sid += 1
                sessions.append({
                    'session_id':        sid,
                    'confidence':        sub['confidence'],
                    'confidence_reason': sub['confidence_reason'],
                    'candidates':        sub['candidates'],
                })

    return sessions


# ============================================================
# Channel assignment
# ============================================================

def assign_channels(session_conns, channels):
    """For each channel, find the (connection, direction) that carries it."""
    channel_map = {}
    for ch in channels:
        match = None
        for c in session_conns:
            if c['ip_a'] == ch['src_ip'] and c['ip_b'] == ch['dst_ip']:
                match = {'conn': c['conn_id'], 'dir': 'ab'}
                break
            if c['ip_b'] == ch['src_ip'] and c['ip_a'] == ch['dst_ip']:
                match = {'conn': c['conn_id'], 'dir': 'ba'}
                break
        if match:
            channel_map[ch['name']] = match
        else:
            print(f"Warning: channel {ch['name']} has no matching connection "
                  f"in session")
    return channel_map


# ============================================================
# TXT rendering (one file per candidate)
# ============================================================

def write_session_meta_txt(doc, output_path, selected_candidate=0):
    """Write the flat TXT for a specific candidate arrangement."""
    connections = doc.get('connections', [])
    by_id = {c['conn_id']: c for c in connections}

    lines = []
    lines.append(f"protocol={doc.get('protocol', '')}")
    lines.append(f"pcap={doc.get('pcap', '')}")
    lines.append(f"generated_by={doc.get('generated_by', '')}")
    lines.append(f"generated_at={doc.get('generated_at', '')}")
    lines.append(f"n_sessions={len(doc.get('sessions', []))}")
    lines.append(f"selected_candidate={selected_candidate}")
    lines.append("")

    for s in doc.get('sessions', []):
        candidates = s.get('candidates', [])
        if not candidates:
            continue
        idx = selected_candidate if selected_candidate < len(candidates) else 0
        c = candidates[idx]

        lines.append(f"session={s['session_id']}")
        lines.append(f"confidence={s['confidence']}")
        lines.append(f"reason={s['confidence_reason']}")
        lines.append(f"n_candidates={len(candidates)}")
        lines.append(f"t_start={c['t_start']}")
        lines.append(f"t_end={c['t_end']}")
        lines.append(f"n_channels={len(c['channel_map'])}")

        for ch_name, ref in c['channel_map'].items():
            conn = by_id.get(ref['conn'])
            if not conn:
                continue
            stream_file = conn['stream_ab'] if ref['dir'] == 'ab' else conn['stream_ba']
            lines.append(f"channel={ch_name},{ref['conn']},{ref['dir']},{stream_file}")
        lines.append("")

    with open(output_path, 'w') as f:
        f.write("\n".join(lines))
    info(f"Wrote {output_path} (candidate {selected_candidate})")


def write_all_session_meta_txts(doc, base_path):
    """
    Write one TXT per candidate arrangement.
    Files: <base_path>_c0.txt, <base_path>_c1.txt, ...
    Returns the list of paths written.
    """
    n_candidates = max(
        (s.get('n_candidates', 1) for s in doc.get('sessions', [])),
        default=1,
    )
    written = []
    for cand_idx in range(n_candidates):
        txt_path = f"{base_path}_c{cand_idx}.txt"
        write_session_meta_txt(doc, txt_path, selected_candidate=cand_idx)
        written.append(txt_path)
    return written


def verify_consistency(doc, txt_path):
    """Check that the flat file and the JSON describe the same sessions."""
    n_sessions = len(doc.get('sessions', []))
    n_channels = 0
    for s in doc.get('sessions', []):
        # Candidate channel counts are invariant across candidates
        if s['candidates']:
            n_channels += len(s['candidates'][0]['channel_map'])

    with open(txt_path) as f:
        content = f.read()

    txt_sessions = sum(1 for line in content.splitlines() if line.startswith('session='))
    txt_channels = sum(1 for line in content.splitlines() if line.startswith('channel='))

    ok = True
    if n_sessions != txt_sessions:
        _log('error',
             f"Consistency: JSON has {n_sessions} sessions, TXT has {txt_sessions}")
        ok = False
    if n_channels != txt_channels:
        _log('error',
             f"Consistency: JSON has {n_channels} channels, TXT has {txt_channels}")
        ok = False

    if not ok:
        sys.exit(3)
    info(f"Consistency verified: {n_sessions} sessions, {n_channels} channels")


# ============================================================
# Main
# ============================================================

def build_session_meta(streams_doc, properties_file, strict=False):
    streams = streams_doc.get('streams', [])
    if not streams:
        _log('error', "streams.json contains no streams")
        sys.exit(2)

    try:
        _, channels = parse_properties_full(properties_file)
    except FileNotFoundError:
        _log('error', f"Properties file not found: {properties_file}")
        sys.exit(2)
    except ValueError as e:
        _log('error', str(e))
        sys.exit(2)

    info(f"Parsed {len(channels)} channels from {properties_file}")
    info(f"K (connections per session) = {compute_k(channels)}")

    connections = pair_connections(streams)
    info(f"Paired {len(connections)} connections from {len(streams)} streams")

    sessions_raw = group_sessions(connections, channels, strict)
    info(f"Identified {len(sessions_raw)} session(s)")

    if not sessions_raw:
        warn("No usable sessions were identified",
             f"paired {len(connections)} connection(s); "
             f"check whether the capture contains protocol traffic")
        if strict:
            sys.exit(1)
        # Fall through: caller (run_test.py) will see zero sessions
        # and should treat the run as failed.
        
    sessions = []
    for s in sessions_raw:
        candidates_out = []
        for cand in s['candidates']:
            session_conns = cand['conns']
            channel_map = assign_channels(session_conns, channels)
            candidates_out.append({
                'candidate_id': cand['candidate_id'],
                'connections':  [c['conn_id'] for c in session_conns],
                'channel_map':  channel_map,
                't_start':      min(c['t_start'] for c in session_conns),
                't_end':        max(c['t_end']   for c in session_conns),
            })
        sessions.append({
            'session_id':        s['session_id'],
            'confidence':        s['confidence'],
            'confidence_reason': s['confidence_reason'],
            'n_candidates':      len(candidates_out),
            'candidates':        candidates_out,
        })

    if strict:
        non_high = [s for s in sessions if s['confidence'] != 'high']
        if non_high:
            _log('error',
                 f"Strict mode: {len(non_high)} session(s) with non-high confidence")
            for s in non_high:
                _log('error',
                     f"  session {s['session_id']}: confidence={s['confidence']}")
            sys.exit(1)

    return {
        'protocol':     streams_doc.get('protocol', ''),
        'pcap':         streams_doc.get('pcap', ''),
        'generated_by': 'sessionbuild.py (step 2)',
        'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'streams':      streams,
        'connections':  connections,
        'sessions':     sessions,
    }


def main():
    global LOG_LEVEL

    parser = argparse.ArgumentParser(
        description="Build session metadata from streams.json")
    parser.add_argument('--streams', required=True,
                        help="Path to {Protocol}_streams.json")
    parser.add_argument('--properties', required=True,
                        help="Path to {Protocol}.properties")
    parser.add_argument('--output', required=True,
                        help="Path to write {Protocol}_session_meta.json")
    parser.add_argument('--strict', action='store_true',
                        help="Fail on ambiguous groupings and on any "
                             "non-high-confidence session")
    parser.add_argument('--log-level',
                        choices=['quiet', 'info', 'verbose'],
                        default='info',
                        help="Verbosity of diagnostic output (default: info)")
    args = parser.parse_args()

    LOG_LEVEL = args.log_level

    # --- input checks ---
    require_file(args.streams,    kind="streams")
    require_file(args.properties, kind="properties")
    require_writable_dir(args.output)

    # --- read streams.json ---
    try:
        with open(args.streams) as f:
            streams_doc = json.load(f)
    except json.JSONDecodeError as e:
        _log('error', f"Malformed JSON in {args.streams}: {e}")
        sys.exit(2)
    except OSError as e:
        _log('error', f"Could not read {args.streams}: {e}")
        sys.exit(2)

    # --- build ---
    doc = build_session_meta(streams_doc, args.properties, args.strict)

    # --- write JSON ---
    try:
        with open(args.output, 'w') as f:
            json.dump(doc, f, indent=2)
    except OSError as e:
        _log('error', f"Could not write {args.output}: {e}")
        sys.exit(2)

    # --- derive base TXT path from JSON path ---
    base_txt = args.output[:-len('.json')] \
               if args.output.endswith('.json') else args.output

    # --- write one TXT per candidate ---
    try:
        txt_paths = write_all_session_meta_txts(doc, base_txt)
    except OSError as e:
        _log('error', f"Could not write TXT files from {base_txt}: {e}")
        sys.exit(2)

    if not txt_paths:
        _log('error', f"No TXT files were written from {base_txt}")
        sys.exit(2)

    # --- verify consistency against candidate 0 ---
    verify_consistency(doc, txt_paths[0])

    # --- summary ---
    print(f"\nSaved {args.output}")
    print(f"  {len(doc['streams'])} streams")
    print(f"  {len(doc['connections'])} connections")
    print(f"  {len(doc['sessions'])} sessions")
    print(f"  {len(txt_paths)} candidate TXT file(s): "
          + ", ".join(os.path.basename(p) for p in txt_paths))
    for s in doc['sessions']:
        n_cands = s.get('n_candidates', 0)
        if s.get('candidates'):
            n_conns = len(s['candidates'][0]['connections'])
            n_chans = len(s['candidates'][0]['channel_map'])
        else:
            n_conns = n_chans = 0
        print(f"    session {s['session_id']}: "
              f"{n_conns} conns, "
              f"confidence={s['confidence']} "
              f"({s['confidence_reason']}), "
              f"candidates={n_cands}, "
              f"channels/candidate={n_chans}")


if __name__ == '__main__':
    main()