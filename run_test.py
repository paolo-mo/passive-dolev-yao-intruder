#!/usr/bin/env python3
"""
run_test.py - Run a single or multiple protocols through the reconstruction pipeline
with automatic stage-level timing collection.

Configuration is read from jpcap2ser.cfg.
All timing data is saved to a single global CSV file with one row per protocol.

Pipeline stages (matches the paper's Section 3 numbering):
    Stage 1 - Generate JavaDocker code     (anbxc -out:JavaDocker)
    Stage 2 - Run Docker and capture PCAP  (run_javadocker)
    Stage 3 - Extract streams              (jpcap2ser.py / outparse.py)
    Stage 4 - Build sessions               (sessionbuild.py)
    Stage 5 - Reconstruct and select       (Pass A: ObjCheck per candidate;
                                            Pass B: Java-gen + passive
                                            intruder per candidate, then
                                            score and select the winner)

Usage:
    python run_test.py <protocol>           # Run a single protocol
    python run_test.py --all               # Run all protocols (excluding EXCLUDE_PROTOCOLS)
    python run_test.py --all --include-excluded  # Run ALL protocols
    python run_test.py --debug <protocol>  # Show all stage output on console
    python run_test.py --help              # Show help
"""

import os
import sys
import re
import subprocess
import time
import csv
import configparser
import argparse
import json as _json
import shutil
from pathlib import Path
from datetime import datetime

CONFIG_FILE = "jpcap2ser.cfg"
GLOBAL_TIMING_CSV = "all_protocols_timing.csv"

# Define the stages in order (short names for CSV columns).
# The mapping to the paper's five-stage scheme is:
#   Stage 1 -> 'JavaDocker generation'
#   Stage 2 -> 'Docker execution'
#   Stage 3 -> 'PCAP to streams'       (and 'Protocol execution (from PCAP)' derived)
#   Stage 4 -> 'Session build'
#   Stage 5 -> 'ObjCheck' + 'Java generation (objcheck)' + 'Java execution (passive DY)'
#   ('Sessions' is a per-run metadata field, not a stage.)
STAGES = [
    ('JavaDocker generation', 'gen'),
    ('Docker execution', 'docker'),
    ('PCAP to streams', 'pcap'),
    ('Session build', 'sessbuild'),
    ('Protocol execution (from PCAP)', 'proto'),
    ('ObjCheck', 'obj'),
    ('Java generation (objcheck)', 'javagen'),
    ('Java execution (passive DY)', 'run'),
    ('Sessions', 'sessions')
]

# Global log file handle (set by run_single)
LOG_FILE = None

def provider_flag(provider):
    """
    Translate the CLI --provider value into the argument expected by anbxc.

    BC  -> 'BC'
    JDK -> 'default'   (uses the java.security settings)
    """
    return 'BC' if provider == 'BC' else 'default'

def validate_tools(config):
    """Validate that all required tools are present and executable."""
    errors = []
    
    # Check Python scripts
    tool_dir = Path(config['DEFAULT']['TOOLBASEDIR'])
    required_scripts = ['jpcap2ser.py', 'outparse.py', 'sessionbuild.py']
    for script in required_scripts:
        script_path = tool_dir / script
        if not script_path.exists():
            errors.append(f"Python script not found: {script_path}")
    
    # Check jpcap2ser.py can find TShark (implicitly checked when run)
    
    # Check ANT_CMD
    ant_cmd = config['DEFAULT'].get('ANT_CMD', 'ant')
    # Strip quotes for checking
    ant_path = ant_cmd.strip('"')
    if ant_path != 'ant' and not Path(ant_path).exists():
        errors.append(f"ANT_CMD not found: {ant_path}")
    
    # Check SerializationDumper
    serdump = config['DEFAULT'].get('SERDUMP_JAR_FILE', '')
    if serdump:
        serdump_path = Path(tool_dir / serdump)
        if not serdump_path.exists():
            errors.append(f"SerializationDumper not found: {serdump_path}")
    
    # Check TShark (if path is explicit)
    tshark = config['DEFAULT'].get('TSHARK_CMD', '')
    if tshark:
        tshark_path = Path(tshark)
        if not tshark_path.exists():
            errors.append(f"TShark not found: {tshark_path}")
    
    # Check anbxc executable (on PATH or in BASEDIR)
    basedir = Path(config['DEFAULT']['BASEDIR'])
    anbxc_paths = [
        basedir / 'anbxc.exe',
        basedir / 'anbxc',
        Path(os.environ.get('PATH', '')).glob('anbxc*')
    ]
    # Simple check: try which anbxc
    try:
        result = subprocess.run(['where', 'anbxc'], capture_output=True, text=True, shell=True)
        if result.returncode != 0:
            # Not on PATH, check BASEDIR
            if not (basedir / 'anbxc.exe').exists():
                errors.append("anbxc not found on PATH or in BASEDIR")
    except:
        errors.append("Failed to check for anbxc")
    
    if errors:
        print("Error: The following tools are missing:")
        for err in errors:
            print(f"  {err}")
        print("\nPlease check your configuration file and system PATH.")
        sys.exit(1)

def check_docker_running():
    """Return True if the Docker daemon is reachable."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, timeout=15
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def resolve_path(base_path, relative_path, config_dir):
    """Resolve a path relative to the config directory."""
    path = Path(relative_path)
    if path.is_absolute():
        return path
    return (config_dir / path).resolve()

def get_config(config_file=None):
    """Load configuration and resolve all paths."""
    if config_file is None:
        config_file = CONFIG_FILE
    
    config_path = Path(config_file)
    if not config_path.exists():
        print(f"Error: Config file '{config_file}' does not exist.")
        sys.exit(1)
    
    config_dir = config_path.parent.resolve()
    config = configparser.ConfigParser()
    config.read(config_file)
    
    # Resolve path entries
    path_keys = ['BASE_PATH', 'BASEDIR', 'TOOLBASEDIR', 'PROT_FOLDER', 
                 'LOG_FOLDER', 'OUTPUT_FOLDER']
    for key in path_keys:
        if key in config['DEFAULT']:
            config['DEFAULT'][key] = str(resolve_path(config_dir, config['DEFAULT'][key], config_dir))
    
    # Resolve optional ANT_CMD if present
    if 'ANT_CMD' in config['DEFAULT']:
        config['DEFAULT']['ANT_CMD'] = str(resolve_path(config_dir, config['DEFAULT']['ANT_CMD'], config_dir))
    
    config['DEFAULT']['CONFIG_DIR'] = str(config_dir)
    return config

def validate_paths(config):
    """Validate that all required paths exist."""
    required = ['BASEDIR', 'BASE_PATH', 'PROT_FOLDER', 'TOOLBASEDIR']
    errors = []
    for key in required:
        path = Path(config['DEFAULT'][key])
        if not path.exists():
            errors.append(f"{key} = {path} does not exist")
    
    # Check for run_javadocker in anbx-dist
    basedir = Path(config['DEFAULT']['BASEDIR'])
    run_javadocker = basedir / 'anbx-dist' / 'run_javadocker.cmd'
    if not run_javadocker.exists():
        errors.append(f"run_javadocker not found at {run_javadocker}")
    
    if errors:
        print("Error: The following paths do not exist:")
        for err in errors:
            print(f"  {err}")
        print("\nPlease check your configuration file.")
        sys.exit(1)

# ------------------------------------------------------------------
# Intruder log parsing (parse the captured stdout)
# ------------------------------------------------------------------
#
# The AnBxJ library emits check status via AnBx_Debug. The markers we
# rely on are:
#   "CHECK # <id>"  — opens a check
#   "check FAILED!" — marks it failed
# Both are emitted by AnB_Protocol. If the library ever changes these
# strings, update the two regexes below.

_INTRUDER_LINE   = re.compile(r'\[ROLE_intr-')
_CHECK_START     = re.compile(r'CHECK # ([\d.]+)')
_CHECK_FAILED    = re.compile(r'check FAILED!')


def parse_intruder_checks(log_text):
    """
    Parse intruder check results from captured runagents output.
    Returns (checks_total, checks_failed, per_check_dict).
    A check is ok unless a 'check FAILED!' line appears before the next
    'CHECK # <id>' line.
    """
    per_check = {}
    current = None
    for line in log_text.splitlines():
        if not _INTRUDER_LINE.search(line):
            continue
        m = _CHECK_START.search(line)
        if m:
            current = m.group(1)
            per_check.setdefault(current, 'ok')
            continue
        if current is not None and _CHECK_FAILED.search(line):
            per_check[current] = 'failed'
    checks_total = len(per_check)
    checks_failed = sum(1 for v in per_check.values() if v == 'failed')
    return checks_total, checks_failed, per_check


def score_for_candidate(session_logs):
    """
    Score a candidate arrangement given the captured intruder logs for
    each of its sessions.
    Returns (n_clean_sessions, -total_failed, total_checks).
    Higher tuples are better under Python's lexicographic comparison.
    """
    n_clean = 0
    total_failed = 0
    total_checks = 0
    for log in session_logs:
        total, failed, _ = parse_intruder_checks(log or '')
        if total == 0:
            # No checks recorded — count this session as failed
            n_clean -= 1
            continue
        if failed == 0:
            n_clean += 1
        total_failed += failed
        total_checks += total
    return (n_clean, -total_failed, total_checks)

def get_excluded_protocols(config):
    """Parse the EXCLUDE_PROTOCOLS from config and return a set."""
    exclude_str = config['DEFAULT'].get('EXCLUDE_PROTOCOLS', '')
    if not exclude_str:
        return set()
    return {p.strip() for p in exclude_str.split(',') if p.strip()}

def log_msg(msg, to_console=True):
    """Write a message to the log file and optionally to the console."""
    global LOG_FILE
    if LOG_FILE:
        LOG_FILE.write(msg + '\n')
        LOG_FILE.flush()
    if to_console:
        print(msg)

def clean_generated_files(protocol, src_folder):
    """Remove previously generated files for this protocol."""
    patterns = [
        f"{protocol}_*_STEP_*.ser",      # multi-session STEP: {Prot}_{session}_{STEP}.ser
        f"{protocol}_STEP_*.ser",        # legacy single-session STEP
        f"{protocol}_STREAM_*.ser",      # both stream naming conventions
        f"{protocol}_streams.json",      # Step 1 metadata
        f"{protocol}_session_meta.json", # Step 2 JSON
        f"{protocol}_session_meta.txt",  # Step 2 TXT
        f"{protocol}_stream_counts.txt", # ObjCheck output
        f"{protocol}_session_meta_c*.txt",
    ]
    for pattern in patterns:
        for f in src_folder.glob(pattern):
            log_msg(f"Removing old file: {f}", to_console=False)
            try:
                f.unlink()
            except OSError as e:
                log_msg(f"Warning: Could not remove {f}: {e}", to_console=True)

def run_stage(description, command, cwd=None, capture_output=True, log_output=True, debug=False):
    """Run a command, measure time, return timing.
    If debug=True, print captured stdout/stderr to console."""
    log_msg(f"  -> {description} ...", to_console=True)
    start = time.perf_counter()
    
    try:
        if capture_output:
            result = subprocess.run(
                command,
                shell=True,
                cwd=cwd,
                capture_output=True,
                text=True
            )
            if log_output:
                if result.stdout:
                    log_msg(f"     stdout:\n{result.stdout.rstrip()}", to_console=False)
                if result.stderr:
                    log_msg(f"     stderr:\n{result.stderr.rstrip()}", to_console=False)
            # If debug, print stdout/stderr to console as well
            if debug:
                if result.stdout:
                    print(f"     stdout:\n{result.stdout.rstrip()}")
                if result.stderr:
                    print(f"     stderr:\n{result.stderr.rstrip()}")
        else:
            # capture_output=False: output goes directly to console (inherited)
            # If debug is off, we still want to see it (like Docker streaming)
            # For consistency, we now use capture_output=True for all stages,
            # so this branch is rarely used. Keep it for completeness.
            result = subprocess.run(
                command,
                shell=True,
                cwd=cwd,
                capture_output=False,
                text=True
            )
            # No captured output to log or debug-print
    
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        log_msg(f"     [FAIL] exception: {e}", to_console=True)
        return {
            'stage': description,
            'time_ms': elapsed,
            'returncode': -1,
        }
    
    elapsed = (time.perf_counter() - start) * 1000
    status = "[OK]" if result.returncode == 0 else "[FAIL]"
    log_msg(f"     {status} ({elapsed:.1f} ms)", to_console=True)
    
    return {
        'stage': description,
        'time_ms': elapsed,
        'returncode': result.returncode,
        'stdout': result.stdout if capture_output else None,
        'stderr': result.stderr if capture_output else None,
    }

def measure_protocol_time_from_pcap(pcap_file, tshark_cmd):
    """Extract protocol execution time from PCAP file using tshark."""
    if not pcap_file or not pcap_file.exists():
        log_msg(f"     DEBUG: PCAP file does not exist: {pcap_file}", to_console=True)
        return None
    
    log_msg(f"     DEBUG: Measuring protocol time from PCAP: {pcap_file}", to_console=True)
    
    try:
        # Check if TShark is available
        version_cmd = f'"{tshark_cmd}" --version'
        version_result = subprocess.run(version_cmd, shell=True, capture_output=True, text=True)
        if version_result.returncode != 0:
            log_msg(f"     DEBUG: TShark not found at '{tshark_cmd}'", to_console=True)
            return None
        
        # Get all timestamps for TCP payload packets
        cmd = f'"{tshark_cmd}" -r "{pcap_file}" -T fields -e frame.time_epoch -Y "tcp.payload"'
        # log_msg(f"     DEBUG: Running TShark: {cmd}", to_console=True)
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # log_msg(f"     DEBUG: TShark return code: {result.returncode}", to_console=True)
        if result.returncode != 0:
            log_msg(f"     DEBUG: TShark stderr: {result.stderr.strip()}", to_console=True)
            return None
        
        # log_msg(f"     DEBUG: TShark stdout length: {len(result.stdout)} chars", to_console=True)
        if not result.stdout.strip():
            log_msg("     DEBUG: No TCP payload packets found in PCAP", to_console=True)
            return None
        
        # Parse timestamps
        times = []
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if line:
                try:
                    times.append(float(line))
                except ValueError:
                    pass
        
        # log_msg(f"     DEBUG: Extracted {len(times)} timestamps", to_console=True)
        if not times:
            log_msg("     DEBUG: No valid timestamps extracted", to_console=True)
            return None
        
        first = min(times)
        last = max(times)
        elapsed_ms = (last - first) * 1000
        log_msg(f"     DEBUG: First: {first}, Last: {last}, Elapsed: {elapsed_ms:.1f} ms", to_console=True)
        return elapsed_ms
    except Exception as e:
        log_msg(f"     DEBUG: Exception: {e}", to_console=True)
        import traceback
        log_msg(f"     DEBUG: {traceback.format_exc()}", to_console=False)
        return None

def save_to_global_csv(protocol, timing_dict, csv_path):
    """Save a single row to the global CSV file."""
    file_exists = Path(csv_path).exists()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    with open(csv_path, 'a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            # Write header with short column names
            header = ['protocol', 'timestamp', 'sessions', 'provider']
            for _, short in STAGES:
                if short != 'sessions':  # Skip sessions in the stage list
                    header.append(f'{short}_t')
            header.append('total_t')
            for _, short in STAGES:
                if short != 'sessions':
                    header.append(f'{short}_rc')
            writer.writerow(header)
        
        # Build the row: protocol, timestamp, sessions
        row = [protocol, timestamp, timing_dict.get('sessions', ''),timing_dict.get('provider', '')]
        
        # Add time values for each stage (excluding sessions)
        total = 0.0
        for full_name, short in STAGES:
            if short == 'sessions':
                continue
            val = timing_dict.get(full_name)
            if val is not None and isinstance(val, dict):
                t = val.get('time_ms')
                if t is not None:
                    row.append(f"{t:.2f}")
                    total += t
                else:
                    row.append('')
            else:
                row.append('')
        row.append(f"{total:.2f}")
        
        # Add return codes for each stage (excluding sessions)
        for full_name, short in STAGES:
            if short == 'sessions':
                continue
            val = timing_dict.get(full_name)
            if val is not None and isinstance(val, dict):
                rc = val.get('returncode')
                if rc is not None:
                    row.append(rc)
                else:
                    row.append('')
            else:
                row.append('')
        
        writer.writerow(row)

def run_single(protocol, config, log_enabled=False, csv_enabled=False, csv_path=GLOBAL_TIMING_CSV, debug=False, sessions=1, strict_sessions=False, provider='JDK', log_suffix=''):
    """Run a single protocol through the pipeline."""
    global LOG_FILE
    
    timings = []
    timing_dict = {}
    
    basedir = Path(config['DEFAULT']['BASEDIR'])
    src_folder = Path(config['DEFAULT']['BASE_PATH']) / protocol.lower()
    prot_folder = Path(config['DEFAULT']['PROT_FOLDER'])
    tool_dir = Path(config['DEFAULT']['TOOLBASEDIR'])
    log_folder = Path(config['DEFAULT']['LOG_FOLDER'])
    output_folder = Path(config['DEFAULT']['OUTPUT_FOLDER'])
    dist = config['DEFAULT']['DIST']
    
    ant_cmd = config['DEFAULT'].get('ANT_CMD', 'ant')
    if ' ' in ant_cmd:
        ant_cmd = f'"{ant_cmd}"'
    
    tshark_cmd = config['DEFAULT'].get('TSHARK_CMD', 'tshark')
    anbx_file = prot_folder / f"{protocol}.AnBx"
    anb_file = prot_folder / f"{protocol}.AnB"
    suffix = f"-{log_suffix}" if log_suffix else ""
    log_file = log_folder / (f"objcheck_{dist}-{provider.lower()}-{sessions}s{suffix}.log")
    jpcap2ser_path = tool_dir / "jpcap2ser.py"
    sessionbuild_path = tool_dir / "sessionbuild.py"
    prov_flag = provider_flag(provider)
    timing_dict['provider'] = provider 
    
    if not anbx_file.exists():
        print(f"Error: {anbx_file} does not exist")
        return None
    
    log_folder.mkdir(parents=True, exist_ok=True)
    output_folder.mkdir(parents=True, exist_ok=True)
    src_folder.mkdir(parents=True, exist_ok=True)
    
    # Clean up any leftover generated files from previous runs
    clean_generated_files(protocol, src_folder)
    
    if log_enabled:
        LOG_FILE = open(log_file, 'a')
    
    log_msg(f"\n{'='*60}")
    log_msg(f"Protocol: {protocol}")
    log_msg(f"{'='*60}")
    # log_msg(f"ANT_CMD: {ant_cmd}")
    
    # Stage 1: Generate JavaDocker
    log_msg("--- Stage 1: Generate JavaDocker ---")
    log_msg(f"Provider: {prov_flag}")

    timing = run_stage(
        "JavaDocker generation",
        f"anbxc {anbx_file} -out:JavaDocker -jdockerpcap -nocfgmsg -silent -jmtserver -jparallelclients {sessions} -jsessions {sessions} -securityProvider {prov_flag}",
        cwd=basedir,
        debug=debug
    )
    timings.append(timing)
    timing_dict['JavaDocker generation'] = {'time_ms': timing['time_ms'], 'returncode': timing['returncode']}
    if timing['returncode'] != 0:
        log_msg("Error: JavaDocker generation failed")
        if LOG_FILE:
            LOG_FILE.close()
            LOG_FILE = None
        if csv_enabled:
            save_to_global_csv(protocol, timing_dict, csv_path)
        return timings
        
    if not check_docker_running():
        log_msg("Error: Docker daemon is not reachable. "
                "Start Docker Desktop and try again.")
        if LOG_FILE:
            LOG_FILE.close()
            LOG_FILE = None
        if csv_enabled:
            save_to_global_csv(protocol, timing_dict, csv_path)
        return timings        
    
    # Stage 2: Run Docker (now captured; output shown only if debug=True)
    log_msg("--- Stage 2: Run Docker ---")
    timing = run_stage(
        "Docker execution",
        f"run_javadocker {protocol}",
        cwd=basedir / 'anbx-dist',
        capture_output=True,
        debug=debug
    )
    timings.append(timing)
    timing_dict['Docker execution'] = {'time_ms': timing['time_ms'], 'returncode': timing['returncode']}
    
    # Stage 3: PCAP to streams
    log_msg("--- Stage 3: PCAP to streams ---")
    timing = run_stage(
        "PCAP to streams",
        f"python {jpcap2ser_path} {protocol} --allstreams --emit-meta",
        cwd=tool_dir,
        debug=debug
    )
    timings.append(timing)
    timing_dict['PCAP to streams'] = {'time_ms': timing['time_ms'], 'returncode': timing['returncode']}
    


    # Define pcap_file before checking it
    pcap_file = src_folder / f"{protocol}_DY.pcap"

    # Stage 4: Session build (pair streams into connections and sessions)
    log_msg("--- Stage 4: Session build ---")
    streams_json = src_folder / f"{protocol}_streams.json"
    properties_file = src_folder / f"{protocol}.properties"
    session_meta_json = src_folder / f"{protocol}_session_meta.json"

    strict_flag = " --strict" if strict_sessions else ""
    timing = run_stage(
        "Session build",
        f"python {sessionbuild_path} "
        f"--streams {streams_json} "
        f"--properties {properties_file} "
        f"--output {session_meta_json} "
        f"--log-level info{strict_flag}",
        cwd=tool_dir,
        debug=debug
    )
    timings.append(timing)
    timing_dict['Session build'] = {'time_ms': timing['time_ms'], 'returncode': timing['returncode']}
    if timing['returncode'] != 0:
        log_msg("Error: Session build failed; skipping the rest of the pipeline")
        if LOG_FILE:
            LOG_FILE.close()
            LOG_FILE = None
        if csv_enabled:
            save_to_global_csv(protocol, timing_dict, csv_path)
        return timings

    # Measure protocol execution time from PCAP
    if pcap_file.exists():
        protocol_time = measure_protocol_time_from_pcap(pcap_file, tshark_cmd)
        if protocol_time is not None:
            timing_dict['Protocol execution (from PCAP)'] = {
                'time_ms': protocol_time, 
                'returncode': 0
            }
            log_msg(f"     Protocol execution time from PCAP: {protocol_time:.1f} ms", to_console=True)
        else:
            timing_dict['Protocol execution (from PCAP)'] = {
                'time_ms': None, 
                'returncode': -1
            }
            log_msg(f"     Warning: Could not measure protocol time from PCAP", to_console=True)
    else:
        log_msg(f"     Warning: PCAP file not found: {pcap_file}", to_console=True)
        timing_dict['Protocol execution (from PCAP)'] = {
            'time_ms': None, 
            'returncode': -1
        }    
    
    # --- Log the protocol specification (.AnB file) after Stage 4 ---
    # When debug is enabled, print the spec to console as well.
    if anb_file.exists():
        log_msg(f"--- Protocol specification ({protocol}.AnB) ---", to_console=debug)
        try:
            with open(anb_file, 'r') as f:
                anb_content = f.read()
                log_msg(anb_content, to_console=debug)
            log_msg("--- End of protocol specification ---", to_console=debug)

            # Emit the expected number of protocol actions (messages).
            # An action is a line of the form "<Role> -> <Role>: <message>"
            # inside the Actions: block. Downstream parsers read this line
            # instead of re-parsing the pretty-printed spec.
            actions_m = re.search(
                r'^\s*Actions:\s*\n(.*?)(?=^\s*\w+:\s*$|\Z)',
                anb_content,
                re.MULTILINE | re.DOTALL,
            )
            if actions_m:
                expected_actions = len(re.findall(
                    r'^\s*\w+\s*->\s*\w+\s*:',
                    actions_m.group(1),
                    re.MULTILINE,
                ))
            else:
                expected_actions = 0
            log_msg(f"ExpectedActions: {expected_actions}", to_console=False)
        except Exception as e:
            log_msg(f"Warning: Could not read {anb_file}: {e}", to_console=True)
    else:
        log_msg(f"Warning: {anb_file} does not exist", to_console=True)

    # --- Expected intruder checks (from the generated intruder template) ---
    # The compiler emits one wffCheck/eqCheck/noteqCheck/seenCheck call per
    # defensive check the passive intruder will perform per session.
    # Counting them here gives downstream parsers a stable ground-truth
    # value independent of whether the intruder completes its run.
    intruder_java = src_folder / f"{protocol}_ROLE_intr.java"
    expected_checks = 0
    if intruder_java.exists():
        try:
            with open(intruder_java, 'r') as f:
                intruder_src = f.read()
            expected_checks = len(re.findall(
                r'\b(?:wffCheck|eqCheck|noteqCheck|seenCheck)\s*\(',
                intruder_src,
            ))
        except Exception as e:
            log_msg(f"Warning: Could not read {intruder_java}: {e}", to_console=True)
    log_msg(f"ExpectedChecks: {expected_checks}", to_console=False)
    
    # Read session IDs and candidate counts from the metadata file
    if not session_meta_json.exists():
        log_msg(f"Warning: {session_meta_json} not found - skipping Java generation")
        if LOG_FILE:
            LOG_FILE.close()
            LOG_FILE = None
        if csv_enabled:
            save_to_global_csv(protocol, timing_dict, csv_path)
        return timings

    try:
        with open(session_meta_json) as f:
            meta = _json.load(f)
    except (OSError, _json.JSONDecodeError) as e:
        log_msg(f"Warning: Could not read {session_meta_json}: {e} - skipping Java generation")
        if LOG_FILE:
            LOG_FILE.close()
            LOG_FILE = None
        if csv_enabled:
            save_to_global_csv(protocol, timing_dict, csv_path)
        return timings

    session_ids = sorted(s['session_id'] for s in meta.get('sessions', []))
    n_candidates_per_session = [s.get('n_candidates', 1)
                                for s in meta.get('sessions', [])]
    max_candidates = max(n_candidates_per_session) if n_candidates_per_session else 1

    log_msg(f"Read sessions from {session_meta_json.name}: {session_ids} "
            f"({len(session_ids)} sessions, up to {max_candidates} candidates each)")
    timing_dict['sessions'] = len(session_ids)

    # Stage 5: Candidate enumeration, reconstruction, and selection.
    # Two passes:
    #   Pass A - ObjCheck per candidate, snapshot STEP files.
    #   Pass B - Java-gen + passive intruder per usable candidate
    #            (x per session), then score and select the winner.
    log_msg("--- Stage 5: Candidate enumeration ---")

    snapshot_root = src_folder / f"{protocol}_step_snapshots"
    if snapshot_root.exists():
        shutil.rmtree(snapshot_root)
    snapshot_root.mkdir()

    total_obj_time = 0
    obj_rc = 0
    usable = []
    score_table = []
    per_candidate_rc = {}

    # ---------- Pass A: ObjCheck per candidate ----------
    for candidate_idx in range(max_candidates):
        src_txt = src_folder / f"{protocol}_session_meta_c{candidate_idx}.txt"
        dst_txt = src_folder / f"{protocol}_session_meta.txt"
        if not src_txt.exists():
            log_msg(f"  Candidate TXT not found: {src_txt.name}; skipping")
            score_table.append((candidate_idx, (-1, 0, 0)))   # ← added
            continue
        shutil.copyfile(src_txt, dst_txt)

        for f in src_folder.glob(f"{protocol}_*_STEP_*.ser"):
            f.unlink()

        timing_obj = run_stage(
            f"ObjCheck (candidate {candidate_idx})",
            f"{ant_cmd} -buildfile {src_folder}/build.xml objcheck",
            cwd=basedir, debug=debug,
        )
        total_obj_time += timing_obj['time_ms']
        timings.append(timing_obj)

        per_candidate_rc.setdefault(candidate_idx, {})['obj'] = timing_obj['returncode']
        if timing_obj['returncode'] != 0:
            obj_rc = timing_obj['returncode']

        step_files = list(src_folder.glob(f"{protocol}_*_STEP_*.ser"))
        
        if not step_files:
            log_msg(f"  No STEP files for candidate {candidate_idx}; skipping")
            score_table.append((candidate_idx, (-1, 0, 0)))   # ← added
            continue

        cand_dir = snapshot_root / f"c{candidate_idx}"
        cand_dir.mkdir()
        for sf in step_files:
            shutil.copyfile(sf, cand_dir / sf.name)
        usable.append(candidate_idx)

    # ---------- Pass B: Java-gen + intruder per usable candidate ----------
    best_candidate = None
    best_score = None
    total_gen_time = 0
    total_run_time = 0
    java_rc = 0
    run_rc = 0

    for candidate_idx in usable:
        for f in src_folder.glob(f"{protocol}_*_STEP_*.ser"):
            try:
                f.unlink()
            except OSError as e:
                log_msg(f"  Warning: could not remove {f}: {e}", to_console=True)
        for sf in (snapshot_root / f"c{candidate_idx}").glob(f"{protocol}_*_STEP_*.ser"):
            shutil.copyfile(sf, src_folder / sf.name)

        shutil.copyfile(
            src_folder / f"{protocol}_session_meta_c{candidate_idx}.txt",
            src_folder / f"{protocol}_session_meta.txt",
        )

        session_logs = []
        cand_java_rc = 0
        cand_run_rc  = 0
        for session_id in session_ids:
            timing_gen = run_stage(
                f"Java generation (session {session_id}, candidate {candidate_idx})",
                f"anbxc {anbx_file} -out:Java -objcheck -nocfgmsg -silent "
                f"-securityProvider {prov_flag} "
                f"-objchecksession {session_id}",
                cwd=basedir, debug=debug,
            )
            total_gen_time += timing_gen['time_ms']
            timings.append(timing_gen)
            if timing_gen['returncode'] != 0:
                java_rc = timing_gen['returncode']
                cand_java_rc = timing_gen['returncode']

            timing_run = run_stage(
                f"Java execution (session {session_id}, candidate {candidate_idx})",
                f"{ant_cmd} -buildfile {src_folder}/build.xml runagents",
                cwd=basedir, debug=debug,
            )
            total_run_time += timing_run['time_ms']
            timings.append(timing_run)
            if timing_run['returncode'] != 0:
                run_rc = timing_run['returncode']
                cand_run_rc = timing_run['returncode']

            session_logs.append(
                (timing_run.get('stdout') or '') + '\n' + (timing_run.get('stderr') or '')
            )

        per_candidate_rc.setdefault(candidate_idx, {})['java'] = cand_java_rc
        per_candidate_rc.setdefault(candidate_idx, {})['run']  = cand_run_rc

        score = score_for_candidate(session_logs)
        score_table.append((candidate_idx, score))
        log_msg(f"  Candidate {candidate_idx} score: {score}")
        if best_score is None or score > best_score:
            best_score = score
            best_candidate = candidate_idx
        

    log_msg(f"Score table: {score_table}")
    if best_candidate is None:
        log_msg("ERROR: no candidate produced a usable reconstruction")
        run_rc = 1
    else:
        log_msg(f"Selected candidate {best_candidate} with score {best_score}")

        # Log the winning assignment so the transcript documents it
        for s in meta.get('sessions', []):
            cands = s.get('candidates', [])
            if best_candidate >= len(cands):
                continue
            c = cands[best_candidate]
            conns = c.get('connections', [])
            log_msg(f"  Session {s['session_id']}: connections "
                    f"[{', '.join(conns)}]")
            for ch_name, ref in c.get('channel_map', {}).items():
                log_msg(f"    {ch_name} <- {ref['conn']}/{ref['dir']}")

        # Override aggregate return codes with the winner's, so the CSV
        # reflects "did the shipped reconstruction succeed" rather than
        # "did any candidate somewhere fail".
        winner_rc = per_candidate_rc.get(best_candidate, {})
        obj_rc  = winner_rc.get('obj',  obj_rc)
        java_rc = winner_rc.get('java', java_rc)
        run_rc  = winner_rc.get('run',  run_rc)

        # Copy the winning candidate's TXT to the working path
        src_txt = src_folder / f"{protocol}_session_meta_c{best_candidate}.txt"
        dst_txt = src_folder / f"{protocol}_session_meta.txt"
        if src_txt.exists():
            shutil.copyfile(src_txt, dst_txt)
            log_msg(f"  Final: copied {src_txt.name} -> {dst_txt.name}")

    # Store aggregate timings
    timing_dict['ObjCheck'] = {
        'time_ms': total_obj_time,
        'returncode': obj_rc
    }
    timing_dict['Java generation (objcheck)'] = {
        'time_ms': total_gen_time,
        'returncode': java_rc
    }
    timing_dict['Java execution (passive DY)'] = {
        'time_ms': total_run_time,
        'returncode': run_rc
    }
    
    # Save CSV on successful completion
    if csv_enabled:
        # Also store the number of sessions in a separate field
        timing_dict['sessions'] = len(session_ids)
        save_to_global_csv(protocol, timing_dict, csv_path)
        log_msg(f"Timing data appended to global CSV: {csv_path}")
        log_msg(f"CSV file saved at: {Path(csv_path).resolve()}", to_console=True)
    
    if LOG_FILE:
        LOG_FILE.close()
        LOG_FILE = None
    
        # --- Reconstruction summary ---
    log_msg("--- Reconstruction summary ---")
    log_msg(f"  Candidates tried: {len(score_table)}")
    log_msg(f"  Score table: {score_table}")
    if best_candidate is not None:
        n_clean, neg_failed, total_checks = best_score
        log_msg(f"  Selected candidate {best_candidate}: "
                f"{n_clean} clean session(s), "
                f"{-neg_failed} failed check(s) out of {total_checks}")
    else:
        log_msg("  No candidate produced a usable reconstruction")

    return timings

def run_all(config, log_enabled=False, csv_enabled=False, csv_path=GLOBAL_TIMING_CSV, include_excluded=False, debug=False, sessions=1, strict_sessions=False, provider='JDK', log_suffix=''):
    """Run all protocols, optionally including those in EXCLUDE_PROTOCOLS."""
    prot_folder = Path(config['DEFAULT']['PROT_FOLDER'])
    excluded = get_excluded_protocols(config)
    
    all_protocols = [f.stem for f in prot_folder.glob('*.AnBx') if not f.stem.endswith('_intr')]
    
    if include_excluded:
        protocols = all_protocols
        print("Including all protocols (ignoring EXCLUDE_PROTOCOLS)")
    else:
        protocols = [p for p in all_protocols if p not in excluded]
        if excluded:
            print(f"Excluded protocols ({len(excluded)}): {', '.join(sorted(excluded))}")
    
    if Path(csv_path).exists():
        print(f"Removing existing global CSV: {csv_path}")
        Path(csv_path).unlink()
    
    print(f"Found {len(protocols)} protocols to process (out of {len(all_protocols)} total)")
    print(f"Global CSV will be saved to: {csv_path}")
    all_timings = {}
    
    for protocol in sorted(protocols):
        timings = run_single(protocol, config, log_enabled, csv_enabled, csv_path, debug=debug, sessions=sessions, strict_sessions=strict_sessions, provider=provider, log_suffix=log_suffix)
        if timings:
            all_timings[protocol] = timings
    
    return all_timings

def main():
    """Parse command line arguments and run the pipeline."""
    parser = argparse.ArgumentParser(
        description="Run the AnBx reconstruction pipeline with timing collection. - CONFIG_FILE=" + CONFIG_FILE,
        epilog="Example: python run_test.py Carlsen"
    )
    
    parser.add_argument(
        'protocol',
        nargs='?',
        help='Protocol name to run (e.g., Carlsen, From_A)'
    )
 
    parser.add_argument(
        '--protocols',
        default=None,
        help='Comma-separated list of protocol names to run (alternative to a '
             'single positional argument or --all).'
    )
    
    parser.add_argument(
        '--all',
        action='store_true',
        help='Run all protocols found in PROT_FOLDER (excluding EXCLUDE_PROTOCOLS by default)'
    )
    
    parser.add_argument(
        '--sessions',
        type=int,
        default=1,
        help='Number of parallel sessions (default: 1)'
    )
    
    parser.add_argument(
        '--include-excluded',
        action='store_true',
        help='Include protocols listed in EXCLUDE_PROTOCOLS (by default they are excluded)'
    )
    
    parser.add_argument(
        '--csv',
        default=GLOBAL_TIMING_CSV,
        help=f'Output CSV filename (default: {GLOBAL_TIMING_CSV})'
    )
    
    parser.add_argument(
        '--no-log',
        action='store_true',
        help='Disable logging to log file'
    )
    
    parser.add_argument(
        '--no-csv',
        action='store_true',
        help='Disable logging to csv file (timing)'
    )
    
    parser.add_argument(
        '--skip-validation',
        action='store_true',
        help='Skip path and tool validation (use with caution)'
    )
    
    parser.add_argument(
        '--strict-sessions',
        action='store_true',
        help='Skip any protocol whose session grouping is not high-confidence '
             '(sessionbuild.py exit code 1 aborts the protocol)'
    )

    parser.add_argument(
        '--provider',
        type=str.upper,
        choices=['BC', 'JDK'],
        default='JDK',
        help='Cryptographic provider: BC (Bouncy Castle) or JDK (standard '
             'Java Cryptography Extension, default). Maps to the anbxc '
             '-securityProvider flag (BC or default).'
    )

    parser.add_argument(
        '--log-suffix',
        default='',
        help='Optional suffix appended to the log filename, between the '
             'session count and the .log extension.  E.g. --log-suffix run2 '
             'produces objcheck_<dist>-<provider>-<N>s-run2.log.  Use this '
             'to keep multiple runs of the same configuration separate '
             'without overwriting or appending.'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Print all stage outputs (stdout/stderr) and protocol specification to the console'
    )
    
    args = parser.parse_args()
    
    config = get_config()
    validate_paths(config)
    
    if not args.skip_validation:
        validate_tools(config)
    
    if not args.all and not args.protocol and not args.protocols:
        parser.error("Specify a protocol name, --protocols, or --all.")

    if args.all:
        all_timings = run_all(
            config,
            log_enabled=not args.no_log,
            csv_enabled=not args.no_csv,
            csv_path=args.csv,
            include_excluded=args.include_excluded,
            debug=args.debug,
            sessions=args.sessions,
            strict_sessions=args.strict_sessions,
            provider=args.provider,
            log_suffix=args.log_suffix,
        )
        print(f"\nCompleted {len(all_timings)} protocols")
        if not args.no_csv:
            print(f"Results saved to: {Path(args.csv).resolve()}")
    elif args.protocols:
        protocols = [p.strip() for p in args.protocols.split(',') if p.strip()]
        if Path(args.csv).exists():
            print(f"Removing existing global CSV: {args.csv}")
            Path(args.csv).unlink()
        print(f"Running {len(protocols)} protocols: "
              f"{', '.join(protocols)}")
        print(f"Global CSV: {args.csv}")
        all_timings = {}
        for proto in protocols:
            timings = run_single(
                proto, config,
                log_enabled=not args.no_log,
                csv_enabled=not args.no_csv,
                csv_path=args.csv,
                debug=args.debug,
                sessions=args.sessions,
                strict_sessions=args.strict_sessions,
                provider=args.provider,
                log_suffix=args.log_suffix,
            )
            if timings:
                all_timings[proto] = timings
        print(f"\nCompleted {len(all_timings)} of {len(protocols)} protocols")
        if not args.no_csv:
            print(f"Results saved to: {Path(args.csv).resolve()}")
    else:
        timings = run_single(args.protocol, config, log_enabled=not args.no_log,
                             csv_enabled=not args.no_csv, csv_path=args.csv,
                             debug=args.debug, sessions=args.sessions,
                             strict_sessions=args.strict_sessions,
                             provider=args.provider,
                             log_suffix=args.log_suffix)
        if timings:
            total = sum(t['time_ms'] for t in timings)
            print(f"\nTotal time: {total:.2f} ms ({total/1000:.2f} s)")
            print(f"\nStage breakdown:")
            for t in timings:
                status = "[OK]" if t['returncode'] == 0 else "[FAIL]"
                print(f"  {status} {t['stage']}: {t['time_ms']:.2f} ms")
            if not args.no_csv:
                print(f"\nResults appended to: {Path(args.csv).resolve()}")

if __name__ == '__main__':
    main()