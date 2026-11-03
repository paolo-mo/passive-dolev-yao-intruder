#!/usr/bin/env python3
r"""
Discrimination experiment: 2 captures x 2 runtime configurations.
Lives in the toolchain folder alongside jpcap2ser.py and sessionbuild.py.

Usage:
    python discrimination.py --root \genAnBx\src\carlsen
"""
import argparse, subprocess, sys, re, shutil, configparser
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

# Read ANT_CMD from the same config file run_test.py uses.
_cfg = configparser.ConfigParser()
_cfg.read(SCRIPT_DIR / "jpcap2ser.cfg")
ANT_CMD = _cfg['DEFAULT'].get('ANT_CMD', 'ant')

# Resolve relative to the config directory, matching run_test.py.
if not Path(ANT_CMD).is_absolute():
    ANT_CMD = str((SCRIPT_DIR / ANT_CMD).resolve())

# Quote if it contains spaces (e.g. "C:\Program Files\...").
if ' ' in ANT_CMD and not ANT_CMD.startswith('"'):
    ANT_CMD = f'"{ANT_CMD}"'

BASEDIR = _cfg['DEFAULT'].get('BASEDIR', '')
if BASEDIR and not Path(BASEDIR).is_absolute():
    BASEDIR = str((SCRIPT_DIR / BASEDIR).resolve())

INTRUDER_ALIAS = "grace"

CELLS = [("ref", "ref"), ("ref", "swap"), ("swap", "ref"), ("swap", "swap")]

# The filename the generated runtime reads for its aliases map.  The
# compiled Java is identical across the two instantiations; only this
# file differs, and it is read at runtime.
RUNTIME_PROPS = "Carlsen.properties"

# Carlsen in this experiment runs as a single session (N=1, K=2).
SESSION_ID = 1

def run(cmd, cwd, log=None, shell=False):
    # On Windows with shell=True, subprocess re-quotes each list element
    # via list2cmdline.  If any element is already quoted (as ANT_CMD is),
    # the result is double-quoted and cmd.exe rejects it.  Build a single
    # string instead, quoting only the elements that need it.
    if shell and isinstance(cmd, list):
        parts = []
        for c in cmd:
            s = str(c)
            if ' ' in s and not (s.startswith('"') and s.endswith('"')):
                s = f'"{s}"'
            parts.append(s)
        cmd = ' '.join(parts)

    print(f"  $ {cmd}")
    out = open(log, "w") if log else None
    r = subprocess.run(cmd, cwd=cwd, stdout=out, stderr=subprocess.STDOUT,
                       text=True, shell=shell)
    if out:
        out.close()
    if r.returncode != 0:
        sys.exit(f"command failed: {cmd}")

def extract_and_objcheck(capture, props, root, snapdir):
    """Stages 3-4 plus ObjCheck.  Snapshot the per-step .ser files."""
    # Put the matching instantiation's properties in place so that both
    # jpcap2ser.py / outparse.py (channel ordering) and the generated
    # code (aliases at runtime) pick up the right map.
    shutil.copy(props, root / RUNTIME_PROPS)

    # Stage 3 - PCAP to streams
    run([sys.executable, str(SCRIPT_DIR / "jpcap2ser.py"), "Carlsen",
         "--pcap", str(capture), "--allstreams", "--emit-meta"],
        cwd=root)

    # Stage 4 - session build
    run([sys.executable, str(SCRIPT_DIR / "sessionbuild.py"),
         "--streams",    str(root / "Carlsen_streams.json"),
         "--properties", str(root / RUNTIME_PROPS),
         "--output",     str(root / "Carlsen_session_meta.json"),
         "--log-level",  "info"],
        cwd=root)

    # Stage 5 Pass A - ObjCheck for candidate 0 (single candidate).
    shutil.copy(root / "Carlsen_session_meta_c0.txt",
                root / "Carlsen_session_meta.txt")
    for f in root.glob("Carlsen_*_STEP_*.ser"):
        f.unlink()
    run([ANT_CMD, "-buildfile", str(root / "build.xml"), "objcheck"],
        cwd=root, shell=True)

    # Snapshot the STEP files so the next capture's extraction does not
    # overwrite this capture's reconstruction.
    if snapdir.exists():
        shutil.rmtree(snapdir)
    snapdir.mkdir(parents=True)
    for f in root.glob("Carlsen_*_STEP_*.ser"):
        shutil.copy(f, snapdir / f.name)

def generate_intruder(anbx_file, root):
    run(["anbxc", str(anbx_file), "-out:Java", "-objcheck",
         "-nocfgmsg", "-silent", "-securityProvider", "default",
         "-objchecksession", str(SESSION_ID)],
        cwd=BASEDIR, shell=True)
    run([ANT_CMD, "-buildfile", str(root / "build.xml"), "compile"],
        cwd=root, shell=True)

    # anbxc has (re)generated Carlsen.properties; extract the ROLE_intr
    # block so run_cell can re-append it after installing the cell's
    # own properties.
    props_path = root / RUNTIME_PROPS
    lines = props_path.read_text().splitlines()

    block = []
    for i, line in enumerate(lines):
        if 'ROLE_intr' in line or 'intr_role' in line:
            # include the preceding comment line if present
            if i > 0 and lines[i - 1].startswith('#'):
                block.append(lines[i - 1])
            block.append(line)

    if not block:
        sys.exit(f"anbxc did not emit a ROLE_intr entry in {props_path}; "
                 f"inspect the file and adjust the parsing")

    (root / "_intruder_props.txt").write_text("\n".join(block) + "\n")

def run_cell(cap, checks, root, snapdirs, props, log):
    for f in root.glob("Carlsen_*_STEP_*.ser"):
        f.unlink()
    for f in snapdirs[cap].glob("Carlsen_*_STEP_*.ser"):
        shutil.copy(f, root / f.name)

    shutil.copy(props[checks], root / RUNTIME_PROPS)

    # Derive the intruder alias row from the cell's own ROLE_B row.
    lines = (root / RUNTIME_PROPS).read_text().splitlines()
    role_b_value = None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("ROLE_B ") and "=" in stripped:
            role_b_value = stripped.split("=", 1)[1].strip()
            break
    if role_b_value is None:
        sys.exit(f"cannot find ROLE_B row in {root / RUNTIME_PROPS}")

    # Use the saved intruder block (alias + channel definitions) from
    # generate_intruder, and replace the alias row with the cell-specific
    # one.  The channel definitions must be present, otherwise the
    # framework cannot create the intruder's session.
    intruder_file = root / "_intruder_props.txt"
    if not intruder_file.exists():
        sys.exit(f"{intruder_file} not found; run generate_intruder first")
    block = intruder_file.read_text().splitlines()
    new_block = []
    for line in block:
        if line.strip().startswith("ROLE_intr ="):
            new_block.append(f"ROLE_intr = {role_b_value},{INTRUDER_ALIAS}")
        else:
            new_block.append(line)

    with open(root / RUNTIME_PROPS, 'a') as f:
        f.write("\n# Intruder entry (auto-generated by driver)\n")
        f.write("\n".join(new_block) + "\n")

    run([ANT_CMD, "-buildfile", str(root / "build.xml"), "runagents"],
        cwd=root, log=log, shell=True)

def parse_log(log):
    ids = []
    current = None
    for line in Path(log).read_text().splitlines():
        m = re.search(r"CHECK\s+#\s*(\S+)", line)
        if m:
            current = m.group(1)
            continue
        if "check FAILED!" in line and current:
            ids.append(current)
    return ids

def restore_plain_java(anbx_file, root):
    """Regenerate the Java sources in the plain (non-intruder) state,
    matching Stage 1 of run_test.py.  This ensures Carlsen_Channels has
    the same channel names as the .properties file, which is what
    ObjCheck expects."""
    run(["anbxc", str(anbx_file), "-out:JavaDocker", "-nocfgmsg", "-silent",
         "-securityProvider", "default"],
        cwd=BASEDIR, shell=True)
    run([ANT_CMD, "-buildfile", str(root / "build.xml"), "compile"],
        cwd=root, shell=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True,
                    help="Folder with Carlsen_ref.pcap, Carlsen_swap.pcap "
                         "and the two .properties files")
    ap.add_argument("--workdir", default="work")
    ap.add_argument("--anbx", default=None,
                    help="Path to Carlsen.AnBx (default: <root>/Carlsen.AnBx)")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    workdir = root / args.workdir
    workdir.mkdir(exist_ok=True)

    anbx_file = Path(args.anbx) if args.anbx else root / "Carlsen.AnBx"
    if not anbx_file.exists():
        sys.exit(f"cannot find {anbx_file}; pass --anbx to override")

    captures = {"ref":  root / "Carlsen_ref.pcap",
                "swap": root / "Carlsen_swap.pcap"}
    props    = {"ref":  root / "Carlsen_ref.properties",
                "swap": root / "Carlsen_swap.properties"}
    snapdirs = {"ref":  workdir / "snap_ref",
                "swap": workdir / "snap_swap"}

    print("=== Restoring plain Java (Stage 1 state) ===")
    restore_plain_java(anbx_file, root)
    
    # Stage 3-4 plus ObjCheck, once per capture.
    for name in ("ref", "swap"):
        print(f"=== Extract capture={name} ===")
        extract_and_objcheck(captures[name], props[name], root, snapdirs[name])

    # Generate and compile the passive intruder once.
    print("=== Generating intruder role ===")
    generate_intruder(anbx_file, root)

    # Four cells.
    results = {}
    for cap, checks in CELLS:
        log = workdir / f"intruder_{cap}_x_{checks}.log"
        print(f"=== Cell: capture={cap}, checks={checks} ===")
        run_cell(cap, checks, root, snapdirs, props, log)
        results[(cap, checks)] = parse_log(log)

    # Matrix.
    print()
    print(f"{'':>15} | {'checks=ref':>14} | {'checks=swap':>14}")
    print("-" * 50)
    for cap in ("ref", "swap"):
        row = []
        for checks in ("ref", "swap"):
            ids = results[(cap, checks)]
            row.append("PASS" if not ids else f"FAIL ({len(ids)})")
        print(f"{cap:>15} | {row[0]:>14} | {row[1]:>14}")

    print()
    for cap, checks in [("ref", "swap"), ("swap", "ref")]:
        print(f"capture={cap} x checks={checks}: "
              f"failed {results[(cap, checks)]}")

if __name__ == "__main__":
    main()
    