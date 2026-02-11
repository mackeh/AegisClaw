#!/usr/bin/env python3
"""Execute code snippets in a sandboxed environment with resource limits."""

import os
import subprocess
import sys
import tempfile

TIMEOUT = int(os.environ.get("TIMEOUT", "30"))
MAX_OUTPUT_KB = int(os.environ.get("MAX_OUTPUT_KB", "256"))
WORKSPACE = "/workspace"
OUTPUT_DIR = "/workspace/output"

RUNNERS = {
    ".py": ["python3"],
    ".sh": ["bash"],
}


def find_snippet():
    """Find the first code file in /workspace."""
    for entry in sorted(os.listdir(WORKSPACE)):
        full = os.path.join(WORKSPACE, entry)
        if not os.path.isfile(full):
            continue
        _, ext = os.path.splitext(entry)
        if ext in RUNNERS:
            return full, ext
    return None, None


def run_snippet(path, ext):
    cmd = RUNNERS[ext] + [path]
    print(f"Running: {' '.join(cmd)} (timeout={TIMEOUT}s)")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=WORKSPACE,
        )
    except subprocess.TimeoutExpired:
        print(f"Error: execution timed out after {TIMEOUT}s", file=sys.stderr)
        sys.exit(124)

    stdout = result.stdout[:MAX_OUTPUT_KB * 1024]
    stderr = result.stderr[:MAX_OUTPUT_KB * 1024]

    if stdout:
        print("--- stdout ---")
        print(stdout)

    if stderr:
        print("--- stderr ---", file=sys.stderr)
        print(stderr, file=sys.stderr)

    # Write output to file
    out_file = os.path.join(OUTPUT_DIR, "result.txt")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(out_file, "w") as f:
        f.write(f"exit_code: {result.returncode}\n")
        f.write(f"--- stdout ---\n{stdout}\n")
        if stderr:
            f.write(f"--- stderr ---\n{stderr}\n")

    print(f"\nExit code: {result.returncode}")
    print(f"Output saved to: {out_file}")
    return result.returncode


if __name__ == "__main__":
    path, ext = find_snippet()
    if path is None:
        print("No runnable code found in /workspace", file=sys.stderr)
        print("Supported extensions:", ", ".join(RUNNERS.keys()))
        sys.exit(1)

    sys.exit(run_snippet(path, ext))
