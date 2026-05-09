"""
Optional helper script - lets users run `python setup.py` to do a one-shot
dependency install + first-run keygen + connectivity probe.

This is *not* a setuptools manifest; it's just a friendly bootstrap.
For packaging the project, prefer pyproject.toml.  Kept here because the
project brief explicitly lists it as an optional convenience.
"""

from __future__ import annotations

import os
import subprocess
import sys


def run(cmd):
    """Run a shell command, streaming output, abort on non-zero exit."""
    print(f"\n>> {' '.join(cmd)}")
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        sys.exit(proc.returncode)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    os.chdir(here)

    print("=== Quantum-Safe Email Encryption - Bootstrap ===")
    run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    run([sys.executable, "main.py", "test"])
    if not os.path.exists("keys.db"):
        run([sys.executable, "main.py", "setup"])
    if not os.path.exists(".env"):
        print("\n(.env not found - copy .env.example to .env and add your "
              "Gmail App Password before sending or receiving mail.)")
    print("\nAll done.  Next: `python main.py threat-report`")


if __name__ == "__main__":
    main()
