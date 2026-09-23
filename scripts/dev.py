"""Cross-platform entry point for common SENTINEL development tasks."""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"


def uv_command() -> list[str]:
    """Find uv as a command or as a module in the active Python installation."""
    executable = shutil.which("uv")
    if executable:
        return [executable]

    candidates: list[list[str]] = [[sys.executable, "-m", "uv"]]
    if os.name == "nt":
        launcher = shutil.which("py")
        if launcher:
            candidates.insert(0, [launcher, "-3.12", "-m", "uv"])

    for candidate in candidates:
        try:
            result = subprocess.run(
                [*candidate, "--version"],
                cwd=ROOT,
                capture_output=True,
                check=False,
                text=True,
            )
        except OSError:
            continue
        if result.returncode == 0:
            return candidate

    raise RuntimeError(
        "uv was not found. Install uv and make it available on PATH, then run this command again. "
        "Installation instructions: https://docs.astral.sh/uv/getting-started/installation/"
    )


def run(command: list[str], *, cwd: Path = ROOT) -> int:
    print(f"+ ({cwd.relative_to(ROOT) if cwd != ROOT else '.'}) {shlex.join(command)}", flush=True)
    try:
        return subprocess.run(command, cwd=cwd, check=False).returncode
    except FileNotFoundError as error:
        print(f"Could not start {command[0]!r}: {error}", file=sys.stderr)
        return 127


def run_uv(uv: list[str], *arguments: str, cwd: Path = ROOT) -> int:
    return run([*uv, *arguments], cwd=cwd)


def setup(uv: list[str]) -> int:
    return run_uv(uv, "sync", "--frozen", "--python", "3.12")


def check(uv: list[str]) -> int:
    commands = [
        (ROOT, ("run", "--frozen", "ruff", "check", "src", "tests", "scripts", "starter-kits")),
        (ROOT, ("run", "--frozen", "ruff", "format", "--check", "src", "tests", "scripts", "starter-kits")),
        (ROOT, ("run", "--frozen", "mypy")),
        (ROOT, ("run", "--frozen", "pytest")),
        (
            ROOT / "starter-kits" / "python-defense",
            ("run", "--project", "../..", "--frozen", "pytest", "-q"),
        ),
        (
            ROOT / "starter-kits" / "learned-monitor",
            ("run", "--project", "../..", "--frozen", "pytest", "-q"),
        ),
        (ROOT, ("run", "--frozen", "sentinel", "scenarios", "validate", "scenarios")),
    ]
    for cwd, arguments in commands:
        status = run_uv(uv, *arguments, cwd=cwd)
        if status:
            return status
    return 0


def npm_command(*arguments: str, cwd: Path = FRONTEND) -> int:
    npm = shutil.which("npm")
    if npm is None:
        print(
            "Node.js and npm are required for observatory tasks. Install Node.js, then retry. "
            "Firewall setup, runs, and checks do not require Node.js.",
            file=sys.stderr,
        )
        return 127
    if os.name == "nt":
        print(f"+ ({cwd.relative_to(ROOT)}) {npm} {shlex.join(list(arguments))}", flush=True)
        try:
            return subprocess.run([npm, *arguments], cwd=cwd, check=False, shell=True).returncode
        except FileNotFoundError as error:
            print(f"Could not start npm: {error}", file=sys.stderr)
            return 127
    return run([npm, *arguments], cwd=cwd)


def observatory(uv: list[str]) -> int:
    if (ROOT / "artifacts" / "phase-final" / "real").is_dir():
        status = run_uv(uv, "run", "--frozen", "python", "scripts/export-next-data.py")
        if status:
            return status

    if not (FRONTEND / "data" / "index.json").is_file():
        print("No exported observatory traces are available in frontend/data.", file=sys.stderr)
        return 2

    if not (FRONTEND / "node_modules").is_dir():
        status = npm_command("ci", "--no-audit", "--no-fund")
        if status:
            return status

    status = npm_command("run", "build")
    if status:
        return status

    print("Open http://127.0.0.1:3000 in a browser. Press Ctrl+C to stop.", flush=True)
    return npm_command("run", "start")


def visual_check() -> int:
    try:
        with urlopen("http://127.0.0.1:3000", timeout=2):
            pass
    except (OSError, URLError):
        print(
            "The observatory is not responding at http://127.0.0.1:3000. "
            "Start it with `python scripts/dev.py observatory` in another terminal.",
            file=sys.stderr,
        )
        return 2

    if not (FRONTEND / "node_modules").is_dir():
        status = npm_command("ci", "--no-audit", "--no-fund")
        if status:
            return status

    status = npm_command("exec", "--", "playwright", "install", "chromium")
    if status:
        return status
    return npm_command("run", "visual-check")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="task", required=True)
    subparsers.add_parser("setup", help="install the frozen Python 3.12 environment")
    subparsers.add_parser("check", help="run lint, type, test, starter-kit, and scenario checks")
    subparsers.add_parser("doctor", help="run the firewall environment diagnostic")
    run_parser = subparsers.add_parser("run", help="run a firewall scenario")
    run_parser.add_argument("arguments", nargs=argparse.REMAINDER, help="scenario path and sentinel-firewall arguments")
    subparsers.add_parser("observatory", help="build and serve the optional local observatory")
    subparsers.add_parser("visual-check", help="run the optional Playwright visual check")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        uv = uv_command()
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 127

    if args.task == "setup":
        return setup(uv)
    if args.task == "check":
        return check(uv)
    if args.task == "doctor":
        return run_uv(uv, "run", "--frozen", "sentinel-firewall", "doctor")
    if args.task == "run":
        forwarded = list(args.arguments)
        if forwarded[:1] == ["--"]:
            forwarded.pop(0)
        scenario = "scenarios/public/enterprise/enterprise_poisoned_invoice.yaml"
        if forwarded and not forwarded[0].startswith("-"):
            scenario = forwarded.pop(0)
        return run_uv(
            uv,
            "run",
            "--frozen",
            "sentinel-firewall",
            "run",
            scenario,
            *forwarded,
        )
    if args.task == "observatory":
        return observatory(uv)
    if args.task == "visual-check":
        return visual_check()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
