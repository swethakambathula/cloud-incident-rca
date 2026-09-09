"""
gitops repository guardrails (Part 16): allowlisted git operations only.

- Only the approved demo-app repo path may be touched.
- Never operate on the default branch (main/master) for writes.
- Never force push, merge, or rewrite history.
- Token values are never logged.
"""
import os
import subprocess
from typing import List

DEFAULT_BRANCHES = {"main", "master"}


def allowed_repos():
    """Evaluated per call so tests (tmp repos via DEMO_APP_PATH) and server env both work."""
    return set(filter(None, [
        os.getenv("DEMO_APP_REPO_URL", ""),
        os.getenv("DEMO_APP_PATH", "") or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "cloud-rca-demo-app"),
    ]))

# Only these git subcommands may ever run (no shell=True anywhere).
ALLOWED_COMMANDS = {
    "status", "diff", "fetch", "checkout", "checkout -b", "add", "commit",
    "push", "rev-parse", "rev-list", "log", "apply --check", "apply", "branch",
}


def run_git(repo_path: str, args: List[str], check: bool = True) -> str:
    key = " ".join(args[:2]) if args[:1] == ["checkout"] and args[1:2] == ["-b"] else (args[0] if args else "")
    if key == "checkout" and len(args) > 1 and args[1] == "-b":
        key = "checkout -b"
    if args[:1] == ["apply"] and "--check" in args:
        key = "apply --check"
    if key not in ALLOWED_COMMANDS:
        raise PermissionError(f"Git subcommand not allowlisted: {args}")
    # Flag smuggling guard: no dangerous flags on any command
    if any(a in ("--force", "-f", "--hard", "--all") for a in args):
        raise PermissionError(f"Dangerous git flag blocked: {args}")
    # push may only ship one explicit branch refspec, never the default branch
    # (writes to main are refused here; commit_fix/push_branch refuse them too)
    if args and args[0] == "push":
        if not (len(args) == 3 and args[1] == "origin" and ":" in args[2]
                and not any(part in DEFAULT_BRANCHES for part in args[2].split(":"))):
            raise PermissionError(f"Push refspec not allowlisted: {args}")
    if not any(repo_path == r or repo_path.startswith((r + os.sep,)) for r in allowed_repos() if r):
        raise PermissionError(f"Repository not approved for gitops: {repo_path}")
    proc = subprocess.run(["git", "-C", repo_path] + args, capture_output=True,
                          text=True, timeout=120)
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()[:500]}")
    return proc.stdout.strip()


def default_branch(repo_path: str) -> str:
    try:
        out = run_git(repo_path, ["rev-parse", "--abbrev-ref", "origin/HEAD"])
        return out.split("/")[-1]
    except Exception:
        return "main"


def ensure_clean_tree(repo_path: str):
    status = run_git(repo_path, ["status", "--porcelain"])
    if status:
        raise RuntimeError(f"Working tree not clean, refusing to branch: {status[:200]}")


def current_branch(repo_path: str) -> str:
    return run_git(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"])
