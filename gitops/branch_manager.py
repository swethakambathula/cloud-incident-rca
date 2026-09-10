"""Branch creation: rca/{incident}-{slug} off a clean default branch. Never writes to main."""
import re
from .repository import run_git, default_branch, ensure_clean_tree, current_branch


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:40] or "fix"


def checkout_base(repo_path: str) -> str:
    """Fetch latest default branch and check it out so investigation/patching
    always starts from clean, faulty base state (never a previous fix branch)."""
    base = default_branch(repo_path)
    run_git(repo_path, ["fetch", "origin", base])
    try:
        run_git(repo_path, ["checkout", base])
    except RuntimeError as e:
        current = current_branch(repo_path)
        raise RuntimeError(
            f"Cannot return to base branch {base}: working tree state from a previous "
            f"attempt is in the way (on {current}). Inspect it, then retry. Detail: {e}")
    # reset any stale in-memory mock state not needed; ensure tree clean-ish
    status = run_git(repo_path, ["status", "--porcelain"])
    if status:
        raise RuntimeError(
            f"Working tree dirty on {base}; previous attempt left uncommitted changes. "
            f"Inspect with git status/diff, then retry.")
    return base


def create_fix_branch(repo_path: str, incident_id: str, root_cause: str) -> str:
    ensure_clean_tree(repo_path)
    base = default_branch(repo_path)
    run_git(repo_path, ["fetch", "origin", base])
    # Never create a branch named like the default branch
    stem = f"rca/{incident_id}-{slugify(root_cause)}"
    if stem.split("/")[-1] in ("main", "master"):
        raise ValueError("Refusing branch name colliding with default branch")
    # Unique name across repeated runs for the same incident. Fresh containers
    # have no local branches, so the remote must be consulted too — otherwise
    # push is rejected non-fast-forward when a previous attempt already pushed.
    try:
        remote_refs = run_git(repo_path, ["ls-remote", "--heads", "origin", stem + "*"])
    except (RuntimeError, PermissionError):
        remote_refs = ""
    def _taken(name: str) -> bool:
        if run_git(repo_path, ["branch", "--list", name]):
            return True
        return any(line.split("\t")[-1] == f"refs/heads/{name}"
                   for line in remote_refs.splitlines() if line.strip())
    branch, suffix = stem, 2
    while _taken(branch):
        branch = f"{stem}-{suffix}"
        suffix += 1
    run_git(repo_path, ["checkout", "-b", branch, f"origin/{base}"])
    return branch
