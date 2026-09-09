"""Branch creation: rca/{incident}-{slug} off a clean default branch. Never writes to main."""
import re
from .repository import run_git, default_branch, ensure_clean_tree


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:40] or "fix"


def create_fix_branch(repo_path: str, incident_id: str, root_cause: str) -> str:
    ensure_clean_tree(repo_path)
    base = default_branch(repo_path)
    run_git(repo_path, ["fetch", "origin", base])
    # Never create a branch named like the default branch
    branch = f"rca/{incident_id}-{slugify(root_cause)}"
    if branch.split("/")[-1] in ("main", "master"):
        raise ValueError("Refusing branch name colliding with default branch")
    run_git(repo_path, ["checkout", "-b", branch, f"origin/{base}"])
    return branch
