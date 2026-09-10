"""Patch application with exact-hash verification (Parts 7, 10)."""
import hashlib
import subprocess
from .repository import run_git


def sha256_of_patch(patch_text: str) -> str:
    return hashlib.sha256(patch_text.encode()).hexdigest()


def verify_hash(patch_text: str, approved_sha256: str):
    actual = sha256_of_patch(patch_text)
    if actual != approved_sha256:
        raise ValueError(
            f"Patch hash mismatch: approval is bound to {approved_sha256[:12]}..., "
            f"but patch is {actual[:12]}.... New approval required.")


def _run_git_stdin(repo_path: str, args: list, patch_text: str):
    """Run git with patch bytes on stdin (bytes avoid Windows CRLF translation)."""
    return subprocess.run(["git", "-C", repo_path] + args, input=patch_text.encode("utf-8"),
                          capture_output=True, timeout=60)


def apply_patch(repo_path: str, patch_text: str, approved_sha256: str) -> str:
    """Apply only after hash match; returns resulting git diff stat."""
    from gitops.repository import is_repo_root
    if not is_repo_root(repo_path):
        raise PermissionError(f"Not a git checkout: {repo_path}")
    verify_hash(patch_text, approved_sha256)
    proc = _run_git_stdin(repo_path, ["apply", "--check", "-"], patch_text)
    if proc.returncode != 0:
        raise RuntimeError(f"Patch does not apply cleanly: {proc.stderr.decode()[:500]}")
    proc = _run_git_stdin(repo_path, ["apply", "-"], patch_text)
    if proc.returncode != 0:
        raise RuntimeError(f"Patch apply failed: {proc.stderr.decode()[:500]}")
    return run_git(repo_path, ["diff", "--stat"])
