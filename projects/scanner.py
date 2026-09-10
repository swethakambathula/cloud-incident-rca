"""
Read-only repository scanner for project onboarding. Never modifies the repo.
Detects languages, frameworks, services, Dockerfiles, tests, CI and config.
"""
import os
import re
from typing import Dict, List

LANG_BY_EXT = {".py": "python", ".js": "javascript", ".ts": "typescript",
               ".go": "go", ".java": "java", ".rb": "ruby"}
FRAMEWORK_MARKERS = {"flask": "flask", "fastapi": "fastapi", "django": "django",
                     "express": "express", "pytest": "pytest"}


def scan_repo(path: str, max_files: int = 400) -> Dict:
    result: Dict = {"languages": [], "frameworks": [], "services": [],
                    "dockerfiles": [], "requirements": [], "tests": [],
                    "ci_files": [], "config_files": [], "file_count": 0,
                    "error": ""}
    if not path or not os.path.isdir(path):
        result["error"] = "Repository path not found or not a directory"
        return result
    langs, frameworks = set(), set()
    files_seen = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules", ".venv", "venv")]
        for fn in files:
            if files_seen >= max_files:
                break
            files_seen += 1
            fp = os.path.join(root, fn)
            rel = os.path.relpath(fp, path)
            ext = os.path.splitext(fn)[1].lower()
            if ext in LANG_BY_EXT:
                langs.add(LANG_BY_EXT[ext])
            low = fn.lower()
            if low == "dockerfile" or low.endswith(".dockerfile"):
                result["dockerfiles"].append(rel)
            if low in ("requirements.txt", "pyproject.toml", "package.json", "go.mod"):
                result["requirements"].append(rel)
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as f:
                        content = f.read(8000).lower()
                    for marker, fw in FRAMEWORK_MARKERS.items():
                        if marker in content:
                            frameworks.add(fw)
                except OSError:
                    pass
            if low.startswith("test_") or (low.startswith("test") and ext in (".py", ".js", ".ts")):
                result["tests"].append(rel)
            if ".github/workflows" in rel.replace(os.sep, "/") or low in (
                    ".gitlab-ci.yml", "cloudbuild.yaml", "jenkinsfile"):
                result["ci_files"].append(rel)
            if low in (".env.example", "config.yaml", "config.yml", "settings.py") or low.endswith(".env"):
                result["config_files"].append(rel)
            if low == "main.py" and os.path.basename(root) not in ("", "."):
                parent = os.path.basename(root)
                grandparent = os.path.basename(os.path.dirname(root))
                if grandparent in ("services", "apps", "src"):
                    result["services"].append(f"{grandparent}/{parent}".replace(os.sep, "/"))
    # service boundaries: top-level service dirs as fallback
    if not result["services"]:
        for entry in sorted(os.listdir(path)):
            if os.path.isdir(os.path.join(path, entry)) and entry in ("services",):
                for sub in sorted(os.listdir(os.path.join(path, entry))):
                    if os.path.isdir(os.path.join(path, entry, sub)):
                        result["services"].append(f"{entry}/{sub}")
    result["languages"] = sorted(langs)
    result["frameworks"] = sorted(frameworks)
    result["file_count"] = files_seen
    return result


def detect_default_branch(path: str) -> str:
    for ref in ("main", "master"):
        if os.path.isdir(os.path.join(path, ".git", "refs", "heads", ref)):
            return ref
    return "main"


def connection_ok(path: str = "", url: str = "") -> Dict:
    """Read-only reachability: local path exists, or URL looks like a git remote."""
    if path:
        ok = os.path.isdir(path)
        return {"ok": ok, "detail": "local path found" if ok else "local path not found"}
    if url:
        ok = bool(re.match(r"^(https?://|git@)[\w.\-/:]+(\.git)?$", url or ""))
        return {"ok": ok, "detail": "URL shape valid" if ok else "URL shape invalid"}
    return {"ok": False, "detail": "provide a local path or repository URL"}
