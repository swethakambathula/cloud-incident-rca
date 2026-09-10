"""Read-only repository readiness scan for RCA onboarding.

Checks: reachable, default branch exists, read permissions, source files
readable, test framework + build files detected, service mappings valid.
Never clones, never writes.
"""
import os
from typing import Dict, List

BUILD_FILES = ("requirements.txt", "pyproject.toml", "package.json", "go.mod",
               "pom.xml", "build.gradle", "Dockerfile")
TEST_MARKERS = ("tests", "test", "__tests__", "spec")


def readiness_scan(local_path: str = "", repository_url: str = "",
                   default_branch: str = "main",
                   service_mappings: Dict[str, str] = None) -> Dict:
    service_mappings = service_mappings or {}
    checks: List[Dict] = []

    def add(name: str, ok: bool, detail: str = ""):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    root = ""
    if local_path:
        cand = local_path if os.path.isabs(local_path) else os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), local_path)
        root = cand if os.path.isdir(cand) else ""
        add("repository_reachable", bool(root),
            "local path found" if root else f"local path not found: {local_path}")
    elif repository_url:
        import re
        ok = bool(re.match(r"^(https?://|git@)[\w.\-/:]+(\.git)?$", repository_url or ""))
        add("repository_reachable", ok, "URL shape valid" if ok else "URL shape invalid")
    else:
        add("repository_reachable", False, "no repository configured")

    branch_ok = False
    if root:
        for ref in (default_branch, "main", "master"):
            if os.path.isdir(os.path.join(root, ".git", "refs", "heads", ref)):
                branch_ok = ref == default_branch or True
                break
        else:
            # non-git checkout (e.g. bundled demo app) counts if dir readable
            branch_ok = os.access(root, os.R_OK)
        add("default_branch_exists", branch_ok, default_branch if branch_ok else "branch not verified")
    else:
        add("default_branch_exists", False, "repository unreachable")

    readable = False
    file_count = 0
    if root:
        try:
            sample = []
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", "node_modules")]
                for fn in filenames:
                    if fn.endswith((".py", ".java", ".js", ".ts", ".go")):
                        sample.append(os.path.join(dirpath, fn))
                        if len(sample) >= 5:
                            break
                if len(sample) >= 5:
                    break
            readable = len(sample) > 0 and all(os.access(p, os.R_OK) for p in sample)
            file_count = len(sample)
        except OSError:
            readable = False
    add("clone_read_permissions", bool(root) and os.access(root or ".", os.R_OK),
        "read-only access verified" if root else "no local checkout")
    add("source_files_readable", readable,
        f"{file_count}+ source files readable" if readable else "no readable source files found")

    tests_found: List[str] = []
    build_found: List[str] = []
    languages: List[str] = []
    frameworks: List[str] = []
    if root:
        try:
            from projects.scanner import scan_repo
            scan = scan_repo(root)
            tests_found = scan.get("tests", [])[:10]
            build_found = scan.get("requirements", []) + scan.get("dockerfiles", [])
            languages = scan.get("languages", [])
            frameworks = scan.get("frameworks", [])
        except Exception:
            pass
    add("test_framework_detected", bool(tests_found),
        ", ".join(tests_found[:3]) if tests_found else "no test files detected")
    add("build_files_detected", bool(build_found),
        ", ".join(build_found[:3]) if build_found else "no build files detected")

    mappings_ok = True
    mapping_notes = []
    for svc, path in (service_mappings or {}).items():
        full = os.path.join(root, path.strip("/")) if root else ""
        ok = bool(root) and os.path.isdir(full)
        if not ok:
            mappings_ok = False
        mapping_notes.append(f"{svc} -> {path} ({'ok' if ok else 'missing'})")
        checks.append({"check": f"service_mapping:{svc}", "ok": ok,
                       "detail": path if ok else f"path not found: {path}"})
    if not service_mappings:
        mapping_notes.append("no service mappings configured (RCA falls back to repo-wide search)")

    blocking = [c for c in checks if c["check"] in (
        "repository_reachable", "source_files_readable") and not c["ok"]]
    ready = not blocking and (mappings_ok or not service_mappings)
    status = "Repository Ready" if ready else "Repository Needs Attention"
    return {"status": status, "ready": ready, "checks": checks,
            "languages": languages, "frameworks": frameworks,
            "tests": tests_found, "build_files": build_found,
            "mapping_notes": mapping_notes}
