"""Repository code search with service-mapping-aware prioritization.

Priority: exact file+line > file+function > function > error signature >
semantic fallback. Never invents files — every hit must exist on disk.
"""
import os
import re
from typing import Dict, List, Optional


def _candidate_roots(repo_root: str, service: str = "",
                     service_mappings: Optional[Dict[str, str]] = None) -> List[str]:
    roots = []
    mappings = service_mappings or {}
    if service and service in mappings:
        roots.append(os.path.join(repo_root, mappings[service].strip("/")))
    # conventional fallbacks
    for cand in (f"services/{service}" if service else "",
                 f"services/checkout", "services/orders", "services/payments",
                 "src", "app", "."):
        if not cand:
            continue
        p = os.path.join(repo_root, cand)
        if os.path.isdir(p) and p not in roots:
            roots.append(p)
    if os.path.isdir(repo_root) and repo_root not in roots:
        roots.append(repo_root)
    return roots


def _iter_source_files(roots: List[str], max_files: int = 600) -> List[str]:
    out = []
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames
                           if d not in (".git", "__pycache__", "node_modules", ".venv", "venv")]
            for fn in filenames:
                if fn.endswith((".py", ".java", ".js", ".ts", ".go")):
                    out.append(os.path.join(dirpath, fn))
                    if len(out) >= max_files:
                        return out
    return out


def search_code(repo_root: str, service: str = "",
                service_mappings: Optional[Dict[str, str]] = None,
                stack: Optional[Dict] = None,
                error_signature: str = "") -> Dict:
    """Return {strategy, hits[]} where each hit has file/line/function/snippet.

    strategy is the first successful tier name, or 'no_match'.
    """
    stack = stack or {}
    frames = stack.get("frames") or []
    hits: List[Dict] = []

    def rel(path: str) -> str:
        try:
            return os.path.relpath(path, repo_root).replace(os.sep, "/")
        except Exception:
            return path

    # Tier 1: exact file+line — resolve frame file against repo
    for fr in frames:
        target = (fr.get("file") or "").replace("\\", "/")
        line = int(fr.get("line") or 0)
        if not target:
            continue
        for root in _candidate_roots(repo_root, service, service_mappings):
            # try exact relative, basename, and suffix matches
            candidates = [os.path.join(repo_root, target),
                          os.path.join(root, os.path.basename(target))]
            for c in candidates:
                if os.path.isfile(c):
                    snippet = ""
                    try:
                        with open(c, encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()
                        if 1 <= line <= len(lines):
                            snippet = lines[line - 1].rstrip()[:400]
                    except OSError:
                        pass
                    return {"strategy": "exact_file_line",
                            "hits": [{"file": rel(c), "line": line,
                                      "function": fr.get("function", ""),
                                      "snippet": snippet}]}
        # suffix search across source files
        base = os.path.basename(target)
        for path in _iter_source_files(_candidate_roots(repo_root, service, service_mappings)):
            if os.path.basename(path) == base:
                snippet = ""
                try:
                    with open(path, encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    if 1 <= line <= len(lines):
                        snippet = lines[line - 1].rstrip()[:400]
                except OSError:
                    pass
                return {"strategy": "exact_file_line",
                        "hits": [{"file": rel(path), "line": line,
                                  "function": fr.get("function", ""), "snippet": snippet}]}

    # Tier 2/3: file+function or function search within mapped service dir
    funcs = [f.get("function", "").split(".")[-1] for f in frames if f.get("function")]
    funcs = [f for f in funcs if f and f not in ("<module>", "unknown")]
    files = _iter_source_files(_candidate_roots(repo_root, service, service_mappings))
    for func in funcs[:5]:
        pat = re.compile(rf"\bdef\s+{re.escape(func)}\b|\bfunction\s+{re.escape(func)}\b|\b{re.escape(func)}\s*\(")
        for path in files:
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                m = pat.search(content)
                if m:
                    line = content[:m.start()].count("\n") + 1
                    hits.append({"file": rel(path), "line": line, "function": func,
                                 "snippet": next((l.strip()[:300] for l in content.splitlines()
                                                  if func in l), "")})
                    if len(hits) >= 5:
                        break
            except OSError:
                continue
        if hits:
            return {"strategy": "function", "hits": hits[:5]}

    # Tier 4: error signature keyword search
    keywords = [w for w in re.findall(r"[A-Za-z_][\w.]{2,40}", error_signature or "")
                if w.lower() not in ("error", "exception", "failure", "none", "object")]
    for kw in keywords[:6]:
        for path in files:
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                for i, line in enumerate(lines, start=1):
                    if kw in line:
                        hits.append({"file": rel(path), "line": i, "function": "",
                                     "snippet": line.strip()[:300]})
                        if len(hits) >= 5:
                            break
            except OSError:
                continue
        if hits:
            return {"strategy": "error_signature", "hits": hits[:5]}

    return {"strategy": "no_match", "hits": []}
