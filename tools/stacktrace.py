"""Stack-trace extraction for code-aware RCA.

Parses Python / Java / JavaScript-Node / Go traces from raw log text and
returns structured frames: file, line, function/class, exception type+message.
No LLM guessing — pure regex extraction, best frame first.
"""
import re
from typing import Dict, List, Optional

PY_FRAME = re.compile(r'^\s*File\s+"(?P<file>[^"]+)",\s*line\s+(?P<line>\d+),\s*in\s+(?P<func>[\w<>.]+)', re.MULTILINE)
PY_EXC = re.compile(r'^(?P<type>\w*(?:Error|Exception|Warning|KeyError|AttributeError|TypeError|ValueError|IndexError|RuntimeError|TimeoutError))\s*:\s*(?P<msg>.*)$', re.MULTILINE)
JAVA_FRAME = re.compile(r'^\s*at\s+(?P<func>[\w.$]+)\((?P<file>[\w.$]+\.java)(?::(?P<line>\d+))?\)', re.MULTILINE)
JAVA_EXC = re.compile(r'^(?:Exception\s+in\s+thread\s+"[^"]+"\s+)?(?P<type>[\w.$]*(?:Exception|Error))(?::\s*(?P<msg>.*))?$', re.MULTILINE)
NODE_FRAME_PAREN = re.compile(r'^\s*at\s+(?:(?P<func>[^\s(]+)\s+)?\((?P<file>[^()]+?\.[cm]?[jt]s)(?::(?P<line>\d+))?', re.MULTILINE)
NODE_FRAME_BARE = re.compile(r'^\s*at\s+(?P<func2>[^\s]+)\s+(?P<file2>[^()\s]+?\.[cm]?[jt]s):(?P<line2>\d+)', re.MULTILINE)
GO_FRAME = re.compile(r'^\s*(?P<file>[\w\-./]+\.go):(?P<line>\d+)(?:\s+\+0x[0-9a-f]+)?(?:\s+(?P<func>[\w./()*-]+))?', re.MULTILINE)
GO_PANIC = re.compile(r'^(?:panic:\s*)?(?P<msg>.*(?:nil pointer|index out of range|deadlock|slice bounds).*)$', re.MULTILINE | re.IGNORECASE)
GENERIC_FILE_LINE = re.compile(r'(?P<file>[\w\-./\\]+(?:\.py|\.java|\.js|\.ts|\.go)):(?P<line>\d+)')
GENERIC_FUNC = re.compile(r'(?:in|at)\s+[`\'"]?(?P<func>[a-zA-Z_][\w.]*)\b')


def extract_stack_trace(text: str) -> Dict:
    """Return {language, exception_type, exception_message, frames[]}.

    frames are ordered outermost-first as found; caller should treat the
    last app frame (or first exact repo match) as primary suspect.
    """
    text = text or ""
    frames: List[Dict] = []
    language: Optional[str] = None
    exc_type, exc_msg = "", ""
    m = PY_EXC.search(text)
    py_frames = list(PY_FRAME.finditer(text))
    java_frames = list(JAVA_FRAME.finditer(text))
    node_frames = list(NODE_FRAME_PAREN.finditer(text)) + list(NODE_FRAME_BARE.finditer(text))
    go_frames = list(GO_FRAME.finditer(text))
    counts = {"python": len(py_frames), "java": len(java_frames),
              "node": len(node_frames), "go": len(go_frames)}
    language = max(counts, key=lambda k: counts[k]) if any(counts.values()) else None
    if language == "python":
        for f in py_frames:
            frames.append({"file": f.group("file"), "line": int(f.group("line")),
                           "function": f.group("func"), "language": "python"})
        if m:
            exc_type, exc_msg = m.group("type"), (m.group("msg") or "").strip()[:500]
    elif language == "java":
        jm = JAVA_EXC.search(text)
        for f in java_frames:
            frames.append({"file": f.group("file"), "line": int(f.group("line") or 0),
                           "function": f.group("func"), "language": "java"})
        if jm:
            exc_type, exc_msg = (jm.group("type") or "").strip(), (jm.group("msg") or "").strip()[:500]
    elif language == "node":
        for f in node_frames:
            try:
                fn = f.group("file") or ""
            except IndexError:
                fn = ""
            try:
                fn2 = f.group("file2") or ""
            except IndexError:
                fn2 = ""
            try:
                ln = f.group("line") or ""
            except IndexError:
                ln = ""
            try:
                ln2 = f.group("line2") or ""
            except IndexError:
                ln2 = ""
            try:
                func = f.group("func") or ""
            except IndexError:
                func = ""
            try:
                func2 = f.group("func2") or ""
            except IndexError:
                func2 = ""
            frames.append({"file": fn or fn2, "line": int(ln or ln2 or 0),
                           "function": func or func2, "language": "node"})
        em = re.search(r'^(?P<type>\w*Error)\s*:\s*(?P<msg>.*)$', text, re.MULTILINE)
        if em:
            exc_type, exc_msg = em.group("type"), em.group("msg").strip()[:500]
    elif language == "go":
        for f in go_frames:
            frames.append({"file": f.group("file"), "line": int(f.group("line")),
                           "function": f.group("func") or "", "language": "go"})
        gm = GO_PANIC.search(text)
        if gm:
            exc_type, exc_msg = "panic", gm.group("msg").strip()[:500]
    if not frames:
        # Fallback: generic file:line mentions (still useful for repo search)
        for f in GENERIC_FILE_LINE.finditer(text):
            frames.append({"file": f.group("file"), "line": int(f.group("line")),
                           "function": "", "language": language or "unknown"})
        if frames and not language:
            language = "unknown"
    if not exc_type:
        # Generic "ErrorType: message" first line heuristic
        gm = re.search(r'^\s*([A-Z][\w.]*(?:Error|Exception|Failure|Timeout|Exceeded|Violation|Mismatch|Regression))\b\s*:?\s*(.*)$', text, re.MULTILINE)
        if gm:
            exc_type, exc_msg = gm.group(1).strip(), (gm.group(2) or "").strip()[:500]
    return {"language": language or "unknown", "exception_type": exc_type,
            "exception_message": exc_msg, "frames": frames,
            "error_signature": f"{exc_type}: {exc_msg}".strip(": ")[:300]}


def primary_suspect(parsed: Dict) -> Optional[Dict]:
    frames = parsed.get("frames") or []
    # Prefer last frame (innermost) that looks like app code (not stdlib/site-packages)
    for fr in reversed(frames):
        f = (fr.get("file") or "")
        if any(skip in f for skip in ("site-packages", "dist-packages", "node_modules",
                                      "urllib", "java.base", "jdk.internal", "goroutine")):
            continue
        return fr
    return frames[-1] if frames else None
