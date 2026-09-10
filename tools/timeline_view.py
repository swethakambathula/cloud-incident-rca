"""
Timeline presentation logic: parse raw event strings into structured,
human-readable groups. Pure functions (unit-tested); the frontend renders.

- parse_event(): splits "ERROR: CODE ... k=v ..." into title/attributes/raw.
- group_events(): collapses repeats of the same signature into one group
  with first/last range, count and peak attributes.
- significant(): keeps non-error-spike events plus one group per signature.
"""
import re
from typing import Any, Dict, List

KV_RE = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^\s,;]+)")
CODE_RE = re.compile(r"\b([A-Z][A-Z0-9_]{3,60})\b")
NUM_RE = re.compile(r"[-+]?\d+(?:\.\d+)?%?")
SKIP_TOKENS = {"HTTP", "HTTPS", "UTC", "ERROR", "WARNING", "INFO", "DEBUG",
               "CRITICAL", "TRACE", "SPAN", "LOG", "SERVICE"}


DISPLAY_OVERRIDES = {
    "WAITING_APPROVAL": "Waiting for Approval",
}


def humanize_enum(value: str) -> str:
    """UPPER_SNAKE -> Title Case words. Display only; contracts untouched."""
    text = str(value or "")
    if text in DISPLAY_OVERRIDES:
        return DISPLAY_OVERRIDES[text]
    return " ".join(w.capitalize() for w in text.split("_") if w)


def parse_event(description: str) -> Dict[str, Any]:
    """Parse one raw timeline description into title/attributes/raw."""
    text = str(description or "")
    codes = [c for c in CODE_RE.findall(text) if c not in SKIP_TOKENS]
    code = codes[0] if codes else ""
    attributes: Dict[str, str] = {}
    for key, val in KV_RE.findall(text):
        if key not in attributes:
            attributes[key] = val
    if code:
        title = humanize_enum(code)
    else:
        head = text.split(":")[-1].strip() if ":" in text else text.strip()
        title = head[:80] or "Event"
    return {"title": title, "error_code": code, "attributes": attributes, "raw": text}


def _signature(parsed: Dict[str, Any], event_type: str) -> str:
    if parsed["error_code"]:
        return f"{event_type}:{parsed['error_code']}"
    return f"{event_type}:{parsed['title'][:60]}"


def _peak_attributes(events: List[Dict[str, Any]]) -> Dict[str, str]:
    """For numeric attributes keep the max observed value across repeats."""
    peaks: Dict[str, str] = {}
    for parsed in events:
        for key, val in parsed["attributes"].items():
            candidate = NUM_RE.search(str(val))
            if not candidate:
                if key not in peaks:
                    peaks[key] = str(val)
                continue
            try:
                num = float(candidate.group(0).rstrip("%"))
            except ValueError:
                continue
            current = NUM_RE.search(str(peaks.get(key, "")))
            current_num = float(current.group(0).rstrip("%")) if current else None
            if current_num is None or num > current_num:
                peaks[key] = str(val)
    return peaks


def group_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse repeats; preserve first-seen order of groups."""
    groups: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for event in events:
        parsed = parse_event(event.get("description", ""))
        key = _signature(parsed, event.get("event_type", ""))
        if key not in groups:
            groups[key] = {"key": key, "title": parsed["title"],
                           "error_code": parsed["error_code"],
                           "event_type": event.get("event_type", ""),
                           "source": event.get("source", ""),
                           "count": 0, "first": event.get("timestamp", ""),
                           "last": event.get("timestamp", ""),
                           "members": []}
            order.append(key)
        group = groups[key]
        group["count"] += 1
        group["last"] = event.get("timestamp", "") or group["last"]
        group["members"].append(parsed)
    result = []
    for key in order:
        group = groups[key]
        group["attributes"] = _peak_attributes(group["members"])
        del group["members"]
        result.append(group)
    return result


def significant(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Significant view: non-spike events verbatim + one entry per error group."""
    spike_types = {"ERROR_SPIKE", "ERROR"}
    out: List[Dict[str, Any]] = []
    groups = group_events([e for e in events if e.get("event_type") in spike_types])
    for event in events:
        if event.get("event_type") not in spike_types:
            parsed = parse_event(event.get("description", ""))
            out.append({"kind": "event", "title": parsed["title"],
                        "timestamp": event.get("timestamp", ""),
                        "event_type": event.get("event_type", ""),
                        "description": event.get("description", ""),
                        "source": event.get("source", "")})
    for group in groups:
        out.append({"kind": "group", **group})
    return out
