"""Best-effort timestamp parsing. Returns ISO string or '' (never guesses)."""
import re
from datetime import datetime, timezone

_PATTERNS = [
    "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S",
]

_ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")


def parse_timestamp(value) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    iso = text.replace("Z", "+00:00") if text.endswith("Z") else text
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except ValueError:
        pass
    for fmt in _PATTERNS:
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    return ""


def extract_timestamp(text: str) -> str:
    m = _ISO_RE.search(text or "")
    return parse_timestamp(m.group(0)) if m else ""
