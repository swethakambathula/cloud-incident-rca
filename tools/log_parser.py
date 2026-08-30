"""
Log Parser Tool for Cloud Incident RCA Agent.
Parses structured JSON logs, syslog formats, Python tracebacks, and plain text log files.
"""
import re
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from agents.rca_agent.schemas import LogEntry, LogLevel


class LogParser:
    """Parses various log formats into structured LogEntry objects."""

    TIMESTAMP_PATTERNS = [
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?',
        r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?',
        r'[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
    ]

    LOG_LEVEL_PATTERN = r'\b(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL|SEVERE)\b'

    @classmethod
    def parse_file(cls, file_path: str, default_service: str = "unknown-service") -> List[LogEntry]:
        """Parses a log file path into a list of LogEntry items."""
        entries: List[LogEntry] = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except FileNotFoundError:
            return entries

        current_multiline: Optional[Dict[str, Any]] = None

        for idx, line in enumerate(lines):
            line_str = line.strip()
            if not line_str:
                continue

            # Check if JSON log format
            if line_str.startswith('{') and line_str.endswith('}'):
                try:
                    data = json.loads(line_str)
                    entry = cls._parse_json_dict(data, default_service, line_str)
                    if entry:
                        entries.append(entry)
                        continue
                except json.JSONDecodeError:
                    pass

            # Standard text line parsing
            entry = cls._parse_text_line(line_str, default_service)
            if entry:
                # Check for stack trace continuation
                if idx + 1 < len(lines) and ("Traceback" in line_str or "Exception" in line_str or "Error" in line_str):
                    stack_lines = [line_str]
                    j = idx + 1
                    while j < len(lines) and (lines[j].startswith('  ') or lines[j].startswith('\t') or "at " in lines[j]):
                        stack_lines.append(lines[j].rstrip())
                        j += 1
                    entry.stack_trace = "\n".join(stack_lines)
                entries.append(entry)

        return entries

    @classmethod
    def _parse_json_dict(cls, data: Dict[str, Any], default_service: str, raw_line: str) -> Optional[LogEntry]:
        """Parses a JSON dictionary into LogEntry."""
        timestamp = data.get("timestamp") or data.get("time") or data.get("datetime") or datetime.utcnow().isoformat()
        service = data.get("service") or data.get("app") or data.get("component") or default_service
        level_str = str(data.get("level") or data.get("severity") or data.get("log_level") or "INFO").upper()

        try:
            level = LogLevel(level_str)
        except ValueError:
            level = LogLevel.ERROR if "ERR" in level_str else LogLevel.INFO

        message = data.get("message") or data.get("msg") or str(data)
        stack_trace = data.get("stack_trace") or data.get("traceback") or data.get("exception")

        parsed_ts = cls._try_parse_timestamp(str(timestamp))

        return LogEntry(
            timestamp=str(timestamp),
            parsed_timestamp=parsed_ts,
            service=service,
            level=level,
            message=message,
            raw_log=raw_line,
            stack_trace=stack_trace,
            metadata={k: v for k, v in data.items() if k not in ("timestamp", "time", "service", "level", "message", "stack_trace")},
            is_anomaly=(level in (LogLevel.ERROR, LogLevel.CRITICAL, LogLevel.FATAL))
        )

    @classmethod
    def _parse_text_line(cls, line: str, default_service: str) -> LogEntry:
        """Parses plain text / syslog log format."""
        ts_match = None
        for pat in cls.TIMESTAMP_PATTERNS:
            match = re.search(pat, line)
            if match:
                ts_match = match.group(0)
                break

        timestamp = ts_match if ts_match else datetime.utcnow().isoformat()
        parsed_ts = cls._try_parse_timestamp(timestamp)

        lvl_match = re.search(cls.LOG_LEVEL_PATTERN, line, re.IGNORECASE)
        level_str = lvl_match.group(1).upper() if lvl_match else "INFO"
        
        try:
            level = LogLevel(level_str)
        except ValueError:
            level = LogLevel.ERROR if "ERR" in level_str else LogLevel.INFO

        # Try to infer service name in brackets or before level
        svc_match = re.search(r'\[([a-zA-Z0-9_-]+)\]', line)
        service = svc_match.group(1) if svc_match else default_service

        return LogEntry(
            timestamp=timestamp,
            parsed_timestamp=parsed_ts,
            service=service,
            level=level,
            message=line,
            raw_log=line,
            is_anomaly=(level in (LogLevel.ERROR, LogLevel.CRITICAL, LogLevel.FATAL))
        )

    @classmethod
    def _try_parse_timestamp(cls, ts_str: str) -> Optional[datetime]:
        """Tries parsing string timestamp into datetime object."""
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%b %d %H:%M:%S",
        ]
        clean_ts = ts_str.replace("Z", "").split("+")[0]
        for fmt in formats:
            try:
                return datetime.strptime(clean_ts, fmt)
            except ValueError:
                continue
        return None
