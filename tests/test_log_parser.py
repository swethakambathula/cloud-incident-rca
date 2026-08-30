"""
Unit tests for LogParser.
"""
import os
import pytest
from tools.log_parser import LogParser
from agents.rca_agent.schemas import LogLevel


def test_parse_json_log(tmp_path):
    log_file = tmp_path / "test_json.log"
    log_file.write_text(
        '{"timestamp": "2026-08-30T14:00:00Z", "service": "payment-api", "level": "ERROR", "message": "ConnectionPoolTimeout error"}\n'
    )

    entries = LogParser.parse_file(str(log_file))
    assert len(entries) == 1
    assert entries[0].service == "payment-api"
    assert entries[0].level == LogLevel.ERROR
    assert "ConnectionPoolTimeout" in entries[0].message


def test_parse_text_log(tmp_path):
    log_file = tmp_path / "test_text.log"
    log_file.write_text(
        '2026-08-30 14:00:00 [inventory-service] ERROR java.lang.OutOfMemoryError: Java heap space\n'
    )

    entries = LogParser.parse_file(str(log_file), default_service="inventory-service")
    assert len(entries) == 1
    assert entries[0].level == LogLevel.ERROR
    assert "OutOfMemoryError" in entries[0].message
