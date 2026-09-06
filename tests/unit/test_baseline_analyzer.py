"""
Unit tests for baseline_analyzer comparison functions.
"""
from tools.baseline_analyzer import (
    compare_error_rate,
    compare_latency,
    compare_request_volume,
    compare_cpu,
    compare_memory,
)


def test_compare_error_rate():
    # Normal
    res = compare_error_rate(0.1, 0.2)
    assert res["severity"] == "NORMAL"
    assert res["percentage_change"] == 100.0

    # Warning
    res = compare_error_rate(0.5, 3.5)
    assert res["severity"] == "WARNING"

    # Critical
    res = compare_error_rate(1.0, 18.5)
    assert res["severity"] == "CRITICAL"
    assert res["incident"] == 18.5


def test_compare_latency():
    # Normal
    res = compare_latency(150.0, 180.0)
    assert res["severity"] == "NORMAL"

    # Warning
    res = compare_latency(200.0, 1200.0)
    assert res["severity"] == "WARNING"

    # Critical
    res = compare_latency(400.0, 3200.0)
    assert res["severity"] == "CRITICAL"


def test_compare_request_volume():
    # Normal
    res = compare_request_volume(1000.0, 1100.0)
    assert res["severity"] == "NORMAL"

    # Warning spike
    res = compare_request_volume(1000.0, 1600.0)
    assert res["severity"] == "WARNING"

    # Critical surge
    res = compare_request_volume(1000.0, 3500.0)
    assert res["severity"] == "CRITICAL"


def test_compare_cpu_and_memory():
    cpu_normal = compare_cpu(25.0, 28.0)
    assert cpu_normal["severity"] == "NORMAL"

    cpu_critical = compare_cpu(30.0, 92.0)
    assert cpu_critical["severity"] == "CRITICAL"

    mem_normal = compare_memory(40.0, 45.0)
    assert mem_normal["severity"] == "NORMAL"

    mem_critical = compare_memory(50.0, 95.0)
    assert mem_critical["severity"] == "CRITICAL"
