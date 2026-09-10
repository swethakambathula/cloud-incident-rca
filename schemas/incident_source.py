"""Incident source tracking: MANUAL vs SIMULATION vs LOG_UPLOAD etc.

Simulations must never contaminate real incidents. All branching logic
(UI + API) keys off this persisted field.
"""
from enum import Enum


class IncidentSource(str, Enum):
    MANUAL = "MANUAL"
    SIMULATION = "SIMULATION"
    LOG_UPLOAD = "LOG_UPLOAD"
    MONITORING = "MONITORING"
    WEBHOOK = "WEBHOOK"
    API = "API"


SIMULATION_SOURCES = {IncidentSource.SIMULATION.value}
REAL_SOURCES = {
    IncidentSource.MANUAL.value,
    IncidentSource.LOG_UPLOAD.value,
    IncidentSource.MONITORING.value,
    IncidentSource.WEBHOOK.value,
    IncidentSource.API.value,
}


def normalize_source(value: str = "") -> str:
    v = (value or "").strip().upper()
    try:
        return IncidentSource(v).value
    except ValueError:
        return IncidentSource.MANUAL.value


def is_simulation(source: str = "") -> bool:
    return (source or "").strip().upper() == IncidentSource.SIMULATION.value
