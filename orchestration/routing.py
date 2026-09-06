"""
Routing logic - decides which agents run based on symptoms / evidence.
Deterministic, no LLM needed.
"""
from schemas.evidence import IncidentEvidence

def select_agents(evidence: IncidentEvidence) -> list:
    """
    Returns list of agent names to invoke.
    Implements supervisor routing tests: not every agent always invoked.
    """
    agents = []
    # Log agent: if errors or symptoms mention logs
    if evidence.application_errors or evidence.request_errors or evidence.raw_evidence:
        agents.append("log_agent")
    else:
        # still run log if no errors? No, skip to test routing
        pass

    # Metrics: always include (critical for SRE) - ensures correlation baseline vs incident is always checked
    agents.append("metrics_agent")

    if evidence.recent_deployments:
        agents.append("deployment_agent")

    if evidence.traces or evidence.dependencies:
        agents.append("trace_agent")

    # Knowledge always? But routing test says not every agent always invoked - so conditionally
    # Invoke knowledge if any error code known
    known_codes = {"DATABASE_CONNECTION_TIMEOUT","DATABASE_CONNECTION_POOL_EXHAUSTED","NULL_POINTER_EXCEPTION","DOWNSTREAM_DEPENDENCY_FAILURE","CONFIGURATION_REGRESSION","REQUEST_QUEUE_FULL_THROTTLED"}
    codes = {e.get("error_code") for e in evidence.application_errors if isinstance(e, dict)}
    if codes & known_codes or evidence.symptoms:
        agents.append("knowledge_agent")

    return agents
