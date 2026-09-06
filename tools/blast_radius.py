"""
Blast Radius Detection Tool.
Evaluates the architectural impact and blast radius of an incident based on
affected endpoints, services, dependencies, revisions, and regional scope.
"""
from typing import List, Dict, Any, Optional


def detect_blast_radius(
    service_name: str,
    revision_name: Optional[str],
    region: Optional[str],
    affected_endpoints: List[str],
    dependencies_affected: List[str],
    total_endpoints_count: int = 5,
    is_multi_region: bool = False
) -> Dict[str, Any]:
    """
    Computes structured blast radius assessment:
      - affected_services
      - affected_endpoints
      - dependencies_affected
      - affected_revision
      - scope: "endpoint-isolated", "service-wide", or "multi-service-cascade"
      - regional_scope: "regional" or "multi-region"
      - summary_text
    """
    affected_services = [service_name]
    for dep in dependencies_affected:
        if dep not in affected_services:
            affected_services.append(dep)

    # Determine scope
    if len(dependencies_affected) > 0 or len(affected_services) > 1:
        scope = "multi-service-cascade"
    elif len(affected_endpoints) >= (total_endpoints_count // 2 + 1) or "/health" in affected_endpoints:
        scope = "service-wide"
    else:
        scope = "endpoint-isolated"

    regional_scope = "multi-region" if is_multi_region else f"regional ({region or 'us-central1'})"

    endpoints_str = ", ".join(affected_endpoints) if affected_endpoints else "all endpoints"
    summary = f"Scope: {scope} affecting {service_name} on {endpoints_str}. Region: {regional_scope}."
    if revision_name:
        summary += f" Active revision: {revision_name}."

    return {
        "affected_services": affected_services,
        "affected_endpoints": affected_endpoints,
        "dependencies_affected": dependencies_affected,
        "affected_revision": revision_name,
        "scope": scope,
        "regional_scope": regional_scope,
        "summary": summary
    }
