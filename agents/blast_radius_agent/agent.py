"""
Blast Radius Agent - estimates impact scope from evidence and findings.
Deterministic classification; no LLM hallucination.
Respects affected services inferred from dependencies + errors.
"""
from typing import List
from schemas.evidence import IncidentEvidence
from schemas.findings import AgentFinding
from schemas.report import BlastRadiusResult
from tools.blast_radius import detect_blast_radius


class BlastRadiusAgent:
    agent_name = "Blast Radius Agent"

    def analyze(self, evidence: IncidentEvidence, findings: List[AgentFinding] = None) -> BlastRadiusResult:
        # Gather affected endpoints from evidence + findings
        req_errors = evidence.request_errors or []
        endpoints = set()
        for r in req_errors:
            ep = r.get("endpoint")
            if ep:
                endpoints.add(ep)
        # also from blast_radius preset
        preset = evidence.blast_radius or {}
        for ep in preset.get("affected_endpoints", []):
            endpoints.add(ep)
        for ep in preset.get("affected_endpoints", []):
            endpoints.add(ep)

        # Gather dependencies that are affected
        deps_affected = [d.get("name") for d in evidence.dependencies if d.get("status") in ("UNAVAILABLE","UNREACHABLE","ERROR")]
        # Also if trace shows dependency failure, include
        if findings:
            for f in findings:
                if "downstream" in f.summary.lower() or "dependency" in f.summary.lower():
                    if f.affected_service and f.affected_service not in deps_affected and f.affected_service != evidence.service_name:
                        deps_affected.append(f.affected_service)

        # Use deterministic tool
        blast_dict = detect_blast_radius(
            service_name=evidence.service_name,
            revision_name=evidence.revision_name,
            region=evidence.region or "us-central1",
            affected_endpoints=list(endpoints),
            dependencies_affected=deps_affected,
        )
        # Classify to required schema values
        scope = blast_dict.get("scope", "service-wide")
        if scope == "multi-service-cascade":
            classification = "MULTI_SERVICE"
            estimated_scope = f"Multi-service cascade: {evidence.service_name} and {', '.join(deps_affected) if deps_affected else 'downstream dependencies'}"
        elif scope == "service-wide":
            classification = "SERVICE_LEVEL"
            estimated_scope = f"Service-wide impact on {evidence.service_name}"
        elif scope == "endpoint-isolated":
            # Distinguish LOCALIZED vs SERVICE_LEVEL: localized if single endpoint
            if len(endpoints) <= 1:
                classification = "LOCALIZED"
                estimated_scope = f"Localized to endpoint {list(endpoints)[0] if endpoints else '/unknown'} on {evidence.service_name}"
            else:
                classification = "SERVICE_LEVEL"
                estimated_scope = f"Service-level impact on subset of endpoints {', '.join(endpoints)}"
        else:
            classification = "SERVICE_LEVEL"
            estimated_scope = blast_dict.get("summary", f"Impact on {evidence.service_name}")

        # Regional check
        region = evidence.region or "us-central1"
        if blast_dict.get("regional_scope") == "multi-region":
            classification = "REGIONAL" if classification != "MULTI_SERVICE" else classification

        # Build dependency impact
        dep_impact = []
        for d in deps_affected:
            dep_impact.append(f"{d} downstream impact via {evidence.service_name}")
        if not dep_impact and blast_dict.get("affected_services") and len(blast_dict["affected_services"])>1:
            dep_impact = [f"Propagation to {s}" for s in blast_dict["affected_services"] if s != evidence.service_name]

        # Evidence citation
        ev = []
        if req_errors:
            ev.append(f"{len(req_errors)} request error records across {len(endpoints)} endpoints")
        if deps_affected:
            ev.append(f"Dependencies affected: {', '.join(deps_affected)}")
        ev.append(f"Revision {evidence.revision_name or 'active'} in region {region}")
        if findings:
            # cite trace findings
            for f in findings:
                if f.finding_type.value in ("DEPENDENCY_BOTTLENECK", "ERROR_PATTERN"):
                    ev.append(f.summary[:120])
                    if len(ev) >= 4:
                        break

        return BlastRadiusResult(
            primary_service=evidence.service_name,
            affected_services=blast_dict.get("affected_services", [evidence.service_name]),
            affected_endpoints=list(endpoints) or ["/unknown"],
            region=region,
            affected_revision=evidence.revision_name,
            dependency_impact=dep_impact,
            estimated_scope=estimated_scope,
            classification=classification,
            evidence=ev[:6],
        )
