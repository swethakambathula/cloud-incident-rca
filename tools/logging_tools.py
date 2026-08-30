from google.cloud import logging_v2


def get_error_logs(
    project_id: str,
    service_name: str,
    limit: int = 50,
):
    client = logging_v2.Client(project=project_id)

    log_filter = f'''
        resource.type="cloud_run_revision"
        AND resource.labels.service_name="{service_name}"
        AND severity>=ERROR
    '''

    entries = client.list_entries(
        filter_=log_filter,
        order_by=logging_v2.DESCENDING,
        max_results=limit,
    )

    results = []

    for entry in entries:

        # Try different payload types
        payload = getattr(entry, "payload", None)

        http_request = getattr(entry, "http_request", None)

        results.append({
            "timestamp": (
                entry.timestamp.isoformat()
                if entry.timestamp
                else None
            ),
            "severity": entry.severity,
            "log_name": entry.log_name,
            "payload": payload,
            "http_request": http_request,
            "labels": entry.labels,
            "resource": dict(entry.resource.labels),
        })

    return results