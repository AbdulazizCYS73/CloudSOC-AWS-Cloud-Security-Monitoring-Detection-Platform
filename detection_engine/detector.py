import json

from normalization.normalizer import (
    normalize_cloudtrail_event,
    normalize_vpc_flow_log
)


def detect_event(event, network_attempts=1):

    alerts = []

    # IAM Policy Change Detection
    if event["event_type"] == "IAM_POLICY_CHANGE":

        alerts.append({
            "alert": True,
            "detection_id": event["detection_id"],
            "event_type": event["event_type"],
            "severity": event["severity"],
            "mitre_attack": event["mitre_attack"],
            "reason": "IAM policy was modified."
        })

    # Network Reject Detection
    elif event["event_type"] == "NETWORK_REJECT":

        if network_attempts >= 20:

            alerts.append({
                "alert": True,
                "detection_id": event["detection_id"],
                "event_type": "NETWORK_SCANNING",
                "severity": "MEDIUM",
                "mitre_attack": "T1046",
                "source_ip": event["source_ip"],
                "target": event["resource"],
                "attempts": network_attempts,
                "reason": "High volume of rejected network connections."
            })

    return alerts


if __name__ == "__main__":

    cloudtrail_event = {
        "eventTime": "2026-09-12T08:30:00Z",
        "eventName": "AttachRolePolicy",
        "sourceIPAddress": "REDACTED",
        "userIdentity": {
            "arn": "arn:aws:iam::REDACTED:root"
        },
        "requestParameters": {
            "roleName": "CloudSOC-Test-Role"
        },
        "responseElements": {}
    }

    vpc_flow_log = (
        "2 REDACTED eni-123456 "
        "203.0.113.10 10.0.11.10 "
        "54321 22 6 1 60 "
        "1757665800 1757665860 REJECT OK"
    )

    cloudtrail_normalized = normalize_cloudtrail_event(
        cloudtrail_event
    )

    vpc_normalized = normalize_vpc_flow_log(
        vpc_flow_log
    )

    print("=== IAM Detection ===")

    iam_alerts = detect_event(
        cloudtrail_normalized
    )

    print(json.dumps(
        iam_alerts,
        indent=4
    ))

    print("\n=== Network Detection: 5 Attempts ===")

    low_network_alerts = detect_event(
        vpc_normalized,
        network_attempts=5
    )

    print(json.dumps(
        low_network_alerts,
        indent=4
    ))

    print("\n=== Network Detection: 50 Attempts ===")

    high_network_alerts = detect_event(
        vpc_normalized,
        network_attempts=50
    )

    print(json.dumps(
        high_network_alerts,
        indent=4
    ))