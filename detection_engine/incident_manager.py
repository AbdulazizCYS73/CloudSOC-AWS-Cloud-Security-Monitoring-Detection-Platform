import json
from datetime import datetime, timezone


def create_incident(correlation_result):

    if not correlation_result["incident"]:
        return None

    incident = {
        "incident_id": correlation_result["incident_id"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "OPEN",
        "severity": correlation_result["severity"],
        "event_type": correlation_result["event_type"],
        "detection_id": "DET-005",
        "mitre_attack": correlation_result["mitre_attack"],
        "source_ip": correlation_result["source_ip"],
        "target": correlation_result["target"],
        "evidence": {
            "rejected_attempts": correlation_result["rejected_attempts"],
            "unique_destination_ports": correlation_result[
                "unique_destination_ports"
            ],
            "protocol": correlation_result["protocol"]
        },
        "recommended_action": [
            "Review source IP activity",
            "Verify affected security controls",
            "Block malicious source if confirmed",
            "Review CloudTrail for related activity"
        ]
    }

    return incident


if __name__ == "__main__":

    correlation_result = {
        "incident": True,
        "incident_id": "INC-001",
        "event_type": "PORT_SCANNING",
        "severity": "MEDIUM",
        "mitre_attack": "T1046",
        "source_ip": "203.0.113.10",
        "target": "10.0.11.10",
        "rejected_attempts": 50,
        "unique_destination_ports": 45,
        "protocol": "TCP"
    }

    incident = create_incident(correlation_result)

    print("=== Incident Created ===")

    print(json.dumps(
        incident,
        indent=4
    ))

    print("\n=== False Positive Incident Test ===")

    false_positive_result = {
        "incident": False,
        "incident_id": "INC-001",
        "event_type": "PORT_SCANNING",
        "severity": "MEDIUM",
        "mitre_attack": "T1046",
        "source_ip": "203.0.113.10",
        "target": "10.0.11.10",
        "rejected_attempts": 50,
        "unique_destination_ports": 3,
        "protocol": "TCP"
    }

    false_positive_incident = create_incident(
        false_positive_result
    )

    print(json.dumps(
        false_positive_incident,
        indent=4
    ))    