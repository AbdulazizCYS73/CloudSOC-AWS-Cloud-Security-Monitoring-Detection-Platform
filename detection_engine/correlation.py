import json


def correlate_network_activity(
    source_ip,
    target_ip,
    rejected_attempts,
    unique_ports,
    protocol
):

    if (
        rejected_attempts >= 20
        and unique_ports >= 20
        and protocol == 6
    ):

        return {
            "incident": True,
            "incident_id": "INC-001",
            "event_type": "PORT_SCANNING",
            "severity": "MEDIUM",
            "mitre_attack": "T1046",
            "source_ip": source_ip,
            "target": target_ip,
            "rejected_attempts": rejected_attempts,
            "unique_destination_ports": unique_ports,
            "protocol": "TCP",
            "reason": "High-volume rejected TCP connections across multiple destination ports."
        }

    return {
        "incident": False,
        "reason": "Network activity did not meet correlation thresholds."
    }


if __name__ == "__main__":

    result = correlate_network_activity(
        source_ip="203.0.113.10",
        target_ip="10.0.11.10",
        rejected_attempts=50,
        unique_ports=45,
        protocol=6
    )

    print("=== Correlation Result ===")

    print(json.dumps(
        result,
        indent=4
    ))

    print("\n=== False Positive Test ===")

    false_positive_result = correlate_network_activity(
        source_ip="203.0.113.10",
        target_ip="10.0.11.10",
        rejected_attempts=50,
        unique_ports=3,
        protocol=6
    )

    print(json.dumps(
        false_positive_result,
        indent=4
    ))    