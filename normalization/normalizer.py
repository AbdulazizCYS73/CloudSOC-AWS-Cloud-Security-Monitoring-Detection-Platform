import json
from datetime import datetime, timezone

import os

def unix_to_iso(timestamp):
    """Convert Unix timestamp to ISO 8601 UTC."""
    return datetime.fromtimestamp(
        int(timestamp),
        tz=timezone.utc
    ).isoformat()


def normalize_cloudtrail_event(event):

    event_name = event.get("eventName")
    user_identity = event.get("userIdentity", {})
    is_root = user_identity.get("type") == "Root"
     
    if is_root and event_name in [
    "CreateUser",
    "CreateRole",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreateAccessKey",
    "DeleteTrail",
    "StopLogging"
    ]:
        event_type = "IAM_POLICY_CHANGE"
        severity = "HIGH"
        detection_id = "DET-003"
        mitre_attack = "T1098"

    elif event_name in [
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy"
    ]:
        
        event_type = "SENSITIVE_AWS_ACTIVITY"
        severity = "HIGH"
        detection_id = "DET-004"
        mitre_attack = "T1078.004"

    else:
        event_type = "AWS_ACTIVITY"
        severity = "LOW"
        detection_id = None
        mitre_attack = None

    normalized_event = {
        "timestamp": event.get("eventTime"),
        "source": "CloudTrail",
        "event_type": event_type,
        "severity": severity,
        "detection_id": detection_id,
        "mitre_attack": mitre_attack,
        "actor": event.get("userIdentity", {}).get("arn"),
        "source_ip": event.get("sourceIPAddress"),
        "action": event_name,
        "resource": event.get("requestParameters", {}).get("roleName"),
        "status": "Success" if event.get("responseElements") is not None else "Failed",
        "raw_event": event
    }

    return normalized_event


def normalize_vpc_flow_log(flow_log):

    parts = flow_log.split()

    action = parts[12]
    start_time = parts[10]

    if action == "REJECT":
        event_type = "NETWORK_REJECT"
        severity = "MEDIUM"
        detection_id = "DET-005"
        mitre_attack = "T1046"
        status = "Blocked"

    else:
        event_type = "NETWORK_TRAFFIC"
        severity = "LOW"
        detection_id = None
        mitre_attack = None
        status = "Allowed"

    normalized_event = {
        "timestamp": unix_to_iso(start_time),
        "source": "VPC Flow Logs",
        "event_type": event_type,
        "severity": severity,
        "detection_id": detection_id,
        "mitre_attack": mitre_attack,
        "actor": None,
        "source_ip": parts[3],
        "action": action,
        "resource": parts[4],
        "status": status,
        "raw_event": flow_log
    }

    return normalized_event


if __name__ == "__main__":

    base_dir = os.path.dirname(__file__)
    samples_dir = os.path.join(base_dir, "samples")

    cloudtrail_file = os.path.join(
        samples_dir,
        "cloudtrail_sample.json"
    )

    vpc_flow_file = os.path.join(
        samples_dir,
        "vpc_flow_sample.log"
    )

    with open(cloudtrail_file, "r") as file:
        cloudtrail_event = json.load(file)

    with open(vpc_flow_file, "r") as file:
        vpc_flow_log = file.read().strip()

    print("=== CloudTrail Event ===")

    print(json.dumps(
        normalize_cloudtrail_event(cloudtrail_event),
        indent=4
    ))

    print("\n=== VPC Flow Log Event ===")

    print(json.dumps(
        normalize_vpc_flow_log(vpc_flow_log),
        indent=4
    ))