import json
import gzip
import base64
import os
import boto3
from datetime import datetime, timezone


# ============================================================
# SNS CONFIGURATION
# ============================================================

sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

# ============================================================
# VPC FLOW LOGS NORMALIZATION
# ============================================================

def normalize_vpc_flow_log(message):

    fields = message.split()

    if "NODATA" in fields or "SKIPDATA" in fields:
        return None

    if len(fields) < 14:
        return None

    (
        version,
        account_id,
        interface_id,
        srcaddr,
        dstaddr,
        srcport,
        dstport,
        protocol,
        packets,
        bytes_count,
        start,
        end,
        action,
        log_status
    ) = fields[:14]

    try:
        timestamp = datetime.fromtimestamp(
            int(start),
            timezone.utc
        ).isoformat()
    except (ValueError, TypeError):
        timestamp = None

    return {
        "timestamp": timestamp,
        "source": "VPC Flow Logs",
        "event_type": (
            "NETWORK_REJECT"
            if action == "REJECT"
            else "NETWORK_TRAFFIC"
        ),
        "severity": (
            "MEDIUM"
            if action == "REJECT"
            else "LOW"
        ),
        "detection_id": (
            "DET-005"
            if action == "REJECT"
            else None
        ),
        "mitre_attack": (
            "T1046"
            if action == "REJECT"
            else None
        ),
        "actor": None,
        "source_ip": srcaddr,
        "source_port": (
            int(srcport)
            if srcport != "-"
            else None
        ),
        "destination_port": (
            int(dstport)
            if dstport != "-"
            else None
        ),
        "protocol": (
            int(protocol)
            if protocol != "-"
            else None
        ),
        "action": action,
        "resource": dstaddr,
        "status": (
            "Blocked"
            if action == "REJECT"
            else "Allowed"
        ),
        "raw_event": message
    }

# ============================================================
# CLOUDTRAIL NORMALIZATION
# ============================================================

def normalize_cloudtrail_event(message):

    try:
        event = json.loads(message)
    except (json.JSONDecodeError, TypeError):
        return None

    event_name = event.get("eventName")
    event_source = event.get("eventSource")

    if not event_name or not event_source:
        return None

    user_identity = event.get(
        "userIdentity",
        {}
    )

    identity_type = user_identity.get("type")
    actor = user_identity.get("arn")

    source_ip = event.get("sourceIPAddress")
    event_time = event.get("eventTime")

    request_parameters = event.get(
        "requestParameters",
        {}
    )

    # ========================================================
    # ROOT SENSITIVE ACTIVITY
    # ========================================================

    root_sensitive_events = {
        "CreateUser",
        "CreateRole",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "CreateAccessKey",
        "DeleteTrail",
        "StopLogging"
    }

    if (
        identity_type == "Root"
        and event_name in root_sensitive_events
    ):

        return {
            "timestamp": event_time,
            "source": "CloudTrail",
            "event_type": "ROOT_SENSITIVE_ACTIVITY",
            "severity": "HIGH",
            "detection_id": "DET-004",
            "mitre_attack": "T1078.004",
            "actor": actor,
            "source_ip": source_ip,
            "source_port": None,
            "destination_port": None,
            "protocol": None,
            "action": event_name,
            "resource": "AWS Account",
            "status": (
                "Failed"
                if event.get("errorCode")
                else "Success"
            ),
            "raw_event": event
        }

    # ========================================================
    # IAM POLICY CHANGE
    # ========================================================

    iam_policy_events = {
        "AttachUserPolicy",
        "AttachRolePolicy",
        "PutUserPolicy",
        "PutRolePolicy"
    }

    if event_name in iam_policy_events:

        role_name = request_parameters.get(
            "roleName"
        )

        policy_arn = request_parameters.get(
            "policyArn"
        )

        resource = (
            role_name
            or policy_arn
            or "IAM resource"
        )

        return {
            "timestamp": event_time,
            "source": "CloudTrail",
            "event_type": "IAM_POLICY_CHANGE",
            "severity": "HIGH",
            "detection_id": "DET-003",
            "mitre_attack": "T1098",
            "actor": actor,
            "source_ip": source_ip,
            "source_port": None,
            "destination_port": None,
            "protocol": None,
            "action": event_name,
            "resource": resource,
            "status": (
                "Failed"
                if event.get("errorCode")
                else "Success"
            ),
            "raw_event": event
        }

    return None    

# ============================================================
# DETECTION ENGINE
# ============================================================

def detect_event(normalized_event):

    if normalized_event is None:
        return None

    # ========================================================
    # DET-005 NETWORK REJECT
    # ========================================================

    if normalized_event["event_type"] == "NETWORK_REJECT":

        return {
            "alert": True,
            "detection_id": "DET-005",
            "event_type": "NETWORK_REJECT",
            "severity": "MEDIUM",
            "mitre_attack": "T1046",
            "source_ip": normalized_event["source_ip"],
            "target": normalized_event["resource"],
            "destination_port": normalized_event[
                "destination_port"
            ],
            "reason": (
                "Network traffic was rejected."
            )
        }

    # ========================================================
    # DET-003 IAM POLICY CHANGE
    # ========================================================

    if normalized_event["event_type"] == "IAM_POLICY_CHANGE":

        return {
            "alert": True,
            "detection_id": "DET-003",
            "event_type": "IAM_POLICY_CHANGE",
            "severity": "HIGH",
            "mitre_attack": "T1098",
            "actor": normalized_event["actor"],
            "source_ip": normalized_event["source_ip"],
            "action": normalized_event["action"],
            "resource": normalized_event["resource"],
            "reason": (
                "An IAM policy was attached "
                "or modified."
            )
        }

    # ========================================================
    # DET-004 ROOT SENSITIVE ACTIVITY
    # ========================================================

    if (
        normalized_event["event_type"]
        == "ROOT_SENSITIVE_ACTIVITY"
    ):

        return {
            "alert": True,
            "detection_id": "DET-004",
            "event_type": "ROOT_SENSITIVE_ACTIVITY",
            "severity": "HIGH",
            "mitre_attack": "T1078.004",
            "actor": normalized_event["actor"],
            "source_ip": normalized_event["source_ip"],
            "action": normalized_event["action"],
            "reason": (
                "The AWS Root account performed "
                "a sensitive security-related operation."
            )
        }

    return {
        "alert": False,
        "reason": (
            "No security detection triggered."
        )
    }    

# ============================================================
# CORRELATION ENGINE
# ============================================================

def correlate_events(normalized_events):

    rejected_events = [
        event
        for event in normalized_events
        if event["event_type"] == "NETWORK_REJECT"
    ]

    if not rejected_events:
        return None

    groups = {}

    for event in rejected_events:

        key = (
            event["source_ip"],
            event["resource"],
            event["protocol"]
        )

        groups.setdefault(
            key,
            []
        ).append(event)

    for key, events in groups.items():

        source_ip, target, protocol = key

        unique_ports = {
            event["destination_port"]
            for event in events
            if event["destination_port"] is not None
        }

        attempts = len(events)

        if (
            attempts >= 20
            and len(unique_ports) >= 20
            and protocol == 6
        ):

            return {
                "incident": True,
                "incident_id": "INC-001",
                "event_type": "PORT_SCANNING",
                "severity": "MEDIUM",
                "mitre_attack": "T1046",
                "source_ip": source_ip,
                "target": target,
                "rejected_attempts": attempts,
                "unique_destination_ports": len(
                    unique_ports
                ),
                "protocol": "TCP",
                "reason": (
                    "High-volume rejected TCP connections "
                    "across multiple destination ports."
                )
            }

    return None

# ============================================================
# INCIDENT MANAGER
# ============================================================

def create_incident(correlation_result):

    if not correlation_result:
        return None

    incident = {
        "incident_id": correlation_result[
            "incident_id"
        ],
        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "status": "OPEN",
        "severity": correlation_result[
            "severity"
        ],
        "event_type": correlation_result[
            "event_type"
        ],
        "detection_id": "DET-005",
        "mitre_attack": correlation_result[
            "mitre_attack"
        ],
        "source_ip": correlation_result[
            "source_ip"
        ],
        "target": correlation_result[
            "target"
        ],
        "evidence": {
            "rejected_attempts": correlation_result[
                "rejected_attempts"
            ],
            "unique_destination_ports": correlation_result[
                "unique_destination_ports"
            ],
            "protocol": correlation_result[
                "protocol"
            ]
        },
        "recommended_actions": [
            "Review source IP activity",
            "Verify affected security controls",
            "Block malicious source if confirmed",
            "Review CloudTrail for related activity"
        ]
    }

    return incident       

# ============================================================
# SNS ALERT
# ============================================================

def send_sns_alert(incident):

    if not incident:
        return False

    message = {
        "alert": "CloudSOC Security Incident",
        "incident_id": incident["incident_id"],
        "severity": incident["severity"],
        "event_type": incident["event_type"],
        "detection_id": incident["detection_id"],
        "mitre_attack": incident["mitre_attack"],
        "source_ip": incident["source_ip"],
        "target": incident["target"],
        "evidence": incident["evidence"],
        "recommended_actions": incident[
            "recommended_actions"
        ]
    }

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=(
            f"CloudSOC Alert - "
            f"{incident['incident_id']}"
        ),
        Message=json.dumps(
            message,
            indent=4
        )
    )

    return True     

# ============================================================
# LAMBDA HANDLER
# ============================================================

def lambda_handler(event, context):

    print("=== CloudSOC Log Processor ===")

    # --------------------------------------------------------
    # Decode CloudWatch Logs payload
    # --------------------------------------------------------

    compressed_data = base64.b64decode(
        event["awslogs"]["data"]
    )

    decompressed_data = gzip.decompress(
        compressed_data
    )

    log_data = json.loads(
        decompressed_data
    )

    normalized_events = []
    detection_results = []

    # --------------------------------------------------------
    # Process log events
    # --------------------------------------------------------

    for log_event in log_data.get(
        "logEvents",
        []
    ):

        message = log_event.get(
            "message",
            ""
        )

        # Try VPC Flow Logs
        normalized_event = normalize_vpc_flow_log(
            message
        )

        # Try CloudTrail if not VPC Flow Logs
        if normalized_event is None:

            normalized_event = normalize_cloudtrail_event(
                message
            )

        # ----------------------------------------------------
        # Add normalized event
        # ----------------------------------------------------

        if normalized_event is not None:

            normalized_events.append(
                normalized_event
            )

            detection_result = detect_event(
                normalized_event
            )

            if detection_result is not None:

                detection_results.append(
                    detection_result
                )

    # --------------------------------------------------------
    # Correlation
    # --------------------------------------------------------

    correlation_result = correlate_events(
        normalized_events
    )

    # --------------------------------------------------------
    # Incident Manager
    # --------------------------------------------------------

    incident = create_incident(
        correlation_result
    )

    # --------------------------------------------------------
    # SNS Alert
    # --------------------------------------------------------

    sns_alert_sent = send_sns_alert(
        incident
    )

    # --------------------------------------------------------
    # Output
    # --------------------------------------------------------

    print("=== Normalized Events ===")

    print(
        json.dumps(
            normalized_events,
            indent=4
        )
    )

    print("=== Detection Results ===")

    print(
        json.dumps(
            detection_results,
            indent=4
        )
    )

    print("=== Correlation Result ===")

    print(
        json.dumps(
            correlation_result,
            indent=4
        )
    )

    print("=== Incident Manager ===")

    print(
        json.dumps(
            incident,
            indent=4
        )
    )

    print("=== SNS Alert ===")

    print(
        json.dumps(
            {
                "sent": sns_alert_sent
            },
            indent=4
        )
    )

    return {
        "statusCode": 200,
        "body": json.dumps({
            "processed_events": len(
                normalized_events
            ),
            "detections": len(
                detection_results
            ),
            "incident_created": (
                incident is not None
            ),
            "sns_alert_sent": sns_alert_sent
        })
    }    