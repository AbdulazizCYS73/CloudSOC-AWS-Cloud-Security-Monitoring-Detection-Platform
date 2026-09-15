# CloudSOC — AWS Cloud Security Monitoring & Detection Platform

CloudSOC is a hands-on AWS Cloud Security and SOC monitoring project designed to demonstrate practical capabilities in cloud security monitoring, detection engineering, incident response, and secure AWS architecture.

The project combines AWS-native security and monitoring services with a lightweight Python-based detection and correlation engine.

---

## 🎯 Project Objectives

The main objectives of CloudSOC are:

- Build a secure and segmented AWS cloud architecture.
- Collect and analyze AWS security and network telemetry.
- Develop practical security detections.
- Normalize security events into a unified schema.
- Correlate multiple network events to identify suspicious activity.
- Create structured security incidents.
- Generate automated security alerts.
- Apply MITRE ATT&CK techniques to detected activity.
- Demonstrate AWS Solutions Architect concepts through a security-focused implementation.

---

# 🏗️ Architecture

The project uses a multi-layer AWS architecture consisting of network, application, monitoring, detection, and response components.

```text
                         Internet
                            │
                            ▼
                    ┌───────────────┐
                    │     ALB       │
                    │ CloudSOC-ALB  │
                    └───────┬───────┘
                            │
                 ┌──────────┴──────────┐
                 ▼                     ▼
          Private Subnet A       Private Subnet B
                 │                     │
                 ▼                     ▼
        ┌────────────────┐    ┌────────────────┐
        │ App Server A   │    │ App Server B   │
        │   EC2          │    │   EC2          │
        └────────────────┘    └────────────────┘

                 AWS Security Telemetry
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
      CloudTrail    VPC Flow Logs   CloudWatch
          │              │              │
          └──────────────┴──────────────┘
                         │
                         ▼
                 CloudWatch Logs
                         │
                         ▼
              CloudSOC Log Processor
                     (Lambda)
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
       Normalization           Detection
                                    │
                              ┌─────┴─────┐
                              ▼           ▼
                         Correlation   Alerts
                              │           │
                              ▼           ▼
                         Incident       SNS
                         Manager         │
                                        ▼
                                     Email
```

---

# ☁️ AWS Infrastructure

## Network Architecture

The environment is deployed in the AWS Stockholm Region (`eu-north-1`).

### VPC

- VPC: `CloudSOC-VPC`
- CIDR: `10.0.0.0/16`

### Subnets

| Subnet | CIDR | Purpose |
|---|---|---|
| Public A | `10.0.1.0/24` | ALB |
| Public B | `10.0.2.0/24` | ALB |
| Private A | `10.0.11.0/24` | Application EC2 |
| Private B | `10.0.12.0/24` | Application EC2 |

The application servers are deployed in private subnets and are not directly exposed to the Internet.

Internet-facing traffic is handled by the Application Load Balancer.

---

# 🔐 Security Architecture

The project follows a layered security model:

1. Network segmentation
2. Security Groups
3. Private EC2 deployment
4. Application Load Balancer
5. Systems Manager Session Manager
6. CloudTrail auditing
7. VPC Flow Logs
8. CloudWatch monitoring
9. Security detections
10. Incident correlation
11. SNS alerting

### Key Security Controls

- No public SSH access to application servers.
- EC2 instances use private IP addresses.
- Administrative access is performed through AWS Systems Manager Session Manager.
- Application traffic is restricted using Security Group-to-Security Group rules.
- CloudTrail records AWS API activity.
- VPC Flow Logs provide network-level visibility.
- CloudWatch provides centralized log analysis and alerting.
- SNS provides security notifications.

---

# 🔎 Security Monitoring

CloudSOC collects two major categories of telemetry:

## 1. Identity and API Activity

Collected using:

- AWS CloudTrail
- CloudWatch Logs

Examples:

- IAM policy changes
- Root account sensitive activity
- Role creation
- Policy attachment

## 2. Network Activity

Collected using:

- VPC Flow Logs
- CloudWatch Logs

Examples:

- Rejected connections
- High-volume connection attempts
- Network reconnaissance
- Port scanning behavior

---

# 🧩 Detection Engineering

CloudSOC contains five security detections.

| Detection | Description | Severity | MITRE ATT&CK |
|---|---|---|---|
| DET-001 | Security Group Ingress Changes | Medium | T1562.007 |
| DET-002 | SSH Open to the World | High | T1133 |
| DET-003 | IAM Policy Changes | High | T1098 |
| DET-004 | Root Sensitive Activity | High | T1078.004 |
| DET-005 | VPC Rejected Traffic | Medium | T1046 |

Detailed detection logic is documented under:

```text
detections/
```

---

# ⚙️ Detection Engine

The project contains a lightweight Python-based detection engine.

```text
Raw Security Events
        │
        ▼
Normalization
        │
        ▼
Detection Engine
        │
        ▼
Correlation Engine
        │
        ▼
Custom Incident Manager
```

## Normalization

Different AWS log formats are converted into a common security event structure.

The normalized schema includes:

```text
timestamp
source
event_type
severity
detection_id
mitre_attack
actor
source_ip
action
resource
status
raw_event
```

This allows different log sources to be processed using a common detection workflow.

---

# 🔄 Correlation

The correlation engine identifies potential port scanning behavior by combining multiple network events.

The current correlation logic looks for:

```text
20+ rejected connections
+
20+ unique destination ports
+
TCP protocol
```

When these conditions are met, the engine creates:

```text
INC-001
PORT_SCANNING
MEDIUM
T1046
```

This demonstrates the difference between:

**Single Event Detection**

and

**Behavior-Based Correlation**

---

# 🚨 Incident Management

When correlation identifies suspicious activity, CloudSOC creates a structured incident containing:

- Incident ID
- Creation timestamp
- Status
- Severity
- Event type
- Detection ID
- MITRE ATT&CK technique
- Source IP
- Target
- Evidence
- Recommended actions

Example:

```text
Incident ID: INC-001
Status: OPEN
Severity: MEDIUM
Event Type: PORT_SCANNING
Detection: DET-005
MITRE ATT&CK: T1046
```

---

# 📧 Automated Alerting

CloudSOC integrates Amazon SNS with the Lambda processing pipeline.

The workflow is:

```text
Detection
    ↓
Correlation
    ↓
Custom Incident Manager
    ↓
Amazon SNS
    ↓
Security Email Alert
```

A successful validation generated an email containing:

```text
INC-001
PORT_SCANNING
MEDIUM
DET-005
T1046
Rejected Attempts
Unique Destination Ports
```

This demonstrates an end-to-end detection-to-notification workflow.

---

#  AWS Lambda Log Processor

The Lambda function:

```text
CloudSOC-Log-Processor
```

processes CloudWatch Logs events.

Its main responsibilities are:

1. Decode CloudWatch Logs payloads.
2. Decompress the payload.
3. Parse supported security events.
4. Normalize events.
5. Execute detections.
6. Perform network correlation.
7. Create incidents.
8. Publish security alerts through SNS.

### Data Flow

```text
CloudWatch Logs
       ↓
CloudSOC-Log-Processor
       ↓
Normalization
       ↓
Detection
       ↓
Correlation
       ↓
Custom Incident Manager
       ↓
SNS
```

---

# 🕵️ Incident Response Case

## INC-001 — Port Scanning

A network reconnaissance incident was identified using VPC Flow Logs.

### Findings

The investigation identified:

- Thousands of rejected TCP connection attempts.
- Thousands of unique destination ports.
- Activity targeting the same internal resource.
- Activity distributed across an extended time period.
- No evidence of successful compromise in the analyzed network telemetry.

### Detection

```text
DET-005 — VPC Rejected Traffic
```

### MITRE ATT&CK

```text
T1046 — Network Service Scanning
```

### Severity

```text
MEDIUM
```

### Containment

A Network ACL deny rule was applied to block the identified source address.

The containment action was subsequently verified through network telemetry.

Full incident documentation is available under:

```text
incident-response/INC-001-port-scanning.md
```

---

# 🧪 Testing & Validation

CloudSOC was validated using both AWS-native telemetry and controlled test events.

### Tested Components

- Security Group ingress detection
- SSH open-to-world detection
- IAM policy change detection
- Root sensitive activity detection
- VPC rejected traffic detection
- Lambda log processing
- Event normalization
- Detection engine
- Correlation engine
- Incident creation
- SNS notification

### End-to-End Validation

The VPC security pipeline successfully produced:

```text
99 rejected attempts
99 unique destination ports
TCP
        ↓
DET-005
        ↓
PORT_SCANNING
        ↓
INC-001
        ↓
SNS
        ↓
Email Alert
```

---

# 🛡️ MITRE ATT&CK Mapping

CloudSOC maps detected behaviors to MITRE ATT&CK techniques.

| Detection | Technique | Description |
|---|---|---|
| DET-001 | T1562.007 | Disable or Modify Cloud Firewall |
| DET-002 | T1133 | External Remote Services |
| DET-003 | T1098 | Account Manipulation |
| DET-004 | T1078.004 | Valid Accounts: Cloud Accounts |
| DET-005 | T1046 | Network Service Scanning |

MITRE mappings are used to provide security context to detections and incidents.

---

# 📊 CloudWatch Security Dashboard

The project includes a CloudWatch security dashboard containing monitoring widgets for:

- Security Group changes
- SSH exposure
- IAM policy changes
- Root sensitive activity
- VPC rejected traffic
- Security alarms

The dashboard provides a centralized view of security-related activity.

---

# 📁 Project Structure

```text
CloudSOC/

│
├── architecture/
│   ├── 01-secure-aws-architecture.md
│   ├── 02-network-architecture.md
│   └── 03-application-architecture.md
│
├── detection_engine/
│   ├── detector.py
│   ├── correlation.py
│   └── incident_manager.py
│
├── detections/
│   ├── 01-security-group-ingress.md
│   ├── 02-ssh-open-to-world.md
│   ├── 03-iam-policy-change.md
│   ├── 04-root-sensitive-activity.md
│   └── 05-vpc-rejected-traffic.md
│
├── normalization/
│   ├── normalizer.py
│   └── samples/
│
├── incident-response/
│   └── INC-001-port-scanning.md
│
├── lambda/
│   └── log_processor.py
│
├── queries/
│   ├── cloudtrail-investigation.md
│   ├── iam-investigation.md
│   └── vpc-flow-investigation.md
│
├── screenshots/
│
├── README.md
│
└── .gitignore
```

---

# 🧠 SAA-C03 Relevance

The project also provides hands-on implementation of AWS Solutions Architect concepts, including:

- VPC design
- CIDR planning
- Public and private subnets
- Multi-AZ architecture
- Internet Gateway
- Route Tables
- Application Load Balancer
- EC2
- Security Groups
- Network ACLs
- VPC Endpoints
- IAM
- High availability
- Fault isolation
- Secure administrative access

The security architecture was designed to demonstrate how these AWS architectural concepts can be applied in a security-focused environment.

---

# 🔒 Security Considerations

Sensitive AWS information must not be committed to the repository.

Before publishing the project:

- Remove AWS Account IDs.
- Remove real public IP addresses.
- Remove internal IP addresses when appropriate.
- Remove ARNs containing account information.
- Remove email addresses.
- Never commit credentials or access keys.
- Never commit `.env` files.

The repository uses `.gitignore` to prevent temporary Python files and environment files from being committed.

---

# ⚠️ Known Limitations

The current Lambda correlation engine evaluates network events within the current CloudWatch Logs batch.

It does not maintain persistent correlation state across multiple Lambda invocations.

A production implementation could use persistent state or a dedicated security analytics platform to correlate events across longer time windows.

CloudTrail processing is also currently more limited than the VPC Flow Logs pipeline and requires further refinement for complete automated CloudTrail event normalization.

These limitations are documented intentionally rather than presenting the prototype as a production SOC platform.

---

# 🚀 Future Improvements

Potential future improvements include:

- Persistent correlation state.
- Improved CloudTrail normalization.
- Automated response actions.
- Integration with a dedicated case-management platform.
- Additional security detections.
- HTTPS with ACM.
- Infrastructure as Code using Terraform or AWS CloudFormation.
- CI/CD security testing.
- Expanded MITRE ATT&CK coverage.
- Threat intelligence enrichment.

These improvements are intentionally separated from the current implementation to keep the project focused and reproducible.

---

# 🎓 Skills Demonstrated

This project demonstrates practical experience in:

### AWS / Cloud

- AWS VPC
- EC2
- ALB
- IAM
- CloudTrail
- CloudWatch
- VPC Flow Logs
- SNS
- Lambda
- Systems Manager

### Cybersecurity

- Cloud Security
- SOC Monitoring
- Detection Engineering
- Log Analysis
- Network Security
- IAM Security
- Incident Response
- Security Alerting
- MITRE ATT&CK

### Technical

- Python
- JSON
- CloudWatch Logs Insights
- AWS IAM Policies
- AWS Security Groups
- Network ACLs
- Event normalization
- Event correlation

---

# 📌 Project Status

**Status: Active Development / Portfolio Ready**

The core CloudSOC monitoring and detection pipeline has been implemented and validated in AWS.

The project currently focuses on demonstrating practical cloud security monitoring, detection engineering, incident investigation, and automated alerting rather than providing a full production SOC platform.

---

# 👤 Author

Cybersecurity Student -- Abdulaziz Alkhathami
 
Cloud Security / SOC / AWS Security
