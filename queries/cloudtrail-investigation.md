# CloudTrail Investigation Queries

These queries are used with Amazon CloudWatch Logs Insights to investigate AWS API activity recorded by CloudTrail.

---

## 1. Recent CloudTrail Events

This query displays recent CloudTrail events for general investigation.

```text
fields @timestamp,
       eventName,
       eventSource,
       userIdentity.type,
       userIdentity.arn
| sort @timestamp desc
| limit 50
```

### Purpose

Provides an overview of recent AWS API activity and helps identify events that require further investigation.

---

## 2. IAM Activity

This query identifies IAM-related events.

```text
fields @timestamp,
       eventName,
       eventSource,
       userIdentity.type,
       userIdentity.arn
| filter eventSource = "iam.amazonaws.com"
| sort @timestamp desc
| limit 50
```

### Purpose

Helps investigate IAM activity such as role, user, and policy operations.

---

## 3. IAM Policy Changes

This query focuses on policy attachment and inline policy modification events.

```text
fields @timestamp,
       eventName,
       userIdentity.type,
       userIdentity.arn,
       requestParameters.roleName,
       requestParameters.policyArn
| filter eventSource = "iam.amazonaws.com"
| filter eventName in [
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy"
]
| sort @timestamp desc
| limit 50
```

### Purpose

Helps identify potentially unauthorized IAM permission changes and supports investigation of `DET-003`.

---

## 4. Root Account Sensitive Activity

This query identifies sensitive operations performed by the AWS Root account.

```text
fields @timestamp,
       eventName,
       eventSource,
       userIdentity.type,
       userIdentity.arn
| filter userIdentity.type = "Root"
| filter eventName in [
    "CreateUser",
    "CreateRole",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreateAccessKey",
    "DeleteTrail",
    "StopLogging"
]
| sort @timestamp desc
| limit 50
```

### Purpose

Helps investigate sensitive Root account activity and supports `DET-004`.

---

## 5. Security Group Ingress Changes

This query identifies Security Group ingress authorization changes.

```text
fields @timestamp,
       eventName,
       eventSource,
       userIdentity.type,
       userIdentity.arn,
       requestParameters
| filter eventName = "AuthorizeSecurityGroupIngress"
| sort @timestamp desc
| limit 50
```

### Purpose

Helps investigate changes that add inbound access to Security Groups and supports `DET-001`.

---

## 6. SSH Open to the World

This query identifies Security Group changes that allow TCP port 22 from any IPv4 address.

```text
fields @timestamp,
       eventName,
       userIdentity.type,
       userIdentity.arn,
       requestParameters.ipPermissions
| filter eventName = "AuthorizeSecurityGroupIngress"
| filter requestParameters.ipPermissions.items[0].fromPort = 22
| filter requestParameters.ipPermissions.items[0].toPort = 22
| filter requestParameters.ipPermissions.items[0].ipRanges.items[0].cidrIp = "0.0.0.0/0"
| sort @timestamp desc
| limit 50
```

### Purpose

Helps investigate potentially exposed SSH access and supports `DET-002`.

---

## Investigation Notes

These queries were used during the CloudSOC security monitoring and investigation workflow.

CloudTrail records AWS API activity, including the identity that performed an operation, the event name, the event time, the source IP address, and request parameters.

Sensitive values such as AWS account identifiers, public IP addresses, ARNs, and email addresses should be redacted before publishing investigation evidence to a public repository.