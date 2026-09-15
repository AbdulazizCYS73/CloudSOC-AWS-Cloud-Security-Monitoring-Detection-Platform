# IAM Investigation Queries

These queries are used with Amazon CloudWatch Logs Insights to investigate IAM activity recorded by AWS CloudTrail.

---

## 1. Recent IAM Events

This query displays recent IAM-related activity.

```text
fields @timestamp,
       eventName,
       eventSource,
       userIdentity.type,
       userIdentity.arn
| filter eventSource = "iam.amazonaws.com"
| sort @timestamp desc
| limit 20
```

### Purpose

Provides an overview of IAM API activity and helps identify operations that require further investigation.

---

## 2. Sensitive IAM Policy Changes

This query identifies IAM policy attachment and inline policy modification events.

```text
fields @timestamp,
       eventName,
       userIdentity.type,
       userIdentity.arn
| filter eventSource = "iam.amazonaws.com"
| filter eventName in [
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "DetachUserPolicy",
    "DetachRolePolicy"
]
| sort @timestamp desc
| limit 50
```

### Purpose

Helps investigate changes to IAM permissions and identify potentially unauthorized policy modifications.

---

## 3. IAM Policy Change Details

This query provides additional details about IAM policy changes.

```text
fields @timestamp,
       eventName,
       userIdentity.type,
       userIdentity.arn,
       requestParameters.roleName,
       requestParameters.policyArn
| filter eventName = "AttachRolePolicy"
| sort @timestamp desc
| limit 20
```

### Purpose

Helps identify which role and policy were involved in an `AttachRolePolicy` operation.

---

## 4. Root Account Activity

This query identifies activity performed using the AWS Root account.

```text
fields @timestamp,
       eventName,
       eventSource,
       userIdentity.type,
       userIdentity.arn
| filter userIdentity.type = "Root"
| sort @timestamp desc
| limit 20
```

### Purpose

Provides visibility into Root account activity and supports further investigation of sensitive operations.

---

## Investigation Notes

IAM investigation should be correlated with CloudTrail event details, including the event name, identity, source IP address, request parameters, and event time.

Sensitive AWS account information should be redacted before publishing investigation evidence to a public repository.