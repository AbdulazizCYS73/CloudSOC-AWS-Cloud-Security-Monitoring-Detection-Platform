# Detection 04 — Root Sensitive Activity

## Overview

Detects sensitive activities performed by the AWS Root account.

The Root account has extensive privileges within an AWS environment, so its use for sensitive operations should be closely monitored.

This detection monitors CloudTrail events where the `userIdentity.type` is `Root` and the performed operation matches a predefined list of security-sensitive activities.

## Objective

Identify sensitive AWS operations performed by the Root account.

The detection focuses on the following events:

- `CreateUser`
- `CreateRole`
- `AttachUserPolicy`
- `AttachRolePolicy`
- `PutUserPolicy`
- `PutRolePolicy`
- `CreateAccessKey`
- `DeleteTrail`
- `StopLogging`

## Detection Logic

The detection monitors AWS CloudTrail events and identifies sensitive operations performed by the Root account.

The CloudWatch Logs metric filter used for this detection is:

```text
{ ($.userIdentity.type = "Root") && (($.eventName = "CreateUser") || ($.eventName = "CreateRole") || ($.eventName = "AttachUserPolicy") || ($.eventName = "AttachRolePolicy") || ($.eventName = "PutUserPolicy") || ($.eventName = "PutRolePolicy") || ($.eventName = "CreateAccessKey") || ($.eventName = "DeleteTrail") || ($.eventName = "StopLogging")) }
```

## Alert Configuration

| Setting | Value |
|---|---|
| Alarm Name | `CloudSOC-Root-Sensitive-Activity-Alarm` |
| Namespace | `CloudSOC/IAM` |
| Metric | `RootSensitiveActivity` |
| Statistic | Sum |
| Period | 5 minutes |
| Threshold | `>= 1` |
| Notification | Amazon SNS |
| Current State | OK |

## Investigation Query

The following CloudWatch Logs Insights query can be used to investigate sensitive activities performed by the Root account:

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

## Testing & Validation

The detection logic was validated using existing CloudTrail events generated during the AWS environment setup and configuration.

The investigation confirmed that sensitive operations performed by the Root account were successfully recorded in CloudTrail and matched the configured detection criteria.

The observed events included IAM-related operations such as `CreateRole` and `AttachRolePolicy`.

These activities were reviewed and determined to be expected administrative actions related to the CloudSOC environment setup.

The Root account detection was therefore validated without intentionally performing additional sensitive Root operations.

This validated the detection pipeline:

```text
Root Account Activity
        ↓
CloudTrail
        ↓
CloudWatch Logs
        ↓
Metric Filter
        ↓
RootSensitiveActivity Metric
        ↓
CloudWatch Alarm
        ↓
SNS Notification
```

## Security Relevance

The AWS Root account has extensive privileges across the AWS environment.

Sensitive Root activities can therefore represent a high-impact security event if they are unauthorized or unexpected.

Monitoring these activities helps detect potential privilege abuse, unauthorized account changes, or attempts to weaken security controls such as CloudTrail.

Root activity should be investigated based on the operation performed, the time of the event, and the expected administrative context.

## Evidence

The following screenshot demonstrates the CloudWatch alarm configured to detect sensitive activities performed by the AWS Root account.

![Root Sensitive Activity Alert](../screenshots/01-security-dashboard.png)