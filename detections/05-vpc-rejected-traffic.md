# Detection 05 — VPC Rejected Traffic

## Overview

Detects rejected network traffic within the VPC using Amazon VPC Flow Logs.

A high volume of rejected connections may indicate network scanning, reconnaissance, probing, or unauthorized connection attempts against resources in the VPC.

This detection uses VPC Flow Logs, CloudWatch Logs, CloudWatch Metrics, and CloudWatch Alarms to identify abnormal levels of rejected traffic.

## Objective

Identify unusually high volumes of rejected network traffic within the VPC.

The detection is designed to provide an early indication of potential network scanning or unauthorized connection attempts before further investigation is performed.

## Detection Logic

The detection monitors VPC Flow Logs for records where the traffic action is `REJECT`.

The CloudWatch Logs metric filter used for this detection is:

```text
[version, accountid, interfaceid, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action="REJECT", logstatus]
```

## Alert Configuration

| Setting | Value |
|---|---|
| Alarm Name | `CloudSOC-VPC-Rejected-Traffic-Alarm` |
| Namespace | `CloudSOC/Network` |
| Metric | `RejectedTraffic` |
| Statistic | Sum |
| Period | 5 minutes |
| Threshold | `>= 20` |
| Notification | Amazon SNS |
| Current State | ALARM |

## Investigation Query

The following CloudWatch Logs Insights query can be used to investigate rejected network traffic and identify potential scanning activity:

```text
fields @timestamp, @message
| parse @message "* * * * * * * * * * * * * *" as version, account, interface, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action, logstatus
| filter action = "REJECT"
| stats count() as rejected_attempts by srcaddr
| sort rejected_attempts desc
| limit 10
```
### Target-Specific Investigation

The following query can be used to investigate rejected traffic from a specific source against a specific target:

```text
fields @timestamp, @message
| parse @message "* * * * * * * * * * * * * *" as version, account, interface, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action, logstatus
| filter action = "REJECT"
| filter srcaddr = "<SOURCE_IP>"
| filter dstaddr = "<TARGET_IP>"
| stats count() as attempts, count_distinct(dstport) as unique_ports
```


## Testing & Validation

The detection was validated using actual rejected network traffic observed in the VPC Flow Logs.

The CloudWatch Logs Insights investigation identified a high volume of rejected TCP connection attempts targeting the EC2 instance.

The analysis identified:

- 3,046 rejected connection attempts
- Approximately 2,903 unique destination ports
- TCP traffic (`protocol 6`)
- Activity observed over more than one day

The high number of connection attempts across a large number of destination ports was consistent with network scanning or reconnaissance activity.

The `CloudSOC-VPC-Rejected-Traffic-Alarm` successfully detected elevated rejected traffic and transitioned to the `ALARM` state.

An SNS notification was also successfully delivered to the configured security alert subscription.

This validated the complete detection pipeline:

```text
VPC Network Traffic
        ↓
VPC Flow Logs
        ↓
CloudWatch Logs
        ↓
Metric Filter
        ↓
RejectedTraffic Metric
        ↓
CloudWatch Alarm
        ↓
SNS Notification
        ↓
Security Investigation
```

## Security Relevance

A high volume of rejected network connections can indicate network scanning, reconnaissance, probing, or unauthorized connection attempts.

Monitoring rejected traffic provides visibility into network activity that is being blocked by the VPC security controls.

The detection helps security analysts identify abnormal traffic patterns and investigate potentially suspicious sources before determining whether the activity represents a confirmed security incident.

## Evidence

The following screenshot demonstrates the CloudWatch alarm detecting elevated rejected network traffic.

![VPC Rejected Traffic Alarm](../screenshots/03-rejected-traffic-alarm.png)

The investigation results were also used as supporting evidence for `INC-001 — Port Scanning`.