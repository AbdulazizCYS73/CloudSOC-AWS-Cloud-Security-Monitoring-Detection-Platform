# VPC Flow Logs Investigation Queries

These queries are used with Amazon CloudWatch Logs Insights to investigate rejected network traffic captured by VPC Flow Logs.

---

## 1. Rejected Traffic Timeline

This query identifies rejected network traffic over 5-minute intervals.

```text
fields @timestamp, @message
| filter @message like /REJECT/
| stats count() as rejected_attempts by bin(5m)
| sort rejected_attempts desc
| limit 20
```

### Purpose

Helps identify periods of increased rejected network activity that may require further investigation.

---

## 2. Top Source IPs

This query identifies the source IP addresses generating the highest number of rejected connections.

```text
fields @timestamp, @message
| parse @message "* * * * * * * * * * * * * *" as version, account, interface, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action, logstatus
| filter action = "REJECT"
| stats count() as rejected_attempts by srcaddr
| sort rejected_attempts desc
| limit 10
```

### Purpose

Helps identify potential sources of repeated rejected connection attempts.

---

## 3. Source-to-Target Investigation

Use this query to investigate rejected traffic from a specific source against a specific target.

```text
fields @timestamp, @message
| parse @message "* * * * * * * * * * * * * *" as version, account, interface, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action, logstatus
| filter action = "REJECT"
| filter srcaddr = "<SOURCE_IP>"
| filter dstaddr = "<TARGET_IP>"
| stats count() as attempts, count_distinct(dstport) as unique_ports
```

Replace:

```text
<SOURCE_IP>
```

and:

```text
<TARGET_IP>
```

with the values relevant to the investigation.

---

## 4. Protocol Analysis

This query identifies the network protocols associated with rejected traffic from a specific source and target.

```text
fields @timestamp, @message
| parse @message "* * * * * * * * * * * * * *" as version, account, interface, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action, logstatus
| filter action = "REJECT"
| filter srcaddr = "<SOURCE_IP>"
| filter dstaddr = "<TARGET_IP>"
| stats count() as attempts by protocol
```

For VPC Flow Logs, protocol `6` represents TCP.

---

## 5. First Seen / Last Seen

This query determines when the activity was first and last observed.

```text
fields @timestamp, @message
| parse @message "* * * * * * * * * * * * * *" as version, account, interface, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action, logstatus
| filter action = "REJECT"
| filter srcaddr = "<SOURCE_IP>"
| filter dstaddr = "<TARGET_IP>"
| stats min(@timestamp) as first_seen, max(@timestamp) as last_seen, count() as attempts
```

### Purpose

Helps determine whether the activity was a short burst or persisted over a longer period.

---

## Investigation Notes

These queries were used during the investigation documented in:

`incident-response/INC-001-port-scanning.md`

The investigation identified repeated rejected TCP connections targeting multiple destination ports.

The source and target IP addresses are intentionally represented as placeholders in reusable investigation queries to avoid exposing real infrastructure details.