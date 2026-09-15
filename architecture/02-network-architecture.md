# Network Architecture

## Overview

The CloudSOC network is deployed inside an Amazon VPC using multiple Availability Zones and separate public and private subnets.

The network is designed to provide isolation, controlled connectivity, and improved availability.

## VPC Configuration

| Component | Configuration |
|---|---|
| VPC | `CloudSOC-VPC` |
| CIDR Block | `10.0.0.0/16` |
| Region | `eu-north-1` |
| Availability Zones | Multiple Availability Zones |

## Subnet Design

The VPC is divided into public and private subnets.

| Subnet | CIDR | Type | Purpose |
|---|---|---|---|
| Public A | `10.0.1.0/24` | Public | Internet-facing resources |
| Public B | `10.0.2.0/24` | Public | Internet-facing resources |
| Private A | `10.0.11.0/24` | Private | Internal application resources |
| Private B | `10.0.12.0/24` | Private | Internal application resources |

## Public Subnets

Public subnets use a route table that contains a default route:

```text
0.0.0.0/0 → Internet Gateway