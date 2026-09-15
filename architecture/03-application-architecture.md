# Application Architecture

## Overview

The CloudSOC application layer is designed to provide a scalable and highly available application environment using Amazon EC2 instances distributed across multiple Availability Zones.

An Application Load Balancer (ALB) is used as the entry point for application traffic and distributes requests across healthy EC2 instances.

## Architecture

The application architecture follows this flow:

```text
Internet
    ↓
Application Load Balancer
    ↓
┌───────────────┬───────────────┐
│               │               │
EC2 Instance A     EC2 Instance B
│               │
└───────────────┴───────────────┘