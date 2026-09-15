# Secure AWS Architecture

## Overview

CloudSOC is designed as a secure AWS cloud environment that combines application infrastructure with centralized security monitoring and detection capabilities.

The architecture separates public-facing components from internal resources and integrates AWS security and monitoring services to provide visibility into network and account activity.

## Architecture Goals

The architecture is designed to achieve the following goals:

- Provide a secure and scalable AWS environment.
- Separate public and private resources.
- Apply least-privilege access controls.
- Provide high availability where applicable.
- Centralize security monitoring and logging.
- Detect suspicious network and IAM activity.
- Support investigation and incident response.
- Demonstrate AWS architectural best practices relevant to the AWS Solutions Architect Associate certification.

## Main Components

The architecture consists of the following components:

| Component | Purpose |
|---|---|
| Amazon VPC | Provides network isolation for the environment |
| Public Subnets | Host internet-facing components |
| Private Subnets | Host internal application and database resources |
| Internet Gateway | Provides internet connectivity for public resources |
| Application Load Balancer | Distributes incoming application traffic |
| Amazon EC2 | Provides application compute capacity |
| Amazon RDS | Provides managed relational database storage |
| Amazon S3 | Provides durable object storage |
| AWS IAM | Controls identities and permissions |
| AWS CloudTrail | Records AWS API activity |
| Amazon CloudWatch | Provides monitoring, logging, metrics, and alarms |
| VPC Flow Logs | Provides network traffic visibility |
| Amazon SNS | Delivers security notifications |

## Security Architecture

Security is implemented through multiple layers:

1. Network isolation using VPC subnets.
2. Security Groups controlling resource-level traffic.
3. IAM policies controlling AWS permissions.
4. CloudTrail for AWS API activity logging.
5. VPC Flow Logs for network visibility.
6. CloudWatch for monitoring and detection.
7. SNS for security alert notifications.
8. Incident response procedures for investigating detected activity.