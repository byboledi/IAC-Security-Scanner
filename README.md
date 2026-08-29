# IAC-Security-Scanner


A lightweight Python tool that scans Terraform (`.tf`) files for common cloud security misconfigurations — before they ever get deployed.

## Why I built this

Cloud misconfigurations are one of the most common causes of real-world breaches — an open S3 bucket or an overly permissive IAM policy can expose data without a single "hack" taking place. As I've been learning cloud architecture, I wanted a tool that catches these mistakes early, at the code level, rather than after something's already live in production.

This project sits at the intersection of my two main interests: cybersecurity and cloud infrastructure.

## What it checks for

| Issue | Severity | Why it matters |
|---|---|---|
| Open CIDR block (`0.0.0.0/0`) | High | Exposes a resource to the entire internet, not just trusted IPs |
| S3 bucket without public access block | Medium | Risk of accidental public data exposure |
| Wildcard IAM Action (`"Action": "*"`) | High | Grants far more permission than almost any role needs |
| Wildcard IAM Resource (`"Resource": "*"`) | High | Lets a policy apply to *any* resource, not just intended ones |
| Hardcoded secrets/passwords | High | Secrets in code can leak via version control or logs |

## How it works

The scanner reads `.tf` files line by line and pattern-matches against known risky configurations. It flags the file, line number, the exact offending code, and a plain-English suggestion for how to fix it.

## Usage

```bash
python iac_scanner.py <path-to-terraform-file-or-folder>
```

Example output: