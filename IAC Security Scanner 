import re
import os
import sys

# Define patterns to detect common Terraform misconfigurations
CHECKS = [
    {
        "name": "Open CIDR block (0.0.0.0/0)",
        "pattern": re.compile(r'cidr_blocks\s*=\s*\[.*0\.0\.0\.0/0.*\]'),
        "severity": "HIGH",
        "advice": "Restrict this to specific IP ranges instead of the whole internet."
    },
    {
        "name": "S3 bucket missing public access block",
        "pattern": re.compile(r'resource\s+"aws_s3_bucket"'),
        "severity": "MEDIUM",
        "advice": "Ensure a matching aws_s3_bucket_public_access_block resource exists.",
        "context_check": True  # special handling below
    },
    {
        "name": "Overly permissive IAM policy",
        "pattern": re.compile(r'"Action"\s*:\s*"\*"'),
        "severity": "HIGH",
        "advice": "Avoid wildcard Actions — grant only the specific permissions needed."
    },
    {
        "name": "Wildcard IAM resource",
        "pattern": re.compile(r'"Resource"\s*:\s*"\*"'),
        "severity": "HIGH",
        "advice": "Avoid wildcard Resources — scope this to specific ARNs."
    },
    {
        "name": "Hardcoded secret/password",
        "pattern": re.compile(r'(password|secret|api_key)\s*=\s*"[^"]+"', re.IGNORECASE),
        "severity": "HIGH",
        "advice": "Use a secrets manager or variables file instead of hardcoding."
    },
]

def scan_file(filepath):
    findings = []
    with open(filepath, 'r', errors='ignore') as f:
        lines = f.readlines()

    full_text = "".join(lines)
    has_public_access_block = "aws_s3_bucket_public_access_block" in full_text

    for i, line in enumerate(lines, start=1):
        for check in CHECKS:
            if check["pattern"].search(line):
                if check.get("context_check") and has_public_access_block:
                    continue  # skip false positive if block resource exists elsewhere
                findings.append({
                    "file": filepath,
                    "line": i,
                    "issue": check["name"],
                    "severity": check["severity"],
                    "advice": check["advice"],
                    "code": line.strip()
                })
    return findings

def scan_path(path):
    all_findings = []
    if os.path.isfile(path):
        all_findings.extend(scan_file(path))
    else:
        for root, _, files in os.walk(path):
            for name in files:
                if name.endswith(".tf"):
                    all_findings.extend(scan_file(os.path.join(root, name)))
    return all_findings

def print_report(findings):
    if not findings:
        print("✅ No issues found.")
        return
    print(f"\n🔍 Found {len(findings)} issue(s):\n")
    for f in findings:
        print(f"[{f['severity']}] {f['issue']}")
        print(f"  File: {f['file']} (line {f['line']})")
        print(f"  Code: {f['code']}")
        print(f"  Fix:  {f['advice']}\n")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    results = scan_path(target)
    print_report(results)
    
    test_content = '''
resource "aws_security_group" "bad" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "leaky" {
  bucket = "my-bucket"
}
'''

with open("bad.tf", "w") as f:
    f.write(test_content)

results = scan_path("bad.tf")
print_report(results)