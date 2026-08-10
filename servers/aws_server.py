#!/usr/bin/env python3
"""AWS MCP server for REDEYE.

Pulls cloud inventory (EC2 servers, Lambda functions, ECS containers, ELB
network devices) and vulnerabilities (Amazon Inspector2) using a **named AWS
profile** via boto3 -- no API keys. Falls back to clearly-flagged mock data when
boto3 / credentials are unavailable so the inventory populates without an AWS
account.

Results flow through the "aws" extractor -> assets become inventory/map nodes
(coloured by kind), Inspector findings become rows in the findings DB.

Environment:
    AWS_PROFILE            default profile if the tool's `profile` arg is empty
    REDEYE_AWS_MOCK=1      force mock mode
    REDEYE_AWS_REGIONS     default comma-list of regions (else the profile's region)

SAFETY: read-only describe/list calls only.
"""
from __future__ import annotations

import json
import os

from mcp.server import MCPServer

srv = MCPServer("redeye-aws")

FORCE_MOCK = os.environ.get("REDEYE_AWS_MOCK", "") == "1"
DEFAULT_REGIONS = [r for r in os.environ.get("REDEYE_AWS_REGIONS", "").split(",") if r]


def _session(profile: str):
    import boto3  # imported lazily so mock mode needs no boto3
    return boto3.Session(profile_name=profile or os.environ.get("AWS_PROFILE") or None)


def _regions(sess, regions: str):
    if regions:
        return [r.strip() for r in regions.split(",") if r.strip()]
    if DEFAULT_REGIONS:
        return DEFAULT_REGIONS
    return [sess.region_name or "us-east-1"]


def _live(profile: str):
    """Return a session if we can authenticate, else None (-> mock)."""
    if FORCE_MOCK:
        return None
    try:
        sess = _session(profile)
        sess.client("sts").get_caller_identity()
        return sess
    except Exception:  # noqa: BLE001 -- no creds / no boto3 / bad profile
        return None


# -- real enumeration --------------------------------------------------------
def _collect_assets(sess, regions) -> list:
    assets = []
    acct = ""
    try:
        acct = sess.client("sts").get_caller_identity().get("Account", "")
    except Exception:  # noqa: BLE001
        pass
    for region in regions:
        # EC2 instances -> servers
        try:
            ec2 = sess.client("ec2", region_name=region)
            for res in ec2.describe_instances().get("Reservations", []):
                for i in res.get("Instances", []):
                    name = _tag(i.get("Tags"), "Name") or i.get("InstanceId", "")
                    assets.append({
                        "id": i.get("InstanceId", ""), "kind": "server",
                        "label": name, "ip": i.get("PrivateIpAddress", ""),
                        "hostname": i.get("PrivateDnsName", ""),
                        "os": i.get("PlatformDetails", i.get("Platform", "linux")),
                        "status": i.get("State", {}).get("Name", ""),
                        "region": region, "account": acct,
                        "meta": {"public_ip": i.get("PublicIpAddress", ""),
                                 "type": i.get("InstanceType", ""),
                                 "vpc": i.get("VpcId", ""), "subnet": i.get("SubnetId", "")}})
        except Exception:  # noqa: BLE001
            pass
        # Lambda functions
        try:
            lam = sess.client("lambda", region_name=region)
            for fn in lam.list_functions().get("Functions", []):
                assets.append({
                    "id": fn.get("FunctionArn", fn.get("FunctionName", "")),
                    "kind": "lambda", "label": fn.get("FunctionName", ""),
                    "os": fn.get("Runtime", ""), "status": fn.get("State", "Active"),
                    "region": region, "account": acct,
                    "meta": {"runtime": fn.get("Runtime", ""),
                             "memory": fn.get("MemorySize", ""),
                             "vpc": (fn.get("VpcConfig") or {}).get("VpcId", "")}})
        except Exception:  # noqa: BLE001
            pass
        # ECS services -> containers
        try:
            ecs = sess.client("ecs", region_name=region)
            for cl_arn in ecs.list_clusters().get("clusterArns", []):
                svc_arns = ecs.list_services(cluster=cl_arn).get("serviceArns", [])
                for s in svc_arns:
                    assets.append({
                        "id": s, "kind": "container",
                        "label": s.split("/")[-1], "status": "running",
                        "region": region, "account": acct,
                        "meta": {"cluster": cl_arn.split("/")[-1]}})
        except Exception:  # noqa: BLE001
            pass
        # ELBv2 load balancers -> network devices
        try:
            elb = sess.client("elbv2", region_name=region)
            for lb in elb.describe_load_balancers().get("LoadBalancers", []):
                assets.append({
                    "id": lb.get("LoadBalancerArn", ""), "kind": "network_device",
                    "label": lb.get("LoadBalancerName", ""),
                    "hostname": lb.get("DNSName", ""),
                    "status": lb.get("State", {}).get("Code", ""),
                    "region": region, "account": acct,
                    "meta": {"scheme": lb.get("Scheme", ""), "type": lb.get("Type", ""),
                             "vpc": lb.get("VpcId", "")}})
        except Exception:  # noqa: BLE001
            pass
    return assets


def _collect_vulns(sess, regions, subnet) -> list:
    from _apiutil import in_subnet
    findings = []
    for region in regions:
        try:
            insp = sess.client("inspector2", region_name=region)
            paginator = insp.get_paginator("list_findings")
            for page in paginator.paginate(maxResults=100):
                for f in page.get("findings", []):
                    res = (f.get("resources") or [{}])[0]
                    details = res.get("details", {}).get("awsEc2Instance", {})
                    ip = details.get("ipV4Addresses", [""])[0] if details else ""
                    if subnet and ip and not in_subnet(ip, subnet):
                        continue
                    cve = (f.get("packageVulnerabilityDetails") or {}).get("vulnerabilityId", "")
                    findings.append({
                        "id": f.get("findingArn", "")[-40:], "cve": cve,
                        "title": f.get("title", ""),
                        "severity": f.get("severity", "MEDIUM"),
                        "asset": res.get("id", ""), "ip": ip,
                        "description": f.get("description", ""),
                        "recommendation": (f.get("remediation") or {}).get(
                            "recommendation", {}).get("text", "")})
        except Exception:  # noqa: BLE001
            pass
    return findings


def _tag(tags, key):
    for t in (tags or []):
        if t.get("Key") == key:
            return t.get("Value", "")
    return ""


# -- mock --------------------------------------------------------------------
def _mock_assets():
    return [
        {"id": "i-0a1b2c3d", "kind": "server", "label": "web-prod-01",
         "ip": "10.0.0.11", "hostname": "ip-10-0-0-11.ec2.internal",
         "os": "Amazon Linux 2023", "status": "running", "region": "us-east-1",
         "account": "123456789012", "meta": {"public_ip": "54.1.2.3",
         "type": "t3.medium", "vpc": "vpc-aaa", "subnet": "subnet-1"}},
        {"id": "i-0e4f5a6b", "kind": "server", "label": "db-prod-01",
         "ip": "10.0.1.22", "hostname": "ip-10-0-1-22.ec2.internal",
         "os": "Ubuntu 22.04", "status": "running", "region": "us-east-1",
         "account": "123456789012", "meta": {"type": "r6i.large", "vpc": "vpc-aaa"}},
        {"id": "checkout-fn", "kind": "lambda", "label": "checkout-fn",
         "os": "python3.12", "status": "Active", "region": "us-east-1",
         "account": "123456789012", "meta": {"runtime": "python3.12", "memory": 512}},
        {"id": "svc/api", "kind": "container", "label": "api",
         "status": "running", "region": "us-east-1", "account": "123456789012",
         "meta": {"cluster": "prod"}},
        {"id": "alb-public", "kind": "network_device", "label": "alb-public",
         "hostname": "alb-public-123.us-east-1.elb.amazonaws.com", "ip": "10.0.0.9",
         "status": "active", "region": "us-east-1", "account": "123456789012",
         "meta": {"scheme": "internet-facing", "type": "application", "vpc": "vpc-aaa"}},
    ]


def _mock_vulns(subnet):
    from _apiutil import filter_subnet
    v = [
        {"id": "insp-1001", "cve": "CVE-2024-3094", "title": "xz-utils backdoor",
         "severity": "CRITICAL", "asset": "i-0a1b2c3d", "ip": "10.0.0.11",
         "remote": True, "description": "Backdoored liblzma reachable via sshd.",
         "recommendation": "Patch xz to a clean version and rotate host keys."},
        {"id": "insp-1002", "cve": "CVE-2021-44228", "title": "Log4Shell (log4j RCE)",
         "severity": "CRITICAL", "asset": "i-0a1b2c3d", "ip": "10.0.0.11",
         "remote": True, "description": "Remote code execution via JNDI lookup.",
         "recommendation": "Upgrade log4j to >= 2.17.1."},
        {"id": "insp-1003", "cve": "CVE-2023-0286", "title": "OpenSSL X.400 type confusion",
         "severity": "HIGH", "asset": "i-0e4f5a6b", "ip": "10.0.1.22",
         "remote": False, "description": "Local type confusion in OpenSSL.",
         "recommendation": "Update OpenSSL packages."},
    ]
    return filter_subnet(v, subnet)


# -- tools -------------------------------------------------------------------
@srv.tool(description="List AWS inventory via a named profile (.aws): EC2 "
                      "servers, Lambda functions, ECS containers and ELB "
                      "network devices. `profile` picks the AWS profile; "
                      "`regions` is an optional comma-list (default: the "
                      "profile's region). Populates the inventory/map.")
def list_assets(profile: str = "", regions: str = "") -> str:
    sess = _live(profile)
    if sess is None:
        return json.dumps({"vendor": "aws", "mock": True, "assets": _mock_assets(),
                           "findings": []})
    try:
        assets = _collect_assets(sess, _regions(sess, regions))
        return json.dumps({"vendor": "aws", "mock": False, "assets": assets,
                           "findings": []})
    except Exception as e:  # noqa: BLE001
        return json.dumps({"vendor": "aws", "mock": False, "error": str(e),
                           "assets": [], "findings": []})


@srv.tool(description="List Amazon Inspector2 vulnerability findings via a named "
                      "profile. `subnet` (CIDR, e.g. 10.0.0.0/24) filters to "
                      "findings on assets in that range -- use it for 'find "
                      "vulns in this subnet'. Writes to the findings DB.")
def list_vulns(profile: str = "", regions: str = "", subnet: str = "") -> str:
    sess = _live(profile)
    if sess is None:
        return json.dumps({"vendor": "aws", "mock": True, "assets": [],
                           "findings": _mock_vulns(subnet)})
    try:
        findings = _collect_vulns(sess, _regions(sess, regions), subnet)
        return json.dumps({"vendor": "aws", "mock": False, "assets": [],
                           "findings": findings})
    except Exception as e:  # noqa: BLE001
        return json.dumps({"vendor": "aws", "mock": False, "error": str(e),
                           "assets": [], "findings": []})


if __name__ == "__main__":
    srv.run("stdio")
