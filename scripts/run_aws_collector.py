#!/usr/bin/env python3
"""
run_aws_collector.py

Manual test of AWSCollector (task 7) against the real AWS sandbox
account, using the dedicated read-only scanner identity -- not sample
data. Run this before wiring AWS into the full pipeline, to catch
real-world API quirks (pagination, missing fields, permission edge
cases) that sample_data/sample_graph.json can never surface.

Usage:
    python3 scripts/run_aws_collector.py [--profile PROFILE_NAME]

Requires:
    - AWS credentials configured for the scanner identity, e.g.:
        aws configure --profile iam-pathfinder-scanner
    - The scanner IAM policy from terraform/scanner/aws.tf applied,
      or the manually-created equivalent.
"""

import argparse
import json
import sys
from pathlib import Path

import boto3

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.collectors.aws_collector import AWSCollector  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Run AWSCollector against the real sandbox")
    parser.add_argument(
        "--profile",
        default="iam-pathfinder-scanner",
        help="AWS CLI profile to authenticate as (default: iam-pathfinder-scanner)",
    )
    parser.add_argument(
        "--dump-json",
        metavar="PATH",
        help="Optional: write raw nodes/edges to this JSON file for later reuse "
        "(e.g. feeding into the correlation/detection stage without re-scanning)",
    )
    args = parser.parse_args()

    print(f"Authenticating as AWS profile: {args.profile}")
    session = boto3.Session(profile_name=args.profile)

    identity = session.client("sts").get_caller_identity()
    print(f"Confirmed identity: {identity['Arn']}")
    print(f"Scanning account: {identity['Account']}\n")

    collector = AWSCollector(session)
    nodes, edges = collector.collect()

    print(f"Collected {len(nodes)} nodes, {len(edges)} edges\n")

    print("--- Nodes ---")
    for n in sorted(nodes, key=lambda n: (n.type.value, n.name)):
        admin_flag = " [ADMIN]" if n.is_admin else ""
        external_flag = " [EXTERNAL]" if n.external_facing else ""
        print(f"  {n.type.value:20} {n.name:45}{admin_flag}{external_flag}")

    print(f"\n--- Edges ({len(edges)} total) ---")
    edge_types = {}
    for e in edges:
        edge_types[e.type.value] = edge_types.get(e.type.value, 0) + 1
    for etype, count in sorted(edge_types.items()):
        print(f"  {etype:25} {count}")

    federated_nodes = [n for n in nodes if n.cloud.value == "cross_cloud"]
    if federated_nodes:
        print(f"\n--- Federated/OIDC bridge nodes ({len(federated_nodes)}) ---")
        for n in federated_nodes:
            print(f"  {n.name}")
            for k, v in n.attributes.items():
                print(f"    {k}: {v}")

    if args.dump_json:
        out = {
            "nodes": [n.to_dict() for n in nodes],
            "edges": [e.to_dict() for e in edges],
        }
        Path(args.dump_json).write_text(json.dumps(out, indent=2, default=str))
        print(f"\nWrote raw graph to {args.dump_json}")
        print("NOTE: this file will contain real account IDs/ARNs -- do not commit it.")


if __name__ == "__main__":
    main()
