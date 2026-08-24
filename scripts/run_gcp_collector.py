#!/usr/bin/env python3
"""
run_gcp_collector.py

Manual test of GCPCollector (task 8) against the real GCP sandbox
project, using the impersonated read-only scanner service account --
not sample data. Run this before wiring GCP into the full detection
pipeline (run_detector.py), to catch real-world API quirks (pagination,
missing fields, permission edge cases) that sample_data/sample_graph.json
can never surface.

Written against a specific, already-validated sandbox layout:
  - WIF pool: github-actions-pool
  - Providers: gh-loose-org-scope (planted misconfig), gh-scoped-repo-branch (control)
  - Service accounts: track1-owner-sa (roles/owner), track1-scoped-sa (roles/viewer)
See TASKS.md Track 1 / docs/THREAT_MODEL.md Pattern 1 for the full design.

The "sandbox-specific checks" section below is a quick pass/fail read
against that known layout -- if your sandbox uses different names,
those checks just won't match anything and print [MISSING]; the raw
node/edge listing above them is unaffected.

Usage:
    python3 scripts/run_gcp_collector.py --project PROJECT_ID
    python3 scripts/run_gcp_collector.py --project PROJECT_ID --dump-json /tmp/gcp_graph.json

Requires:
    gcloud auth application-default login \\
      --impersonate-service-account=iam-pathfinder-scanner@PROJECT_ID.iam.gserviceaccount.com

Credentials: asset_v1.AssetServiceClient() resolves ADC automatically
with no explicit credentials argument. The IAM Admin API v1 client
(googleapiclient.discovery) is built explicitly with
google.auth.default()'s credentials -- the standard, unambiguous
pattern for discovery-based clients.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.collectors.gcp_collector import GCPCollector

EXPECTED_LOOSE_PROVIDER = "gh-loose-org-scope"
EXPECTED_SCOPED_PROVIDER = "gh-scoped-repo-branch"
EXPECTED_OWNER_SA = "track1-owner-sa"
EXPECTED_SCOPED_SA = "track1-scoped-sa"


def main():
    parser = argparse.ArgumentParser(description="Run GCPCollector against the real sandbox")
    parser.add_argument("--project", required=True, help="GCP project ID to scan")
    parser.add_argument(
        "--dump-json",
        metavar="PATH",
        help="Optional: write raw nodes/edges to this JSON file (feeds into run_detector.py)",
    )
    args = parser.parse_args()

    print(f"Scanning GCP project: {args.project}\n")

    try:
        import google.auth
        from google.cloud import asset_v1
        from googleapiclient.discovery import build
    except ImportError as e:
        print(f"Missing GCP client library: {e}. pip install -r requirements.txt", file=sys.stderr)
        sys.exit(1)

    credentials, _default_project = google.auth.default()
    asset_client = asset_v1.AssetServiceClient()
    iam_client = build("iam", "v1", credentials=credentials, static_discovery=True)

    collector = GCPCollector(asset_client=asset_client, iam_client=iam_client, project_id=args.project)
    nodes, edges = collector.collect()

    print(f"Collected {len(nodes)} nodes, {len(edges)} edges\n")

    print("--- Nodes ---")
    for n in sorted(nodes, key=lambda n: (n.type.value, n.name)):
        admin_flag = " [ADMIN]" if n.is_admin else ""
        external_flag = " [EXTERNAL]" if n.external_facing else ""
        print(f"  {n.type.value:20} {n.name:55}{admin_flag}{external_flag}")

    print(f"\n--- Edges ({len(edges)} total) ---")
    edge_types = {}
    for e in edges:
        edge_types[e.type.value] = edge_types.get(e.type.value, 0) + 1
    for etype, count in sorted(edge_types.items()):
        print(f"  {etype:25} {count}")

    # --- Specific sanity checks against the known real sandbox layout ---
    print("\n--- Sandbox-specific checks ---")

    owner_sa = next((n for n in nodes if EXPECTED_OWNER_SA in n.name), None)
    scoped_sa = next((n for n in nodes if EXPECTED_SCOPED_SA in n.name), None)

    if owner_sa:
        status = "OK" if owner_sa.is_admin else "UNEXPECTED -- should be is_admin=True (roles/owner)"
        print(f"  [{status}] Found {EXPECTED_OWNER_SA}, is_admin={owner_sa.is_admin}")
    else:
        print(f"  [MISSING] {EXPECTED_OWNER_SA} not found in collected nodes")

    if scoped_sa:
        status = "OK" if not scoped_sa.is_admin else "UNEXPECTED -- should be is_admin=False (roles/viewer)"
        print(f"  [{status}] Found {EXPECTED_SCOPED_SA}, is_admin={scoped_sa.is_admin}")
    else:
        print(f"  [MISSING] {EXPECTED_SCOPED_SA} not found in collected nodes")

    # The raw attributeCondition CEL string lives on the FEDERATES_WITH
    # EDGE (Edge.condition), not on a node attribute -- that's what
    # confidence.py's score_gcp_condition() reads. Printed here, before
    # correlation runs, as the clearest way to confirm the collector
    # captured it untouched rather than reformatting or dropping it.
    print("\n--- WIF provider attribute_condition (raw, as captured on each FEDERATES_WITH edge) ---")
    found_conditions = False
    for e in edges:
        if e.type.value != "federates_with" or not e.condition:
            continue
        found_conditions = True
        which = (
            "LOOSE (planted misconfig)"
            if EXPECTED_LOOSE_PROVIDER in (e.evidence or "")
            else "SCOPED (negative control)"
            if EXPECTED_SCOPED_PROVIDER in (e.evidence or "")
            else "unknown provider"
        )
        print(f"  [{which}] {e.source} -> {e.target}")
        print(f"      {e.condition}")
    if not found_conditions:
        print("  None found on any FEDERATES_WITH edge -- check whether any SA has a")
        print("  roles/iam.workloadIdentityUser binding the collector could resolve.")

    if args.dump_json:
        out = {
            "nodes": [n.to_dict() for n in nodes],
            "edges": [e.to_dict() for e in edges],
        }
        Path(args.dump_json).write_text(json.dumps(out, indent=2, default=str))
        print(f"\nWrote raw graph to {args.dump_json}")
        print("NOTE: this file will contain real project IDs/SA emails -- do not commit it.")


if __name__ == "__main__":
    main()
