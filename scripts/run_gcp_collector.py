#!/usr/bin/env python3
"""
run_gcp_collector.py

Manual test of GCPCollector (task 8) against the real GCP sandbox
project, using the impersonated read-only scanner service account.

Written against a specific, already-validated sandbox layout:
  - WIF pool: github-actions-pool
  - Providers: gh-loose-org-scope (planted misconfig), gh-scoped-repo-branch (control)
  - Service accounts: track1-owner-sa (roles/owner), track1-scoped-sa (roles/viewer)
See TASKS.md Track 1 / docs/THREAT_MODEL.md Pattern 1 for the full design.

NOTE: as of this writing, GCPCollector's constructor and internals are
being implemented (task 8) -- the asset_client wiring below reflects
the module's documented plan (google.cloud.asset_v1), not a confirmed
final signature. Adjust the constructor call if the real implementation
lands differently.

Usage:
    python3 scripts/run_gcp_collector.py --project PROJECT_ID

Requires:
    gcloud auth application-default login \\
      --impersonate-service-account=iam-pathfinder-scanner@PROJECT_ID.iam.gserviceaccount.com
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.collectors.gcp_collector import GCPCollector  # noqa: E402

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
        from google.cloud import asset_v1

        asset_client = asset_v1.AssetServiceClient()
    except ImportError:
        print(
            "google-cloud-asset not installed. Add it to requirements.txt: "
            "pip install google-cloud-asset --break-system-packages",
            file=sys.stderr,
        )
        sys.exit(1)

    collector = GCPCollector(asset_client=asset_client, project_id=args.project)

    try:
        nodes, edges = collector.collect()
    except NotImplementedError as e:
        print(f"GCPCollector is still a stub: {e}")
        print("Expected until task 8 lands -- check back once Claude Code confirms it's done.")
        sys.exit(1)

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

    # Print the raw attribute_condition for both providers if the collector
    # captured them -- this is the exact string confidence.py's
    # score_gcp_condition() will parse. Seeing it here raw, before
    # correlation runs, is the clearest way to confirm the collector
    # captured it correctly rather than reformatting or dropping it.
    print(f"\n--- WIF provider attribute_condition (raw, as captured) ---")
    found_conditions = False
    for n in nodes:
        cond = n.attributes.get("attribute_condition") or n.attributes.get("condition")
        if cond:
            found_conditions = True
            which = (
                "LOOSE (planted misconfig)"
                if EXPECTED_LOOSE_PROVIDER in n.name
                else "SCOPED (negative control)"
                if EXPECTED_SCOPED_PROVIDER in n.name
                else "unknown provider"
            )
            print(f"  [{which}] {n.name}")
            print(f"      {cond}")
    if not found_conditions:
        print("  None found on any node -- check whether GCPCollector stores this as a node")
        print("  attribute or only on the edge (see confidence.py's expected input shape).")

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
