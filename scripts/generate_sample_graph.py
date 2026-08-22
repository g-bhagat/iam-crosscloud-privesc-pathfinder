#!/usr/bin/env python3
"""
generate_sample_graph.py

Builds sample_data/sample_graph.json: a synthetic, Track-1-shaped identity
graph used to exercise the analysis layer (correlation, escalation rules,
pathfinder, visualization) end to end without live AWS/GCP credentials.

Mirrors terraform/track1/ exactly -- same resource names, same
misconfiguration shape -- but with placeholder account/project IDs (never
real ones, per SCOPE.md rule 5). Regenerate after changing that Terraform
or the graph schema:

    python3 scripts/generate_sample_graph.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.graph_schema import Cloud, Edge, EdgeType, Node, NodeType

AWS_ACCOUNT_ID = "123456789012"  # AWS's own standard placeholder example account ID
GCP_PROJECT_ID = "track1-sandbox-project"
GITHUB_ORG = "acme-corp"
GITHUB_REPO = "iam-crosscloud-victim-pipeline"
GITHUB_BRANCH = "main"
OIDC_ISSUER = "token.actions.githubusercontent.com"


def build() -> tuple[list[Node], list[Edge]]:
    nodes: list[Node] = []
    edges: list[Edge] = []

    # ---- AWS side (terraform/track1/aws.tf) --------------------------------

    aws_oidc_provider_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:oidc-provider/{OIDC_ISSUER}"
    aws_bridge_id = f"federated:{aws_oidc_provider_arn}"
    nodes.append(
        Node(
            id=aws_bridge_id,
            type=NodeType.APP_REGISTRATION,
            cloud=Cloud.CROSS_CLOUD,
            name=aws_oidc_provider_arn,
            external_facing=True,
        )
    )

    aws_role_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/track1-cicd-deploy-role"
    aws_role_id = f"aws:role:{aws_role_arn}"
    nodes.append(
        Node(
            id=aws_role_id,
            type=NodeType.ROLE,
            cloud=Cloud.AWS,
            name="track1-cicd-deploy-role",
            is_admin=False,
            attributes={"arn": aws_role_arn},
        )
    )

    # Correctly scoped: sub pinned to repo AND ref (task 15 -- the control).
    aws_condition = json.dumps(
        {
            "StringEquals": {
                "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                "token.actions.githubusercontent.com:sub": f"repo:{GITHUB_ORG}/{GITHUB_REPO}:ref:refs/heads/{GITHUB_BRANCH}",
            }
        }
    )
    edges.append(
        Edge(
            source=aws_bridge_id,
            target=aws_role_id,
            type=EdgeType.FEDERATES_WITH,
            cloud=Cloud.CROSS_CLOUD,
            condition=aws_condition,
            evidence="OIDC/SAML federated trust",
        )
    )

    # A small, unrelated in-cloud AWS chain -- proves the pathfinder (task 11)
    # is generic graph reachability, not cross-cloud-specific: a user reaches
    # admin purely through AWS group membership, no federation involved.
    aws_group_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:group/break-glass-admins"
    aws_group_id = f"aws:group:{aws_group_arn}"
    nodes.append(
        Node(
            id=aws_group_id,
            type=NodeType.GROUP,
            cloud=Cloud.AWS,
            name="break-glass-admins",
            is_admin=True,  # AdministratorAccess attached directly to the group
            attributes={"arn": aws_group_arn},
        )
    )
    aws_user_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/sam-devops"
    aws_user_id = f"aws:user:{aws_user_arn}"
    nodes.append(
        Node(
            id=aws_user_id,
            type=NodeType.USER,
            cloud=Cloud.AWS,
            name="sam-devops",
            mfa_enabled=True,
            attributes={"arn": aws_user_arn},
        )
    )
    edges.append(Edge(source=aws_user_id, target=aws_group_id, type=EdgeType.MEMBER_OF, cloud=Cloud.AWS))

    # Unreachable admin node -- nothing points at it. Proves the pathfinder
    # doesn't spuriously report admin nodes that aren't actually reachable.
    nodes.append(
        Node(
            id=f"aws:role:arn:aws:iam::{AWS_ACCOUNT_ID}:role/legacy-break-glass",
            type=NodeType.ROLE,
            cloud=Cloud.AWS,
            name="legacy-break-glass",
            is_admin=True,
            attributes={"note": "no inbound edges -- deliberately unreachable in this sample"},
        )
    )

    # ---- GCP side (terraform/track1/gcp.tf) --------------------------------

    gcp_bridge_id = f"gcp:wif_bridge:https://{OIDC_ISSUER}"
    nodes.append(
        Node(
            id=gcp_bridge_id,
            type=NodeType.APP_REGISTRATION,
            cloud=Cloud.CROSS_CLOUD,
            name=f"https://{OIDC_ISSUER}",
            external_facing=True,
        )
    )

    owner_sa_email = f"track1-owner-sa@{GCP_PROJECT_ID}.iam.gserviceaccount.com"
    owner_sa_id = f"gcp:service_account:{owner_sa_email}"
    nodes.append(
        Node(
            id=owner_sa_id,
            type=NodeType.SERVICE_ACCOUNT,
            cloud=Cloud.GCP,
            name="track1-owner-sa",
            is_admin=True,  # roles/owner
            attributes={"email": owner_sa_email, "role": "roles/owner"},
        )
    )
    # THE PLANTED MISCONFIGURATION (task 16/17): attribute-condition scoped
    # only to the GitHub org, not the specific repo/branch.
    edges.append(
        Edge(
            source=gcp_bridge_id,
            target=owner_sa_id,
            type=EdgeType.FEDERATES_WITH,
            cloud=Cloud.CROSS_CLOUD,
            condition=f'assertion.repository_owner == "{GITHUB_ORG}"',
            evidence="Workload Identity Federation binding (gh-loose-org-scope)",
        )
    )

    scoped_sa_email = f"track1-scoped-sa@{GCP_PROJECT_ID}.iam.gserviceaccount.com"
    scoped_sa_id = f"gcp:service_account:{scoped_sa_email}"
    nodes.append(
        Node(
            id=scoped_sa_id,
            type=NodeType.SERVICE_ACCOUNT,
            cloud=Cloud.GCP,
            name="track1-scoped-sa",
            is_admin=False,  # roles/viewer
            attributes={"email": scoped_sa_email, "role": "roles/viewer"},
        )
    )
    # THE NEGATIVE CONTROL (task 18): correctly scoped to repo AND ref.
    edges.append(
        Edge(
            source=gcp_bridge_id,
            target=scoped_sa_id,
            type=EdgeType.FEDERATES_WITH,
            cloud=Cloud.CROSS_CLOUD,
            condition=(
                f'assertion.repository == "{GITHUB_ORG}/{GITHUB_REPO}" '
                f'&& assertion.ref == "refs/heads/{GITHUB_BRANCH}"'
            ),
            evidence="Workload Identity Federation binding (gh-scoped-repo-branch)",
        )
    )

    return nodes, edges


def main():
    nodes, edges = build()
    out = {
        "nodes": [n.to_dict() for n in nodes],
        "edges": [e.to_dict() for e in edges],
    }
    out_path = Path(__file__).resolve().parent.parent / "sample_data" / "sample_graph.json"
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2) + "\n")
    print(f"Wrote {len(nodes)} nodes, {len(edges)} edges -> {out_path}")


if __name__ == "__main__":
    main()
