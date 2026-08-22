## ---------------------------------------------------------------------------
## Optional: create the victim CI/CD repo + its Actions workflow (tasks 13-14).
## Gated behind var.manage_github_repo (default false) -- if the repo already
## exists, leave this off and just make sure its workflow's `sub` claim
## matches what aws.tf / gcp.tf expect: repo:${github_org}/${github_repo}:ref:refs/heads/${github_branch}
## ---------------------------------------------------------------------------

resource "github_repository" "victim_pipeline" {
  count = var.manage_github_repo ? 1 : 0

  name        = var.github_repo
  description = "Track 1 sandbox: synthetic CI/CD pipeline used to demonstrate a cross-cloud OIDC trust mismatch. No real deploy targets -- see docs/THREAT_MODEL.md Pattern 1."
  visibility  = "private"

  auto_init = true
}

resource "github_repository_file" "workflow" {
  count = var.manage_github_repo ? 1 : 0

  repository          = github_repository.victim_pipeline[0].name
  branch              = var.github_branch
  file                = ".github/workflows/deploy.yml"
  overwrite_on_create = true
  commit_message      = "Add Track 1 sandbox deploy workflow (id-token: write)"

  content = <<-YAML
    name: track1-sandbox-deploy

    on:
      push:
        branches: [${var.github_branch}]

    # Required for the workflow to receive a GitHub-issued OIDC token that
    # AWS's AssumeRoleWithWebIdentity and GCP's Workload Identity Federation
    # both accept in exchange for short-lived cloud credentials.
    permissions:
      id-token: write
      contents: read

    jobs:
      federate-and-deploy:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4

          - name: Assume AWS role via OIDC
            uses: aws-actions/configure-aws-credentials@v4
            with:
              role-to-assume: ${var.aws_role_name} # replace with the full role ARN from `terraform output`
              aws-region: ${var.aws_region}

          - name: Federate to GCP via Workload Identity Federation
            uses: google-github-actions/auth@v2
            with:
              workload_identity_provider: PLACEHOLDER # `terraform output gcp_scoped_provider_resource_name` -- use the SCOPED provider in real workflows; the loose one exists only to be exploited for the demo
              service_account: PLACEHOLDER            # `terraform output gcp_scoped_service_account_email`

          - name: Sandbox no-op
            run: echo "This is a synthetic pipeline for a portfolio security project. It does not deploy anything real."
  YAML
}
