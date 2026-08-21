# Deploying this site to GitHub Pages + GoDaddy

This site lives at `docs/` inside the main `iam-crosscloud-privesc-pathfinder`
project repo — not a standalone repo. It's currently a placeholder;
real content (case studies, diagrams, findings) replaces it once
Track 1 and Track 2 are validated (see TASKS.md).

## 1. Push the project repo (if not already pushed)

```bash
cd iam-crosscloud-privesc-pathfinder
git init
git add .
git commit -m "Initial project + placeholder docs site"
git branch -M main
git remote add origin https://github.com/<your-username>/iam-crosscloud-privesc-pathfinder.git
git push -u origin main
```

## 2. Enable GitHub Pages, sourced from /docs

1. On GitHub, go to the repo → **Settings** → **Pages**
2. Under "Build and deployment", set **Source** to `Deploy from a branch`
3. Branch: `main`, folder: `/docs` → **Save**
4. Wait ~1 minute, then a URL like
   `https://<username>.github.io/iam-crosscloud-privesc-pathfinder/` appears at the
   top of that page. Confirm it loads before continuing — don't add the
   custom domain until the default URL works.

## 3. Decide: apex domain or subdomain

- **Subdomain** (e.g. `projects.yourdomain.com`) — simpler, recommended.
  Keeps your root domain free for something else later (email, a main
  site) without conflicting DNS records.
- **Apex/root domain** (e.g. `yourdomain.com`) — works too, but apex
  domains can't use a plain CNAME record (DNS rules), so GitHub Pages
  requires pointing A records at GitHub's IPs instead. More fragile if
  GitHub ever changes those IPs.

**Recommendation: use a subdomain**, e.g. `projects.yourdomain.com`.

## 4. Add the custom domain in GitHub

1. Repo → **Settings** → **Pages** → under "Custom domain", enter your
   chosen domain (e.g. `projects.yourdomain.com`) → **Save**
2. This automatically creates a `CNAME` file in your repo root containing
   that domain — commit and push it if it doesn't appear automatically.
3. Leave "Enforce HTTPS" unchecked for now — it can't be enabled until
   DNS is verified (next step). Come back and check it once it's
   available.

## 5. Add the DNS record at GoDaddy

Log into GoDaddy → **My Products** → your domain → **DNS** → **Manage**.

**If using a subdomain (recommended):**

| Type  | Name       | Value                    | TTL     |
|-------|------------|--------------------------|---------|
| CNAME | `projects` | `<username>.github.io.`  | 600 (or default) |

(Replace `projects` with whatever subdomain you chose. Note the trailing
dot on the value — some registrars want it, GoDaddy usually doesn't
require it but accepts it.)

**If using the apex/root domain instead:**

Add four A records, all with Name `@`, pointing at GitHub Pages' IPs:

| Type | Name | Value           |
|------|------|-----------------|
| A    | @    | 185.199.108.153 |
| A    | @    | 185.199.109.153 |
| A    | @    | 185.199.110.153 |
| A    | @    | 185.199.111.153 |

(These are GitHub's current published Pages IPs — verify against
GitHub's own docs at the time you do this, in case they've changed.)

## 6. Wait for propagation, then verify

- DNS changes typically take 10 minutes to a few hours (rarely up to 24h)
- Check propagation: `dig projects.yourdomain.com` (or any online DNS
  checker) — should resolve to `<username>.github.io` (subdomain) or the
  GitHub IPs (apex)
- Once it resolves, go back to repo **Settings → Pages** — GitHub
  auto-detects the DNS and issues a Let's Encrypt certificate. This can
  take up to a few hours after DNS resolves correctly.
- Once available, check **Enforce HTTPS** in the Pages settings

## 7. Confirm

Visit `https://projects.yourdomain.com` (or your apex domain). You
should see this placeholder page over HTTPS with a valid padlock and be
able to click through to the second page.

## Updating the site later

Any push to `main` auto-redeploys within about a minute — no separate
build/deploy step, unlike the S3+CloudFront alternative we ruled out.
