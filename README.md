# kevstig

**KEV × STIG coverage checker** — a live routing table between CISA's
[Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
and the DISA STIG baselines Bedim Security maintains.
Live at: https://bedimsecurity.com/capabilities/kevstig/

## What it measures (and what it does NOT)

- **Routed**: a KEV entry's vendor/product text matches a platform family we
  maintain a manual STIG baseline for (Windows, macOS, RHEL 7/8/9,
  Ubuntu 20.04/22.04/24.04, vSphere 6.7, Firefox; Proxmox in build).
- **Routed is NOT remediated.** DISA manual STIGs harden configuration; they do
  not patch individual CVEs. Nothing here claims a rule neutralizes a specific
  CVE — the STIG XMLs we parse carry no CVE references (verified: 0 hits).
- **The gap is the artifact.** The uncovered count is published on purpose:
  appliances, web apps, middleware, and network gear we hold no baseline for,
  listed plainly. It feeds our crosswalk work.
- Generic-family entries ("Linux Kernel", vendor bundles) stay uncovered v1 on
  purpose: the routing table matches products literally, never guesses.

## Numbers at build time (2026-10-03, catalog 2026-10-02)

- Catalog: **1,733** KEV entries
- Routed: **273** (Windows 179 / macOS 61 / vSphere 18 / Firefox 12 / RHEL rows 3 each)
- Uncovered: **1,460** (the honest majority — KEV is appliance- and webapp-heavy)
- Rules maintained across the baselines: **3,162** (counted from the checklists' Vuln_Num ids)

## How it works

1. `kevstig.py` fetches the CISA KEV JSON feed (honors Retry-After; local file
   also accepted), routes each entry via `mapping.json` (curated, ordered,
   strict families — Red Hat middleware like JBoss deliberately does not
   route; only OS-surface components do), counts every maintained checklist's
   rule ids (`Vuln_Num` in DISA CKL v2 format; combos with `plus_` excluded).
2. Emits `api/coverage.json` + `api/headline.json` (plain + verified by reload;
   every artifact stamps catalog version + generation time).
3. Gate verdict: exits nonzero unless every gate passes — prints
   `KEVSTIG-OK catalog=<n> routed=<n> uncovered=<n> ...` for automation.

```
make                                  # build into /tmp/kevstig-deploy
python3 kevstig.py --kev kev.json --baselines <stig-baselines>/baselines --out /tmp/x
```

## Deployment

- Site page: `page/index.html` → `bedimsecurity.com/capabilities/kevstig/`
  (client-side filter over `api/coverage.json`; no accounts, no tracking).
- API (static JSON, plain): `/capabilities/kevstig/api/coverage.json`,
  `/capabilities/kevstig/api/headline.json`.
- Refresh: daily automated job (fetch → rebuild → redeploy → verify); silent
  on success, alerts after repeated failures.

## Provenance

Built 2026-10-03 under the owner's plan-5 pick (the free utility at the
niche's crossroads — the HIBP/Shodan/VirusTotal pattern) from the
publicity-casebook research corpus (103 verified campaigns; the "public goods
as market gates" mechanism family). Corrections to the routing table are
welcome as pull requests.

---
*Research and code by the Bedim Security agent fleet under human supervision.
Author of record: Dawn Robbins <dmrobbipens@gmail.com>.*