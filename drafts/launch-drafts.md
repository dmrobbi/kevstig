# kevstig launch drafts (STAGED — nothing sends without the owner's gate)

_Status: drafts only, 2026-10-03. The posting path stays owner-gated: the
HISTORIC note said the digest blast would run through authorize_activity, but
the owner's trigger word ("send the digest blast", 2026-10-04 16:05 UTC) was
honored via the simpler path documented the same day: send_digest-style direct
mail. DIGEST BLAST: SENT 2026-10-04 16:05 UTC to the active subscriber list
(one subscriber; email scrubbed from this public file 2026-10-14 per the
repo-scrub rule) via drafts/send_launch_blast.py (same From/Reply-To/unsub
token conventions as the daily digest; .digest-last untouched). HN/X posts:
STILL DRAFTS — awaiting owner review + channel access (copy-paste or tokens).
Voice rule from the casebook: numbers, artifacts,
no adjectives. 2026-10-06: numbers refreshed to the post-retire build (1,734 /
298 / 1,436 / 6,431 rules across 21 platform rows — the RHEL 7 EOL track retired
and archived on the owner's call); the sent digest-blast record below stays as
the historical record._

## 1. Show HN post

**Title:** `Show HN: kevstig — a live routing table between CISA's KEV catalog and DISA STIG baselines`

**First-comment text:**

> kevstig answers one question: of CISA's known-exploited vulnerabilities
> (1,734 entries today), how many touch platforms for which a maintained DISA
> STIG baseline exists — and how many fall in the gap (appliances, web apps,
> middleware).
>
> Today: 298 routed, 1,436 uncovered, 6,431 STIG rules across the maintained
> set (Windows, macOS, RHEL 8/9, Ubuntu 20.04/22.04/24.04; the full VMware
> estate — vSphere 6.5/6.7/7.0/8.0 as per-generation rows plus vRealize
> Operations/Automation, NSX, Horizon, Workspace ONE; Citrix Virtual Apps and
> Desktops; Microsoft Exchange + Outlook; Firefox). The uncovered count is
> published deliberately — it is the honest boundary of the baseline set, not
> marketing.
>
> Semantics live on the page: routed is not remediated. DISA manual STIGs
> harden configuration; they do not patch CVEs. The routing table is curated
> JSON in the repo — corrections are pull requests.
>
> Runnable, no signup: https://bedimsecurity.com/capabilities/kevstig/
> API (plain JSON): https://bedimsecurity.com/capabilities/kevstig/api/coverage.json
> Repo: https://github.com/dmrobbi/kevstig
>
> Refreshed daily by an automated job (fetch -> rebuild -> redeploy -> verify).

## 2. X post

> Is that exploited CVE in your hardening baseline's neighborhood?
> kevstig: a live routing table between CISA's KEV catalog and the DISA STIG
> baselines we maintain — 298 of 1,734 routed, the 1,436-entry gap published
> on purpose. Per-CVE checks, public JSON API, refreshed nightly.
> https://bedimsecurity.com/capabilities/kevstig/

## 3. Digest blast (email, sent via the posting path after owner authorization)

**Subject:** `New live tool: KEV x STIG coverage checker`

**Body:**

> We just published kevstig — a live routing table between CISA's
> known-exploited vulnerability catalog and the DISA STIG baselines we
> maintain: per-CVE checks, a platform scoreboard, and the honest uncovered
> gap (published on purpose; routed is not remediated — the methodology is on
> the page).
>
> Open it: https://bedimsecurity.com/capabilities/kevstig/
> Public JSON API: https://bedimsecurity.com/capabilities/kevstig/api/coverage.json
> Source + routing table: https://github.com/dmrobbi/kevstig
>
> Refreshed daily by an automated job. Unsubscribe anytime — every digest
> carries the link.
>
> — Bedim Security (composed by the agent fleet under human supervision)

## 4. soc-disk-health addon — Reddit announcements (PRACTICE — staged 2026-10-14)

_Status: drafts only, added 2026-10-14. This section is the agent PRACTICING
announcement writing and social advertising — learning the best formats by
drafting, not sending. Suggestions and tips from the owner are welcome and
will be folded back in. Nothing sends without the owner's explicit gate.
The practice commentary + collected advice live on darth under
`~/.openclaw/workspace/.reddit/` for future analysis._

**Product:** soc-disk-health — SMART physical-disk health monitoring addon
for an OpenClaw/Wazuh SOC (smartd on bare-metal hosts + a Wazuh rules file
+ a nightly producer that trends disk telemetry into the estate's realtime
JSONL and posts breach alerts to the ingest server).
**Links:** https://github.com/dmrobbi/soc-disk-health ·
companion runbook: https://github.com/dmrobbi/soc-openclaw

### 4a. r/selfhosted draft

**Title:** `I gave my home-lab SOC physical-disk monitoring: bare-metal SMART health into Wazuh alerts and nightly trend rows`

**Body:**

> Home-lab lesson learned this week: an SOC that watches services and logs
> can still go blind the day a disk starts dying — SMART health is not in
> any log file.
>
> So I built a small addon around smartd for our OpenClaw/Wazuh setup:
>
> - smartd on every bare-metal host watches health status, the SMART
>   error log, and temperature (`-W 4,65,0`), logging failures at
>   LOG_CRIT — a small Wazuh rules file turns those into SOC alerts.
> - A nightly producer sweeps every physical disk (local + SSH-reachable
>   hosts) and appends one flat JSONL row per device — device, model,
>   temperature, percentage_used, critical_warning, media_errors and its
>   run-over-run growth — into the file the SOC already ships off-host
>   every 5 minutes, so dashboards trend it.
> - Hosts without an agent still alert: the producer posts Wazuh-shaped
>   breach alerts to the ingest server itself.
> - Thresholds: critical_warning != 0, media-error growth,
>   percentage_used >= 90%, temperature >= 65 C.
>
> Verified end-to-end on real hardware before publishing: forced a
> threshold trip, watched the real syslog message become a manager rule
> match, an indexed alert, and an incident.
>
> Two honest gaps stated up front: VMs are covered through their host's
> physical disks (no per-VM virtual-disk telemetry), and agentless hosts
> get alerts only at the nightly sweep.
>
> Repo (MIT): https://github.com/dmrobbi/soc-disk-health
> Companion SOC runbook: https://github.com/dmrobbi/soc-openclaw
>
> Feedback welcome — especially from anyone running smartd at scale: I
> kept the config minimal rather than enabling every reporting directive.

### 4b. r/sysadmin draft (variant — ops voice, less personal)

**Title:** `Pattern for SOC disk-health coverage: smartd + Wazuh rules + a nightly SMART trend row`

**Body:**

> Sharing a pattern that closed a real gap for us: the SOC watched
> services and logs, but nothing watched the disks. smartd plus two small
> integrations fixed it without new infrastructure:
>
> 1. smartd, minimal config: `-H -l error -W 4,65,0` per device; optional
>    nightly short self-test.
> 2. Manager rules keyed off the stock smartd pre-match so health
>    failures, error-log growth, and temperature-limit crossings become
>    alerts (level 10-12).
> 3. A nightly smartctl sweep emitting one flat JSONL row per device into
>    the pipeline the SIEM already ships (temperature, percentage_used,
>    critical_warning, media_errors + growth delta).
> 4. Agentless hosts: the sweep posts breach alerts straight to the
>    ingest endpoint.
>
> Traps hit, documented in the repo: some NVMe drives report "Self-tests
> not supported" (leave the self-test directive off their smartd line),
> and `systemctl enable` without `--now` leaves the timer unarmed —
> list-timers showed zero timers while the install step claimed success.
>
> Repo + configs (MIT): https://github.com/dmrobbi/soc-disk-health

### 4c. r/opensource draft (launcher voice)

**Title:** `soc-disk-health: an MIT addon that adds physical-disk health monitoring to an OpenClaw/Wazuh SOC`

**Body:**

> New repo: the SOC-watching-itself problem, disk edition. Most home- and
> small-team SOC setups monitor services, logs, and vulnerabilities — the
> physical disks are assumed healthy until they are not.
>
> soc-disk-health is three pieces, all existing tools: smartd (health,
> error log, temperature), a Wazuh rules file for smartd's syslog
> severity messages, and a stdlib-only Python producer that emits a flat
> per-device JSONL row nightly (temperature, percentage_used,
> critical_warning, media_errors + growth) and posts breach alerts to the
> SOC's ingest endpoint when the host is agentless.
>
> MIT, stdlib only, no signup: https://github.com/dmrobbi/soc-disk-health
> Thresholds: critical_warning != 0 | media growth | percentage_used >=
> 90 | temperature >= 65 C. Corrections and config improvements more
> than welcome.