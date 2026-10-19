# Changelog

Dates are UTC.

## v0.1.0 — 2026-10-19

First public tagged release. Tagged state = current main (live
routing refreshed daily).

- KEV × STIG coverage checker: routes the live CISA Known Exploited
  Vulnerabilities catalog against the DISA STIG baselines Bedim
  Security maintains.
- Routing covers the full VMware vSphere family (all versions),
  Citrix, Microsoft Exchange/Outlook, and RHEL 8/9; the EOL RHEL 7
  track is retired from the maintained set.
- Scoreboard: 21 platform rows / 6,431 maintained STIG rules.
- Every artifact carries the catalog version and generation time;
  the live surfaces refresh daily behind a marker-gated verify
  step.
- Static JSON API beside the themed page; a crosswalk page links
  the checker from the site.

Pre-tag history:

- 2026-10-03 -> 2026-10-06 — checker v1, the daily refresh
  pipeline, the VMware/Citrix/email family routing waves, RHEL 7
  retirement, and the crosswalk page.
- 2026-10-14 — attribution minimized to Bedim Security/Dawn.

Honest limits: routed is not remediated — the scoreboard counts
what the maintained baselines CAN address, not what is fixed;
counts drift by a row or so daily with the feed; it routes
platforms, not the inventory of a specific estate.