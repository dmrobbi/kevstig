#!/usr/bin/env python3
"""Kevstig LAUNCH blast (one-shot, owner-gated 2026-10-04): the staged
launch email from drafts/launch-drafts.md, sent to the active subscriber
list with the digest machinery's conventions (From reports@bedimsecurity.com
via mailcow SMTP, per-subscriber one-click unsub token, text + HTML).

Deliberately separate from the daily digest: does NOT touch .digest-last.
Usage: python3 send_launch_blast.py [--to EMAIL]  (--to = test send)
"""
import json, smtplib, ssl, sys
from email.message import EmailMessage
from email.utils import formataddr

BASE = '/home/wez/.openclaw/soc/news/'
SUBS = BASE + 'subscribers.json'
ENV = '/home/wez/.openclaw/soc/secrets/reports-mailbox.env'

SUBJECT = 'New live tool: KEV x STIG coverage checker'
TEXT = """We just published kevstig — a live routing table between CISA's
known-exploited vulnerability catalog and the DISA STIG baselines we
maintain: per-CVE checks, a platform scoreboard, and the honest uncovered
gap (published on purpose; routed is not remediated — the methodology is
on the page).

Open it: https://bedimsecurity.com/capabilities/kevstig/
Public JSON API: https://bedimsecurity.com/capabilities/kevstig/api/coverage.json
Source + routing table: https://github.com/dmrobbi/kevstig

Refreshed daily by an automated job. Unsubscribe anytime — every digest
carries the link.

— Bedim Security (composed by the agent fleet under human supervision)
"""
FOOTER = '\n\nUnsubscribe (one click): https://bedimsecurity.com/news/unsub?u=%TOKEN%\nEvery message we send comes from an @bedimsecurity.com address.'

HTML = """<div style="max-width:600px;margin:0 auto;font-family:-apple-system,Segoe UI,Arial,sans-serif;color:#1a2233;">
<div style="background:#1a2233;color:#c9a96a;padding:18px 20px;font-family:Georgia,serif;letter-spacing:.12em;font-size:18px;">BEDIM&nbsp;SECURITY</div>
<div style="padding:20px;border:1px solid #e9ecf1;border-top:0;">
<p style="margin:0 0 4px;font-size:15px;color:#1a2233;"><strong>New live tool: KEV x STIG coverage checker</strong></p>
<p style="margin:0 0 14px;font-size:13px;color:#5a6478;">From the team that maintains open DISA STIG baselines.</p>
<p style="margin:0 0 12px;font-size:14px;color:#2f3a4f;line-height:1.5;">We just published <strong>kevstig</strong> &mdash; a live routing table between CISA's known-exploited vulnerability catalog and the DISA STIG baselines we maintain: per-CVE checks, a platform scoreboard, and the honest uncovered gap (published on purpose; routed is not remediated &mdash; the methodology is on the page).</p>
<p style="margin:0 0 4px;font-size:14px;">Open it: <a href="https://bedimsecurity.com/capabilities/kevstig/" style="color:#a7873f;">bedimsecurity.com/capabilities/kevstig/</a></p>
<p style="margin:0 0 4px;font-size:14px;">Public JSON API: <a href="https://bedimsecurity.com/capabilities/kevstig/api/coverage.json" style="color:#a7873f;">.../api/coverage.json</a></p>
<p style="margin:0 0 14px;font-size:14px;">Source + routing table: <a href="https://github.com/dmrobbi/kevstig" style="color:#a7873f;">github.com/dmrobbi/kevstig</a></p>
<p style="margin:0 0 0;font-size:14px;color:#2f3a4f;">Refreshed daily by an automated job. Unsubscribe anytime &mdash; every digest carries the link.</p>
<p style="margin:14px 0 0;font-size:12px;color:#5a6478;">You receive this because you subscribed at bedimsecurity.com. <a href="https://bedimsecurity.com/news/unsub?u=%TOKEN%" style="color:#a7873f;">Unsubscribe in one click</a> &mdash; it completes within a few hours. Every message we send comes from an @bedimsecurity.com address.</p>
<p style="margin:14px 0 0;font-size:12px;color:#5a6478;">&mdash; Bedim Security (composed by the agent fleet under human supervision)</p>
</div></div>"""

def load_env(path):
    env = {}
    for line in open(path):
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, _, v = line.partition('=')
            env[k.strip()] = v.strip()
    return env

def main():
    to_filter = None
    if '--to' in sys.argv:
        to_filter = sys.argv[sys.argv.index('--to') + 1]
    store = json.load(open(SUBS))
    subs = [s for s in store.get('subscribers', []) if not s.get('removed')]
    env = load_env(ENV)
    host, port = env['SMTP_HOST'], int(env.get('SMTP_PORT', '587'))
    user, pw = env['REPORTS_MAILBOX'], env['REPORTS_MAILBOX_PW']
    text = TEXT + FOOTER
    sent = 0
    ctx = ssl.create_default_context()
    # Private encrypted route to the mailcow host; cert does not cover the
    # Tailscale IP (same compromise as the daily digest).
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for s in subs:
        to = s['email']
        if to_filter and to != to_filter:
            continue
        msg = EmailMessage()
        msg['Subject'] = SUBJECT
        msg['From'] = formataddr(('Bedim Security', user))
        msg['To'] = to
        msg['Reply-To'] = 'info@bedimsecurity.com'
        msg.set_content(text.replace('%TOKEN%', s['token']))
        msg.add_alternative(HTML.replace('%TOKEN%', s['token']), subtype='html')
        with smtplib.SMTP(host, port, timeout=60) as smtp:
            smtp.starttls(context=ctx)
            smtp.login(user, pw)
            smtp.send_message(msg)
        sent += 1
        print('sent to', to)
    if sent == 0:
        print('BLAST ERROR: no mail sent')
        sys.exit(1)
    print('BLAST-OK', sent, 'recipient(s)')

main()