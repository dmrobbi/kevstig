#!/usr/bin/env python3
"""kevstig — the KEV x maintained-STIG-baselines coverage checker.

Honest v1 semantics (methodology):
- CISA's Known Exploited Vulnerabilities catalog is the input (daily refresh).
- Each KEV entry is ROUTED to our maintained platform baselines by curated
  product/vendor matching (mapping.json). Routed = "this known-exploited CVE
  touches a platform we maintain a DISA STIG baseline for".
- Routed is NOT "remediated": DISA manual STIGs harden configuration; they do
  not patch individual CVEs. The uncovered list is the honest gap.
- Every artifact carries catalog version + generation time. Usage stats page
  ships from day one (dataset stats + refresh stamps, no fake counters).

Usage: kevstig.py [--kev URL|PATH] --baselines /path/to/stig-baselines --out /tmp/kevstig-deploy
Exit 0 + KEVSTIG-OK on success; nonzero on any gate failure (automation gate).
"""
import argparse, datetime, gzip, io, json, os, re, sys, urllib.request, urllib.error

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
UA = "bedimsecurity-kevstig/1.0 (+https://bedimsecurity.com/capabilities/kevstig/)"
HERE = os.path.dirname(os.path.abspath(__file__))

def load_mapping():
    with open(os.path.join(HERE, "mapping.json"), encoding="utf-8") as fh:
        m = json.load(fh)
    # family: {match: [substrings], platforms: {dirname: display}, version_hints: [regexes]}
    for fam in m["families"]:
        for s in fam["match"]:
            assert isinstance(s, str) and s
        assert fam["platforms"], fam
    return m

def fetch_kev(spec):
    if os.path.exists(spec):
        with open(spec, encoding="utf-8") as fh:
            return json.load(fh), "file:" + spec
    last = None
    for attempt in (1, 2):
        try:
            req = urllib.request.Request(spec or KEV_URL, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8")), (spec or KEV_URL)
        except urllib.error.HTTPError as e:
            wait = e.headers.get("Retry-After")
            last = e
            if e.code == 429 and wait and attempt == 1:
                secs = float(wait)
                import time; time.sleep(min(secs, 120)); continue
            raise
        except Exception as e:  # noqa: BLE001
            if attempt == 1:
                import time; time.sleep(20)
                continue
            raise
    raise last  # pragma: no cover

def route(product, vendor, mapping):
    """Ordered family rules; returns list of platform dirs (may be empty)."""
    text = f"{vendor} {product}".strip().lower()
    out = []
    for fam in mapping["families"]:
        hit = any(s in text for s in fam["match"])
        if hit:
            wins = fam["platforms"]
            specific = []
            for hint in fam.get("version_hints", []):
                if re.search(hint["regex"], text):
                    specific.extend(hint["platforms"])
                    break  # ordered versions first; single hint wins
            if not specific:
                if fam.get("strict"):
                    break  # strict families: no generic fallback
            for s in (specific or list(wins)):
                if s not in out:
                    out.append(s)
            break  # first matching family wins (ordered table)
    if not out:
        for fam in mapping.get("secondary_families", []):
            if any(s in text for s in fam["match"]):
                for k in fam["platforms"]:
                    if k not in out:
                        out.append(k)
                break
    return out

def inventory_baselines(bas, known_platforms, ckl_hints=None):
    """Per platform dir: matching-ckl count + maintained VID count (dedup
    across the matching checklists only — platform dirs may carry sibling
    checklists for other surfaces)."""
    inv = {}
    for pdir in sorted(known_platforms):
        d = os.path.join(bas, pdir)
        hint = (ckl_hints or {}).get(pdir)
        vids = set()
        n = 0
        if os.path.isdir(d):
            for root, _dirs, files in os.walk(d):
                for f in files:
                    if f.lower().endswith(".ckl") and "plus_" not in f \
                            and (not hint or re.search(hint, f, re.IGNORECASE)):
                        n += 1
                        try:
                            with open(os.path.join(root, f), encoding="utf-8",
                                      errors="replace") as fh:
                                txt = fh.read()
                            if "VULN_ATTRIBUTE" in txt:
                                # DISA CKL v2: rule ids live as Vuln_Num data
                                for blk in re.split(r"<VULN>", txt)[1:]:
                                    m = re.search(
                                        r"Vuln_Num</VULN_ATTRIBUTE>\s*"
                                        r"<ATTRIBUTE_DATA>\s*(V-[0-9]+)",
                                        blk)
                                    if m:
                                        vids.add(m.group(1))
                            else:
                                vids |= set(re.findall(
                                    r"<VID>(V-[0-9]+)</VID>", txt))
                        except OSError:
                            pass
        inv[pdir] = {"ckls": n, "vids": sorted(vids), "vid_count": len(vids)}
    return inv

def build(args):
    mapping = load_mapping()
    known = set()
    for fam in mapping["families"] + mapping.get("secondary_families", []):
        known.update(fam["platforms"].keys())

    cat, source = fetch_kev(args.kev)
    vulns = cat.get("vulnerabilities", [])
    if not vulns:
        raise SystemExit("kev parse: no vulns")
    catalog_date = cat.get("dateReleased", "")
    now = datetime.datetime.now(datetime.timezone.utc)

    inv = inventory_baselines(args.baselines, known,
                              mapping.get("ckl_hints", {}))

    cut30 = (now - datetime.timedelta(days=30)).date()
    routed_rows = []
    uncovered = []
    per_platform = {p: {"total": 0, "last30": 0, "newest": ""} for p in known}
    for v in vulns:
        cve = v.get("cveID", "")
        vendor = v.get("vendorProject", "")
        product = v.get("product", "")
        added = v.get("dateAdded", "")
        plats = route(product, vendor, mapping)
        row = {
            "cve": cve, "vendor": vendor, "product": product,
            "name": v.get("vulnerabilityName", ""),
            "description": (v.get("shortDescription", "") or "")[:240],
            "dateAdded": added, "note": v.get("notes", ""),
            "platforms": sorted(plats),
            "coveredByMaintenance": bool(plats),
        }
        routed_rows.append(row)
        if plats:
            for p in plats:
                per_platform[p]["total"] += 1
                try:
                    d = datetime.date.fromisoformat(added[:10])
                except ValueError:
                    d = None
                if d and d >= cut30:
                    per_platform[p]["last30"] += 1
                if d and added > per_platform[p]["newest"]:
                    per_platform[p]["newest"] = added
        else:
            uncovered.append(row)

    platforms_out = []
    for p in sorted(known):
        label = None
        for fam in mapping["families"] + mapping.get("secondary_families", []):
            if p in fam["platforms"]:
                label = fam["platforms"][p]
                break
        st = per_platform[p]
        platforms_out.append({
            "platform": p, "label": label,
            "ckls": inv[p]["ckls"], "rules_maintained": inv[p]["vid_count"],
            "kev_routed_total": st["total"], "kev_routed_30d": st["last30"],
            "newest_KEV": st["newest"],
        })
    routed = sum(1 for r in routed_rows if r["coveredByMaintenance"])

    platforms_out.sort(key=lambda x: -x["kev_routed_total"])

    os.makedirs(os.path.join(args.out, "api"), exist_ok=True)
    def write_json(path, obj):
        raw = json.dumps(obj, indent=1, ensure_ascii=False)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(raw)
        with gzip.open(path + ".gz", "wb") as fh:
            fh.write(raw.encode("utf-8"))

    coverage = {
        "generated_at": now.isoformat(timespec="seconds"),
        "catalog_date": catalog_date, "source": source,
        "catalog_count": len(vulns), "routed_count": routed,
        "uncovered_count": len(uncovered),
        "platforms": platforms_out,
        "entries": routed_rows,
    }
    write_json(os.path.join(args.out, "api", "coverage.json"), coverage)

    headline = {
        "generated_at": coverage["generated_at"],
        "catalog_date": catalog_date,
        "catalog_count": len(vulns),
        "routed_count": routed,
        "uncovered_count": len(uncovered),
        "platform_count": len(known),
        "total_rules_maintained": sum(p["rules_maintained"] for p in platforms_out),
        "top_platforms_30d": [
            {"platform": p["label"], "kev_30d": p["kev_routed_30d"]}
            for p in platforms_out if p["kev_routed_30d"]][:5],
        "note": ("routed = KEV entry touches a platform for which Bedim Security "
                 "maintains a DISA STIG baseline; routed is not remediated"),
    }
    write_json(os.path.join(args.out, "api", "headline.json"), headline)

    # Gates: reload what we wrote, totals must agree; entries subset check
    back = json.load(open(os.path.join(args.out, "api", "coverage.json"),
                          encoding="utf-8"))
    assert back["catalog_count"] == len(vulns)
    assert back["routed_count"] + back["uncovered_count"] == len(vulns)
    bad = [r for r in routed_rows if not set(r["platforms"]) <= known]
    assert not bad, "unknown platform dir route: %s" % (bad[:2],)
    assert os.path.getsize(os.path.join(args.out, "api", "coverage.json")) > 10000
    assert os.path.getsize(os.path.join(args.out, "api", "headline.json")) > 200
    print("KEVSTIG-OK catalog=%d routed=%d uncovered=%d platforms=%d "
          "rules=%d src=%s" % (len(vulns), routed, len(uncovered),
                               len(known),
                               sum(p["rules_maintained"] for p in platforms_out),
                               source))
    return 0

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--kev", default=KEV_URL, help="KEV URL or local JSON path")
    ap.add_argument("--baselines", default="/home/wez/repos/stig-baselines")
    ap.add_argument("--out", default="/tmp/kevstig-deploy")
    a = ap.parse_args()
    sys.exit(build(a))