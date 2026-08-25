#!/usr/bin/env python3
"""Allowlist source-tier verification tool.

Classifies every verified allowlist entry into source tiers:
  tier 1 - source URL lives on the allowlisted registrable itself
  tier 2 - source URL is an official parent (same registrable family, e.g. gov.sg)
  tier 3 - anything else (third-party / stale evidence)

With --purge-tier3, tier-3 entries are removed from allowlist.json.
Without flags, prints a report and exits non-zero when any entry's
source URL is unreachable (HTTP >= 400 or network error).
"""
import argparse
import json
import sys
import urllib.request
import urllib.error
from urllib.parse import urlparse

TIMEOUT_SECONDS = 10
USER_AGENT = "sgCertWatch-allowlist-verifier/1.0"


def load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def registrable_of(url):
    host = (urlparse(url).hostname or "").lower()
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2:] not in (["com", "sg"], ["gov", "sg"], ["edu", "sg"], ["org", "sg"], ["net", "sg"], ["per", "sg"]):
        return ".".join(parts[-3:])
    return host


def classify_tier(entry):
    source = entry.get("source") or ""
    reg = entry.get("registrable", "").lower()
    src_host = (urlparse(source).hostname or "").lower()
    if not src_host:
        return 3
    if src_host == reg or src_host.endswith("." + reg):
        return 1
    src_parts = src_host.split(".")
    reg_parts = reg.split(".")
    if len(src_parts) >= 2 and len(reg_parts) >= 2 and src_parts[-1] == reg_parts[-1]:
        return 2
    if reg.endswith(".gov.sg") and src_host.endswith(".gov.sg"):
        return 2
    return 3


def check_url(url):
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return resp.status < 400
    except urllib.error.HTTPError as e:
        if e.code in (403, 405, 501):
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            try:
                with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                    return resp.status < 400
            except Exception:
                return False
        return False
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--purge-tier3", action="store_true",
                        help="remove tier-3 entries from allowlist.json")
    parser.add_argument("--skip-network", action="store_true",
                        help="only classify tiers; do not probe source URLs")
    args = parser.parse_args()

    data = load_json("allowlist.json")
    entries = data.get("entries", [])

    tiers = {1: [], 2: [], 3: []}
    for entry in entries:
        tier = entry.get("tier") or classify_tier(entry)
        entry["tier"] = tier
        tiers[tier].append(entry)

    print(f"Allowlist entries: {len(entries)}")
    print(f"  tier 1 (self-source):      {len(tiers[1])}")
    print(f"  tier 2 (official parent):  {len(tiers[2])}")
    print(f"  tier 3 (weak/third-party): {len(tiers[3])}")

    if args.purge_tier3 and tiers[3]:
        purged = [e["registrable"] for e in tiers[3]]
        data["entries"] = [e for e in entries if e not in tiers[3]]
        save_json("allowlist.json", data)
        print(f"Purged {len(purged)} tier-3 entries: {purged}")

    failures = []
    if not args.skip_network:
        for entry in entries:
            url = entry.get("source") or ""
            if not url.startswith("http"):
                failures.append((entry["registrable"], url, "missing/invalid source URL"))
                continue
            ok = check_url(url)
            status = "ok" if ok else "UNREACHABLE"
            print(f"  [{status}] {entry['registrable']} <- {url}")
            if not ok:
                failures.append((entry["registrable"], url, "unreachable"))

    if failures:
        print(f"\nSource verification FAILURES: {len(failures)}")
        for reg, url, reason in failures:
            print(f"  {reg}: {reason} ({url})")
        sys.exit(1)

    print("\nAll allowlist sources verified.")


if __name__ == "__main__":
    main()
