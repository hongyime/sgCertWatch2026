#!/usr/bin/env python3
"""Validate sgCertWatch2026 seed data files."""

from __future__ import annotations

import json
import re
import sys
from argparse import ArgumentParser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
REGISTRABLE_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
TLD_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
TOKEN_RE = re.compile(r"^[a-z0-9]+$")


class ValidationError(Exception):
    pass


def load_json(name: str) -> dict[str, Any]:
    path = ROOT / name
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError(f"{name}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValidationError(f"{name}: top-level value must be an object")
    return data


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def require_string(value: Any, path: str, errors: list[str]) -> None:
    require(isinstance(value, str) and bool(value.strip()), f"{path}: must be a non-empty string", errors)


def require_bool(value: Any, path: str, errors: list[str]) -> None:
    require(isinstance(value, bool), f"{path}: must be a boolean", errors)


def require_token_list(value: Any, path: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or not value:
        errors.append(f"{path}: must be a non-empty list")
        return []
    tokens: list[str] = []
    seen: set[str] = set()
    for index, token in enumerate(value):
        token_path = f"{path}[{index}]"
        if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
            errors.append(f"{token_path}: must be lowercase alphanumeric")
            continue
        if token in seen:
            errors.append(f"{token_path}: duplicate token '{token}'")
        seen.add(token)
        tokens.append(token)
    return tokens


def require_registrable(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not REGISTRABLE_RE.fullmatch(value):
        errors.append(f"{path}: must be a lowercase registrable domain")


def validate_watchlist(data: dict[str, Any], errors: list[str]) -> set[str]:
    require(data.get("version") == 1, "watchlist.json: version must be 1", errors)
    brands = data.get("brands")
    if not isinstance(brands, list) or not brands:
        errors.append("watchlist.json: brands must be a non-empty list")
        return set()

    brand_ids: set[str] = set()
    all_tokens: set[str] = set()
    for index, brand in enumerate(brands):
        path = f"watchlist.json: brands[{index}]"
        if not isinstance(brand, dict):
            errors.append(f"{path}: must be an object")
            continue

        brand_id = brand.get("id")
        require_string(brand_id, f"{path}.id", errors)
        if isinstance(brand_id, str):
            require(TOKEN_RE.fullmatch(brand_id) is not None, f"{path}.id: must be lowercase alphanumeric", errors)
            require(brand_id not in brand_ids, f"{path}.id: duplicate brand id '{brand_id}'", errors)
            brand_ids.add(brand_id)

        require_string(brand.get("display"), f"{path}.display", errors)
        require_string(brand.get("category"), f"{path}.category", errors)
        require(isinstance(brand.get("max_edit_distance"), int) and 0 <= brand["max_edit_distance"] <= 2, f"{path}.max_edit_distance: must be 0, 1, or 2", errors)
        require_bool(brand.get("require_context"), f"{path}.require_context", errors)
        require_bool(brand.get("allow_affix"), f"{path}.allow_affix", errors)

        tokens = require_token_list(brand.get("tokens"), f"{path}.tokens", errors)
        for token in tokens:
            if token in all_tokens:
                errors.append(f"{path}.tokens: token '{token}' is used by multiple brands")
            all_tokens.add(token)

        require_token_list(brand.get("context_tokens"), f"{path}.context_tokens", errors)
        tlds = brand.get("known_tlds")
        if not isinstance(tlds, list) or not tlds:
            errors.append(f"{path}.known_tlds: must be a non-empty list")
        else:
            for tld_index, tld in enumerate(tlds):
                require(isinstance(tld, str) and TLD_RE.fullmatch(tld) is not None, f"{path}.known_tlds[{tld_index}]: must be a plausible TLD string", errors)

    return brand_ids


def validate_keywords(data: dict[str, Any], errors: list[str]) -> set[str]:
    require(data.get("version") == 1, "keywords.json: version must be 1", errors)
    keywords = data.get("keywords")
    if not isinstance(keywords, list) or not keywords:
        errors.append("keywords.json: keywords must be a non-empty list")
        return set()

    tokens: set[str] = set()
    for index, keyword in enumerate(keywords):
        path = f"keywords.json: keywords[{index}]"
        if not isinstance(keyword, dict):
            errors.append(f"{path}: must be an object")
            continue
        token = keyword.get("token")
        require_string(token, f"{path}.token", errors)
        if isinstance(token, str):
            require(TOKEN_RE.fullmatch(token) is not None, f"{path}.token: must be lowercase alphanumeric", errors)
            require(token not in tokens, f"{path}.token: duplicate token '{token}'", errors)
            tokens.add(token)
        require_string(keyword.get("category"), f"{path}.category", errors)
        require_bool(keyword.get("affix"), f"{path}.affix", errors)
    return tokens


def validate_verified_metadata(entry: dict[str, Any], path: str, errors: list[str]) -> None:
    require_string(entry.get("verified_at"), f"{path}.verified_at", errors)
    require(isinstance(entry.get("source"), str) and entry["source"].startswith("https://"), f"{path}.source: must be an https URL", errors)


def validate_allowlist(data: dict[str, Any], brand_ids: set[str], errors: list[str], release: bool) -> int:
    require(data.get("version") == 1, "allowlist.json: version must be 1", errors)
    entries = data.get("entries")
    if not isinstance(entries, list):
        errors.append("allowlist.json: entries must be a list")
        return 0

    seen: set[tuple[str, str]] = set()
    unverified = 0
    for index, entry in enumerate(entries):
        path = f"allowlist.json: entries[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{path}: must be an object")
            continue
        registrable = entry.get("registrable")
        brand = entry.get("brand")
        require_registrable(registrable, f"{path}.registrable", errors)
        require_string(brand, f"{path}.brand", errors)
        if isinstance(brand, str):
            require(brand in brand_ids, f"{path}.brand: unknown brand id '{brand}'", errors)
        require_bool(entry.get("verified"), f"{path}.verified", errors)
        if entry.get("verified") is False:
            unverified += 1
        elif entry.get("verified") is True:
            validate_verified_metadata(entry, path, errors)
        if isinstance(registrable, str) and isinstance(brand, str):
            key = (registrable, brand)
            require(key not in seen, f"{path}: duplicate allowlist entry '{registrable}' for '{brand}'", errors)
            seen.add(key)

    removal_requests = data.get("removal_requests", {}).get("entries", [])
    require(isinstance(removal_requests, list), "allowlist.json: removal_requests.entries must be a list", errors)
    if release and unverified:
        errors.append(f"allowlist.json: {unverified} entries are unverified; release readiness requires all entries to be verified")
    return unverified


def validate_schemes(data: dict[str, Any], errors: list[str], release: bool) -> int:
    require(data.get("version") == 1, "schemes.json: version must be 1", errors)
    schemes = data.get("schemes")
    if not isinstance(schemes, list) or not schemes:
        errors.append("schemes.json: schemes must be a non-empty list")
        return 0

    ids: set[str] = set()
    tokens: set[str] = set()
    unverified = 0
    for index, scheme in enumerate(schemes):
        path = f"schemes.json: schemes[{index}]"
        if not isinstance(scheme, dict):
            errors.append(f"{path}: must be an object")
            continue
        scheme_id = scheme.get("id")
        require_string(scheme_id, f"{path}.id", errors)
        if isinstance(scheme_id, str):
            require(re.fullmatch(r"[a-z0-9_]+", scheme_id) is not None, f"{path}.id: must be lowercase snake_case", errors)
            require(scheme_id not in ids, f"{path}.id: duplicate scheme id '{scheme_id}'", errors)
            ids.add(scheme_id)
        require_string(scheme.get("display"), f"{path}.display", errors)
        for token in require_token_list(scheme.get("tokens"), f"{path}.tokens", errors):
            require(token not in tokens, f"{path}.tokens: token '{token}' is used by multiple schemes", errors)
            tokens.add(token)
        require(isinstance(scheme.get("max_edit_distance"), int) and 0 <= scheme["max_edit_distance"] <= 2, f"{path}.max_edit_distance: must be 0, 1, or 2", errors)
        require_registrable(scheme.get("official_registrable"), f"{path}.official_registrable", errors)
        require_bool(scheme.get("verified"), f"{path}.verified", errors)
        if scheme.get("verified") is False:
            unverified += 1
        elif scheme.get("verified") is True:
            validate_verified_metadata(scheme, path, errors)
        active_window = scheme.get("active_window")
        require(active_window is None or isinstance(active_window, dict), f"{path}.active_window: must be null or an object", errors)
    if release and unverified:
        errors.append(f"schemes.json: {unverified} entries are unverified; release readiness requires all entries to be verified")
    return unverified


def validate_scoring(data: dict[str, Any], errors: list[str]) -> None:
    path = "scoring.json"
    version = data.get("version")
    require(isinstance(version, int) and version >= 1, f"{path}: version must be a positive integer", errors)

    weights = data.get("weights")
    if not isinstance(weights, dict) or not weights:
        errors.append(f"{path}: weights must be a non-empty object")
    else:
        for k, v in weights.items():
            if not isinstance(v, int) or v < 0:
                errors.append(f"{path}.weights.{k}: must be a non-negative integer")

    thresholds = data.get("thresholds")
    if not isinstance(thresholds, dict):
        errors.append(f"{path}: thresholds must be an object")
    else:
        p_min = thresholds.get("persist_min")
        d_min = thresholds.get("dashboard_min")
        dig_min = thresholds.get("digest_min")
        a_min = thresholds.get("alert_min")
        for name, val in [("persist_min", p_min), ("dashboard_min", d_min), ("digest_min", dig_min), ("alert_min", a_min)]:
            if not isinstance(val, int) or val < 0:
                errors.append(f"{path}.thresholds.{name}: must be a non-negative integer")
        if isinstance(p_min, int) and isinstance(d_min, int) and isinstance(dig_min, int) and isinstance(a_min, int):
            require(p_min <= d_min < dig_min < a_min, f"{path}.thresholds: must be strictly increasing (persist_min <= dashboard_min < digest_min < alert_min)", errors)

    caps = data.get("caps")
    if not isinstance(caps, dict) or not isinstance(caps.get("total"), int):
        errors.append(f"{path}: caps.total must be an integer")
    elif isinstance(weights, dict):
        num_weights = [v for v in weights.values() if isinstance(v, int)]
        top3_sum = sum(sorted(num_weights, reverse=True)[:3])
        if caps["total"] < top3_sum:
            errors.append(f"{path}: caps.total ({caps['total']}) must be >= sum of 3 largest weights ({top3_sum})")


def validate_scoring_keys_referenced(keywords: dict[str, Any], schemes: dict[str, Any], errors: list[str]) -> None:
    lib_dir = ROOT / "lib"
    js_files = list(lib_dir.glob("**/*.js"))
    all_code = "\n".join(f.read_text(encoding="utf-8") for f in js_files)

    kw_scoring = keywords.get("scoring", {})
    if isinstance(kw_scoring, dict):
        for key in kw_scoring.keys():
            if key in ("note", "_comment"):
                continue
            if key not in all_code:
                errors.append(f"keywords.json: scoring key '{key}' is never referenced in lib/")

    scheme_scoring = schemes.get("scoring", {})
    if isinstance(scheme_scoring, dict):
        for key in scheme_scoring.keys():
            if key in ("note", "_comment"):
                continue
            if key not in all_code:
                errors.append(f"schemes.json: scoring key '{key}' is never referenced in lib/")


# Source-ref format contracts per declared feed source. Flat feeds (openphish
# feed.txt) never emit '#fragment' sub-records; a fragment there is fabricated
# provenance. Hosts must match the declared source's domain.
SOURCE_REF_CONTRACTS = {
    "openphish": {
        "host_suffix": "openphish.com",
        "allow_fragment": False,
    },
    "phishtank": {
        "host_suffix": "phishtank.org",
        "allow_fragment": False,
        "path_pattern": r"^/phish_detail\.php$",
        "require_query_id": True,
    },
    "urlhaus": {
        "host_suffix": "urlhaus.abuse.ch",
        "allow_fragment": False,
        "path_pattern": r"^/url/\d+$",
    },
}


def validate_corpus_provenance(corpus: dict[str, Any], errors: list[str]) -> None:
    """E2 (Instruction Set B2): a positive item's source_ref must match its declared
    source's record format. Fabricated provenance is a hard failure."""
    items = corpus.get("items") or []
    sequential_ids: dict[str, list[int]] = {}
    for idx, item in enumerate(items):
        if item.get("label") != "positive":
            continue
        path = f"corpus.json.items[{idx}]"
        source = item.get("source")
        ref = item.get("source_ref")
        if not ref:
            if not item.get("constructed"):
                errors.append(f"{path}: positive without source_ref must be constructed:true")
            continue
        contract = SOURCE_REF_CONTRACTS.get(source)
        if contract is None:
            continue
        parsed = urlparse(ref)
        host = (parsed.hostname or '').lower()
        if not host.endswith(contract['host_suffix']):
            errors.append(f"{path}: source_ref host '{host}' does not match declared source '{source}'")
            continue
        if parsed.fragment and not contract.get('allow_fragment', True):
            errors.append(f"{path}: source_ref carries a '#'fragment but {source} feeds are flat lists with no sub-records")
        path_re = contract.get("path_pattern")
        if path_re and not re.match(path_re, parsed.path or ''):
            errors.append(f"{path}: source_ref path '{parsed.path}' does not match {source} record format")
        if contract.get('require_query_id'):
            m = re.search(r'[?&]id=(\d+)', parsed.query or '')
            if m:
                sequential_ids.setdefault(source, []).append(int(m.group(1)))
    # Perfectly consecutive id blocks across many entries are a generation artifact.
    for src, ids in sequential_ids.items():
        ids_sorted = sorted(ids)
        run = 1
        for prev, cur in zip(ids_sorted, ids_sorted[1:]):
            run = run + 1 if cur == prev + 1 else 1
            if run >= 10:
                errors.append(
                    f"corpus.json: {src} source_ref ids form a strictly consecutive block "
                    f"(>=10 running from {ids_sorted[0]}); real feed assignments are not sequential"
                )
                break

def main() -> int:
    parser = ArgumentParser(description="Validate sgCertWatch2026 seed data files.")
    parser.add_argument("--release", action="store_true", help="fail if launch-readiness verification is incomplete")
    args = parser.parse_args()

    errors: list[str] = []
    try:
        watchlist = load_json("watchlist.json")
        keywords = load_json("keywords.json")
        allowlist = load_json("allowlist.json")
        schemes = load_json("schemes.json")
        scoring = load_json("scoring.json")
    except ValidationError as exc:
        print(exc, file=sys.stderr)
        return 1

    brand_ids = validate_watchlist(watchlist, errors)
    validate_keywords(keywords, errors)
    unverified_allowlist = validate_allowlist(allowlist, brand_ids, errors, args.release)
    unverified_schemes = validate_schemes(schemes, errors, args.release)
    validate_scoring(scoring, errors)
    validate_scoring_keys_referenced(keywords, schemes, errors)
    if Path('corpus.json').exists():
        validate_corpus_provenance(load_json('corpus.json'), errors)

    if errors:
        print("Data validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print("Data validation passed.")
    print(f"Brands: {len(watchlist['brands'])}")
    print(f"Keywords: {len(keywords['keywords'])}")
    print(f"Allowlist entries: {len(allowlist['entries'])} ({unverified_allowlist} unverified)")
    print(f"Schemes: {len(schemes['schemes'])} ({unverified_schemes} unverified)")
    print(f"Scoring version: {scoring.get('version')} ({len(scoring.get('weights', {}))} weights)")
    if unverified_allowlist or unverified_schemes:
        message = "Launch readiness: blocked until unverified allowlist and scheme entries are verified."
        if args.release:
            print(message, file=sys.stderr)
        else:
            print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
