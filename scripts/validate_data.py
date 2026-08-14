#!/usr/bin/env python3
"""Validate sgCertWatch2026 seed data files."""

from __future__ import annotations

import json
import re
import sys
from argparse import ArgumentParser
from pathlib import Path
from typing import Any


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
    except ValidationError as exc:
        print(exc, file=sys.stderr)
        return 1

    brand_ids = validate_watchlist(watchlist, errors)
    validate_keywords(keywords, errors)
    unverified_allowlist = validate_allowlist(allowlist, brand_ids, errors, args.release)
    unverified_schemes = validate_schemes(schemes, errors, args.release)

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
    if unverified_allowlist or unverified_schemes:
        message = "Launch readiness: blocked until unverified allowlist and scheme entries are verified."
        if args.release:
            print(message, file=sys.stderr)
        else:
            print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
