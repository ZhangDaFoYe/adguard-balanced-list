#!/usr/bin/env python3
"""Download, normalize, deduplicate, and merge DNS blocklists."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCES = ROOT / "sources.json"
DEFAULT_OUTPUT = ROOT / "dist" / "adguard-balanced.txt"
DEFAULT_STATS = ROOT / "dist" / "stats.json"
MIN_RULES = 20_000
USER_AGENT = "adguard-balanced-list/1.0"
REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "OWNER/adguard-balanced-list")

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)
ADBLOCK_DOMAIN_RE = re.compile(r"^\|\|([^/^$*|]+)\^(?:\$.*)?$", re.IGNORECASE)
DNSMASQ_RE = re.compile(r"^(?:address|server)=/([^/]+)/", re.IGNORECASE)
HOSTS_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::|::1)\s+([^\s#]+)", re.IGNORECASE)


@dataclass(frozen=True)
class Source:
    name: str
    url: str


def load_sources(path: Path) -> list[Source]:
    data = json.loads(path.read_text(encoding="utf-8"))
    sources = [Source(str(x["name"]), str(x["url"])) for x in data["sources"]]
    if not sources:
        raise ValueError("sources.json contains no sources")
    return sources


def download(source: Source, timeout: int = 60) -> bytes:
    request = urllib.request.Request(source.url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        status = getattr(response, "status", 200)
        if status != 200:
            raise RuntimeError(f"{source.name}: HTTP {status}")
        payload = response.read(32 * 1024 * 1024 + 1)
    if len(payload) > 32 * 1024 * 1024:
        raise RuntimeError(f"{source.name}: response larger than 32 MiB")
    if len(payload) < 100:
        raise RuntimeError(f"{source.name}: response unexpectedly small ({len(payload)} bytes)")
    return payload


def normalize_domain(value: str) -> str | None:
    domain = value.strip().strip(".").lower()
    if not domain or domain == "localhost" or domain.endswith(".local"):
        return None
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass
    if DOMAIN_RE.fullmatch(domain):
        return domain
    return None


def parse_rule(line: str) -> tuple[str, str] | None:
    """Return (kind, value), where kind is domain or raw."""
    value = line.strip().lstrip("\ufeff")
    if not value or value.startswith(("!", "#", "[", ";", "//")):
        return None
    if value.startswith(("@@", "/", "#@#", "#?#", "#$#")):
        return None

    match = ADBLOCK_DOMAIN_RE.fullmatch(value)
    if match:
        domain = normalize_domain(match.group(1))
        return ("domain", domain) if domain else None

    match = HOSTS_RE.match(value)
    if match:
        domain = normalize_domain(match.group(1))
        return ("domain", domain) if domain else None

    match = DNSMASQ_RE.match(value)
    if match:
        domain = normalize_domain(match.group(1))
        return ("domain", domain) if domain else None

    domain = normalize_domain(value)
    if domain:
        return "domain", domain

    # Keep valid advanced AdGuard rules that cannot safely be reduced to a domain.
    if value.startswith("||") or value.startswith("|"):
        return "raw", value
    return None


def collapse_domains(domains: set[str]) -> list[str]:
    """Remove child domains already covered by a parent domain rule."""
    kept: set[str] = set()
    for domain in sorted(domains, key=lambda item: (item.count("."), item)):
        labels = domain.split(".")
        covered = any(".".join(labels[index:]) in kept for index in range(1, len(labels) - 1))
        if not covered:
            kept.add(domain)
    return sorted(kept)


def merge(payloads: list[tuple[Source, bytes]]) -> tuple[str, dict]:
    domains: set[str] = set()
    raw_rules: set[str] = set()
    source_stats = []

    for source, payload in payloads:
        parsed = 0
        source_domains: set[str] = set()
        source_raw: set[str] = set()
        text = payload.decode("utf-8", errors="replace")
        for line in text.splitlines():
            rule = parse_rule(line)
            if not rule:
                continue
            parsed += 1
            kind, value = rule
            if kind == "domain":
                source_domains.add(value)
                domains.add(value)
            else:
                source_raw.add(value)
                raw_rules.add(value)
        if not source_domains and not source_raw:
            raise RuntimeError(f"{source.name}: downloaded list produced no usable rules")
        source_stats.append(
            {
                "name": source.name,
                "url": source.url,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "parsed_lines": parsed,
                "unique_domains": len(source_domains),
                "unique_advanced_rules": len(source_raw),
            }
        )

    collapsed = collapse_domains(domains)
    output_rules = [f"||{domain}^" for domain in collapsed] + sorted(raw_rules)
    if len(output_rules) < MIN_RULES:
        raise RuntimeError(f"refusing to publish only {len(output_rules)} rules; minimum is {MIN_RULES}")

    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    header = [
        "! Title: AdGuard Balanced List",
        "! Description: OISD Small + AWAvenue + URLHaus, normalized and deduplicated",
        f"! Homepage: https://github.com/{REPOSITORY}",
        f"! Last modified: {generated}",
        f"! Expires: 1 day (update frequency)",
        f"! Rules: {len(output_rules)}",
        "! License: Each source retains its own license and terms",
        "!",
    ]
    content = "\n".join(header + output_rules) + "\n"
    stats = {
        "generated_at": generated,
        "source_count": len(payloads),
        "unique_domains_before_parent_collapse": len(domains),
        "unique_domains_after_parent_collapse": len(collapsed),
        "unique_advanced_rules": len(raw_rules),
        "output_rules": len(output_rules),
        "output_sha256": hashlib.sha256(content.encode()).hexdigest(),
        "sources": source_stats,
    }
    return content, stats


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--stats", type=Path, default=DEFAULT_STATS)
    parser.add_argument("--fixture-dir", type=Path)
    args = parser.parse_args()

    sources = load_sources(args.sources)
    payloads = []
    for index, source in enumerate(sources, start=1):
        if args.fixture_dir:
            payload = (args.fixture_dir / f"{index}.txt").read_bytes()
        else:
            print(f"Downloading {source.name}: {source.url}", file=sys.stderr)
            payload = download(source)
        payloads.append((source, payload))

    content, stats = merge(payloads)
    atomic_write(args.output, content)
    atomic_write(args.stats, json.dumps(stats, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
