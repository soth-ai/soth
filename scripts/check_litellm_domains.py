#!/usr/bin/env python3
"""Check/optionally sync SOTH AI inference domains against LiteLLM provider endpoints.

Usage examples:
  python3 scripts/check_litellm_domains.py
  python3 scripts/check_litellm_domains.py --source-file /tmp/provider_endpoint_support.json
  python3 scripts/check_litellm_domains.py --apply
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any


DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/BerriAI/litellm/main/"
    "provider_endpoints_support.json"
)
DEFAULT_DOMAINS_FILE = Path("domains/ai_inference.yaml")

URL_HOST_RE = re.compile(r"https?://([a-zA-Z0-9*._:-]+)")
HOST_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_*.-])([*a-zA-Z0-9_-]+(?:\.[*a-zA-Z0-9_-]+)+)(?![A-Za-z0-9_-])"
)
SAFE_HOST_RE = re.compile(r"^[a-z0-9*.-]+$")

IGNORE_HOSTS = {
    "github.com",
    "docs.github.com",
    "docs.litellm.ai",
    "litellm.ai",
    "localhost",
}
IGNORE_SUFFIXES = (
    ".md",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".js",
    ".css",
)


def read_text_from_url(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "soth-litellm-domain-check/1.0",
            "Accept": "application/json,text/plain,*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        data = response.read()
    return data.decode("utf-8")


def load_json(source_url: str, source_file: Path | None) -> Any:
    if source_file is not None:
        return json.loads(source_file.read_text(encoding="utf-8"))
    return json.loads(read_text_from_url(source_url))


def load_ai_domains(path: Path) -> list[str]:
    domains: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line.startswith("-"):
            continue
        value = line[1:].strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
        value = value.strip()
        if value:
            domains.append(value)
    return domains


def write_ai_domains(path: Path, domains: list[str]) -> None:
    original_lines = path.read_text(encoding="utf-8").splitlines()
    prefix: list[str] = []
    found_domains_header = False

    for line in original_lines:
        prefix.append(line)
        if line.strip() == "domains:":
            found_domains_header = True
            break

    if not found_domains_header:
        prefix = ["# AI inference/API domains", "domains:"]

    body = [f'  - "{domain}"' for domain in domains]
    content = "\n".join(prefix + body) + "\n"
    path.write_text(content, encoding="utf-8")


def normalize_host(raw_host: str) -> str | None:
    host = raw_host.strip().strip(".,;:!?()[]{}<>\"'")
    if not host:
        return None

    if "://" not in host and "/" in host:
        host = host.split("/", 1)[0]
    if "://" in host:
        parsed = urllib.parse.urlparse(host if host.startswith("http") else f"https://{host}")
        host = parsed.hostname or host
    if ":" in host and not host.startswith("["):
        host = host.split(":", 1)[0]

    host = host.lstrip("*.").lower().strip(".")
    if not host or "." not in host:
        return None
    if not SAFE_HOST_RE.match(host):
        return None
    if host in IGNORE_HOSTS:
        return None
    if host.endswith(IGNORE_SUFFIXES):
        return None
    return host


def extract_hosts_from_text(text: str) -> set[str]:
    hosts: set[str] = set()

    for match in URL_HOST_RE.finditer(text):
        host = normalize_host(match.group(1))
        if host:
            hosts.add(host)

    for match in HOST_TOKEN_RE.finditer(text):
        host = normalize_host(match.group(1))
        if host:
            hosts.add(host)

    return hosts


def iter_strings(node: Any, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], str]]:
    out: list[tuple[tuple[str, ...], str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            out.extend(iter_strings(value, path + (str(key),)))
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            out.extend(iter_strings(value, path + (str(idx),)))
    elif isinstance(node, str):
        out.append((path, node))
    return out


def is_host_covered(host: str, configured_domains: list[str]) -> bool:
    for pattern in configured_domains:
        p = pattern.lower().strip().strip(".,")
        if not p:
            continue
        if p.startswith("*."):
            suffix = p[2:]
            if host == suffix or host.endswith(f".{suffix}"):
                return True
            continue
        if "*" in p:
            if fnmatch.fnmatch(host, p):
                return True
            continue
        if host == p:
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--domains-file",
        type=Path,
        default=DEFAULT_DOMAINS_FILE,
        help="Path to domains/ai_inference.yaml",
    )
    parser.add_argument(
        "--source-url",
        default=DEFAULT_SOURCE_URL,
        help="LiteLLM provider endpoint support JSON URL",
    )
    parser.add_argument(
        "--source-file",
        type=Path,
        default=None,
        help="Read LiteLLM provider endpoint support JSON from a local file",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when uncovered hosts are found",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Append uncovered exact hosts to the domains file (sorted, deduplicated)",
    )
    args = parser.parse_args()

    configured = load_ai_domains(args.domains_file)
    try:
        upstream = load_json(args.source_url, args.source_file)
    except Exception as exc:
        source_label = str(args.source_file) if args.source_file else args.source_url
        print(f"Failed to load LiteLLM endpoint data from {source_label}: {exc}", file=sys.stderr)
        return 1

    host_sources: dict[str, set[str]] = defaultdict(set)
    for path, text in iter_strings(upstream):
        for host in extract_hosts_from_text(text):
            if host.endswith("litellm.ai"):
                continue
            host_sources[host].add(".".join(path[-3:]) if path else "<root>")

    upstream_hosts = sorted(host_sources.keys())
    uncovered = [host for host in upstream_hosts if not is_host_covered(host, configured)]

    print(f"Configured AI inference domains: {len(configured)}")
    print(f"LiteLLM-discovered endpoint hosts: {len(upstream_hosts)}")
    print(f"Uncovered hosts: {len(uncovered)}")

    if uncovered:
        print("\nMissing host coverage:")
        for host in uncovered:
            source_hint = ", ".join(sorted(host_sources[host])[:3])
            print(f"- {host}  (from: {source_hint})")

        print("\nSuggested additions (exact hosts):")
        for host in uncovered:
            print(f'  - "{host}"')

        if args.apply:
            merged = sorted(set(configured + uncovered))
            write_ai_domains(args.domains_file, merged)
            print(
                f"\nUpdated {args.domains_file} with {len(uncovered)} uncovered hosts "
                f"({len(merged)} total entries)."
            )

    if uncovered and args.strict:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
