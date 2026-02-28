#!/usr/bin/env python3
import fnmatch
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any


HOST_RE = re.compile(r"^[a-z0-9.-]+$")


def env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


HOME = str(Path.home())
SOTH_HOME = env("SOTH_HOME_DIR", f"{HOME}/.soth-local")
BUNDLE_PATH = Path(env("SOTH_GATING_BUNDLE_PATH", f"{SOTH_HOME}/bundle/gating/bundle.json"))
DETECT_BUNDLE_PATH = Path(env("SOTH_DETECT_BUNDLE_PATH", f"{SOTH_HOME}/bundle/detect/bundle.json"))
TRACE_PATH = Path(env("SOTH_PIPELINE_TRACE_FILE", f"{SOTH_HOME}/logs/pipeline-trace.ndjson"))
OUT_PATH = Path(
    env(
        "SOTH_GATING_CORPUS_OUT",
        env("SOTH_GATING_CORPUS_OUTPUT", f"{SOTH_HOME}/logs/gating-corpus-results.ndjson"),
    )
)
EVENTS_DB_PATH = Path(env("SOTH_EVENTS_DB_PATH", f"{SOTH_HOME}/logs/events.db"))
PROXY_URL = env("SOTH_PROXY_URL", "http://127.0.0.1:5074")

MAX_TIME_SECS = env_int("SOTH_GATING_CORPUS_TIMEOUT_SECS", 20)
TRACE_SETTLE_SECS = env_float("SOTH_GATING_TRACE_SETTLE_SECS", 0.25)
INTERCEPT_TRACE_EXTRA_WAIT_SECS = env_float("SOTH_GATING_TRACE_INTERCEPT_WAIT_SECS", 1.5)
REQUEST_RETRY_COUNT = env_int("SOTH_GATING_CORPUS_RETRIES", 1)

PROVIDER_LIMIT = env_int("SOTH_GATING_CORPUS_PROVIDER_LIMIT", 36)
METHOD_CASE_LIMIT = env_int("SOTH_GATING_CORPUS_METHOD_LIMIT", 24)
PASSTHROUGH_LIMIT = env_int("SOTH_GATING_CORPUS_PASSTHROUGH_LIMIT", 8)
DENY_CASE_LIMIT = env_int("SOTH_GATING_CORPUS_DENY_LIMIT", 12)
CASE_CAP = env_int("SOTH_GATING_CORPUS_CASE_CAP", 0)

AWS_BEDROCK_RUNTIME_HOST = env(
    "SOTH_GATING_AWS_BEDROCK_RUNTIME_HOST", "bedrock-runtime.us-east-1.amazonaws.com"
).strip().lower()
AWS_BEDROCK_CONTROL_HOST = env(
    "SOTH_GATING_AWS_BEDROCK_CONTROL_HOST", "bedrock.us-east-1.amazonaws.com"
).strip().lower()
AZURE_OPENAI_HOST = env("SOTH_GATING_AZURE_OPENAI_HOST", "").strip().lower()

SKIP_PROVIDER_HOSTS = {"api.tbox.cn", "127.0.0.1", "localhost"}

PARSER_FOR_FORMAT = {
    "openai": "openai-v1",
    "anthropic": "anthropic-v1",
    "cohere": "cohere-v1",
    "google": "gemini-v1",
    "bedrock": "bedrock-v1",
}

PARSE_SOURCE_PROVIDER_FOR_FORMAT = {
    "openai": "open_ai",
    "anthropic": "anthropic",
    "cohere": "cohere",
    "google": "gemini",
    "bedrock": "bedrock",
}


def trim(value: Any) -> str:
    return str(value or "").strip().lower()


def norm_path(path: str | None) -> str:
    if not path:
        return "/"
    return path if path.startswith("/") else f"/{path}"


def concrete_glob(path: str) -> str:
    return path.replace("**", "x").replace("*", "x").replace("?", "q")


def host_matches_pattern(host: str, pattern: Any) -> bool:
    p = trim(pattern)
    if not p:
        return False
    if p.startswith("="):
        return host == p[1:]
    if "*" in p:
        return fnmatch.fnmatch(host, p)
    return host == p


def host_in_tls_catalog(host: str, patterns: list[Any]) -> bool:
    h = trim(host)
    return any(host_matches_pattern(h, p) for p in (patterns or []))


def materialize_provider_host(entity_id: str, pattern: Any) -> str:
    p = trim(pattern)
    if not p:
        return ""
    if p.startswith("="):
        p = p[1:]
    if HOST_RE.match(p):
        return p
    if entity_id == "aws_bedrock" and p == "bedrock-runtime*.amazonaws.com":
        return AWS_BEDROCK_RUNTIME_HOST
    if entity_id == "aws_bedrock" and p == "bedrock*.amazonaws.com":
        return AWS_BEDROCK_CONTROL_HOST
    if entity_id == "azure_openai" and p == "*.openai.azure.com" and AZURE_OPENAI_HOST:
        return AZURE_OPENAI_HOST
    return ""


def materialize_passthrough_host(domain: Any) -> str:
    d = trim(domain)
    if not d:
        return ""
    if d.startswith("="):
        d = d[1:]
    if HOST_RE.match(d):
        return d
    return ""


def method_for(methods: list[str]) -> str:
    mset = {m.upper() for m in (methods or [])}
    if "POST" in mset:
        return "POST"
    if "GET" in mset:
        return "GET"
    return "GET"


def parse_method_for(methods: list[str]) -> str:
    mset = {m.upper() for m in (methods or [])}
    return "POST" if "POST" in mset else "GET"


def path_is_blacklisted(bundle: dict[str, Any], path: str) -> bool:
    p = (path or "").lower()
    stage3 = ((bundle.get("gates") or {}).get("stage3_blacklist") or {})
    needles = (stage3.get("blacklisted_keywords") or []) + (
        stage3.get("blacklisted_path_substrings") or []
    )
    for needle in needles:
        n = trim(needle)
        if n and n in p:
            return True
    return False


def preferred_allow_path(bundle: dict[str, Any], entity_id: str, allow_paths: list[str]) -> str:
    normalized = [concrete_glob(norm_path(p)) for p in (allow_paths or [])]
    for path in normalized:
        if not path_is_blacklisted(bundle, path):
            return path
    if normalized:
        return normalized[0]
    return fallback_path_for(entity_id)


def fallback_path_for(entity_id: str) -> str:
    if entity_id == "openai":
        return "/v1/chat/completions"
    if entity_id == "anthropic":
        return "/v1/messages"
    if entity_id == "azure_openai":
        return "/openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-10-21"
    if entity_id == "aws_bedrock":
        return "/model/amazon.titan-text-premier-v1:0/invoke"
    if entity_id == "cohere":
        return "/v2/chat"
    if entity_id in {"google", "google_vertex"}:
        return "/v1beta/models/gemini-1.5-flash:generateContent?key=demo"
    return "/v1/chat/completions"


def default_parse_path_for(rule: dict[str, Any]) -> str:
    entity_id = rule["entity_id"]
    host = rule["host"]
    api_format = rule["api_format"]

    if api_format == "anthropic":
        return "/v1/messages"
    if api_format == "cohere":
        return "/v2/chat"
    if api_format == "google":
        if "aiplatform.googleapis.com" in host:
            return (
                "/v1/projects/demo/locations/us-central1/publishers/google/"
                "models/gemini-1.5-pro:generateContent"
            )
        return "/v1beta/models/gemini-1.5-flash:generateContent?key=demo"
    if api_format == "bedrock":
        return "/model/amazon.titan-text-premier-v1:0/invoke"
    if entity_id == "openrouter":
        return "/api/v1/responses"
    if entity_id == "azure_openai":
        return "/openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-10-21"
    return "/v1/chat/completions"


def choose_allow_path(bundle: dict[str, Any], rule: dict[str, Any]) -> str:
    candidate = preferred_allow_path(bundle, rule["entity_id"], rule["allow"])
    if rule["allow"]:
        return candidate
    if candidate in {"/", "/v1/models"}:
        return default_parse_path_for(rule)
    return candidate


def prompt_text(variant: str, entity_id: str) -> str:
    if variant == "code":
        return (
            f"{entity_id} corpus code path. Analyze and improve this Rust function:\n"
            "```rust\n"
            "fn fib(n:u32)->u32{if n<2{n}else{fib(n-1)+fib(n-2)}}\n"
            "```\n"
            "Then provide a Python equivalent and complexity notes."
        )
    if variant == "secret":
        return (
            f"{entity_id} corpus secret scan. Please redact these values: "
            "sk-live-1234567890abcdefghijklmnopqrstuv, "
            "AKIAIOSFODNN7EXAMPLE, "
            "-----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkqhki... -----END PRIVATE KEY-----"
        )
    return f"{entity_id} corpus baseline prompt: summarize deterministic test coverage goals."


def body_for_format(api_format: str, variant: str, entity_id: str) -> str:
    prompt = prompt_text(variant, entity_id)
    if api_format == "anthropic":
        body = {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 96,
            "system": "You are a deterministic corpus assistant.",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "stream": False,
        }
        return json.dumps(body, separators=(",", ":"), ensure_ascii=True)

    if api_format == "cohere":
        body = {
            "model": "command-r-plus",
            "message": prompt,
            "chat_history": [{"role": "SYSTEM", "message": "Be concise and deterministic."}],
            "max_tokens": 96,
            "temperature": 0.2,
            "stream": False,
        }
        return json.dumps(body, separators=(",", ":"), ensure_ascii=True)

    if api_format == "google":
        body = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "systemInstruction": {
                "parts": [{"text": "You are a deterministic corpus assistant."}]
            },
            "generationConfig": {
                "maxOutputTokens": 96,
                "temperature": 0.2,
                "topP": 0.9,
            },
        }
        return json.dumps(body, separators=(",", ":"), ensure_ascii=True)

    if api_format == "bedrock":
        body = {
            "modelId": "amazon.titan-text-premier-v1:0",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 96,
            "temperature": 0.2,
        }
        return json.dumps(body, separators=(",", ":"), ensure_ascii=True)

    body = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You are a deterministic corpus assistant."},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 96,
        "temperature": 0.2,
        "stream": False,
    }
    return json.dumps(body, separators=(",", ":"), ensure_ascii=True)


def extra_headers_for_format(api_format: str) -> dict[str, str]:
    headers = {"content-type": "application/json"}
    if api_format == "anthropic":
        headers["anthropic-version"] = "2023-06-01"
    return headers


def expected_parse_provider_for(rule: dict[str, Any], path: str) -> str | None:
    entity_id = rule["entity_id"]
    host = rule["host"]
    api_format = rule["api_format"]

    if api_format == "anthropic":
        return "anthropic"
    if api_format == "cohere":
        return "cohere"
    if api_format == "google":
        return "gemini"
    if entity_id == "openai" and host == "api.openai.com" and "/v1/" in path:
        return "open_ai"
    return None


def load_bundle(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"failed to read bundle: {path} ({exc})", file=sys.stderr)
        sys.exit(1)


def load_detect_bundle(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def provider_api_format_map(detect_bundle: dict[str, Any]) -> dict[str, str]:
    providers = (detect_bundle.get("llm_providers") or {}) if isinstance(detect_bundle, dict) else {}
    out: dict[str, str] = {}
    for provider_id, entry in providers.items():
        if not isinstance(entry, dict):
            continue
        fmt = trim(entry.get("api_format"))
        out[str(provider_id)] = fmt if fmt else "openai"
    return out


def sorted_provider_rules(bundle: dict[str, Any], api_format_map: dict[str, str]) -> list[dict[str, Any]]:
    tls_patterns = (((bundle.get("gates") or {}).get("stage0_tls") or {}).get("tls_intercept_hosts") or [])
    providers = (((bundle.get("entities") or {}).get("providers")) or [])

    rules: list[dict[str, Any]] = []
    for provider in providers:
        entity_id = provider.get("entity_id") or ""
        if not entity_id:
            continue

        api_format = api_format_map.get(entity_id, "openai")
        for host_rule in provider.get("hosts") or []:
            host = materialize_provider_host(entity_id, host_rule.get("pattern"))
            if not host or host in SKIP_PROVIDER_HOSTS:
                continue
            if not host_in_tls_catalog(host, tls_patterns):
                continue
            paths = host_rule.get("paths") or {}
            rules.append(
                {
                    "entity_id": entity_id,
                    "api_format": api_format,
                    "host": host,
                    "methods": host_rule.get("methods") or [],
                    "allow": paths.get("allow") or [],
                    "deny_exact": paths.get("deny_exact") or [],
                    "deny_glob": paths.get("deny_glob") or [],
                }
            )

    rules.sort(key=lambda r: (r["entity_id"], r["host"], r["api_format"]))
    return rules


def make_allow_case(rule: dict[str, Any], path: str, variant: str) -> dict[str, Any]:
    method = parse_method_for(rule["methods"])
    body = body_for_format(rule["api_format"], variant, rule["entity_id"]) if method == "POST" else ""
    headers = extra_headers_for_format(rule["api_format"]) if method == "POST" else {}

    expected_parser = PARSER_FOR_FORMAT.get(rule["api_format"]) if method == "POST" else None
    expected_source_provider = (
        PARSE_SOURCE_PROVIDER_FOR_FORMAT.get(rule["api_format"]) if method == "POST" else None
    )
    expected_provider = expected_parse_provider_for(rule, path) if method == "POST" else None

    return {
        "id": f"allow:{rule['entity_id']}:{rule['host']}:{variant}",
        "scheme": "https",
        "host": rule["host"],
        "method": method,
        "path": path,
        "body": body,
        "headers": headers,
        "expected": "intercept",
        "expect_classify": True,
        "expected_parse_provider": expected_provider,
        "expected_parse_parser": expected_parser,
        "expected_parse_source_provider": expected_source_provider,
    }


def parse_signature_cases(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []

    cases.append(
        {
            "id": "parse:openai:chat_completions",
            "scheme": "https",
            "host": "api.openai.com",
            "method": "POST",
            "path": "/v1/chat/completions",
            "body": body_for_format("openai", "baseline", "openai"),
            "headers": extra_headers_for_format("openai"),
            "expected": "intercept",
            "expect_classify": True,
            "expected_parse_provider": "open_ai",
            "expected_parse_parser": "openai-v1",
            "expected_parse_source_provider": "open_ai",
        }
    )

    cases.append(
        {
            "id": "parse:openai:responses",
            "scheme": "https",
            "host": "api.openai.com",
            "method": "POST",
            "path": "/v1/responses",
            "body": json.dumps(
                {
                    "model": "gpt-4.1-mini",
                    "input": "openai responses corpus probe",
                    "max_output_tokens": 64,
                },
                separators=(",", ":"),
                ensure_ascii=True,
            ),
            "headers": extra_headers_for_format("openai"),
            "expected": "intercept",
            "expect_classify": True,
            "expected_parse_provider": "open_ai",
            "expected_parse_parser": "openai-v1",
            "expected_parse_source_provider": "open_ai",
        }
    )

    cases.append(
        {
            "id": "parse:anthropic:messages",
            "scheme": "https",
            "host": "api.anthropic.com",
            "method": "POST",
            "path": "/v1/messages",
            "body": body_for_format("anthropic", "baseline", "anthropic"),
            "headers": extra_headers_for_format("anthropic"),
            "expected": "intercept",
            "expect_classify": True,
            "expected_parse_provider": "anthropic",
            "expected_parse_parser": "anthropic-v1",
            "expected_parse_source_provider": "anthropic",
        }
    )

    cases.append(
        {
            "id": "parse:cohere:v2_chat",
            "scheme": "https",
            "host": "api.cohere.ai",
            "method": "POST",
            "path": "/v2/chat",
            "body": body_for_format("cohere", "baseline", "cohere"),
            "headers": extra_headers_for_format("cohere"),
            "expected": "intercept",
            "expect_classify": True,
            "expected_parse_provider": "cohere",
            "expected_parse_parser": "cohere-v1",
            "expected_parse_source_provider": "cohere",
        }
    )

    cases.append(
        {
            "id": "parse:google:generate_content",
            "scheme": "https",
            "host": "generativelanguage.googleapis.com",
            "method": "POST",
            "path": "/v1beta/models/gemini-1.5-flash:generateContent?key=demo",
            "body": body_for_format("google", "baseline", "google"),
            "headers": extra_headers_for_format("google"),
            "expected": "intercept",
            "expect_classify": True,
            "expected_parse_provider": "gemini",
            "expected_parse_parser": "gemini-v1",
            "expected_parse_source_provider": "gemini",
        }
    )

    cases.append(
        {
            "id": "parse:bedrock:invoke",
            "scheme": "https",
            "host": AWS_BEDROCK_RUNTIME_HOST,
            "method": "POST",
            "path": "/model/amazon.titan-text-premier-v1:0/invoke",
            "body": body_for_format("bedrock", "baseline", "aws_bedrock"),
            "headers": extra_headers_for_format("bedrock"),
            "expected": "intercept",
            "expect_classify": True,
            "expected_parse_provider": None,
            "expected_parse_parser": "bedrock-v1",
            "expected_parse_source_provider": "bedrock",
        }
    )

    cases.append(
        {
            "id": "parse:openrouter:responses",
            "scheme": "https",
            "host": "openrouter.ai",
            "method": "POST",
            "path": "/api/v1/responses",
            "body": json.dumps(
                {
                    "model": "openai/gpt-4o-mini",
                    "input": "openrouter responses corpus probe",
                    "max_output_tokens": 64,
                },
                separators=(",", ":"),
                ensure_ascii=True,
            ),
            "headers": extra_headers_for_format("openai"),
            "expected": "intercept",
            "expect_classify": True,
            "expected_parse_provider": None,
            "expected_parse_parser": "openai-v1",
            "expected_parse_source_provider": "open_ai",
        }
    )

    if AZURE_OPENAI_HOST:
        cases.append(
            {
                "id": "parse:azure_openai:chat_completions",
                "scheme": "https",
                "host": AZURE_OPENAI_HOST,
                "method": "POST",
                "path": "/openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-10-21",
                "body": body_for_format("openai", "baseline", "azure_openai"),
                "headers": extra_headers_for_format("openai"),
                "expected": "intercept",
                "expect_classify": True,
                "expected_parse_provider": None,
                "expected_parse_parser": "openai-v1",
                "expected_parse_source_provider": "open_ai",
            }
        )

    # json-rpc edge format forcing content-type based detection.
    cases.append(
        {
            "id": "parse:jsonrpc:openai_host",
            "scheme": "https",
            "host": "api.openai.com",
            "method": "POST",
            "path": "/rpc/execute",
            "body": json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "responses.create",
                    "params": {"input": "jsonrpc corpus probe"},
                },
                separators=(",", ":"),
                ensure_ascii=True,
            ),
            "headers": {"content-type": "application/json-rpc"},
            "expected": "intercept",
            "expect_classify": True,
            "expected_parse_provider": None,
            "expected_parse_parser": "jsonrpc-v1",
            "expected_parse_source_provider": None,
        }
    )

    # Keep the original fixed gate controls.
    cases.append(
        {
            "id": "blacklist_keyword:openai:sentry",
            "scheme": "https",
            "host": "api.openai.com",
            "method": "GET",
            "path": "/sentry/ping",
            "body": "",
            "headers": {},
            "expected": "skip",
            "expect_classify": False,
            "expected_parse_provider": None,
            "expected_parse_parser": None,
            "expected_parse_source_provider": None,
        }
    )

    cases.append(
        {
            "id": "tls_intercept_catalog:api.openai.com",
            "scheme": "https",
            "host": "api.openai.com",
            "method": "GET",
            "path": "/v1/models",
            "body": "",
            "headers": {},
            "expected": "tls_intercept",
            "expect_classify": True,
            "expected_parse_provider": None,
            "expected_parse_parser": None,
            "expected_parse_source_provider": None,
        }
    )

    filtered: list[dict[str, Any]] = []
    tls_patterns = (((bundle.get("gates") or {}).get("stage0_tls") or {}).get("tls_intercept_hosts") or [])
    for case in cases:
        if case["expected"] == "tls_passthrough":
            filtered.append(case)
            continue
        if host_in_tls_catalog(case["host"], tls_patterns):
            filtered.append(case)
    return filtered


def generate_cases(bundle: dict[str, Any], detect_bundle: dict[str, Any]) -> list[dict[str, Any]]:
    api_format_map = provider_api_format_map(detect_bundle)
    rules = sorted_provider_rules(bundle, api_format_map)

    selected_rules = rules[: max(0, PROVIDER_LIMIT)]

    allow_cases: list[dict[str, Any]] = []
    variants = ["baseline", "code", "secret"]
    for rule in selected_rules:
        path = choose_allow_path(bundle, rule)
        method = parse_method_for(rule["methods"])
        if method == "POST":
            for variant in variants:
                allow_cases.append(make_allow_case(rule, path, variant))
        else:
            allow_cases.append(make_allow_case(rule, path, "baseline"))

    method_cases: list[dict[str, Any]] = []
    for rule in selected_rules[: max(0, METHOD_CASE_LIMIT)]:
        path = choose_allow_path(bundle, rule)
        method_cases.append(
            {
                "id": f"method_not_allowed:{rule['entity_id']}:{rule['host']}",
                "scheme": "https",
                "host": rule["host"],
                "method": "TRACE",
                "path": path,
                "body": "",
                "headers": {},
                "expected": "skip",
                "expect_classify": False,
                "expected_parse_provider": None,
                "expected_parse_parser": None,
                "expected_parse_source_provider": None,
            }
        )

    deny_cases: list[dict[str, Any]] = []
    for rule in selected_rules:
        if len(deny_cases) >= max(0, DENY_CASE_LIMIT):
            break

        allowed_method = method_for(rule["methods"])
        parser_expect = PARSER_FOR_FORMAT.get(rule["api_format"]) if allowed_method == "POST" else None
        source_expect = (
            PARSE_SOURCE_PROVIDER_FOR_FORMAT.get(rule["api_format"]) if allowed_method == "POST" else None
        )

        for deny_exact in (rule.get("deny_exact") or []):
            if len(deny_cases) >= max(0, DENY_CASE_LIMIT):
                break
            path = norm_path(deny_exact)
            body = (
                body_for_format(rule["api_format"], "baseline", rule["entity_id"])
                if allowed_method == "POST"
                else ""
            )
            headers = extra_headers_for_format(rule["api_format"]) if allowed_method == "POST" else {}
            deny_cases.append(
                {
                    "id": f"path_denied_exact:{rule['entity_id']}:{rule['host']}:{path}",
                    "scheme": "https",
                    "host": rule["host"],
                    "method": allowed_method,
                    "path": path,
                    "body": body,
                    "headers": headers,
                    "expected": "skip",
                    "expect_classify": False,
                    "expected_parse_provider": None,
                    "expected_parse_parser": parser_expect,
                    "expected_parse_source_provider": source_expect,
                }
            )

        for deny_glob in (rule.get("deny_glob") or []):
            if len(deny_cases) >= max(0, DENY_CASE_LIMIT):
                break
            path = norm_path(concrete_glob(deny_glob))
            body = (
                body_for_format(rule["api_format"], "baseline", rule["entity_id"])
                if allowed_method == "POST"
                else ""
            )
            headers = extra_headers_for_format(rule["api_format"]) if allowed_method == "POST" else {}
            deny_cases.append(
                {
                    "id": f"path_denied_glob:{rule['entity_id']}:{rule['host']}:{path}",
                    "scheme": "https",
                    "host": rule["host"],
                    "method": allowed_method,
                    "path": path,
                    "body": body,
                    "headers": headers,
                    "expected": "skip",
                    "expect_classify": False,
                    "expected_parse_provider": None,
                    "expected_parse_parser": parser_expect,
                    "expected_parse_source_provider": source_expect,
                }
            )

    passthrough_domains = (
        (((bundle.get("gates") or {}).get("stage0_tls") or {}).get("passthrough_domains") or [])
    )
    passthrough_hosts: list[str] = []
    for domain in passthrough_domains:
        host = materialize_passthrough_host(domain)
        if host and host not in passthrough_hosts:
            passthrough_hosts.append(host)

    passthrough_cases = [
        {
            "id": f"tls_passthrough:{host}",
            "scheme": "https",
            "host": host,
            "method": "GET",
            "path": "/",
            "body": "",
            "headers": {},
            "expected": "tls_passthrough",
            "expect_classify": False,
            "expected_parse_provider": None,
            "expected_parse_parser": None,
            "expected_parse_source_provider": None,
        }
        for host in passthrough_hosts[: max(0, PASSTHROUGH_LIMIT)]
    ]

    parse_cases = parse_signature_cases(bundle)

    combined = parse_cases + allow_cases + method_cases + deny_cases + passthrough_cases

    deduped: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for case in combined:
        case_id = case["id"]
        if case_id in seen_ids:
            continue
        seen_ids.add(case_id)
        deduped.append(case)

    if CASE_CAP > 0:
        return deduped[:CASE_CAP]
    return deduped


def parse_trace_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def line_count(path: Path) -> int:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return sum(1 for _ in f)


def read_trace_delta(path: Path, pre_lines: int) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f, start=1):
            if idx <= pre_lines:
                continue
            event = parse_trace_line(line)
            if event is not None:
                events.append(event)
    return events


def last_tls_reason_for_host(events: list[dict[str, Any]], host: str) -> Any:
    h = trim(host)
    for evt in reversed(events):
        if evt.get("event") != "tls_stage":
            continue
        if trim(evt.get("host")) != h:
            continue
        return evt.get("reason")
    return None


def find_connection_id(events: list[dict[str, Any]], case: dict[str, Any]) -> str | None:
    host = trim(case["host"])
    method = trim(case["method"]).upper()
    path = case["path"]

    for evt in reversed(events):
        if evt.get("event") != "http_gate_outcome":
            continue
        if trim(evt.get("host")) != host:
            continue
        if trim(evt.get("method")).upper() != method:
            continue
        if (evt.get("path") or "") != path:
            continue
        cid = evt.get("connection_id")
        if isinstance(cid, str) and cid:
            return cid

    for evt in reversed(events):
        if evt.get("event") != "gate_stage":
            continue
        cid = evt.get("connection_id")
        if isinstance(cid, str) and cid:
            return cid
    return None


def last_conn_value(events: list[dict[str, Any]], event_name: str, connection_id: str, field: str) -> Any:
    for evt in reversed(events):
        if evt.get("event") == event_name and evt.get("connection_id") == connection_id:
            return evt.get(field)
    return None


def parse_source_provider(value: Any) -> Any:
    if isinstance(value, dict):
        provider = value.get("provider")
        return provider if isinstance(provider, str) else None
    return None


def capture_observation(events: list[dict[str, Any]], case: dict[str, Any]) -> dict[str, Any]:
    connection_id = find_connection_id(events, case)
    tls_reason = last_tls_reason_for_host(events, case["host"])

    gate_verdict = None
    gate_reason = None
    gate_stage = None
    http_decision = None
    http_reason = None

    detect_provider = None
    detect_confidence = None
    detect_source = None
    detect_source_provider = None
    detect_parser = None
    detect_is_ai = None
    detect_warnings = None

    classify_event_id = None
    classify_policy_kind = None
    classify_policy_decision = None

    db_write_status = None
    db_write_event_id = None

    if connection_id:
        gate_verdict = last_conn_value(events, "gate_stage", connection_id, "verdict")
        gate_reason = last_conn_value(events, "gate_stage", connection_id, "reason")
        gate_stage = last_conn_value(events, "gate_stage", connection_id, "gate")

        http_decision = last_conn_value(events, "http_gate_outcome", connection_id, "decision")
        http_reason = last_conn_value(events, "http_gate_outcome", connection_id, "reason")

        detect_provider = last_conn_value(events, "detect_summary", connection_id, "provider")
        detect_confidence = last_conn_value(events, "detect_summary", connection_id, "parse_confidence")
        detect_source = last_conn_value(events, "detect_summary", connection_id, "parse_source")
        detect_source_provider = parse_source_provider(detect_source)
        detect_parser = last_conn_value(events, "detect_summary", connection_id, "parser_id")
        detect_is_ai = last_conn_value(events, "detect_summary", connection_id, "is_ai_call")
        detect_warnings = last_conn_value(events, "detect_summary", connection_id, "warnings_count")

        classify_event_id = last_conn_value(events, "classify_result", connection_id, "event_id")
        classify_policy_kind = last_conn_value(events, "classify_result", connection_id, "policy_kind")
        classify_policy_decision = last_conn_value(events, "classify_result", connection_id, "policy_decision")

        db_write_status = last_conn_value(events, "db_write", connection_id, "status")
        db_write_event_id = last_conn_value(events, "db_write", connection_id, "event_id")

    return {
        "connection_id": connection_id,
        "tls_reason": tls_reason,
        "terminal_gate_stage": gate_stage,
        "terminal_gate_verdict": gate_verdict,
        "terminal_gate_reason": gate_reason,
        "http_decision": http_decision,
        "http_reason": http_reason,
        "detect": {
            "provider": detect_provider,
            "parse_confidence": detect_confidence,
            "parse_source": detect_source,
            "parse_source_provider": detect_source_provider,
            "parser_id": detect_parser,
            "is_ai_call": detect_is_ai if isinstance(detect_is_ai, bool) else None,
            "warnings_count": detect_warnings if isinstance(detect_warnings, int) else None,
        },
        "classify": {
            "event_id": classify_event_id,
            "policy_kind": classify_policy_kind,
            "policy_decision": classify_policy_decision,
        },
        "db": {
            "write_status": db_write_status,
            "event_id": db_write_event_id,
        },
    }


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    pre_lines = line_count(TRACE_PATH)
    url = f"{case['scheme']}://{case['host']}{case['path']}"

    cmd = [
        "curl",
        "-sS",
        "-k",
        "--max-time",
        str(MAX_TIME_SECS),
        "-x",
        PROXY_URL,
        "-X",
        case["method"],
    ]

    for key, value in (case.get("headers") or {}).items():
        cmd.extend(["-H", f"{key}: {value}"])

    if case["method"] in {"POST", "PUT", "PATCH"}:
        cmd.extend(["-d", case.get("body") or ""])

    cmd.extend(["-o", "/dev/null", "-w", "%{http_code} %{http_version}\\n", url])

    proc = None
    curl_out = "000 0"
    proto = "0"
    status = None
    curl_error = None
    attempts = max(1, REQUEST_RETRY_COUNT + 1)
    for attempt in range(attempts):
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        curl_out = proc.stdout.strip() or "000 0"
        parts = curl_out.split(maxsplit=1)
        status_raw = parts[0] if parts else "000"
        proto = parts[1] if len(parts) > 1 else "0"
        status = int(status_raw) if status_raw.isdigit() else None
        curl_error = " ".join(proc.stderr.split()) if proc.stderr else None
        if proc.returncode == 0:
            break
        if attempt + 1 < attempts:
            time.sleep(0.2)

    time.sleep(TRACE_SETTLE_SECS)

    events = read_trace_delta(TRACE_PATH, pre_lines)
    observed = capture_observation(events, case)

    if case.get("expected") in {"intercept", "tls_intercept"} and (
        not observed["classify"]["event_id"] or not observed["db"]["write_status"]
    ):
        deadline = time.time() + max(0.0, INTERCEPT_TRACE_EXTRA_WAIT_SECS)
        while time.time() < deadline:
            time.sleep(0.15)
            events = read_trace_delta(TRACE_PATH, pre_lines)
            observed = capture_observation(events, case)
            if observed["classify"]["event_id"] and observed["db"]["write_status"]:
                break

    return {
        "id": case["id"],
        "expected": case["expected"],
        "expect_classify": bool(case.get("expect_classify", False)),
        "expected_parse_provider": case.get("expected_parse_provider"),
        "expected_parse_parser": case.get("expected_parse_parser"),
        "expected_parse_source_provider": case.get("expected_parse_source_provider"),
        "request": {
            "method": case["method"],
            "url": url,
            "body_len": len(case.get("body") or ""),
        },
        "transport": {
            "status": status,
            "protocol": proto,
            "curl_exit": proc.returncode,
            "curl_error": curl_error,
        },
        "trace": {
            "connection_id": observed["connection_id"],
            "tls_reason": observed["tls_reason"],
            "terminal_gate_stage": observed["terminal_gate_stage"],
            "terminal_gate_verdict": observed["terminal_gate_verdict"],
            "terminal_gate_reason": observed["terminal_gate_reason"],
            "http_decision": observed["http_decision"],
            "http_reason": observed["http_reason"],
        },
        "detect": observed["detect"],
        "classify": observed["classify"],
        "db": observed["db"],
        "telemetry": {
            "db_row_present": None,
            "db_path": str(EVENTS_DB_PATH),
        },
    }


def annotate_db_rows(rows: list[dict[str, Any]]) -> None:
    event_ids = []
    for row in rows:
        event_id = ((row.get("classify") or {}).get("event_id")) or ((row.get("db") or {}).get("event_id"))
        if isinstance(event_id, str) and event_id:
            event_ids.append(event_id)

    if not event_ids:
        return

    if not EVENTS_DB_PATH.is_file():
        return

    try:
        conn = sqlite3.connect(EVENTS_DB_PATH)
    except sqlite3.Error:
        return

    try:
        seen: set[str] = set()
        unique_ids = list(dict.fromkeys(event_ids))
        chunk_size = 400
        for i in range(0, len(unique_ids), chunk_size):
            chunk = unique_ids[i : i + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            sql = f"SELECT event_id FROM intercept_records WHERE event_id IN ({placeholders})"
            for row in conn.execute(sql, chunk):
                if row and row[0]:
                    seen.add(str(row[0]))

        for record in rows:
            telemetry = record.get("telemetry") or {}
            event_id = ((record.get("classify") or {}).get("event_id")) or ((record.get("db") or {}).get("event_id"))
            telemetry["db_row_present"] = bool(event_id in seen)
            record["telemetry"] = telemetry
    finally:
        conn.close()


def score_rows(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    scored_rows: list[dict[str, Any]] = []

    for row in rows:
        expected = row.get("expected") or ""
        decision = ((row.get("trace") or {}).get("http_decision")) or ""
        verdict = ((row.get("trace") or {}).get("terminal_gate_verdict")) or ""
        tls_reason = ((row.get("trace") or {}).get("tls_reason")) or ""

        if expected == "intercept":
            gate_pass = decision == "intercept" or verdict == "intercept"
        elif expected == "skip":
            gate_pass = decision == "skip" or verdict == "skip"
        elif expected == "tls_passthrough":
            gate_pass = (
                tls_reason == "tls_passthrough_domain"
                or verdict == "passthrough"
                or decision == "passthrough"
            )
        elif expected == "tls_intercept":
            gate_pass = tls_reason == "tls_intercept_catalog"
        else:
            gate_pass = False

        detect = row.get("detect") or {}
        expected_provider = row.get("expected_parse_provider") or ""
        expected_parser = row.get("expected_parse_parser") or ""
        expected_source_provider = row.get("expected_parse_source_provider") or ""

        provider_ok = True if not expected_provider else (detect.get("provider") == expected_provider)
        parser_ok = True if not expected_parser else (detect.get("parser_id") == expected_parser)
        source_provider_ok = (
            True
            if not expected_source_provider
            else (detect.get("parse_source_provider") == expected_source_provider)
        )
        parse_expected = bool(expected_provider or expected_parser or expected_source_provider)
        parse_pass = provider_ok and parser_ok and source_provider_ok

        classify_expected = bool(row.get("expect_classify")) and expected in {"intercept", "tls_intercept"}
        classify = row.get("classify") or {}
        db = row.get("db") or {}
        classify_pass = True
        if classify_expected:
            classify_pass = bool(classify.get("event_id")) and db.get("write_status") == "ok"

        telemetry_expected = classify_expected
        telemetry = row.get("telemetry") or {}
        telemetry_pass = True
        if telemetry_expected:
            telemetry_pass = telemetry.get("db_row_present") is True

        overall_pass = gate_pass and parse_pass and classify_pass and telemetry_pass

        row_copy = dict(row)
        row_copy["gate_pass"] = gate_pass
        row_copy["parse_pass"] = parse_pass
        row_copy["parse_expected"] = parse_expected
        row_copy["classify_pass"] = classify_pass
        row_copy["classify_expected"] = classify_expected
        row_copy["telemetry_pass"] = telemetry_pass
        row_copy["telemetry_expected"] = telemetry_expected
        row_copy["overall_pass"] = overall_pass
        scored_rows.append(row_copy)

    gate_failed_cases = []
    parse_failed_cases = []
    classify_failed_cases = []
    telemetry_failed_cases = []

    for row in scored_rows:
        if not row["gate_pass"]:
            trace = row.get("trace") or {}
            transport = row.get("transport") or {}
            gate_failed_cases.append(
                {
                    "id": row.get("id"),
                    "expected": row.get("expected"),
                    "status": transport.get("status"),
                    "reason": (
                        trace.get("http_reason")
                        or trace.get("terminal_gate_reason")
                        or trace.get("tls_reason")
                        or "none"
                    ),
                }
            )

        if row.get("parse_expected") and not row["parse_pass"]:
            detect = row.get("detect") or {}
            parse_failed_cases.append(
                {
                    "id": row.get("id"),
                    "expected_parse_provider": row.get("expected_parse_provider"),
                    "expected_parse_parser": row.get("expected_parse_parser"),
                    "expected_parse_source_provider": row.get("expected_parse_source_provider"),
                    "observed_provider": detect.get("provider"),
                    "observed_parser": detect.get("parser_id"),
                    "observed_parse_source_provider": detect.get("parse_source_provider"),
                }
            )

        if row.get("classify_expected") and not row["classify_pass"]:
            classify = row.get("classify") or {}
            db = row.get("db") or {}
            classify_failed_cases.append(
                {
                    "id": row.get("id"),
                    "classify_event_id": classify.get("event_id"),
                    "db_write_status": db.get("write_status"),
                    "db_event_id": db.get("event_id"),
                }
            )

        if row.get("telemetry_expected") and not row["telemetry_pass"]:
            telemetry = row.get("telemetry") or {}
            classify = row.get("classify") or {}
            telemetry_failed_cases.append(
                {
                    "id": row.get("id"),
                    "classify_event_id": classify.get("event_id"),
                    "db_row_present": telemetry.get("db_row_present"),
                }
            )

    summary = {
        "total": len(scored_rows),
        "gate_passed": sum(1 for r in scored_rows if r["gate_pass"]),
        "gate_failed": sum(1 for r in scored_rows if not r["gate_pass"]),
        "parse_expected": sum(1 for r in scored_rows if r["parse_expected"]),
        "parse_matched": sum(1 for r in scored_rows if r["parse_expected"] and r["parse_pass"]),
        "classify_expected": sum(1 for r in scored_rows if r["classify_expected"]),
        "classify_matched": sum(
            1 for r in scored_rows if r["classify_expected"] and r["classify_pass"]
        ),
        "telemetry_expected": sum(1 for r in scored_rows if r["telemetry_expected"]),
        "telemetry_matched": sum(
            1 for r in scored_rows if r["telemetry_expected"] and r["telemetry_pass"]
        ),
        "overall_passed": sum(1 for r in scored_rows if r["overall_pass"]),
        "overall_failed": sum(1 for r in scored_rows if not r["overall_pass"]),
        "gate_failed_cases": gate_failed_cases,
        "parse_failed_cases": parse_failed_cases,
        "classify_failed_cases": classify_failed_cases,
        "telemetry_failed_cases": telemetry_failed_cases,
    }
    return scored_rows, summary


def print_gate_verdict_summary(rows: list[dict[str, Any]]) -> None:
    counter = Counter(((r.get("trace") or {}).get("terminal_gate_verdict")) or "none" for r in rows)
    for verdict, count in counter.most_common():
        print(f"{count:4d} {verdict}")


def print_case_mix(cases: list[dict[str, Any]]) -> None:
    prefix_counts = Counter((c.get("id") or "").split(":", 1)[0] for c in cases)
    print("Case Mix:")
    for key, count in prefix_counts.most_common():
        print(f"  {key:20s} {count:4d}")


def main() -> int:
    if not BUNDLE_PATH.is_file():
        print(f"bundle not found: {BUNDLE_PATH}", file=sys.stderr)
        return 1
    if not TRACE_PATH.is_file():
        print(f"trace file not found: {TRACE_PATH}", file=sys.stderr)
        print("start proxy with dev trace enabled first (SOTH_PIPELINE_TRACE=1)", file=sys.stderr)
        return 1

    bundle = load_bundle(BUNDLE_PATH)
    detect_bundle = load_detect_bundle(DETECT_BUNDLE_PATH)
    cases = generate_cases(bundle, detect_bundle)
    if not cases:
        print(f"no cases generated from bundle: {BUNDLE_PATH}", file=sys.stderr)
        return 1

    rows: list[dict[str, Any]] = []
    for case in cases:
        row = run_case(case)
        rows.append(row)

    annotate_db_rows(rows)
    scored_rows, summary = score_rows(rows)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w", encoding="utf-8") as f:
        for row in scored_rows:
            json.dump(row, f, ensure_ascii=True, separators=(",", ":"))
            f.write("\n")

    print(f"Generated {len(cases)} cases from {BUNDLE_PATH}")
    print_case_mix(cases)
    print(f"Wrote results to {OUT_PATH}")
    print("Gate Verdict Summary:")
    print_gate_verdict_summary(scored_rows)

    print("Score Summary:")
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
