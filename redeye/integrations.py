"""Integration settings for each tool/connector.

Declares the settings each integration needs (URL, username, API key, ...) and
which are *sensitive* (secret). Sensitive values are never stored in config --
the daemon keeps them in the encrypted key vault and stores only a `vault:<id>`
reference. resolve_env() turns the stored settings back into environment
variables for the tool's server process (resolving vault references).
"""
from __future__ import annotations

# type: "text" | "url" | "secret"; env: the env var the server reads (optional)
# multiple: whether several independent instances can be configured (e.g. two
# Tenable tenants, several AWS accounts).
SCHEMAS = {
    "aws": {"name": "AWS", "multiple": True, "fields": [
        {"key": "region", "label": "Region", "type": "text", "env": "AWS_DEFAULT_REGION"},
        {"key": "access_key_id", "label": "Access Key ID", "type": "text", "env": "AWS_ACCESS_KEY_ID"},
        {"key": "secret_access_key", "label": "Secret Access Key", "type": "secret", "env": "AWS_SECRET_ACCESS_KEY"},
    ]},
    "crowdstrike": {"name": "CrowdStrike Falcon", "multiple": True, "fields": [
        {"key": "base_url", "label": "Base URL", "type": "url", "env": "FALCON_BASE_URL"},
        {"key": "client_id", "label": "Client ID", "type": "text", "env": "FALCON_CLIENT_ID"},
        {"key": "client_secret", "label": "Client Secret", "type": "secret", "env": "FALCON_CLIENT_SECRET"},
    ]},
    "tenable": {"name": "Tenable", "multiple": True, "fields": [
        {"key": "base_url", "label": "Base URL", "type": "url", "env": "TENABLE_URL"},
        {"key": "access_key", "label": "Access Key", "type": "secret", "env": "TENABLE_ACCESS_KEY"},
        {"key": "secret_key", "label": "Secret Key", "type": "secret", "env": "TENABLE_SECRET_KEY"},
    ]},
    "wiz": {"name": "Wiz", "multiple": True, "fields": [
        {"key": "api_url", "label": "API URL", "type": "url", "env": "WIZ_API_URL"},
        {"key": "client_id", "label": "Client ID", "type": "text", "env": "WIZ_CLIENT_ID"},
        {"key": "client_secret", "label": "Client Secret", "type": "secret", "env": "WIZ_CLIENT_SECRET"},
    ]},
    "http-probe": {"name": "HTTP probe", "multiple": False, "fields": [
        {"key": "default_username", "label": "Default username", "type": "text", "env": ""},
        {"key": "default_password", "label": "Default password", "type": "secret", "env": ""},
    ]},
    "subfinder": {"name": "subfinder", "multiple": False, "fields": [
        {"key": "binary", "label": "Binary path", "type": "text", "env": ""},
        {"key": "shodan_api_key", "label": "Shodan API key", "type": "secret", "env": "SHODAN_API_KEY"},
    ]},
}

# scanners that just run a local binary get a single (non-sensitive) path field
_SCANNER_DEFAULT = [{"key": "binary", "label": "Binary path", "type": "text", "env": ""}]


def schema_for(key: str, name: str = "") -> dict:
    s = SCHEMAS.get(key)
    if s:
        return s
    return {"name": name or key, "multiple": False,
            "fields": [dict(f) for f in _SCANNER_DEFAULT]}


def multiple(key: str) -> bool:
    return bool(schema_for(key).get("multiple", False))


def is_secret(field: dict) -> bool:
    return field.get("type") == "secret"


def resolve_env(tool: str, values: dict, reveal) -> dict:
    """values: {field_key: raw str}; reveal(vault_id)->secret str."""
    env = {}
    for f in schema_for(tool)["fields"]:
        if not f.get("env"):
            continue
        raw = str(values.get(f["key"], "") or "")
        if not raw:
            continue
        val = raw
        if is_secret(f) and raw.startswith("vault:"):
            val = reveal(raw.split(":", 1)[1]) or ""
        if val:
            env[f["env"]] = val
    return env
