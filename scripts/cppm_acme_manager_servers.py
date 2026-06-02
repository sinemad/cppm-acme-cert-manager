#!/usr/bin/env python3
"""
cppm_acme_manager_servers.py – CLI server management for the CPPM ACME cert manager.

Manages the ClearPass server entries stored in /data/certs/servers.json.  Each
entry maps a ClearPass Policy Manager host to its ACME certificate authority and
DNS provider configuration.

Usage (run inside the container via docker exec):
    docker exec -it cppm-acme-cert-manager cppm-servers list
    docker exec -it cppm-acme-cert-manager cppm-servers show <id>
    docker exec -it cppm-acme-cert-manager cppm-servers add
    docker exec -it cppm-acme-cert-manager cppm-servers edit <id>
    docker exec -it cppm-acme-cert-manager cppm-servers delete <id>

Notes:
    - Server IDs are UUIDs assigned automatically on creation (shown by 'list')
    - Each ClearPass host must be unique across all server entries
    - Credentials are stored in /data/certs/servers.json (chmod 600)
    - Secret values are never echoed; 'show' displays (set) / (empty) only
"""

import getpass
import sys

sys.path.insert(0, "/opt/cppm")

try:
    from config_utils import (
        SERVERS_FILE,
        add_server,
        delete_server,
        get_server,
        load_servers,
        update_server,
    )
except ImportError as exc:
    sys.exit(
        f"ERROR: Cannot import config_utils: {exc}\n"
        "This script must be run inside the container:\n"
        "  docker exec -it cppm-acme-cert-manager "
        "cppm-servers <cmd>"
    )


# ── Provider metadata ─────────────────────────────────────────────────────────

_DNS_PROVIDERS = {
    "cloudflare":   "Cloudflare",
    "porkbun":      "Porkbun",
    "route53":      "AWS Route 53",
    "digitalocean": "DigitalOcean",
    "godaddy":      "GoDaddy",
}

_ACME_SERVERS = {
    "letsencrypt":      "Let's Encrypt",
    "letsencrypt_test": "Let's Encrypt (Staging)",
    "zerossl":          "ZeroSSL",
    "buypass":          "Buypass",
}

# (env_key, display_label, is_secret, hint)
_DNS_CRED_FIELDS = {
    "cloudflare": [
        ("CF_Token",      "API Token",      True,  "Zone DNS scoped token — recommended"),
        ("CF_Zone_ID",    "Zone ID",        False, "Found on the zone overview page"),
        ("CF_Account_ID", "Account ID",     False, "Optional when using a scoped token"),
        ("CF_Key",        "Global API Key", True,  "Alternative to scoped token"),
        ("CF_Email",      "Account Email",  False, "Required only when using global key"),
    ],
    "porkbun": [
        ("PORKBUN_API_KEY",        "API Key",        True, ""),
        ("PORKBUN_SECRET_API_KEY", "Secret API Key", True, ""),
    ],
    "route53": [
        ("AWS_ACCESS_KEY_ID",     "Access Key ID",     False, ""),
        ("AWS_SECRET_ACCESS_KEY", "Secret Access Key", True,  ""),
        ("AWS_DEFAULT_REGION",    "Region",            False, "e.g. us-east-1"),
    ],
    "digitalocean": [
        ("DO_API_KEY", "API Token", True, ""),
    ],
    "godaddy": [
        ("GD_Key",    "API Key",    False, ""),
        ("GD_Secret", "API Secret", True,  ""),
    ],
}


# ── Prompt helpers ────────────────────────────────────────────────────────────

def _prompt(label: str, default: str = "", required: bool = False,
            hint: str = "", secret: bool = False) -> str:
    """Prompt for one value. Returns new input or default on Enter."""
    hint_str = f"  ({hint})" if hint else ""
    if default:
        display = "(currently set)" if secret else f"[{default}]"
        prompt_str = f"  {label}{hint_str} {display}: "
    else:
        prompt_str = f"  {label}{hint_str}: "

    while True:
        try:
            val = getpass.getpass(prompt_str) if secret else input(prompt_str).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if val:
            return val
        if default:
            return default
        if not required:
            return ""
        print(f"  {label} is required.")


def _prompt_choice(label: str, choices: dict, default: str = "") -> str:
    """Numbered menu prompt. Returns the selected key."""
    keys = list(choices.keys())
    print(f"\n  {label}:")
    for i, k in enumerate(keys, 1):
        marker = " *" if k == default else ""
        print(f"    {i}. {choices[k]}{marker}")
    keep = " (Enter to keep current)" if default else ""
    while True:
        try:
            val = input(f"  Choice [1-{len(keys)}]{keep}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if not val and default:
            return default
        try:
            idx = int(val) - 1
            if 0 <= idx < len(keys):
                return keys[idx]
        except (ValueError, IndexError):
            pass
        print(f"  Enter a number between 1 and {len(keys)}.")


def _prompt_bool(label: str, default: bool = False) -> bool:
    default_str = "Y/n" if default else "y/N"
    try:
        val = input(f"  {label} [{default_str}]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return default if not val else val in ("y", "yes")


# ── Interactive field collection ──────────────────────────────────────────────

def _collect_server(existing: dict = None) -> dict:
    """Walk through all server fields interactively. Pass existing for edit mode."""
    s = dict(existing) if existing else {}
    creds = dict(s.get("dns_credentials") or {})

    print("\n── Server Identity ──────────────────────────────────────────────────────")
    s["label"] = _prompt("Label", s.get("label", ""), required=True,
                         hint="friendly name, e.g. Production ClearPass")

    print("\n── ClearPass Server ─────────────────────────────────────────────────────")
    s["cppm_host"]           = _prompt("Host / IP",        s.get("cppm_host", ""),           required=True,
                                       hint="e.g. cppm.example.com or 10.0.0.10")
    s["cppm_client_id"]      = _prompt("Client ID",        s.get("cppm_client_id", ""),      required=True)
    s["cppm_client_secret"]  = _prompt("Client Secret",    s.get("cppm_client_secret", ""),  required=True, secret=True)
    s["cppm_cert_passphrase"]= _prompt("Cert Passphrase",  s.get("cppm_cert_passphrase", ""),
                                       hint="PKCS12 export passphrase — leave blank for none", secret=True)
    s["cppm_callback_host"]  = _prompt("Callback Host",    s.get("cppm_callback_host", ""),
                                       hint="Docker host LAN IP that ClearPass can reach")
    s["cppm_callback_port"]  = _prompt("Callback Port",    str(s.get("cppm_callback_port", "8765")))
    s["cppm_verify_ssl"]     = _prompt_bool("Verify SSL (enable after initial cert install)",
                                            s.get("cppm_verify_ssl", False))

    print("\n── Domain & ACME ────────────────────────────────────────────────────────")
    s["domain"]      = _prompt("Domain",     s.get("domain", ""),      required=True,
                               hint="e.g. cppm.example.com")
    s["acme_email"]  = _prompt("ACME Email", s.get("acme_email", ""), required=True,
                               hint="certificate contact address")
    s["acme_server"] = _prompt_choice("Certificate Authority", _ACME_SERVERS,
                                      s.get("acme_server", "letsencrypt"))

    print("\n── DNS Provider ─────────────────────────────────────────────────────────")
    s["dns_provider"] = _prompt_choice("Provider", _DNS_PROVIDERS,
                                       s.get("dns_provider", "cloudflare"))

    fields = _DNS_CRED_FIELDS.get(s["dns_provider"], [])
    if fields:
        print(f"\n  Credentials for {_DNS_PROVIDERS[s['dns_provider']]}:")
        for key, label, is_secret, hint in fields:
            creds[key] = _prompt(label, creds.get(key, ""), hint=hint, secret=is_secret)

    s["dns_credentials"] = creds
    return s


# ── Subcommands ───────────────────────────────────────────────────────────────

def cmd_list() -> int:
    servers = load_servers()
    if not servers:
        print(f"No servers configured.  Storage: {SERVERS_FILE}")
        print("  Add the first server:  cppm-servers add")
        return 0
    print(f"Configured servers ({len(servers)}) — {SERVERS_FILE}:")
    for s in servers:
        dns  = _DNS_PROVIDERS.get(s.get("dns_provider", ""), s.get("dns_provider", "—"))
        acme = _ACME_SERVERS.get(s.get("acme_server",   ""), s.get("acme_server",   "—"))
        print()
        print(f"  ID:       {s.get('id', '')}")
        print(f"  Label:    {s.get('label', '')}")
        print(f"  Host:     {s.get('cppm_host', '')}")
        print(f"  Domain:   {s.get('domain', '')}")
        print(f"  DNS:      {dns}")
        print(f"  ACME CA:  {acme}")
    return 0


def cmd_show(server_id: str) -> int:
    s = get_server(server_id)
    if not s:
        print(f"Server '{server_id}' not found.  Run 'list' to see all IDs.")
        return 1
    creds = s.get("dns_credentials") or {}
    dns  = _DNS_PROVIDERS.get(s.get("dns_provider", ""), s.get("dns_provider", "—"))
    acme = _ACME_SERVERS.get(s.get("acme_server",   ""), s.get("acme_server",   "—"))

    print(f"\n── {s.get('label', 'Server')} ({server_id}) ──")
    print(f"  ID:               {s.get('id', '')}")
    print(f"  Label:            {s.get('label', '')}")
    print()
    print(f"  ClearPass Host:   {s.get('cppm_host', '')}")
    print(f"  Client ID:        {s.get('cppm_client_id', '')}")
    print(f"  Client Secret:    {'(set)' if s.get('cppm_client_secret') else '(empty)'}")
    print(f"  Cert Passphrase:  {'(set)' if s.get('cppm_cert_passphrase') else '(empty)'}")
    print(f"  Callback Host:    {s.get('cppm_callback_host', '')}")
    print(f"  Callback Port:    {s.get('cppm_callback_port', '8765')}")
    print(f"  Verify SSL:       {s.get('cppm_verify_ssl', False)}")
    print()
    print(f"  Domain:           {s.get('domain', '')}")
    print(f"  ACME Email:       {s.get('acme_email', '')}")
    print(f"  Certificate Auth: {acme}")
    print()
    print(f"  DNS Provider:     {dns}")
    for key, label, is_secret, _ in _DNS_CRED_FIELDS.get(s.get("dns_provider", ""), []):
        if is_secret:
            val = "(set)" if creds.get(key) else "(empty)"
        else:
            val = creds.get(key, "(empty)")
        print(f"  {label + ':':20}{val}")
    return 0


def cmd_add() -> int:
    print("Adding a new ClearPass server entry.")
    print("Press Enter to accept a default value; Ctrl-C to cancel.")
    try:
        entry = _collect_server()
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 0
    try:
        server_id = add_server(entry)
        print(f"\nServer '{entry.get('label')}' added successfully.")
        print(f"  ID: {server_id}")
        return 0
    except ValueError as exc:
        print(f"\nError: {exc}")
        return 1


def cmd_edit(server_id: str) -> int:
    existing = get_server(server_id)
    if not existing:
        print(f"Server '{server_id}' not found.  Run 'list' to see all IDs.")
        return 1
    label = existing.get("label") or existing.get("cppm_host", "")
    print(f"Editing server '{label}' ({server_id}).")
    print("Press Enter to keep the current value; Ctrl-C to cancel.")
    try:
        entry = _collect_server(existing)
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 0
    try:
        update_server(server_id, entry)
        print(f"\nServer '{entry.get('label')}' updated.")
        return 0
    except ValueError as exc:
        print(f"\nError: {exc}")
        return 1


def cmd_delete(server_id: str) -> int:
    s = get_server(server_id)
    if not s:
        print(f"Server '{server_id}' not found.  Run 'list' to see all IDs.")
        return 1
    label = s.get("label") or s.get("cppm_host", "")
    try:
        confirm = input(f"Delete server '{label}' ({server_id})? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return 0
    if confirm != "y":
        print("Cancelled.")
        return 0
    if delete_server(server_id):
        print(f"Server '{label}' deleted.")
        remaining = load_servers()
        if remaining:
            print(f"  {len(remaining)} server(s) remaining.")
        else:
            print("  No servers remain. Add a new one with: cppm-servers add")
        return 0
    return 1


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1

    cmd, *rest = args

    if cmd == "list":
        return cmd_list()

    if cmd == "add":
        return cmd_add()

    if cmd in ("show", "edit", "delete"):
        if not rest:
            print(f"Usage: cppm-servers {cmd} <id>")
            print("  Use 'list' to see server IDs.")
            return 1
        return {"show": cmd_show, "edit": cmd_edit, "delete": cmd_delete}[cmd](rest[0])

    print(f"Unknown command: '{cmd}'")
    print("Available commands: list, show, add, edit, delete")
    return 1


if __name__ == "__main__":
    sys.exit(main())
