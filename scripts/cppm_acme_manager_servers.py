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
    docker exec -it cppm-acme-cert-manager cppm-servers profiles
    docker exec -it cppm-acme-cert-manager cppm-servers edit-profile <profile-id>
    docker exec -it cppm-acme-cert-manager cppm-servers detach-profile <profile-id>

Notes:
    - A certificate profile is the ACME/DNS config shared by every server
      entry with the same Certificate Profile ID (set via 'add'/'edit').
      Use 'edit-profile' to change it once for every target that shares
      it — a shared field edited through 'edit' on a single target is
      silently re-derived from its sibling on save and will not stick.
    - Server IDs are UUIDs assigned automatically on creation (shown by 'list')
    - Each ClearPass host must be unique across all server entries
    - Credentials are stored in /data/certs/servers.json (chmod 600)
    - Secret values are never echoed; 'show' displays (set) / (empty) only
"""

import getpass
import re
import sys

sys.path.insert(0, "/opt/cppm")

try:
    from config_utils import (
        SERVERS_FILE,
        _slugify_certificate_id,
        acme_dns_resolvers,
        add_server,
        delete_certificate_profile,
        delete_server,
        get_server,
        get_server_shell_env,
        list_certificate_profiles,
        list_profile_members,
        load_servers,
        migrate_from_env,
        resolve_target_fields,
        update_certificate_profile,
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
}

_TARGET_TYPES = {
    "clearpass": "ClearPass Policy Manager",
    "linux_ssh": "Linux Server (SSH)",
}

# (env_key, display_label, is_secret, hint)
_DNS_CRED_FIELDS = {
    "cloudflare": [
        ("CF_Token",      "API Token",      True,  "Zone DNS scoped token — recommended"),
        ("CF_Zone_ID",    "Zone ID",        False, "Found on the zone overview page"),
        ("CF_Account_ID", "Account ID",     False, "Optional — only needed to verify an account-owned token"),
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

def _suggest_certificate_id(s: dict) -> str:
    """Suggest a default Certificate Profile ID from the target's host.

    Domain isn't collected yet at the point this is called (it's asked for
    in _prompt_shared_acme_fields, right after), so this mirrors
    config_utils.certificate_id()'s host-based fallback rather than using
    the domain.
    """
    host = s.get("cppm_host") or (s.get("target_config") or {}).get("ssh_host", "")
    return _slugify_certificate_id(host or s.get("label", ""))


def _prompt_certificate_profile(s: dict) -> tuple:
    """Prompt for the (now required) Certificate Profile ID, offering to
    share an existing profile's ACME/DNS config -- the same mechanism the
    web UI's "Certificate Profile" dropdown uses (add_server/update_server
    re-derive those fields from the matching profile_id on save regardless
    of target_type, via config_utils._inherit_certificate_profile).

    Returns (s, True) if a profile is shared (by picking one from the menu,
    or by typing an ID that happens to match one) -- the caller should skip
    collecting Domain/ACME/DNS/Advanced, since they'll be overwritten on
    save anyway -- or (s, False) if this is a standalone/new profile.
    """
    profiles = list_certificate_profiles()
    suggested = s.get("certificate_id") or _suggest_certificate_id(s)

    if not profiles:
        s["certificate_id"] = _prompt(
            "Certificate Profile ID", suggested, required=True,
            hint="reuse this value on another target later to share its ACME/DNS config")
        return s, False

    print("\n  Existing certificate profiles found. Sharing one fills in this target's")
    print("  Domain/ACME/DNS config automatically -- no need to re-enter DNS credentials.")
    choices = {"__new__": "New profile — configure ACME/DNS for this target"}
    for p in profiles:
        pid = str(p.get("certificate_id", "")).strip()
        label = p.get("label") or p.get("domain") or p.get("cppm_host") or p.get("ssh_host") or pid
        choices[pid] = f"{pid} — {label}"
    current = s.get("certificate_id", "")
    default = current if current in choices else "__new__"
    chosen = _prompt_choice("Certificate Profile", choices, default)
    if chosen != "__new__":
        s["certificate_id"] = chosen
        print(f"  Using certificate profile '{chosen}' — ACME/DNS config will be inherited from it.")
        return s, True

    typed = _prompt(
        "Certificate Profile ID", current or suggested, required=True,
        hint="reuse this value on another target later to share its ACME/DNS config")
    if typed in choices and typed != "__new__":
        print(f"  Note: '{typed}' matches an existing profile ({choices[typed]}) — "
              f"its ACME/DNS config will be used here instead of whatever you'd enter next.")
        s["certificate_id"] = typed
        return s, True
    s["certificate_id"] = typed
    return s, False


def _collect_ssh_server(s: dict) -> dict:
    """Collect the Linux-SSH-specific fields (nested under target_config,
    per the groundwork shim's convention) and offer a test-connection step.
    """
    print("\n── Linux Server (SSH) ───────────────────────────────────────────────────")
    tc = dict(s.get("target_config") or {})
    tc["ssh_host"] = _prompt("Host / IP", tc.get("ssh_host", ""), required=True,
                             hint="e.g. 10.0.0.20 or myhost.example.com")
    tc["ssh_port"] = _prompt("Port", str(tc.get("ssh_port", "22") or "22"))
    tc["ssh_user"] = _prompt("SSH User", tc.get("ssh_user", ""), required=True)
    print("  Provide a private key (recommended) or a password. Enter to keep current / skip.")
    tc["ssh_private_key"] = _prompt("Private Key (paste, Ctrl-D on empty line to end)",
                                    tc.get("ssh_private_key", ""), secret=True,
                                    hint="leave blank to use a password instead")
    tc["ssh_password"] = _prompt("Password", tc.get("ssh_password", ""), secret=True,
                                 hint="leave blank if a private key is set above")
    if not tc.get("ssh_private_key") and not tc.get("ssh_password"):
        print("  Either a private key or a password is required.")
        return _collect_ssh_server(s)
    tc["remote_cert_dir"] = _prompt("Remote Cert Directory", tc.get("remote_cert_dir", ""),
                                    required=True,
                                    hint="e.g. /etc/ssl/cppm-acme — holds fullchain.pem/privkey.pem")
    tc["reload_command"] = _prompt("Reload Command", tc.get("reload_command", ""),
                                   hint="e.g. sudo systemctl reload nginx — optional")
    s["target_config"] = tc

    try:
        test_now = _prompt_bool("Test this connection now", True)
    except Exception:
        test_now = False
    if test_now:
        try:
            import ssh_upload
            probe = dict(tc)
            result = ssh_upload.test_ssh_target(probe)
        except Exception as exc:
            result = {"status": "error", "message": str(exc)}
        status = result.get("status", "unknown")
        print(f"\n  Test result [{status}]: {result.get('message', '')}")
        for line in result.get("remediation") or []:
            print(f"    $ {line}")
    return s


def _collect_server(existing: dict = None) -> dict:
    """Walk through all server fields interactively. Pass existing for edit mode."""
    s = dict(resolve_target_fields(existing)) if existing else {}
    creds = dict(s.get("dns_credentials") or {})

    print("\n── Server Identity ──────────────────────────────────────────────────────")
    s["label"] = _prompt("Label", s.get("label", ""), required=True,
                         hint="friendly name, e.g. Production ClearPass")
    s["target_type"] = _prompt_choice("Target Type", _TARGET_TYPES,
                                      s.get("target_type", "clearpass"))

    if s["target_type"] == "linux_ssh":
        s = _collect_ssh_server(s)
    else:
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

    s, inherited = _prompt_certificate_profile(s)
    if inherited:
        return s

    return _prompt_shared_acme_fields(s)


def _prompt_shared_acme_fields(s: dict) -> dict:
    """Prompt for the ACME/DNS fields a certificate profile shares across targets.

    Mirrors config_utils._SHARED_PROFILE_FIELDS (minus cert_types, which this
    CLI has never prompted for — it defaults to all cert types, same as
    add_server/update_server). Used both by _collect_server (new entry) and
    cmd_edit_profile (editing a shared profile across every target at once).
    """
    creds = dict(s.get("dns_credentials") or {})

    print("\n── Domain & ACME ────────────────────────────────────────────────────────")
    s["domain"]      = _prompt("Domain",     s.get("domain", ""),      required=True,
                               hint="e.g. cppm.example.com")
    s["acme_email"]  = _prompt("ACME Email", s.get("acme_email", ""), required=True,
                               hint="certificate contact address")
    s["acme_server"] = _prompt_choice("Certificate Authority", _ACME_SERVERS,
                                      s.get("acme_server", "letsencrypt"))

    if s["acme_server"] == "zerossl":
        print("\n  ZeroSSL External Account Binding credentials:")
        creds["EAB_KID"] = _prompt("EAB KID", creds.get("EAB_KID", ""), required=True)
        creds["EAB_HMAC_KEY"] = _prompt(
            "EAB HMAC Key", creds.get("EAB_HMAC_KEY", ""), required=True, secret=True
        )

    print("\n── DNS Provider ─────────────────────────────────────────────────────────")
    s["dns_provider"] = _prompt_choice("Provider", _DNS_PROVIDERS,
                                       s.get("dns_provider", "cloudflare"))

    fields = _DNS_CRED_FIELDS.get(s["dns_provider"], [])
    if fields:
        print(f"\n  Credentials for {_DNS_PROVIDERS[s['dns_provider']]}:")
        for key, label, is_secret, hint in fields:
            creds[key] = _prompt(label, creds.get(key, ""), hint=hint, secret=is_secret)

    s["dns_credentials"] = creds

    print("\n── Advanced ─────────────────────────────────────────────────────────────")
    print("  Split-horizon: answer yes only if your internal DNS server has its own copy")
    print("  of this domain (common with Active Directory). Certificate validation then")
    print("  checks public DNS instead. Not sure? Answer no — the dashboard warns if needed.")
    s["split_horizon_dns"] = _prompt_bool("Split-horizon DNS", s.get("split_horizon_dns", False))
    if s["split_horizon_dns"]:
        current = ", ".join(s.get("split_horizon_resolvers") or [])
        raw = _prompt("Custom public resolvers", current,
                      hint="optional, comma-separated — default 1.1.1.1, 8.8.8.8")
        s["split_horizon_resolvers"] = [r for r in re.split(r"[,\s]+", raw) if r]
    else:
        s["split_horizon_resolvers"] = []
    return s


def _print_split_horizon_warning(entry: dict) -> None:
    """Best-effort split-horizon DNS check, run right after a server is saved.

    Catches a split-horizon misconfiguration before the first issuance
    attempt instead of only surfacing it later via the dashboard or renewal
    log. Read-only (SOA lookups via dig); any failure here is swallowed.
    """
    if not entry.get("domain"):
        return
    try:
        from dns_utils import split_horizon_check
        problem = split_horizon_check(
            entry.get("domain", ""),
            bool(entry.get("split_horizon_dns")),
            acme_dns_resolvers(entry),
        )
    except Exception:
        return
    if problem:
        print(f"\n  Warning: {problem['message']}")


# ── Subcommands ───────────────────────────────────────────────────────────────

def cmd_ids() -> int:
    """Print one server ID per line — used by shell scripts to iterate over servers."""
    for s in load_servers():
        sid = s.get("id", "")
        if sid:
            print(sid)
    return 0


def cmd_env(server_id: str) -> int:
    """Print shell-sourceable export statements for a server's configuration."""
    output = get_server_shell_env(server_id)
    if output is None:
        print(f"Server '{server_id}' not found.  Run 'list' to see all IDs.", file=sys.stderr)
        return 1
    print(output)
    return 0


def cmd_list() -> int:
    servers = load_servers()
    if not servers:
        print(f"No servers configured.  Storage: {SERVERS_FILE}")
        print("  Add the first server:  cppm-servers add")
        return 0
    print(f"Configured servers ({len(servers)}) — {SERVERS_FILE}:")
    for raw in servers:
        s = resolve_target_fields(raw)
        dns  = _DNS_PROVIDERS.get(s.get("dns_provider", ""), s.get("dns_provider", "—"))
        acme = _ACME_SERVERS.get(s.get("acme_server",   ""), s.get("acme_server",   "—"))
        target_type = s.get("target_type", "clearpass") or "clearpass"
        host = s.get("ssh_host", "") if target_type == "linux_ssh" else s.get("cppm_host", "")
        print()
        print(f"  ID:       {s.get('id', '')}")
        print(f"  Label:    {s.get('label', '')}")
        print(f"  Type:     {_TARGET_TYPES.get(target_type, target_type)}")
        print(f"  Host:     {host}")
        print(f"  Domain:   {s.get('domain', '')}")
        print(f"  DNS:      {dns}")
        print(f"  ACME CA:  {acme}")
    return 0


def cmd_show(server_id: str) -> int:
    raw = get_server(server_id)
    if not raw:
        print(f"Server '{server_id}' not found.  Run 'list' to see all IDs.")
        return 1
    s = resolve_target_fields(raw)
    creds = s.get("dns_credentials") or {}
    dns  = _DNS_PROVIDERS.get(s.get("dns_provider", ""), s.get("dns_provider", "—"))
    acme = _ACME_SERVERS.get(s.get("acme_server",   ""), s.get("acme_server",   "—"))
    target_type = s.get("target_type", "clearpass") or "clearpass"

    print(f"\n── {s.get('label', 'Server')} ({server_id}) ──")
    print(f"  ID:               {s.get('id', '')}")
    print(f"  Label:            {s.get('label', '')}")
    print(f"  Type:             {_TARGET_TYPES.get(target_type, target_type)}")
    print()
    if target_type == "linux_ssh":
        print(f"  SSH Host:         {s.get('ssh_host', '')}")
        print(f"  SSH Port:         {s.get('ssh_port', '22')}")
        print(f"  SSH User:         {s.get('ssh_user', '')}")
        print(f"  Private Key:      {'(set)' if s.get('ssh_private_key') else '(empty)'}")
        print(f"  Password:         {'(set)' if s.get('ssh_password') else '(empty)'}")
        print(f"  Remote Cert Dir:  {s.get('remote_cert_dir', '')}")
        print(f"  Reload Command:   {s.get('reload_command', '')}")
    else:
        print(f"  ClearPass Host:   {s.get('cppm_host', '')}")
        print(f"  Client ID:        {s.get('cppm_client_id', '')}")
        print(f"  Client Secret:    {'(set)' if s.get('cppm_client_secret') else '(empty)'}")
        print(f"  Cert Passphrase:  {'(set)' if s.get('cppm_cert_passphrase') else '(empty)'}")
        print(f"  Callback Host:    {s.get('cppm_callback_host', '')}")
        print(f"  Callback Port:    {s.get('cppm_callback_port', '8765')}")
        print(f"  Verify SSL:       {s.get('cppm_verify_ssl', False)}")
        print(f"  Cluster Mode:     {s.get('cppm_cluster_mode', False)}")
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
    print()
    print(f"  Split-horizon DNS: {s.get('split_horizon_dns', False)}")
    if s.get("split_horizon_dns"):
        print(f"  Challenge DNS:    {', '.join(acme_dns_resolvers(s))}")
    return 0


def cmd_add() -> int:
    print("Adding a new server entry.")
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
        _print_split_horizon_warning(entry)
        return 0
    except ValueError as exc:
        print(f"\nError: {exc}")
        return 1


def cmd_edit(server_id: str) -> int:
    existing = get_server(server_id)
    if not existing:
        print(f"Server '{server_id}' not found.  Run 'list' to see all IDs.")
        return 1
    resolved_existing = resolve_target_fields(existing)
    label = resolved_existing.get("label") or resolved_existing.get("cppm_host") or resolved_existing.get("ssh_host", "")
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
        _print_split_horizon_warning(entry)
        return 0
    except ValueError as exc:
        print(f"\nError: {exc}")
        return 1


def cmd_delete(server_id: str) -> int:
    s = get_server(server_id)
    if not s:
        print(f"Server '{server_id}' not found.  Run 'list' to see all IDs.")
        return 1
    resolved = resolve_target_fields(s)
    label = resolved.get("label") or resolved.get("cppm_host") or resolved.get("ssh_host", "")
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


def cmd_profiles() -> int:
    profiles = list_certificate_profiles()
    if not profiles:
        print("No certificate profiles configured.")
        print("  Set a matching Certificate Profile ID on two or more servers")
        print("  (via 'add'/'edit') to share one ACME/DNS config between them.")
        return 0
    print(f"Certificate profiles ({len(profiles)}):")
    for p in profiles:
        pid = str(p.get("certificate_id", "")).strip()
        dns  = _DNS_PROVIDERS.get(p.get("dns_provider", ""), p.get("dns_provider", "—"))
        acme = _ACME_SERVERS.get(p.get("acme_server",   ""), p.get("acme_server",   "—"))
        members = list_profile_members(pid)
        print()
        print(f"  Profile:  {pid}")
        print(f"  Domain:   {p.get('domain', '')}")
        print(f"  DNS:      {dns}")
        print(f"  ACME CA:  {acme}")
        print(f"  Members:  " + ", ".join(
            f"{m.get('label', '')} ({_TARGET_TYPES.get(m.get('target_type', 'clearpass'), 'clearpass')})"
            for m in members
        ))
    return 0


def cmd_edit_profile(profile_id: str) -> int:
    members = list_profile_members(profile_id)
    if not members:
        print(f"Certificate profile '{profile_id}' not found.  Run 'profiles' to see all profiles.")
        return 1
    print(f"Editing certificate profile '{profile_id}' — shared by {len(members)} target(s):")
    for m in members:
        print(f"  - {m.get('label', '')} ({_TARGET_TYPES.get(m.get('target_type', 'clearpass'), 'clearpass')})")
    print("Press Enter to keep the current value; Ctrl-C to cancel.")
    try:
        fields = _prompt_shared_acme_fields(dict(members[0]))
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 0
    try:
        n = update_certificate_profile(profile_id, fields)
        print(f"\nProfile '{profile_id}' updated — {n} target(s) affected.")
        _print_split_horizon_warning(fields)
        return 0
    except ValueError as exc:
        print(f"\nError: {exc}")
        return 1


def cmd_detach_profile(profile_id: str) -> int:
    members = list_profile_members(profile_id)
    if not members:
        print(f"Certificate profile '{profile_id}' not found.  Run 'profiles' to see all profiles.")
        return 1
    print(f"This will detach {len(members)} target(s) from profile '{profile_id}':")
    for m in members:
        print(f"  - {m.get('label', '')} ({_TARGET_TYPES.get(m.get('target_type', 'clearpass'), 'clearpass')})")
    print("Each keeps its current ACME/DNS values but will no longer share edits.")
    try:
        confirm = input("Detach all? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return 0
    if confirm != "y":
        print("Cancelled.")
        return 0
    n = delete_certificate_profile(profile_id)
    print(f"Detached {n} target(s) from profile '{profile_id}'.")
    return 0


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1

    cmd, *rest = args

    if cmd == "list":
        return cmd_list()

    if cmd == "ids":
        return cmd_ids()

    if cmd == "add":
        return cmd_add()

    if cmd == "profiles":
        return cmd_profiles()

    if cmd in ("show", "edit", "delete", "env"):
        if not rest:
            print(f"Usage: cppm-servers {cmd} <id>")
            print("  Use 'list' to see server IDs.")
            return 1
        return {"show": cmd_show, "edit": cmd_edit, "delete": cmd_delete,
                "env": cmd_env}[cmd](rest[0])

    if cmd in ("edit-profile", "detach-profile"):
        if not rest:
            print(f"Usage: cppm-servers {cmd} <profile-id>")
            print("  Use 'profiles' to see all certificate profile IDs.")
            return 1
        return {"edit-profile": cmd_edit_profile,
                "detach-profile": cmd_detach_profile}[cmd](rest[0])

    print(f"Unknown command: '{cmd}'")
    print("Available commands: list, ids, show, add, edit, delete, env, "
          "profiles, edit-profile, detach-profile")
    return 1


if __name__ == "__main__":
    sys.exit(main())
