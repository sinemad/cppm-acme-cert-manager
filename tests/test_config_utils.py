"""Tests for config_utils module."""
import copy
import os

import pytest

import config_utils
from config_utils import (
    add_server,
    delete_server,
    get_server,
    get_server_shell_env,
    load_servers,
    migrate_from_env,
    server_cert_dir,
    update_server,
    validate_server,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def patch_servers_file(tmp_path, monkeypatch):
    monkeypatch.setattr(config_utils, "SERVERS_FILE", tmp_path / "servers.json")


BASE_ENTRY = {
    "label": "Test ClearPass",
    "cppm_host": "cppm.example.com",
    "cppm_client_id": "cppm-client",
    "cppm_client_secret": "secret123",
    "domain": "cppm.example.com",
    "acme_email": "admin@example.com",
    "acme_server": "letsencrypt",
    "dns_provider": "cloudflare",
    "cppm_callback_port": 8765,
    "cert_types": ["ecc", "rsa"],
}


def _make_entry(**overrides):
    e = copy.deepcopy(BASE_ENTRY)
    e.update(overrides)
    return e


def _parse_shell_env(text: str) -> dict:
    """Parse 'export K=V' lines, stripping surrounding quotes from values."""
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("export "):
            continue
        rest = line[len("export "):]
        if "=" not in rest:
            continue
        k, _, v = rest.partition("=")
        # Strip surrounding single or double quotes
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
            v = v[1:-1]
        result[k] = v
    return result


# ── validate_server ───────────────────────────────────────────────────────────

class TestValidateServer:
    def test_valid_entry_passes(self):
        validate_server(BASE_ENTRY)  # should not raise

    @pytest.mark.parametrize("field", [
        "label", "cppm_host", "cppm_client_id", "cppm_client_secret",
        "domain", "acme_email", "acme_server", "dns_provider",
    ])
    def test_missing_required_field_raises(self, field):
        entry = _make_entry()
        del entry[field]
        with pytest.raises(ValueError):
            validate_server(entry)

    def test_port_99999_raises(self):
        with pytest.raises(ValueError):
            validate_server(_make_entry(cppm_callback_port=99999))

    def test_port_0_raises(self):
        with pytest.raises(ValueError):
            validate_server(_make_entry(cppm_callback_port=0))

    def test_port_not_a_number_raises(self):
        with pytest.raises(ValueError):
            validate_server(_make_entry(cppm_callback_port="notaport"))

    def test_empty_cert_types_raises_with_certificate_type(self):
        with pytest.raises(ValueError, match="certificate type"):
            validate_server(_make_entry(cert_types=[]))

    def test_ecc_only_cert_types_passes(self):
        validate_server(_make_entry(cert_types=["ecc"]))

    def test_rsa_only_cert_types_passes(self):
        validate_server(_make_entry(cert_types=["rsa"]))


# ── CRUD ──────────────────────────────────────────────────────────────────────

class TestCrud:
    def test_add_server_returns_nonempty_id(self):
        sid = add_server(_make_entry())
        assert sid and len(sid) > 0

    def test_add_server_persists_to_load_servers(self):
        sid = add_server(_make_entry())
        servers = load_servers()
        ids = [s["id"] for s in servers]
        assert sid in ids

    def test_get_server_returns_entry_by_id(self):
        sid = add_server(_make_entry())
        s = get_server(sid)
        assert s is not None
        assert s["id"] == sid

    def test_get_server_returns_none_for_unknown_id(self):
        assert get_server("nonexistent-id-12345") is None

    def test_duplicate_cppm_host_raises(self):
        add_server(_make_entry())
        with pytest.raises(ValueError, match="already exists"):
            add_server(_make_entry(label="Another Label"))

    def test_update_server_replaces_label(self):
        sid = add_server(_make_entry())
        updated = _make_entry(label="New Label")
        result = update_server(sid, updated)
        assert result is True
        s = get_server(sid)
        assert s["label"] == "New Label"

    def test_update_server_preserves_id(self):
        sid = add_server(_make_entry())
        updated = _make_entry(label="Updated")
        update_server(sid, updated)
        s = get_server(sid)
        assert s["id"] == sid

    def test_update_server_returns_false_for_unknown_id(self):
        result = update_server("bad-id", _make_entry())
        assert result is False

    def test_delete_server_removes_entry(self):
        sid = add_server(_make_entry())
        result = delete_server(sid)
        assert result is True
        assert get_server(sid) is None

    def test_delete_server_returns_false_for_unknown_id(self):
        result = delete_server("nonexistent-id")
        assert result is False

    def test_load_servers_returns_empty_when_file_missing(self):
        # File doesn't exist yet (tmp_path is fresh)
        assert load_servers() == []

    def test_two_entries_with_different_hosts_coexist(self):
        sid1 = add_server(_make_entry(cppm_host="host1.example.com", domain="host1.example.com"))
        sid2 = add_server(_make_entry(
            cppm_host="host2.example.com",
            domain="host2.example.com",
            label="Second Server",
        ))
        servers = load_servers()
        assert len(servers) == 2
        ids = {s["id"] for s in servers}
        assert sid1 in ids
        assert sid2 in ids


# ── server_cert_dir ───────────────────────────────────────────────────────────

class TestServerCertDir:
    def test_normal_hostname_ends_with_that_name(self):
        path = server_cert_dir({"cppm_host": "cppm.example.com"})
        assert path.name == "cppm.example.com"

    def test_special_chars_brackets_and_exclamation_absent(self):
        path = server_cert_dir({"cppm_host": "cppm [lab]!"})
        name = path.name
        assert "[" not in name
        assert "]" not in name
        assert "!" not in name

    def test_empty_hostname_path_name_is_not_empty(self):
        path = server_cert_dir({"cppm_host": ""})
        assert path.name != ""


# ── get_server_shell_env ──────────────────────────────────────────────────────

class TestGetServerShellEnv:
    def test_returns_none_for_unknown_id(self):
        assert get_server_shell_env("no-such-id") is None

    def test_contains_domain(self):
        sid = add_server(_make_entry())
        env_text = get_server_shell_env(sid)
        assert "export DOMAIN=" in env_text

    def test_contains_acme_email(self):
        sid = add_server(_make_entry())
        env_text = get_server_shell_env(sid)
        assert "export ACME_EMAIL=" in env_text

    def test_contains_dns_provider(self):
        sid = add_server(_make_entry())
        env_text = get_server_shell_env(sid)
        assert "export DNS_PROVIDER=" in env_text

    def test_contains_cppm_host(self):
        sid = add_server(_make_entry())
        env_text = get_server_shell_env(sid)
        assert "export CPPM_HOST=" in env_text

    def test_ecc_only_issue_flags(self):
        sid = add_server(_make_entry(cert_types=["ecc"]))
        env_text = get_server_shell_env(sid)
        parsed = _parse_shell_env(env_text)
        assert parsed["ISSUE_ECC"] == "true"
        assert parsed["ISSUE_RSA"] == "false"

    def test_rsa_only_issue_flags(self):
        sid = add_server(_make_entry(cert_types=["rsa"]))
        env_text = get_server_shell_env(sid)
        parsed = _parse_shell_env(env_text)
        assert parsed["ISSUE_ECC"] == "false"
        assert parsed["ISSUE_RSA"] == "true"

    def test_dns_credentials_appear_in_output(self):
        entry = _make_entry(dns_credentials={"CF_Token": "tok123", "CF_Zone_ID": "zone456"})
        sid = add_server(entry)
        env_text = get_server_shell_env(sid)
        assert "CF_Token" in env_text
        assert "tok123" in env_text

    def test_server_cert_dir_appears_in_output(self):
        sid = add_server(_make_entry())
        env_text = get_server_shell_env(sid)
        assert "SERVER_CERT_DIR=" in env_text


# ── migrate_from_env ──────────────────────────────────────────────────────────

class TestMigrateFromEnv:
    def test_returns_none_when_servers_already_exist(self, monkeypatch):
        add_server(_make_entry())
        monkeypatch.setenv("DOMAIN", "cppm.example.com")
        monkeypatch.setenv("CPPM_HOST", "cppm.example.com")
        result = migrate_from_env()
        assert result is None

    def test_returns_none_when_domain_absent(self, monkeypatch):
        monkeypatch.delenv("DOMAIN", raising=False)
        monkeypatch.setenv("CPPM_HOST", "cppm.example.com")
        result = migrate_from_env()
        assert result is None

    def test_returns_none_when_cppm_host_absent(self, monkeypatch):
        monkeypatch.setenv("DOMAIN", "cppm.example.com")
        monkeypatch.delenv("CPPM_HOST", raising=False)
        result = migrate_from_env()
        assert result is None

    def test_creates_entry_when_both_domain_and_cppm_host_set(self, monkeypatch):
        monkeypatch.setenv("DOMAIN", "cppm.example.com")
        monkeypatch.setenv("CPPM_HOST", "cppm.example.com")
        monkeypatch.setenv("ACME_EMAIL", "admin@example.com")
        monkeypatch.setenv("CPPM_CLIENT_ID", "client-id")
        monkeypatch.setenv("CPPM_CLIENT_SECRET", "secret")
        result = migrate_from_env()
        assert result is not None
        assert isinstance(result, str)

    def test_migrated_entry_domain_matches_env_var(self, monkeypatch):
        monkeypatch.setenv("DOMAIN", "myhost.example.com")
        monkeypatch.setenv("CPPM_HOST", "myhost.example.com")
        monkeypatch.setenv("ACME_EMAIL", "admin@example.com")
        monkeypatch.setenv("CPPM_CLIENT_ID", "client-id")
        monkeypatch.setenv("CPPM_CLIENT_SECRET", "secret")
        migrate_from_env()
        servers = load_servers()
        assert len(servers) == 1
        assert servers[0]["domain"] == "myhost.example.com"
