"""Tests for acme_cli: _require, _key_types, _dns_env, and CLI dispatch."""
import sys
from unittest.mock import MagicMock, patch

import pytest

import acme_cli
from acme_cli import _dns_env, _key_types, _require
from acme_provider import AcmeError, IssueResult, KeyTypeResult


# ── Helpers ───────────────────────────────────────────────────────────────────

def _issued():
    return IssueResult(results=[KeyTypeResult(key_type="ecc", issued=True)])


def _not_renewed():
    return IssueResult(results=[KeyTypeResult(key_type="ecc", issued=False)])


def _base_env(monkeypatch):
    monkeypatch.setenv("DOMAIN", "cppm.example.com")
    monkeypatch.setenv("SERVER_CERT_DIR", "/tmp/test-certs")
    monkeypatch.setenv("ACME_EMAIL", "admin@example.com")
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CF_Token", "tok123")
    monkeypatch.setenv("ISSUE_ECC", "true")
    monkeypatch.setenv("ISSUE_RSA", "false")


# ── _require ──────────────────────────────────────────────────────────────────

class TestRequire:
    def test_returns_value_when_set(self, monkeypatch):
        monkeypatch.setenv("TEST_REQ_VAR", "hello")
        assert _require("TEST_REQ_VAR") == "hello"

    def test_exits_1_when_missing(self, monkeypatch):
        monkeypatch.delenv("TEST_REQ_VAR", raising=False)
        with pytest.raises(SystemExit) as exc_info:
            _require("TEST_REQ_VAR")
        assert exc_info.value.code == 1

    def test_exits_1_when_empty_string(self, monkeypatch):
        monkeypatch.setenv("TEST_REQ_VAR", "")
        with pytest.raises(SystemExit) as exc_info:
            _require("TEST_REQ_VAR")
        assert exc_info.value.code == 1


# ── _key_types ────────────────────────────────────────────────────────────────

class TestKeyTypes:
    def test_both_by_default(self, monkeypatch):
        monkeypatch.delenv("ISSUE_ECC", raising=False)
        monkeypatch.delenv("ISSUE_RSA", raising=False)
        assert set(_key_types()) == {"ecc", "rsa"}

    def test_ecc_only(self, monkeypatch):
        monkeypatch.setenv("ISSUE_ECC", "true")
        monkeypatch.setenv("ISSUE_RSA", "false")
        assert _key_types() == ["ecc"]

    def test_rsa_only(self, monkeypatch):
        monkeypatch.setenv("ISSUE_ECC", "false")
        monkeypatch.setenv("ISSUE_RSA", "true")
        assert _key_types() == ["rsa"]

    def test_neither_exits_1(self, monkeypatch):
        monkeypatch.setenv("ISSUE_ECC", "false")
        monkeypatch.setenv("ISSUE_RSA", "false")
        with pytest.raises(SystemExit) as exc_info:
            _key_types()
        assert exc_info.value.code == 1

    def test_case_insensitive_true(self, monkeypatch):
        monkeypatch.setenv("ISSUE_ECC", "True")
        monkeypatch.setenv("ISSUE_RSA", "FALSE")
        assert _key_types() == ["ecc"]


# ── _dns_env ──────────────────────────────────────────────────────────────────

class TestDnsEnv:
    def test_includes_cf_token_when_set(self, monkeypatch):
        monkeypatch.setenv("CF_Token", "mytoken")
        assert _dns_env().get("CF_Token") == "mytoken"

    def test_includes_acme_email_when_set(self, monkeypatch):
        monkeypatch.setenv("ACME_EMAIL", "a@b.com")
        assert _dns_env().get("ACME_EMAIL") == "a@b.com"

    def test_excludes_unrelated_vars(self, monkeypatch):
        monkeypatch.setenv("UNRELATED_VAR", "nope")
        assert "UNRELATED_VAR" not in _dns_env()

    def test_absent_key_not_included(self, monkeypatch):
        monkeypatch.delenv("GD_Key", raising=False)
        assert "GD_Key" not in _dns_env()


# ── cmd_issue dispatch ────────────────────────────────────────────────────────

class TestCmdIssue:
    def test_success_calls_issue_cert(self, monkeypatch):
        _base_env(monkeypatch)
        mock_provider = MagicMock()
        mock_provider.issue_cert.return_value = _issued()
        monkeypatch.setattr(sys, "argv", ["acme_cli.py", "issue"])
        with patch("acme_cli.get_provider", return_value=mock_provider):
            acme_cli.main()
        mock_provider.issue_cert.assert_called_once()

    def test_force_flag_passed_to_provider(self, monkeypatch):
        _base_env(monkeypatch)
        mock_provider = MagicMock()
        mock_provider.issue_cert.return_value = _issued()
        monkeypatch.setattr(sys, "argv", ["acme_cli.py", "issue", "--force"])
        with patch("acme_cli.get_provider", return_value=mock_provider):
            acme_cli.main()
        assert mock_provider.issue_cert.call_args.kwargs["force"] is True

    def test_no_force_by_default(self, monkeypatch):
        _base_env(monkeypatch)
        mock_provider = MagicMock()
        mock_provider.issue_cert.return_value = _issued()
        monkeypatch.setattr(sys, "argv", ["acme_cli.py", "issue"])
        with patch("acme_cli.get_provider", return_value=mock_provider):
            acme_cli.main()
        assert mock_provider.issue_cert.call_args.kwargs["force"] is False

    def test_acme_error_exits_1(self, monkeypatch):
        _base_env(monkeypatch)
        mock_provider = MagicMock()
        mock_provider.issue_cert.side_effect = AcmeError("lego failed")
        monkeypatch.setattr(sys, "argv", ["acme_cli.py", "issue"])
        with patch("acme_cli.get_provider", return_value=mock_provider):
            with pytest.raises(SystemExit) as exc_info:
                acme_cli.main()
        assert exc_info.value.code == 1

    def test_missing_domain_exits_1(self, monkeypatch):
        _base_env(monkeypatch)
        monkeypatch.delenv("DOMAIN")
        monkeypatch.setattr(sys, "argv", ["acme_cli.py", "issue"])
        with pytest.raises(SystemExit) as exc_info:
            acme_cli.main()
        assert exc_info.value.code == 1

    def test_missing_acme_email_exits_1(self, monkeypatch):
        _base_env(monkeypatch)
        monkeypatch.delenv("ACME_EMAIL")
        monkeypatch.setattr(sys, "argv", ["acme_cli.py", "issue"])
        with pytest.raises(SystemExit) as exc_info:
            acme_cli.main()
        assert exc_info.value.code == 1

    def test_missing_dns_provider_exits_1(self, monkeypatch):
        _base_env(monkeypatch)
        monkeypatch.delenv("DNS_PROVIDER")
        monkeypatch.setattr(sys, "argv", ["acme_cli.py", "issue"])
        with pytest.raises(SystemExit) as exc_info:
            acme_cli.main()
        assert exc_info.value.code == 1


# ── cmd_renew dispatch ────────────────────────────────────────────────────────

class TestCmdRenew:
    def test_renewed_exits_0(self, monkeypatch):
        _base_env(monkeypatch)
        mock_provider = MagicMock()
        mock_provider.renew_cert.return_value = _issued()
        monkeypatch.setattr(sys, "argv", ["acme_cli.py", "renew"])
        with patch("acme_cli.get_provider", return_value=mock_provider):
            with pytest.raises(SystemExit) as exc_info:
                acme_cli.main()
        assert exc_info.value.code == 0

    def test_not_due_exits_2(self, monkeypatch):
        _base_env(monkeypatch)
        mock_provider = MagicMock()
        mock_provider.renew_cert.return_value = _not_renewed()
        monkeypatch.setattr(sys, "argv", ["acme_cli.py", "renew"])
        with patch("acme_cli.get_provider", return_value=mock_provider):
            with pytest.raises(SystemExit) as exc_info:
                acme_cli.main()
        assert exc_info.value.code == 2

    def test_acme_error_exits_1(self, monkeypatch):
        _base_env(monkeypatch)
        mock_provider = MagicMock()
        mock_provider.renew_cert.side_effect = AcmeError("lego renew failed")
        monkeypatch.setattr(sys, "argv", ["acme_cli.py", "renew"])
        with patch("acme_cli.get_provider", return_value=mock_provider):
            with pytest.raises(SystemExit) as exc_info:
                acme_cli.main()
        assert exc_info.value.code == 1

    def test_missing_acme_email_exits_1(self, monkeypatch):
        _base_env(monkeypatch)
        monkeypatch.delenv("ACME_EMAIL")
        monkeypatch.setattr(sys, "argv", ["acme_cli.py", "renew"])
        with pytest.raises(SystemExit) as exc_info:
            acme_cli.main()
        assert exc_info.value.code == 1

    def test_missing_server_cert_dir_exits_1(self, monkeypatch):
        _base_env(monkeypatch)
        monkeypatch.delenv("SERVER_CERT_DIR")
        monkeypatch.setattr(sys, "argv", ["acme_cli.py", "renew"])
        with pytest.raises(SystemExit) as exc_info:
            acme_cli.main()
        assert exc_info.value.code == 1


# ── cmd_install dispatch ──────────────────────────────────────────────────────

class TestCmdInstall:
    def test_success_calls_install_cert(self, monkeypatch):
        _base_env(monkeypatch)
        mock_provider = MagicMock()
        monkeypatch.setattr(sys, "argv", ["acme_cli.py", "install"])
        with patch("acme_cli.get_provider", return_value=mock_provider):
            acme_cli.main()
        mock_provider.install_cert.assert_called_once()

    def test_acme_error_exits_1(self, monkeypatch):
        _base_env(monkeypatch)
        mock_provider = MagicMock()
        mock_provider.install_cert.side_effect = AcmeError("missing cert file")
        monkeypatch.setattr(sys, "argv", ["acme_cli.py", "install"])
        with patch("acme_cli.get_provider", return_value=mock_provider):
            with pytest.raises(SystemExit) as exc_info:
                acme_cli.main()
        assert exc_info.value.code == 1

    def test_missing_domain_exits_1(self, monkeypatch):
        _base_env(monkeypatch)
        monkeypatch.delenv("DOMAIN")
        monkeypatch.setattr(sys, "argv", ["acme_cli.py", "install"])
        with pytest.raises(SystemExit) as exc_info:
            acme_cli.main()
        assert exc_info.value.code == 1
