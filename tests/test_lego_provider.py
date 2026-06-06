"""Tests for LegoProvider."""
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from acme_provider import AcmeError, IssueResult
from lego_provider import LegoProvider, _ACME_SERVER_MAP, _DNS_PLUGIN_MAP


# ── Fake PEM content ──────────────────────────────────────────────────────────

FAKE_CHAIN_PEM = """\
-----BEGIN CERTIFICATE-----
MIIFAKE1MIIFAKE1MIIFAKE1==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFAKE2MIIFAKE2MIIFAKE2==
-----END CERTIFICATE-----
"""
FAKE_KEY_PEM = "-----BEGIN EC PRIVATE KEY-----\nFAKEKEY==\n-----END EC PRIVATE KEY-----\n"
FAKE_ISSUER_PEM = "-----BEGIN CERTIFICATE-----\nMIIISSUER==\n-----END CERTIFICATE-----\n"
SINGLE_CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIFAKE1==\n-----END CERTIFICATE-----\n"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_proc(returncode: int) -> MagicMock:
    proc = MagicMock()
    proc.returncode = returncode
    return proc


def _setup_lego_state(
    base_dir,
    kt: str,
    domain: str,
    chain_pem: str,
    key_pem: str,
    issuer_pem=None,
) -> None:
    """Write Lego cert state files into the expected directory layout."""
    certs_dir = Path(base_dir) / f"lego-{kt}" / "certificates"
    certs_dir.mkdir(parents=True, exist_ok=True)
    (certs_dir / f"{domain}.crt").write_text(chain_pem)
    (certs_dir / f"{domain}.key").write_text(key_pem)
    if issuer_pem is not None:
        (certs_dir / f"{domain}.issuer.crt").write_text(issuer_pem)


# ── _server_url ───────────────────────────────────────────────────────────────

class TestServerUrl:
    def setup_method(self):
        self.p = LegoProvider()

    def test_known_keys_map_to_url(self):
        for key, url in _ACME_SERVER_MAP.items():
            assert self.p._server_url(key) == url

    def test_unknown_key_falls_back_to_letsencrypt(self):
        le_url = _ACME_SERVER_MAP["letsencrypt"]
        assert self.p._server_url("totally_unknown") == le_url

    def test_http_string_passes_through(self):
        custom = "https://custom.acme.example.com/directory"
        assert self.p._server_url(custom) == custom

    def test_http_plain_passes_through(self):
        custom = "http://local.acme.test/dir"
        assert self.p._server_url(custom) == custom


# ── _dns_plugin ───────────────────────────────────────────────────────────────

class TestDnsPlugin:
    def setup_method(self):
        self.p = LegoProvider()

    @pytest.mark.parametrize("alias,expected", [
        ("cloudflare", "cloudflare"),
        ("cf",         "cloudflare"),
        ("porkbun",    "porkbun"),
        ("route53",    "route53"),
        ("aws",        "route53"),
        ("r53",        "route53"),
        ("digitalocean", "digitalocean"),
        ("do",         "digitalocean"),
        ("godaddy",    "godaddy"),
        ("gd",         "godaddy"),
    ])
    def test_known_alias_maps_correctly(self, alias, expected):
        assert self.p._dns_plugin(alias) == expected

    def test_unknown_provider_passes_through(self):
        assert self.p._dns_plugin("some_unknown_dns") == "some_unknown_dns"

    def test_case_insensitive(self):
        assert self.p._dns_plugin("CloudFlare") == "cloudflare"
        assert self.p._dns_plugin("CF") == "cloudflare"
        assert self.p._dns_plugin("DO") == "digitalocean"


# ── _map_dns_env ──────────────────────────────────────────────────────────────

class TestMapDnsEnv:
    def setup_method(self):
        self.p = LegoProvider()

    def test_cf_token_remapped(self):
        result = self.p._map_dns_env({"CF_Token": "tok123"})
        assert result.get("CF_DNS_API_TOKEN") == "tok123"
        assert "CF_Token" not in result

    def test_cf_key_and_email_remapped(self):
        result = self.p._map_dns_env({"CF_Key": "key1", "CF_Email": "a@b.com"})
        assert result.get("CF_API_KEY") == "key1"
        assert result.get("CF_API_EMAIL") == "a@b.com"

    def test_do_api_key_remapped(self):
        result = self.p._map_dns_env({"DO_API_KEY": "do_token"})
        assert result.get("DO_AUTH_TOKEN") == "do_token"
        assert "DO_API_KEY" not in result

    def test_godaddy_remapped(self):
        result = self.p._map_dns_env({"GD_Key": "gdkey", "GD_Secret": "gdsecret"})
        assert result.get("GODADDY_API_KEY") == "gdkey"
        assert result.get("GODADDY_API_SECRET") == "gdsecret"

    def test_aws_region_remapped(self):
        result = self.p._map_dns_env({"AWS_DEFAULT_REGION": "us-west-2"})
        assert result.get("AWS_REGION") == "us-west-2"
        assert "AWS_DEFAULT_REGION" not in result

    def test_cf_zone_id_dropped(self):
        result = self.p._map_dns_env({"CF_Zone_ID": "zone123"})
        assert "CF_Zone_ID" not in result
        assert "zone123" not in result.values()

    def test_cf_account_id_dropped(self):
        result = self.p._map_dns_env({"CF_Account_ID": "acc123"})
        assert "CF_Account_ID" not in result

    def test_acme_email_dropped(self):
        result = self.p._map_dns_env({"ACME_EMAIL": "user@example.com"})
        assert "ACME_EMAIL" not in result

    def test_unknown_keys_pass_through(self):
        result = self.p._map_dns_env({
            "AWS_ACCESS_KEY_ID": "AKID",
            "PORKBUN_API_KEY": "pbkey",
        })
        assert result.get("AWS_ACCESS_KEY_ID") == "AKID"
        assert result.get("PORKBUN_API_KEY") == "pbkey"

    def test_empty_dict_in_empty_dict_out(self):
        assert self.p._map_dns_env({}) == {}


# ── issue_cert ────────────────────────────────────────────────────────────────

class TestIssueCert:
    def _common_kwargs(self, cert_dir: str) -> dict:
        return dict(
            domain="cppm.example.com",
            acme_server="letsencrypt",
            cert_dir=cert_dir,
            key_types=["ecc", "rsa"],
            dns_provider="cloudflare",
            dns_env={"ACME_EMAIL": "admin@example.com", "CF_Token": "tok"},
            log_file="/tmp/test.log",
        )

    def test_happy_path_both_key_types(self, tmp_path):
        p = LegoProvider()
        with patch.object(p, "_run", return_value=_make_proc(0)) as mock_run:
            result = p.issue_cert(**self._common_kwargs(str(tmp_path)))
        assert result.newly_issued is True
        assert mock_run.call_count == 2

    def test_accept_tos_appears_after_run_subcommand(self, tmp_path):
        """Regression test: --accept-tos must come after the 'run' subcommand."""
        p = LegoProvider()
        calls_args = []
        def capture_run(args, **kwargs):
            calls_args.append(args)
            return _make_proc(0)
        with patch.object(p, "_run", side_effect=capture_run):
            p.issue_cert(**self._common_kwargs(str(tmp_path)))
        for args in calls_args:
            run_idx = args.index("run")
            tos_idx = args.index("--accept-tos")
            assert tos_idx > run_idx, (
                f"--accept-tos (pos {tos_idx}) must come after 'run' (pos {run_idx})"
            )

    def test_ecc_uses_ec256_key_type(self, tmp_path):
        p = LegoProvider()
        calls_args = []
        def capture_run(args, **kwargs):
            calls_args.append(args)
            return _make_proc(0)
        with patch.object(p, "_run", side_effect=capture_run):
            p.issue_cert(
                domain="cppm.example.com",
                acme_server="letsencrypt",
                cert_dir=str(tmp_path),
                key_types=["ecc"],
                dns_provider="cloudflare",
                dns_env={"ACME_EMAIL": "a@b.com"},
                log_file="/tmp/test.log",
            )
        assert "--key-type" in calls_args[0]
        kt_idx = calls_args[0].index("--key-type")
        assert calls_args[0][kt_idx + 1] == "ec256"

    def test_rsa_uses_rsa2048_key_type(self, tmp_path):
        p = LegoProvider()
        calls_args = []
        def capture_run(args, **kwargs):
            calls_args.append(args)
            return _make_proc(0)
        with patch.object(p, "_run", side_effect=capture_run):
            p.issue_cert(
                domain="cppm.example.com",
                acme_server="letsencrypt",
                cert_dir=str(tmp_path),
                key_types=["rsa"],
                dns_provider="cloudflare",
                dns_env={"ACME_EMAIL": "a@b.com"},
                log_file="/tmp/test.log",
            )
        kt_idx = calls_args[0].index("--key-type")
        assert calls_args[0][kt_idx + 1] == "rsa2048"

    def test_ecc_and_rsa_use_separate_path_dirs(self, tmp_path):
        p = LegoProvider()
        calls_args = []
        def capture_run(args, **kwargs):
            calls_args.append(args)
            return _make_proc(0)
        with patch.object(p, "_run", side_effect=capture_run):
            p.issue_cert(**self._common_kwargs(str(tmp_path)))
        paths = []
        for args in calls_args:
            path_idx = args.index("--path")
            paths.append(args[path_idx + 1])
        assert any("lego-ecc" in p for p in paths)
        assert any("lego-rsa" in p for p in paths)
        assert paths[0] != paths[1]

    def test_nonzero_returncode_raises_acme_error(self, tmp_path):
        p = LegoProvider()
        with patch.object(p, "_run", return_value=_make_proc(1)):
            with pytest.raises(AcmeError):
                p.issue_cert(**self._common_kwargs(str(tmp_path)))

    def test_force_deletes_existing_cert_file(self, tmp_path):
        domain = "cppm.example.com"
        # Pre-create the ECC cert file
        ecc_certs = tmp_path / "lego-ecc" / "certificates"
        ecc_certs.mkdir(parents=True)
        cert_file = ecc_certs / f"{domain}.crt"
        cert_file.write_text("old cert")

        p = LegoProvider()
        with patch.object(p, "_run", return_value=_make_proc(0)):
            p.issue_cert(
                domain=domain,
                acme_server="letsencrypt",
                cert_dir=str(tmp_path),
                key_types=["ecc"],
                dns_provider="cloudflare",
                dns_env={"ACME_EMAIL": "a@b.com"},
                log_file="/tmp/test.log",
                force=True,
            )
        # File should have been deleted before subprocess call
        assert not cert_file.exists()

    def test_no_force_leaves_existing_cert_file(self, tmp_path):
        domain = "cppm.example.com"
        ecc_certs = tmp_path / "lego-ecc" / "certificates"
        ecc_certs.mkdir(parents=True)
        cert_file = ecc_certs / f"{domain}.crt"
        cert_file.write_text("old cert")

        p = LegoProvider()
        with patch.object(p, "_run", return_value=_make_proc(0)):
            p.issue_cert(
                domain=domain,
                acme_server="letsencrypt",
                cert_dir=str(tmp_path),
                key_types=["ecc"],
                dns_provider="cloudflare",
                dns_env={"ACME_EMAIL": "a@b.com"},
                log_file="/tmp/test.log",
                force=False,
            )
        # File should still be there (not deleted)
        assert cert_file.exists()

    def test_unknown_key_type_raises_acme_error(self, tmp_path):
        p = LegoProvider()
        with patch.object(p, "_run", return_value=_make_proc(0)):
            with pytest.raises(AcmeError):
                p.issue_cert(
                    domain="cppm.example.com",
                    acme_server="letsencrypt",
                    cert_dir=str(tmp_path),
                    key_types=["badtype"],
                    dns_provider="cloudflare",
                    dns_env={"ACME_EMAIL": "a@b.com"},
                    log_file="/tmp/test.log",
                )

    def test_credential_remapping_cf_token(self, tmp_path):
        """CF_Token must be remapped to CF_DNS_API_TOKEN in subprocess env."""
        p = LegoProvider()
        captured_env = {}
        def capture_run(args, extra_env=None, **kwargs):
            if extra_env:
                captured_env.update(extra_env)
            return _make_proc(0)
        with patch.object(p, "_run", side_effect=capture_run):
            p.issue_cert(
                domain="cppm.example.com",
                acme_server="letsencrypt",
                cert_dir=str(tmp_path),
                key_types=["ecc"],
                dns_provider="cloudflare",
                dns_env={
                    "ACME_EMAIL": "a@b.com",
                    "CF_Token": "my_token",
                    "CF_Zone_ID": "zone123",
                },
                log_file="/tmp/test.log",
            )
        assert "CF_DNS_API_TOKEN" in captured_env
        assert captured_env["CF_DNS_API_TOKEN"] == "my_token"
        assert "CF_Token" not in captured_env
        assert "CF_Zone_ID" not in captured_env


# ── renew_cert ────────────────────────────────────────────────────────────────

class TestRenewCert:
    def _common_kwargs(self, cert_dir: str) -> dict:
        return dict(
            domain="cppm.example.com",
            acme_server="letsencrypt",
            cert_dir=cert_dir,
            key_types=["ecc", "rsa"],
            dns_provider="cloudflare",
            dns_env={"ACME_EMAIL": "admin@example.com"},
            log_file="/tmp/test.log",
        )

    def test_mtime_changed_means_issued_true(self, tmp_path):
        domain = "cppm.example.com"
        # Set up cert files
        _setup_lego_state(tmp_path, "ecc", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM)
        _setup_lego_state(tmp_path, "rsa", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM)

        ecc_cert = tmp_path / "lego-ecc" / "certificates" / f"{domain}.crt"
        rsa_cert = tmp_path / "lego-rsa" / "certificates" / f"{domain}.crt"
        before_time = ecc_cert.stat().st_mtime

        p = LegoProvider()
        call_count = [0]

        def mock_run(args, **kwargs):
            # Simulate renewal by bumping mtime
            call_count[0] += 1
            if "renew" in args:
                if "lego-ecc" in " ".join(args):
                    os.utime(str(ecc_cert), (before_time + 100, before_time + 100))
                elif "lego-rsa" in " ".join(args):
                    os.utime(str(rsa_cert), (before_time + 100, before_time + 100))
            return _make_proc(0)

        with patch.object(p, "_run", side_effect=mock_run):
            result = p.renew_cert(**self._common_kwargs(str(tmp_path)))

        assert result.newly_issued is True

    def test_mtime_unchanged_means_issued_false(self, tmp_path):
        domain = "cppm.example.com"
        _setup_lego_state(tmp_path, "ecc", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM)
        _setup_lego_state(tmp_path, "rsa", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM)

        p = LegoProvider()
        with patch.object(p, "_run", return_value=_make_proc(0)):
            result = p.renew_cert(**self._common_kwargs(str(tmp_path)))

        assert result.newly_issued is False

    def test_ecc_fails_rsa_still_attempted_then_raises(self, tmp_path):
        """If ECC fails, RSA should still be attempted; AcmeError raised at the end."""
        domain = "cppm.example.com"
        _setup_lego_state(tmp_path, "ecc", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM)
        _setup_lego_state(tmp_path, "rsa", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM)

        call_args_list = []
        def mock_run(args, **kwargs):
            call_args_list.append(args)
            if "lego-ecc" in " ".join(args):
                return _make_proc(1)
            return _make_proc(0)

        p = LegoProvider()
        with patch.object(p, "_run", side_effect=mock_run):
            with pytest.raises(AcmeError) as exc_info:
                p.renew_cert(**self._common_kwargs(str(tmp_path)))

        # Both ECC and RSA should have been called
        assert len(call_args_list) == 2
        assert "ECC" in str(exc_info.value)

    def test_both_fail_error_contains_ecc_and_rsa(self, tmp_path):
        domain = "cppm.example.com"
        _setup_lego_state(tmp_path, "ecc", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM)
        _setup_lego_state(tmp_path, "rsa", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM)

        p = LegoProvider()
        with patch.object(p, "_run", return_value=_make_proc(1)):
            with pytest.raises(AcmeError) as exc_info:
                p.renew_cert(**self._common_kwargs(str(tmp_path)))

        error_msg = str(exc_info.value)
        assert "ECC" in error_msg
        assert "RSA" in error_msg

    def test_days_30_in_args(self, tmp_path):
        domain = "cppm.example.com"
        _setup_lego_state(tmp_path, "ecc", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM)
        calls_args = []
        def capture_run(args, **kwargs):
            calls_args.append(args)
            return _make_proc(0)

        p = LegoProvider()
        with patch.object(p, "_run", side_effect=capture_run):
            p.renew_cert(
                domain=domain,
                acme_server="letsencrypt",
                cert_dir=str(tmp_path),
                key_types=["ecc"],
                dns_provider="cloudflare",
                dns_env={"ACME_EMAIL": "a@b.com"},
                log_file="/tmp/test.log",
            )
        assert "--days" in calls_args[0]
        days_idx = calls_args[0].index("--days")
        assert calls_args[0][days_idx + 1] == "30"


# ── install_cert ──────────────────────────────────────────────────────────────

class TestInstallCert:
    def _install(self, tmp_path, domain, key_types):
        p = LegoProvider()
        p.install_cert(
            domain=domain,
            cert_dir=str(tmp_path),
            key_types=key_types,
            log_file="/tmp/test.log",
        )

    def test_happy_path_ecc_all_four_files_created(self, tmp_path):
        domain = "cppm.example.com"
        _setup_lego_state(tmp_path, "ecc", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM, FAKE_ISSUER_PEM)
        self._install(tmp_path, domain, ["ecc"])
        assert (tmp_path / f"{domain}.ecc.cer").exists()
        assert (tmp_path / f"{domain}.ecc.key").exists()
        assert (tmp_path / f"{domain}.ecc.fullchain.cer").exists()
        assert (tmp_path / f"{domain}.ecc.ca.cer").exists()

    def test_happy_path_rsa_all_four_files_created(self, tmp_path):
        domain = "cppm.example.com"
        _setup_lego_state(tmp_path, "rsa", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM, FAKE_ISSUER_PEM)
        self._install(tmp_path, domain, ["rsa"])
        assert (tmp_path / f"{domain}.rsa.cer").exists()
        assert (tmp_path / f"{domain}.rsa.key").exists()
        assert (tmp_path / f"{domain}.rsa.fullchain.cer").exists()
        assert (tmp_path / f"{domain}.rsa.ca.cer").exists()

    def test_fullchain_contains_both_cert_blocks(self, tmp_path):
        domain = "cppm.example.com"
        _setup_lego_state(tmp_path, "ecc", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM, FAKE_ISSUER_PEM)
        self._install(tmp_path, domain, ["ecc"])
        fullchain = (tmp_path / f"{domain}.ecc.fullchain.cer").read_text()
        assert "MIIFAKE1" in fullchain
        assert "MIIFAKE2" in fullchain

    def test_cer_contains_only_first_pem_block(self, tmp_path):
        domain = "cppm.example.com"
        _setup_lego_state(tmp_path, "ecc", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM, FAKE_ISSUER_PEM)
        self._install(tmp_path, domain, ["ecc"])
        cer = (tmp_path / f"{domain}.ecc.cer").read_text()
        assert "MIIFAKE1" in cer
        assert "MIIFAKE2" not in cer

    def test_private_key_file_mode_600(self, tmp_path):
        domain = "cppm.example.com"
        _setup_lego_state(tmp_path, "ecc", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM, FAKE_ISSUER_PEM)
        self._install(tmp_path, domain, ["ecc"])
        key_file = tmp_path / f"{domain}.ecc.key"
        mode = oct(key_file.stat().st_mode)[-3:]
        assert mode == "600"

    def test_ca_cert_from_issuer_crt_when_present(self, tmp_path):
        domain = "cppm.example.com"
        _setup_lego_state(tmp_path, "ecc", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM, FAKE_ISSUER_PEM)
        self._install(tmp_path, domain, ["ecc"])
        ca = (tmp_path / f"{domain}.ecc.ca.cer").read_text()
        assert ca == FAKE_ISSUER_PEM

    def test_ca_cert_fallback_when_issuer_absent_uses_second_cert(self, tmp_path):
        domain = "cppm.example.com"
        _setup_lego_state(tmp_path, "ecc", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM)
        self._install(tmp_path, domain, ["ecc"])
        ca = (tmp_path / f"{domain}.ecc.ca.cer").read_text()
        assert "MIIFAKE2" in ca
        assert "MIIFAKE1" not in ca

    def test_ca_cert_fallback_fails_when_single_cert_and_no_issuer(self, tmp_path):
        domain = "cppm.example.com"
        _setup_lego_state(tmp_path, "ecc", domain, SINGLE_CERT_PEM, FAKE_KEY_PEM)
        with pytest.raises(AcmeError):
            self._install(tmp_path, domain, ["ecc"])

    def test_missing_crt_file_raises_acme_error_with_not_found(self, tmp_path):
        domain = "cppm.example.com"
        p = LegoProvider()
        with pytest.raises(AcmeError) as exc_info:
            p.install_cert(
                domain=domain,
                cert_dir=str(tmp_path),
                key_types=["ecc"],
                log_file="/tmp/test.log",
            )
        assert "not found" in str(exc_info.value).lower()

    def test_both_ecc_and_rsa_eight_files_created(self, tmp_path):
        domain = "cppm.example.com"
        _setup_lego_state(tmp_path, "ecc", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM, FAKE_ISSUER_PEM)
        _setup_lego_state(tmp_path, "rsa", domain, FAKE_CHAIN_PEM, FAKE_KEY_PEM, FAKE_ISSUER_PEM)
        self._install(tmp_path, domain, ["ecc", "rsa"])
        for kt in ("ecc", "rsa"):
            for suffix in (f"{kt}.cer", f"{kt}.key", f"{kt}.fullchain.cer", f"{kt}.ca.cer"):
                assert (tmp_path / f"{domain}.{suffix}").exists(), f"Missing: {domain}.{suffix}"
