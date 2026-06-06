"""Tests for acme_provider module: IssueResult, get_provider factory."""
import pytest

from acme_provider import AcmeError, IssueResult, KeyTypeResult, get_provider


# ── IssueResult.newly_issued ──────────────────────────────────────────────────

class TestNewlyIssued:
    def test_true_when_any_issued(self):
        result = IssueResult(results=[
            KeyTypeResult(key_type="ecc", issued=False),
            KeyTypeResult(key_type="rsa", issued=True),
        ])
        assert result.newly_issued is True

    def test_true_when_all_issued(self):
        result = IssueResult(results=[
            KeyTypeResult(key_type="ecc", issued=True),
            KeyTypeResult(key_type="rsa", issued=True),
        ])
        assert result.newly_issued is True

    def test_false_when_all_not_issued(self):
        result = IssueResult(results=[
            KeyTypeResult(key_type="ecc", issued=False),
            KeyTypeResult(key_type="rsa", issued=False),
        ])
        assert result.newly_issued is False

    def test_false_when_results_empty(self):
        result = IssueResult(results=[])
        assert result.newly_issued is False


# ── get_provider factory ──────────────────────────────────────────────────────

class TestGetProvider:
    def test_lego_returns_lego_provider(self):
        from lego_provider import LegoProvider
        provider = get_provider("lego")
        assert isinstance(provider, LegoProvider)

    def test_acme_sh_returns_acme_sh_provider(self):
        from acme_sh_provider import AcmeShProvider
        provider = get_provider("acme_sh")
        assert isinstance(provider, AcmeShProvider)

    def test_default_returns_lego_provider(self):
        from lego_provider import LegoProvider
        provider = get_provider()
        assert isinstance(provider, LegoProvider)

    def test_unknown_raises_value_error(self):
        with pytest.raises(ValueError):
            get_provider("unknown")
