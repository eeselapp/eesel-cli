"""Unit tests for the eesel CLI.

Run with: `python3 -m pytest test_eesel.py -v` from the repo root.

The CLI script has no `.py` extension, so we load it via importlib.
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import hmac
import http.client
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
import re
import socket
import ssl
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ──────────────────────────────────────────────────────────────────────────
# Module loading
# ──────────────────────────────────────────────────────────────────────────

_HERE = Path(__file__).parent.resolve()


def _load_eesel():
    # The CLI script has no `.py` extension, so spec_from_file_location returns
    # None — bypass that by giving importlib an explicit SourceFileLoader.
    loader = SourceFileLoader("eesel_cli_module", str(_HERE / "eesel"))
    spec = importlib.util.spec_from_loader("eesel_cli_module", loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


eesel = _load_eesel()


# ──────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────


@pytest.fixture
def tmp_config(tmp_path, monkeypatch):
    """Redirect the module's config paths into a tmpdir for each test."""
    config_dir = tmp_path / "eesel"
    sessions_dir = config_dir / "sessions"
    monkeypatch.setattr(eesel, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(eesel, "SESSIONS_DIR", sessions_dir)
    monkeypatch.setattr(eesel, "CREDS_FILE", config_dir / "credentials.json")
    monkeypatch.setattr(eesel, "CURRENT_FILE", config_dir / "current.json")
    return config_dir


@pytest.fixture
def fake_creds(tmp_config):
    creds = {
        "env": "dev",
        "api_url": "http://localhost:8080",
        "dashboard_url": "http://localhost:3000",
        "workspace_id": "ws-test-123",
        "agent_id": "agent-test-456",
        "token": "test-jwt-token",
        "expires_at": int(time.time()) + 3600,
        # These tests target the new platform; caching it here keeps every
        # command's resolve_platform() a local read (no license probe / network).
        # Legacy-detection tests pop or override this explicitly.
        "platform": "platform",
    }
    eesel.save_creds(creds)
    return creds


@pytest.fixture(autouse=True)
def _reset_impersonation_target():
    # The guard sets _impersonation_target and require_creds sets _current_creds
    # as module globals (not via monkeypatch), so force both clear around every
    # test to stop the backstop / 401 self-heal leaking state between tests.
    eesel._impersonation_target = None
    eesel._current_creds = None
    yield
    eesel._impersonation_target = None
    eesel._current_creds = None


# ──────────────────────────────────────────────────────────────────────────
# JWT helpers
# ──────────────────────────────────────────────────────────────────────────


class TestB64Url:
    def test_no_padding(self):
        # standard b64 of b"abc" is "YWJj" (no padding) — should match
        assert eesel._b64url(b"abc") == "YWJj"

    def test_strips_padding(self):
        # b"a" → "YQ==" in standard b64; b64url strips trailing "="
        assert eesel._b64url(b"a") == "YQ"

    def test_url_safe_alphabet(self):
        # bytes that produce '+' or '/' in standard b64 should yield '-' and '_'.
        # b'\xfb\xff' → standard "+/8=", url-safe "-_8"
        out = eesel._b64url(b"\xfb\xff")
        assert "+" not in out and "/" not in out
        assert out == "-_8"


class TestMintDevJwt:
    def test_three_parts(self):
        token = eesel.mint_dev_jwt("ws-1", "agent-1")
        assert token.count(".") == 2

    def test_payload_contains_ids(self):
        token = eesel.mint_dev_jwt("ws-1", "agent-1")
        _, payload_b64, _ = token.split(".")
        # Re-pad for stdlib base64 decode.
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        assert payload["workspace_id"] == "ws-1"
        assert payload["agent_id"] == "agent-1"
        assert payload["exp"] > payload["iat"]
        assert payload["exp"] - payload["iat"] == eesel.CLI_TOKEN_TTL_SECONDS  # 30d

    def test_signature_verifies(self):
        token = eesel.mint_dev_jwt("ws-1", "agent-1")
        header, payload, sig = token.split(".")
        signing_input = f"{header}.{payload}".encode()
        expected = base64.urlsafe_b64encode(hmac.new(eesel.DEV_JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()).rstrip(b"=").decode()
        assert sig == expected

    def test_omits_agent_id_when_none(self):
        token = eesel.mint_dev_jwt("ws-1", None)
        _, payload_b64, _ = token.split(".")
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        assert "agent_id" not in payload
        assert payload["workspace_id"] == "ws-1"


class TestLoginDev:
    def test_mints_workspace_scoped_token_and_stores_no_agent(self, tmp_config, monkeypatch):
        monkeypatch.setattr(eesel, "discover_local_ids", lambda workspace_id=None: ("ws-1", "agent-1", "user-1"))

        creds = eesel.login_dev()

        _, payload_b64, _ = creds["token"].split(".")
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        assert payload["workspace_id"] == "ws-1"
        assert payload["user_id"] == "user-1"
        assert "agent_id" not in payload
        # Login no longer stores a default agent: commands scope themselves.
        assert creds["agent_id"] is None


# ──────────────────────────────────────────────────────────────────────────
# Credential storage
# ──────────────────────────────────────────────────────────────────────────


class TestCreds:
    def test_load_returns_none_when_missing(self, tmp_config):
        assert eesel.load_creds() is None

    def test_save_then_load_roundtrip(self, tmp_config):
        original = {"env": "dev", "workspace_id": "ws-1", "token": "x", "expires_at": 9999}
        eesel.save_creds(original)
        loaded = eesel.load_creds()
        assert loaded == original

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
    def test_creds_file_chmod_600(self, tmp_config):
        eesel.save_creds({"token": "secret"})
        mode = eesel.CREDS_FILE.stat().st_mode & 0o777
        assert mode == 0o600

    def test_require_creds_exits_when_missing(self, tmp_config):
        with pytest.raises(SystemExit):
            eesel.require_creds()

    def test_require_creds_exits_when_expired(self, tmp_config):
        eesel.save_creds(
            {
                "env": "dev",
                "workspace_id": "ws-1",
                "token": "x",
                "expires_at": int(time.time()) - 1,  # already expired
            }
        )
        with pytest.raises(SystemExit):
            eesel.require_creds()

    def test_require_creds_returns_when_valid(self, tmp_config, fake_creds):
        out = eesel.require_creds()
        assert out["workspace_id"] == "ws-test-123"

    def test_require_creds_refreshes_near_expiry(self, tmp_config, monkeypatch):
        # A prod login with a refresh token and an access token inside the skew
        # window is renewed silently rather than rejected.
        eesel.save_creds(
            {
                "env": "prod",
                "workspace_id": "ws-1",
                "token": "old",
                "refresh_token": "rt",
                "expires_at": int(time.time()) + 10,  # within TOKEN_REFRESH_SKEW_SECONDS
                "dashboard_url": "https://dashboard.eesel.ai",
            }
        )

        def fake_refresh(creds):
            creds["token"] = "fresh"
            creds["expires_at"] = int(time.time()) + 3600
            return creds

        monkeypatch.setattr(eesel, "refresh_prod_token", fake_refresh)
        out = eesel.require_creds()
        assert out["token"] == "fresh"

    def test_require_creds_exits_when_refresh_fails_and_expired(self, tmp_config, monkeypatch):
        eesel.save_creds(
            {
                "env": "prod",
                "workspace_id": "ws-1",
                "token": "old",
                "refresh_token": "rt",
                "expires_at": int(time.time()) - 1,  # already dead
            }
        )
        monkeypatch.setattr(eesel, "refresh_prod_token", lambda creds: None)
        with pytest.raises(SystemExit):
            eesel.require_creds()

    def test_require_creds_uses_current_token_when_refresh_fails_but_not_expired(
        self, tmp_config, monkeypatch
    ):
        # Refresh failed transiently but the access token is still valid — use
        # it for this command rather than forcing a re-login.
        eesel.save_creds(
            {
                "env": "prod",
                "workspace_id": "ws-1",
                "token": "still-good",
                "refresh_token": "rt",
                "expires_at": int(time.time()) + 30,  # near expiry, not past
            }
        )
        monkeypatch.setattr(eesel, "refresh_prod_token", lambda creds: None)
        out = eesel.require_creds()
        assert out["token"] == "still-good"

    def test_require_creds_does_not_refresh_dev_token(self, tmp_config, monkeypatch):
        # A dev login has no refresh token; an expired one means re-login, and
        # refresh_prod_token must never be called.
        eesel.save_creds(
            {
                "env": "dev",
                "workspace_id": "ws-1",
                "token": "x",
                "expires_at": int(time.time()) - 1,
            }
        )
        called = {"hit": False}

        def boom(creds):
            called["hit"] = True
            return creds

        monkeypatch.setattr(eesel, "refresh_prod_token", boom)
        with pytest.raises(SystemExit):
            eesel.require_creds()
        assert called["hit"] is False


class TestLoginPayload:
    """`_creds_from_login_payload` accepts both the Auth0 and legacy workspace
    handoff shapes, so a current CLI works against any dashboard version."""

    def test_auth0_payload_stores_access_and_refresh(self, tmp_config):
        creds = eesel._creds_from_login_payload(
            {
                "access_token": "auth0-access",
                "refresh_token": "rt",
                "workspace_id": "ws-1",
                "user_email": "a@b.com",
                "expires_in": 3600,
            },
            "https://oracle.eesel.app",
            "https://dashboard.eesel.ai",
        )
        assert creds["token"] == "auth0-access"
        assert creds["refresh_token"] == "rt"
        assert creds["workspace_id"] == "ws-1"
        assert creds["expires_at"] <= int(time.time()) + 3600

    def test_workspace_payload_stores_bare_token_no_refresh(self, tmp_config):
        # A dashboard that predates the Auth0 handoff (or a rollback) returns a
        # bare workspace token. The CLI still logs in; no refresh token is set.
        creds = eesel._creds_from_login_payload(
            {
                "token": "ws-jwt",
                "workspace_id": "ws-1",
                "expires_in": 2592000,
            },
            "https://oracle.eesel.app",
            "https://dashboard.eesel.ai",
        )
        assert creds["token"] == "ws-jwt"
        assert "refresh_token" not in creds
        # A workspace-token login is treated like the dev token by require_creds:
        # no refresh, re-login on expiry.
        eesel.save_creds(creds)
        assert eesel.require_creds()["token"] == "ws-jwt"

    def test_workspace_payload_ttl_falls_back_to_30_days(self, tmp_config):
        creds = eesel._creds_from_login_payload(
            {"token": "ws-jwt", "workspace_id": "ws-1"},  # no expires_in
            "https://oracle.eesel.app",
            "https://dashboard.eesel.ai",
        )
        # Workspace tokens are long-lived; the fallback must not be the short
        # Auth0 window.
        assert creds["expires_at"] > int(time.time()) + eesel.CLI_TOKEN_TTL_SECONDS - 5

    def test_auth0_payload_ttl_falls_back_to_short_window(self, tmp_config):
        creds = eesel._creds_from_login_payload(
            {"access_token": "a", "refresh_token": "r", "workspace_id": "ws-1"},
            "https://oracle.eesel.app",
            "https://dashboard.eesel.ai",
        )
        expected = int(time.time()) + eesel.PROD_TOKEN_TTL_FALLBACK_SECONDS
        assert abs(creds["expires_at"] - expected) <= 5

    def test_exits_when_no_token_at_all(self, tmp_config):
        with pytest.raises(SystemExit):
            eesel._creds_from_login_payload(
                {"workspace_id": "ws-1"}, "https://oracle.eesel.app", "https://dashboard.eesel.ai"
            )

    def test_exits_when_workspace_id_missing(self, tmp_config):
        with pytest.raises(SystemExit):
            eesel._creds_from_login_payload(
                {"access_token": "a", "refresh_token": "r"},
                "https://oracle.eesel.app",
                "https://dashboard.eesel.ai",
            )


class _FakeResp:
    """Minimal stand-in for the object urllib.request.urlopen yields."""

    def __init__(self, data):
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return json.dumps(self._data).encode()


# ──────────────────────────────────────────────────────────────────────────
# Per-worktree branch-env link (`eesel link`, ENG-5002)
# ──────────────────────────────────────────────────────────────────────────

PREPROD_URL = "https://my-slug.preprod.eesel.xyz"
# The exact shape server/app/api/dev_session.py returns (contract under test).
DEV_SESSION_RESP = {
    "workspace_id": "ws-branch-abc",
    "user_id": "auth0|preview-dev-user",
    "auth_token": "branch-jwt-xyz",
}


@pytest.fixture
def linked_worktree(tmp_path, monkeypatch):
    """A git worktree linked to a branch env, with cwd in a deep subdir — so
    tests exercise the walk-up discovery from where an agent actually runs."""
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / "eesel.dev.json").write_text(json.dumps({"base_url": PREPROD_URL}))
    deep = root / "server" / "app" / "api"
    deep.mkdir(parents=True)
    monkeypatch.chdir(deep)
    monkeypatch.delenv("EESEL_BASE_URL", raising=False)
    monkeypatch.delenv("EESEL_AGENT", raising=False)
    return root


def _stub_dev_session(monkeypatch, session_resp=DEV_SESSION_RESP, session_status=200, agents=None):
    """Route the two HTTP calls a linked command makes: POST /dev/session (via
    `http_request_allow_error`, so it can react to status) mints the token; GET
    /agents (via `http_request`) is the command itself. Returns recorded calls."""
    calls = []

    def fake_allow(method, url, *, token=None, body=None, timeout=60):
        calls.append({"method": method, "url": url, "token": token, "body": body})
        return session_status, session_resp

    def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
        calls.append({"method": method, "url": url, "token": token, "body": body})
        if "/agents" in url:
            return {"agents": agents or []}
        return {}

    monkeypatch.setattr(eesel, "http_request_allow_error", fake_allow)
    monkeypatch.setattr(eesel, "http_request", fake)
    return calls


class TestIsPreprodUrl:
    def test_accepts_branch_env(self):
        assert eesel.is_preprod_url("https://foo.preprod.eesel.xyz")
        assert eesel.is_preprod_url("https://a-b-c.preprod.eesel.xyz/")

    def test_rejects_prod_and_dev(self):
        assert not eesel.is_preprod_url("https://oracle.eesel.app")
        assert not eesel.is_preprod_url("https://dashboard.eesel.ai")
        assert not eesel.is_preprod_url("http://localhost:8080")

    def test_rejects_http_scheme(self):
        # branch envs are https; a plaintext preprod host is still refused.
        assert not eesel.is_preprod_url("http://foo.preprod.eesel.xyz")

    def test_rejects_lookalike_hosts(self):
        # a real dot must precede the suffix, and it must be the trailing host.
        assert not eesel.is_preprod_url("https://preprod.eesel.xyz")
        assert not eesel.is_preprod_url("https://evil-preprod.eesel.xyz")
        assert not eesel.is_preprod_url("https://foo.preprod.eesel.xyz.evil.com")

    def test_rejects_no_scheme(self):
        assert not eesel.is_preprod_url("oracle.eesel.app")
        assert not eesel.is_preprod_url("foo.preprod.eesel.xyz")


class TestWalkUpFind:
    def test_finds_in_current_dir(self, tmp_path):
        (tmp_path / "eesel.dev.json").write_text("{}")
        assert eesel.walk_up_find("eesel.dev.json", tmp_path) == tmp_path.resolve()

    def test_finds_by_walking_up_from_deep_subdir(self, tmp_path):
        (tmp_path / "eesel.dev.json").write_text("{}")
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        assert eesel.walk_up_find("eesel.dev.json", deep) == tmp_path.resolve()

    def test_returns_none_when_absent(self, tmp_path):
        deep = tmp_path / "a" / "b"
        deep.mkdir(parents=True)
        assert eesel.walk_up_find("eesel.dev.json", deep) is None

    def test_finds_git_dir(self, tmp_path):
        (tmp_path / ".git").mkdir()
        deep = tmp_path / "x"
        deep.mkdir()
        assert eesel.walk_up_find(".git", deep) == tmp_path.resolve()


class TestAddToGitignore:
    def test_creates_when_missing(self, tmp_path):
        eesel.add_to_gitignore(tmp_path, "eesel.dev.json")
        assert (tmp_path / ".gitignore").read_text() == "eesel.dev.json\n"

    def test_appends_newline_when_file_lacks_trailing(self, tmp_path):
        gi = tmp_path / ".gitignore"
        gi.write_text("node_modules")  # no trailing newline
        eesel.add_to_gitignore(tmp_path, "eesel.dev.json")
        assert gi.read_text() == "node_modules\neesel.dev.json\n"

    def test_preserves_existing_and_appends(self, tmp_path):
        gi = tmp_path / ".gitignore"
        gi.write_text("node_modules\n__pycache__/\n")
        eesel.add_to_gitignore(tmp_path, "eesel.dev.json")
        assert gi.read_text() == "node_modules\n__pycache__/\neesel.dev.json\n"

    def test_idempotent(self, tmp_path):
        eesel.add_to_gitignore(tmp_path, "eesel.dev.json")
        eesel.add_to_gitignore(tmp_path, "eesel.dev.json")
        assert (tmp_path / ".gitignore").read_text().count("eesel.dev.json") == 1


class TestResolveDevBaseUrl:
    def test_none_when_no_link_and_no_env(self, tmp_path, monkeypatch):
        monkeypatch.delenv("EESEL_BASE_URL", raising=False)
        monkeypatch.chdir(tmp_path)
        assert eesel.resolve_dev_base_url() is None

    def test_env_var_wins_over_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "eesel.dev.json").write_text(json.dumps({"base_url": PREPROD_URL}))
        monkeypatch.setenv("EESEL_BASE_URL", "https://other.preprod.eesel.xyz/")
        assert eesel.resolve_dev_base_url() == "https://other.preprod.eesel.xyz"

    def test_reads_file_walking_up_and_strips_slash(self, tmp_path, monkeypatch):
        # The config lives at the worktree root; a deep subdir still finds it.
        monkeypatch.delenv("EESEL_BASE_URL", raising=False)
        (tmp_path / ".git").mkdir()
        (tmp_path / "eesel.dev.json").write_text(json.dumps({"base_url": PREPROD_URL + "/"}))
        deep = tmp_path / "a" / "b"
        deep.mkdir(parents=True)
        monkeypatch.chdir(deep)
        assert eesel.resolve_dev_base_url() == PREPROD_URL

    def test_ignores_stray_config_above_worktree_root(self, tmp_path, monkeypatch):
        # A forgotten eesel.dev.json above the repo (e.g. in $HOME) must NOT
        # hijack commands inside an unrelated repo below it.
        monkeypatch.delenv("EESEL_BASE_URL", raising=False)
        (tmp_path / "eesel.dev.json").write_text(json.dumps({"base_url": PREPROD_URL}))
        repo = tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)
        sub = repo / "src"
        sub.mkdir()
        monkeypatch.chdir(sub)
        assert eesel.resolve_dev_base_url() is None

    def test_errors_on_missing_base_url(self, tmp_path, monkeypatch, capsys):
        monkeypatch.delenv("EESEL_BASE_URL", raising=False)
        monkeypatch.chdir(tmp_path)
        (tmp_path / "eesel.dev.json").write_text(json.dumps({"nope": 1}))
        with pytest.raises(SystemExit):
            eesel.resolve_dev_base_url()

    def test_errors_on_non_string_base_url(self, tmp_path, monkeypatch):
        # A hand-edited non-string base_url gives a clean error, not a traceback.
        monkeypatch.delenv("EESEL_BASE_URL", raising=False)
        monkeypatch.chdir(tmp_path)
        (tmp_path / "eesel.dev.json").write_text(json.dumps({"base_url": 123}))
        with pytest.raises(SystemExit):
            eesel.resolve_dev_base_url()


class TestDevSessionCreds:
    def test_refuses_non_preprod_before_any_network(self, monkeypatch):
        # AC#6: hard-refuse a non-preprod host with NO network call (neither helper).
        called = []
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: called.append(1) or {})
        monkeypatch.setattr(eesel, "http_request_allow_error", lambda *a, **k: called.append(1) or (200, {}))
        with pytest.raises(SystemExit):
            eesel.dev_session_creds("https://oracle.eesel.app")
        assert called == []

    def test_mints_creds_from_dev_session(self, monkeypatch):
        calls = _stub_dev_session(monkeypatch)
        creds = eesel.dev_session_creds(PREPROD_URL)
        assert creds["api_url"] == PREPROD_URL
        assert creds["workspace_id"] == "ws-branch-abc"
        assert creds["token"] == "branch-jwt-xyz"
        assert creds["env"] == "preprod"
        assert creds["agent_id"] is None
        assert creds["ephemeral"] is True  # marked so save_creds refuses to persist it
        assert calls[0]["method"] == "POST"
        assert calls[0]["url"] == PREPROD_URL + "/dev/session"

    def test_errors_when_response_missing_token(self, monkeypatch):
        _stub_dev_session(monkeypatch, session_resp={"workspace_id": "ws-1"})
        with pytest.raises(SystemExit):
            eesel.dev_session_creds(PREPROD_URL)

    def test_errors_on_non_200(self, monkeypatch, capsys):
        # A torn-down / non-dev env 404s on /dev/session — clean actionable error.
        _stub_dev_session(monkeypatch, session_status=404, session_resp={"error": "not found"})
        with pytest.raises(SystemExit):
            eesel.dev_session_creds(PREPROD_URL)
        assert "404" in capsys.readouterr().err


class TestCmdLink:
    def _link(self, url):
        args = eesel.build_parser(staff=False).parse_args(["link", url])
        return args.func(args)

    def test_writes_url_only_config_and_gitignores_it(self, tmp_path, monkeypatch):
        # AC#1: writes eesel.dev.json = exactly {"base_url": ...}, and gitignores it.
        (tmp_path / ".git").mkdir()
        monkeypatch.chdir(tmp_path)
        assert self._link(PREPROD_URL) == 0
        data = json.loads((tmp_path / "eesel.dev.json").read_text())
        assert data == {"base_url": PREPROD_URL}  # URL only — no token, no workspace id
        assert "eesel.dev.json" in (tmp_path / ".gitignore").read_text().splitlines()

    def test_strips_trailing_slash(self, tmp_path, monkeypatch):
        (tmp_path / ".git").mkdir()
        monkeypatch.chdir(tmp_path)
        self._link(PREPROD_URL + "/")
        assert json.loads((tmp_path / "eesel.dev.json").read_text())["base_url"] == PREPROD_URL

    def test_writes_at_worktree_root_from_subdir(self, tmp_path, monkeypatch):
        # AC#4 (write side): run from a deep subdir, config lands at the .git root.
        (tmp_path / ".git").mkdir()
        deep = tmp_path / "a" / "b"
        deep.mkdir(parents=True)
        monkeypatch.chdir(deep)
        self._link(PREPROD_URL)
        assert (tmp_path / "eesel.dev.json").exists()
        assert not (deep / "eesel.dev.json").exists()

    def test_refuses_non_preprod(self, tmp_path, monkeypatch, capsys):
        # AC#6 (link side): won't even write a config for a non-branch host.
        monkeypatch.chdir(tmp_path)
        assert self._link("https://oracle.eesel.app") == 1
        assert not (tmp_path / "eesel.dev.json").exists()

    def test_falls_back_to_cwd_outside_git(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)  # no .git under tmp
        self._link(PREPROD_URL)
        assert (tmp_path / "eesel.dev.json").exists()


class TestRequireCredsBranchOverride:
    def test_linked_worktree_mints_without_login_and_stores_nothing(
        self, tmp_config, linked_worktree, monkeypatch
    ):
        # The core promise: no credentials.json on disk, yet a linked worktree
        # resolves creds by minting from /dev/session — and stores nothing.
        _stub_dev_session(monkeypatch)
        assert eesel.load_creds() is None  # genuinely not logged in
        creds = eesel.require_creds()
        assert creds["api_url"] == PREPROD_URL
        assert creds["workspace_id"] == "ws-branch-abc"
        assert creds["token"] == "branch-jwt-xyz"
        assert not eesel.CREDS_FILE.exists()  # nothing written to disk

    def test_env_var_override(self, tmp_config, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("EESEL_AGENT", raising=False)
        monkeypatch.setenv("EESEL_BASE_URL", "https://envwin.preprod.eesel.xyz")
        calls = _stub_dev_session(monkeypatch)
        creds = eesel.require_creds()
        assert creds["api_url"] == "https://envwin.preprod.eesel.xyz"
        assert calls[0]["url"].endswith("/dev/session")

    def test_no_link_falls_through_to_stored_login(
        self, tmp_config, fake_creds, tmp_path, monkeypatch
    ):
        # AC#5 must-not-change: no eesel.dev.json + no EESEL_BASE_URL → the stored
        # login is used exactly as before, with no /dev/session mint.
        monkeypatch.delenv("EESEL_BASE_URL", raising=False)
        monkeypatch.delenv("EESEL_AGENT", raising=False)
        monkeypatch.chdir(tmp_path)
        called = []
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: called.append(a) or {})
        creds = eesel.require_creds()
        assert creds["api_url"] == "http://localhost:8080"  # the stored dev login
        assert creds["token"] == "test-jwt-token"
        assert called == []  # no network mint happened


class TestLinkedCommandContract:
    def test_agents_list_hits_branch_env_with_minted_token(
        self, tmp_config, linked_worktree, monkeypatch, capsys
    ):
        # AC#2: after linking, a read command hits the branch env — the request
        # carries that env's workspace id and the token minted from /dev/session.
        calls = _stub_dev_session(
            monkeypatch,
            agents=[{"agent_id": "branch-agent-1", "name": "Branch Bot", "is_active": True}],
        )
        args = eesel.build_parser(staff=False).parse_args(["agents", "list"])
        assert args.func(args) == 0
        mint = next(c for c in calls if c["url"].endswith("/dev/session"))
        fetch = next(c for c in calls if "/agents" in c["url"])
        assert mint["method"] == "POST"
        assert fetch["url"].startswith(PREPROD_URL + "/agents")
        assert "workspace_id=ws-branch-abc" in fetch["url"]
        assert fetch["token"] == "branch-jwt-xyz"
        assert "Branch Bot" in capsys.readouterr().out

    def test_two_worktrees_hit_their_own_envs(self, tmp_config, tmp_path, monkeypatch):
        # AC#3: two worktrees linked to two slugs each resolve to their own env
        # from their own directory — nothing global shared between them.
        for slug in ("alpha", "bravo"):
            root = tmp_path / slug
            (root / ".git").mkdir(parents=True)
            url = f"https://{slug}.preprod.eesel.xyz"
            (root / "eesel.dev.json").write_text(json.dumps({"base_url": url}))
        monkeypatch.delenv("EESEL_BASE_URL", raising=False)
        monkeypatch.delenv("EESEL_AGENT", raising=False)

        def fake_allow(method, url, *, token=None, body=None, timeout=60):
            slug = url.split("//", 1)[1].split(".", 1)[0]
            return 200, {"workspace_id": f"ws-{slug}", "user_id": "u", "auth_token": f"tok-{slug}"}

        monkeypatch.setattr(eesel, "http_request_allow_error", fake_allow)
        monkeypatch.chdir(tmp_path / "alpha")
        a = eesel.require_creds()
        monkeypatch.chdir(tmp_path / "bravo")
        b = eesel.require_creds()
        assert (a["api_url"], a["workspace_id"], a["token"]) == (
            "https://alpha.preprod.eesel.xyz", "ws-alpha", "tok-alpha")
        assert (b["api_url"], b["workspace_id"], b["token"]) == (
            "https://bravo.preprod.eesel.xyz", "ws-bravo", "tok-bravo")


class TestWhoamiLinked:
    def test_whoami_reports_linked_env(self, tmp_config, linked_worktree, monkeypatch, capsys):
        _stub_dev_session(monkeypatch)
        args = eesel.build_parser(staff=False).parse_args(["whoami"])
        assert args.func(args) == 0
        out = capsys.readouterr().out
        assert "preprod" in out
        assert PREPROD_URL in out
        assert "ws-branch-abc" in out
        assert "eesel.dev.json" in out  # shows the link source

    def test_whoami_unlinked_shows_stored_login(
        self, tmp_config, fake_creds, tmp_path, monkeypatch, capsys
    ):
        # AC#5: no link → whoami reports the stored login as before.
        monkeypatch.delenv("EESEL_BASE_URL", raising=False)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(eesel, "_get_impersonate_status", lambda creds: None)
        args = eesel.build_parser(staff=False).parse_args(["whoami"])
        assert args.func(args) == 0
        assert "http://localhost:8080" in capsys.readouterr().out


class TestEphemeralCreds:
    def test_save_creds_refuses_ephemeral(self, tmp_config):
        eesel.save_creds({"env": "preprod", "token": "x", "ephemeral": True})
        assert not eesel.CREDS_FILE.exists()  # never written to disk

    def test_linked_worktree_does_not_clobber_real_login(
        self, tmp_config, fake_creds, linked_worktree, monkeypatch
    ):
        # A real login is on disk; inside a linked worktree, minted creds flow
        # through require_creds and any downstream save (e.g. impersonate's
        # resync) must NOT overwrite the stored login.
        _stub_dev_session(monkeypatch)
        minted = eesel.require_creds()
        assert minted.get("ephemeral") is True
        eesel.save_creds(minted)  # the impersonate-resync path, on branch creds
        assert eesel.load_creds()["token"] == "test-jwt-token"  # real login intact
        assert eesel.load_creds()["api_url"] == "http://localhost:8080"


class TestHttpTimeoutHandling:
    def test_http_request_exits_clean_on_timeout(self, monkeypatch, capsys):
        def boom(req, timeout=None):
            raise socket.timeout("timed out")

        monkeypatch.setattr(eesel.urllib.request, "urlopen", boom)
        with pytest.raises(SystemExit) as exc:
            eesel.http_request("GET", "https://x.preprod.eesel.xyz/dev/logs")
        # A timeout is a server-class failure: typed exit code, clean one-line
        # message on stderr (not a traceback, and no longer the exit payload).
        assert exc.value.code == eesel.EXIT_SERVER
        assert "timed out" in capsys.readouterr().err

    def test_allow_error_exits_clean_on_timeout(self, monkeypatch, capsys):
        def boom(req, timeout=None):
            raise socket.timeout("timed out")

        monkeypatch.setattr(eesel.urllib.request, "urlopen", boom)
        with pytest.raises(SystemExit) as exc:
            eesel.http_request_allow_error("POST", "https://x.preprod.eesel.xyz/dev/session")
        assert exc.value.code == eesel.EXIT_SERVER
        assert "timed out" in capsys.readouterr().err


class TestExitCodes:
    """Typed exit codes are a contract a headless agent branches on: a failure
    carries a code that names its class, so an agent decides retry vs. re-auth
    vs. give-up without scraping stderr."""

    @pytest.mark.parametrize("status, code", [
        (401, 3), (403, 3),          # auth
        (404, 4),                    # not-found
        (400, 5), (422, 5),          # validation
        (429, 6),                    # rate-limit
        (500, 7), (502, 7), (503, 7),  # server
        (402, 1), (409, 1),          # unclassified 4xx → generic
    ])
    def test_code_for_status_maps_each_class(self, status, code):
        assert eesel.code_for_status(status) == code

    def test_the_five_classes_have_distinct_locked_numbers(self):
        # The numbers are a committed contract — guard against an accidental
        # renumber or collision (including with argparse's usage code 2).
        assert (eesel.EXIT_AUTH, eesel.EXIT_NOT_FOUND, eesel.EXIT_VALIDATION,
                eesel.EXIT_RATE_LIMIT, eesel.EXIT_SERVER) == (3, 4, 5, 6, 7)
        assert eesel.EXIT_OK == 0 and eesel.EXIT_GENERIC == 1 and eesel.EXIT_USAGE == 2

    def test_fail_prints_to_stderr_and_exits_with_code(self, capsys):
        with pytest.raises(SystemExit) as exc:
            eesel.fail(eesel.EXIT_AUTH, "please re-authenticate")
        assert exc.value.code == eesel.EXIT_AUTH
        assert "please re-authenticate" in capsys.readouterr().err

    @pytest.mark.parametrize("status, code", [
        (401, 3), (404, 4), (400, 5), (429, 6), (500, 7),
    ])
    def test_http_request_exits_with_typed_code_for_status(self, monkeypatch, capsys, status, code):
        # Drive each HTTP failure status through the shared request helper and
        # read the process exit code — the end-to-end contract an agent sees.
        import io

        def boom(req, timeout=None):
            raise eesel.urllib.error.HTTPError("http://x/y", status, "err", {}, io.BytesIO(b'{"error":"x"}'))

        monkeypatch.setattr(eesel.urllib.request, "urlopen", boom)
        with pytest.raises(SystemExit) as exc:
            eesel.http_request("GET", "http://x/y")
        assert exc.value.code == code


class TestRefreshProdToken:
    def _creds(self, **over):
        creds = {
            "env": "prod",
            "api_url": "https://oracle.eesel.app",
            "dashboard_url": "https://dashboard.eesel.ai",
            "workspace_id": "ws-1",
            "token": "old-access",
            "refresh_token": "rt-old",
            "expires_at": int(time.time()) - 1,
        }
        creds.update(over)
        return creds

    def test_success_updates_and_persists(self, tmp_config, monkeypatch):
        creds = self._creds()
        eesel.save_creds(creds)
        seen = {}

        def fake_urlopen(req, timeout=None):
            seen["url"] = req.full_url
            seen["body"] = json.loads(req.data)
            return _FakeResp(
                {"access_token": "new-access", "refresh_token": "rt-new", "expires_in": 7200}
            )

        monkeypatch.setattr(eesel.urllib.request, "urlopen", fake_urlopen)
        out = eesel.refresh_prod_token(creds)
        assert out is not None
        assert out["token"] == "new-access"
        assert out["refresh_token"] == "rt-new"
        assert out["expires_at"] > int(time.time()) + 7000
        assert seen["url"].endswith("/api/cli/refresh")
        assert seen["body"] == {"refresh_token": "rt-old"}
        # The new token is written to disk, not just the in-memory dict.
        assert eesel.load_creds()["token"] == "new-access"

    def test_keeps_refresh_token_when_response_omits_it(self, tmp_config, monkeypatch):
        creds = self._creds()
        monkeypatch.setattr(
            eesel.urllib.request,
            "urlopen",
            lambda req, timeout=None: _FakeResp({"access_token": "new-access", "expires_in": 3600}),
        )
        out = eesel.refresh_prod_token(creds)
        assert out["refresh_token"] == "rt-old"

    def test_returns_none_on_network_error(self, tmp_config, monkeypatch):
        creds = self._creds()

        def boom(req, timeout=None):
            raise OSError("connection refused")

        monkeypatch.setattr(eesel.urllib.request, "urlopen", boom)
        assert eesel.refresh_prod_token(creds) is None

    def test_returns_none_when_no_access_token(self, tmp_config, monkeypatch):
        creds = self._creds()
        monkeypatch.setattr(
            eesel.urllib.request,
            "urlopen",
            lambda req, timeout=None: _FakeResp({"error": "refresh_failed"}),
        )
        assert eesel.refresh_prod_token(creds) is None


class TestMcpToken:
    def test_mint_workspace_token_exchanges_auth0_bearer(self, tmp_config, monkeypatch):
        creds = {"api_url": "https://oracle.eesel.app", "token": "auth0-access", "agent_id": "agent-9"}
        seen = {}

        def fake_http(method, url, *, token=None, body=None, **kw):
            seen.update(method=method, url=url, token=token, body=body)
            return {"token": "ws-token", "expires_in": 2592000, "workspaceId": "ws-1"}

        monkeypatch.setattr(eesel, "http_request", fake_http)
        out = eesel.mint_workspace_token(creds, creds["agent_id"])
        assert out == "ws-token"
        assert seen["method"] == "POST"
        assert seen["url"].endswith("/workspaces/token")
        # The Auth0 access token is the Bearer used to mint the workspace token.
        assert seen["token"] == "auth0-access"
        assert seen["body"] == {"client": "cli", "agent_id": "agent-9"}

    def test_mint_omits_agent_when_unset(self, tmp_config, monkeypatch):
        seen = {}

        def fake_http(method, url, *, token=None, body=None, **kw):
            seen["body"] = body
            return {"token": "ws"}

        monkeypatch.setattr(eesel, "http_request", fake_http)
        eesel.mint_workspace_token({"api_url": "x", "token": "t"}, None)
        assert "agent_id" not in seen["body"]

    def test_cmd_mcp_token_prints_only_the_token(self, tmp_config, monkeypatch, capsys):
        eesel.save_creds(
            {
                "env": "prod",
                "api_url": "https://oracle.eesel.app",
                "workspace_id": "ws-1",
                "token": "auth0",
                "refresh_token": "rt",
                "expires_at": int(time.time()) + 3600,
                "agent_id": "agent-9",
            }
        )
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"token": "ws-token-xyz"})
        args = eesel.build_parser(staff=False).parse_args(["mcp", "token"])
        rc = args.func(args)
        assert rc == 0
        assert capsys.readouterr().out.strip() == "ws-token-xyz"

    def test_cmd_mcp_token_prints_existing_token_for_workspace_login(
        self, tmp_config, monkeypatch, capsys
    ):
        # A workspace-token (or dev) login already holds a token /mcp accepts —
        # print it as-is instead of trying to mint (which would 401, since the
        # stored token isn't an Auth0 bearer).
        eesel.save_creds(
            {
                "env": "prod",
                "api_url": "https://oracle.eesel.app",
                "workspace_id": "ws-1",
                "token": "ws-jwt-existing",  # no refresh_token → workspace login
                "expires_at": int(time.time()) + 3600,
                "agent_id": "agent-9",
            }
        )

        def boom(*a, **k):
            raise AssertionError("must not mint for a workspace-token login")

        monkeypatch.setattr(eesel, "mint_workspace_token", boom)
        args = eesel.build_parser(staff=False).parse_args(["mcp", "token"])
        rc = args.func(args)
        assert rc == 0
        assert capsys.readouterr().out.strip() == "ws-jwt-existing"


class TestWorkspaceToken:
    """`workspace_token()` picks the right bearer for the HS256-only endpoints
    (tasks + chat). A few server routes decode the bearer with HS256 only, so an
    Auth0 login must send a minted workspace token rather than its RS256 token."""

    def test_passes_through_when_no_refresh_token(self, monkeypatch):
        # Workspace-token / dev logins already hold a token these routes accept.
        def boom(*a, **k):
            raise AssertionError("must not mint for a non-Auth0 login")

        monkeypatch.setattr(eesel, "mint_workspace_token", boom)
        creds = {"api_url": "x", "token": "ws-jwt"}
        assert eesel.workspace_token(creds) == "ws-jwt"

    def test_mints_and_caches_for_auth0_login(self, monkeypatch):
        calls = {"n": 0}

        def fake_mint(creds, agent_id):
            calls["n"] += 1
            assert agent_id == "agent-9"  # mints scoped to the active agent
            return "minted-ws-token"

        monkeypatch.setattr(eesel, "mint_workspace_token", fake_mint)
        creds = {"api_url": "x", "token": "auth0", "refresh_token": "rt", "agent_id": "agent-9"}
        assert eesel.workspace_token(creds) == "minted-ws-token"
        # Second call reuses the cached token rather than re-minting.
        assert eesel.workspace_token(creds) == "minted-ws-token"
        assert calls["n"] == 1

    def test_tasks_send_minted_token_for_auth0_login(self, monkeypatch):
        # fetch_tasks must authenticate with the minted workspace token, not the
        # Auth0 access token (which the HS256-only /workspace/tasks route rejects).
        monkeypatch.setattr(eesel, "mint_workspace_token", lambda creds, agent_id: "minted-ws-token")
        seen = {}

        def fake_http(method, url, *, token=None, body=None, **kw):
            seen["token"] = token
            return {"tasks": [], "totalCount": 0}

        monkeypatch.setattr(eesel, "http_request", fake_http)
        creds = {"api_url": "http://x", "token": "auth0", "refresh_token": "rt", "agent_id": "agent-9"}
        eesel.fetch_tasks(creds)
        assert seen["token"] == "minted-ws-token"


# ──────────────────────────────────────────────────────────────────────────
# Session storage
# ──────────────────────────────────────────────────────────────────────────


class TestSessions:
    def test_list_returns_empty_when_dir_missing(self, tmp_config):
        assert eesel.list_sessions() == []

    def test_save_load_roundtrip(self, tmp_config):
        sess = {
            "id": "abc",
            "name": "test",
            "agent_id": "a-1",
            "workspace_id": "w-1",
            "task_id": "t-1",
            "messages": [{"sender": "user", "message": "hi"}],
            "created_at": time.time(),
        }
        eesel.save_session(sess)
        loaded = eesel.load_session("abc")
        assert loaded["id"] == "abc"
        assert loaded["messages"] == [{"sender": "user", "message": "hi"}]
        assert loaded["updated_at"] > 0  # save_session sets this

    def test_load_returns_none_for_missing(self, tmp_config):
        assert eesel.load_session("nope") is None

    def test_list_sorted_by_updated_at_desc(self, tmp_config):
        eesel.save_session({"id": "old", "messages": []})
        time.sleep(0.01)
        eesel.save_session({"id": "new", "messages": []})
        sessions = eesel.list_sessions()
        assert [s["id"] for s in sessions] == ["new", "old"]

    def test_current_pointer_roundtrip(self, tmp_config):
        assert eesel.load_current() is None
        eesel.set_current("abc")
        assert eesel.load_current() == "abc"
        eesel.set_current(None)
        assert eesel.load_current() is None

    def test_delete_session(self, tmp_config):
        eesel.save_session({"id": "x", "messages": []})
        assert eesel.load_session("x") is not None
        assert eesel.delete_session("x") is True
        assert eesel.load_session("x") is None
        assert eesel.delete_session("x") is False  # already gone

    def test_delete_clears_current_pointer(self, tmp_config):
        eesel.save_session({"id": "x", "messages": []})
        eesel.set_current("x")
        eesel.delete_session("x")
        assert eesel.load_current() is None

    def test_delete_preserves_unrelated_current(self, tmp_config):
        eesel.save_session({"id": "x", "messages": []})
        eesel.save_session({"id": "y", "messages": []})
        eesel.set_current("y")
        eesel.delete_session("x")
        assert eesel.load_current() == "y"

    def test_new_session_sets_current(self, tmp_config, fake_creds):
        sess = eesel.new_session(fake_creds, agent_id="ag-1", name=None, switch_to=True)
        assert eesel.load_current() == sess["id"]
        assert sess["agent_id"] == "ag-1"
        assert sess["workspace_id"] == fake_creds["workspace_id"]
        assert sess["messages"] == []
        assert "task_id" in sess and len(sess["task_id"]) > 0

    def test_new_session_no_switch(self, tmp_config, fake_creds):
        eesel.set_current("existing")
        sess = eesel.new_session(fake_creds, agent_id="ag-1", name="custom", switch_to=False)
        assert sess["name"] == "custom"
        assert eesel.load_current() == "existing"

    def test_ensure_current_creates_when_none(self, tmp_config, fake_creds):
        sess = eesel.ensure_current_session(fake_creds, agent_id="ag-1")
        assert sess is not None
        assert eesel.load_current() == sess["id"]

    def test_ensure_current_returns_existing(self, tmp_config, fake_creds):
        first = eesel.new_session(fake_creds, agent_id="ag-1", name=None)
        second = eesel.ensure_current_session(fake_creds)
        assert first["id"] == second["id"]

    def test_ensure_current_reuses_matching_agent(self, tmp_config, fake_creds):
        first = eesel.new_session(fake_creds, agent_id="ag-1", name=None)
        second = eesel.ensure_current_session(fake_creds, agent_id="ag-1")
        assert first["id"] == second["id"]

    def test_ensure_current_reuses_when_no_agent_requested(self, tmp_config, fake_creds):
        first = eesel.new_session(fake_creds, agent_id="ag-1", name=None)
        second = eesel.ensure_current_session(fake_creds, agent_id=None)
        assert first["id"] == second["id"]

    def test_ensure_current_starts_new_session_on_agent_mismatch(self, fake_creds, monkeypatch, capsys):
        old = {"id": "old-session", "agent_id": "ag-old", "workspace_id": "ws-test-123", "messages": []}
        new = {"id": "new-session", "agent_id": "ag-new", "workspace_id": "ws-test-123", "messages": []}
        calls = {}

        monkeypatch.setattr(eesel, "load_current", lambda: "old-session")
        monkeypatch.setattr(eesel, "load_session", lambda sid: old)

        def fake_new_session(creds, *, agent_id, name, switch_to, **kwargs):
            calls.update(agent_id=agent_id, name=name, switch_to=switch_to, kwargs=kwargs)
            return new

        monkeypatch.setattr(eesel, "new_session", fake_new_session)

        assert eesel.ensure_current_session(fake_creds, agent_id="ag-new") is new
        assert calls == {"agent_id": "ag-new", "name": None, "switch_to": True, "kwargs": {}}
        err = capsys.readouterr().err
        assert "active session old-session belongs to agent ag-old" in err
        assert "starting a new session for agent ag-new" in err


class TestFilesCommand:
    @pytest.fixture(autouse=True)
    def _default_single_agent(self, monkeypatch):
        # Documents are agent-scoped; with a single agent the CLI auto-selects
        # it. The default fake workspace's document keys are under agent-test-456.
        # Tests needing a multi-agent workspace override fetch_agents themselves.
        monkeypatch.setattr(eesel, "fetch_agents",
                            lambda creds: [{"agent_id": "agent-test-456", "name": "Default Bot"}])

    def test_document_list_prints_workspace_documents(self, tmp_config, fake_creds, monkeypatch, capsys):
        calls = []

        def fake_http_request(method, url, *, token=None, body=None, timeout=60):
            calls.append((method, url, token))
            return {
                "documents": [
                    {
                        "id": "doc-123456789",
                        "key": "outputs/skills/agent-test-456/blog/run-1/POST.md",
                        "name": "POST.md",
                    },
                    {
                        "id": "doc-other-agent",
                        "key": "files/other-agent/random.md",
                        "name": "random.md",
                    },
                ]
            }

        monkeypatch.setattr(eesel, "http_request", fake_http_request)

        rc = eesel.cmd_files(
            type(
                "Args",
                (),
                {
                    "file_cmd": "list",
                    "prefix": "outputs/skills",
                    "search": "post",
                    "limit": 25,
                    "offset": 10,
                },
            )()
        )

        assert rc == 0
        assert calls == [
            (
                "GET",
                "http://localhost:8080/documents?limit=25&offset=10&prefix=outputs%2Fskills&search=post",
                "test-jwt-token",
            )
        ]
        out = capsys.readouterr().out
        assert "doc-12345678" in out
        assert "outputs/skills/agent-test-456/blog/run-1/POST.md" in out
        assert "POST.md" in out
        assert "files/other-agent/random.md" not in out

    def test_document_list_json_emits_agent_scoped_payload(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(
            eesel,
            "http_request",
            lambda *a, **k: {
                "documents": [
                    {"id": "doc-1", "key": "files/agent-test-456/a.md", "name": "a.md"},
                    {"id": "doc-2", "key": "files/other-agent/b.md", "name": "b.md"},
                ]
            },
        )
        args = type(
            "Args",
            (),
            {"file_cmd": "list", "prefix": None, "search": None, "limit": 100, "offset": 0, "json": True},
        )()
        rc = eesel.cmd_files(args)
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        # Only the current agent's document survives the scope filter.
        assert [d["id"] for d in payload] == ["doc-1"]

    def test_document_list_agent_flag_scopes_to_resolved_agent(self, tmp_config, fake_creds, monkeypatch, capsys):
        # --agent (id, id-prefix, or name) overrides the active agent for the
        # listing scope, in memory only — it never rewrites the saved active agent.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [
            {"agent_id": "agent-test-456", "name": "Default Bot"},
            {"agent_id": "other-agent", "name": "Other Bot"},
        ])
        monkeypatch.setattr(eesel, "save_creds", lambda creds: pytest.fail("--agent must not persist the active agent"))
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"documents": [
            {"id": "doc-1", "key": "files/agent-test-456/a.md", "name": "a.md"},
            {"id": "doc-2", "key": "files/other-agent/b.md", "name": "b.md"},
        ]})
        args = type("Args", (), {
            "file_cmd": "list", "prefix": None, "search": None,
            "limit": 100, "offset": 0, "json": True, "agent": "Other Bot",
        })()
        rc = eesel.cmd_files(args)
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        # Only the --agent target's document survives the scope filter.
        assert [d["id"] for d in payload] == ["doc-2"]

    def test_document_list_unknown_agent_errors_before_fetch(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "a1", "name": "Bot"}])
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: pytest.fail("should not fetch on an unresolved --agent"))
        args = type("Args", (), {
            "file_cmd": "list", "prefix": None, "search": None,
            "limit": 100, "offset": 0, "json": False, "agent": "nope",
        })()
        with pytest.raises(SystemExit):
            eesel.cmd_files(args)
        assert "No agent matches 'nope'" in capsys.readouterr().err

    def test_document_list_plain_emits_tab_separated_rows(self, tmp_config, fake_creds, monkeypatch, capsys):
        # `--plain` emits one decoration-free, tab-separated row per document:
        # id<TAB>key<TAB>name, scoped to the current agent. The human view's
        # two-space column padding is absent, confirming the human formatter was
        # bypassed.
        monkeypatch.setattr(
            eesel,
            "http_request",
            lambda *a, **k: {
                "documents": [
                    {"id": "doc-1", "key": "files/agent-test-456/a.md", "name": "a.md"},
                    {"id": "doc-2", "key": "files/other-agent/b.md", "name": "b.md"},
                ]
            },
        )
        args = type(
            "Args",
            (),
            {"file_cmd": "list", "prefix": None, "search": None, "limit": 100, "offset": 0, "plain": True},
        )()
        rc = eesel.cmd_files(args)
        assert rc == 0
        out = capsys.readouterr().out
        lines = out.strip().splitlines()
        assert lines == ["doc-1\tfiles/agent-test-456/a.md\ta.md"]

    def test_document_export_by_document_key_downloads_file(self, tmp_config, fake_creds, tmp_path, monkeypatch):
        # cli resolves the key to a document id via GET /documents (agent-scoped),
        # mints a signed link via /documents/{id}/export-link, then downloads it.
        key = "outputs/skills/agent-test-456/blog/run-1/POST.md"
        calls = []

        def fake_http_request(method, url, *, token=None, body=None, timeout=60, headers=None):
            calls.append(("request", method, url, token))
            if "/export-link" in url:
                return {"url": "http://localhost:8080/documents/export/signed-token"}
            return {"documents": [{"id": "doc-123456789", "key": key, "name": "POST.md"}]}

        def fake_http_download(url, *, token, output_path):
            calls.append(("download", url, token, output_path))
            output_path.write_text("# Exported")

        monkeypatch.setattr(eesel, "http_request", fake_http_request)
        monkeypatch.setattr(eesel, "http_download", fake_http_download)

        output = tmp_path / "post.md"
        rc = eesel.cmd_files(
            type(
                "Args",
                (),
                {
                    "file_cmd": "export",
                    "document_key": key,
                    "document_id": None,
                    "format": "md",
                    "output": str(output),
                },
            )()
        )

        assert rc == 0
        assert output.read_text() == "# Exported"
        # 1) resolve the key (prefix-scoped lookup), 2) mint export-link, 3) download
        assert calls[0][1:4] == (
            "GET",
            "http://localhost:8080/documents?limit=500&offset=0&prefix=outputs%2Fskills%2Fagent-test-456%2Fblog%2Frun-1%2FPOST.md",
            "test-jwt-token",
        )
        assert calls[1][1:4] == (
            "GET",
            "http://localhost:8080/documents/doc-123456789/export-link?format=md",
            "test-jwt-token",
        )
        assert calls[2] == (
            "download",
            "http://localhost:8080/documents/export/signed-token",
            "test-jwt-token",
            output,
        )

    def test_document_export_by_document_id_resolves_prefix(self, tmp_config, fake_creds, tmp_path, monkeypatch):
        full_id = "d22e305b-5d1b-41a1-9316-3424db9a1c49"
        calls = []

        def fake_http_request(method, url, *, token=None, body=None, timeout=60, headers=None):
            calls.append(("request", method, url, token))
            if "/export-link" in url:
                return {"url": "http://localhost:8080/documents/export/html-token"}
            return {"documents": [{"id": full_id, "key": "outputs/skills/agent-test-456/blog/run-1/POST.md"}]}

        def fake_http_download(url, *, token, output_path):
            calls.append(("download", url, token, output_path))
            output_path.write_text("<html></html>")

        monkeypatch.setattr(eesel, "http_request", fake_http_request)
        monkeypatch.setattr(eesel, "http_download", fake_http_download)

        output = tmp_path / "post.html"
        rc = eesel.cmd_files(
            type(
                "Args",
                (),
                {
                    "file_cmd": "export",
                    "document_key": None,
                    "document_id": "d22e305b-5d1",
                    "format": "html",
                    "output": str(output),
                },
            )()
        )

        assert rc == 0
        assert output.read_text() == "<html></html>"
        # an id-prefix resolves against the agent-scoped document list (no prefix filter)
        assert calls[0][1:4] == (
            "GET",
            "http://localhost:8080/documents?limit=500&offset=0",
            "test-jwt-token",
        )
        # the export-link is minted against the *full* resolved id, not the prefix
        assert calls[1][1:4] == (
            "GET",
            f"http://localhost:8080/documents/{full_id}/export-link?format=html",
            "test-jwt-token",
        )
        assert calls[2] == (
            "download",
            "http://localhost:8080/documents/export/html-token",
            "test-jwt-token",
            output,
        )

    def test_document_export_exact_document_id_still_resolves(self, tmp_config, fake_creds, tmp_path, monkeypatch):
        full_id = "d22e305b-5d1b-41a1-9316-3424db9a1c49"

        monkeypatch.setattr(
            eesel,
            "http_request",
            lambda method, url, *, token=None, body=None, timeout=60, headers=None: (
                {"url": "http://localhost:8080/documents/export/md-token"}
                if "/export-link" in url
                else {"documents": [{"id": full_id, "key": "outputs/skills/agent-test-456/blog/run-1/POST.md"}]}
            ),
        )
        monkeypatch.setattr(eesel, "http_download", lambda url, *, token, output_path: output_path.write_text("# Exported"))

        output = tmp_path / "post.md"
        rc = eesel.cmd_files(
            type(
                "Args",
                (),
                {
                    "file_cmd": "export",
                    "document_key": None,
                    "document_id": full_id,
                    "format": "md",
                    "output": str(output),
                },
            )()
        )

        assert rc == 0
        assert output.read_text() == "# Exported"

    def test_document_export_rejects_ambiguous_document_id_prefix(self, tmp_config, fake_creds, tmp_path, monkeypatch):
        monkeypatch.setattr(
            eesel,
            "http_request",
            lambda method, url, *, token=None, body=None, timeout=60, headers=None: {
                "documents": [
                    {"id": "d22e305b-5d1b-41a1-9316-3424db9a1c49"},
                    {"id": "d22e305b-5d1c-41a1-9316-3424db9a1c50", "key": "files/agent-test-456/random.md"},
                    {"id": "d22e305b-5d1d-41a1-9316-3424db9a1c51", "key": "outputs/skills/agent-test-456/blog/post.md"},
                ]
            },
        )
        download_mock = MagicMock()
        monkeypatch.setattr(eesel, "http_download", download_mock)

        rc = eesel.cmd_files(
            type(
                "Args",
                (),
                {
                    "file_cmd": "export",
                    "document_key": None,
                    "document_id": "d22e305b-5d1",
                    "format": "md",
                    "output": str(tmp_path / "post.md"),
                },
            )()
        )

        assert rc == 1
        download_mock.assert_not_called()

    def test_document_export_rejects_other_workspace_key(self, tmp_config, fake_creds, tmp_path, monkeypatch):
        request_mock = MagicMock()
        download_mock = MagicMock()
        monkeypatch.setattr(eesel, "http_request", request_mock)
        monkeypatch.setattr(eesel, "http_download", download_mock)

        rc = eesel.cmd_files(
            type(
                "Args",
                (),
                {
                    "file_cmd": "export",
                    "document_key": "c11e2c42-b77e-45f1-88d1-cf9b22974c90/outputs/skills/agent-A/blog/run-1/POST.md",
                    "document_id": None,
                    "format": "md",
                    "output": str(tmp_path / "post.md"),
                },
            )()
        )

        assert rc == 1
        request_mock.assert_not_called()
        download_mock.assert_not_called()

    def test_document_export_rejects_other_agent_key(self, tmp_config, fake_creds, tmp_path, monkeypatch):
        request_mock = MagicMock()
        download_mock = MagicMock()
        monkeypatch.setattr(eesel, "http_request", request_mock)
        monkeypatch.setattr(eesel, "http_download", download_mock)

        rc = eesel.cmd_files(
            type(
                "Args",
                (),
                {
                    "file_cmd": "export",
                    "document_key": "files/other-agent/random.md",
                    "document_id": None,
                    "format": "md",
                    "output": str(tmp_path / "post.md"),
                },
            )()
        )

        assert rc == 1
        request_mock.assert_not_called()
        download_mock.assert_not_called()

    def test_document_export_preserves_matching_workspace_prefix(self, tmp_config, fake_creds, tmp_path, monkeypatch):
        workspace_id = "c11e2c42-b77e-45f1-88d1-cf9b22974c90"
        fake_creds["workspace_id"] = workspace_id
        eesel.save_creds(fake_creds)
        stripped_key = "outputs/skills/agent-test-456/blog/run-1/POST.md"
        calls = []

        def fake_http_request(method, url, *, token=None, body=None, timeout=60, headers=None):
            calls.append(("request", method, url, token))
            if "/export-link" in url:
                return {"url": "http://localhost:8080/documents/export/prefixed-token"}
            return {"documents": [{"id": "doc-ws-1", "key": stripped_key, "name": "POST.md"}]}

        def fake_http_download(url, *, token, output_path):
            calls.append(("download", url, token, output_path))
            output_path.write_text("# Exported")

        monkeypatch.setattr(eesel, "http_request", fake_http_request)
        monkeypatch.setattr(eesel, "http_download", fake_http_download)

        output = tmp_path / "post.md"
        rc = eesel.cmd_files(
            type(
                "Args",
                (),
                {
                    "file_cmd": "export",
                    # caller passes a key that includes its own workspace id prefix
                    "document_key": f"{workspace_id}/{stripped_key}",
                    "document_id": None,
                    "format": "md",
                    "output": str(output),
                },
            )()
        )

        assert rc == 0
        # the workspace-id prefix is stripped before the key is resolved
        assert calls[0][1:3] == (
            "GET",
            "http://localhost:8080/documents?limit=500&offset=0&prefix=outputs%2Fskills%2Fagent-test-456%2Fblog%2Frun-1%2FPOST.md",
        )
        assert calls[1][1:3] == (
            "GET",
            "http://localhost:8080/documents/doc-ws-1/export-link?format=md",
        )


class TestFilesRead:
    # fake_creds.agent_id == "agent-test-456"
    @pytest.fixture(autouse=True)
    def _default_single_agent(self, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents",
                            lambda creds: [{"agent_id": "agent-test-456", "name": "Default Bot"}])

    DOCS = [
        {"id": "doc-aaa11122", "key": "files/agent-test-456/notes.md", "name": "notes.md"},
        {"id": "doc-bbb33344", "key": "outputs/skills/agent-test-456/blog/run-1/POST.md", "name": "POST.md"},
        {"id": "doc-other-99", "key": "files/other-agent/secret.md", "name": "secret.md"},
        {"id": "doc-integ-77", "key": "integrations/zendesk/acme/article-1", "name": "article-1"},
    ]

    def _args(self, **kw):
        base = {"file_cmd": "read", "target": None, "prefix": None, "format": "md"}
        base.update(kw)
        return type("Args", (), base)()

    def _wire(self, monkeypatch, *, content=b"# Hello\nbody"):
        seen = {}
        monkeypatch.setattr(eesel, "fetch_documents", lambda creds, **kw: (seen.update(kw) or self.DOCS))

        def fake_signed(creds, *, document_id, document_key, fmt):
            seen["doc_id"] = document_id
            seen["fmt"] = fmt
            return ("x." + fmt, f"https://signed/{document_id}.{fmt}")

        monkeypatch.setattr(eesel, "doc_export_signed_url", fake_signed)
        monkeypatch.setattr(eesel, "http_fetch", lambda url, *, token, timeout=120: (seen.update(fetch_url=url) or content))
        return seen

    def test_read_by_id_prints_content(self, tmp_config, fake_creds, monkeypatch, capsys):
        seen = self._wire(monkeypatch, content=b"# Notes\nhello world")
        rc = eesel.cmd_files_read(self._args(target="doc-aaa11122"))
        assert rc == 0
        assert seen["doc_id"] == "doc-aaa11122"
        assert seen["fmt"] == "md"
        out = capsys.readouterr().out
        assert out == "# Notes\nhello world\n"  # body to stdout, trailing newline added

    def test_read_header_goes_to_stderr(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._wire(monkeypatch)
        eesel.cmd_files_read(self._args(target="notes.md"))  # match by filename
        captured = capsys.readouterr()
        assert "files/agent-test-456/notes.md" in captured.err
        assert "files/agent-test-456/notes.md" not in captured.out

    def test_read_by_filename_and_html_format(self, tmp_config, fake_creds, monkeypatch):
        seen = self._wire(monkeypatch, content=b"<h1>x</h1>")
        rc = eesel.cmd_files_read(self._args(target="POST.md", format="html"))
        assert rc == 0
        assert seen["doc_id"] == "doc-bbb33344"
        assert seen["fmt"] == "html"

    def test_read_no_target_uses_interactive_menu(self, tmp_config, fake_creds, monkeypatch):
        seen = self._wire(monkeypatch)
        captured = {}

        def fake_select(options, *, title=None, initial=0):
            captured["options"] = options
            return 1  # pick the second agent-owned doc

        # The picker path requires an interactive terminal.
        monkeypatch.setattr(eesel.sys, "stdin", _FakeStdin(True))
        monkeypatch.setattr(eesel, "interactive_select", fake_select)
        rc = eesel.cmd_files_read(self._args())
        assert rc == 0
        # Only the two agent-owned docs are offered (other-agent + integrations filtered out).
        assert len(captured["options"]) == 2
        assert seen["doc_id"] == "doc-bbb33344"

    def test_read_prefix_is_passed_through_and_scopes(self, tmp_config, fake_creds, monkeypatch):
        seen = self._wire(monkeypatch)
        monkeypatch.setattr(eesel.sys, "stdin", _FakeStdin(True))
        monkeypatch.setattr(eesel, "interactive_select", lambda *a, **k: 0)
        eesel.cmd_files_read(self._args(prefix="files/"))
        assert seen.get("prefix") == "files/"  # forwarded to fetch_documents

    def test_read_unknown_target_errors(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._wire(monkeypatch)
        rc = eesel.cmd_files_read(self._args(target="nope"))
        assert rc == 1
        assert capsys.readouterr().out == ""

    def test_read_ambiguous_id_prefix_errors(self, tmp_config, fake_creds, monkeypatch, capsys):
        # Two agent-owned ids share the prefix "doc-".
        self._wire(monkeypatch)
        rc = eesel.cmd_files_read(self._args(target="doc-"))
        assert rc == 1
        assert "ambiguous" in capsys.readouterr().err

    def test_read_excludes_other_agents_doc(self, tmp_config, fake_creds, monkeypatch, capsys):
        # The other agent's doc must not be reachable by id.
        self._wire(monkeypatch)
        rc = eesel.cmd_files_read(self._args(target="doc-other-99"))
        assert rc == 1

    def test_read_no_files_is_clean_exit(self, tmp_config, fake_creds, monkeypatch, capsys):
        # An empty workspace on an interactive terminal: nothing to pick, so a
        # clean "(no files)" exit 0. (On a non-TTY, no target errors 6 before
        # the fetch — see test_read_no_target_non_tty_errors_with_validation_code.)
        monkeypatch.setattr(eesel.sys, "stdin", _FakeStdin(True))
        monkeypatch.setattr(eesel, "fetch_documents", lambda creds, **kw: [])
        rc = eesel.cmd_files_read(self._args(prefix="integrations/"))
        assert rc == 0
        assert "no files" in capsys.readouterr().err

    def test_read_cancel_menu_returns_nonzero(self, tmp_config, fake_creds, monkeypatch):
        self._wire(monkeypatch)
        monkeypatch.setattr(eesel.sys, "stdin", _FakeStdin(True))
        monkeypatch.setattr(eesel, "interactive_select", lambda *a, **k: None)
        assert eesel.cmd_files_read(self._args()) == 1

    def test_read_no_target_non_tty_errors_before_the_fetch(self, tmp_config, fake_creds, monkeypatch, capsys):
        # No target on a non-interactive terminal: fail with the validation code
        # and name the fix — never the misleading "Cancelled." (nothing was
        # cancelled). The guard runs BEFORE the document fetch, so a down server
        # can't turn this into a server-class exit 7 ("retry later") for a call
        # that can never succeed as invoked.
        monkeypatch.setattr(eesel.sys, "stdin", _FakeStdin(False))
        monkeypatch.setattr(eesel, "fetch_documents", lambda *a, **k: pytest.fail("must not fetch before the no-target guard"))
        monkeypatch.setattr(eesel, "interactive_select", lambda *a, **k: pytest.fail("must not open a picker on a non-TTY"))
        rc = eesel.cmd_files_read(self._args())
        assert rc == eesel.EXIT_VALIDATION
        err = capsys.readouterr().err
        assert "Cancelled." not in err
        assert "files read" in err

    def test_read_no_target_consumes_piped_index(self, tmp_config, fake_creds, monkeypatch):
        # `echo 1 | eesel files read`: no TTY, but stdin carries a picked index.
        # The no-target guard must NOT fire — the numbered-select fallback reads
        # the index off stdin and the chosen file is read as if picked from the
        # menu.
        seen = self._wire(monkeypatch)
        monkeypatch.setattr(eesel.sys, "stdin", _FakeStdin(False))
        monkeypatch.setattr(eesel, "_stdin_has_piped_data", lambda: True)
        monkeypatch.setattr("builtins.input", lambda _="": "1")  # pick the second agent-owned doc
        rc = eesel.cmd_files_read(self._args())
        assert rc == 0
        assert seen["doc_id"] == "doc-bbb33344"


class TestBestEffortLookupsStaySilent:
    """`_latest_sync_run` and `find_task_row` decorate an already-successful
    command (integrations status / tasks show/cost). When their background fetch
    fails they must degrade to None *silently* — `fail()` prints via `err()`
    before exiting, so without suppression the caught SystemExit would still leak
    a red error banner onto the command's real output."""

    def test_latest_sync_run_swallows_failure_without_printing(self, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "_fetch_sync_runs", lambda creds: eesel.fail(eesel.EXIT_SERVER, "sync-runs endpoint down"))
        assert eesel._latest_sync_run({"api_url": "x", "token": "t"}, "int-1") is None
        assert capsys.readouterr().err == ""

    def test_find_task_row_swallows_failure_without_printing(self, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_tasks", lambda creds, **k: eesel.fail(eesel.EXIT_AUTH, "401 on tasks list"))
        assert eesel.find_task_row({"api_url": "x", "token": "t"}, "task-1") is None
        assert capsys.readouterr().err == ""


class TestHttpFetch:
    def test_http_download_uses_http_fetch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(eesel, "http_fetch", lambda url, *, token: b"DATA")
        out = tmp_path / "f.md"
        eesel.http_download("https://x/y", token="t", output_path=out)
        assert out.read_bytes() == b"DATA"


class TestFilesAdd:
    @pytest.fixture(autouse=True)
    def _default_single_agent(self, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents",
                            lambda creds: [{"agent_id": "agent-test-456", "name": "Default Bot"}])

    def _args(self, **over):
        base = {"file_cmd": "add", "title": "My Doc", "content": None, "content_file": None, "source_type": "files"}
        base.update(over)
        return type("Args", (), base)()

    def test_posts_title_content_source_type_and_agent_then_prints_key(self, tmp_config, fake_creds, monkeypatch, capsys):
        calls = []

        def fake_http(method, url, *, token=None, body=None, timeout=60, headers=None):
            calls.append((method, url, body))
            return {"id": "doc-99", "key": "files/agent-test-456/my-doc.md", "name": "My Doc"}

        monkeypatch.setattr(eesel, "http_request", fake_http)
        rc = eesel.cmd_files(self._args(content="hello world"))
        assert rc == 0
        assert calls == [
            (
                "POST",
                "http://localhost:8080/documents",
                {"title": "My Doc", "content": "hello world", "source_type": "files", "agent_id": "agent-test-456"},
            )
        ]
        # The key is printed to stdout so it can be captured by a script.
        assert capsys.readouterr().out.strip() == "files/agent-test-456/my-doc.md"

    def test_reads_content_from_file(self, tmp_config, fake_creds, tmp_path, monkeypatch):
        captured = {}

        def fake_http(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured.update(body or {})
            return {"key": "files/agent-test-456/from-file.md"}

        monkeypatch.setattr(eesel, "http_request", fake_http)
        content_file = tmp_path / "body.md"
        content_file.write_text("# From a file\n")
        rc = eesel.cmd_files(self._args(content_file=str(content_file)))
        assert rc == 0
        assert captured["content"] == "# From a file\n"

    def test_falls_back_to_id_when_no_key(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"id": "doc-only-id"})
        rc = eesel.cmd_files(self._args(content="x"))
        assert rc == 0
        assert capsys.readouterr().out.strip() == "doc-only-id"


class TestFilesRemove:
    # `remove` resolves each argument against the documents that actually exist
    # before deleting anything, so the tests stand up a small document set.
    @pytest.fixture(autouse=True)
    def _default_single_agent(self, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents",
                            lambda creds: [{"agent_id": "agent-test-456", "name": "Default Bot"}])

    DOCS = [
        {"id": "doc-a", "key": "files/a.md"},
        {"id": "doc-b", "key": "files/b.md"},
    ]

    def _args(self, keys, force=False):
        return type("Args", (), {"file_cmd": "remove", "keys": keys, "force": force, "agent": None})()

    def test_removes_resolved_keys_when_confirmed(self, tmp_config, fake_creds, monkeypatch):
        calls = []

        def fake_http(method, url, *, token=None, body=None, timeout=60, headers=None):
            calls.append((method, url, body))
            return {"message": "Documents deleted successfully"}

        monkeypatch.setattr(eesel, "agent_documents", lambda creds, **k: self.DOCS)
        monkeypatch.setattr(eesel, "http_request", fake_http)
        monkeypatch.setattr(eesel, "confirm", lambda prompt: True)
        rc = eesel.cmd_files(self._args(["files/a.md", "files/b.md"]))
        assert rc == 0
        assert calls == [
            ("DELETE", "http://localhost:8080/documents", {"keys": ["files/a.md", "files/b.md"]})
        ]

    def test_resolves_an_id_to_its_key(self, tmp_config, fake_creds, monkeypatch):
        # A document id is a valid address; it resolves to that document's key,
        # which is what the DELETE body carries.
        calls = []
        monkeypatch.setattr(eesel, "agent_documents", lambda creds, **k: self.DOCS)
        monkeypatch.setattr(eesel, "http_request", lambda method, url, **k: calls.append((method, k.get("body"))) or {})
        monkeypatch.setattr(eesel, "confirm", lambda prompt: True)
        rc = eesel.cmd_files(self._args(["doc-a"]))
        assert rc == 0
        assert calls == [("DELETE", {"keys": ["files/a.md"]})]

    def test_force_flag_skips_confirmation(self, tmp_config, fake_creds, monkeypatch):
        calls = []
        monkeypatch.setattr(eesel, "agent_documents", lambda creds, **k: self.DOCS)
        monkeypatch.setattr(eesel, "http_request", lambda method, url, **k: calls.append((method, url, k.get("body"))) or {})

        def boom(prompt):
            raise AssertionError("confirm() must not be called when --force is passed")

        monkeypatch.setattr(eesel, "confirm", boom)
        rc = eesel.cmd_files(self._args(["files/a.md"], force=True))
        assert rc == 0
        assert calls == [("DELETE", "http://localhost:8080/documents", {"keys": ["files/a.md"]})]

    def test_aborts_without_confirmation(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "agent_documents", lambda creds, **k: self.DOCS)

        def boom(method, url, **k):
            raise AssertionError("must not DELETE when the user declines")

        monkeypatch.setattr(eesel, "http_request", boom)
        monkeypatch.setattr(eesel, "confirm", lambda prompt: False)
        rc = eesel.cmd_files(self._args(["files/a.md"]))
        assert rc == 1

    def test_unknown_key_refuses_and_deletes_nothing(self, tmp_config, fake_creds, monkeypatch):
        # A typo'd / nonexistent key must refuse the whole command (deleting
        # nothing) rather than POST the unresolved key and report a fabricated
        # "Removed N" for a key the server silently ignored.
        monkeypatch.setattr(eesel, "agent_documents", lambda creds, **k: self.DOCS)

        def boom(method, url, **k):
            raise AssertionError("must not DELETE when an argument matches no document")

        monkeypatch.setattr(eesel, "http_request", boom)
        monkeypatch.setattr(eesel, "confirm", lambda prompt: True)
        rc = eesel.cmd_files(self._args(["files/typo.md"]))
        assert rc == 1

    def test_one_bad_key_among_good_ones_refuses_all(self, tmp_config, fake_creds, monkeypatch):
        # All-or-nothing: a single unmatched argument blocks the batch, so a
        # partial silent delete can't happen behind a fabricated success.
        monkeypatch.setattr(eesel, "agent_documents", lambda creds, **k: self.DOCS)

        def boom(method, url, **k):
            raise AssertionError("must not DELETE when any argument is unmatched")

        monkeypatch.setattr(eesel, "http_request", boom)
        monkeypatch.setattr(eesel, "confirm", lambda prompt: True)
        rc = eesel.cmd_files(self._args(["files/a.md", "files/nope.md"]))
        assert rc == 1

    def test_blank_key_refuses(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "agent_documents", lambda creds, **k: self.DOCS)

        def boom(method, url, **k):
            raise AssertionError("a blank key must not delete anything")

        monkeypatch.setattr(eesel, "http_request", boom)
        monkeypatch.setattr(eesel, "confirm", lambda prompt: True)
        rc = eesel.cmd_files(self._args([""], force=True))
        assert rc == 1


class TestBlankTargetRefusal:
    """A blank/whitespace target must match nothing across every resolver. An
    empty string is a prefix of every id, so without the guard a blank target
    would match every row — and on a single-row workspace that lone match would
    resolve as 'unique' and let a destructive `remove` act with no real target
    given. The strict resolvers refuse only on 0 or 2+ matches, so the guard has
    to live in the matchers."""

    AGENTS = [{"agent_id": "agent-one", "name": "Only Agent"}]
    INTEGRATIONS = [{"id": "int-one", "integrationType": "zendesk"}]
    JOBS = [{"id": "job-one", "config": {"title": "Nightly"}}]
    TRIGGERS = [{"id": "trig-one", "trigger_key": "ticket.created"}]
    SERVERS = [{"id": "mcp-one", "name": "Notion"}]

    @pytest.mark.parametrize("blank", ["", "   ", "\t"])
    def test_matchers_return_nothing_for_blank(self, blank):
        assert eesel.match_agents(self.AGENTS, blank) == []
        assert eesel.match_integrations(self.INTEGRATIONS, blank) == []
        assert eesel.match_scheduled_jobs(self.JOBS, blank) == []
        assert eesel.match_event_triggers(self.TRIGGERS, blank) == []
        assert eesel.match_mcp_servers(self.SERVERS, blank) == []

    def test_a_real_prefix_still_matches_the_sole_row(self):
        # Sanity: the guard only rejects blanks — a real id-prefix on a
        # single-row workspace still resolves.
        assert len(eesel.match_agents(self.AGENTS, "agent")) == 1
        assert len(eesel.match_event_triggers(self.TRIGGERS, "trig")) == 1

    def test_strict_resolvers_refuse_blank(self):
        agent, candidates = eesel.resolve_agent_strict(self.AGENTS, "")
        assert agent is None and candidates == []
        assert eesel.resolve_integration_strict(self.INTEGRATIONS, "") is None


class TestFilesAcl:
    AGENTS = [{"agent_id": "agent-test-456", "name": "Support Bot"}]

    def _get_args(self, agent):
        return type("Args", (), {"file_cmd": "acl", "acl_cmd": "show", "agent": agent, "json": False})()

    def _set_args(self, agent, prefixes):
        return type("Args", (), {"file_cmd": "acl", "acl_cmd": "set", "agent": agent, "prefix": prefixes})()

    def test_show_prints_key_prefixes(self, tmp_config, fake_creds, monkeypatch, capsys):
        calls = []

        def fake_http(method, url, *, token=None, body=None, timeout=60, headers=None):
            calls.append((method, url, body))
            return {"key_prefixes": ["files/agent-test-456", "outputs/skills/agent-test-456"]}

        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        monkeypatch.setattr(eesel, "http_request", fake_http)
        rc = eesel.cmd_files(self._get_args("Support Bot"))
        assert rc == 0
        assert calls == [("GET", "http://localhost:8080/agents/agent-test-456/knowledge-acl", None)]
        out = capsys.readouterr().out
        assert "files/agent-test-456" in out
        assert "outputs/skills/agent-test-456" in out

    def test_show_json_emits_prefix_array(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        monkeypatch.setattr(
            eesel,
            "http_request",
            lambda *a, **k: {"key_prefixes": ["files/agent-test-456", "outputs/skills/agent-test-456"]},
        )
        args = type("Args", (), {"file_cmd": "acl", "acl_cmd": "show", "agent": "Support Bot", "json": True})()
        rc = eesel.cmd_files(args)
        assert rc == 0
        assert json.loads(capsys.readouterr().out) == ["files/agent-test-456", "outputs/skills/agent-test-456"]

    def test_set_prints_server_readback_not_put_echo(self, tmp_config, fake_creds, monkeypatch, capsys):
        # The PUT response echoes the request (plus an auto-injected own-files
        # prefix), but the server normalizes on store: a bare `files` is dropped
        # and duplicates collapsed. `set` must report the GET readback, not the
        # PUT echo, or it would overstate the access actually granted.
        calls = []

        def fake_http(method, url, *, token=None, body=None, timeout=60, headers=None):
            calls.append((method, url, body))
            if method == "PUT":
                # Echo: request prefixes verbatim + the auto-injected own prefix.
                return {"key_prefixes": body["key_prefixes"] + ["files/agent-test-456"]}
            # GET readback: the normalized stored set — bare `files` dropped.
            return {"key_prefixes": ["files/shared", "files/agent-test-456"]}

        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        monkeypatch.setattr(eesel, "http_request", fake_http)
        # User asks for a broad bare `files` plus a specific prefix.
        rc = eesel.cmd_files(self._set_args("agent-test-456", ["files", "files/shared"]))
        assert rc == 0
        # PUT to write, then GET to read back what the server actually stored.
        assert [c[0] for c in calls] == ["PUT", "GET"]
        assert calls[0][2] == {"key_prefixes": ["files", "files/shared"]}
        out_lines = capsys.readouterr().out.split()
        # The normalized readback is printed; the dropped bare `files` is not.
        assert "files/shared" in out_lines
        assert "files/agent-test-456" in out_lines
        assert "files" not in out_lines

    def test_unknown_agent_errors(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)

        def boom(*a, **k):
            raise AssertionError("must not hit the API when the agent can't be resolved")

        monkeypatch.setattr(eesel, "http_request", boom)
        rc = eesel.cmd_files(self._get_args("does-not-exist"))
        assert rc == 1


# ──────────────────────────────────────────────────────────────────────────
# Misc
# ──────────────────────────────────────────────────────────────────────────


class TestFindFreePort:
    def test_returns_usable_port(self):
        port = eesel._find_free_port()
        assert isinstance(port, int)
        assert 1024 < port < 65536
        # Confirm we can actually bind to it.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", port))


class TestResolveAgent:
    AGENTS = [
        {"agent_id": "agent-abc123", "name": "Support Bot", "agent_type": "help_desk_agent"},
        {"agent_id": "agent-def456", "name": "Blog Writer", "agent_type": "blog_writer_agent"},
    ]

    def test_exact_id(self):
        assert eesel.resolve_agent(self.AGENTS, "agent-abc123")["name"] == "Support Bot"

    def test_id_prefix(self):
        assert eesel.resolve_agent(self.AGENTS, "agent-def")["name"] == "Blog Writer"

    def test_exact_name(self):
        assert eesel.resolve_agent(self.AGENTS, "Support Bot")["agent_id"] == "agent-abc123"

    def test_no_match(self):
        assert eesel.resolve_agent(self.AGENTS, "nope") is None

    def test_exact_id_beats_prefix(self):
        # An exact id match wins even if another id shares the prefix.
        agents = [{"agent_id": "ag", "name": "Short"}, {"agent_id": "ag-long", "name": "Long"}]
        assert eesel.resolve_agent(agents, "ag")["name"] == "Short"

    def test_first_match_on_ambiguous_prefix(self):
        # `use` keeps its first-match behaviour even when a prefix is ambiguous.
        agents = [{"agent_id": "agent-1", "name": "One"}, {"agent_id": "agent-2", "name": "Two"}]
        assert eesel.resolve_agent(agents, "agent-")["name"] == "One"


class TestResolveAgentStrict:
    AGENTS = [
        {"agent_id": "agent-abc123", "name": "Support Bot"},
        {"agent_id": "agent-def456", "name": "Blog Writer"},
        {"agent_id": "agent-def789", "name": "Blog Writer"},  # duplicate name
    ]

    def test_unique_match_returns_agent_and_no_candidates(self):
        agent, candidates = eesel.resolve_agent_strict(self.AGENTS, "agent-abc123")
        assert agent["name"] == "Support Bot"
        assert candidates == []

    def test_unique_prefix_match(self):
        agent, candidates = eesel.resolve_agent_strict(self.AGENTS, "agent-abc")
        assert agent["name"] == "Support Bot"
        assert candidates == []

    def test_ambiguous_prefix_refuses_and_lists_candidates(self):
        agent, candidates = eesel.resolve_agent_strict(self.AGENTS, "agent-def")
        assert agent is None
        assert {a["agent_id"] for a in candidates} == {"agent-def456", "agent-def789"}

    def test_ambiguous_name_refuses(self):
        agent, candidates = eesel.resolve_agent_strict(self.AGENTS, "Blog Writer")
        assert agent is None
        assert len(candidates) == 2

    def test_no_match_returns_none_and_empty(self):
        agent, candidates = eesel.resolve_agent_strict(self.AGENTS, "nope")
        assert agent is None
        assert candidates == []

    def test_exact_id_is_unique_even_when_prefix_of_another(self):
        agents = [{"agent_id": "ag", "name": "Short"}, {"agent_id": "ag-long", "name": "Long"}]
        agent, candidates = eesel.resolve_agent_strict(agents, "ag")
        assert agent["name"] == "Short"
        assert candidates == []

    def test_same_agent_not_double_counted_on_prefix_and_name(self):
        # An agent matching both by id-prefix and name must count once, so a
        # genuinely unique target isn't mistaken for ambiguous.
        agents = [{"agent_id": "abc", "name": "abc"}]
        agent, candidates = eesel.resolve_agent_strict(agents, "abc")
        assert agent["name"] == "abc"
        assert candidates == []


class TestBuildAgentCreateBody:
    def test_created_live_with_instructions(self):
        body = eesel.build_agent_create_body("ws-1", "QA Bot", "be helpful")
        assert body == {"workspace_id": "ws-1", "name": "QA Bot", "prompt": "be helpful", "is_active": True}

    def test_instructions_optional_default_empty(self):
        # Instructions are optional; the `prompt` wire field is sent as "".
        body = eesel.build_agent_create_body("ws-1", "QA Bot")
        assert body == {"workspace_id": "ws-1", "name": "QA Bot", "prompt": "", "is_active": True}

    def test_always_live(self):
        # New agents are live; there is no inactive create path.
        assert eesel.build_agent_create_body("ws-1", "QA Bot", "p")["is_active"] is True


class TestBuildAgentUpdateBody:
    def test_empty_when_nothing_passed(self):
        assert eesel.build_agent_update_body() == {}

    def test_only_name(self):
        assert eesel.build_agent_update_body(name="Renamed") == {"name": "Renamed"}

    def test_instructions_map_to_prompt_field(self):
        assert eesel.build_agent_update_body(instructions="new text") == {"prompt": "new text"}

    def test_both_fields(self):
        body = eesel.build_agent_update_body(name="N", instructions="P")
        assert body == {"name": "N", "prompt": "P"}


def _capture_requests(monkeypatch, response=None, *, default=None):
    """Replace http_request with a recorder; returns the list of calls made.

    A read-back GET (the pattern write commands use to confirm a 200 actually
    applied) returns the fields last written to the same URL, so a write +
    read-back round-trip reflects what the real server would hand back. Pass an
    explicit ``response`` to override this for a specific test, or ``default`` to
    change the stub returned for a write that has no recorded read-back.
    """
    calls = []
    written: dict = {}
    fallback = default if default is not None else {"agent_id": "created-id-999"}

    def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
        calls.append({"method": method, "url": url, "body": body})
        if response is not None:
            return response
        if method in ("PUT", "POST", "PATCH") and isinstance(body, dict):
            written[url] = {**written.get(url, {}), **body}
            # A real PATCH returns the merged config, so the caller can read its
            # write back from the response without a separate GET.
            if method == "PATCH":
                return written[url]
        if method == "GET" and url in written:
            return written[url]
        return fallback

    monkeypatch.setattr(eesel, "http_request", fake)
    return calls


def _parse(*argv):
    return eesel.build_parser(staff=False).parse_args(list(argv))


class TestAgentsListCommand:
    AGENTS = [
        {"agent_id": "agent-abc123", "name": "Support Bot", "is_active": True},
        {"agent_id": "agent-def456", "name": "Blog Writer", "is_active": False},
    ]

    def test_list_shows_status_column_for_every_agent(self, tmp_config, fake_creds, monkeypatch, capsys):
        # `list` shows everything with its on/off state as a column; it never
        # filters down to only the active ones.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        rc = eesel.cmd_agents(_parse("agents", "list"))
        assert rc == 0
        out = capsys.readouterr().out
        assert "Support Bot" in out and "Blog Writer" in out
        assert "[on]" in out and "[off]" in out

    def test_list_json_emits_raw_records(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        rc = eesel.cmd_agents(_parse("agents", "list", "--json"))
        assert rc == 0
        parsed = json.loads(capsys.readouterr().out)
        assert [a["agent_id"] for a in parsed] == ["agent-abc123", "agent-def456"]

    def test_list_plain_emits_tab_separated_rows(self, tmp_config, fake_creds, monkeypatch, capsys):
        # `--plain` emits one decoration-free, tab-separated row per agent:
        # agent_id<TAB>state<TAB>name. The human view's bracketed status markers
        # must not appear, confirming the human formatter was bypassed.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        rc = eesel.cmd_agents(_parse("agents", "list", "--plain"))
        assert rc == 0
        out = capsys.readouterr().out
        lines = out.strip().splitlines()
        assert lines == ["agent-abc123\ton\tSupport Bot", "agent-def456\toff\tBlog Writer"]
        assert "[on]" not in out and "[off]" not in out


class TestAgentsCreateCommand:
    def test_missing_name_fails_before_request(self, tmp_config, fake_creds, monkeypatch, capsys):
        calls = _capture_requests(monkeypatch)
        rc = eesel.cmd_agents(_parse("agents", "create", "--instructions", "p"))
        assert rc == 1
        assert calls == []  # no request sent
        assert "--name" in capsys.readouterr().err

    def test_create_name_only_succeeds_live_with_empty_instructions(self, tmp_config, fake_creds, monkeypatch, capsys):
        calls = _capture_requests(monkeypatch)
        rc = eesel.cmd_agents(_parse("agents", "create", "--name", "QA Bot"))
        assert rc == 0
        assert calls[0]["method"] == "POST"
        assert calls[0]["url"].endswith("/agents")
        assert calls[0]["body"] == {
            "workspace_id": "ws-test-123",
            "name": "QA Bot",
            "prompt": "",
            "is_active": True,
        }

    def test_create_posts_expected_body_and_prints_id(self, tmp_config, fake_creds, monkeypatch, capsys):
        calls = _capture_requests(monkeypatch)
        rc = eesel.cmd_agents(_parse("agents", "create", "--name", "QA Bot", "--instructions", "you are a test agent"))
        assert rc == 0
        assert len(calls) == 1
        assert calls[0]["body"] == {
            "workspace_id": "ws-test-123",
            "name": "QA Bot",
            "prompt": "you are a test agent",
            "is_active": True,
        }
        assert "created-id-999" in capsys.readouterr().err  # ok() writes to stderr

    def test_add_verb_is_no_longer_accepted(self):
        # `agents add` used to be a hidden alias for `create`; that alias is
        # removed, so `add` is no longer a valid agents verb.
        with pytest.raises(SystemExit):
            _parse("agents", "add", "--name", "QA Bot", "--instructions", "you are a test agent")


class TestAgentsEditFieldsCommand:
    AGENTS = [
        {"agent_id": "agent-abc123", "name": "Support Bot"},
        {"agent_id": "agent-def456", "name": "Blog Writer"},
        {"agent_id": "agent-def789", "name": "Blog Writer"},
    ]

    def test_sends_only_provided_field(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        calls = _capture_requests(monkeypatch)
        rc = eesel.cmd_agents(_parse("agents", "set", "agent-abc123", "--name", "Renamed"))
        assert rc == 0
        assert calls[0]["method"] == "PUT"
        assert calls[0]["url"].endswith("/agents/agent-abc123")
        assert calls[0]["body"] == {"name": "Renamed"}

    def test_instructions_only_sends_prompt(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        calls = _capture_requests(monkeypatch)
        eesel.cmd_agents(_parse("agents", "set", "agent-abc123", "--instructions", "new text"))
        # calls[0] is the PUT; a read-back GET follows it.
        assert calls[0]["body"] == {"prompt": "new text"}

    def test_nothing_to_change_fails(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        calls = _capture_requests(monkeypatch)
        rc = eesel.cmd_agents(_parse("agents", "set", "agent-abc123"))
        assert rc == 1
        assert calls == []

    def test_ambiguous_target_refuses_without_request(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        calls = _capture_requests(monkeypatch)
        rc = eesel.cmd_agents(_parse("agents", "set", "Blog Writer", "--name", "X"))
        assert rc == 1
        assert calls == []
        err = capsys.readouterr().err
        assert "agent-def456" in err and "agent-def789" in err

    def test_unknown_target_errors(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        calls = _capture_requests(monkeypatch)
        rc = eesel.cmd_agents(_parse("agents", "set", "nope", "--name", "X"))
        assert rc == 1
        assert calls == []


class TestAgentsRemoveCommand:
    AGENTS = [
        {"agent_id": "agent-abc123", "name": "Support Bot"},
        {"agent_id": "agent-def456", "name": "Blog Writer"},
        {"agent_id": "agent-def789", "name": "Blog Writer"},
    ]

    def test_yes_flag_skips_prompt_and_removes(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        calls = _capture_requests(monkeypatch, response={})
        rc = eesel.cmd_agents(_parse("agents", "remove", "agent-abc123", "--force"))
        assert rc == 0
        assert calls[0]["method"] == "DELETE"
        assert calls[0]["url"].endswith("/agents/agent-abc123")

    def test_affirmative_confirmation_removes(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        monkeypatch.setattr("builtins.input", lambda prompt="": "yes")
        calls = _capture_requests(monkeypatch, response={})
        rc = eesel.cmd_agents(_parse("agents", "remove", "agent-abc123"))
        assert rc == 0
        assert calls[0]["method"] == "DELETE"

    def test_negative_confirmation_aborts_without_request(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        monkeypatch.setattr("builtins.input", lambda prompt="": "")  # bare Enter
        calls = _capture_requests(monkeypatch, response={})
        rc = eesel.cmd_agents(_parse("agents", "remove", "agent-abc123"))
        assert rc == 1
        assert calls == []

    def test_removing_an_agent_issues_delete(self, tmp_config, fake_creds, monkeypatch):
        # There is no stored active-agent pointer to clear; removal just deletes.
        agents = [{"agent_id": "agent-test-456", "name": "Active One"}]
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: agents)
        calls = _capture_requests(monkeypatch, response={})
        rc = eesel.cmd_agents(_parse("agents", "remove", "agent-test-456", "--force"))
        assert rc == 0
        assert any(c["method"] == "DELETE" and "/agents/agent-test-456" in c["url"] for c in calls)

    def test_ambiguous_target_refuses(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        calls = _capture_requests(monkeypatch, response={})
        rc = eesel.cmd_agents(_parse("agents", "remove", "Blog Writer", "--force"))
        assert rc == 1
        assert calls == []


class TestAgentsShowCommand:
    AGENTS = [
        {
            "agent_id": "agent-abc123",
            "name": "Support Bot",
            "agent_type": "help_desk_agent",
            "is_active": True,
            "description": "Handles tickets",
            "prompt": "You are support.",
        },
        {"agent_id": "agent-def456", "name": "Blog Writer"},
        {"agent_id": "agent-def789", "name": "Blog Writer"},
    ]

    def test_prints_detail_from_listing_without_extra_request(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        calls = _capture_requests(monkeypatch)
        rc = eesel.cmd_agents(_parse("agents", "show", "agent-abc123"))
        assert rc == 0
        assert calls == []  # the listing already carries every field
        out = capsys.readouterr().out
        assert "Support Bot" in out
        assert "help_desk_agent" in out
        assert "live" in out
        assert "You are support." in out

    def test_json_outputs_raw_record(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        _capture_requests(monkeypatch)
        rc = eesel.cmd_agents(_parse("agents", "show", "agent-abc123", "--json"))
        assert rc == 0
        assert json.loads(capsys.readouterr().out)["agent_id"] == "agent-abc123"

    def test_ambiguous_target_refuses(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        rc = eesel.cmd_agents(_parse("agents", "show", "Blog Writer"))
        assert rc == 1


def _agents_subparsers():
    """The `agents` sub-subparsers action, for inspecting which agent
    subcommands are visible in help vs. hidden."""
    agents = _subparsers_action(eesel.build_parser(staff=False)).choices["agents"]
    return _subparsers_action(agents)


class TestAgentsVerbNaming:
    """The agents subcommands follow the CLI's canonical verb set
    (list/show/create/set/remove). The old REST-shaped spellings
    (get/update/delete) and the former `edit` alias are removed outright — this
    is an unreleased command surface, so there are no back-compat aliases for
    them."""

    AGENTS = [{"agent_id": "agent-abc123", "name": "Support Bot"}]

    def test_canonical_verbs_visible_in_help(self):
        visible = [a.dest for a in _agents_subparsers()._choices_actions]
        for verb in ("list", "show", "create", "set", "remove"):
            assert verb in visible

    def test_edit_alias_is_no_longer_accepted(self):
        # `set` is canonical; the former `edit` alias is removed and no longer
        # parses (neither visible nor accepted).
        visible = [a.dest for a in _agents_subparsers()._choices_actions]
        assert "edit" not in visible
        with pytest.raises(SystemExit):
            _parse("agents", "edit", "agent-abc123", "--name", "Z")

    def test_use_and_unset_hidden_from_help(self):
        visible = [a.dest for a in _agents_subparsers()._choices_actions]
        metavar = _agents_subparsers().metavar or ""
        for verb in ("use", "unset"):
            assert verb not in visible
            assert verb not in metavar

    def test_removed_verbs_are_not_accepted(self):
        # The old spellings no longer exist as subcommands at all. (`set` is now
        # the canonical field-change verb, replacing `edit` — see the alias test.)
        for verb in ("get", "update", "delete"):
            with pytest.raises(SystemExit):
                _parse("agents", verb, "agent-abc123")

    def test_show_renders_detail(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        calls = _capture_requests(monkeypatch)
        rc = eesel.cmd_agents(_parse("agents", "show", "agent-abc123"))
        assert rc == 0
        assert calls == []  # detail comes from the listing, no extra request
        assert "Support Bot" in capsys.readouterr().out

    def test_edit_updates_fields(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        calls = _capture_requests(monkeypatch)
        rc = eesel.cmd_agents(_parse("agents", "set", "agent-abc123", "--name", "Renamed"))
        assert rc == 0
        assert calls[0]["method"] == "PUT"
        assert calls[0]["body"] == {"name": "Renamed"}

    def test_remove_deletes(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        calls = _capture_requests(monkeypatch)
        rc = eesel.cmd_agents(_parse("agents", "remove", "agent-abc123", "--force"))
        assert rc == 0
        assert calls[0]["method"] == "DELETE"
        assert calls[0]["url"].endswith("/agents/agent-abc123")


class TestAgentEnvOverride:
    """EESEL_AGENT scopes a single command to one agent without writing to
    disk. It overrides the stored active agent; a --agent flag still wins
    because each command applies it after require_creds returns."""

    AGENTS = [
        {"agent_id": "agent-abc123", "name": "Support Bot"},
        {"agent_id": "agent-def456", "name": "Blog Writer"},
    ]

    def test_unset_env_leaves_creds_untouched(self, fake_creds, monkeypatch):
        monkeypatch.delenv("EESEL_AGENT", raising=False)
        creds = {"agent_id": "stored-agent", "token": "t"}
        assert eesel.apply_agent_env_override(creds) is creds

    def test_env_id_overrides_stored_active_agent(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        monkeypatch.setenv("EESEL_AGENT", "agent-def456")
        creds = {"agent_id": "agent-abc123", "token": "t"}
        out = eesel.apply_agent_env_override(creds)
        assert out["agent_id"] == "agent-def456"
        # The override is per-invocation only — the input dict is never mutated.
        assert creds["agent_id"] == "agent-abc123"

    def test_env_resolves_by_name(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        monkeypatch.setenv("EESEL_AGENT", "Blog Writer")
        out = eesel.apply_agent_env_override({"agent_id": None, "token": "t"})
        assert out["agent_id"] == "agent-def456"

    def test_unresolvable_env_exits(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        monkeypatch.setenv("EESEL_AGENT", "ghost")
        with pytest.raises(SystemExit):
            eesel.apply_agent_env_override({"token": "t"})
        assert "EESEL_AGENT" in capsys.readouterr().err

    def test_ambiguous_env_exits_and_lists_candidates(self, fake_creds, monkeypatch, capsys):
        # An EESEL_AGENT value that matches more than one agent must fail loudly
        # with the full ids, not silently scope to an arbitrary first match.
        dupes = [
            {"agent_id": "agent-aaa111", "name": "Twin"},
            {"agent_id": "agent-bbb222", "name": "Twin"},
        ]
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: dupes)
        monkeypatch.setenv("EESEL_AGENT", "Twin")
        with pytest.raises(SystemExit):
            eesel.apply_agent_env_override({"token": "t"})
        out = capsys.readouterr().err
        assert "ambiguous" in out
        assert "agent-aaa111" in out and "agent-bbb222" in out

    def test_env_does_not_persist_to_disk(self, tmp_config, fake_creds, monkeypatch):
        # require_creds applies the override in memory; nothing is saved, so the
        # stored active agent is unchanged for the next command.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        monkeypatch.setenv("EESEL_AGENT", "agent-def456")
        out = eesel.require_creds()
        assert out["agent_id"] == "agent-def456"
        assert eesel.load_creds()["agent_id"] == fake_creds["agent_id"]


class TestMatchAgents:
    AGENTS = [
        {"agent_id": "agent-abc123", "name": "Support Bot"},
        {"agent_id": "agent-abc999", "name": "Support Bot"},
        {"agent_id": "agent-def456", "name": "Blog Writer"},
    ]

    def test_exact_id_short_circuits_to_one(self):
        assert eesel.match_agents(self.AGENTS, "agent-abc123") == [self.AGENTS[0]]

    def test_ambiguous_prefix_returns_all(self):
        # "agent-abc" prefixes two agents; both come back so callers can refuse.
        matches = eesel.match_agents(self.AGENTS, "agent-abc")
        assert len(matches) == 2

    def test_ambiguous_name_returns_all(self):
        assert len(eesel.match_agents(self.AGENTS, "Support Bot")) == 2

    def test_no_double_listing_prefix_and_name(self):
        # An agent matched by prefix is not also re-listed under the name pass.
        agents = [{"agent_id": "abc", "name": "abc"}]
        assert eesel.match_agents(agents, "abc") == agents


class TestResolveAgentStrict:
    AGENTS = [
        {"agent_id": "agent-abc123", "name": "Support Bot"},
        {"agent_id": "agent-abc999", "name": "Support Bot"},
        {"agent_id": "agent-def456", "name": "Blog Writer"},
    ]

    def test_unique_match_returns_agent_no_candidates(self):
        agent, candidates = eesel.resolve_agent_strict(self.AGENTS, "agent-def456")
        assert agent["name"] == "Blog Writer"
        assert candidates == []

    def test_ambiguous_returns_none_with_candidates(self):
        agent, candidates = eesel.resolve_agent_strict(self.AGENTS, "agent-abc")
        assert agent is None
        assert len(candidates) == 2

    def test_no_match_returns_none_empty(self):
        agent, candidates = eesel.resolve_agent_strict(self.AGENTS, "nope")
        assert agent is None
        assert candidates == []


class TestResolveAgentOrError:
    AGENTS = [
        {"agent_id": "agent-abc123", "name": "Support Bot"},
        {"agent_id": "agent-abc999", "name": "Support Bot"},
    ]

    def test_unique_match_returns_agent(self, monkeypatch):
        monkeypatch.delenv("EESEL_AGENT", raising=False)
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        assert eesel.resolve_agent_or_error({}, "agent-abc123")["name"] == "Support Bot"

    def test_ambiguous_lists_candidates_and_returns_none(self, monkeypatch, capsys):
        monkeypatch.delenv("EESEL_AGENT", raising=False)
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        assert eesel.resolve_agent_or_error({}, "agent-abc") is None
        errout = capsys.readouterr().err
        assert "ambiguous" in errout
        assert "agent-abc123" in errout and "agent-abc999" in errout

    def test_no_target_multi_agent_errors(self, monkeypatch, capsys):
        # No explicit scope in a multi-agent workspace: refuse and list the
        # agents rather than act on an arbitrary one.
        monkeypatch.delenv("EESEL_AGENT", raising=False)
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        assert eesel.resolve_agent_or_error({}, None) is None
        assert "2 agents" in capsys.readouterr().err

    def test_no_target_single_agent_auto_selects(self, monkeypatch):
        # The one implicit case: a single-agent workspace is used automatically.
        monkeypatch.delenv("EESEL_AGENT", raising=False)
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "solo", "name": "Solo"}])
        assert eesel.resolve_agent_or_error({}, None)["agent_id"] == "solo"

    def test_falls_back_to_env(self, monkeypatch):
        monkeypatch.setenv("EESEL_AGENT", "agent-abc123")
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        assert eesel.resolve_agent_or_error({}, None)["agent_id"] == "agent-abc123"


class TestConfirm:
    def test_prompt_goes_to_stderr_not_stdout(self, monkeypatch, capsys):
        # The prompt must not land on stdout, or it would be captured by
        # `eesel ... > out.txt`.
        monkeypatch.setattr("builtins.input", lambda: "y")
        eesel.confirm("Delete everything? [y/N] ")
        captured = capsys.readouterr()
        assert "Delete everything?" in captured.err
        assert captured.out == ""

    def test_yes_variants(self, monkeypatch):
        for ans in ("y", "yes", "  YES  ", "Y"):
            monkeypatch.setattr("builtins.input", lambda ans=ans: ans)
            assert eesel.confirm("?") is True

    def test_anything_else_is_no(self, monkeypatch):
        for ans in ("", "n", "no", "maybe"):
            monkeypatch.setattr("builtins.input", lambda ans=ans: ans)
            assert eesel.confirm("?") is False

    def test_eof_is_no(self, monkeypatch):
        def boom():
            raise EOFError
        monkeypatch.setattr("builtins.input", boom)
        assert eesel.confirm("?") is False


class TestHttpRequestNonJson:
    class _FakeResp:
        def __init__(self, body: bytes, status: int = 200):
            self._body = body
            self.status = status

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def test_non_json_200_exits_cleanly(self, monkeypatch, capsys):
        # A proxy/login HTML page served with status 200 must not raise a raw
        # JSONDecodeError traceback, and it exits with the server-class code (7)
        # like the timeout/unreachable branches — a headless agent treats a
        # gateway answering instead of the API as "retry later", not a generic
        # exit 1.
        html = b"<html><body>Gateway timeout</body></html>"
        monkeypatch.setattr(
            eesel.urllib.request, "urlopen", lambda *a, **k: self._FakeResp(html)
        )
        with pytest.raises(SystemExit) as exc:
            eesel.http_request("GET", "http://proxy/agents")
        assert exc.value.code == eesel.EXIT_SERVER
        msg = capsys.readouterr().err
        assert "not JSON" in msg
        assert "JSONDecodeError" not in msg

    def test_empty_body_returns_empty_dict(self, monkeypatch):
        monkeypatch.setattr(
            eesel.urllib.request, "urlopen", lambda *a, **k: self._FakeResp(b"")
        )
        assert eesel.http_request("GET", "http://x/y") == {}

    def test_valid_json_still_parsed(self, monkeypatch):
        monkeypatch.setattr(
            eesel.urllib.request, "urlopen", lambda *a, **k: self._FakeResp(b'{"ok": true}')
        )
        assert eesel.http_request("GET", "http://x/y") == {"ok": True}


class TestParseConfigObject:
    def test_valid_object(self):
        assert eesel.parse_config_object('{"cron": "0 9 * * *"}') == {"cron": "0 9 * * *"}

    def test_invalid_json_exits_2(self, capsys):
        with pytest.raises(SystemExit) as exc:
            eesel.parse_config_object("{not json}")
        assert exc.value.code == 2
        assert "not valid JSON" in capsys.readouterr().err

    def test_non_object_exits_2(self, capsys):
        with pytest.raises(SystemExit) as exc:
            eesel.parse_config_object('["a", "b"]')
        assert exc.value.code == 2
        assert "must be a JSON object" in capsys.readouterr().err

    def test_example_in_message_is_customizable(self, capsys):
        with pytest.raises(SystemExit):
            eesel.parse_config_object("42", example='{"enabled": true}')
        assert '{"enabled": true}' in capsys.readouterr().err


class TestMatchAgents:
    AGENTS = [
        {"agent_id": "agent-abc123", "name": "Support Bot"},
        {"agent_id": "agent-abc999", "name": "Support Bot"},
        {"agent_id": "agent-def456", "name": "Blog Writer"},
    ]

    def test_exact_id_short_circuits_to_one(self):
        assert eesel.match_agents(self.AGENTS, "agent-abc123") == [self.AGENTS[0]]

    def test_ambiguous_prefix_returns_all(self):
        # "agent-abc" prefixes two agents; both come back so callers can refuse.
        matches = eesel.match_agents(self.AGENTS, "agent-abc")
        assert len(matches) == 2

    def test_ambiguous_name_returns_all(self):
        assert len(eesel.match_agents(self.AGENTS, "Support Bot")) == 2

    def test_no_double_listing_prefix_and_name(self):
        # An agent matched by prefix is not also re-listed under the name pass.
        agents = [{"agent_id": "abc", "name": "abc"}]
        assert eesel.match_agents(agents, "abc") == agents


class TestResolveAgentStrict:
    AGENTS = [
        {"agent_id": "agent-abc123", "name": "Support Bot"},
        {"agent_id": "agent-abc999", "name": "Support Bot"},
        {"agent_id": "agent-def456", "name": "Blog Writer"},
    ]

    def test_unique_match_returns_agent_no_candidates(self):
        agent, candidates = eesel.resolve_agent_strict(self.AGENTS, "agent-def456")
        assert agent["name"] == "Blog Writer"
        assert candidates == []

    def test_ambiguous_returns_none_with_candidates(self):
        agent, candidates = eesel.resolve_agent_strict(self.AGENTS, "agent-abc")
        assert agent is None
        assert len(candidates) == 2

    def test_no_match_returns_none_empty(self):
        agent, candidates = eesel.resolve_agent_strict(self.AGENTS, "nope")
        assert agent is None
        assert candidates == []


class TestResolveAgentOrError:
    AGENTS = [
        {"agent_id": "agent-abc123", "name": "Support Bot"},
        {"agent_id": "agent-abc999", "name": "Support Bot"},
    ]

    def test_unique_match_returns_agent(self, monkeypatch):
        monkeypatch.delenv("EESEL_AGENT", raising=False)
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        assert eesel.resolve_agent_or_error({}, "agent-abc123")["name"] == "Support Bot"

    def test_ambiguous_lists_candidates_and_returns_none(self, monkeypatch, capsys):
        monkeypatch.delenv("EESEL_AGENT", raising=False)
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        assert eesel.resolve_agent_or_error({}, "agent-abc") is None
        errout = capsys.readouterr().err
        assert "ambiguous" in errout
        assert "agent-abc123" in errout and "agent-abc999" in errout

    def test_no_target_multi_agent_errors(self, monkeypatch, capsys):
        # No explicit scope in a multi-agent workspace: refuse and list the
        # agents rather than act on an arbitrary one.
        monkeypatch.delenv("EESEL_AGENT", raising=False)
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        assert eesel.resolve_agent_or_error({}, None) is None
        assert "2 agents" in capsys.readouterr().err

    def test_no_target_single_agent_auto_selects(self, monkeypatch):
        # The one implicit case: a single-agent workspace is used automatically.
        monkeypatch.delenv("EESEL_AGENT", raising=False)
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "solo", "name": "Solo"}])
        assert eesel.resolve_agent_or_error({}, None)["agent_id"] == "solo"

    def test_falls_back_to_env(self, monkeypatch):
        monkeypatch.setenv("EESEL_AGENT", "agent-abc123")
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        assert eesel.resolve_agent_or_error({}, None)["agent_id"] == "agent-abc123"


class TestConfirm:
    def test_prompt_goes_to_stderr_not_stdout(self, monkeypatch, capsys):
        # The prompt must not land on stdout, or it would be captured by
        # `eesel ... > out.txt`.
        monkeypatch.setattr("builtins.input", lambda: "y")
        eesel.confirm("Delete everything? [y/N] ")
        captured = capsys.readouterr()
        assert "Delete everything?" in captured.err
        assert captured.out == ""

    def test_yes_variants(self, monkeypatch):
        for ans in ("y", "yes", "  YES  ", "Y"):
            monkeypatch.setattr("builtins.input", lambda ans=ans: ans)
            assert eesel.confirm("?") is True

    def test_anything_else_is_no(self, monkeypatch):
        for ans in ("", "n", "no", "maybe"):
            monkeypatch.setattr("builtins.input", lambda ans=ans: ans)
            assert eesel.confirm("?") is False

    def test_eof_is_no(self, monkeypatch):
        def boom():
            raise EOFError
        monkeypatch.setattr("builtins.input", boom)
        assert eesel.confirm("?") is False


class TestHttpRequestNonJson:
    class _FakeResp:
        def __init__(self, body: bytes, status: int = 200):
            self._body = body
            self.status = status

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def test_non_json_200_exits_cleanly(self, monkeypatch, capsys):
        # A proxy/login HTML page served with status 200 must not raise a raw
        # JSONDecodeError traceback, and it exits with the server-class code (7)
        # like the timeout/unreachable branches — a headless agent treats a
        # gateway answering instead of the API as "retry later", not a generic
        # exit 1.
        html = b"<html><body>Gateway timeout</body></html>"
        monkeypatch.setattr(
            eesel.urllib.request, "urlopen", lambda *a, **k: self._FakeResp(html)
        )
        with pytest.raises(SystemExit) as exc:
            eesel.http_request("GET", "http://proxy/agents")
        assert exc.value.code == eesel.EXIT_SERVER
        msg = capsys.readouterr().err
        assert "not JSON" in msg
        assert "JSONDecodeError" not in msg

    def test_empty_body_returns_empty_dict(self, monkeypatch):
        monkeypatch.setattr(
            eesel.urllib.request, "urlopen", lambda *a, **k: self._FakeResp(b"")
        )
        assert eesel.http_request("GET", "http://x/y") == {}

    def test_valid_json_still_parsed(self, monkeypatch):
        monkeypatch.setattr(
            eesel.urllib.request, "urlopen", lambda *a, **k: self._FakeResp(b'{"ok": true}')
        )
        assert eesel.http_request("GET", "http://x/y") == {"ok": True}


class TestParseConfigObject:
    def test_valid_object(self):
        assert eesel.parse_config_object('{"cron": "0 9 * * *"}') == {"cron": "0 9 * * *"}

    def test_invalid_json_exits_2(self, capsys):
        with pytest.raises(SystemExit) as exc:
            eesel.parse_config_object("{not json}")
        assert exc.value.code == 2
        assert "not valid JSON" in capsys.readouterr().err

    def test_non_object_exits_2(self, capsys):
        with pytest.raises(SystemExit) as exc:
            eesel.parse_config_object('["a", "b"]')
        assert exc.value.code == 2
        assert "must be a JSON object" in capsys.readouterr().err

    def test_example_in_message_is_customizable(self, capsys):
        with pytest.raises(SystemExit):
            eesel.parse_config_object("42", example='{"enabled": true}')
        assert '{"enabled": true}' in capsys.readouterr().err


class TestInstructionsCommand:
    AGENTS = [
        {"agent_id": "agent-test-456", "name": "Active One", "prompt": "Be helpful and concise."},
        {"agent_id": "agent-other-9", "name": "Sales Bot", "prompt": "Always upsell."},
        {"agent_id": "agent-blank-0", "name": "Empty", "prompt": ""},
    ]

    def _args(self, agent=None):
        return type("Args", (), {"agent": agent})()

    def test_single_agent_auto_prints_prompt(self, tmp_config, fake_creds, monkeypatch, capsys):
        # With one agent and no explicit scope, the CLI uses that sole agent.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [self.AGENTS[0]])
        rc = eesel.cmd_instructions(self._args())
        assert rc == 0
        out = capsys.readouterr().out
        assert out.strip() == "Be helpful and concise."

    def test_resolves_named_agent(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        rc = eesel.cmd_instructions(self._args("Sales Bot"))
        assert rc == 0
        assert capsys.readouterr().out.strip() == "Always upsell."

    def test_resolves_id_prefix(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        rc = eesel.cmd_instructions(self._args("agent-other"))
        assert rc == 0
        assert capsys.readouterr().out.strip() == "Always upsell."

    def test_unknown_agent_errors(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        rc = eesel.cmd_instructions(self._args("ghost"))
        assert rc == 1
        assert capsys.readouterr().out == ""  # nothing leaks to stdout

    def test_empty_prompt_reports_no_instructions(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        rc = eesel.cmd_instructions(self._args("Empty"))
        assert rc == 0
        # Header + "(no instructions...)" go to stderr; stdout stays clean.
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "no instructions" in captured.err

    def test_no_agents_errors(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [])
        assert eesel.cmd_instructions(self._args()) == 1

    def test_multi_agent_no_scope_errors(self, tmp_config, fake_creds, monkeypatch):
        # Several agents and no explicit scope → refuse rather than guess.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        assert eesel.cmd_instructions(self._args()) == 1


class _FakeStdin:
    """Minimal stand-in for sys.stdin so a test can control isatty()."""
    def __init__(self, tty):
        self._tty = tty

    def isatty(self):
        return self._tty


class TestStdinHasPipedData:
    """`_stdin_has_piped_data` must return True only for a non-TTY stdin that
    actually carries a byte to read. An empty pipe or file (a headless caller
    that produced no input) must read as "no piped data" so the no-target /
    no-message guards fire instead of dropping into a REPL that reads EOF and
    reports success having done nothing."""

    def test_tty_has_no_piped_data(self, monkeypatch):
        monkeypatch.setattr(eesel.sys, "stdin", _FakeStdin(True))
        assert eesel._stdin_has_piped_data() is False

    def test_non_empty_file_has_piped_data(self, tmp_path, monkeypatch):
        p = tmp_path / "msg.txt"
        p.write_text("summarize this\n")
        with open(p, "r") as f:
            monkeypatch.setattr(eesel.sys, "stdin", f)
            assert eesel._stdin_has_piped_data() is True

    def test_empty_file_has_no_piped_data(self, tmp_path, monkeypatch):
        # `eesel chat < empty.txt`: a real regular file, but zero bytes. The old
        # descriptor-type-only check returned True here and re-opened the exit-0
        # silent no-op; peeking a byte settles it as empty.
        p = tmp_path / "empty.txt"
        p.write_text("")
        with open(p, "r") as f:
            monkeypatch.setattr(eesel.sys, "stdin", f)
            assert eesel._stdin_has_piped_data() is False

    def test_non_empty_pipe_has_piped_data_without_consuming(self, monkeypatch):
        # A pipe carrying a message reads as "has data", and the peek must not
        # consume it — a following read still sees the whole line.
        r_fd, w_fd = os.pipe()
        os.write(w_fd, b"line one\n")
        os.close(w_fd)
        with os.fdopen(r_fd, "r") as f:
            monkeypatch.setattr(eesel.sys, "stdin", f)
            assert eesel._stdin_has_piped_data() is True
            assert f.readline() == "line one\n"

    def test_empty_closed_pipe_has_no_piped_data(self, monkeypatch):
        # `produces_nothing | eesel chat`: the writer closes without emitting a
        # byte, so the peek sees EOF immediately and the guard can fire.
        r_fd, w_fd = os.pipe()
        os.close(w_fd)
        with os.fdopen(r_fd, "r") as f:
            monkeypatch.setattr(eesel.sys, "stdin", f)
            assert eesel._stdin_has_piped_data() is False


class TestPickAgent:
    """chat / new resolve their agent via pick_agent: an explicit scope wins, a
    single-agent workspace is used automatically, an interactive terminal
    prompts, and a non-interactive run refuses rather than guess. Nothing is
    persisted."""
    AGENTS = [{"agent_id": "a1", "name": "One"}, {"agent_id": "a2", "name": "Two"}]

    def test_explicit_scope_wins_without_lookup(self, monkeypatch):
        # --agent / EESEL_AGENT already set creds["agent_id"] in memory.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: pytest.fail("no lookup needed"))
        assert eesel.pick_agent({"agent_id": "a2"}) == "a2"

    def test_single_agent_auto_selected(self, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "solo", "name": "Solo"}])
        assert eesel.pick_agent({}) == "solo"

    def test_multi_agent_non_interactive_errors(self, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        monkeypatch.setattr(eesel.sys, "stdin", _FakeStdin(False))
        with pytest.raises(SystemExit):
            eesel.pick_agent({}, prompt=True)
        assert "2 agents" in capsys.readouterr().err

    def test_multi_agent_tty_prompts(self, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        monkeypatch.setattr(eesel.sys, "stdin", _FakeStdin(True))
        monkeypatch.setattr("builtins.input", lambda *a, **k: "1")  # pick the second
        assert eesel.pick_agent({}, prompt=True) == "a2"

    def test_does_not_persist(self, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "solo", "name": "Solo"}])
        monkeypatch.setattr(eesel, "save_creds", lambda creds: pytest.fail("pick_agent must not persist"))
        assert eesel.pick_agent({}) == "solo"


class TestInteractiveSelectFallback:
    def test_numbered_select_valid_index(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _="": "1")
        assert eesel._numbered_select(["a", "b", "c"]) == 1

    def test_numbered_select_out_of_range(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _="": "9")
        assert eesel._numbered_select(["a", "b"]) is None

    def test_numbered_select_non_numeric(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _="": "nope")
        assert eesel._numbered_select(["a", "b"]) is None

    def test_numbered_select_eof_cancels(self, monkeypatch):
        def boom(_=""):
            raise EOFError

        monkeypatch.setattr("builtins.input", boom)
        assert eesel._numbered_select(["a", "b"]) is None

    def test_interactive_select_empty_options(self):
        assert eesel.interactive_select([]) is None

    def test_interactive_select_falls_back_when_not_tty(self, monkeypatch):
        # Non-TTY stdin → fall back to the numbered prompt path.
        monkeypatch.setattr(eesel.sys.stdin, "isatty", lambda: False)
        monkeypatch.setattr("builtins.input", lambda _="": "0")
        assert eesel.interactive_select(["only"]) == 0


def _subparsers_action(parser):
    import argparse

    return next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))


def _visible_commands(parser):
    """Command names shown in `--help` (the descriptive list)."""
    return [a.dest for a in _subparsers_action(parser)._choices_actions]


def _all_subparser_actions(parser):
    """Every subparsers action in the parser tree (root + nested groups)."""
    import argparse

    out = []

    def walk(p):
        action = next((a for a in p._actions if isinstance(a, argparse._SubParsersAction)), None)
        if action is None:
            return
        out.append(action)
        for child in action.choices.values():
            walk(child)

    walk(parser)
    return out


def test_no_group_leaks_hidden_aliases_into_its_metavar():
    # A hidden back-compat alias (help=SUPPRESS) must be dropped from BOTH the
    # visible choice list and the usage-line metavar. argparse builds the metavar
    # from every registered subparser unless it is pinned, so a group that pins
    # the choice list but forgets the metavar leaks the alias into `--help` — as
    # `schedules` once leaked `delete`/`run`. hide_subcommands() does both steps;
    # this guards every group (and the root) at once so the leak can't return.
    for action in _all_subparser_actions(eesel.build_parser(staff=False)):
        metavar = action.metavar or ""
        if not metavar:
            continue
        assert "SUPPRESS" not in metavar
        inner = metavar.strip("{}")
        listed = set(inner.split(",")) if inner else set()
        visible = {a.dest for a in action._choices_actions}
        assert listed == visible, f"metavar {metavar!r} != visible {sorted(visible)}"


def _dev_flag_help(parser):
    login = _subparsers_action(parser).choices["login"]
    return next(a for a in login._actions if a.dest == "dev").help


class TestStaffCommandVisibility:
    """`impersonate` and dev login are surfaced only for global impersonators."""

    def test_impersonate_hidden_from_non_staff_help(self):
        parser = eesel.build_parser(staff=False)
        assert "impersonate" not in _visible_commands(parser)
        # ...and absent from the `{...}` usage metavar too.
        assert "impersonate" not in (_subparsers_action(parser).metavar or "")

    def test_impersonate_visible_for_staff(self):
        parser = eesel.build_parser(staff=True)
        assert "impersonate" in _visible_commands(parser)
        assert "impersonate" in _subparsers_action(parser).metavar

    def test_impersonate_still_parseable_for_non_staff(self):
        # Hidden from help, but the server allowlist is the real gate — so it
        # must still dispatch if someone types it.
        parser = eesel.build_parser(staff=False)
        args = parser.parse_args(["impersonate", "clear"])
        assert args.func is eesel.cmd_impersonate
        assert args.user_id == "clear"

    def test_dev_flags_suppressed_for_non_staff(self):
        import argparse

        assert _dev_flag_help(eesel.build_parser(staff=False)) is argparse.SUPPRESS

    def test_dev_flags_shown_for_staff(self):
        import argparse

        assert _dev_flag_help(eesel.build_parser(staff=True)) is not argparse.SUPPRESS

    def test_login_dev_parses_regardless_of_staff(self):
        # Kept parseable both ways so a fresh staff machine can still dev-login.
        for staff in (False, True):
            args = eesel.build_parser(staff=staff).parse_args(["login", "--dev", "--workspace-id", "ws-1"])
            assert args.dev is True
            assert args.workspace_id == "ws-1"

    def test_default_build_parser_is_non_staff(self):
        # build_parser() with no arg must hide staff commands (the safe default).
        assert "impersonate" not in _visible_commands(eesel.build_parser())


class TestImpersonatorFlagCaching:
    def _creds(self, **extra):
        c = {
            "env": "prod",
            "api_url": "https://api.example",
            "workspace_id": "ws-1",
            "token": "tok",
            "expires_at": int(time.time()) + 3600,
        }
        c.update(extra)
        eesel.save_creds(c)
        return c

    def test_caches_true(self, tmp_config, monkeypatch):
        creds = self._creds()
        monkeypatch.setattr(eesel, "_get_impersonate_status", lambda c: {"allowed": True})
        assert eesel.cache_impersonator_flag(creds) is True
        assert eesel.load_creds()["is_impersonator"] is True

    def test_caches_false(self, tmp_config, monkeypatch):
        creds = self._creds(is_impersonator=True)  # was true, now downgraded
        monkeypatch.setattr(eesel, "_get_impersonate_status", lambda c: {"allowed": False})
        assert eesel.cache_impersonator_flag(creds) is False
        assert eesel.load_creds()["is_impersonator"] is False

    def test_network_error_keeps_cached_value(self, tmp_config, monkeypatch):
        creds = self._creds(is_impersonator=True)
        monkeypatch.setattr(eesel, "_get_impersonate_status", lambda c: None)
        # A blip must not transiently hide a staff member's commands.
        assert eesel.cache_impersonator_flag(creds) is True
        assert eesel.load_creds()["is_impersonator"] is True

    def test_cmd_login_caches_flag(self, tmp_config, monkeypatch):
        stored = {
            "env": "prod",
            "api_url": "https://api.example",
            "workspace_id": "ws-1",
            "token": "tok",
            "expires_at": int(time.time()) + 3600,
        }

        def fake_login_prod():
            eesel.save_creds(stored)
            return stored

        monkeypatch.setattr(eesel, "login_prod", fake_login_prod)
        monkeypatch.setattr(eesel, "_get_impersonate_status", lambda c: {"allowed": True})
        rc = eesel.cmd_login(type("Args", (), {"dev": False, "workspace_id": None})())
        assert rc == 0
        assert eesel.load_creds()["is_impersonator"] is True

    def test_whoami_persists_flag_and_reports(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(
            eesel, "_get_impersonate_status", lambda c: {"allowed": True, "target_user_id": None}
        )
        eesel.cmd_whoami(type("Args", (), {})())
        assert eesel.load_creds()["is_impersonator"] is True
        assert "impersonator : yes" in capsys.readouterr().out

    def test_whoami_shows_effective_workspace_without_persisting_it(self, tmp_config, monkeypatch, capsys):
        # whoami resolves the effective (impersonated) workspace for DISPLAY
        # only. It also saves creds to refresh the is_impersonator flag — that
        # save must not carry the resolved workspace onto disk over the stored
        # one, or a read-only whoami would silently corrupt the login.
        eesel.save_creds({
            "env": "prod",
            "api_url": "https://oracle.eesel.app",
            "workspace_id": "ws-A-own",
            "token": "auth0",
            "refresh_token": "rt",
            "expires_at": int(time.time()) + 3600,
        })
        # The guard has already resolved the target's workspace onto the module
        # global; whoami reuses it for display.
        monkeypatch.setattr(eesel, "_impersonation_target",
                            {"user": "victim-9", "workspace": "ws-B-target"}, raising=False)
        monkeypatch.setattr(
            eesel, "_get_impersonate_status",
            lambda c: {"allowed": True, "target_user_id": "victim-9"},
        )
        eesel.cmd_whoami(type("Args", (), {})())
        assert "ws-B-target" in capsys.readouterr().out          # display is the effective ws
        assert eesel.load_creds()["workspace_id"] == "ws-A-own"  # disk is untouched


class TestMainStaffGating:
    def _save(self, **extra):
        c = {
            "env": "prod",
            "api_url": "https://api.example",
            "workspace_id": "ws-1",
            "token": "tok",
            "expires_at": int(time.time()) + 3600,
        }
        c.update(extra)
        eesel.save_creds(c)

    def _run_capturing_staff(self, monkeypatch):
        seen = {}
        real = eesel.build_parser

        def spy(staff=False, platform_hint=None):
            seen["staff"] = staff
            return real(staff, platform_hint)

        monkeypatch.setattr(eesel, "build_parser", spy)
        eesel.main(["logout"])  # no network; safe with tmp_config
        return seen.get("staff")

    def test_main_staff_true_when_cached(self, tmp_config, monkeypatch):
        self._save(is_impersonator=True)
        assert self._run_capturing_staff(monkeypatch) is True

    def test_main_staff_false_when_flag_absent(self, tmp_config, monkeypatch):
        self._save()  # no is_impersonator key
        assert self._run_capturing_staff(monkeypatch) is False

    def test_main_staff_false_when_not_logged_in(self, tmp_config, monkeypatch):
        assert self._run_capturing_staff(monkeypatch) is False


def _ns(**kw):
    """A throwaway argparse-Namespace stand-in carrying only the given attrs."""
    return type("Args", (), kw)()


class TestIsWriteCommand:
    """`_is_write_command` reads the `write=True` tag each customer-changing
    subcommand sets at its parser. These parse real argv through build_parser so
    the test breaks if a write verb loses (or a read verb gains) its tag."""

    def _writes(self, *argv):
        args = eesel.build_parser(staff=True).parse_args(list(argv))
        return eesel._is_write_command(args)

    def test_write_verbs_are_writes(self):
        for argv in [
            ("agents", "create", "--name", "x"),
            ("agents", "set", "a", "--name", "n"),
            ("agents", "remove", "a"),
            ("mcp", "add", "--name", "n", "--url", "u"),
            ("mcp", "set", "s", "--name", "n"),
            ("mcp", "enable", "s"),
            ("mcp", "remove", "s"),
            ("workspace", "set", "billing-limit", "5"),
            ("workspace", "extend-trial"),
            ("tasks", "export"),
            ("integrations", "connect", "z"),
            ("integrations", "sync", "z"),
            ("integrations", "remove", "z"),
            ("automations", "triggers", "add", "a", "--key", "k"),
            ("automations", "schedules", "fire", "j"),
            ("files", "add", "--title", "t", "--content", "c"),
            ("files", "remove", "k"),
            ("files", "acl", "set", "a", "--prefix", "p"),
            ("settings", "notifications", "set", "a"),
        ]:
            assert self._writes(*argv), f"{argv} should be a write"

    def test_read_verbs_are_not_writes(self):
        for argv in [
            ("agents", "list"),
            ("agents", "show", "a"),
            ("mcp", "list"),
            ("workspace", "show"),
            ("workspace", "members"),
            ("tasks", "list"),
            ("billing", "show"),
            ("integrations", "list"),
            ("integrations", "sync-status"),
            ("files", "list"),
            ("settings", "notifications", "show", "a"),
        ]:
            assert not self._writes(*argv), f"{argv} should NOT be a write"

    def test_chat_and_control_commands_are_not_writes(self):
        # chat (its write tools are stubbed server-side) and impersonate (control)
        # must never be blocked while impersonating.
        assert not self._writes("chat", "hi")
        assert not self._writes("impersonate", "auth0|x")
        assert not self._writes("impersonate", "clear")
        assert not self._writes("whoami")


class TestImpersonationBackstop:
    """The http_request backstop refuses a mutating request under a live target,
    unless its path is a known read/plumbing exception."""

    def _arm(self, monkeypatch):
        monkeypatch.setattr(eesel, "_impersonation_target",
                            {"user": "auth0|cust", "workspace": "cust-ws"}, raising=False)

    def test_mutating_call_blocked_before_network(self, monkeypatch, capsys):
        self._arm(monkeypatch)

        def boom(*a, **k):
            raise AssertionError("request must not reach the network")

        monkeypatch.setattr(eesel.urllib.request, "urlopen", boom)
        with pytest.raises(SystemExit) as e:
            eesel.http_request("POST", "https://api.example/agents", token="t")
        assert e.value.code == eesel.EXIT_IMPERSONATION_BLOCKED  # distinct code 3
        assert "Refused" in capsys.readouterr().err

    def test_allowed_paths_pass_the_backstop(self, monkeypatch):
        self._arm(monkeypatch)
        seen = []
        monkeypatch.setattr(
            eesel.urllib.request, "urlopen",
            lambda req, timeout=None: seen.append(req.full_url) or _FakeResp({}),
        )
        for path in ("/workspaces/token", "/workspace/tasks", "/workspace/tasks/analytics", "/dev/session"):
            eesel.http_request("POST", f"https://api.example{path}", token="t")
        assert len(seen) == 4  # every allowed path reached the network, none blocked

    def test_export_is_not_confused_with_tasks_list(self, monkeypatch, capsys):
        # `/workspace/tasks` (list) is allowed; `/tasks/export` (emails the
        # customer) must NOT be — a prefix match would wrongly allow it.
        self._arm(monkeypatch)
        monkeypatch.setattr(eesel.urllib.request, "urlopen",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("blocked path hit network")))
        with pytest.raises(SystemExit) as e:
            eesel.http_request("POST", "https://api.example/tasks/export", token="t")
        assert e.value.code == eesel.EXIT_IMPERSONATION_BLOCKED

    def test_reads_pass_under_a_target(self, monkeypatch):
        self._arm(monkeypatch)
        got = {}

        def fake(req, timeout=None):
            got["m"] = req.get_method()
            return _FakeResp({})

        monkeypatch.setattr(eesel.urllib.request, "urlopen", fake)
        eesel.http_request("GET", "https://api.example/agents", token="t")
        assert got["m"] == "GET"  # a GET is never blocked

    def test_no_target_lets_writes_through(self, monkeypatch):
        # Not impersonating → the backstop is inert; a POST proceeds normally.
        monkeypatch.setattr(eesel, "_impersonation_target", None, raising=False)
        seen = []
        monkeypatch.setattr(eesel.urllib.request, "urlopen",
                            lambda req, timeout=None: seen.append(1) or _FakeResp({}))
        eesel.http_request("POST", "https://api.example/agents", token="t")
        assert seen == [1]


class TestGuardImpersonatedCommand:
    """`_guard_impersonated_command` runs before dispatch: banner on every
    command under a live target, refusal for writes, nothing off the staff path."""

    def _creds(self, **extra):
        c = {"is_impersonator": True, "api_url": "https://api.example",
             "token": "t", "workspace_id": "own-ws"}
        c.update(extra)
        return c

    def _real_target(self, monkeypatch, ws="cust-ws"):
        monkeypatch.setattr(eesel, "_get_impersonate_status",
                            lambda c: {"allowed": True, "target_user_id": "auth0|cust"})
        monkeypatch.setattr(eesel, "resolve_effective_workspace_id", lambda c: ws)

    def test_normal_customer_pays_nothing(self, monkeypatch):
        # No cached staff flag → no status call, no banner, no target armed.
        def boom(c):
            raise AssertionError("must not check impersonation status for a normal login")

        monkeypatch.setattr(eesel, "_get_impersonate_status", boom)
        monkeypatch.setattr(eesel, "_impersonation_target", None, raising=False)
        eesel._guard_impersonated_command(_ns(write=True), {"api_url": "x", "token": "t"})
        assert eesel._impersonation_target is None

    def test_idle_staff_not_blocked(self, monkeypatch, capsys):
        # Allowlisted but no target armed → acts as themselves; no banner, no block.
        monkeypatch.setattr(eesel, "_get_impersonate_status",
                            lambda c: {"allowed": True, "target_user_id": None})
        monkeypatch.setattr(eesel, "_impersonation_target", None, raising=False)
        eesel._guard_impersonated_command(_ns(write=True), self._creds())
        assert eesel._impersonation_target is None
        assert capsys.readouterr().err == ""

    def test_write_refused_with_distinct_code(self, monkeypatch, capsys):
        self._real_target(monkeypatch)
        with pytest.raises(SystemExit) as e:
            eesel._guard_impersonated_command(_ns(write=True), self._creds())
        assert e.value.code == eesel.EXIT_IMPERSONATION_BLOCKED
        err = capsys.readouterr().err
        assert "▲ impersonating auth0|cust — cust-ws" in err  # banner
        assert "Refused" in err                               # refusal

    def test_read_shows_banner_but_is_not_blocked(self, monkeypatch, capsys):
        self._real_target(monkeypatch)
        eesel._guard_impersonated_command(_ns(write=False), self._creds())
        cap = capsys.readouterr()
        assert "▲ impersonating" in cap.err  # banner on stderr
        assert "Refused" not in cap.err       # not blocked
        assert cap.out == ""                  # stdout untouched (byte-for-byte clean)
        assert eesel._impersonation_target is not None

    def test_control_command_not_blocked_under_target(self, monkeypatch, capsys):
        # `impersonate clear` must run even while a target is live — it carries
        # no write tag, so the guard shows the banner but does not refuse it.
        self._real_target(monkeypatch)
        eesel._guard_impersonated_command(_ns(write=False), self._creds())
        assert "Refused" not in capsys.readouterr().err

    def test_expired_staff_token_is_refreshed_before_probing(self, monkeypatch):
        # A cached staff token near expiry is refreshed up front, so the status
        # probe runs on a live token and the write-block still arms. Without the
        # refresh the probe would 401, report no target, and let the write through
        # after require_creds refreshed the token.
        creds = self._creds(refresh_token="rt",
                            expires_at=int(time.time()) - 1)  # already expired
        refreshed = {"called": False}

        def fake_refresh(c):
            refreshed["called"] = True
            c["token"] = "fresh"
            c["expires_at"] = int(time.time()) + 3600
            return c

        monkeypatch.setattr(eesel, "refresh_prod_token", fake_refresh)
        # Probe only reports the live target once the token is fresh.
        monkeypatch.setattr(eesel, "_get_impersonate_status",
                            lambda c: {"allowed": True, "target_user_id": "auth0|cust"}
                            if c["token"] == "fresh" else None)
        monkeypatch.setattr(eesel, "resolve_effective_workspace_id", lambda c: "cust-ws")
        with pytest.raises(SystemExit) as e:
            eesel._guard_impersonated_command(_ns(write=True), creds)
        assert refreshed["called"] is True
        assert e.value.code == eesel.EXIT_IMPERSONATION_BLOCKED

    def test_write_fails_closed_when_status_unknown(self, monkeypatch, capsys):
        # Probe fails even after any refresh (e.g. real network outage). A tagged
        # write must not slip through unguarded — fail closed with the block code.
        monkeypatch.setattr(eesel, "_get_impersonate_status", lambda c: None)
        with pytest.raises(SystemExit) as e:
            eesel._guard_impersonated_command(_ns(write=True), self._creds())
        assert e.value.code == eesel.EXIT_IMPERSONATION_BLOCKED
        assert "couldn't confirm impersonation state" in capsys.readouterr().err

    def test_read_falls_through_when_status_unknown(self, monkeypatch):
        # A read on an unconfirmable staff login acts as the caller — it can't
        # change a customer, so there's no reason to block it.
        monkeypatch.setattr(eesel, "_get_impersonate_status", lambda c: None)
        monkeypatch.setattr(eesel, "_impersonation_target", None, raising=False)
        eesel._guard_impersonated_command(_ns(write=False), self._creds())
        assert eesel._impersonation_target is None


class TestImpersonationWriteBlockEndToEnd:
    """main() refuses an impersonated write before any API call."""

    def _save_staff(self):
        eesel.save_creds({
            "env": "prod", "api_url": "https://api.example", "workspace_id": "own-ws",
            "token": "tok", "refresh_token": "rt", "is_impersonator": True,
            "expires_at": int(time.time()) + 3600,
        })

    def test_write_refused_before_any_api_call(self, tmp_config, monkeypatch, capsys):
        self._save_staff()
        monkeypatch.setattr(eesel, "_get_impersonate_status",
                            lambda c: {"allowed": True, "target_user_id": "auth0|cust"})
        monkeypatch.setattr(eesel, "resolve_effective_workspace_id", lambda c: "cust-ws")

        def no_api(*a, **k):
            raise AssertionError("a write command must not reach any HTTP call while impersonating")

        monkeypatch.setattr(eesel, "http_request", no_api)
        monkeypatch.setattr(eesel, "http_request_allow_error", no_api)

        with pytest.raises(SystemExit) as e:
            eesel.main(["agents", "create", "--name", "x"])
        assert e.value.code == eesel.EXIT_IMPERSONATION_BLOCKED
        cap = capsys.readouterr()
        assert "Refused" in cap.err
        assert cap.out == ""  # no partial output on stdout

    def test_expired_staff_token_write_still_refused(self, tmp_config, monkeypatch, capsys):
        # The bypass case: staff creds cached with an expired token and a live
        # server-side target. main() must refuse the write with exit 3 — the
        # refresh happens up front so the guard sees the target, rather than the
        # probe 401ing and the refreshed write reaching the customer.
        eesel.save_creds({
            "env": "prod", "api_url": "https://api.example", "workspace_id": "own-ws",
            "token": "stale", "refresh_token": "rt", "is_impersonator": True,
            "expires_at": int(time.time()) - 1,  # already expired
        })

        def fake_refresh(c):
            c["token"] = "fresh"
            c["expires_at"] = int(time.time()) + 3600
            eesel.save_creds(c)
            return c

        monkeypatch.setattr(eesel, "refresh_prod_token", fake_refresh)
        monkeypatch.setattr(eesel, "_get_impersonate_status",
                            lambda c: {"allowed": True, "target_user_id": "auth0|cust"}
                            if c["token"] == "fresh" else None)
        monkeypatch.setattr(eesel, "resolve_effective_workspace_id", lambda c: "cust-ws")

        def no_api(*a, **k):
            raise AssertionError("a write must not reach any HTTP call once the token refreshes")

        monkeypatch.setattr(eesel, "http_request", no_api)
        monkeypatch.setattr(eesel, "http_request_allow_error", no_api)

        with pytest.raises(SystemExit) as e:
            eesel.main(["agents", "create", "--name", "should-be-blocked"])
        assert e.value.code == eesel.EXIT_IMPERSONATION_BLOCKED
        assert capsys.readouterr().out == ""

    def test_read_runs_in_the_targets_workspace(self, tmp_config, monkeypatch):
        # End to end: while impersonating, a read command runs in the TARGET's
        # workspace — the guard resolves it once and require_creds reuses it.
        self._save_staff()
        monkeypatch.setattr(eesel, "_get_impersonate_status",
                            lambda c: {"allowed": True, "target_user_id": "auth0|cust"})
        monkeypatch.setattr(eesel, "resolve_effective_workspace_id", lambda c: "cust-ws")
        seen = {}
        monkeypatch.setattr(eesel, "fetch_agents",
                            lambda creds: seen.setdefault("ws", creds["workspace_id"]) and [] or [])
        eesel.main(["agents", "list"])
        assert seen["ws"] == "cust-ws"  # ran against the target, not "own-ws"


class TestEffectiveWorkspaceZeroCost:
    """A non-impersonating login makes no workspace-resolution call and keeps
    its stored (login) workspace — the "zero cost for normal customers" contract."""

    def test_normal_login_makes_no_resolution_call(self, tmp_config, monkeypatch):
        eesel.save_creds({
            "env": "prod", "api_url": "https://api.example", "workspace_id": "login-ws",
            "token": "tok", "refresh_token": "rt",  # a normal prod login (not staff)
            "expires_at": int(time.time()) + 3600,
        })

        def boom(*a, **k):
            raise AssertionError("a normal login must not resolve the workspace")

        # Neither the impersonation-status probe nor the workspace mint may fire.
        monkeypatch.setattr(eesel, "_get_impersonate_status", boom)
        monkeypatch.setattr(eesel, "resolve_effective_workspace_id", boom)
        seen = {}
        monkeypatch.setattr(eesel, "fetch_agents",
                            lambda creds: seen.setdefault("ws", creds["workspace_id"]) and [] or [])
        eesel.main(["agents", "list"])
        assert seen["ws"] == "login-ws"  # stored login workspace, unchanged


def _http_error(code=401, body=b'{"message":"no editor access"}'):
    import io
    return eesel.urllib.error.HTTPError("https://api.example/x", code, "Unauthorized", {}, io.BytesIO(body))


class TestSelfHealWorkspace401:
    """A 401 on a request carrying the stored workspace_id re-resolves the
    effective workspace, persists it, and retries once — for prod logins only,
    without looping."""

    def _creds(self, **extra):
        c = {"api_url": "https://api.example", "token": "tok", "refresh_token": "rt", "workspace_id": "STALE-WS"}
        c.update(extra)
        return c

    def _arm(self, monkeypatch, fresh="FRESH-WS", creds=None):
        eesel.save_creds(creds or self._creds())
        monkeypatch.setattr(eesel, "_current_creds", creds or eesel.load_creds())
        monkeypatch.setattr(eesel, "resolve_effective_workspace_id", lambda c: fresh)

    def test_read_heals_url_and_retries(self, tmp_config, monkeypatch):
        self._arm(monkeypatch)
        seen = []

        def fake_send(method, url, *, token, body, timeout, headers):
            seen.append(url)
            if len(seen) == 1:
                raise _http_error(401)
            return {"ok": True}

        monkeypatch.setattr(eesel, "_http_send", fake_send)
        out = eesel.http_request("GET", "https://api.example/agents?workspace_id=STALE-WS", token="tok")
        assert out == {"ok": True}
        assert len(seen) == 2
        assert "FRESH-WS" in seen[1] and "STALE-WS" not in seen[1]
        assert eesel.load_creds()["workspace_id"] == "FRESH-WS"  # correction persisted

    def test_write_heals_workspace_in_body(self, tmp_config, monkeypatch):
        self._arm(monkeypatch)
        bodies = []

        def fake_send(method, url, *, token, body, timeout, headers):
            bodies.append(body)
            if len(bodies) == 1:
                raise _http_error(401)
            return {"ok": True}

        monkeypatch.setattr(eesel, "_http_send", fake_send)
        eesel.http_request("POST", "https://api.example/agents", token="tok",
                           body={"workspace_id": "STALE-WS", "name": "x"})
        assert bodies[1] == {"workspace_id": "FRESH-WS", "name": "x"}  # id swapped, rest intact

    def test_401_without_workspace_in_request_fails_fast(self, tmp_config, monkeypatch):
        self._arm(monkeypatch)

        def boom(c):
            raise AssertionError("must not re-resolve when the workspace wasn't in the request")

        monkeypatch.setattr(eesel, "resolve_effective_workspace_id", boom)
        n = [0]

        def fake_send(*a, **k):
            n[0] += 1
            raise _http_error(401)

        monkeypatch.setattr(eesel, "_http_send", fake_send)
        with pytest.raises(SystemExit):
            eesel.http_request("GET", "https://api.example/agents", token="tok")  # no workspace id
        assert n[0] == 1  # one attempt, no retry

    def test_non_prod_login_does_not_self_heal(self, tmp_config, monkeypatch):
        # No refresh token → not a prod login → self-heal never runs.
        monkeypatch.setattr(eesel, "_current_creds",
                            {"api_url": "https://api.example", "token": "t", "workspace_id": "STALE-WS"})

        def boom(c):
            raise AssertionError("must not re-resolve for a non-prod login")

        monkeypatch.setattr(eesel, "resolve_effective_workspace_id", boom)
        n = [0]

        def fake_send(*a, **k):
            n[0] += 1
            raise _http_error(401)

        monkeypatch.setattr(eesel, "_http_send", fake_send)
        with pytest.raises(SystemExit):
            eesel.http_request("GET", "https://api.example/agents?workspace_id=STALE-WS", token="t")
        assert n[0] == 1

    def test_resolve_returns_same_workspace_no_retry(self, tmp_config, monkeypatch):
        self._arm(monkeypatch, fresh="STALE-WS")  # re-resolve gives the same id → nothing to heal
        n = [0]

        def fake_send(*a, **k):
            n[0] += 1
            raise _http_error(401)

        monkeypatch.setattr(eesel, "_http_send", fake_send)
        with pytest.raises(SystemExit):
            eesel.http_request("GET", "https://api.example/agents?workspace_id=STALE-WS", token="tok")
        assert n[0] == 1

    def test_retry_that_also_401s_does_not_loop(self, tmp_config, monkeypatch):
        self._arm(monkeypatch)
        n = [0]

        def fake_send(*a, **k):
            n[0] += 1
            raise _http_error(401)  # even the retry fails

        monkeypatch.setattr(eesel, "_http_send", fake_send)
        with pytest.raises(SystemExit):
            eesel.http_request("GET", "https://api.example/agents?workspace_id=STALE-WS", token="tok")
        assert n[0] == 2  # original + exactly one retry, then stop

    def test_in_memory_agent_id_is_not_persisted_by_the_heal(self, tmp_config, monkeypatch):
        eesel.save_creds(self._creds())          # disk has no agent_id
        cur = eesel.load_creds()
        cur["agent_id"] = "in-memory-agent"      # set only in memory, like --agent/EESEL_AGENT
        monkeypatch.setattr(eesel, "_current_creds", cur)
        monkeypatch.setattr(eesel, "resolve_effective_workspace_id", lambda c: "FRESH-WS")
        seq = [_http_error(401)]

        def fake_send(method, url, *, token, body, timeout, headers):
            if seq:
                raise seq.pop()
            return {"ok": True}

        monkeypatch.setattr(eesel, "_http_send", fake_send)
        eesel.http_request("GET", "https://api.example/agents?workspace_id=STALE-WS", token="tok")
        disk = eesel.load_creds()
        assert disk["workspace_id"] == "FRESH-WS"
        assert "agent_id" not in disk  # the heal must not leak the in-memory agent onto disk

    def test_workspace_id_as_substring_is_not_matched(self, tmp_config, monkeypatch):
        # The stale id appears only as a prefix of a larger opaque id, not as a
        # whole URL segment — self-heal must not fire (no spurious resolve/retry).
        self._arm(monkeypatch)

        def boom(c):
            raise AssertionError("must not re-resolve on a substring-only match")

        monkeypatch.setattr(eesel, "resolve_effective_workspace_id", boom)
        n = [0]

        def fake_send(*a, **k):
            n[0] += 1
            raise _http_error(401)

        monkeypatch.setattr(eesel, "_http_send", fake_send)
        with pytest.raises(SystemExit):
            eesel.http_request("GET", "https://api.example/agents/STALE-WS-EXTRA/tools", token="tok")
        assert n[0] == 1  # substring didn't count as the workspace → no retry

    def test_workspace_id_as_path_segment_is_matched(self, tmp_config, monkeypatch):
        self._arm(monkeypatch)
        seen = []

        def fake_send(method, url, *, token, body, timeout, headers):
            seen.append(url)
            if len(seen) == 1:
                raise _http_error(401)
            return {"ok": True}

        monkeypatch.setattr(eesel, "_http_send", fake_send)
        eesel.http_request("GET", "https://api.example/workspaces/STALE-WS/mcp-servers", token="tok")
        assert seen[1] == "https://api.example/workspaces/FRESH-WS/mcp-servers"  # segment healed

    def test_end_to_end_create_after_clear_self_heals(self, tmp_config, monkeypatch):
        # The reported case: not impersonating, a stale stored workspace, so the
        # operator's own `agents create` 401s — then self-heals and succeeds.
        # _current_creds is set by the real require_creds (not stubbed).
        eesel.save_creds({
            "env": "prod", "api_url": "https://api.example", "workspace_id": "STALE-WS",
            "token": "tok", "refresh_token": "rt", "expires_at": int(time.time()) + 3600,
        })
        monkeypatch.setattr(eesel, "resolve_effective_workspace_id", lambda c: "OWN-WS")
        sends = []

        def fake_send(method, url, *, token, body, timeout, headers):
            sends.append((url, body))
            if len(sends) == 1:
                raise _http_error(401)  # server rejects the stale workspace
            return {"agent_id": "a1"}

        monkeypatch.setattr(eesel, "_http_send", fake_send)
        rc = eesel.main(["agents", "create", "--name", "x"])
        assert rc == 0
        assert len(sends) == 2
        assert sends[1][1]["workspace_id"] == "OWN-WS"       # retried with the real workspace
        assert eesel.load_creds()["workspace_id"] == "OWN-WS"  # and it's persisted


class TestSubcommandSuggestions:
    def test_top_level_typo_suggests_nearest(self, capsys):
        with pytest.raises(SystemExit):
            eesel.build_parser().parse_args(["agentss"])
        assert "Did you mean 'agents'?" in capsys.readouterr().err

    def test_nested_typo_suggests_nearest(self, capsys):
        # Suggestions are installed at every level, not just one noun.
        with pytest.raises(SystemExit):
            eesel.build_parser().parse_args(["sessions", "lst"])
        assert "Did you mean 'list'?" in capsys.readouterr().err

    def test_no_close_match_lists_choices(self, capsys):
        with pytest.raises(SystemExit):
            eesel.build_parser().parse_args(["zzzzzz"])
        assert "Choose from:" in capsys.readouterr().err

    def test_valid_subcommand_unaffected(self):
        # The error override must not interfere with successful parses.
        args = eesel.build_parser().parse_args(["sessions", "list"])
        assert args.sessions_cmd == "list"

    def test_top_level_triggers_is_no_longer_a_choice(self, capsys):
        # `triggers` moved under `automations`; the old top-level spelling
        # should fail with the relocation hint, not a generic choice list.
        with pytest.raises(SystemExit):
            eesel.build_parser().parse_args(["triggers", "fire", "abc123"])
        err = capsys.readouterr().err
        assert "automations schedules" in err

    def test_relocated_name_skips_generic_did_you_mean(self, capsys):
        with pytest.raises(SystemExit):
            eesel.build_parser().parse_args(["triggers", "fire", "abc123"])
        err = capsys.readouterr().err
        assert "automations schedules" in err
        assert "Did you mean" not in err

    def test_documents_relocation_points_to_files(self, capsys):
        with pytest.raises(SystemExit):
            eesel.build_parser().parse_args(["documents", "list"])
        err = capsys.readouterr().err
        assert "renamed to `files`" in err
        assert "eesel files" in err
        assert "Did you mean" not in err

    def test_schedules_relocation_points_to_automations_schedules(self, capsys):
        with pytest.raises(SystemExit):
            eesel.build_parser().parse_args(["schedules", "list"])
        err = capsys.readouterr().err
        assert "automations schedules" in err
        assert "Did you mean" not in err

    def test_triggers_typo_still_suggests_nearest(self, capsys):
        # Typos under the `automations triggers` namespace keep the generic
        # nearest-verb suggestion.
        with pytest.raises(SystemExit):
            eesel.build_parser().parse_args(["automations", "triggers", "lst"])
        assert "Did you mean 'list'?" in capsys.readouterr().err


class TestTriggersAllRemoved:
    def test_all_flag_is_not_accepted(self):
        # `triggers --all` was removed (listing-all is now the default for
        # `automations triggers list`). The flag no longer exists on the parser,
        # so passing it is rejected.
        with pytest.raises(SystemExit):
            eesel.build_parser().parse_args(["automations", "triggers", "--all"])

    def test_all_flag_absent_from_help(self):
        # The flag is gone from the parser and must not appear in help text.
        triggers = _subparsers_action(
            _subparsers_action(eesel.build_parser()).choices["automations"]
        ).choices["triggers"]
        assert "--all" not in triggers.format_help()


class TestChatConnectionFailure:
    """A server that isn't reachable at all (connection refused / DNS / timeout)
    must fail honestly — a clean "server reachable?" error envelope (status
    "error", the reason in `error`) and no raw connection-error traceback — so
    `eesel chat --json` always emits one parseable object on any failure."""

    def _sess(self):
        return {
            "id": "s1",
            "agent_id": "agent-test-456",
            "workspace_id": "ws-test-123",
            "task_id": "t1",
            "messages": [],
        }

    def test_sandbox_start_unreachable_gives_error_envelope(self, fake_creds, monkeypatch):
        def boom(req, timeout=None):
            raise eesel.urllib.error.URLError("connection refused")

        monkeypatch.setattr(eesel.urllib.request, "urlopen", boom)
        env = eesel.send_message(fake_creds, self._sess(), "hello")
        assert env["status"] == "error"
        assert "server reachable?" in env["error"]

    def test_stream_unreachable_flags_error(self, fake_creds, monkeypatch):
        def boom(req, timeout=None):
            raise eesel.urllib.error.URLError("connection refused")

        monkeypatch.setattr(eesel.urllib.request, "urlopen", boom)
        result = eesel.stream_reply(fake_creds, "task1", None)
        assert result["error"] is True
        assert "server reachable?" in result["error_text"]

    class _StreamResp:
        def __init__(self, exc):
            self.exc = exc

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def __iter__(self):
            raise self.exc

    def test_stream_connection_reset_flags_error(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(
            eesel.urllib.request,
            "urlopen",
            lambda *a, **k: self._StreamResp(ConnectionResetError("reset")),
        )
        result = eesel.stream_reply(fake_creds, "task1", None)
        assert result["error"] is True
        assert result["text"] == "" and result["tool_calls"] == []
        assert "chat stream dropped mid-reply" in capsys.readouterr().err

    def test_stream_incomplete_read_flags_error(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(
            eesel.urllib.request,
            "urlopen",
            lambda *a, **k: self._StreamResp(http.client.IncompleteRead(b"partial")),
        )
        result = eesel.stream_reply(fake_creds, "task1", None)
        assert result["error"] is True
        assert "chat stream dropped mid-reply" in capsys.readouterr().err

    def test_stream_tls_teardown_flags_error(self, fake_creds, monkeypatch, capsys):
        # An encrypted connection torn down mid-reply raises ssl.SSLEOFError,
        # which is an OSError but neither a ConnectionError nor a URLError. It is
        # the common abrupt drop on the HTTPS prod transport and must fail the
        # turn cleanly, not escape as a traceback.
        monkeypatch.setattr(
            eesel.urllib.request,
            "urlopen",
            lambda *a, **k: self._StreamResp(ssl.SSLEOFError("EOF in violation of protocol")),
        )
        result = eesel.stream_reply(fake_creds, "task1", None)
        assert result["error"] is True
        assert "chat stream dropped mid-reply" in capsys.readouterr().err

    def test_stream_generic_ssl_error_flags_error(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(
            eesel.urllib.request,
            "urlopen",
            lambda *a, **k: self._StreamResp(ssl.SSLError("decryption failed")),
        )
        result = eesel.stream_reply(fake_creds, "task1", None)
        assert result["error"] is True
        assert "chat stream dropped mid-reply" in capsys.readouterr().err


class TestArgParser:
    def test_parser_builds(self):
        # Smoke test: argparse construction shouldn't blow up.
        parser = eesel.build_parser()
        assert parser is not None

    def test_no_args_exits(self):
        # `eesel` with no args should trigger argparse's required-subcommand error.
        with pytest.raises(SystemExit):
            eesel.main([])

    def test_login_dev_subcommand_parses(self):
        # Just verify the parser accepts the flag without raising; we can't fully
        # exercise it without docker/postgres.
        parser = eesel.build_parser()
        args = parser.parse_args(["login", "--dev"])
        assert args.cmd == "login"
        assert args.dev is True

    def test_login_dev_workspace_id_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["login", "--dev", "--workspace-id", "ws-123"])
        assert args.cmd == "login"
        assert args.dev is True
        assert args.workspace_id == "ws-123"

    def test_chat_message_subcommand_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["chat", "hello world"])
        assert args.cmd == "chat"
        assert args.message == "hello world"

    def test_sessions_use_requires_id(self):
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["sessions", "use"])  # missing positional

    def test_agents_use_is_no_longer_a_subcommand(self):
        # The stored active-agent concept was removed; `use`/`unset` are gone.
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["agents", "use", "my-agent"])

    def test_tasks_analytics_parses_dates_and_agent(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["tasks", "analytics", "--agent", "Bot", "--start-date", "2026-05-01", "--end-date", "2026-05-31"])
        assert args.cmd == "tasks"
        assert args.tasks_cmd == "analytics"
        assert args.agent == "Bot"
        assert args.start_date == "2026-05-01"
        assert args.end_date == "2026-05-31"
        assert args.func is eesel.cmd_tasks

    def test_tasks_export_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["tasks", "export", "--agent", "Bot", "--start-date", "2026-05-01"])
        assert args.cmd == "tasks"
        assert args.tasks_cmd == "export"
        assert args.agent == "Bot"
        assert args.start_date == "2026-05-01"
        assert args.func is eesel.cmd_tasks

    def test_tasks_read_commands_accept_json(self):
        # Every read command must expose --json for scripts and agent self-QA.
        parser = eesel.build_parser()
        for sub in ("list", "count", "analytics", "show", "cost"):
            argv = ["tasks", sub]
            if sub in ("show", "cost"):
                argv.append("284a6a43-afa7-43f3-88e6-25d1a92cf7d7")
            argv.append("--json")
            args = parser.parse_args(argv)
            assert args.json is True, sub

    def test_tasks_unknown_subcommand_suggests_closest(self, capsys):
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["tasks", "lst"])
        assert "Did you mean 'list'?" in capsys.readouterr().err

    def test_instructions_subcommand_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["instructions"])
        assert args.func is eesel.cmd_instructions
        assert args.agent is None

    def test_instructions_subcommand_parses_agent(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["instructions", "Support Bot"])
        assert args.func is eesel.cmd_instructions
        assert args.agent == "Support Bot"

    def test_singular_instruction_is_not_a_command(self):
        # We standardized on the plural; the singular should not parse.
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["instruction"])

    def test_chat_cost_flag_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["chat", "--cost", "hi there"])
        assert args.cmd == "chat"
        assert args.cost is True
        assert args.message == "hi there"

    def test_chat_without_cost_flag_defaults_false(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["chat", "hi"])
        assert args.cost is False

    def test_triggers_registry_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["automations", "triggers", "registry"])
        assert args.cmd == "automations"
        assert args.triggers_cmd == "registry"
        assert args.func is eesel.cmd_triggers

    def test_triggers_add_parses_key_and_config(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["automations", "triggers", "add", "Support Bot", "--key", "zendesk_ticket_created", "--config", "{}"])
        assert args.triggers_cmd == "add"
        assert args.agent == "Support Bot"
        assert args.key == "zendesk_ticket_created"
        assert args.config == "{}"

    def test_triggers_add_requires_key(self):
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["automations", "triggers", "add", "Support Bot"])  # missing --key

    def test_triggers_show_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["automations", "triggers", "show", "trg-1"])
        assert args.triggers_cmd == "show"
        assert args.trigger_id == "trg-1"
        assert args.func is eesel.cmd_triggers

    def test_triggers_remove_parses_force_flag(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["automations", "triggers", "remove", "trg-1", "--force"])
        assert args.triggers_cmd == "remove"
        assert args.trigger_id == "trg-1"
        assert args.force is True

    def test_top_level_triggers_and_schedules_are_removed(self):
        # `triggers` and `schedules` now live under the `automations` parent;
        # the old top-level spellings are no longer valid choices.
        parser = eesel.build_parser()
        for argv in (["triggers", "registry"], ["schedules", "list"]):
            with pytest.raises(SystemExit):
                parser.parse_args(argv)

    def test_bare_automations_reports_sub_namespace_error(self, capsys):
        # `eesel automations` with no sub-namespace routes to cmd_automations,
        # which names the available sub-namespaces and returns 2.
        parser = eesel.build_parser()
        args = parser.parse_args(["automations"])
        assert args.cmd == "automations"
        assert args.func is eesel.cmd_automations
        rc = args.func(args)
        assert rc == 2
        err = capsys.readouterr().err
        assert "triggers" in err and "schedules" in err

    def test_triggers_removed_verbs_no_longer_parse(self):
        # The REST-derived verbs (`create`/`delete`) were renamed to the canonical
        # set and must not parse. `fire`/`run` previously lingered as triggers
        # aliases that no longer dispatched; manually firing a scheduled job now
        # lives solely under `eesel automations schedules fire`, so they must not
        # parse here.
        parser = eesel.build_parser()
        for argv in (
            ["automations", "triggers", "create", "Support Bot", "--key", "k"],
            ["automations", "triggers", "delete", "trg-1"],
            ["automations", "triggers", "fire", "heartbeat"],
            ["automations", "triggers", "run", "heartbeat"],
        ):
            with pytest.raises(SystemExit):
                parser.parse_args(argv)

    def test_schedules_list_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["automations", "schedules", "list"])
        assert args.cmd == "automations"
        assert args.schedules_cmd == "list"
        assert args.func is eesel.cmd_schedules

    def test_schedules_add_parses_cron_and_flags(self):
        parser = eesel.build_parser()
        args = parser.parse_args([
            "automations", "schedules", "add", "Support Bot",
            "--cron", "0 9 * * *", "--prompt", "Send the morning digest",
            "--title", "Morning digest", "--timezone", "Europe/London",
        ])
        assert args.schedules_cmd == "add"
        assert args.agent == "Support Bot"
        assert args.cron == "0 9 * * *"
        assert args.prompt == "Send the morning digest"
        assert args.title == "Morning digest"
        assert args.timezone == "Europe/London"

    def test_schedules_add_requires_cron(self):
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            # missing --cron (--prompt also required, but --cron alone is enough to reject)
            parser.parse_args(["automations", "schedules", "add", "Support Bot", "--prompt", "x"])

    def test_schedules_add_requires_prompt(self):
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            # The server rejects scheduled triggers without a prompt, so the CLI
            # makes it a required flag and fails before sending the request.
            parser.parse_args(["automations", "schedules", "add", "Support Bot", "--cron", "0 9 * * *"])

    def test_schedules_remove_parses_force_flag(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["automations", "schedules", "remove", "sch-1", "-f"])
        assert args.schedules_cmd == "remove"
        assert args.job == "sch-1"
        assert args.force is True

    def test_schedules_fire_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["automations", "schedules", "fire", "heartbeat"])
        assert args.schedules_cmd == "fire"
        assert args.job == "heartbeat"

    def test_new_schedule_flag_and_trigger_alias(self):
        # `--trigger` is the old name; both map to the same `schedule` dest.
        parser = eesel.build_parser()
        assert parser.parse_args(["new", "--schedule", "heartbeat"]).schedule == "heartbeat"
        assert parser.parse_args(["new", "--trigger", "heartbeat"]).schedule == "heartbeat"


class TestConfirm:
    def test_yes_variants_return_true(self, monkeypatch):
        for answer in ("y", "yes", "Y", "YES", " yes "):
            monkeypatch.setattr("builtins.input", lambda _="", a=answer: a)
            assert eesel.confirm("ok? ") is True

    def test_no_and_empty_return_false(self, monkeypatch):
        for answer in ("", "n", "no", "nope"):
            monkeypatch.setattr("builtins.input", lambda _="", a=answer: a)
            assert eesel.confirm("ok? ") is False

    def test_eof_returns_false(self, monkeypatch):
        def boom(_=""):
            raise EOFError

        monkeypatch.setattr("builtins.input", boom)
        assert eesel.confirm("ok? ") is False

    def test_cost_subcommand_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["cost"])
        assert args.cmd == "cost"
        assert args.session_id is None

    def test_cost_subcommand_with_session(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["cost", "abc12345"])
        assert args.session_id == "abc12345"

    def test_files_list_subcommand_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["files", "list", "--prefix", "outputs/skills", "--search", "post", "--limit", "25"])
        assert args.cmd == "files"
        assert args.file_cmd == "list"
        assert args.prefix == "outputs/skills"
        assert args.search == "post"
        assert args.limit == 25

    def test_files_subcommands_accept_agent_flag(self):
        parser = eesel.build_parser()
        for argv in (
            ["files", "list", "--agent", "Bot"],
            ["files", "show", "doc-1", "--agent", "Bot"],
            ["files", "add", "--title", "T", "--content", "x", "--agent", "Bot"],
        ):
            args = parser.parse_args(argv)
            assert args.agent == "Bot"

    def test_files_export_subcommand_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["files", "export", "--file-id", "doc-123", "--format", "html"])
        assert args.cmd == "files"
        assert args.file_cmd == "export"
        assert args.document_id == "doc-123"
        assert args.format == "html"

    def test_files_defaults_to_list(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["files"])
        assert args.cmd == "files"
        assert args.file_cmd == "list"
        assert args.limit == 100

    def test_files_read_subcommand_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["files", "read", "doc-123", "--prefix", "files/", "--format", "html"])
        assert args.file_cmd == "read"
        assert args.target == "doc-123"
        assert args.prefix == "files/"
        assert args.format == "html"

    def test_files_read_no_target_defaults(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["files", "read"])
        assert args.file_cmd == "read"
        assert args.target is None
        assert args.prefix is None
        assert args.format == "md"

    def test_top_level_export_removed(self):
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["export", "--file-id", "doc-123"])

    def test_plural_documents_is_removed(self):
        # `files` is the canonical noun; plural `documents` no longer exists.
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["documents", "list"])

    def test_singular_document_still_parses_as_alias(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["document", "list"])
        assert args.cmd == "document"
        assert args.file_cmd == "list"
        assert args.func is eesel.cmd_files

    def test_singular_document_hidden_from_help(self):
        # The alias parses but is dropped from the top-level command listing.
        help_text = eesel.build_parser().format_help()
        assert "files" in help_text
        assert "\n    document " not in help_text

    def test_show_is_documented_synonym_of_read(self):
        parser = eesel.build_parser()
        show_args = parser.parse_args(["files", "show", "doc-1", "--format", "html"])
        read_args = parser.parse_args(["files", "read", "doc-1", "--format", "html"])
        assert show_args.file_cmd == "show"
        assert read_args.file_cmd == "read"
        # Both route to the same handler, which treats show/read identically.
        assert show_args.func is eesel.cmd_files and read_args.func is eesel.cmd_files

    def test_read_hidden_from_files_help(self):
        # `read` stays parseable but is not advertised under `files --help`.
        files_action = next(
            a for a in eesel.build_parser()._subparsers._group_actions[0].choices.values()
            if a.prog.endswith("files")
        )
        sub_help = files_action.format_help()
        assert "show " in sub_help
        assert "read" not in sub_help.split("optional arguments")[0].replace("==SUPPRESS==", "")

    def test_files_list_accepts_json(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["files", "list", "--search", "post", "--json"])
        assert args.file_cmd == "list"
        assert args.search == "post"
        assert args.json is True

    def test_files_add_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["files", "add", "--title", "T", "--content", "C"])
        assert args.file_cmd == "add"
        assert args.title == "T"
        assert args.content == "C"
        assert args.source_type == "files"

    def test_files_add_requires_content(self):
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["files", "add", "--title", "T"])

    def test_files_add_rejects_both_content_sources(self):
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["files", "add", "--title", "T", "--content", "C", "--content-file", "f"])

    def test_files_search_is_a_list_flag_not_a_verb(self):
        # A free-text query folds into `list --search`; there is no `search` verb.
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["files", "search", "files/abc"])

    def test_files_remove_parses_multiple_keys_and_force(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["files", "remove", "k1", "k2", "-f"])
        assert args.file_cmd == "remove"
        assert args.keys == ["k1", "k2"]
        assert args.force is True

    def test_files_acl_show_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["files", "acl", "show", "Support Bot"])
        assert args.file_cmd == "acl"
        assert args.acl_cmd == "show"
        assert args.agent == "Support Bot"

    def test_files_acl_set_parses_repeatable_prefix(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["files", "acl", "set", "agent-1", "--prefix", "a/", "--prefix", "b/"])
        assert args.acl_cmd == "set"
        assert args.agent == "agent-1"
        assert args.prefix == ["a/", "b/"]

    def test_files_acl_set_requires_prefix(self):
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["files", "acl", "set", "agent-1"])


# ──────────────────────────────────────────────────────────────────────────
# Cost tracking
# ──────────────────────────────────────────────────────────────────────────


class TestCostParsing:
    def test_parse_empty(self):
        d = eesel.parse_cost_rows("")
        assert d["total_cost"] == 0
        assert d["total_runs"] == 0
        assert d["by_task"] == []

    def test_parse_single_root(self):
        # task_id|parent|name|cost|in|out|cache_read|cache_write|runs
        raw = "abc-123||My Task|0.1234|10000|500|2000|1000|3"
        d = eesel.parse_cost_rows(raw)
        assert d["total_runs"] == 3
        assert abs(d["total_cost"] - 0.1234) < 1e-9
        assert d["totals"]["input_tokens"] == 10000
        assert d["totals"]["output_tokens"] == 500
        assert d["totals"]["cache_read_tokens"] == 2000
        assert d["totals"]["cache_write_tokens"] == 1000
        assert len(d["by_task"]) == 1
        row = d["by_task"][0]
        assert row["task_id"] == "abc-123"
        assert row["parent_task_id"] is None
        assert row["name"] == "My Task"
        assert row["runs"] == 3

    def test_parse_root_plus_subtasks(self):
        raw = "\n".join(
            [
                "root-1||Root|0.10|1000|100|0|0|2",
                "sub-1|root-1|Triage|0.05|500|50|0|0|1",
                "sub-2|root-1|Research|0.08|800|80|0|0|1",
            ]
        )
        d = eesel.parse_cost_rows(raw)
        assert d["total_runs"] == 4
        assert abs(d["total_cost"] - 0.23) < 1e-9
        assert d["totals"]["input_tokens"] == 2300
        assert d["totals"]["output_tokens"] == 230
        assert len(d["by_task"]) == 3
        assert d["by_task"][0]["parent_task_id"] is None
        assert d["by_task"][1]["parent_task_id"] == "root-1"
        assert d["by_task"][2]["parent_task_id"] == "root-1"

    def test_parse_skips_malformed_rows(self):
        raw = "\n".join(
            [
                "root-1||Root|0.10|1000|100|0|0|2",
                "this is not a valid row",
                "",
                "sub-1|root-1||0.05|500|50|0|0|1",
            ]
        )
        d = eesel.parse_cost_rows(raw)
        assert len(d["by_task"]) == 2
        assert d["total_runs"] == 3

    def test_parse_zero_runs(self):
        # Task exists in tree but has no metric rows yet.
        raw = "abc-123|||0|0|0|0|0|0"
        d = eesel.parse_cost_rows(raw)
        assert d["total_runs"] == 0
        assert d["total_cost"] == 0
        assert len(d["by_task"]) == 1


class TestCostFormatting:
    def test_fmt_tokens(self):
        assert eesel._fmt_tokens(0) == "0"
        assert eesel._fmt_tokens(123) == "123"
        assert eesel._fmt_tokens(9999) == "9,999"
        assert eesel._fmt_tokens(12_345) == "12.3k"
        assert eesel._fmt_tokens(584_145) == "584.1k"
        assert eesel._fmt_tokens(2_500_000) == "2.50M"

    def test_fmt_cost_4_decimals(self):
        # Always 4 decimal places — small chats should not round to $0.00.
        assert eesel._fmt_cost(0) == "$0.0000"
        assert eesel._fmt_cost(0.0001) == "$0.0001"
        assert eesel._fmt_cost(1.5) == "$1.5000"

    def test_oneline_no_data(self):
        d = {"total_cost": 0, "total_runs": 0, "totals": {}, "by_task": []}
        out = eesel.format_cost_oneline(d)
        assert "no cost data" in out

    def test_oneline_single_task(self):
        d = {
            "total_cost": 0.373,
            "total_runs": 5,
            "totals": {"input_tokens": 584145, "output_tokens": 4822, "cache_read_tokens": 0, "cache_write_tokens": 0},
            "by_task": [{"task_id": "x", "parent_task_id": None}],
        }
        out = eesel.format_cost_oneline(d)
        assert "$0.3730" in out
        assert "584.1k in" in out
        assert "4,822 out" in out
        assert "5 calls" in out
        # Single task → no "N tasks" suffix
        assert "tasks]" not in out

    def test_oneline_with_subtasks(self):
        d = {
            "total_cost": 0.5,
            "total_runs": 7,
            "totals": {"input_tokens": 1000, "output_tokens": 100, "cache_read_tokens": 0, "cache_write_tokens": 0},
            "by_task": [
                {"task_id": "root", "parent_task_id": None},
                {"task_id": "sub", "parent_task_id": "root"},
            ],
        }
        out = eesel.format_cost_oneline(d)
        assert "2 tasks" in out

    def test_oneline_singular_call(self):
        d = {
            "total_cost": 0.01,
            "total_runs": 1,
            "totals": {"input_tokens": 100, "output_tokens": 10, "cache_read_tokens": 0, "cache_write_tokens": 0},
            "by_task": [{"task_id": "x", "parent_task_id": None}],
        }
        out = eesel.format_cost_oneline(d)
        assert "1 call]" in out

    def test_full_includes_breakdown_when_subtasks(self):
        sess = {"id": "abc", "name": "test", "task_id": "root"}
        d = {
            "total_cost": 0.5,
            "total_runs": 4,
            "totals": {"input_tokens": 1000, "output_tokens": 100, "cache_read_tokens": 50, "cache_write_tokens": 25},
            "by_task": [
                {"task_id": "root-id", "parent_task_id": None, "name": "Root task", "cost": 0.3, "runs": 2},
                {"task_id": "sub-id", "parent_task_id": "root-id", "name": "Triage skill", "cost": 0.2, "runs": 2},
            ],
        }
        out = eesel.format_cost_full(d, sess)
        assert "session abc" in out
        assert "$0.5000" in out
        assert "by task (2)" in out
        assert "[root]" in out
        assert "[sub]" in out
        assert "Triage skill" in out

    def test_full_no_data_message(self):
        sess = {"id": "abc", "name": "empty", "task_id": "t"}
        d = {"total_cost": 0, "total_runs": 0, "totals": {}, "by_task": []}
        out = eesel.format_cost_full(d, sess)
        assert "no cost data" in out


class TestFetchSessionCost:
    def test_returns_none_in_prod(self, monkeypatch):
        creds = {"env": "prod"}
        sess = {"task_id": "abc-123"}
        monkeypatch.setattr(eesel, "_run_psql", lambda sql: pytest.fail("psql should not run in prod"))
        assert eesel.fetch_session_cost(creds, sess) is None

    def test_returns_none_when_task_id_not_uuid_shaped(self, monkeypatch):
        # Defence-in-depth against SQL injection via task_id (we interpolate
        # into a template). Anything outside [0-9a-f-] short-circuits to None.
        creds = {"env": "dev"}
        sess = {"task_id": "abc'; DROP TABLE eesel_ai_tasks; --"}
        monkeypatch.setattr(eesel, "_run_psql", lambda sql: pytest.fail("psql should not run for malformed id"))
        assert eesel.fetch_session_cost(creds, sess) is None

    def test_returns_none_on_psql_failure(self, monkeypatch):
        creds = {"env": "dev"}
        sess = {"task_id": "284a6a43-afa7-43f3-88e6-25d1a92cf7d7"}

        def boom(sql):
            raise RuntimeError("docker not running")

        monkeypatch.setattr(eesel, "_run_psql", boom)
        assert eesel.fetch_session_cost(creds, sess) is None

    def test_parses_psql_output_in_dev(self, monkeypatch):
        creds = {"env": "dev"}
        sess = {"task_id": "284a6a43-afa7-43f3-88e6-25d1a92cf7d7"}
        canned = "abc-123||My Task|0.5|10000|500|0|0|3"
        monkeypatch.setattr(eesel, "_run_psql", lambda sql: canned)
        d = eesel.fetch_session_cost(creds, sess)
        assert d is not None
        assert d["total_cost"] == 0.5
        assert d["total_runs"] == 3

    def test_returns_none_when_no_task_id(self, monkeypatch):
        creds = {"env": "dev"}
        sess = {}  # no task_id
        monkeypatch.setattr(eesel, "_run_psql", lambda sql: pytest.fail("psql should not run"))
        assert eesel.fetch_session_cost(creds, sess) is None


# ──────────────────────────────────────────────────────────────────────────
# Subcommand integration (light)
# ──────────────────────────────────────────────────────────────────────────


class TestSubcommands:
    def test_logout_clears_creds(self, tmp_config, fake_creds):
        assert eesel.CREDS_FILE.exists()
        rc = eesel.cmd_logout(None)
        assert rc == 0
        assert not eesel.CREDS_FILE.exists()

    def test_logout_when_already_logged_out(self, tmp_config):
        # Should not raise even if no creds file.
        rc = eesel.cmd_logout(None)
        assert rc == 0

    def test_whoami_when_logged_out(self, tmp_config, capsys):
        rc = eesel.cmd_whoami(None)
        assert rc == 0
        # stderr ends up captured by capsys too via the info() helper
        # (we don't assert specific text, just that it doesn't crash)


# ──────────────────────────────────────────────────────────────────────────
# Tasks — workspace-wide agent activity
# ──────────────────────────────────────────────────────────────────────────


def _args(**kw):
    """Build a throwaway args namespace for cmd_* calls."""
    return type("Args", (), kw)()


def _make_task(task_id, *, agent_name="Support Bot", name="hello", channel="chat", updated_at="2026-05-29T13:40:00+00:00"):
    return {
        "task_id": task_id,
        "agent_id": "agent-test-456",
        "agent_name": agent_name,
        "name": name,
        "updated_at": updated_at,
        "created_at": updated_at,
        "trigger_context": {"channel": channel},
        "external_reference": None,
        "parent_task_id": None,
    }


class TestTasksFetch:
    def test_fetch_tasks_sends_status_grouping_and_desc_sort(self, fake_creds, monkeypatch):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["method"], captured["url"], captured["body"] = method, url, body
            return {"tasks": [_make_task("aaaa1111-0000-0000-0000-000000000000")], "hasNextPage": False, "nextPage": None, "totalCount": 1}

        monkeypatch.setattr(eesel, "http_request", fake)
        rows, has_next, next_page = eesel.fetch_tasks(fake_creds, limit=25, page=2)

        assert captured["method"] == "POST"
        assert captured["url"] == "http://localhost:8080/workspace/tasks"
        assert captured["body"]["grouping"] == "status"
        assert captured["body"]["sorting"] == "updatedDate"
        assert captured["body"]["sort_order"] == 1
        assert captured["body"]["page"] == 2 and captured["body"]["limit"] == 25
        assert "agent" not in captured["body"]["filters"]
        assert len(rows) == 1 and has_next is False and next_page is None

    def test_fetch_tasks_agent_filter_is_a_list(self, fake_creds, monkeypatch):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["body"] = body
            return {"tasks": [], "hasNextPage": False}

        monkeypatch.setattr(eesel, "http_request", fake)
        eesel.fetch_tasks(fake_creds, agent_id="agent-xyz")
        # Server requires TaskFilter.AGENT to be a list, else it's ignored.
        assert captured["body"]["filters"] == {"agent": ["agent-xyz"]}

    def test_fetch_tasks_sorts_desc_by_updated_at(self, fake_creds, monkeypatch):
        rows_in = [
            _make_task("old00000-0000-0000-0000-000000000000", updated_at="2026-05-01T00:00:00+00:00"),
            _make_task("new00000-0000-0000-0000-000000000000", updated_at="2026-05-29T00:00:00+00:00"),
        ]
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"tasks": rows_in})
        rows, _, _ = eesel.fetch_tasks(fake_creds)
        assert [r["task_id"][:3] for r in rows] == ["new", "old"]

    def test_count_tasks_reads_total_count(self, fake_creds, monkeypatch):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["body"] = body
            return {"tasks": [], "totalCount": 142}

        monkeypatch.setattr(eesel, "http_request", fake)
        assert eesel.count_tasks(fake_creds) == 142
        # Count only needs the aggregate, not the rows.
        assert captured["body"]["limit"] == 1

    def test_resolve_task_id_passthrough_for_uuid_without_listing(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: pytest.fail("should not list for a full uuid"))
        full = "284a6a43-afa7-43f3-88e6-25d1a92cf7d7"
        assert eesel.resolve_task_id(fake_creds, full) == full

    def test_resolve_task_id_prefix_match(self, fake_creds, monkeypatch):
        rows = [_make_task("7f3a9c21-0000-0000-0000-000000000000"), _make_task("b8e1d0f4-0000-0000-0000-000000000000")]
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"tasks": rows})
        assert eesel.resolve_task_id(fake_creds, "7f3a") == "7f3a9c21-0000-0000-0000-000000000000"

    def test_resolve_task_id_ambiguous_returns_none(self, fake_creds, monkeypatch, capsys):
        rows = [_make_task("7f3a0000-0000-0000-0000-000000000000"), _make_task("7f3a1111-0000-0000-0000-000000000000")]
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"tasks": rows})
        assert eesel.resolve_task_id(fake_creds, "7f3a") is None
        assert "ambiguous" in capsys.readouterr().err

    def test_resolve_task_id_no_match_returns_none(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"tasks": [_make_task("aaaa0000-0000-0000-0000-000000000000")]})
        assert eesel.resolve_task_id(fake_creds, "zzzz") is None
        assert "No task matches" in capsys.readouterr().err


class TestTasksList:
    def test_list_prints_rows(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(
            eesel,
            "http_request",
            lambda *a, **k: {"tasks": [_make_task("7f3a9c21-1234-0000-0000-000000000000", agent_name="Support Bot", name="Refund for #1024", channel="helpdesk")], "hasNextPage": False},
        )
        rc = eesel.cmd_tasks(_args(tasks_cmd="list", limit=50, page=1, agent=None))
        out = capsys.readouterr().out
        assert rc == 0
        assert "7f3a9c21-123" in out  # task_id truncated to 12 chars
        assert "Support Bot" in out
        assert "helpdesk" in out
        assert "Refund for #1024" in out

    def test_list_paging_footer_when_more(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"tasks": [_make_task("aaaa0000-0000-0000-0000-000000000000")], "hasNextPage": True, "nextPage": 3})
        eesel.cmd_tasks(_args(tasks_cmd="list", limit=50, page=2, agent=None))
        # Footer goes to stderr via info().
        assert "eesel tasks list --page 3" in capsys.readouterr().err

    def test_list_marks_local_sessions_with_star(self, fake_creds, monkeypatch, capsys):
        # Create a local CLI session whose task_id matches one of the rows.
        sess = eesel.new_session(fake_creds, agent_id="agent-test-456", name="mine", switch_to=False)
        local_tid = sess["task_id"]
        monkeypatch.setattr(
            eesel,
            "http_request",
            lambda *a, **k: {"tasks": [_make_task(local_tid), _make_task("ffff0000-0000-0000-0000-000000000000")], "hasNextPage": False},
        )
        eesel.cmd_tasks(_args(tasks_cmd="list", limit=50, page=1, agent=None))
        out = capsys.readouterr().out
        assert f"* {local_tid[:12]}" in out

    def test_list_empty_state(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"tasks": [], "hasNextPage": False})
        rc = eesel.cmd_tasks(_args(tasks_cmd="list", limit=50, page=1, agent=None))
        assert rc == 0
        assert "(no tasks)" in capsys.readouterr().err

    def test_count_command_prints_total(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"tasks": [], "totalCount": 7})
        rc = eesel.cmd_tasks(_args(tasks_cmd="count", agent=None))
        assert rc == 0
        assert "7 tasks" in capsys.readouterr().out

    def test_count_agent_filter_resolves_name(self, fake_creds, monkeypatch, capsys):
        seen = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            if url.endswith("/workspace/tasks"):
                seen["filters"] = body["filters"]
                return {"tasks": [], "totalCount": 3}
            # GET /agents — name resolution
            return [{"agent_id": "agent-test-456", "name": "Support Bot"}]

        monkeypatch.setattr(eesel, "http_request", fake)
        rc = eesel.cmd_tasks(_args(tasks_cmd="count", agent="Support Bot"))
        assert rc == 0
        assert seen["filters"] == {"agent": ["agent-test-456"]}
        assert "for this agent" in capsys.readouterr().out

    def test_list_json_emits_raw_rows(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(
            eesel,
            "http_request",
            lambda *a, **k: {"tasks": [_make_task("7f3a9c21-1234-0000-0000-000000000000")], "hasNextPage": True, "nextPage": 2},
        )
        rc = eesel.cmd_tasks(_args(tasks_cmd="list", limit=50, page=1, agent=None, json=True))
        payload = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert payload["tasks"][0]["task_id"] == "7f3a9c21-1234-0000-0000-000000000000"
        assert payload["has_next"] is True
        assert payload["next_page"] == 2

    def test_list_json_empty_is_valid_json(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"tasks": [], "hasNextPage": False})
        rc = eesel.cmd_tasks(_args(tasks_cmd="list", limit=50, page=1, agent=None, json=True))
        payload = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert payload["tasks"] == []

    def test_list_plain_emits_tab_separated_rows(self, fake_creds, monkeypatch, capsys):
        # `--plain` emits one decoration-free, tab-separated row per task:
        # task_id<TAB>updated<TAB>agent<TAB>source<TAB>label. The full task id is
        # printed, not the 12-char truncation the human view uses, confirming the
        # human formatter was bypassed.
        monkeypatch.setattr(
            eesel,
            "http_request",
            lambda *a, **k: {"tasks": [_make_task("7f3a9c21-1234-0000-0000-000000000000", agent_name="Support Bot", name="Refund for #1024", channel="helpdesk")], "hasNextPage": False},
        )
        rc = eesel.cmd_tasks(_args(tasks_cmd="list", limit=50, page=1, agent=None, plain=True))
        assert rc == 0
        out = capsys.readouterr().out
        row = out.strip().splitlines()[0]
        assert row == "7f3a9c21-1234-0000-0000-000000000000\t2026-05-29 13:40\tSupport Bot\thelpdesk\tRefund for #1024"

    def test_count_json_emits_count(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"tasks": [], "totalCount": 7})
        rc = eesel.cmd_tasks(_args(tasks_cmd="count", agent=None, json=True))
        payload = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert payload["count"] == 7
        assert payload["agent_id"] is None


class TestTasksShow:
    HISTORY = {
        "runs": [
            {
                "run_id": "run-1",
                "items": [
                    {"type": "message", "role": "user", "content": "how do refunds work?"},
                    {"type": "thinking", "content": "checking policy"},
                    {"type": "tool_call", "name": "doc_search", "tool_arguments": {"query": "refund"}},
                    {"type": "tool_result", "name": "doc_search", "tool_output": {"hits": 2}},
                    {"type": "message", "role": "assistant", "content": "Refunds take 5 days."},
                ],
            }
        ]
    }

    def _fake(self, history):
        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            if "/history" in url:
                return history
            # find_task_row's list call
            return {"tasks": [_make_task("284a6a43-afa7-43f3-88e6-25d1a92cf7d7", name="refund chat")], "hasNextPage": False}

        return fake

    def test_show_renders_each_item_type(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", self._fake(self.HISTORY))
        rc = eesel.cmd_tasks(_args(tasks_cmd="show", task_id="284a6a43-afa7-43f3-88e6-25d1a92cf7d7", json=False, full=False, cost=False))
        out = capsys.readouterr().out
        assert rc == 0
        assert "you" in out and "how do refunds work?" in out
        assert "eesel" in out and "Refunds take 5 days." in out
        assert "[tool] doc_search" in out
        assert "[thinking]" in out
        assert "# task 284a6a43-afa7-43f3-88e6-25d1a92cf7d7" in out

    def test_show_json_emits_raw_payload(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", self._fake(self.HISTORY))
        eesel.cmd_tasks(_args(tasks_cmd="show", task_id="284a6a43-afa7-43f3-88e6-25d1a92cf7d7", json=True, full=False, cost=False))
        payload = json.loads(capsys.readouterr().out)
        assert payload["task_id"] == "284a6a43-afa7-43f3-88e6-25d1a92cf7d7"
        assert payload["runs"][0]["items"][0]["content"] == "how do refunds work?"

    def test_show_empty_history(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", self._fake({"runs": []}))
        rc = eesel.cmd_tasks(_args(tasks_cmd="show", task_id="284a6a43-afa7-43f3-88e6-25d1a92cf7d7", json=False, full=False, cost=False))
        assert rc == 0
        assert "(no history)" in capsys.readouterr().err

    def test_show_cost_reuses_session_cost_path(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", self._fake(self.HISTORY))
        # Dev cost path: stub psql to return one root row.
        monkeypatch.setattr(eesel, "_run_psql", lambda sql: "284a6a43-afa7-43f3-88e6-25d1a92cf7d7||refund chat|0.5|10000|500|0|0|3")
        eesel.cmd_tasks(_args(tasks_cmd="show", task_id="284a6a43-afa7-43f3-88e6-25d1a92cf7d7", json=False, full=False, cost=True))
        out = capsys.readouterr().out
        # format_cost_full is reused with label="task".
        assert "task 284a6a43-aff" in out or "task 284a6a43" in out
        assert "$0.5" in out

    def test_cost_command_dev_only_hint_in_prod(self, fake_creds, monkeypatch, capsys):
        prod = dict(fake_creds)
        prod["env"] = "prod"
        eesel.save_creds(prod)
        monkeypatch.setattr(eesel, "http_request", self._fake(self.HISTORY))
        monkeypatch.setattr(eesel, "_run_psql", lambda sql: pytest.fail("psql must not run in prod"))
        rc = eesel.cmd_tasks(_args(tasks_cmd="cost", task_id="284a6a43-afa7-43f3-88e6-25d1a92cf7d7"))
        assert rc == 0
        assert "dev-only" in capsys.readouterr().err

    def test_cost_json_emits_breakdown(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", self._fake(self.HISTORY))
        monkeypatch.setattr(eesel, "_run_psql", lambda sql: "284a6a43-afa7-43f3-88e6-25d1a92cf7d7||refund chat|0.5|10000|500|0|0|3")
        rc = eesel.cmd_tasks(_args(tasks_cmd="cost", task_id="284a6a43-afa7-43f3-88e6-25d1a92cf7d7", json=True))
        payload = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert payload["total_cost"] == 0.5
        assert len(payload["by_task"]) == 1


_ANALYTICS = {
    "total_tasks": 10,
    "tasks_by_status": {"completed": 10},
    "tasks_by_agent": {"agent-test-456": {"name": "Support Bot", "count": 7}, "agent-other": {"name": "Sales Bot", "count": 3}},
    "tasks_by_channel": {"helpdesk": 6, "chat": 4},
    "resolution_counts": {"resolved": 6, "escalated": 2, "pending": 2},
    "csat_distribution": {"great": 4, "good": 3, "fair": 1, "poor": 0},
}


class TestTaskAnalyticsFetch:
    def test_posts_to_workspace_analytics_with_dates_and_agent(self, fake_creds, monkeypatch):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["method"], captured["url"], captured["body"] = method, url, body
            return _ANALYTICS

        monkeypatch.setattr(eesel, "http_request", fake)
        eesel.fetch_task_analytics(fake_creds, start_date="2026-05-01", end_date="2026-05-31", agent_id="agent-test-456")
        assert captured["method"] == "POST"
        assert captured["url"] == "http://localhost:8080/workspace/tasks/analytics"
        assert captured["body"]["start_date"] == "2026-05-01"
        assert captured["body"]["end_date"] == "2026-05-31"
        # Server filters on a list of agent ids, not a single id.
        assert captured["body"]["agent_ids"] == ["agent-test-456"]

    def test_omits_empty_filters(self, fake_creds, monkeypatch):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["body"] = body
            return _ANALYTICS

        monkeypatch.setattr(eesel, "http_request", fake)
        eesel.fetch_task_analytics(fake_creds)
        # No date range and no agent → an empty body, yielding all-time totals.
        assert captured["body"] == {}

    def test_uses_workspace_token_not_raw_login_token(self, fake_creds, monkeypatch):
        # /workspace/tasks/analytics is workspace-authenticated (HS256), so it must
        # send the exchanged workspace token like the other /workspace/tasks calls.
        # The raw login token is an RS256 access token in prod and gets 401'd there.
        monkeypatch.setattr(eesel, "workspace_token", lambda creds: "WS-EXCHANGED")
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["token"] = token
            return _ANALYTICS

        monkeypatch.setattr(eesel, "http_request", fake)
        eesel.fetch_task_analytics(fake_creds)
        assert captured["token"] == "WS-EXCHANGED"


class TestTaskAnalyticsCommand:
    def test_summary_prints_resolution_rate_and_breakdowns(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: _ANALYTICS)
        rc = eesel.cmd_tasks(_args(tasks_cmd="analytics", agent=None, start_date=None, end_date=None, json=False))
        out = capsys.readouterr().out
        assert rc == 0
        assert "total tasks: 10" in out
        # 6 resolved out of 8 with a known outcome (resolved + escalated) = 75.0%.
        assert "resolution rate: 75.0%" in out
        assert "Support Bot" in out and "Sales Bot" in out
        assert "helpdesk" in out

    def test_json_emits_raw_payload(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: _ANALYTICS)
        eesel.cmd_tasks(_args(tasks_cmd="analytics", agent=None, start_date=None, end_date=None, json=True))
        payload = json.loads(capsys.readouterr().out)
        assert payload["total_tasks"] == 10
        assert payload["resolution_counts"]["resolved"] == 6

    def test_empty_range_reports_no_tasks(self, fake_creds, monkeypatch, capsys):
        empty = {"total_tasks": 0, "resolution_counts": {"resolved": 0, "escalated": 0, "pending": 0}}
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: empty)
        rc = eesel.cmd_tasks(_args(tasks_cmd="analytics", agent=None, start_date=None, end_date=None, json=False))
        assert rc == 0
        assert "(no tasks in range)" in capsys.readouterr().err

    def test_agent_filter_resolves_before_request(self, fake_creds, monkeypatch):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            if "/agents" in url:
                return [{"agent_id": "agent-test-456", "name": "Support Bot"}]
            captured["body"] = body
            return _ANALYTICS

        monkeypatch.setattr(eesel, "http_request", fake)
        # A bare name resolves to its agent id before the analytics request.
        eesel.cmd_tasks(_args(tasks_cmd="analytics", agent="Support Bot", start_date=None, end_date=None, json=False))
        assert captured["body"]["agent_ids"] == ["agent-test-456"]

    def test_unknown_agent_returns_error(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda method, url, **k: [] if "/agents" in url else _ANALYTICS)
        rc = eesel.cmd_tasks(_args(tasks_cmd="analytics", agent="nope", start_date=None, end_date=None, json=False))
        assert rc == 1
        assert "No agent matches" in capsys.readouterr().err


class TestTaskExport:
    def test_export_posts_filters_to_query_params(self, fake_creds, monkeypatch):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["method"], captured["url"], captured["body"] = method, url, body
            return {"message": "Export started"}

        monkeypatch.setattr(eesel, "http_request", fake)
        eesel.export_tasks(fake_creds, start_date="2026-05-01", end_date="2026-05-31", agent_id="agent-test-456")
        assert captured["method"] == "POST"
        # The server reads the date range and agent from the query string.
        assert captured["url"].startswith("http://localhost:8080/tasks/export?")
        assert "start_date=2026-05-01" in captured["url"]
        assert "end_date=2026-05-31" in captured["url"]
        assert "agent_id=agent-test-456" in captured["url"]
        # Additional filters travel in the JSON body.
        assert captured["body"] == {"filters": {}}

    def test_export_no_filters_has_no_query_string(self, fake_creds, monkeypatch):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["url"] = url
            return {"message": "Export started"}

        monkeypatch.setattr(eesel, "http_request", fake)
        eesel.export_tasks(fake_creds)
        assert captured["url"] == "http://localhost:8080/tasks/export"

    def test_command_reports_export_started(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"message": "Export started"})
        rc = eesel.cmd_tasks(_args(tasks_cmd="export", agent=None, start_date=None, end_date=None))
        captured = capsys.readouterr()
        assert rc == 0
        assert "Export started" in captured.out + captured.err
        assert "emailed" in captured.err

    def test_command_prints_returned_reference(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"message": "Export started", "job_id": "job-123"})
        eesel.cmd_tasks(_args(tasks_cmd="export", agent=None, start_date=None, end_date=None))
        assert "job-123" in capsys.readouterr().out

    def test_command_resolves_agent_filter(self, fake_creds, monkeypatch):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            if "/agents" in url:
                return [{"agent_id": "agent-test-456", "name": "Support Bot"}]
            captured["url"] = url
            return {"message": "Export started"}

        monkeypatch.setattr(eesel, "http_request", fake)
        eesel.cmd_tasks(_args(tasks_cmd="export", agent="Support Bot", start_date=None, end_date=None))
        assert "agent_id=agent-test-456" in captured["url"]


# ──────────────────────────────────────────────────────────────────────────
# Integrations / tools / triggers list  (read-only inspectors)
# ──────────────────────────────────────────────────────────────────────────


_INTEGRATIONS = [
    {
        "id": "int-zendesk-1",
        "integrationType": "zendesk",
        "connectionStatus": "FULL",
        "identifier": "acme.zendesk.com",
        "properties": [
            {"key": "subdomain", "value": "acme"},
            {"key": "zendesk_conversations_access_token", "value": "tok-SECRET-xyz"},
        ],
    },
    {"id": None, "integrationType": "ai_actions", "connectionStatus": "FULL", "properties": []},
]

# Catalog of connectable types, shaped like GET /integration-definitions: each
# definition carries connection_options[], each with a `type` (the --option
# value), a `handler_type` (submit = direct POST, redirect = browser OAuth), an
# `endpoint`, and a field `schema`.
_DEFINITIONS = [
    {
        "key": "zendesk",
        "title": "Zendesk",
        "category": "helpdesk",
        "availability": "available",
        "connection_options": [
            {
                "type": "quick_start",
                "handler_type": "submit",
                "endpoint": "/integrations/zendesk/quick_start",
                "schema": {"properties": {"subdomain": {"title": "Zendesk Domain"}}, "required": ["subdomain"]},
            },
            {
                "type": "oauth",
                "handler_type": "redirect",
                "endpoint": "/api/integrations/zendesk/oauth/start?createIntegration=true",
            },
        ],
    },
    {
        "key": "website",
        "title": "Website",
        "category": "documents",
        "availability": "available",
        "connection_options": [
            {
                "type": "quick_start",
                "handler_type": "submit",
                "endpoint": "/integrations/website/quick_start",
                "schema": {"properties": {"url": {"title": "URL"}}, "required": ["url"]},
            }
        ],
    },
]

_TOOLS = [
    {
        "tool_id": "t1",
        "tool_key": "zendesk_leave_internal_note",
        "name": "Leave internal note",
        "tool_action": "write",
        "permission_mode": "ask",
        "integration_id": "int-zendesk-1",
        "is_connected": True,
        "config": {"type": "json_schema", "tool_data": {"integration_key": "zendesk", "description": "note"}},
    },
    {
        "tool_id": "t2",
        "tool_key": "doc_search",
        "name": "Search docs",
        "tool_action": "read",
        "permission_mode": "always_allow",
        "integration_id": None,
        "is_connected": True,
        "config": {"tool_data": {"integration_key": "ai_actions"}},
    },
]

_ALL_TRIGGERS = [
    {"id": "sch-1", "type": "SCHEDULE", "trigger_key": "eesel_scheduled",
     "config": {"title": "Heartbeat", "cron": "0 9 * * *", "timezone": "UTC"},
     "integration_id": None, "agent_id": "a1", "agent_name": "Bot"},
    {"id": "zd-1", "type": "WEBHOOK", "trigger_key": "zendesk_ticket_created",
     "config": {"foo": "bar"}, "integration_id": "int-zendesk-1",
     "last_executed_at": "2026-05-01T10:00:00+00:00", "agent_id": "a1", "agent_name": "Bot"},
    {"id": "ic-1", "type": "EVENT", "trigger_key": "intercom_conversation_replied",
     "config": None, "integration_id": "int-ic-9", "agent_id": "a1", "agent_name": "Bot"},
]


class TestIntegrationsFetch:
    def test_fetch_integrations_passes_agent_id_and_returns_list(self, fake_creds, monkeypatch):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["method"], captured["url"] = method, url
            return [{"id": "int-1", "integrationType": "zendesk"}]

        monkeypatch.setattr(eesel, "http_request", fake)
        out = eesel.fetch_integrations(fake_creds, agent_id="agent-x")
        assert captured["method"] == "GET"
        assert captured["url"] == "http://localhost:8080/integrations?agent_id=agent-x"
        assert out[0]["integrationType"] == "zendesk"

    def test_fetch_integrations_no_agent_omits_query(self, fake_creds, monkeypatch):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["url"] = url
            return []

        monkeypatch.setattr(eesel, "http_request", fake)
        eesel.fetch_integrations(fake_creds)
        assert captured["url"] == "http://localhost:8080/integrations"

    def test_fetch_integrations_unwraps_dict_shape(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"integrations": [{"id": "x"}]})
        assert eesel.fetch_integrations(fake_creds) == [{"id": "x"}]


class TestToolsFetch:
    def test_fetch_tools_returns_bare_list(self, fake_creds, monkeypatch):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["url"] = url
            return [{"tool_key": "doc_search"}]

        monkeypatch.setattr(eesel, "http_request", fake)
        out = eesel.fetch_tools(fake_creds, "agent-x")
        assert captured["url"] == "http://localhost:8080/agents/agent-x/tools"
        assert out[0]["tool_key"] == "doc_search"

    def test_tool_row_pulls_integration_key_from_tool_data(self):
        row = eesel._tool_row(_TOOLS[0])
        assert row["name"] == "Leave internal note"
        assert row["action"] == "WRITE"  # uppercased from "write"
        assert row["permission"] == "ask"
        assert row["integration_key"] == "zendesk"  # from config.tool_data
        assert row["integration_id"] == "int-zendesk-1"

    def test_tool_row_handles_null_config_and_integration(self):
        row = eesel._tool_row({"tool_key": "k", "tool_action": "read", "config": None})
        assert row["name"] == "k"  # falls back to tool_key when name absent
        assert row["action"] == "READ"
        assert row["integration_key"] == "—"
        assert row["integration_id"] == "—"


class TestTriggerHelpers:
    def test_fetch_all_triggers_augments_every_agent(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [
            {"agent_id": "a1", "name": "Bot"}, {"agent_id": "a2", "name": "Bot2"}])
        per_agent = {
            "a1": [{"id": "t1", "trigger_key": "eesel_scheduled"}],
            "a2": [{"id": "t2", "trigger_key": "zendesk_ticket_created"}],
        }
        monkeypatch.setattr(eesel, "fetch_triggers", lambda creds, aid: per_agent[aid])
        rows = eesel.fetch_all_triggers(fake_creds)
        assert {r["id"] for r in rows} == {"t1", "t2"}
        assert {r["agent_name"] for r in rows} == {"Bot", "Bot2"}

    def test_fetch_all_scheduled_jobs_is_subset(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))
        scheduled = eesel.fetch_all_scheduled_jobs(fake_creds)
        assert [t["id"] for t in scheduled] == ["sch-1"]

    def test_fetch_all_event_triggers_excludes_scheduled(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))
        events = eesel.fetch_all_event_triggers(fake_creds)
        assert "sch-1" not in {t["id"] for t in events}
        assert all(t.get("trigger_key") != "eesel_scheduled" for t in events)

    def test_one_agent_failure_does_not_blank_list(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [
            {"agent_id": "a1", "name": "Bot"}, {"agent_id": "a2", "name": "Broken"}])

        def flaky(creds, aid):
            if aid == "a2":
                raise RuntimeError("boom")
            return [{"id": "t1", "trigger_key": "eesel_scheduled"}]

        monkeypatch.setattr(eesel, "fetch_triggers", flaky)
        rows = eesel.fetch_all_triggers(fake_creds)
        assert [r["id"] for r in rows] == ["t1"]

    def test_integration_label_resolves_then_falls_back_to_prefix(self):
        id_to_type = {"int-zendesk-1": "zendesk"}
        assert eesel._trigger_integration_label(_ALL_TRIGGERS[1], id_to_type) == "zendesk"
        # int-ic-9 not in the map → derive from the trigger_key prefix.
        assert eesel._trigger_integration_label(_ALL_TRIGGERS[2], id_to_type) == "intercom"

    def test_redact_secrets_masks_sensitive_keys_only(self):
        cfg = {
            "app_id": "r9",
            "access_token": "tok-xyz",
            "tags": ["a", "b"],
            "nested": {"client_secret": "shh", "mode": "any"},
        }
        red = eesel._redact_secrets(cfg)
        assert red["app_id"] == "r9"
        assert red["access_token"] == "***"
        assert red["tags"] == ["a", "b"]
        assert red["nested"]["client_secret"] == "***"
        assert red["nested"]["mode"] == "any"
        # Empty/None secret values are left as-is (nothing to leak).
        assert eesel._redact_secrets({"token": ""}) == {"token": ""}
        # The original dict is not mutated.
        assert cfg["access_token"] == "tok-xyz"


class TestIsSysadmin:
    def test_true_when_allowed(self, fake_creds, monkeypatch):
        monkeypatch.setattr(
            eesel, "_get_impersonate_status", lambda c: {"allowed": True, "target_user_id": None}
        )
        assert eesel._is_sysadmin(fake_creds) is True

    def test_false_when_not_allowed(self, fake_creds, monkeypatch):
        monkeypatch.setattr(
            eesel, "_get_impersonate_status", lambda c: {"allowed": False, "target_user_id": None}
        )
        assert eesel._is_sysadmin(fake_creds) is False

    def test_fails_closed_when_status_unavailable(self, fake_creds, monkeypatch):
        # _get_impersonate_status returns None on any error → not a sysadmin.
        monkeypatch.setattr(eesel, "_get_impersonate_status", lambda c: None)
        assert eesel._is_sysadmin(fake_creds) is False


class TestImpersonateStatus:
    """Normalization of /sysadmin/impersonator-status into {allowed, target_user_id}."""

    def _status(self, monkeypatch, payload):
        monkeypatch.setattr(
            eesel.urllib.request, "urlopen", lambda req, timeout=None: _FakeResp(payload)
        )
        return eesel._get_impersonate_status({"api_url": "https://oracle.eesel.app", "token": "t"})

    def test_active_target_reported_when_origin_present(self, tmp_config, monkeypatch):
        # A real swap: impersonator_uid (origin) set, target_uid is the target.
        out = self._status(
            monkeypatch,
            {"is_impersonator": True, "is_sysadmin": False,
             "impersonator_uid": "staff-1", "target_uid": "victim-9"},
        )
        assert out == {"allowed": True, "target_user_id": "victim-9"}

    def test_idle_echoes_caller_as_both_reports_no_target(self, tmp_config, monkeypatch):
        # Not impersonating: the endpoint echoes the caller's own uid into BOTH
        # impersonator_uid and target_uid. That must NOT be read as an active
        # target, or every sysadmin sees a phantom self-impersonation.
        out = self._status(
            monkeypatch,
            {"is_impersonator": True, "is_sysadmin": False,
             "impersonator_uid": "self-1", "target_uid": "self-1"},
        )
        assert out == {"allowed": True, "target_user_id": None}

    def test_idle_allowlisted_with_null_origin_reports_no_target(self, tmp_config, monkeypatch):
        # A null impersonator_uid also means no active swap.
        out = self._status(
            monkeypatch,
            {"is_impersonator": True, "is_sysadmin": False,
             "impersonator_uid": None, "target_uid": "self-1"},
        )
        assert out == {"allowed": True, "target_user_id": None}

    def test_sysadmin_flag_alone_grants_allowed(self, tmp_config, monkeypatch):
        out = self._status(
            monkeypatch,
            {"is_impersonator": False, "is_sysadmin": True,
             "impersonator_uid": None, "target_uid": None},
        )
        assert out["allowed"] is True

    def test_returns_none_on_error(self, tmp_config, monkeypatch):
        def boom(req, timeout=None):
            raise OSError("unreachable")

        monkeypatch.setattr(eesel.urllib.request, "urlopen", boom)
        assert eesel._get_impersonate_status({"api_url": "https://oracle.eesel.app", "token": "t"}) is None


class TestImpersonateCommand:
    def _creds(self):
        return {
            "env": "prod",
            "api_url": "https://oracle.eesel.app",
            "workspace_id": "ws-1",
            "token": "auth0",
            "refresh_token": "rt",
            "expires_at": int(time.time()) + 3600,
        }

    def test_set_hits_sysadmin_endpoint_with_target_query(self, tmp_config, monkeypatch, capsys):
        eesel.save_creds(self._creds())
        seen = {}

        def fake_http(method, url, *, token=None, body=None, **kw):
            seen.update(method=method, url=url)
            return 200, {"message": "Impersonation target set", "target": "victim-9"}

        monkeypatch.setattr(eesel, "http_request_allow_error", fake_http)
        args = eesel.build_parser(staff=True).parse_args(["impersonate", "victim-9"])
        rc = args.func(args)
        assert rc == 0
        assert seen["method"] == "GET"
        assert "/sysadmin/set-impersonator-target?" in seen["url"]
        assert "target=victim-9" in seen["url"]
        # ok()/info() write to stderr.
        assert "Impersonating: victim-9" in capsys.readouterr().err

    def test_clear_hits_clear_endpoint(self, tmp_config, monkeypatch, capsys):
        eesel.save_creds(self._creds())
        seen = {}

        def fake_http(method, url, *, token=None, body=None, **kw):
            seen.update(method=method, url=url)
            return 200, {"message": "Impersonation target cleared"}

        monkeypatch.setattr(eesel, "http_request_allow_error", fake_http)
        args = eesel.build_parser(staff=True).parse_args(["impersonate", "clear"])
        rc = args.func(args)
        assert rc == 0
        assert seen["method"] == "GET"
        assert seen["url"].endswith("/sysadmin/clear-impersonator-target")
        assert "cleared" in capsys.readouterr().err.lower()

    def test_clear_while_impersonating_nonsysadmin_explains_the_trap(self, tmp_config, monkeypatch, capsys):
        # Clearing runs through the swap as the impersonated non-sysadmin, so the
        # server returns 401. The user must be told it auto-expires / to use the
        # dashboard, not left with a bare "Unauthorized".
        eesel.save_creds(self._creds())
        monkeypatch.setattr(
            eesel, "http_request_allow_error",
            lambda method, url, **kw: (401, {"error": "Unauthorized"}),
        )
        args = eesel.build_parser(staff=True).parse_args(["impersonate", "clear"])
        rc = args.func(args)
        assert rc == 1
        err = capsys.readouterr().err.lower()
        assert "auto-expires" in err or "dashboard" in err


class TestResolveEffectiveWorkspaceId:
    """`resolve_effective_workspace_id` reads the effective workspace from the
    /workspaces/token mint, best-effort."""

    def test_returns_workspace_id_from_token_mint(self, monkeypatch):
        monkeypatch.setattr(
            eesel.urllib.request, "urlopen",
            lambda req, timeout=None: _FakeResp({"workspaceId": "ws-x", "token": "t"}),
        )
        creds = {"api_url": "https://oracle.eesel.app", "token": "t"}
        assert eesel.resolve_effective_workspace_id(creds) == "ws-x"

    def test_returns_none_on_error(self, monkeypatch):
        def boom(req, timeout=None):
            raise OSError("down")

        monkeypatch.setattr(eesel.urllib.request, "urlopen", boom)
        creds = {"api_url": "https://oracle.eesel.app", "token": "t"}
        assert eesel.resolve_effective_workspace_id(creds) is None


class TestEffectiveWorkspace:
    """`_apply_effective_workspace` re-points workspace_id at the impersonated
    target's workspace when one is active, reusing the workspace the guard
    already resolved (no network call of its own), and is a no-op otherwise."""

    def test_adopts_the_active_targets_workspace(self, monkeypatch):
        monkeypatch.setattr(eesel, "_impersonation_target",
                            {"user": "victim-9", "workspace": "ws-target"}, raising=False)
        creds = {"api_url": "x", "token": "auth0", "workspace_id": "ws-stored"}
        eesel._apply_effective_workspace(creds)
        assert creds["workspace_id"] == "ws-target"

    def test_no_target_leaves_workspace_untouched_without_a_network_call(self, monkeypatch):
        # The key "zero cost for normal customers" guarantee: with no active
        # target, this neither resolves nor changes the stored workspace.
        monkeypatch.setattr(eesel, "_impersonation_target", None, raising=False)

        def boom(*a, **k):
            raise AssertionError("must not resolve the workspace when not impersonating")

        monkeypatch.setattr(eesel, "resolve_effective_workspace_id", boom)
        creds = {"api_url": "x", "token": "auth0", "workspace_id": "ws-stored"}
        eesel._apply_effective_workspace(creds)
        assert creds["workspace_id"] == "ws-stored"


class TestIntegrationsCommand:
    def test_lists_id_type_status_subdomain_without_secrets(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        rc = eesel.cmd_integrations(_args(json=False, secrets=False))
        cap = capsys.readouterr()
        assert rc == 0
        assert "zendesk" in cap.out and "FULL" in cap.out and "acme.zendesk.com" in cap.out
        assert "ai_actions" in cap.out
        # Secrets stay hidden by default.
        assert "tok-SECRET-xyz" not in cap.out

    def test_list_plain_emits_tab_separated_rows(self, fake_creds, monkeypatch, capsys):
        # `--plain` emits one decoration-free, tab-separated row per integration:
        # id<TAB>type<TAB>connection<TAB>subdomain. A None id / missing subdomain
        # renders as an empty field, not the literal "None". The human view's
        # column padding is absent, confirming the human formatter was bypassed.
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        rc = eesel.cmd_integrations(_args(json=False, plain=True, secrets=False))
        assert rc == 0
        out = capsys.readouterr().out
        # Split on newlines only — the last column may be an empty field whose
        # trailing tab a str.strip() would swallow.
        lines = out.splitlines()
        assert lines == [
            "int-zendesk-1\tzendesk\tFULL\tacme.zendesk.com",
            "\tai_actions\tFULL\t",
        ]
        assert "None" not in out

    def test_secrets_revealed_for_sysadmin(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "_is_sysadmin", lambda creds: True)
        eesel.cmd_integrations(_args(json=False, secrets=True))
        out = capsys.readouterr().out
        assert "tok-SECRET-xyz" in out
        assert "subdomain = acme" in out

    def test_secrets_denied_for_non_sysadmin(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "_is_sysadmin", lambda creds: False)
        eesel.cmd_integrations(_args(json=False, secrets=True))
        cap = capsys.readouterr()
        assert "tok-SECRET-xyz" not in cap.out
        assert "restricted" in cap.err

    def test_json_redacts_secrets_for_non_sysadmin(self, fake_creds, monkeypatch, capsys):
        # --json goes through the same --secrets+sysadmin gate as the table view,
        # so a non-sysadmin sees masked tokens but still gets the full structure
        # (ids, types, non-sensitive properties like subdomain).
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "_is_sysadmin", lambda creds: False)
        eesel.cmd_integrations(_args(json=True, secrets=False))
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert payload[0]["integrationType"] == "zendesk"
        assert "tok-SECRET-xyz" not in out
        # The masked entry is present (just its value redacted), and non-secret
        # properties survive.
        props = {p["key"]: p["value"] for p in payload[0]["properties"]}
        assert props["zendesk_conversations_access_token"] == "***"
        assert props["subdomain"] == "acme"

    def test_json_reveals_secrets_for_sysadmin_with_secrets_flag(self, fake_creds, monkeypatch, capsys):
        # With --secrets on a sysadmin account, --json emits the raw payload,
        # tokens included — mirroring the table view's reveal path.
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "_is_sysadmin", lambda creds: True)
        eesel.cmd_integrations(_args(json=True, secrets=True))
        out = capsys.readouterr().out
        assert "tok-SECRET-xyz" in out

    def test_json_secrets_flag_denied_for_non_sysadmin_keeps_redaction(self, fake_creds, monkeypatch, capsys):
        # A non-sysadmin passing --secrets is warned and still gets redacted JSON.
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "_is_sysadmin", lambda creds: False)
        eesel.cmd_integrations(_args(json=True, secrets=True))
        cap = capsys.readouterr()
        assert "tok-SECRET-xyz" not in cap.out
        assert "restricted" in cap.err

    def test_empty(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: [])
        rc = eesel.cmd_integrations(_args(json=False, secrets=False))
        assert rc == 0
        assert "(no integrations)" in capsys.readouterr().err

    def test_bare_command_defaults_to_list(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        # No integrations_cmd attribute at all → dispatcher falls back to list.
        rc = eesel.cmd_integrations(_args(json=False, secrets=False))
        assert rc == 0
        assert "zendesk" in capsys.readouterr().out


class TestIntegrationsAvailable:
    """`integrations available` lists the connectable catalog (read-only)."""

    def test_lists_key_category_title_and_connect_options(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integration_definitions", lambda creds: list(_DEFINITIONS))
        rc = eesel.cmd_integrations(_args(integrations_cmd="available", json=False, agent=None))
        out = capsys.readouterr().out
        assert rc == 0
        # Zendesk appears under its category, with its connect-option types so a
        # user knows what `connect --option` accepts.
        assert "zendesk" in out and "helpdesk" in out
        assert "quick_start" in out and "oauth" in out
        assert "website" in out

    def test_json_emits_raw_definitions(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integration_definitions", lambda creds: list(_DEFINITIONS))
        rc = eesel.cmd_integrations(_args(integrations_cmd="available", json=True, agent=None))
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert [d["key"] for d in payload] == ["zendesk", "website"]

    def test_empty_catalog(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integration_definitions", lambda creds: [])
        rc = eesel.cmd_integrations(_args(integrations_cmd="available", json=False, agent=None))
        assert rc == 0
        assert "(no connectable integrations)" in capsys.readouterr().err

    def test_fetch_unwraps_integrations_key(self, fake_creds, monkeypatch):
        monkeypatch.setattr(
            eesel, "http_request",
            lambda *a, **k: {"categories": {}, "integrations": list(_DEFINITIONS)},
        )
        assert [d["key"] for d in eesel.fetch_integration_definitions(fake_creds)] == ["zendesk", "website"]


class TestIntegrationsAgentScope:
    """`--agent` overrides the active agent for the whole integrations group."""

    _AGENTS = [
        {"agent_id": "agent-test-456", "name": "Default Bot"},
        {"agent_id": "agent-other-789", "name": "Other Bot"},
    ]

    def test_agent_flag_overrides_active_agent_for_list(self, fake_creds, monkeypatch):
        # The active agent is agent-test-456; --agent must scope the fetch to the
        # resolved agent instead, without persisting the change.
        seen = {}
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: list(self._AGENTS))

        def fake_fetch(creds, agent_id=None):
            seen["agent_id"] = agent_id
            return []

        monkeypatch.setattr(eesel, "fetch_integrations", fake_fetch)
        rc = eesel.cmd_integrations(_args(integrations_cmd="list", json=False, secrets=False, agent="Other Bot"))
        assert rc == 0
        assert seen["agent_id"] == "agent-other-789"

    def test_agent_flag_scopes_connect_redirect_url(self, fake_creds, monkeypatch, capsys):
        # The resolved --agent (not the stored active agent) is the agentId in
        # the OAuth hand-off URL, so the post-auth redirect lands on that agent.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: list(self._AGENTS))
        monkeypatch.setattr(eesel, "fetch_integration_definition", lambda creds, key: next((d for d in _DEFINITIONS if d["key"] == key), None))
        monkeypatch.setattr(eesel, "webbrowser", type("W", (), {"open": staticmethod(lambda url: True)}))
        # The browser hand-off only runs on an interactive terminal.
        monkeypatch.setattr(eesel.sys, "stdin", _FakeStdin(True))
        rc = eesel.cmd_integrations(
            _connect_args(integrations_cmd="connect", key="zendesk", option="oauth", agent="agent-other-789")
        )
        assert rc == 0
        assert "agentId=agent-other-789" in capsys.readouterr().err

    def test_unknown_agent_errors_before_request(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: list(self._AGENTS))
        # If resolution fails the command must abort before touching the network.
        monkeypatch.setattr(
            eesel, "fetch_integrations",
            lambda *a, **k: pytest.fail("should not fetch when --agent is unresolvable"),
        )
        rc = eesel.cmd_integrations(_args(integrations_cmd="list", json=False, secrets=False, agent="nope"))
        assert rc == 1
        assert "No agent matches 'nope'" in capsys.readouterr().err

    def test_ambiguous_agent_errors_with_candidates(self, fake_creds, monkeypatch, capsys):
        # Both ids share the "agent-" prefix; a prefix that matches more than one
        # agent is refused rather than resolved to an arbitrary one.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: list(self._AGENTS))
        rc = eesel.cmd_integrations(_args(integrations_cmd="list", json=False, secrets=False, agent="agent-"))
        assert rc == 1
        assert "ambiguous" in capsys.readouterr().err


def _connect_args(**kw):
    """args for `integrations connect`/`add` with option/field and the hidden
    headless guard (no_input) defaulted off."""
    for key, default in (("option", None), ("field", None), ("no_input", False)):
        kw.setdefault(key, default)
    return _args(**kw)


class TestIntegrationsConnect:
    """`integrations connect` drives off each definition's connection_options: a
    `submit` option POSTs the option endpoint; a `redirect` option hands off to
    the browser. `add` is the hidden back-compat alias."""

    def _defs(self, monkeypatch):
        # `connect` fetches one definition by key, not the whole catalog.
        monkeypatch.setattr(
            eesel, "fetch_integration_definition",
            lambda creds, key: next((d for d in _DEFINITIONS if d["key"] == key), None),
        )

    def _no_browser(self, monkeypatch, sink=None):
        def _open(url):
            if sink is not None:
                sink.append(url)
            return True
        monkeypatch.setattr(eesel, "webbrowser", type("W", (), {"open": staticmethod(_open)}))

    def test_submit_option_posts_endpoint_with_fields(self, fake_creds, monkeypatch, capsys):
        self._defs(monkeypatch)
        captured = {}

        def fake_request(method, url, *, token=None, body=None, timeout=60):
            captured.update(method=method, url=url, body=body)
            return 201, {"integration_id": "int-new-1", "identifier": "acme.zendesk.com"}

        monkeypatch.setattr(eesel, "http_request_allow_error", fake_request)
        rc = eesel.cmd_integrations(_connect_args(integrations_cmd="connect", key="zendesk", option="quick_start", field=["subdomain=acme"]))
        assert rc == 0
        # POSTs the chosen option's endpoint (NOT /integrations/{key}), with the
        # --field values as the body.
        assert captured["method"] == "POST"
        assert captured["url"] == "http://localhost:8080/integrations/zendesk/quick_start"
        assert captured["body"] == {"subdomain": "acme"}
        assert "Connected 'zendesk'" in capsys.readouterr().err

    def test_redirect_option_opens_browser_and_exits(self, fake_creds, monkeypatch, capsys):
        self._defs(monkeypatch)
        opened = []
        self._no_browser(monkeypatch, opened)
        # On an interactive terminal the redirect option hands off to the browser.
        monkeypatch.setattr(eesel.sys, "stdin", _FakeStdin(True))
        monkeypatch.setattr(eesel, "http_request_allow_error", lambda *a, **k: pytest.fail("redirect must not POST"))
        rc = eesel.cmd_integrations(_connect_args(integrations_cmd="connect", key="zendesk", option="oauth"))
        assert rc == 0
        # Hands off to the dashboard OAuth URL; does not wait or poll.
        assert opened and opened[0].startswith("http://localhost:3000/api/integrations/zendesk/oauth/start")
        assert "createIntegration=true" in opened[0]
        assert "Opening your browser" in capsys.readouterr().err

    def test_requires_option_when_several(self, fake_creds, monkeypatch, capsys):
        self._defs(monkeypatch)
        rc = eesel.cmd_integrations(_connect_args(integrations_cmd="connect", key="zendesk"))
        assert rc == 1
        err = capsys.readouterr().err
        assert "choose one with --option" in err
        assert "quick_start" in err and "oauth" in err

    def test_single_option_needs_no_choice(self, fake_creds, monkeypatch):
        # website exposes exactly one option, so it is used without --option.
        self._defs(monkeypatch)
        captured = {}
        monkeypatch.setattr(
            eesel, "http_request_allow_error",
            lambda method, url, *, token=None, body=None, timeout=60: (captured.update(url=url) or (201, {"integration_id": "w1"})),
        )
        rc = eesel.cmd_integrations(_connect_args(integrations_cmd="connect", key="website", field=["url=https://acme.com"]))
        assert rc == 0
        assert captured["url"] == "http://localhost:8080/integrations/website/quick_start"

    def test_unknown_option_lists_available(self, fake_creds, monkeypatch, capsys):
        self._defs(monkeypatch)
        rc = eesel.cmd_integrations(_connect_args(integrations_cmd="connect", key="zendesk", option="nope"))
        assert rc == 1
        err = capsys.readouterr().err
        assert "no connection option 'nope'" in err
        assert "quick_start" in err

    def test_missing_required_field_errors_before_post(self, fake_creds, monkeypatch, capsys):
        self._defs(monkeypatch)
        monkeypatch.setattr(eesel, "http_request_allow_error", lambda *a, **k: pytest.fail("must not POST when a required field is missing"))
        rc = eesel.cmd_integrations(_connect_args(integrations_cmd="connect", key="zendesk", option="quick_start"))
        assert rc == 1
        assert "missing required field(s): subdomain" in capsys.readouterr().err

    def test_unknown_key_points_at_available(self, fake_creds, monkeypatch, capsys):
        self._defs(monkeypatch)
        rc = eesel.cmd_integrations(_connect_args(integrations_cmd="connect", key="nope"))
        assert rc == 1
        err = capsys.readouterr().err
        assert "No connectable integration 'nope'" in err
        assert "available" in err

    def test_add_alias_is_no_longer_accepted(self):
        # `integrations add` used to alias `connect`; that alias is removed, so
        # `add` is no longer a valid integrations verb.
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(eesel._normalize_integrations_argv(["integrations", "add", "zendesk"]))

    def test_submit_surfaces_server_400(self, fake_creds, monkeypatch, capsys):
        self._defs(monkeypatch)
        monkeypatch.setattr(
            eesel, "http_request_allow_error",
            lambda *a, **k: (400, {"error": "Zendesk subdomain or custom hostname is required"}),
        )
        rc = eesel.cmd_integrations(_connect_args(integrations_cmd="connect", key="zendesk", option="quick_start", field=["subdomain=bad"]))
        # A server 400 on a submit connect maps to the validation exit code.
        assert rc == eesel.EXIT_VALIDATION
        assert "Zendesk subdomain or custom hostname is required" in capsys.readouterr().err

    def test_no_input_refuses_redirect(self, fake_creds, monkeypatch, capsys):
        # --no-input forces the honest refusal even on an interactive terminal:
        # a browser-OAuth connect can't complete without human interaction.
        self._defs(monkeypatch)
        monkeypatch.setattr(eesel.sys, "stdin", _FakeStdin(True))
        rc = eesel.cmd_integrations(_connect_args(integrations_cmd="connect", key="zendesk", option="oauth", no_input=True))
        assert rc == eesel.EXIT_VALIDATION
        assert "interactive browser" in capsys.readouterr().err

    def test_no_input_flag_is_documented(self):
        # --no-input is a public, discoverable flag now (no longer suppressed),
        # so an agent can find it in `eesel integrations connect --help`.
        import argparse as _argparse
        parser = eesel.build_parser()
        integrations = _subparsers_action(parser).choices["integrations"]
        connect = _subparsers_action(integrations).choices["connect"]
        action = next(a for a in connect._actions if "--no-input" in a.option_strings)
        assert action.help and action.help is not _argparse.SUPPRESS

    def test_redirect_refuses_on_non_tty(self, fake_creds, monkeypatch, capsys):
        # Without --no-input, a non-interactive stdin (a headless agent) must
        # still refuse a browser-OAuth connect — never print a URL and exit 0
        # having connected nothing.
        self._defs(monkeypatch)
        monkeypatch.setattr(eesel.sys, "stdin", _FakeStdin(False))
        monkeypatch.setattr(eesel, "webbrowser", type("W", (), {"open": staticmethod(lambda url: pytest.fail("must not open a browser on a non-TTY"))}))
        rc = eesel.cmd_integrations(_connect_args(integrations_cmd="connect", key="zendesk", option="oauth"))
        assert rc == eesel.EXIT_VALIDATION
        assert "interactive browser" in capsys.readouterr().err

    def test_browser_connect_url_resolves_dashboard_and_fills_params(self, fake_creds):
        # Drops unresolved {{...}} params, fills the identifier param the endpoint
        # templates, and appends the active agent id — on the dashboard host.
        endpoint = "/api/integrations/zendesk-conversations/oauth/start?zendeskSubdomain={{integrationIdentifier}}&agentId={{agentId}}"
        url = eesel._browser_connect_url(fake_creds, endpoint, identifier="acme")
        assert url.startswith("http://localhost:3000/api/integrations/zendesk-conversations/oauth/start")
        assert "zendeskSubdomain=acme" in url
        assert "agentId=agent-test-456" in url
        assert "{{" not in url

    def test_malformed_field_exits(self, fake_creds, monkeypatch):
        self._defs(monkeypatch)
        with pytest.raises(SystemExit):
            eesel.cmd_integrations(_connect_args(integrations_cmd="connect", key="zendesk", option="quick_start", field=["noequalshere"]))


class TestIntegrationsSync:
    def test_posts_sync_type_for_resolved_integration(self, fake_creds, monkeypatch, capsys):
        captured = {}

        def fake_request(method, url, *, token=None, body=None, timeout=60):
            captured["method"] = method
            captured["url"] = url
            captured["body"] = body
            return 202, {"message": "sync triggered"}

        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "http_request_allow_error", fake_request)
        # Resolve by integration type "zendesk" → its id int-zendesk-1.
        rc = eesel.cmd_integrations(_args(integrations_cmd="sync", id="zendesk", type="tickets"))
        assert rc == 0
        assert captured["url"] == "http://localhost:8080/integrations/int-zendesk-1/trigger-sync"
        assert captured["body"] == {"sync_type": "tickets"}
        assert "sync triggered" in capsys.readouterr().err

    def test_rejects_unknown_sync_type(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request_allow_error", lambda *a, **k: pytest.fail("should not POST"))
        rc = eesel.cmd_integrations(_args(integrations_cmd="sync", id="zendesk", type="everything"))
        assert rc == 1
        err = capsys.readouterr().err
        assert "Invalid --type" in err
        assert "help-center" in err

    def test_unresolvable_id_errors(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        rc = eesel.cmd_integrations(_args(integrations_cmd="sync", id="nope", type="macros"))
        assert rc == 1
        assert "No connected integration matches" in capsys.readouterr().err

    def test_skipped_when_already_in_progress(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(
            eesel,
            "http_request_allow_error",
            lambda *a, **k: (200, {"skipped": True, "reason": "a 'tickets' sync is already in progress for this integration", "existing_run_id": "run-9"}),
        )
        rc = eesel.cmd_integrations(_args(integrations_cmd="sync", id="int-zendesk-1", type="tickets"))
        assert rc == 0
        assert "already in progress" in capsys.readouterr().err

    def test_surfaces_server_error(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(
            eesel,
            "http_request_allow_error",
            lambda *a, **k: (400, {"error": "only zendesk integrations support trigger-sync"}),
        )
        rc = eesel.cmd_integrations(_args(integrations_cmd="sync", id="int-zendesk-1", type="tickets"))
        # A server 400 maps to the validation exit code, not the generic 1.
        assert rc == eesel.EXIT_VALIDATION
        assert "only zendesk integrations support trigger-sync" in capsys.readouterr().err


_SYNC_RUNS = {
    "jobs": [
        {
            "id": "run-1",
            "status": "running",
            "metadata": {"integration_id": "int-zendesk-1", "integration_type": "zendesk"},
            "progress": {"completed_steps": 3, "total_steps": 4, "message": "Syncing help center"},
        },
        {
            "id": "run-2",
            "status": "failed",
            "metadata": {"integration_id": "int-other-9", "integration_type": "salesforce_v2"},
            "progress": {"completed_steps": 0, "total_steps": None, "message": "Syncing accounts"},
        },
    ],
    "workspace_id": "ws-test-123",
}


class TestIntegrationsSyncStatus:
    def test_lists_all_runs_with_status_and_progress(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: dict(_SYNC_RUNS))
        rc = eesel.cmd_integrations(_args(integrations_cmd="sync-status", id=None, json=False, agent=None))
        out = capsys.readouterr().out
        assert rc == 0
        assert "running" in out and "75%" in out and "Syncing help center" in out
        # A run with no total-step count falls back to the server's message.
        assert "failed" in out and "Syncing accounts" in out

    def test_filters_to_one_integration_by_metadata_id(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: dict(_SYNC_RUNS))
        # "zendesk" resolves to int-zendesk-1, so only run-1 (its metadata id) shows.
        rc = eesel.cmd_integrations(_args(integrations_cmd="sync-status", id="zendesk", json=False, agent=None))
        out = capsys.readouterr().out
        assert rc == 0
        assert "Syncing help center" in out
        assert "Syncing accounts" not in out

    def test_unresolvable_id_errors(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        rc = eesel.cmd_integrations(_args(integrations_cmd="sync-status", id="nope", json=False, agent=None))
        assert rc == 1
        assert "No connected integration matches" in capsys.readouterr().err

    def test_empty_runs(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"jobs": [], "workspace_id": "ws-test-123"})
        rc = eesel.cmd_integrations(_args(integrations_cmd="sync-status", id=None, json=False, agent=None))
        assert rc == 0
        assert "(no active or recent sync runs)" in capsys.readouterr().err

    def test_json_emits_filtered_runs(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: dict(_SYNC_RUNS))
        rc = eesel.cmd_integrations(_args(integrations_cmd="sync-status", id=None, json=True, agent=None))
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert [r["id"] for r in payload] == ["run-1", "run-2"]

    def test_progress_clamps_overcount_and_drops_empty_head(self):
        # Server can report completed > total; the percentage clamps to 100.
        assert eesel._sync_run_progress({"progress": {"completed_steps": 2, "total_steps": 1}}) == "100%"
        # No usable step counts but a message → just the message (no "— —").
        assert eesel._sync_run_progress({"progress": {"completed_steps": 0, "total_steps": None, "message": "x"}}) == "x"
        # Nothing at all → an em dash.
        assert eesel._sync_run_progress({"progress": {}}) == "—"


class TestIntegrationsShow:
    def test_shows_detail_with_connection_and_latest_sync_run(self, fake_creds, monkeypatch, capsys):
        captured = {}

        def fake_request(method, url, *, token=None, body=None, timeout=60):
            captured["method"] = method
            captured["url"] = url
            return dict(_SYNC_RUNS)

        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "http_request", fake_request)
        rc = eesel.cmd_integrations(_args(integrations_cmd="show", id="int-zendesk-1", json=False))
        out = capsys.readouterr().out
        assert rc == 0
        # The latest run is read from the sync-runs feed, NOT the per-integration
        # /sync endpoint (which would trigger a sync).
        assert captured["method"] == "GET"
        assert captured["url"] == "http://localhost:8080/v2/sync-runs"
        assert "zendesk" in out
        assert "FULL" in out  # connection status as a field
        assert "running" in out and "75%" in out  # the matched run's status + progress

    def test_unresolvable_id_errors(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        rc = eesel.cmd_integrations(_args(integrations_cmd="show", id="missing", json=False))
        assert rc == 1
        assert "No connected integration matches" in capsys.readouterr().err

    def test_no_recent_run_shows_dash(self, fake_creds, monkeypatch, capsys):
        # An integration with no active or recent run shows "—" for sync, not an
        # error — and reading status never triggers a sync.
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"jobs": [], "workspace_id": "ws-test-123"})
        rc = eesel.cmd_integrations(_args(integrations_cmd="show", id="int-zendesk-1", json=False))
        out = capsys.readouterr().out
        assert rc == 0
        assert "FULL" in out
        assert " sync        —" in out

    def test_json_includes_latest_sync_run(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: dict(_SYNC_RUNS))
        eesel.cmd_integrations(_args(integrations_cmd="show", id="int-zendesk-1", json=True))
        payload = json.loads(capsys.readouterr().out)
        assert payload["integrationType"] == "zendesk"
        assert payload["syncRun"]["status"] == "running"

    def test_json_redacts_secrets(self, fake_creds, monkeypatch, capsys):
        # `show` has no --secrets flag, so its --json output always masks tokens.
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: dict(_SYNC_RUNS))
        eesel.cmd_integrations(_args(integrations_cmd="show", id="int-zendesk-1", json=True))
        out = capsys.readouterr().out
        assert "tok-SECRET-xyz" not in out
        props = {p["key"]: p["value"] for p in json.loads(out)["properties"]}
        assert props["zendesk_conversations_access_token"] == "***"


class TestIntegrationsRemove:
    def test_removes_resolved_integration_with_force(self, fake_creds, monkeypatch, capsys):
        captured = {}

        def fake_request(method, url, *, token=None, body=None, timeout=60):
            captured["method"] = method
            captured["url"] = url
            return {}

        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "http_request", fake_request)
        rc = eesel.cmd_integrations(_args(integrations_cmd="remove", id="zendesk", force=True))
        assert rc == 0
        assert captured["method"] == "DELETE"
        assert captured["url"] == "http://localhost:8080/integrations/int-zendesk-1"
        assert "Uninstalled" in capsys.readouterr().err

    def test_disconnect_alias_is_no_longer_accepted(self):
        # `integrations disconnect` used to alias `remove`; that alias is removed,
        # so `disconnect` is no longer a valid integrations verb.
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(eesel._normalize_integrations_argv(["integrations", "disconnect", "int-zendesk-1"]))

    def test_prompts_and_aborts_on_no(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: pytest.fail("must not DELETE when aborted"))
        monkeypatch.setattr("builtins.input", lambda *a, **k: "n")
        rc = eesel.cmd_integrations(_args(integrations_cmd="remove", id="int-zendesk-1", force=False))
        assert rc == 1
        assert "Aborted" in capsys.readouterr().err

    def test_unresolvable_id_errors_without_request(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: pytest.fail("must not DELETE an unknown id"))
        rc = eesel.cmd_integrations(_args(integrations_cmd="remove", id="nope", force=True))
        assert rc == 1
        assert "No connected integration matches" in capsys.readouterr().err

    def test_ambiguous_type_refuses_without_request(self, fake_creds, monkeypatch, capsys):
        # Two integrations of the same type: `remove zendesk` must refuse and
        # list candidates rather than disconnect an arbitrary one.
        rows = [
            {"id": "int-zd-1", "integrationType": "zendesk", "identifier": "acme"},
            {"id": "int-zd-2", "integrationType": "zendesk", "identifier": "beta"},
        ]
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: rows)
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: pytest.fail("must not DELETE an ambiguous integration"))
        rc = eesel.cmd_integrations(_args(integrations_cmd="remove", id="zendesk", force=True))
        assert rc == 1
        out = capsys.readouterr().err
        assert "ambiguous" in out
        assert "int-zd-1" in out and "int-zd-2" in out

    def test_blank_agent_flag_errors_without_request(self, fake_creds, monkeypatch, capsys):
        # A present-but-empty `--agent` (e.g. `--agent "$AGENT"` with the variable
        # unset) must be treated as an error, NOT as "no agent" — otherwise the
        # removal silently falls through to the workspace-wide uninstall. It is
        # distinct from omitting `--agent` entirely (which IS a workspace uninstall).
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: pytest.fail("must not resolve an integration for a blank --agent"))
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: pytest.fail("must not DELETE for a blank --agent"))
        rc = eesel.cmd_integrations(_args(integrations_cmd="remove", id="zendesk", force=True, agent=""))
        assert rc == 1
        assert "--agent was given but is empty" in capsys.readouterr().err

    def test_agent_scoped_remove_hits_per_agent_endpoint(self, fake_creds, monkeypatch, capsys):
        # `--agent` (the flat form of `agents <id> remove <x>`) removes the
        # integration from just that agent — DELETE /agents/{id}/integrations/{id} —
        # not the workspace-wide DELETE /integrations/{id}.
        captured = {}
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "agent-test-456", "name": "Bot"}])
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "http_request", lambda method, url, **k: captured.update(method=method, url=url) or {"message": "Integration removed from agent"})
        rc = eesel.cmd_integrations(_args(integrations_cmd="remove", id="zendesk", force=True, agent="agent-test-456"))
        assert rc == 0
        assert captured["method"] == "DELETE"
        assert captured["url"] == "http://localhost:8080/agents/agent-test-456/integrations/int-zendesk-1"
        out = capsys.readouterr().err
        assert "Removed" in out and "Other agents keep their access" in out

    def test_agent_scoped_remove_surfaces_partial_cleanup_errors(self, fake_creds, monkeypatch, capsys):
        # A 207 from the server carries an `errors` list: report it as a warning
        # but still treat the removal as done (rc 0).
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "agent-test-456", "name": "Bot"}])
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"message": "Integration removed with partial errors", "errors": ["triggers: boom"]})
        rc = eesel.cmd_integrations(_args(integrations_cmd="remove", id="zendesk", force=True, agent="agent-test-456"))
        assert rc == 0
        out = capsys.readouterr().err
        assert "partial cleanup issue" in out and "triggers: boom" in out
        assert "Removed" in out

    def test_remove_prompt_text_differs_by_scope(self, fake_creds, monkeypatch):
        # The confirmation makes the blast radius explicit: per-agent reassures
        # that other agents keep access; workspace warns it hits every agent.
        prompts = []
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "agent-test-456", "name": "Bot"}])
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {})
        monkeypatch.setattr("builtins.input", lambda prompt="": prompts.append(prompt) or "y")

        eesel.cmd_integrations(_args(integrations_cmd="remove", id="zendesk", agent="agent-test-456"))
        eesel.cmd_integrations(_args(integrations_cmd="remove", id="zendesk"))
        scoped_prompt, workspace_prompt = prompts
        assert "Other agents keep their access" in scoped_prompt
        assert "whole workspace" in workspace_prompt and "cannot be undone" in workspace_prompt

    def test_agent_scoped_force_skips_prompt(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "agent-test-456", "name": "Bot"}])
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {})
        monkeypatch.setattr("builtins.input", lambda *a, **k: pytest.fail("--force must not prompt"))
        rc = eesel.cmd_integrations(_args(integrations_cmd="remove", id="zendesk", force=True, agent="agent-test-456"))
        assert rc == 0


class TestResolveIntegration:
    def test_matches_by_exact_id_then_prefix_then_type(self):
        rows = [
            {"id": "int-abc-123", "integrationType": "zendesk"},
            {"id": "int-def-456", "integrationType": "intercom"},
        ]
        assert eesel.resolve_integration(rows, "int-abc-123")["integrationType"] == "zendesk"
        assert eesel.resolve_integration(rows, "int-def")["integrationType"] == "intercom"
        assert eesel.resolve_integration(rows, "zendesk")["id"] == "int-abc-123"
        assert eesel.resolve_integration(rows, "nope") is None

    def test_strict_refuses_ambiguous_type_and_lists_candidates(self, capsys):
        # Two integrations of the same type: the strict (destructive) resolver
        # must refuse rather than disconnect an arbitrary one.
        rows = [
            {"id": "int-zd-1", "integrationType": "zendesk", "identifier": "acme"},
            {"id": "int-zd-2", "integrationType": "zendesk", "identifier": "beta"},
        ]
        assert eesel.resolve_integration_strict(rows, "zendesk") is None
        out = capsys.readouterr().err
        assert "ambiguous" in out
        assert "int-zd-1" in out and "int-zd-2" in out

    def test_strict_returns_unique_match(self):
        rows = [
            {"id": "int-abc-123", "integrationType": "zendesk"},
            {"id": "int-def-456", "integrationType": "intercom"},
        ]
        assert eesel.resolve_integration_strict(rows, "zendesk")["id"] == "int-abc-123"


class TestHttpRequestAllowError:
    def test_returns_status_and_parsed_body_on_error(self, monkeypatch):
        import urllib.error
        import io

        def raise_http_error(*a, **k):
            raise urllib.error.HTTPError(
                url="http://x/integrations/zendesk",
                code=400,
                msg="Bad Request",
                hdrs=None,
                fp=io.BytesIO(b'{"error": "subdomain is required"}'),
            )

        monkeypatch.setattr(eesel.urllib.request, "urlopen", raise_http_error)
        status, body = eesel.http_request_allow_error("POST", "http://x/integrations/zendesk", token="t", body={})
        assert status == 400
        assert body["error"] == "subdomain is required"


class TestIntegrationActionsList:
    """`eesel integrations <integration> actions list` (and show)."""

    def _agents(self):
        return [{"agent_id": "agent-test-456", "name": "Support Bot"}]

    def test_lists_actions_scoped_to_integration(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "fetch_tools", lambda creds, aid: list(_TOOLS))
        rc = eesel.cmd_integration_actions(_args(actions_cmd="list", integration="zendesk", agent=None, json=False))
        out = capsys.readouterr().out
        assert rc == 0
        # Only the zendesk action is shown; the ai_actions doc_search is filtered out.
        assert "Leave internal note" in out and "WRITE" in out and "ask" in out
        assert "Search docs" not in out

    def test_list_shows_tool_key_column(self, fake_creds, monkeypatch, capsys):
        # The key the write verbs (show/enable/disable/set) require must be
        # visible in the table, not only under --json.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "fetch_tools", lambda creds, aid: list(_TOOLS))
        eesel.cmd_integration_actions(_args(actions_cmd="list", integration="zendesk", agent=None, json=False))
        cap = capsys.readouterr()
        assert "zendesk_leave_internal_note" in cap.out
        assert "key" in cap.err  # header line goes to stderr

    def test_show_resolves_display_name(self, fake_creds, monkeypatch, capsys):
        # `show` accepts the human display name, not just the tool_key.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "fetch_tools", lambda creds, aid: list(_TOOLS))
        rc = eesel.cmd_integration_actions(_args(
            actions_cmd="show", integration="zendesk", action="Leave internal note", agent=None, json=False))
        cap = capsys.readouterr()
        assert rc == 0
        assert "zendesk_leave_internal_note" in (cap.out + cap.err)

    def test_resolves_named_agent(self, fake_creds, monkeypatch, capsys):
        captured = {}
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [
            {"agent_id": "agent-test-456", "name": "Support Bot"},
            {"agent_id": "agent-other-999", "name": "Sales Bot"}])

        def fake_tools(creds, aid):
            captured["aid"] = aid
            return []

        monkeypatch.setattr(eesel, "fetch_tools", fake_tools)
        eesel.cmd_integration_actions(_args(actions_cmd="list", integration="zendesk", agent="Sales Bot", json=False))
        assert captured["aid"] == "agent-other-999"

    def test_multi_agent_no_scope_errors(self, fake_creds, monkeypatch, capsys):
        # Several agents and no --agent/EESEL_AGENT → refuse before any fetch.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [
            {"agent_id": "a1", "name": "Bot"}, {"agent_id": "a2", "name": "Bot2"}])
        monkeypatch.setattr(eesel, "fetch_tools", lambda creds, aid: pytest.fail("should not fetch"))
        rc = eesel.cmd_integration_actions(_args(actions_cmd="list", integration="zendesk", agent=None, json=False))
        assert rc == 1
        assert "2 agents" in capsys.readouterr().err

    def test_json_emits_scoped_payload(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "fetch_tools", lambda creds, aid: list(_TOOLS))
        eesel.cmd_integration_actions(_args(actions_cmd="list", integration="zendesk", agent=None, json=True))
        payload = json.loads(capsys.readouterr().out)
        # Filtered to the named integration.
        assert [t["tool_key"] for t in payload] == ["zendesk_leave_internal_note"]

    def test_empty_actions(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "fetch_tools", lambda creds, aid: [])
        rc = eesel.cmd_integration_actions(_args(actions_cmd="list", integration="zendesk", agent=None, json=False))
        assert rc == 0
        assert "no 'zendesk' actions" in capsys.readouterr().err

    def test_show_one_action(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "fetch_tools", lambda creds, aid: list(_TOOLS))
        rc = eesel.cmd_integration_actions(_args(
            actions_cmd="show", integration="zendesk", action="zendesk_leave_internal_note", agent=None, json=False))
        cap = capsys.readouterr()
        combined = cap.out + cap.err
        assert rc == 0
        assert "Leave internal note" in combined and "int-zendesk-1" in combined and "ask" in combined

    def test_show_missing_action_errors(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "fetch_tools", lambda creds, aid: list(_TOOLS))
        rc = eesel.cmd_integration_actions(_args(
            actions_cmd="show", integration="zendesk", action="nope", agent=None, json=False))
        assert rc == 1
        assert "No 'nope' action" in capsys.readouterr().err


class TestTriggersList:
    """`eesel triggers list` shows event/webhook triggers only, grouped by
    integration. Scheduled jobs are excluded — they live under `eesel
    schedules`."""

    def test_list_groups_event_triggers_by_integration(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        rc = eesel.cmd_triggers(_args(triggers_cmd="list", json=False))
        out = capsys.readouterr().out
        assert rc == 0
        # The scheduled job is not part of the triggers view.
        assert "scheduled" not in out and "Heartbeat" not in out
        # zendesk group (resolved via integration map) + intercom (prefix fallback).
        assert "zendesk (1)" in out and "zendesk_ticket_created" in out and "WEBHOOK" in out
        assert "intercom (1)" in out and "intercom_conversation_replied" in out
        # config shown inline for event triggers.
        assert '"foo": "bar"' in out

    def test_list_json_emits_raw_event_payload(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))
        monkeypatch.setattr(eesel, "fetch_integrations", lambda *a, **k: pytest.fail("json path must not fetch integrations"))
        eesel.cmd_triggers(_args(triggers_cmd="list", json=True))
        payload = json.loads(capsys.readouterr().out)
        # Only event triggers — the scheduled job (sch-1) is excluded.
        assert {t["id"] for t in payload} == {"zd-1", "ic-1"}

    def test_list_plain_emits_tab_separated_rows(self, fake_creds, monkeypatch, capsys):
        # `--plain` emits one decoration-free, tab-separated row per event
        # trigger: id<TAB>state<TAB>trigger_key<TAB>agent. The integration
        # grouping headers and config blobs of the human view are absent,
        # confirming the human formatter was bypassed.
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))
        monkeypatch.setattr(eesel, "fetch_integrations", lambda *a, **k: pytest.fail("plain path must not fetch integrations"))
        rc = eesel.cmd_triggers(_args(triggers_cmd="list", json=False, plain=True))
        assert rc == 0
        out = capsys.readouterr().out
        lines = out.strip().splitlines()
        assert set(lines) == {
            "zd-1\ton\tzendesk_ticket_created\tBot",
            "ic-1\ton\tintercom_conversation_replied\tBot",
        }
        # No grouping headers and no inline config from the human view.
        assert "zendesk (1)" not in out and "config:" not in out

    def test_list_degrades_when_integrations_unreachable(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))

        def boom(*a, **k):
            raise SystemExit("GET /integrations → 401")

        monkeypatch.setattr(eesel, "fetch_integrations", boom)
        rc = eesel.cmd_triggers(_args(triggers_cmd="list", json=False))
        out = capsys.readouterr().out
        assert rc == 0
        # zendesk integration_id can't be resolved to a type → prefix label used.
        assert "zendesk (1)" in out and "intercom (1)" in out

    def test_list_redacts_secrets_in_config(self, fake_creds, monkeypatch, capsys):
        triggers = [{
            "id": "ic-1", "type": "WEBHOOK", "trigger_key": "intercom_conversation_replied",
            "config": {"access_token": "tok-LEAK", "app_id": "abc"},
            "integration_id": None, "agent_id": "a1", "agent_name": "Bot",
        }]
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: triggers)
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: [])
        eesel.cmd_triggers(_args(triggers_cmd="list", json=False))
        out = capsys.readouterr().out
        assert "tok-LEAK" not in out
        assert '"access_token": "***"' in out
        assert "abc" in out  # non-secret config still shown


class TestSchedulesList:
    def test_list_shows_scheduled_jobs_only(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))
        rc = eesel.cmd_schedules(_args(schedules_cmd="list", json=False))
        out = capsys.readouterr().out
        assert rc == 0
        assert "Heartbeat" in out and "cron=0 9 * * *" in out
        # Event triggers are not listed by the schedules view.
        assert "zendesk_ticket_created" not in out

    def test_list_json_emits_scheduled_payload(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))
        eesel.cmd_schedules(_args(schedules_cmd="list", json=True))
        payload = json.loads(capsys.readouterr().out)
        assert {t["id"] for t in payload} == {"sch-1"}

    def test_list_empty_hints_at_add(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: [])
        rc = eesel.cmd_schedules(_args(schedules_cmd="list", json=False))
        assert rc == 0
        assert "no scheduled jobs" in capsys.readouterr().err


class TestTriggersRegistry:
    _REGISTRY = [
        {"trigger_id": "eesel_scheduled", "integration_key": "eesel", "name": "Scheduled", "description": "Run on a cron schedule"},
        {"trigger_id": "zendesk_ticket_created", "integration_key": "zendesk", "name": "Ticket created", "description": "A new ticket"},
    ]

    def test_registry_calls_endpoint_and_lists_keys(self, fake_creds, monkeypatch, capsys):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["method"], captured["url"] = method, url
            return {"triggers": list(self._REGISTRY)}

        monkeypatch.setattr(eesel, "http_request", fake)
        rc = eesel.cmd_triggers(_args(triggers_cmd="registry", json=False))
        assert rc == 0
        assert captured["method"] == "GET"
        assert captured["url"] == "http://localhost:8080/triggers/registry"
        cap = capsys.readouterr()
        # The registry's trigger_id is the key the user passes to `add --key`.
        assert "zendesk_ticket_created" in cap.out
        # The scheduled-job type is filtered out — it's created via `eesel schedules add`.
        assert "eesel_scheduled" not in cap.out

    def test_registry_json_excludes_scheduled_type(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"triggers": list(self._REGISTRY)})
        rc = eesel.cmd_triggers(_args(triggers_cmd="registry", json=True))
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        # Only event trigger types; the scheduled-job sentinel is filtered out.
        assert {t["trigger_id"] for t in payload} == {"zendesk_ticket_created"}

    def test_registry_empty(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"triggers": []})
        rc = eesel.cmd_triggers(_args(triggers_cmd="registry", json=False))
        assert rc == 0
        assert "no trigger types" in capsys.readouterr().err


class TestTriggersAdd:
    def _agents(self):
        return [{"agent_id": "agent-test-456", "name": "Support Bot", "agent_type": "support"}]

    def test_add_posts_trigger_key_and_config(self, fake_creds, monkeypatch, capsys):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["method"], captured["url"], captured["body"] = method, url, body
            return {"trigger": {"id": "trg-new-1", "trigger_key": "zendesk_ticket_created"}}

        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "http_request", fake)
        rc = eesel.cmd_triggers(_args(triggers_cmd="add", agent="Support Bot", key="zendesk_ticket_created", config='{"foo": "bar"}'))
        assert rc == 0
        assert captured["method"] == "POST"
        assert captured["url"] == "http://localhost:8080/agents/agent-test-456/triggers"
        assert captured["body"] == {"trigger_key": "zendesk_ticket_created", "config": {"foo": "bar"}}
        err_out = capsys.readouterr().err
        assert "trg-new-1" in err_out

    def test_add_defaults_config_to_empty_object(self, fake_creds, monkeypatch):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["body"] = body
            return {"trigger": {"id": "trg-new-2"}}

        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "http_request", fake)
        rc = eesel.cmd_triggers(_args(triggers_cmd="add", agent="agent-test-456", key="public_chat", config=None))
        assert rc == 0
        # Server rejects a null config, so an omitted --config must become {}.
        assert captured["body"] == {"trigger_key": "public_chat", "config": {}}

    def test_add_unknown_agent_errors(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        sent = {"called": False}
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: sent.__setitem__("called", True))
        rc = eesel.cmd_triggers(_args(triggers_cmd="add", agent="nope", key="zendesk_ticket_created", config=None))
        assert rc == 1
        assert sent["called"] is False

    def test_add_invalid_json_config_errors(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        sent = {"called": False}
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: sent.__setitem__("called", True))
        rc = eesel.cmd_triggers(_args(triggers_cmd="add", agent="Support Bot", key="zendesk_ticket_created", config="{not json"))
        assert rc == 1
        assert sent["called"] is False

    def test_add_non_object_config_errors(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        sent = {"called": False}
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: sent.__setitem__("called", True))
        rc = eesel.cmd_triggers(_args(triggers_cmd="add", agent="Support Bot", key="zendesk_ticket_created", config='["a", "b"]'))
        assert rc == 1
        assert sent["called"] is False


class TestTriggersShow:
    def test_show_finds_trigger_by_id(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))
        rc = eesel.cmd_triggers(_args(triggers_cmd="show", trigger_id="zd-1", json=False))
        out = capsys.readouterr().out
        assert rc == 0
        assert "zd-1" in out
        assert "zendesk_ticket_created" in out
        assert "WEBHOOK" in out

    def test_show_resolves_by_id_prefix(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))
        rc = eesel.cmd_triggers(_args(triggers_cmd="show", trigger_id="ic", json=False))
        out = capsys.readouterr().out
        assert rc == 0
        assert "intercom_conversation_replied" in out

    def test_show_json_emits_raw_payload(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))
        rc = eesel.cmd_triggers(_args(triggers_cmd="show", trigger_id="zd-1", json=True))
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["id"] == "zd-1"

    def test_show_redacts_secrets(self, fake_creds, monkeypatch, capsys):
        triggers = [{
            "id": "zd-1", "type": "WEBHOOK", "trigger_key": "zendesk_ticket_created",
            "config": {"access_token": "tok-LEAK", "app_id": "abc"},
            "integration_id": None, "agent_id": "a1", "agent_name": "Bot",
        }]
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: triggers)
        eesel.cmd_triggers(_args(triggers_cmd="show", trigger_id="zd-1", json=False))
        out = capsys.readouterr().out
        assert "tok-LEAK" not in out and '"access_token": "***"' in out

    def test_show_unknown_id_errors(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))
        rc = eesel.cmd_triggers(_args(triggers_cmd="show", trigger_id="nope", json=False))
        assert rc == 1
        assert "No event/webhook trigger matches" in capsys.readouterr().err


class TestTriggersRemove:
    # `remove` resolves its id argument (full id or prefix) against the
    # workspace-wide trigger list before issuing the DELETE, so each test seeds
    # that list with the row it targets.
    def _seed(self, monkeypatch, *ids):
        rows = [{"id": i, "trigger_key": "eesel", "agent_name": "A"} for i in ids]
        monkeypatch.setattr(eesel, "fetch_all_event_triggers", lambda creds: rows)

    def test_remove_with_force_skips_confirm(self, fake_creds, monkeypatch, capsys):
        self._seed(monkeypatch, "trg-1")
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["method"], captured["url"] = method, url
            return {"message": "Trigger removed"}

        monkeypatch.setattr(eesel, "http_request", fake)
        monkeypatch.setattr(eesel, "confirm", lambda *a, **k: pytest.fail("--force must skip confirm"))
        rc = eesel.cmd_triggers(_args(triggers_cmd="remove", trigger_id="trg-1", force=True))
        assert rc == 0
        assert captured["method"] == "DELETE"
        assert captured["url"] == "http://localhost:8080/triggers/trg-1"
        assert "Removed trigger trg-1" in capsys.readouterr().err

    def test_remove_prompts_and_proceeds_on_yes(self, fake_creds, monkeypatch):
        self._seed(monkeypatch, "trg-2")
        captured = {}
        monkeypatch.setattr(eesel, "confirm", lambda prompt: True)
        monkeypatch.setattr(eesel, "http_request", lambda method, url, **k: captured.update(method=method, url=url) or {})
        rc = eesel.cmd_triggers(_args(triggers_cmd="remove", trigger_id="trg-2", force=False))
        assert rc == 0
        assert captured == {"method": "DELETE", "url": "http://localhost:8080/triggers/trg-2"}

    def test_remove_aborts_when_not_confirmed(self, fake_creds, monkeypatch):
        self._seed(monkeypatch, "trg-3")
        sent = {"called": False}
        monkeypatch.setattr(eesel, "confirm", lambda prompt: False)
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: sent.__setitem__("called", True))
        rc = eesel.cmd_triggers(_args(triggers_cmd="remove", trigger_id="trg-3", force=False))
        assert rc == 1
        assert sent["called"] is False

    def test_remove_resolves_prefix_to_full_id(self, fake_creds, monkeypatch):
        # A prefix resolves to the full id client-side; the DELETE carries the
        # full id, never the raw prefix (which the server has no row for → 500).
        self._seed(monkeypatch, "trg-aaaa-1111", "trg-bbbb-2222")
        calls = _capture_requests(monkeypatch)
        rc = eesel.cmd_triggers(_args(triggers_cmd="remove", trigger_id="trg-aaaa", force=True))
        assert rc == 0
        assert calls[0]["method"] == "DELETE"
        assert calls[0]["url"].endswith("/triggers/trg-aaaa-1111")

    def test_remove_unknown_id_errors_without_request(self, fake_creds, monkeypatch, capsys):
        self._seed(monkeypatch, "trg-aaaa-1111")
        calls = _capture_requests(monkeypatch)
        rc = eesel.cmd_triggers(_args(triggers_cmd="remove", trigger_id="nope", force=True))
        assert rc == 1
        assert calls == []  # no DELETE fired for a non-matching id
        assert "No event/webhook trigger matches" in capsys.readouterr().err

    def test_remove_ambiguous_prefix_refuses_without_request(self, fake_creds, monkeypatch, capsys):
        # Two triggers whose ids share the given prefix: removing must refuse and
        # list the candidates rather than delete an arbitrary first match. This is
        # the same strict-resolution guard the destructive schedules/agents/mcp
        # paths use; --force does not override it.
        self._seed(monkeypatch, "trg-shared-1111", "trg-shared-2222")
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: pytest.fail("must not DELETE an ambiguous trigger"))
        rc = eesel.cmd_triggers(_args(triggers_cmd="remove", trigger_id="trg-shared", force=True))
        assert rc == 1
        out = capsys.readouterr().err
        assert "ambiguous" in out
        assert "trg-shared-1111" in out and "trg-shared-2222" in out


class TestSchedulesFire:
    def _match(self):
        return {"id": "sch-1", "agent_name": "Support Bot", "config": {"title": "Heartbeat"}}

    def test_fire_fires_scheduled_job(self, fake_creds, monkeypatch, capsys):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["method"], captured["url"] = method, url
            return {"scheduled_at": "2026-06-24T09:00:00+00:00", "external_reference": "schedule_sch-1_x"}

        monkeypatch.setattr(eesel, "resolve_scheduled_job_strict", lambda creds, t: self._match())
        monkeypatch.setattr(eesel, "http_request", fake)
        rc = eesel.cmd_schedules(_args(schedules_cmd="fire", job="heartbeat"))
        assert rc == 0
        assert captured["method"] == "POST"
        assert captured["url"] == "http://localhost:8080/triggers/sch-1/fire"
        assert "Fired 'Heartbeat'" in capsys.readouterr().err

    def test_run_alias_is_no_longer_accepted(self):
        # `run` was a backward-compat alias for `fire`; it is removed and no
        # longer parses under `automations schedules`.
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["automations", "schedules", "run", "heartbeat"])

    def test_fire_no_match_errors(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "resolve_scheduled_job_strict", lambda creds, t: None)
        sent = {"called": False}
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: sent.__setitem__("called", True))
        rc = eesel.cmd_schedules(_args(schedules_cmd="fire", job="nope"))
        assert rc == 1
        assert sent["called"] is False

    def test_fire_ambiguous_job_refuses_without_request(self, fake_creds, monkeypatch, capsys):
        # A title substring matching two jobs must refuse and list candidates
        # rather than fire an arbitrary first match.
        jobs = [
            {"id": "sch-aa", "config": {"title": "Daily report"}, "agent_name": "Bot"},
            {"id": "sch-bb", "config": {"title": "Weekly report"}, "agent_name": "Bot"},
        ]
        monkeypatch.setattr(eesel, "fetch_all_scheduled_jobs", lambda creds: jobs)
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: pytest.fail("must not fire an ambiguous job"))
        rc = eesel.cmd_schedules(_args(schedules_cmd="fire", job="report"))
        assert rc == 1
        out = capsys.readouterr().err
        assert "ambiguous" in out
        assert "sch-aa" in out and "sch-bb" in out


class TestSchedulesAdd:
    def _agents(self):
        return [{"agent_id": "agent-test-456", "name": "Support Bot", "agent_type": "support"}]

    def test_add_builds_config_from_flags_and_sends_scheduled_key(self, fake_creds, monkeypatch, capsys):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["method"], captured["url"], captured["body"] = method, url, body
            return {"trigger": {"id": "sch-new-1"}}

        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "http_request", fake)
        rc = eesel.cmd_schedules(_args(
            schedules_cmd="add", agent="Support Bot",
            cron="0 9 * * *", prompt="Send the morning digest",
            title="Morning digest", timezone="Europe/London", config=None,
        ))
        assert rc == 0
        assert captured["method"] == "POST"
        assert captured["url"] == "http://localhost:8080/agents/agent-test-456/triggers"
        assert captured["body"] == {
            "trigger_key": "eesel_scheduled",
            "config": {
                "cron": "0 9 * * *", "prompt": "Send the morning digest",
                "title": "Morning digest", "timezone": "Europe/London",
            },
        }
        assert "sch-new-1" in capsys.readouterr().err

    def test_add_flags_win_over_config_json(self, fake_creds, monkeypatch):
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["body"] = body
            return {"trigger": {"id": "sch-new-2"}}

        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "http_request", fake)
        # --config sets cron, but the dedicated --cron flag must override it.
        rc = eesel.cmd_schedules(_args(
            schedules_cmd="add", agent="agent-test-456",
            cron="30 8 * * 1", prompt="Weekly review", title=None, timezone=None,
            config='{"cron": "0 0 * * *", "extra": "kept"}',
        ))
        assert rc == 0
        assert captured["body"]["config"]["cron"] == "30 8 * * 1"
        assert captured["body"]["config"]["prompt"] == "Weekly review"
        assert captured["body"]["config"]["extra"] == "kept"

    def test_add_unknown_agent_errors(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        sent = {"called": False}
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: sent.__setitem__("called", True))
        rc = eesel.cmd_schedules(_args(schedules_cmd="add", agent="nope", cron="0 9 * * *", title=None, timezone=None, config=None))
        assert rc == 1
        assert sent["called"] is False

    def test_add_invalid_json_config_errors(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        sent = {"called": False}
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: sent.__setitem__("called", True))
        rc = eesel.cmd_schedules(_args(schedules_cmd="add", agent="Support Bot", cron="0 9 * * *", title=None, timezone=None, config="{not json"))
        assert rc == 1
        assert sent["called"] is False


class TestSchedulesRemove:
    def test_remove_with_force_skips_confirm(self, fake_creds, monkeypatch, capsys):
        captured = {}
        monkeypatch.setattr(eesel, "resolve_scheduled_job_strict", lambda creds, target: {"id": "sch-1", "config": {"title": "Daily"}, "agent_name": "Bot"})
        monkeypatch.setattr(eesel, "http_request", lambda method, url, **k: captured.update(method=method, url=url) or {})
        monkeypatch.setattr(eesel, "confirm", lambda *a, **k: pytest.fail("--force must skip confirm"))
        rc = eesel.cmd_schedules(_args(schedules_cmd="remove", job="sch-1", force=True))
        assert rc == 0
        assert captured == {"method": "DELETE", "url": "http://localhost:8080/triggers/sch-1"}
        assert "Removed scheduled job sch-1" in capsys.readouterr().err

    def test_remove_aborts_when_not_confirmed(self, fake_creds, monkeypatch):
        sent = {"called": False}
        monkeypatch.setattr(eesel, "resolve_scheduled_job_strict", lambda creds, target: {"id": "sch-2", "config": {}, "agent_name": "Bot"})
        monkeypatch.setattr(eesel, "confirm", lambda prompt: False)
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: sent.__setitem__("called", True))
        rc = eesel.cmd_schedules(_args(schedules_cmd="remove", job="sch-2", force=False))
        assert rc == 1
        assert sent["called"] is False

    def test_delete_alias_is_no_longer_accepted(self):
        # `delete` was a backward-compat alias for `remove`; it is removed and no
        # longer parses under `automations schedules`.
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["automations", "schedules", "delete", "sch-3"])

    def test_remove_unmatched_job_errors_cleanly(self, fake_creds, monkeypatch, capsys):
        # A non-matching value (e.g. a title with a space) must NOT be sent to the
        # server verbatim — it is resolved first, so an unmatched job is a clean
        # error, never an unhandled URL-construction exception.
        monkeypatch.setattr(eesel, "fetch_all_scheduled_jobs", lambda creds: [])
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: pytest.fail("must not call the server on an unmatched job"))
        rc = eesel.cmd_schedules(_args(schedules_cmd="remove", job="No Such Job", force=True))
        assert rc == 1
        assert "No scheduled job matches 'No Such Job'" in capsys.readouterr().err

    def test_remove_ambiguous_job_refuses_without_request(self, fake_creds, monkeypatch, capsys):
        # Two jobs whose titles both contain the target: removing must refuse and
        # list the candidates rather than delete an arbitrary first match.
        jobs = [
            {"id": "sch-aa", "config": {"title": "Daily report"}, "agent_name": "Bot"},
            {"id": "sch-bb", "config": {"title": "Weekly report"}, "agent_name": "Bot"},
        ]
        monkeypatch.setattr(eesel, "fetch_all_scheduled_jobs", lambda creds: jobs)
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: pytest.fail("must not DELETE an ambiguous job"))
        rc = eesel.cmd_schedules(_args(schedules_cmd="remove", job="report", force=True))
        assert rc == 1
        out = capsys.readouterr().err
        assert "ambiguous" in out
        assert "sch-aa" in out and "sch-bb" in out


# ──────────────────────────────────────────────────────────────────────────
# Skills
# ──────────────────────────────────────────────────────────────────────────


_SKILLS_AGENTS = [
    {"agent_id": "agent-abc123", "name": "Support Bot"},
    {"agent_id": "agent-def456", "name": "Blog Writer"},
]


def _capture_skill_requests(monkeypatch, response=None):
    """Recorder for skills tests — same write/read-back simulation as
    `_capture_requests`, but a write with no recorded read-back falls back to the
    skills endpoints' `{"status": "ok"}` shape instead of an agent stub."""
    return _capture_requests(monkeypatch, response, default={"status": "ok"})


def _skills_parse(*argv):
    return eesel.build_parser(staff=False).parse_args(list(argv))


class TestSkillsList:
    def test_list_shows_all_skills_with_status_column(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)

        def fake_http(method, url, *, token=None, body=None, timeout=60, headers=None):
            assert method == "GET"
            # Must ask for every installed skill, not just the enabled ones.
            assert "/agents/agent-abc123/skills" in url
            assert "filter=all" in url
            return [
                {"id": "triage", "name": "Triage", "description": "Sort tickets", "enabled": True},
                {"id": "summarize", "name": "Summarize", "description": "Recap threads", "enabled": False},
            ]

        monkeypatch.setattr(eesel, "http_request", fake_http)
        rc = eesel.cmd_skills(_skills_parse("skills", "list", "Support Bot"))
        out = capsys.readouterr().out
        assert rc == 0
        # Disabled skills are listed too, with their state shown as a column.
        assert "triage" in out and "[on]" in out
        assert "summarize" in out and "[off]" in out

    def test_list_uses_env_agent_when_positional_omitted(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        monkeypatch.setenv("EESEL_AGENT", "agent-abc123")
        captured = {}

        def fake_http(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["url"] = url
            return []

        monkeypatch.setattr(eesel, "http_request", fake_http)
        rc = eesel.cmd_skills(_skills_parse("skills", "list"))
        assert rc == 0
        assert "/agents/agent-abc123/skills" in captured["url"]

    def test_list_multi_agent_no_scope_errors(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.delenv("EESEL_AGENT", raising=False)
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)  # 2 agents
        calls = _capture_skill_requests(monkeypatch)
        rc = eesel.cmd_skills(_skills_parse("skills", "list"))
        assert rc == 1
        assert calls == []  # refused before hitting the skills endpoint
        assert "2 agents" in capsys.readouterr().err

    def test_list_empty_prints_hint(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: [])
        rc = eesel.cmd_skills(_skills_parse("skills", "list", "agent-abc123"))
        assert rc == 0
        assert "no skills installed" in capsys.readouterr().err


class TestSkillsAvailable:
    """`skills list --available` lists the marketplace catalog an agent can
    install from — the ids `skills add` accepts, so a valid <skill_id> is
    discoverable without leaving the CLI."""

    def test_available_requests_available_filter_and_lists_ids(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        captured = {}

        def fake_http(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["url"] = url
            return [
                {"id": "simulation", "name": "Simulate", "description": "Run past tickets"},
                {"id": "translation", "name": "Translate", "description": "Localize replies"},
            ]

        monkeypatch.setattr(eesel, "http_request", fake_http)
        rc = eesel.cmd_skills(_skills_parse("skills", "list", "agent-abc123", "--available"))
        out = capsys.readouterr().out
        assert rc == 0
        assert "filter=available" in captured["url"]  # the catalog, not installed
        assert "simulation" in out and "translation" in out

    def test_available_plain_emits_id_and_name(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: [{"id": "simulation", "name": "Simulate"}])
        rc = eesel.cmd_skills(_skills_parse("skills", "list", "agent-abc123", "--available", "--plain"))
        assert rc == 0
        assert "simulation\tSimulate" in capsys.readouterr().out

    def test_list_json_emits_raw_payload(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        payload = [{"id": "triage", "name": "Triage", "description": "Sort", "enabled": True}]
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: payload)
        rc = eesel.cmd_skills(_skills_parse("skills", "list", "agent-abc123", "--json"))
        assert rc == 0
        assert json.loads(capsys.readouterr().out) == payload

    def test_list_plain_emits_tab_separated_rows(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        monkeypatch.setattr(
            eesel,
            "http_request",
            lambda *a, **k: [
                {"id": "triage", "name": "Triage", "enabled": True},
                {"id": "summarize", "name": "Summarize", "enabled": False},
            ],
        )
        rc = eesel.cmd_skills(_skills_parse("skills", "list", "agent-abc123", "--plain"))
        out = capsys.readouterr().out
        assert rc == 0
        assert "triage\ton\tTriage" in out
        assert "summarize\toff\tSummarize" in out

    def test_list_unknown_agent_errors(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        calls = _capture_skill_requests(monkeypatch)
        rc = eesel.cmd_skills(_skills_parse("skills", "list", "ghost"))
        assert rc == 1
        # fetch_agents was stubbed; no skills request should have fired.
        assert calls == []
        assert "No agent matches" in capsys.readouterr().err


class TestSkillsShow:
    def test_show_prints_matching_skill(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        monkeypatch.setattr(
            eesel,
            "http_request",
            lambda *a, **k: [
                {"id": "triage", "name": "Triage", "enabled": True},
                {"id": "summarize", "name": "Summarize", "enabled": False},
            ],
        )
        rc = eesel.cmd_skills(_skills_parse("skills", "show", "agent-abc123", "summarize"))
        out = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert out["id"] == "summarize" and out["enabled"] is False

    def test_show_unknown_skill_errors(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: [{"id": "triage"}])
        rc = eesel.cmd_skills(_skills_parse("skills", "show", "agent-abc123", "ghost"))
        assert rc == 1
        assert "No skill 'ghost'" in capsys.readouterr().err


class TestSkillsAdd:
    def test_add_posts_empty_body(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        calls = _capture_skill_requests(monkeypatch, response={"agent_id": "agent-abc123", "skill_id": "triage"})
        rc = eesel.cmd_skills(_skills_parse("skills", "add", "agent-abc123", "triage"))
        assert rc == 0
        assert calls[0]["method"] == "POST"
        assert calls[0]["url"].endswith("/agents/agent-abc123/skills/triage")
        assert calls[0]["body"] == {}
        err = capsys.readouterr().err
        assert "Installed skill 'triage'" in err
        assert "eesel skills list" in err  # readback hint

    def test_add_resolves_agent_by_name(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        calls = _capture_skill_requests(monkeypatch)
        rc = eesel.cmd_skills(_skills_parse("skills", "add", "Blog Writer", "triage"))
        assert rc == 0
        assert calls[0]["url"].endswith("/agents/agent-def456/skills/triage")


class TestSkillsRemove:
    def test_yes_flag_skips_prompt_and_deletes(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        calls = _capture_skill_requests(monkeypatch)
        rc = eesel.cmd_skills(_skills_parse("skills", "remove", "agent-abc123", "triage", "-f"))
        assert rc == 0
        assert calls[0]["method"] == "DELETE"
        assert calls[0]["url"].endswith("/agents/agent-abc123/skills/triage")

    def test_affirmative_confirmation_deletes(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        monkeypatch.setattr("builtins.input", lambda prompt="": "yes")
        calls = _capture_skill_requests(monkeypatch)
        rc = eesel.cmd_skills(_skills_parse("skills", "remove", "agent-abc123", "triage"))
        assert rc == 0
        assert calls[0]["method"] == "DELETE"

    def test_negative_confirmation_aborts_without_request(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        monkeypatch.setattr("builtins.input", lambda prompt="": "")  # bare Enter
        calls = _capture_skill_requests(monkeypatch)
        rc = eesel.cmd_skills(_skills_parse("skills", "remove", "agent-abc123", "triage"))
        assert rc == 1
        assert calls == []


class TestSkillsEdit:
    def test_set_patches_parsed_config_object(self, tmp_config, fake_creds, monkeypatch, capsys):
        # `set` is canonical; it PATCHes (merges) the config so a partial write
        # doesn't drop the skill's other keys.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        calls = _capture_skill_requests(monkeypatch)
        rc = eesel.cmd_skills(
            _skills_parse("skills", "set", "agent-abc123", "triage", "--config", '{"threshold": 3}')
        )
        assert rc == 0
        assert calls[0]["method"] == "PATCH"
        assert calls[0]["url"].endswith("/agents/agent-abc123/skills/triage/config")
        assert calls[0]["body"] == {"threshold": 3}

    def test_set_does_not_send_a_replacing_put(self, tmp_config, fake_creds, monkeypatch, capsys):
        # Guard against a regression to PUT, which replaces the whole config and
        # would silently drop fields the user didn't pass.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        calls = _capture_skill_requests(monkeypatch)
        eesel.cmd_skills(
            _skills_parse("skills", "set", "agent-abc123", "triage", "--config", '{"threshold": 3}')
        )
        assert all(c["method"] != "PUT" for c in calls)

    def test_edit_is_hidden_alias_for_set(self, tmp_config, fake_creds, monkeypatch):
        parser = eesel.build_parser()
        sk_sub = _subparsers_action(_subparsers_action(parser).choices["skills"])
        visible = [a.dest for a in sk_sub._choices_actions]
        assert "set" in visible and "edit" not in visible

    def test_set_patches_multi_key_config_object(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        calls = _capture_skill_requests(monkeypatch)
        rc = eesel.cmd_skills(
            _skills_parse("skills", "set", "agent-abc123", "triage", "--config", '{"threshold": 3, "label": "urgent"}')
        )
        assert rc == 0
        assert calls[0]["method"] == "PATCH"
        assert calls[0]["url"].endswith("/agents/agent-abc123/skills/triage/config")
        assert calls[0]["body"] == {"threshold": 3, "label": "urgent"}

    def test_set_rejects_invalid_json_before_request(self, tmp_config, fake_creds, monkeypatch, capsys):
        # Malformed --config exits with the shared parse_config_object contract
        # (code 2) before any request is sent.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        calls = _capture_skill_requests(monkeypatch)
        with pytest.raises(SystemExit) as exc:
            eesel.cmd_skills(_skills_parse("skills", "set", "agent-abc123", "triage", "--config", "{not json"))
        assert exc.value.code == 2
        assert calls == []
        assert "not valid JSON" in capsys.readouterr().err

    def test_set_rejects_non_object_json(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _SKILLS_AGENTS)
        calls = _capture_skill_requests(monkeypatch)
        with pytest.raises(SystemExit) as exc:
            eesel.cmd_skills(_skills_parse("skills", "set", "agent-abc123", "triage", "--config", "[1, 2, 3]"))
        assert exc.value.code == 2
        assert calls == []
        assert "must be a JSON object" in capsys.readouterr().err


class TestSkillsArgParser:
    def test_list_parses(self):
        args = _skills_parse("skills", "list", "my-agent")
        assert args.cmd == "skills"
        assert args.skills_cmd == "list"
        assert args.agent == "my-agent"
        assert args.func is eesel.cmd_skills

    def test_list_agent_is_optional(self):
        args = _skills_parse("skills", "list")
        assert args.skills_cmd == "list"
        assert args.agent is None

    def test_add_requires_skill_id(self):
        with pytest.raises(SystemExit):
            _skills_parse("skills", "add", "my-agent")  # missing skill_id

    def test_remove_yes_flag_parses(self):
        args = _skills_parse("skills", "remove", "my-agent", "skill-1", "-f")
        assert args.skills_cmd == "remove"
        assert args.force is True

    def test_show_parses(self):
        args = _skills_parse("skills", "show", "my-agent", "skill-1")
        assert args.skills_cmd == "show"
        assert args.skill_id == "skill-1"

    def test_set_requires_config(self):
        with pytest.raises(SystemExit):
            _skills_parse("skills", "set", "my-agent", "skill-1")  # missing --config


# ──────────────────────────────────────────────────────────────────────────
# MCP servers
# ──────────────────────────────────────────────────────────────────────────


def _mcp_capture(monkeypatch, response=None):
    """Replace http_request with a recorder; returns the list of calls made.

    Default response carries an id so create can echo it; pass response={} for
    the endpoints whose return value the CLI ignores (toggle/delete/edit)."""
    calls = []

    def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
        calls.append({"method": method, "url": url, "body": body})
        return response if response is not None else {"id": "mcp-new-999"}

    monkeypatch.setattr(eesel, "http_request", fake)
    return calls


def _mcp_parse(*argv):
    return eesel.build_parser(staff=False).parse_args(list(argv))


class TestMcpAddBody:
    def test_url_maps_to_base_url(self):
        body = eesel._mcp_create_body("Srv", "https://mcp.example.com")
        assert body == {"name": "Srv", "base_url": "https://mcp.example.com"}

    def test_config_merged_but_name_and_url_win(self):
        body = eesel._mcp_create_body(
            "Srv",
            "https://real",
            {"auth_type": "bearer", "auth_token": "tok", "name": "ignored", "base_url": "ignored"},
        )
        assert body == {
            "auth_type": "bearer",
            "auth_token": "tok",
            "name": "Srv",
            "base_url": "https://real",
        }


class TestMcpUpdateBody:
    def test_empty_when_nothing_passed(self):
        assert eesel._mcp_update_body() == {}

    def test_name_only(self):
        assert eesel._mcp_update_body(name="Renamed") == {"name": "Renamed"}

    def test_url_maps_to_base_url(self):
        assert eesel._mcp_update_body(url="https://new") == {"base_url": "https://new"}

    def test_both(self):
        assert eesel._mcp_update_body(name="N", url="https://u") == {
            "name": "N",
            "base_url": "https://u",
        }


class TestResolveMcpServer:
    SERVERS = [
        {"id": "srv-abc123", "name": "Alpha"},
        {"id": "srv-def456", "name": "Beta"},
    ]

    def test_exact_id(self):
        assert eesel.resolve_mcp_server(self.SERVERS, "srv-abc123")["name"] == "Alpha"

    def test_id_prefix(self):
        assert eesel.resolve_mcp_server(self.SERVERS, "srv-def")["name"] == "Beta"

    def test_exact_name(self):
        assert eesel.resolve_mcp_server(self.SERVERS, "Alpha")["id"] == "srv-abc123"

    def test_no_match_returns_none(self):
        assert eesel.resolve_mcp_server(self.SERVERS, "nope") is None

    def test_strict_resolver_refuses_ambiguous_prefix(self, fake_creds, monkeypatch, capsys):
        # Two servers sharing an id prefix: the write/destructive resolver must
        # refuse and list candidates rather than act on an arbitrary one.
        servers = [
            {"id": "srv-shared-1", "name": "One"},
            {"id": "srv-shared-2", "name": "Two"},
        ]
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: servers)
        assert eesel._resolve_one_mcp_server(fake_creds, "srv-shared") is None
        out = capsys.readouterr().err
        assert "ambiguous" in out
        assert "srv-shared-1" in out and "srv-shared-2" in out


class TestMcpListCommand:
    def test_lists_servers_with_state(self, tmp_config, fake_creds, monkeypatch, capsys):
        servers = [
            {"id": "srv-abc123", "name": "Alpha", "base_url": "https://a", "is_active": True},
            {"id": "srv-def456", "name": "Beta", "base_url": "https://b", "is_active": False},
        ]
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: servers)
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "list"))
        out = capsys.readouterr().out
        assert rc == 0
        assert "Alpha" in out and "https://a" in out and "[on]" in out
        assert "Beta" in out and "[off]" in out

    def test_json_emits_raw_payload(self, tmp_config, fake_creds, monkeypatch, capsys):
        servers = [{"id": "srv-abc123", "name": "Alpha", "base_url": "https://a", "is_active": True}]
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: servers)
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "list", "--json"))
        out = capsys.readouterr().out
        assert rc == 0
        assert json.loads(out) == servers

    def test_list_plain_emits_tab_separated_rows(self, tmp_config, fake_creds, monkeypatch, capsys):
        # `--plain` emits one decoration-free, tab-separated row per server:
        # id<TAB>state<TAB>name<TAB>url. The human view's bracketed status
        # markers are absent, confirming the human formatter was bypassed.
        servers = [
            {"id": "srv-abc123", "name": "Alpha", "base_url": "https://a", "is_active": True},
            {"id": "srv-def456", "name": "Beta", "base_url": "https://b", "is_active": False},
        ]
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: servers)
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "list", "--plain"))
        assert rc == 0
        out = capsys.readouterr().out
        lines = out.strip().splitlines()
        assert lines == [
            "srv-abc123\ton\tAlpha\thttps://a",
            "srv-def456\toff\tBeta\thttps://b",
        ]
        assert "[on]" not in out and "[off]" not in out

    def test_empty_list(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: [])
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "list"))
        assert rc == 0
        assert "no MCP servers" in capsys.readouterr().err

    def test_bare_mcp_defaults_to_list(self):
        # `eesel mcp` with no subcommand dispatches to the list view.
        args = _mcp_parse("mcp")
        assert args.func is eesel.cmd_mcp
        assert args.mcp_cmd == "list"

    def test_fetch_hits_workspace_scoped_path(self, tmp_config, fake_creds, monkeypatch):
        calls = _mcp_capture(monkeypatch, response={"mcp_servers": []})
        eesel.fetch_mcp_servers(fake_creds)
        assert calls[0]["method"] == "GET"
        assert "/workspaces/ws-test-123/mcp-servers" in calls[0]["url"]


class TestMcpAddCommand:
    def test_posts_base_url_and_prints_id(self, tmp_config, fake_creds, monkeypatch, capsys):
        calls = _mcp_capture(monkeypatch)
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "add", "--name", "Alpha", "--url", "https://a"))
        assert rc == 0
        assert calls[0]["method"] == "POST"
        assert calls[0]["url"].endswith("/workspaces/ws-test-123/mcp-servers")
        assert calls[0]["body"] == {"name": "Alpha", "base_url": "https://a"}
        assert "mcp-new-999" in capsys.readouterr().err  # ok() writes to stderr

    def test_config_json_is_merged(self, tmp_config, fake_creds, monkeypatch):
        calls = _mcp_capture(monkeypatch)
        rc = eesel.cmd_mcp(
            _mcp_parse("mcp", "add", "--name", "Alpha", "--url", "https://a",
                       "--config", '{"auth_type": "bearer", "auth_token": "tok"}')
        )
        assert rc == 0
        assert calls[0]["body"] == {
            "auth_type": "bearer",
            "auth_token": "tok",
            "name": "Alpha",
            "base_url": "https://a",
        }

    def test_invalid_config_json_fails_before_request(self, tmp_config, fake_creds, monkeypatch, capsys):
        calls = _mcp_capture(monkeypatch)
        rc = eesel.cmd_mcp(
            _mcp_parse("mcp", "add", "--name", "A", "--url", "https://a", "--config", "{not json}")
        )
        assert rc == 1
        assert calls == []
        assert "valid JSON" in capsys.readouterr().err


class TestMcpShowCommand:
    SERVERS = [
        {"id": "srv-abc123", "name": "Alpha", "base_url": "https://a",
         "is_active": True, "auth_type": "bearer", "has_auth_token": True},
    ]

    def test_shows_one_servers_detail(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "show", "srv-abc123"))
        out = capsys.readouterr().out
        assert rc == 0
        assert "srv-abc123" in out and "https://a" in out and "bearer" in out

    def test_json_emits_raw_server(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "show", "srv-abc123", "--json"))
        out = capsys.readouterr().out
        assert rc == 0
        assert json.loads(out) == self.SERVERS[0]

    def test_unknown_target_errors(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "show", "nope"))
        assert rc == 1


class TestMcpEditCommand:
    SERVERS = [
        {"id": "srv-abc123", "name": "Alpha", "base_url": "https://a", "is_active": True},
        {"id": "srv-def456", "name": "Beta", "base_url": "https://b", "is_active": True},
    ]

    def test_sends_only_provided_field(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "set", "srv-abc123", "--name", "Renamed"))
        assert rc == 0
        assert calls[0]["method"] == "PUT"
        assert calls[0]["url"].endswith("/workspaces/ws-test-123/mcp-servers/srv-abc123")
        assert calls[0]["body"] == {"name": "Renamed"}

    def test_set_is_canonical_and_edit_is_removed(self, tmp_config, fake_creds, monkeypatch):
        # `set` is canonical and does the PUT; the former `edit` alias is removed.
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "set", "srv-abc123", "--name", "Renamed"))
        assert rc == 0 and calls[0]["body"] == {"name": "Renamed"}
        m_sub = _subparsers_action(_subparsers_action(eesel.build_parser()).choices["mcp"])
        visible = [a.dest for a in m_sub._choices_actions]
        assert "set" in visible and "edit" not in visible
        with pytest.raises(SystemExit):
            _mcp_parse("mcp", "edit", "srv-abc123", "--name", "X")

    def test_url_only_sends_base_url(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        eesel.cmd_mcp(_mcp_parse("mcp", "set", "srv-abc123", "--url", "https://new"))
        assert calls[-1]["body"] == {"base_url": "https://new"}

    def test_nothing_to_update_fails(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "set", "srv-abc123"))
        assert rc == 1
        assert calls == []

    def test_unknown_target_errors(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "set", "nope", "--name", "X"))
        assert rc == 1
        assert calls == []


class TestMcpToggleCommands:
    SERVERS = [{"id": "srv-abc123", "name": "Alpha", "base_url": "https://a", "is_active": False}]

    def test_enable_posts_true(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "enable", "srv-abc123"))
        assert rc == 0
        assert calls[0]["method"] == "POST"
        assert calls[0]["url"].endswith("/workspaces/ws-test-123/mcp-servers/srv-abc123/toggle")
        assert calls[0]["body"] == {"is_active": True}

    def test_disable_posts_false(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "disable", "srv-abc123"))
        assert rc == 0
        assert calls[0]["body"] == {"is_active": False}
        assert calls[0]["url"].endswith("/toggle")


class TestMcpRemoveCommand:
    SERVERS = [{"id": "srv-abc123", "name": "Alpha", "base_url": "https://a", "is_active": True}]

    def test_force_flag_skips_prompt_and_removes(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "remove", "srv-abc123", "--force"))
        assert rc == 0
        assert calls[0]["method"] == "DELETE"
        assert calls[0]["url"].endswith("/workspaces/ws-test-123/mcp-servers/srv-abc123")

    def test_short_f_flag_also_skips_prompt(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "remove", "srv-abc123", "-f"))
        assert rc == 0
        assert calls[0]["method"] == "DELETE"

    def test_affirmative_confirmation_removes(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        monkeypatch.setattr("builtins.input", lambda prompt="": "yes")
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "remove", "srv-abc123"))
        assert rc == 0
        assert calls[0]["method"] == "DELETE"

    def test_negative_confirmation_aborts_without_request(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        monkeypatch.setattr("builtins.input", lambda prompt="": "")  # bare Enter
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "remove", "srv-abc123"))
        assert rc == 1
        assert calls == []

    def test_unknown_target_errors_without_request(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "remove", "nope", "--force"))
        assert rc == 1
        assert calls == []


# ──────────────────────────────────────────────────────────────────────────
# workspace — operate on the active workspace (creds["workspace_id"])
# ──────────────────────────────────────────────────────────────────────────


def _record_requests(monkeypatch, responses):
    """Replace http_request with a recorder that returns a response chosen by a
    `(method, url-substring) -> dict` mapping. The first matching entry wins;
    unmatched calls return {}. Returns the list of recorded calls."""
    calls = []

    def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
        calls.append({"method": method, "url": url, "body": body, "token": token})
        for (m, frag), resp in responses.items():
            if method == m and frag in url:
                return resp
        return {}

    monkeypatch.setattr(eesel, "http_request", fake)
    return calls


class TestWorkspaceShow:
    WS = {
        "workspaceId": "ws-test-123",
        "workspaceName": "Acme",
        "workspaceOwnerUserId": "auth0|owner",
        "trialDurationDays": 14,
        "stripeSubscriptionId": "sub_1",
        "stripeCustomerId": "cus_1",
        "onboarding_completed": True,
        "dataResidency": None,
        "namespaces": ["ns-1", "ns-2"],
    }

    def test_show_calls_workspace_endpoint_and_prints_fields(self, tmp_config, fake_creds, monkeypatch, capsys):
        calls = _record_requests(monkeypatch, {("GET", "/workspaces/ws-test-123"): self.WS})
        rc = eesel.cmd_workspace(_args(workspace_cmd="show", json=False))
        assert rc == 0
        assert calls[0]["method"] == "GET"
        assert calls[0]["url"] == "http://localhost:8080/workspaces/ws-test-123"
        out = capsys.readouterr().out
        assert "workspaceName" in out and "Acme" in out
        assert "trialDurationDays" in out and "14" in out
        # The large structural field is omitted from the default view.
        assert "namespaces" not in out

    def test_show_is_the_default_subcommand(self, tmp_config, fake_creds, monkeypatch, capsys):
        _record_requests(monkeypatch, {("GET", "/workspaces/"): self.WS})
        rc = eesel.cmd_workspace(_args(workspace_cmd=None, json=False))
        assert rc == 0
        assert "Acme" in capsys.readouterr().out

    def test_show_json_emits_raw_payload(self, tmp_config, fake_creds, monkeypatch, capsys):
        _record_requests(monkeypatch, {("GET", "/workspaces/"): self.WS})
        rc = eesel.cmd_workspace(_args(workspace_cmd="show", json=True))
        assert rc == 0
        assert json.loads(capsys.readouterr().out) == self.WS


class TestWorkspaceSetName:
    def test_set_name_puts_workspace_name_then_reads_back(self, tmp_config, fake_creds, monkeypatch, capsys):
        calls = _record_requests(
            monkeypatch,
            {
                ("PUT", "/workspaces/ws-test-123"): {"message": "Workspace updated successfully"},
                ("GET", "/workspaces/ws-test-123"): {"workspaceName": "Renamed"},
            },
        )
        rc = eesel.cmd_workspace(_args(workspace_cmd="set", field="name", value="Renamed"))
        assert rc == 0
        # First call is the PUT with the workspaceName body; the field name must
        # match the server's WorkspaceUpdate schema exactly.
        assert calls[0]["method"] == "PUT"
        assert calls[0]["url"] == "http://localhost:8080/workspaces/ws-test-123"
        assert calls[0]["body"] == {"workspaceName": "Renamed"}
        # Second call reads the workspace back (the PUT returns only a message).
        assert calls[1]["method"] == "GET"
        assert "Renamed" in capsys.readouterr().err  # ok() writes to stderr


class TestWorkspaceSetBillingLimit:
    def test_set_billing_limit_posts_value_to_singular_path(self, tmp_config, fake_creds, monkeypatch, capsys):
        calls = _record_requests(monkeypatch, {("POST", "/workspace/billing-limit"): {"status": "success"}})
        rc = eesel.cmd_workspace(_args(workspace_cmd="set", field="billing-limit", value="250"))
        assert rc == 0
        # Path is the SINGULAR /workspace/billing-limit; body field is `value`,
        # and the string positional is coerced to an int.
        assert calls[0]["method"] == "POST"
        assert calls[0]["url"] == "http://localhost:8080/workspace/billing-limit"
        assert calls[0]["body"] == {"value": 250}
        assert "250" in capsys.readouterr().err

    def test_set_billing_limit_rejects_non_integer_before_request(self, tmp_config, fake_creds, monkeypatch, capsys):
        calls = _record_requests(monkeypatch, {})
        rc = eesel.cmd_workspace(_args(workspace_cmd="set", field="billing-limit", value="lots"))
        assert rc == 1
        assert calls == []
        assert "non-negative integer" in capsys.readouterr().err

    def test_set_billing_limit_rejects_negative_before_request(self, tmp_config, fake_creds, monkeypatch, capsys):
        calls = _record_requests(monkeypatch, {})
        rc = eesel.cmd_workspace(_args(workspace_cmd="set", field="billing-limit", value="-5"))
        assert rc == 1
        assert calls == []
        assert "non-negative integer" in capsys.readouterr().err


class TestWorkspaceMembers:
    MEMBERS = [
        {"user_id": "auth0|owner", "email": "owner@acme.com", "role": "editor", "status": "accepted"},
        {"user_id": "auth0|m2", "email": "viewer@acme.com", "role": "viewer", "status": "accepted"},
        {"user_id": None, "email": "invited@acme.com", "role": "editor", "status": "pending"},
    ]

    def test_members_lists_email_and_role(self, tmp_config, fake_creds, monkeypatch, capsys):
        calls = _record_requests(monkeypatch, {("GET", "/members"): {"members": self.MEMBERS}})
        rc = eesel.cmd_workspace(_args(workspace_cmd="members", json=False))
        assert rc == 0
        assert calls[0]["url"] == "http://localhost:8080/workspaces/ws-test-123/members"
        out = capsys.readouterr().out
        assert "owner@acme.com" in out and "editor" in out
        assert "viewer@acme.com" in out and "viewer" in out
        # A non-accepted member surfaces its status.
        assert "invited@acme.com" in out and "pending" in out

    def test_members_accepts_bare_list_response(self, tmp_config, fake_creds, monkeypatch, capsys):
        _record_requests(monkeypatch, {("GET", "/members"): self.MEMBERS})
        rc = eesel.cmd_workspace(_args(workspace_cmd="members", json=False))
        assert rc == 0
        assert "owner@acme.com" in capsys.readouterr().out

    def test_members_empty_is_clean_exit(self, tmp_config, fake_creds, monkeypatch, capsys):
        _record_requests(monkeypatch, {("GET", "/members"): {"members": []}})
        rc = eesel.cmd_workspace(_args(workspace_cmd="members", json=False))
        assert rc == 0
        assert "no members" in capsys.readouterr().err


class TestWorkspaceExtendTrial:
    def test_extend_trial_posts_and_prints_message(self, tmp_config, fake_creds, monkeypatch, capsys):
        calls = _record_requests(
            monkeypatch,
            {("POST", "/subscription/extend-trial"): {"success": True, "message": "Trial extended successfully"}},
        )
        rc = eesel.cmd_workspace(_args(workspace_cmd="extend-trial"))
        assert rc == 0
        assert calls[0]["method"] == "POST"
        assert calls[0]["url"] == "http://localhost:8080/subscription/extend-trial"
        assert calls[0]["body"] == {}
        assert "Trial extended successfully" in capsys.readouterr().err


class TestWorkspaceParser:
    def _parse(self, *argv):
        return eesel.build_parser(staff=False).parse_args(list(argv))

    def test_registered_with_show_default(self):
        args = self._parse("workspace")
        assert args.func is eesel.cmd_workspace
        assert args.workspace_cmd is None  # cmd_workspace defaults to "show"

    def test_set_name_takes_field_and_value_positionals(self):
        args = self._parse("workspace", "set", "name", "New Name")
        assert args.workspace_cmd == "set"
        assert args.field == "name"
        assert args.value == "New Name"

    def test_set_billing_limit_keeps_value_as_string(self):
        # The value positional is parsed as a string for every field; the
        # billing-limit handler coerces and validates the integer itself.
        args = self._parse("workspace", "set", "billing-limit", "300")
        assert args.workspace_cmd == "set"
        assert args.field == "billing-limit"
        assert args.value == "300"

    def test_set_rejects_unknown_field(self):
        # `field` is constrained by choices, so an unknown field is a parse error.
        with pytest.raises(SystemExit):
            self._parse("workspace", "set", "color", "blue")

    def test_members_and_extend_trial_register(self):
        assert self._parse("workspace", "members").workspace_cmd == "members"
        assert self._parse("workspace", "extend-trial").workspace_cmd == "extend-trial"


# ──────────────────────────────────────────────────────────────────────────
# Billing (read-only subscription views)
# ──────────────────────────────────────────────────────────────────────────


def _record_http(monkeypatch, response):
    """Replace http_request with a recorder returning `response`. Returns the
    list of recorded calls so a test can assert method/url."""
    calls = []

    def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
        calls.append({"method": method, "url": url, "body": body})
        return response

    monkeypatch.setattr(eesel, "http_request", fake)
    return calls


class TestBillingCommand:
    def test_bare_billing_shows_usage(self, fake_creds, monkeypatch, capsys):
        calls = _record_http(monkeypatch, {
            "numMessages": 12, "maxMessages": 100,
            "numNamespaces": 3, "maxNamespaces": 5,
            "numLearningJobs": 1, "maxLearningJobs": 10,
            "costConsumed": 4.5,
            "numLightTasks": 2, "numRegularTasks": 1, "numHeavyTasks": 0,
            "limitReached": False,
        })
        # `eesel billing` with no subcommand falls back to `show usage`.
        rc = eesel.cmd_billing(_args(billing_cmd=None, topic=None, json=False, plain=False))
        assert rc == 0
        assert calls[0]["method"] == "GET"
        assert calls[0]["url"].endswith("/subscription/usage")
        out = capsys.readouterr().out
        assert "12 / 100" in out
        assert "$4.50" in out

    def test_show_license_hits_license_endpoint_and_summarizes(self, fake_creds, monkeypatch, capsys):
        calls = _record_http(monkeypatch, {
            "isActive": True,
            "planName": "Team",
            "subscriptionStatus": "active",
            "subscriptionSource": "STRIPE",
            "billingPeriodStart": "2026-06-01T00:00:00+00:00",
            "billingPeriodEnd": "2026-07-01T00:00:00+00:00",
            "features": ["AI_AGENTS", "ANALYTICS"],
            "pricing": {"lightTaskDollars": 0.01, "regularTaskDollars": 0.05, "heavyTaskDollars": 0.2},
        })
        rc = eesel.cmd_billing(_args(billing_cmd="show", topic="license", json=False, plain=False))
        assert rc == 0
        assert calls[0]["url"].endswith("/subscription/license")
        out = capsys.readouterr().out
        assert "Team" in out
        assert "AI_AGENTS, ANALYTICS" in out

    def test_list_invoices_endpoint_and_empty_list(self, fake_creds, monkeypatch, capsys):
        calls = _record_http(monkeypatch, [])
        rc = eesel.cmd_billing(_args(billing_cmd="list", kind="invoices", json=False, plain=False))
        assert rc == 0
        assert calls[0]["url"].endswith("/subscription/invoices")
        assert "(no invoices)" in capsys.readouterr().err

    def test_list_spend_endpoint_totals_amounts(self, fake_creds, monkeypatch, capsys):
        calls = _record_http(monkeypatch, [
            {"date": "2026-06-01", "amount": 1.5},
            {"date": "2026-06-02", "amount": 2.25},
        ])
        rc = eesel.cmd_billing(_args(billing_cmd="list", kind="spend", json=False, plain=False))
        assert rc == 0
        assert calls[0]["url"].endswith("/subscription/spend-history")
        out = capsys.readouterr().out
        assert "$3.75" in out  # total

    def test_show_mode_endpoint(self, fake_creds, monkeypatch, capsys):
        calls = _record_http(monkeypatch, {
            "mode": "threshold", "eligible": True, "canSwitchToMonthly": False, "successfulCharges": 2,
        })
        rc = eesel.cmd_billing(_args(billing_cmd="show", topic="mode", json=False, plain=False))
        assert rc == 0
        assert calls[0]["url"].endswith("/subscription/billing-mode")
        assert "threshold" in capsys.readouterr().out

    def test_json_emits_raw_payload(self, fake_creds, monkeypatch, capsys):
        _record_http(monkeypatch, {"mode": "monthly"})
        rc = eesel.cmd_billing(_args(billing_cmd="show", topic="mode", json=True, plain=False))
        assert rc == 0
        assert json.loads(capsys.readouterr().out) == {"mode": "monthly"}

    def test_plain_emits_tab_separated_keyvalues(self, fake_creds, monkeypatch, capsys):
        _record_http(monkeypatch, {"mode": "monthly", "eligible": True})
        rc = eesel.cmd_billing(_args(billing_cmd="show", topic="mode", json=False, plain=True))
        assert rc == 0
        out = capsys.readouterr().out
        assert "mode\tmonthly" in out

    def test_list_plain_emits_tab_separated_columns(self, fake_creds, monkeypatch, capsys):
        _record_http(monkeypatch, [{"date": "2026-06-01", "amount": 1.5}])
        rc = eesel.cmd_billing(_args(billing_cmd="list", kind="spend", json=False, plain=True))
        assert rc == 0
        assert "2026-06-01\t1.5" in capsys.readouterr().out

    def test_unknown_topic_errors(self, fake_creds, monkeypatch, capsys):
        calls = _record_http(monkeypatch, {})
        rc = eesel.cmd_billing(_args(billing_cmd="show", topic="bogus", json=False, plain=False))
        assert rc == 1
        assert calls == []

    def test_parser_bare_billing_defaults_to_show_usage(self):
        args = eesel.build_parser(staff=False).parse_args(["billing"])
        assert args.billing_cmd == "show"
        assert args.topic == "usage"
        assert args.func is eesel.cmd_billing

    def test_parser_show_accepts_each_topic(self):
        for name in ("usage", "license", "mode"):
            args = eesel.build_parser(staff=False).parse_args(["billing", "show", name])
            assert args.billing_cmd == "show"
            assert args.topic == name

    def test_parser_list_accepts_each_kind(self):
        for name in ("invoices", "spend"):
            args = eesel.build_parser(staff=False).parse_args(["billing", "list", name])
            assert args.billing_cmd == "list"
            assert args.kind == name

    def test_parser_show_rejects_unknown_topic(self):
        with pytest.raises(SystemExit):
            eesel.build_parser(staff=False).parse_args(["billing", "show", "invoices"])


# ──────────────────────────────────────────────────────────────────────────
# Settings — agent notification configuration
# ──────────────────────────────────────────────────────────────────────────


_NOTIF_AGENTS = [
    {"agent_id": "agent-test-456", "name": "Support Bot"},
    {"agent_id": "agent-zzz999", "name": "Blog Writer"},
]

_NOTIF_RESPONSE = {
    "enabled": True,
    "channel": "slack",
    "email": {"member_ids": ["u-1", "u-2"]},
    "slack": {"channel_ids": ["C123"]},
}


class TestSettingsNotificationsShow:
    def test_show_hits_endpoint_and_prints_summary(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _NOTIF_AGENTS)
        calls = _record_http(monkeypatch, _NOTIF_RESPONSE)
        rc = eesel.cmd_settings(_args(settings_cmd="notifications", notifications_cmd="show", agent="Support Bot", json=False, plain=False))
        assert rc == 0
        assert calls[0]["method"] == "GET"
        assert calls[0]["url"].endswith("/agents/agent-test-456/notification-settings")
        out = capsys.readouterr().out
        assert "slack" in out
        assert "C123" in out
        assert "u-1, u-2" in out

    def test_show_json_emits_raw_payload(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _NOTIF_AGENTS)
        _record_http(monkeypatch, _NOTIF_RESPONSE)
        rc = eesel.cmd_settings(_args(settings_cmd="notifications", notifications_cmd="show", agent="agent-test-456", json=True, plain=False))
        assert rc == 0
        assert json.loads(capsys.readouterr().out) == _NOTIF_RESPONSE

    def test_show_plain_emits_tab_separated(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _NOTIF_AGENTS)
        _record_http(monkeypatch, _NOTIF_RESPONSE)
        rc = eesel.cmd_settings(_args(settings_cmd="notifications", notifications_cmd="show", agent="agent-test-456", json=False, plain=True))
        assert rc == 0
        out = capsys.readouterr().out
        assert "enabled\tTrue" in out
        assert "slack\tC123" in out

    def test_show_unknown_agent_errors_without_request(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _NOTIF_AGENTS)
        calls = _record_http(monkeypatch, _NOTIF_RESPONSE)
        rc = eesel.cmd_settings(_args(settings_cmd="notifications", notifications_cmd="show", agent="nope", json=False, plain=False))
        assert rc == 1
        assert calls == []


class TestSettingsNotificationsEnableDisable:
    def test_enable_patches_enabled_true(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _NOTIF_AGENTS)
        calls = _record_http(monkeypatch, _NOTIF_RESPONSE)
        rc = eesel.cmd_settings(_args(settings_cmd="notifications", notifications_cmd="enable", agent="agent-zzz999", json=False))
        assert rc == 0
        assert calls[0]["method"] == "PATCH"
        assert calls[0]["url"].endswith("/agents/agent-zzz999/notification-settings")
        assert calls[0]["body"] == {"enabled": True}

    def test_disable_patches_enabled_false(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _NOTIF_AGENTS)
        calls = _record_http(monkeypatch, _NOTIF_RESPONSE)
        rc = eesel.cmd_settings(_args(settings_cmd="notifications", notifications_cmd="disable", agent="agent-zzz999", json=False))
        assert rc == 0
        assert calls[0]["body"] == {"enabled": False}


class TestSettingsNotificationsSet:
    def test_set_patches_only_the_channel_field(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _NOTIF_AGENTS)
        calls = _record_http(monkeypatch, _NOTIF_RESPONSE)
        rc = eesel.cmd_settings(_args(settings_cmd="notifications", notifications_cmd="set", agent="agent-test-456", channel="email", json=False))
        assert rc == 0
        assert calls[0]["method"] == "PATCH"
        assert calls[0]["body"] == {"channel": "email"}

    def test_set_nothing_fails_without_request(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _NOTIF_AGENTS)
        calls = _record_http(monkeypatch, _NOTIF_RESPONSE)
        rc = eesel.cmd_settings(_args(settings_cmd="notifications", notifications_cmd="set", agent="agent-test-456", channel=None, json=False))
        assert rc == 1
        assert calls == []

    def test_set_prints_readback(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: _NOTIF_AGENTS)
        _record_http(monkeypatch, _NOTIF_RESPONSE)
        eesel.cmd_settings(_args(settings_cmd="notifications", notifications_cmd="set", agent="agent-test-456", channel="email", json=False))
        out = capsys.readouterr().out
        # The readback reflects the server response shape (nested email/slack).
        assert "C123" in out


class TestSettingsParser:
    def test_show_parses_agent_positional(self):
        args = eesel.build_parser(staff=False).parse_args(["settings", "notifications", "show", "my-agent"])
        assert args.settings_cmd == "notifications"
        assert args.notifications_cmd == "show"
        assert args.agent == "my-agent"
        assert args.func is eesel.cmd_settings

    def test_enable_disable_parse_agent_positional(self):
        for verb in ("enable", "disable"):
            args = eesel.build_parser(staff=False).parse_args(["settings", "notifications", verb, "my-agent"])
            assert args.notifications_cmd == verb
            assert args.agent == "my-agent"

    def test_set_parses_channel_flag(self):
        args = eesel.build_parser(staff=False).parse_args(
            ["settings", "notifications", "set", "my-agent", "--channel", "slack"]
        )
        assert args.notifications_cmd == "set"
        assert args.channel == "slack"

    def test_set_rejects_invalid_channel(self):
        with pytest.raises(SystemExit):
            eesel.build_parser(staff=False).parse_args(["settings", "notifications", "set", "a", "--channel", "carrier-pigeon"])


class TestParseToolConfig:
    def test_parses_json_object(self):
        assert eesel.parse_tool_config('{"permission_mode": "ask"}') == {"permission_mode": "ask"}

    def test_rejects_malformed_json(self):
        with pytest.raises(ValueError, match="not valid JSON"):
            eesel.parse_tool_config("{not json}")

    def test_rejects_non_object_top_level(self):
        with pytest.raises(ValueError, match="must be a JSON object"):
            eesel.parse_tool_config('"a string"')
        with pytest.raises(ValueError, match="must be a JSON object"):
            eesel.parse_tool_config("[1, 2, 3]")


class TestIntegrationActionsWrite:
    """enable / set / disable on `eesel integrations <integration> actions`."""

    def _agents(self):
        return [
            {"agent_id": "agent-test-456", "name": "Support Bot"},
            {"agent_id": "agent-other-999", "name": "Sales Bot"},
        ]

    def _setup(self, monkeypatch, response=None):
        """Stub agents + integrations resolution and capture the write request.

        The integration positional (e.g. 'zendesk') is resolved to its connected
        instance id via fetch_integrations, so write commands stub it here.
        """
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        captured = {}

        def fake(method, url, *, token=None, body=None, timeout=60, headers=None):
            captured["method"] = method
            captured["url"] = url
            captured["body"] = body
            captured["token"] = token
            return response if response is not None else {}

        monkeypatch.setattr(eesel, "http_request", fake)
        return captured

    # ── enable ──────────────────────────────────────────────────────────
    def test_enable_posts_empty_config_with_resolved_integration_id(self, fake_creds, monkeypatch, capsys):
        captured = self._setup(monkeypatch, {"tool_id": "t9", "config": {}})
        rc = eesel.cmd_integration_actions(_args(
            actions_cmd="enable", integration="zendesk", agent="Sales Bot", action="zendesk_leave_internal_note"))
        assert rc == 0
        assert captured["method"] == "POST"
        assert captured["url"] == "http://localhost:8080/agents/agent-other-999/tools/zendesk_leave_internal_note"
        # Enable sends an empty config; the integration type resolves to its instance id.
        assert captured["body"] == {"config": {}, "integration_id": "int-zendesk-1"}
        assert "Enabled" in capsys.readouterr().err

    def test_enable_unresolved_integration_posts_unscoped(self, fake_creds, monkeypatch):
        # ai_actions has no instance id, so the write proceeds without integration_id.
        captured = self._setup(monkeypatch)
        eesel.cmd_integration_actions(_args(
            actions_cmd="enable", integration="ai_actions", agent="agent-test-456", action="doc_search"))
        assert captured["body"] == {"config": {}}

    def test_enable_accepts_display_name(self, fake_creds, monkeypatch, capsys):
        # A human display name resolves to its tool_key for the write.
        captured = self._setup(monkeypatch)
        monkeypatch.setattr(eesel, "fetch_tools", lambda creds, aid: list(_TOOLS))
        rc = eesel.cmd_integration_actions(_args(
            actions_cmd="enable", integration="zendesk", agent="Sales Bot", action="Leave internal note"))
        assert rc == 0
        assert captured["url"].endswith("/tools/zendesk_leave_internal_note")
        assert "Enabled 'zendesk_leave_internal_note'" in capsys.readouterr().err

    def test_enable_unknown_agent_errors_without_request(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: pytest.fail("should not POST"))
        rc = eesel.cmd_integration_actions(_args(
            actions_cmd="enable", integration="zendesk", agent="Ghost", action="k"))
        assert rc == 1
        assert "No agent matches" in capsys.readouterr().err

    # ── set ─────────────────────────────────────────────────────────────
    def test_set_posts_parsed_config(self, fake_creds, monkeypatch, capsys):
        captured = self._setup(monkeypatch, {"config": {"permission_mode": "ask"}})
        rc = eesel.cmd_integration_actions(_args(
            actions_cmd="set", integration="zendesk", agent="agent-test-456",
            action="zendesk_leave_internal_note", config='{"permission_mode": "ask"}'))
        assert rc == 0
        assert captured["method"] == "POST"
        assert captured["url"] == "http://localhost:8080/agents/agent-test-456/tools/zendesk_leave_internal_note"
        assert captured["body"] == {"config": {"permission_mode": "ask"}, "integration_id": "int-zendesk-1"}

    def test_set_rejects_bad_json_without_request(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: pytest.fail("should not POST"))
        rc = eesel.cmd_integration_actions(_args(
            actions_cmd="set", integration="zendesk", agent="agent-test-456", action="k", config="{bad"))
        assert rc == 1
        assert "not valid JSON" in capsys.readouterr().err

    def test_set_redacts_secrets_in_echoed_config(self, fake_creds, monkeypatch, capsys):
        self._setup(monkeypatch, {"config": {"access_token": "tok-LEAK", "mode": "ask"}})
        eesel.cmd_integration_actions(_args(
            actions_cmd="set", integration="zendesk", agent="agent-test-456", action="k", config='{"mode": "ask"}'))
        err = capsys.readouterr().err
        assert "tok-LEAK" not in err
        assert "***" in err

    # ── disable ─────────────────────────────────────────────────────────
    def test_disable_with_force_deletes_without_prompt(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "confirm", lambda prompt: pytest.fail("should not prompt with --force"))
        captured = self._setup(monkeypatch)
        rc = eesel.cmd_integration_actions(_args(
            actions_cmd="disable", integration="zendesk", agent="agent-test-456",
            action="zendesk_leave_internal_note", force=True))
        assert rc == 0
        assert captured["method"] == "DELETE"
        # Resolved integration id is passed as a query param to scope the delete.
        assert captured["url"].endswith("/tools/zendesk_leave_internal_note?integration_id=int-zendesk-1")
        assert "Disabled" in capsys.readouterr().err

    def test_disable_affirmative_confirmation_deletes(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "confirm", lambda prompt: True)
        captured = self._setup(monkeypatch)
        rc = eesel.cmd_integration_actions(_args(
            actions_cmd="disable", integration="zendesk", agent="agent-test-456", action="k", force=False))
        assert rc == 0
        assert captured["method"] == "DELETE"

    def test_disable_declined_confirmation_aborts(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "confirm", lambda prompt: False)
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: pytest.fail("should not DELETE when declined"))
        rc = eesel.cmd_integration_actions(_args(
            actions_cmd="disable", integration="zendesk", agent="agent-test-456", action="k", force=False))
        assert rc == 1
        assert "Aborted" in capsys.readouterr().err


class TestToolsBackCompatAndForce:
    def test_tools_is_hidden_backcompat_alias(self):
        # `eesel tools [agent]` was restructured to `integrations ... actions`,
        # but the read-only alias is kept (suppressed) for existing scripts.
        parser = eesel.build_parser()
        args = parser.parse_args(["tools", "Support Bot"])
        assert args.func is eesel.cmd_tools
        assert args.agent == "Support Bot"

    def test_tools_hidden_from_help(self):
        assert "tools" not in _visible_commands(eesel.build_parser())

    def test_actions_disable_accepts_short_force_flag(self):
        parser = eesel.build_parser()
        argv = ["integrations", "actions", "zendesk", "disable", "zendesk_tag_ticket", "-f"]
        args = parser.parse_args(eesel._normalize_integrations_argv(argv))
        assert args.force is True


class TestNormalizeIntegrationsArgv:
    def test_bare_integrations_untouched(self):
        # The integration listing path is left alone.
        assert eesel._normalize_integrations_argv(["integrations"]) == ["integrations"]
        assert eesel._normalize_integrations_argv(["integrations", "--json"]) == ["integrations", "--json"]

    def test_actions_without_verb_defaults_to_list(self):
        # `integrations zendesk actions` → `integrations actions zendesk list`.
        assert eesel._normalize_integrations_argv(["integrations", "zendesk", "actions"]) == [
            "integrations", "actions", "zendesk", "list"]

    def test_actions_reorders_integration_before_keyword(self):
        # The user-facing path puts the integration first; argparse wants it after `actions`.
        assert eesel._normalize_integrations_argv(["integrations", "zendesk", "actions", "enable", "reply"]) == [
            "integrations", "actions", "zendesk", "enable", "reply"]

    def test_actions_explicit_verbs_preserved(self):
        for verb in ("list", "show", "enable", "disable", "set", "edit"):
            argv = ["integrations", "zendesk", "actions", verb, "reply"]
            assert eesel._normalize_integrations_argv(argv) == ["integrations", "actions", "zendesk", verb, "reply"]

    def test_actions_set_is_canonical_and_edit_is_removed(self):
        # `set` is the canonical config verb; the former `edit` alias is removed.
        parser = eesel.build_parser()
        args = parser.parse_args(
            eesel._normalize_integrations_argv(
                ["integrations", "zendesk", "actions", "set", "reply", "--config", "{}"]))
        assert args.actions_cmd == "set"
        with pytest.raises(SystemExit):
            parser.parse_args(
                eesel._normalize_integrations_argv(
                    ["integrations", "zendesk", "actions", "edit", "reply", "--config", "{}"]))
        integrations = _subparsers_action(parser).choices["integrations"]
        act_sub = _subparsers_action(integrations).choices["actions"]
        visible = [a.dest for a in _subparsers_action(act_sub)._choices_actions]
        assert "set" in visible and "edit" not in visible

    def test_flags_after_verb_kept_in_order(self):
        assert eesel._normalize_integrations_argv(
            ["integrations", "zendesk", "actions", "disable", "reply", "--force"]) == [
            "integrations", "actions", "zendesk", "disable", "reply", "--force"]

    def test_not_actions_path_left_untouched(self):
        # `integrations <something>` that isn't followed by `actions` is left for
        # the parser (it'll surface a helpful error).
        assert eesel._normalize_integrations_argv(["integrations", "zendesk"]) == ["integrations", "zendesk"]

    def test_non_integrations_argv_untouched(self):
        assert eesel._normalize_integrations_argv(["agents", "list"]) == ["agents", "list"]

    def test_help_reaches_parent_parser(self):
        # `integrations --help` shows the integrations help, not the actions help.
        assert eesel._normalize_integrations_argv(["integrations", "--help"]) == ["integrations", "--help"]
        assert eesel._normalize_integrations_argv(["integrations", "-h"]) == ["integrations", "-h"]

    def test_actions_help_reaches_actions_parser(self):
        assert eesel._normalize_integrations_argv(["integrations", "zendesk", "actions", "--help"]) == [
            "integrations", "actions", "zendesk", "--help"]

    def test_actions_unknown_verb_passed_through_for_suggestion(self):
        # A typo'd verb must NOT be defaulted to `list` (which would bury it as an
        # unexpected argument to `list`); it's passed through unchanged so the
        # actions subparser raises a suggesting "invalid choice" error.
        assert eesel._normalize_integrations_argv(["integrations", "zendesk", "actions", "enabl", "reply"]) == [
            "integrations", "actions", "zendesk", "enabl", "reply"]

    def test_actions_flags_only_defaults_to_list(self):
        # Only flags after `actions` (no verb at all) still defaults to `list`.
        assert eesel._normalize_integrations_argv(["integrations", "zendesk", "actions", "--json"]) == [
            "integrations", "actions", "zendesk", "list", "--json"]


class TestChatAgentFlag:
    def test_parser_accepts_agent(self):
        args = eesel.build_parser().parse_args(["chat", "hi", "--agent", "Bot"])
        assert args.agent == "Bot"
        assert args.func is eesel.cmd_chat

    def test_unmatched_agent_errors_before_chatting(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "a1", "name": "Bot"}])
        monkeypatch.setattr(eesel, "send_message", lambda *a, **k: pytest.fail("must not chat on an unmatched --agent"))
        rc = eesel.cmd_chat(_args(agent="nope", message="hi", cost=False, task=None, trigger=None))
        assert rc == 1
        assert "No agent matches 'nope'" in capsys.readouterr().err

    def test_agent_flag_does_not_persist_active_agent(self, fake_creds, monkeypatch):
        # --agent is a stateless, per-command scope: it resolves in memory and
        # must never rewrite the saved active agent on disk.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "other-agent", "name": "Other"}])
        monkeypatch.setattr(eesel, "save_creds", lambda creds: pytest.fail("--agent must not persist the active agent"))
        # Stop after agent resolution so we don't exercise the sandbox/streaming path.
        monkeypatch.setattr(eesel, "send_message", lambda *a, **k: (_ for _ in ()).throw(SystemExit("stop")))
        with pytest.raises(SystemExit):
            eesel.cmd_chat(_args(agent="Other", message="hi", cost=False, task=None, trigger=None))

    def test_schedule_flag_does_not_persist_active_agent(self, fake_creds, monkeypatch, capsys):
        # Binding a chat to a scheduled job pins that job's agent for the preview
        # session only — it must never rewrite the saved active agent on disk, or
        # every later unrelated command would silently run against the wrong agent.
        monkeypatch.setattr(
            eesel, "resolve_scheduled_job",
            lambda creds, target: {"id": "trig-1", "agent_id": "schedule-agent", "agent_name": "Heartbeat", "config": {"title": "heartbeat"}},
        )
        monkeypatch.setattr(eesel, "pick_agent", lambda creds, **k: None)
        monkeypatch.setattr(eesel, "new_session", lambda creds, **k: {"id": "sess-1", "trigger_id": "trig-1", "trigger_title": "heartbeat", "agent_id": creds.get("agent_id")})
        # A successful turn returns a "completed" envelope.
        monkeypatch.setattr(eesel, "send_message", lambda *a, **k: {"status": "completed", "reply": "ok", "task_id": "t1", "tool_calls": []})
        monkeypatch.setattr(eesel, "save_creds", lambda creds: pytest.fail("--schedule must not persist the active agent"))
        rc = eesel.cmd_chat(_args(schedule="heartbeat", message="go", cost=False, task=None, agent=None))
        assert rc == 0


class TestChatNonTtyGuard:
    """A headless agent that runs `eesel chat` with no message must be told to
    pass one (the validation exit code), not silently dropped into a REPL that
    reads end-of-input and exits 0 having sent nothing."""

    def test_no_message_on_non_tty_errors_before_any_work(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel.sys, "stdin", _FakeStdin(False))
        monkeypatch.setattr(eesel, "pick_agent", lambda *a, **k: pytest.fail("must not resolve an agent"))
        monkeypatch.setattr(eesel, "ensure_current_session", lambda *a, **k: pytest.fail("must not open a session"))
        monkeypatch.setattr(eesel, "send_message", lambda *a, **k: pytest.fail("must not start a chat turn"))
        rc = eesel.cmd_chat(_args(message=None, agent=None, task=None, schedule=None, cost=False))
        assert rc == eesel.EXIT_VALIDATION
        assert "message" in capsys.readouterr().err

    def test_message_on_non_tty_still_runs(self, fake_creds, monkeypatch):
        # A message provided → the guard doesn't fire; the one-shot turn runs.
        monkeypatch.setattr(eesel.sys, "stdin", _FakeStdin(False))
        monkeypatch.setattr(eesel, "pick_agent", lambda creds, **k: "a1")
        monkeypatch.setattr(eesel, "ensure_current_session", lambda creds, **k: {"id": "s1", "agent_id": "a1", "task_id": "t1", "messages": []})
        # send_message returns the chat envelope; a completed turn exits 0.
        monkeypatch.setattr(eesel, "send_message", lambda *a, **k: {"task_id": "t1", "status": "completed", "reply": "hello back", "tool_calls": [], "error": None})
        rc = eesel.cmd_chat(_args(message="hi", agent=None, task=None, schedule=None, cost=False))
        assert rc == 0

    def test_piped_message_on_non_tty_is_sent(self, fake_creds, monkeypatch):
        # `echo "summarize this" | eesel chat`: no --message and no TTY, but stdin
        # carries a real message. The guard must NOT fire — the REPL's input()
        # reads the piped line, sends it, and returns 0 on end-of-input. Refusing
        # here would drop a delivered instruction as a silent no-op.
        monkeypatch.setattr(eesel.sys, "stdin", _FakeStdin(False))
        monkeypatch.setattr(eesel, "_stdin_has_piped_data", lambda: True)
        monkeypatch.setattr(eesel, "pick_agent", lambda creds, **k: "a1")
        monkeypatch.setattr(eesel, "ensure_current_session", lambda creds, **k: {"id": "s1", "agent_id": "a1", "task_id": "t1", "messages": []})
        sent = []
        monkeypatch.setattr(eesel, "send_message", lambda creds, sess, msg, **k: (sent.append(msg) or "ok"))

        lines = iter(["summarize this"])

        def fake_input(_=""):
            try:
                return next(lines)
            except StopIteration:
                raise EOFError  # end of the piped input closes the REPL

        monkeypatch.setattr("builtins.input", fake_input)
        rc = eesel.cmd_chat(_args(message=None, agent=None, task=None, schedule=None, cost=False))
        assert rc == 0
        assert sent == ["summarize this"]


class TestChatTaskFlag:
    def test_resolves_prefix_to_full_task_id_before_binding(self, fake_creds, monkeypatch, capsys):
        # A `--task` id-prefix is resolved to the full task id before the session
        # is pinned — binding the truncated value would create a junk session that
        # fails the stream with an empty error.
        full_id = "330c8f22-aaaa-bbbb-cccc-dddddddddddd"
        monkeypatch.setattr(eesel, "pick_agent", lambda creds, **k: None)
        monkeypatch.setattr(eesel, "fetch_tasks", lambda creds, **k: ([{"task_id": full_id}], None, None))
        monkeypatch.setattr(eesel, "find_session_by_task", lambda tid: None)
        created = {}

        def fake_new_session(creds, **k):
            created.update(k)
            return {"id": "sess-1", **k}

        monkeypatch.setattr(eesel, "new_session", fake_new_session)
        # A successful turn returns a "completed" envelope.
        monkeypatch.setattr(eesel, "send_message", lambda *a, **k: {"status": "completed", "reply": "ok", "task_id": "t1", "tool_calls": []})
        rc = eesel.cmd_chat(_args(task="330c8f22", schedule=None, agent=None, message="hi", cost=False))
        assert rc == 0
        # The full resolved id is pinned, not the truncated prefix.
        assert created["task_id"] == full_id

    def test_ambiguous_prefix_errors_without_binding(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "pick_agent", lambda creds, **k: None)
        monkeypatch.setattr(
            eesel, "fetch_tasks",
            lambda creds, **k: ([{"task_id": "330c8f22-aaaa"}, {"task_id": "330c8f22-bbbb"}], None, None),
        )
        monkeypatch.setattr(eesel, "find_session_by_task", lambda tid: pytest.fail("must not look up a session before resolving"))
        monkeypatch.setattr(eesel, "new_session", lambda *a, **k: pytest.fail("must not bind a session on an ambiguous prefix"))
        rc = eesel.cmd_chat(_args(task="330c8f22", schedule=None, agent=None, message="hi", cost=False))
        assert rc == 1
        assert "ambiguous" in capsys.readouterr().err


class TestChatHonestExit:
    """`eesel chat "…"` (one-shot) must exit non-zero when the server rejects the
    turn. send_message returns an envelope dict whose `status` is "error" on
    failure; a successful turn (even an empty reply) has status "completed" and
    exits 0."""

    def _sess(self):
        return {"id": "s1", "agent_id": "ag-1", "workspace_id": "ws-test-123",
                "task_id": "t1", "messages": []}

    def test_send_message_gives_error_envelope_on_sandbox_http_error(self, fake_creds, monkeypatch):
        import io

        def boom(req, timeout=None):
            raise eesel.urllib.error.HTTPError(
                req.full_url, 402, "Payment Required", {},
                io.BytesIO(b'{"code":"BILLING_LIMIT_EXCEEDED"}'))

        monkeypatch.setattr(eesel.urllib.request, "urlopen", boom)
        env = eesel.send_message(fake_creds, self._sess(), "hi")
        assert env["status"] == "error"
        assert "402" in env["error"]

    def test_stream_reply_flags_error_on_http_error(self, fake_creds, monkeypatch):
        import io

        def boom(req, timeout=None):
            raise eesel.urllib.error.HTTPError(req.full_url, 500, "Server Error", {}, io.BytesIO(b"boom"))

        monkeypatch.setattr(eesel.urllib.request, "urlopen", boom)
        assert eesel.stream_reply(fake_creds, "task1", None)["error"] is True

    class _RawResp:
        def __init__(self, body: bytes, status: int = 200):
            self._body = body
            self.status = status

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def test_send_message_non_json_200_gives_error_envelope(self, fake_creds, monkeypatch):
        html = b"<html><body>login</body></html>"
        monkeypatch.setattr(eesel.urllib.request, "urlopen", lambda *a, **k: self._RawResp(html))

        env = eesel.send_message(fake_creds, self._sess(), "hi")
        assert env["status"] == "error"
        assert "not JSON" in env["error"]
        assert "JSONDecodeError" not in env["error"]  # no raw traceback leaked

    class _SseResp:
        def __init__(self, lines):
            self.lines = lines

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def __iter__(self):
            return iter(self.lines)

    def test_stream_reply_flags_error_on_error_event(self, fake_creds, monkeypatch, capsys):
        lines = [b'data: {"type":"error","errorText":"turn failed"}\n']
        monkeypatch.setattr(eesel.urllib.request, "urlopen", lambda *a, **k: self._SseResp(lines))

        assert eesel.stream_reply(fake_creds, "task1", None)["error"] is True
        assert "turn failed" in capsys.readouterr().err

    def test_oneshot_exits_1_when_turn_rejected(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "pick_agent", lambda creds, **k: None)
        monkeypatch.setattr(eesel, "ensure_current_session", lambda creds, **k: self._sess())
        # rejected turn → error envelope
        monkeypatch.setattr(eesel, "send_message", lambda *a, **k: {"status": "error", "reply": "", "task_id": "t1", "tool_calls": [], "error": "boom"})
        rc = eesel.cmd_chat(_args(agent=None, task=None, schedule=None, message="hi", cost=False))
        assert rc == 1

    def test_oneshot_exits_0_on_success(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "pick_agent", lambda creds, **k: None)
        monkeypatch.setattr(eesel, "ensure_current_session", lambda creds, **k: self._sess())
        monkeypatch.setattr(eesel, "send_message", lambda *a, **k: {"status": "completed", "reply": "the reply", "task_id": "t1", "tool_calls": []})
        rc = eesel.cmd_chat(_args(agent=None, task=None, schedule=None, message="hi", cost=False))
        assert rc == 0

    def test_oneshot_exits_0_on_empty_but_successful_reply(self, fake_creds, monkeypatch):
        # An empty reply is a successful (if quiet) turn — status "completed", not failure.
        monkeypatch.setattr(eesel, "pick_agent", lambda creds, **k: None)
        monkeypatch.setattr(eesel, "ensure_current_session", lambda creds, **k: self._sess())
        monkeypatch.setattr(eesel, "send_message", lambda *a, **k: {"status": "completed", "reply": "", "task_id": "t1", "tool_calls": []})
        rc = eesel.cmd_chat(_args(agent=None, task=None, schedule=None, message="hi", cost=False))
        assert rc == 0

    def test_oneshot_with_cost_still_prints_then_exits_nonzero(self, fake_creds, monkeypatch):
        printed = {}
        monkeypatch.setattr(eesel, "pick_agent", lambda creds, **k: None)
        monkeypatch.setattr(eesel, "ensure_current_session", lambda creds, **k: self._sess())
        monkeypatch.setattr(eesel, "_current_run_count", lambda creds, sess: 0)
        monkeypatch.setattr(eesel, "_print_cost_after_turn", lambda *a, **k: printed.setdefault("cost", True))
        monkeypatch.setattr(eesel, "send_message", lambda *a, **k: {"status": "error", "reply": "", "task_id": "t1", "tool_calls": [], "error": "boom"})
        rc = eesel.cmd_chat(_args(agent=None, task=None, schedule=None, message="hi", cost=True))
        assert rc == 1
        assert printed.get("cost") is True  # cost summary still printed despite the failure


class TestDryRunGuardsBilledAndLoginPaths:
    """--dry-run must cover the side effects that spend money or write creds, not
    only config mutations. A chat turn is a billed POST and login mints/stores a
    token, so both preview and make no call under --dry-run."""

    def _sess(self):
        return {"id": "s1", "agent_id": "ag-1", "workspace_id": "ws-test-123",
                "task_id": "t1", "messages": []}

    def test_send_message_previews_and_makes_no_call(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "_DRY_RUN", True)
        monkeypatch.setattr(eesel, "_is_tty", lambda: True)
        monkeypatch.setattr(
            eesel.urllib.request, "urlopen",
            lambda *a, **k: pytest.fail("--dry-run must not POST to sandbox/start"))
        with pytest.raises(SystemExit) as exc:
            eesel.send_message(fake_creds, self._sess(), "hello")
        assert exc.value.code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["method"] == "POST"
        assert payload["url"].endswith("/agents/sandbox/start")
        assert payload["body"]["messages"][-1]["message"] == "hello"

    def test_login_dev_previews_and_writes_no_creds(self, tmp_config, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "_DRY_RUN", True)
        monkeypatch.setattr(eesel, "login_dev", lambda *a, **k: pytest.fail("--dry-run must not log in"))
        monkeypatch.setattr(eesel, "save_creds", lambda creds: pytest.fail("--dry-run must not write credentials"))
        with pytest.raises(SystemExit) as exc:
            eesel.cmd_login(type("Args", (), {"dev": True, "workspace_id": None})())
        assert exc.value.code == 0
        payload = json.loads(capsys.readouterr().out)
        assert "login" in payload["action"]

    def test_login_prod_previews_and_opens_no_browser(self, tmp_config, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "_DRY_RUN", True)
        monkeypatch.setattr(eesel, "login_prod", lambda *a, **k: pytest.fail("--dry-run must not open the OAuth bridge"))
        with pytest.raises(SystemExit) as exc:
            eesel.cmd_login(type("Args", (), {"dev": False, "workspace_id": None})())
        assert exc.value.code == 0
        assert "login" in json.loads(capsys.readouterr().out)["action"]


class TestChatJson:
    """`eesel chat --json "…"` is the keystone agent call: one JSON object on
    stdout carrying the reply, the ordered tool-calls (with full untruncated
    input/output), the task_id and a terminal status — and nothing else on
    stdout. Plain `eesel chat "…"` must stream to a human exactly as before."""

    def _sess(self):
        return {"id": "s1", "agent_id": "agent-test-456", "workspace_id": "ws-test-123",
                "task_id": "t1", "messages": []}

    class _SseResp:
        def __init__(self, lines):
            self.lines = lines

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def __iter__(self):
            return iter(self.lines)

    def _urlopen(self, start_resp, sse_lines):
        """Dispatch the two calls a turn makes: the sandbox/start POST (JSON) and
        the raw-stream GET (SSE). streamUrl is left None so the stream goes to
        the raw-stream URL, which the dispatcher recognises."""
        outer = self

        def _open(req, timeout=None):
            url = req.full_url if hasattr(req, "full_url") else req
            if url.endswith("/agents/sandbox/start"):
                return _FakeResp(start_resp)
            return outer._SseResp(sse_lines)

        return _open

    def _sse(self, *events):
        return [("data: " + json.dumps(e) + "\n").encode() for e in events]

    # ---- envelope shape (direct send_message) -------------------------------

    def test_envelope_shape_happy(self, fake_creds, monkeypatch):
        lines = self._sse(
            {"type": "text-start", "id": "m1"},
            {"type": "tool-input-available", "toolCallId": "c1",
             "toolName": "doc_search", "input": {"query": "refunds"}},
            {"type": "text-delta", "id": "m1", "delta": "Refunds "},
            {"type": "tool-output-available", "toolCallId": "c1", "output": "3 docs found"},
            {"type": "text-delta", "id": "m1", "delta": "are covered."},
            {"type": "finish"},
        )
        monkeypatch.setattr(eesel.urllib.request, "urlopen",
                            self._urlopen({"taskId": "task-xyz", "streamUrl": None}, lines))
        env = eesel.send_message(fake_creds, self._sess(), "do refunds work?", render=False)
        assert env["task_id"] == "task-xyz"
        assert env["status"] == "completed"
        assert env["reply"] == "Refunds are covered."
        assert env["tool_calls"] == [
            {"name": "doc_search", "input": {"query": "refunds"}, "output": "3 docs found"}
        ]
        assert "error" not in env

    def test_tool_calls_paired_by_id_when_outputs_arrive_out_of_order(self, fake_creds, monkeypatch):
        # Tools can run in parallel, so outputs need not arrive in input order.
        # Pairing is by toolCallId; ordering is by when each input first appeared.
        lines = self._sse(
            {"type": "tool-input-available", "toolCallId": "a", "toolName": "first", "input": {"n": 1}},
            {"type": "tool-input-available", "toolCallId": "b", "toolName": "second", "input": {"n": 2}},
            {"type": "tool-output-available", "toolCallId": "b", "output": "out-b"},
            {"type": "tool-output-available", "toolCallId": "a", "output": "out-a"},
        )
        monkeypatch.setattr(eesel.urllib.request, "urlopen",
                            self._urlopen({"taskId": "tk", "streamUrl": None}, lines))
        env = eesel.send_message(fake_creds, self._sess(), "run both", render=False)
        assert [c["name"] for c in env["tool_calls"]] == ["first", "second"]
        assert env["tool_calls"][0]["output"] == "out-a"
        assert env["tool_calls"][1]["output"] == "out-b"

    def test_tool_io_is_not_truncated(self, fake_creds, monkeypatch):
        # The human view truncates tool input/output to 200 chars; the JSON
        # envelope must carry them in full so an agent reads back what really ran.
        big_input = {"blob": "x" * 500}
        big_output = "y" * 500
        lines = self._sse(
            {"type": "tool-input-available", "toolCallId": "c1", "toolName": "big", "input": big_input},
            {"type": "tool-output-available", "toolCallId": "c1", "output": big_output},
        )
        monkeypatch.setattr(eesel.urllib.request, "urlopen",
                            self._urlopen({"taskId": "tk", "streamUrl": None}, lines))
        env = eesel.send_message(fake_creds, self._sess(), "big", render=False)
        assert env["tool_calls"][0]["input"] == big_input
        assert env["tool_calls"][0]["output"] == big_output

    def test_error_event_gives_error_envelope(self, fake_creds, monkeypatch):
        lines = self._sse({"type": "error", "errorText": "turn failed"})
        monkeypatch.setattr(eesel.urllib.request, "urlopen",
                            self._urlopen({"taskId": "task-xyz", "streamUrl": None}, lines))
        env = eesel.send_message(fake_creds, self._sess(), "hi", render=False)
        assert env["status"] == "error"
        assert env["task_id"] == "task-xyz"
        # The specific server reason is threaded into the envelope so an agent
        # parsing only stdout learns *why* it failed, not just that it did.
        assert env["error"] == "turn failed"

    def test_clean_eof_without_finish_is_reported_as_error(self, fake_creds, monkeypatch):
        # A stream that closes cleanly after partial text but WITHOUT the terminal
        # `finish` event is a truncated turn (LB idle-close, graceful shutdown),
        # not a completed one. Reporting it "completed" would exit 0 on a partial
        # reply; the missing terminal signal makes it an error envelope instead.
        lines = self._sse(
            {"type": "text-start", "id": "m1"},
            {"type": "text-delta", "id": "m1", "delta": "partial ans"},
        )  # no finish
        monkeypatch.setattr(eesel.urllib.request, "urlopen",
                            self._urlopen({"taskId": "task-xyz", "streamUrl": None}, lines))
        env = eesel.send_message(fake_creds, self._sess(), "hi", render=False)
        assert env["status"] == "error"
        assert "completion signal" in env["error"]
        # The partial text is still carried, so a caller can inspect what arrived.
        assert env["reply"] == "partial ans"

    def test_finish_event_marks_the_turn_completed(self, fake_creds, monkeypatch):
        lines = self._sse(
            {"type": "text-delta", "id": "m1", "delta": "done"},
            {"type": "finish"},
        )
        monkeypatch.setattr(eesel.urllib.request, "urlopen",
                            self._urlopen({"taskId": "tk", "streamUrl": None}, lines))
        env = eesel.send_message(fake_creds, self._sess(), "hi", render=False)
        assert env["status"] == "completed"
        assert env["reply"] == "done"

    def test_abort_event_gives_error_envelope(self, fake_creds, monkeypatch):
        # An aborted turn is a real terminal signal (not a truncation) but the
        # reply is partial, so it's still an error envelope.
        lines = self._sse(
            {"type": "text-delta", "id": "m1", "delta": "half"},
            {"type": "abort", "reason": "cancelled"},
        )
        monkeypatch.setattr(eesel.urllib.request, "urlopen",
                            self._urlopen({"taskId": "tk", "streamUrl": None}, lines))
        env = eesel.send_message(fake_creds, self._sess(), "hi", render=False)
        assert env["status"] == "error"
        assert "aborted" in env["error"]

    def test_midstream_unreachable_gives_error_envelope(self, fake_creds, monkeypatch):
        # A server that vanishes mid-stream (URLError on the raw-stream GET) must
        # still yield one parseable error envelope, not a bare exit with empty
        # stdout — the sandbox/start POST succeeds, then the stream dies.
        def _open(req, timeout=None):
            url = req.full_url if hasattr(req, "full_url") else req
            if url.endswith("/agents/sandbox/start"):
                return _FakeResp({"taskId": "task-xyz", "streamUrl": None})
            raise eesel.urllib.error.URLError("connection refused")

        monkeypatch.setattr(eesel.urllib.request, "urlopen", _open)
        env = eesel.send_message(fake_creds, self._sess(), "hi", render=False)
        assert env["status"] == "error"
        assert env["task_id"] == "task-xyz"
        assert "server reachable?" in env["error"]

    def test_prestream_http_error_gives_error_envelope(self, fake_creds, monkeypatch):
        import io

        def boom(req, timeout=None):
            raise eesel.urllib.error.HTTPError(
                req.full_url, 402, "Payment Required", {},
                io.BytesIO(b'{"code":"BILLING_LIMIT_EXCEEDED"}'))

        monkeypatch.setattr(eesel.urllib.request, "urlopen", boom)
        env = eesel.send_message(fake_creds, self._sess(), "hi", render=False)
        assert env["status"] == "error"
        assert "402" in env["error"]
        assert env["tool_calls"] == []

    # ---- cmd_chat: stdout purity, exit codes, guards ------------------------

    def test_cmd_chat_json_emits_one_clean_object_and_exits_0(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "resolve_session_agent", lambda creds: ("agent-test-456", None))
        monkeypatch.setattr(eesel, "ensure_current_session", lambda creds, **k: self._sess())
        lines = self._sse(
            {"type": "text-start", "id": "m1"},
            {"type": "tool-input-available", "toolCallId": "c1",
             "toolName": "doc_search", "input": {"q": "x"}},
            {"type": "tool-output-available", "toolCallId": "c1", "output": "ok"},
            {"type": "text-delta", "id": "m1", "delta": "hello"},
            {"type": "finish"},
        )
        monkeypatch.setattr(eesel.urllib.request, "urlopen",
                            self._urlopen({"taskId": "task-xyz", "streamUrl": None}, lines))
        rc = eesel.cmd_chat(_args(agent=None, task=None, schedule=None,
                                  message="hi", cost=False, json=True))
        assert rc == 0
        out = capsys.readouterr().out
        # Exactly one JSON object, and none of the human streaming noise.
        env = json.loads(out)
        assert env["status"] == "completed"
        assert env["reply"] == "hello"
        assert env["task_id"] == "task-xyz"
        assert env["tool_calls"][0]["name"] == "doc_search"
        assert "eesel" not in out and "[tool]" not in out and "→" not in out

    def test_cmd_chat_json_error_event_exits_nonzero_with_object(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "resolve_session_agent", lambda creds: ("agent-test-456", None))
        monkeypatch.setattr(eesel, "ensure_current_session", lambda creds, **k: self._sess())
        lines = self._sse({"type": "error", "errorText": "turn failed"})
        monkeypatch.setattr(eesel.urllib.request, "urlopen",
                            self._urlopen({"taskId": "task-xyz", "streamUrl": None}, lines))
        rc = eesel.cmd_chat(_args(agent=None, task=None, schedule=None,
                                  message="hi", cost=False, json=True))
        assert rc == 1
        env = json.loads(capsys.readouterr().out)  # still one parseable object
        assert env["status"] == "error"

    def test_human_mode_still_streams_to_stdout(self, fake_creds, monkeypatch, capsys):
        # Regression: plain `eesel chat "…"` (no --json) streams the reply and
        # tool activity to stdout behind the `eesel →` prefix, exactly as before.
        lines = self._sse(
            {"type": "text-start", "id": "m1"},
            {"type": "tool-input-available", "toolCallId": "c1",
             "toolName": "doc_search", "input": {"q": "x"}},
            {"type": "tool-output-available", "toolCallId": "c1", "output": "ok"},
            {"type": "text-delta", "id": "m1", "delta": "hi there"},
            {"type": "finish"},
        )
        monkeypatch.setattr(eesel.urllib.request, "urlopen",
                            self._urlopen({"taskId": "task-xyz", "streamUrl": None}, lines))
        env = eesel.send_message(fake_creds, self._sess(), "hi")  # render defaults True
        assert env["status"] == "completed" and env["reply"] == "hi there"
        out = capsys.readouterr().out
        assert "eesel" in out and "hi there" in out and "[tool] doc_search" in out

    def test_cmd_chat_json_no_message_refuses_repl(self, fake_creds, monkeypatch, capsys):
        # --json with no message must not drop into the REPL; it errors and the
        # picker is never reached.
        monkeypatch.setattr(eesel, "pick_agent", lambda *a, **k: pytest.fail("must not prompt for an agent"))
        rc = eesel.cmd_chat(_args(agent=None, task=None, schedule=None,
                                  message=None, cost=False, json=True))
        assert rc == 1
        captured = capsys.readouterr()
        assert captured.out == ""  # nothing on stdout
        assert "REPL" in captured.err or "--json requires a message" in captured.err

    def test_cmd_chat_json_ambiguous_agent_emits_error_envelope(self, fake_creds, monkeypatch, capsys):
        # A multi-agent workspace with no --agent: JSON mode must NOT show a
        # picker (which would corrupt stdout on a TTY) or exit with only a stderr
        # message (no envelope non-interactively). It emits one JSON error
        # envelope on stdout and exits non-zero, and never reaches the interactive
        # picker.
        monkeypatch.setattr(eesel, "pick_agent", lambda *a, **k: pytest.fail("JSON mode must not use the interactive picker"))
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [
            {"agent_id": "a1", "name": "One"}, {"agent_id": "a2", "name": "Two"}])
        monkeypatch.setattr(eesel, "ensure_current_session", lambda creds, **k: pytest.fail("must not start a session with no agent"))
        rc = eesel.cmd_chat(_args(agent=None, task=None, schedule=None,
                                  message="hi", cost=False, json=True))
        assert rc == 1
        out = capsys.readouterr().out
        env = json.loads(out)  # exactly one parseable object on stdout
        assert env["status"] == "error"
        assert env["task_id"] is None
        assert "2 agents" in env["error"]

    def test_cmd_chat_json_invalid_agent_flag_emits_error_envelope(self, fake_creds, monkeypatch, capsys):
        # An explicit but unresolvable `--agent` must also produce one JSON error
        # envelope on stdout, not an empty stdout + stderr-only exit.
        monkeypatch.setattr(eesel, "resolve_agent_or_error", lambda creds, target: None)
        rc = eesel.cmd_chat(_args(agent="missing", task=None, schedule=None,
                                  message="hi", cost=False, json=True))
        assert rc == 1
        env = json.loads(capsys.readouterr().out)
        assert env["status"] == "error"
        assert env["task_id"] is None
        assert "--agent" in env["error"] and "missing" in env["error"]

    def test_cmd_chat_json_invalid_task_emits_error_envelope(self, fake_creds, monkeypatch, capsys):
        # An unresolvable `--task` returns before a turn starts; JSON mode still
        # emits one envelope.
        monkeypatch.setattr(eesel, "resolve_task_id", lambda creds, t: None)
        rc = eesel.cmd_chat(_args(agent=None, task="bogus", schedule=None,
                                  message="hi", cost=False, json=True))
        assert rc == 1
        env = json.loads(capsys.readouterr().out)
        assert env["status"] == "error"
        assert "--task" in env["error"] and "bogus" in env["error"]

    def test_cmd_chat_json_unmatched_trigger_emits_error_envelope(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "resolve_scheduled_job", lambda creds, t: None)
        rc = eesel.cmd_chat(_args(agent=None, task=None, schedule="nope",
                                  message="hi", cost=False, json=True))
        assert rc == 1
        env = json.loads(capsys.readouterr().out)
        assert env["status"] == "error"
        assert "nope" in env["error"]

    def test_cmd_chat_json_task_and_trigger_conflict_emits_error_envelope(self, fake_creds, monkeypatch, capsys):
        rc = eesel.cmd_chat(_args(agent=None, task="t1", schedule="s1",
                                  message="hi", cost=False, json=True))
        assert rc == 1
        env = json.loads(capsys.readouterr().out)
        assert env["status"] == "error"
        assert "mutually exclusive" in env["error"]


class TestNewAgentScope:
    """`eesel new --agent X` / `--schedule J` scope the new session to that agent
    in memory only — they must never rewrite the saved active agent, and --agent
    must be resolved (id/prefix/name), not stored raw."""

    def test_new_agent_resolves_and_does_not_persist(self, fake_creds, monkeypatch):
        created = {}
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "other-agent", "name": "Other"}])
        monkeypatch.setattr(eesel, "save_creds", lambda creds: pytest.fail("new --agent must not persist the active agent"))
        monkeypatch.setattr(eesel, "new_session", lambda creds, **k: (created.update(k) or {"id": "sess-1", "name": k.get("name")}))
        rc = eesel.cmd_new(_args(agent="Other", schedule=None, name=None))
        assert rc == 0
        assert created["agent_id"] == "other-agent"  # name resolved to id, not stored raw

    def test_new_agent_unmatched_errors(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "a1", "name": "Bot"}])
        monkeypatch.setattr(eesel, "new_session", lambda *a, **k: pytest.fail("must not create a session for an unmatched --agent"))
        with pytest.raises(SystemExit):
            eesel.cmd_new(_args(agent="nope", schedule=None, name=None))

    def test_new_agent_ambiguous_prefix_errors(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "ag-1", "name": "One"}, {"agent_id": "ag-2", "name": "Two"}])
        monkeypatch.setattr(eesel, "new_session", lambda *a, **k: pytest.fail("must not create a session on an ambiguous prefix"))
        with pytest.raises(SystemExit):
            eesel.cmd_new(_args(agent="ag", schedule=None, name=None))

    def test_new_schedule_does_not_persist(self, fake_creds, monkeypatch):
        created = {}
        monkeypatch.setattr(eesel, "pick_agent", lambda creds, **k: None)
        monkeypatch.setattr(eesel, "resolve_scheduled_job", lambda creds, target: {"id": "trig-1", "agent_id": "sched-agent", "config": {"title": "hb"}})
        monkeypatch.setattr(eesel, "save_creds", lambda creds: pytest.fail("new --schedule must not persist the active agent"))
        monkeypatch.setattr(eesel, "new_session", lambda creds, **k: (created.update(k) or {"id": "sess-1", "name": "sess-1", "trigger_id": k.get("trigger_id"), "trigger_title": k.get("trigger_title")}))
        monkeypatch.setattr(eesel, "send_message", lambda *a, **k: {"status": "completed", "reply": "ok", "task_id": "t1", "tool_calls": []})
        rc = eesel.cmd_new(_args(agent=None, schedule="hb", name=None))
        assert rc == 0
        assert created["agent_id"] == "sched-agent"  # session pinned to the trigger's agent, in memory only

    def test_new_schedule_exits_nonzero_when_preview_fire_fails(self, fake_creds, monkeypatch):
        # The auto-fire preview turn failing must surface as a non-zero exit, not
        # a silent 0 — a script chaining on `eesel new --trigger X` should stop.
        monkeypatch.setattr(eesel, "pick_agent", lambda creds, **k: None)
        monkeypatch.setattr(eesel, "resolve_scheduled_job", lambda creds, target: {"id": "trig-1", "agent_id": "sched-agent", "config": {"title": "hb"}})
        monkeypatch.setattr(eesel, "new_session", lambda creds, **k: {"id": "sess-1", "name": "sess-1", "trigger_id": k.get("trigger_id"), "trigger_title": k.get("trigger_title")})
        monkeypatch.setattr(eesel, "send_message", lambda *a, **k: {"status": "error", "reply": "", "task_id": "t1", "tool_calls": [], "error": "boom"})
        rc = eesel.cmd_new(_args(agent=None, schedule="hb", name=None))
        assert rc == 1


class TestPathScopeResolver:
    """`agents <id> <noun> <verb> …` (path-as-scope) normalizes into the flat
    argv the handlers already implement. Flat forms pass through untouched."""

    def n(self, *argv):
        return eesel._normalize_path_scope_argv(list(argv))

    # ── pass-through: not a path-scoped agents invocation ──
    def test_bare_agents_unchanged(self):
        assert self.n("agents") == ["agents"]

    def test_agents_with_flag_unchanged(self):
        assert self.n("agents", "--json") == ["agents", "--json"]

    def test_flat_verb_unchanged(self):
        assert self.n("agents", "list") == ["agents", "list"]
        assert self.n("agents", "show", "blog") == ["agents", "show", "blog"]
        assert self.n("agents", "set", "blog", "--name", "X") == ["agents", "set", "blog", "--name", "X"]

    def test_removed_agents_use_verb_errors_on_the_verb(self, capsys):
        with pytest.raises(SystemExit) as exc:
            self.n("agents", "use", "a1b2")
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "`eesel agents use` is gone" in err
        assert "is not an agent command" not in err

    def test_removed_agents_unset_verb_errors_on_the_verb(self, capsys):
        with pytest.raises(SystemExit) as exc:
            self.n("agents", "unset")
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "`eesel agents unset` is gone" in err
        assert "is not an agent command" not in err

    def test_non_agents_command_unchanged(self):
        assert self.n("integrations", "list") == ["integrations", "list"]
        assert self.n("chat", "hi") == ["chat", "hi"]

    # ── agent's own verbs ──
    def test_bare_id_becomes_show(self):
        assert self.n("agents", "blog-bot") == ["agents", "show", "blog-bot"]

    def test_show_carries_flags(self):
        assert self.n("agents", "blog", "show", "--instructions") == ["agents", "show", "blog", "--instructions"]

    def test_set_one_field(self):
        assert self.n("agents", "blog", "set", "name", "QA Bot") == ["agents", "set", "blog", "--name", "QA Bot"]

    def test_set_multiple_fields(self):
        assert self.n("agents", "blog", "set", "name", "QA", "instructions", "Be terse") == \
            ["agents", "set", "blog", "--name", "QA", "--instructions", "Be terse"]

    # ── grant / revoke at agent scope ──
    def test_grant_integration(self):
        # The grant `add` head maps to the canonical `connect` verb (the old
        # `integrations add` alias was removed).
        assert self.n("agents", "blog", "add", "zendesk") == ["integrations", "connect", "zendesk", "--agent", "blog"]

    def test_revoke_integration(self):
        assert self.n("agents", "blog", "remove", "zendesk") == ["integrations", "remove", "zendesk", "--agent", "blog"]

    # ── empty agent scope is rejected, never reshaped ──
    def test_empty_agent_scope_exits_without_reshaping(self):
        # `eesel agents "" remove zendesk` (e.g. an unset shell variable spliced
        # into the path) must not reshape into an empty `--agent`, which the
        # removal would read as "no agent" and uninstall workspace-wide. It exits
        # before any routing, so no destructive flat form is ever produced.
        for tail in (["remove", "zendesk"], ["integrations", "list"], []):
            with pytest.raises(SystemExit) as exc:
                self.n("agents", "", *tail)
            assert exc.value.code == 2

    def test_whitespace_only_agent_scope_exits(self):
        with pytest.raises(SystemExit) as exc:
            self.n("agents", "   ", "remove", "zendesk")
        assert exc.value.code == 2

    # ── child noun descent: "flag" scoping ──
    def test_integrations_list_flag_scoped(self):
        assert self.n("agents", "blog", "integrations", "list") == ["integrations", "list", "--agent", "blog"]

    def test_integrations_actions_path(self):
        # path-scope hands off to _normalize_integrations_argv for the actions reshape
        assert self.n("agents", "blog", "integrations", "zd", "actions", "enable", "reply") == \
            ["integrations", "zd", "actions", "enable", "reply", "--agent", "blog"]

    def test_files_flag_scoped(self):
        assert self.n("agents", "blog", "files", "list") == ["files", "list", "--agent", "blog"]

    # ── child noun descent: "pos" scoping (agent is the first positional) ──
    def test_skills_list_pos_scoped(self):
        assert self.n("agents", "blog", "skills", "list") == ["skills", "list", "blog"]

    def test_skills_default_verb_is_list(self):
        assert self.n("agents", "blog", "skills") == ["skills", "list", "blog"]

    def test_skills_show_pos_scoped(self):
        assert self.n("agents", "blog", "skills", "show", "translation") == ["skills", "show", "blog", "translation"]

    def test_triggers_schedules_are_not_scoped_and_error_clearly(self):
        # `triggers`/`schedules` list is workspace-wide (no agent arg), so they
        # are NOT agent-scoped children. Rather than reshape them, the resolver
        # exits with an error naming the noun (it does not inject an agent the
        # handler would reject). Their per-agent path form arrives with the
        # `automations` unification.
        for noun in ("triggers", "schedules"):
            with pytest.raises(SystemExit):
                self.n("agents", "blog", noun, "list")

    # ── chat at agent scope ──
    def test_chat_flag_scoped(self):
        assert self.n("agents", "blog", "chat", "hello") == ["chat", "hello", "--agent", "blog"]


class TestNamingRenames:
    """Phase-1 renames: reads go through `show`/`list`, old verbs stay as hidden
    aliases. Canonical = `agents <id> show --instructions`, `skills list --available`."""

    def _parse(self, *argv):
        return eesel.build_parser().parse_args(list(argv))

    # ── #5 instructions → show --instructions ──
    def test_show_instructions_flag_parses(self):
        a = self._parse("agents", "show", "blog", "--instructions")
        assert a.agents_cmd == "show"
        assert a.show_instructions is True

    def test_show_instructions_routes_to_prompt_printer(self, fake_creds, monkeypatch):
        called = {}

        def fake_instr(args):
            called["hit"] = getattr(args, "agent", None)
            return 0

        monkeypatch.setattr(eesel, "cmd_instructions", fake_instr)
        a = self._parse("agents", "show", "blog", "--instructions")
        assert eesel.cmd_agents(a) == 0
        assert called["hit"] == "blog"  # routed with the id as the agent target

    def test_plain_show_does_not_route_to_prompt(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "cmd_instructions", lambda args: pytest.fail("plain show must not print only the prompt"))
        monkeypatch.setattr(eesel, "_agents_get", lambda args, creds: 0)
        a = self._parse("agents", "show", "blog")
        assert eesel.cmd_agents(a) == 0

    def test_instructions_alias_still_works(self):
        a = self._parse("instructions", "blog")
        assert a.func is eesel.cmd_instructions

    # ── #3 available → list --available ──
    def test_skills_list_available_flag_parses(self):
        a = self._parse("skills", "list", "blog", "--available")
        assert a.skills_cmd == "list"
        assert a.available is True

    def test_skills_list_available_fetches_marketplace(self, fake_creds, monkeypatch):
        seen = {}
        monkeypatch.setattr(eesel, "resolve_agent_or_error", lambda creds, t: {"agent_id": "a1", "name": "Bot"})
        monkeypatch.setattr(eesel, "fetch_agent_skills", lambda creds, aid, **kw: seen.update(kw) or [])
        a = self._parse("skills", "list", "blog", "--available")
        eesel.cmd_skills(a)
        assert seen.get("filter_") == "available"  # routed to the catalog, not installed

    def test_skills_plain_list_fetches_installed(self, fake_creds, monkeypatch):
        seen = {}
        monkeypatch.setattr(eesel, "resolve_agent_or_error", lambda creds, t: {"agent_id": "a1", "name": "Bot"})
        monkeypatch.setattr(eesel, "fetch_agent_skills", lambda creds, aid, **kw: seen.update({"kw": kw}) or [])
        a = self._parse("skills", "list", "blog")
        eesel.cmd_skills(a)
        assert seen["kw"] == {}  # installed view: no filter_

    def test_skills_available_alias_is_removed(self):
        # `available` was a verb alias for `list --available`; it is removed and
        # no longer parses.
        with pytest.raises(SystemExit):
            self._parse("skills", "available", "blog")


class TestPathScopeParsesEndToEnd:
    """The reshaped argv must actually PARSE (argparse accepts it), not merely
    equal an expected tuple — a scoped noun whose flat handler doesn't accept the
    injected agent would still build a list here but fail to parse (rc=2). This
    asserts the reshape and the flat parsers stay in sync."""

    def _parses(self, *argv):
        # Mirror main(): path-scope reshape, then the integrations actions reshape.
        argv = eesel._normalize_path_scope_argv(list(argv))
        argv = eesel._normalize_integrations_argv(argv)
        # parse_args raises SystemExit on an unrecognized/invalid argv.
        eesel.build_parser().parse_args(argv)

    def test_agent_scoped_forms_parse(self):
        forms = [
            ("agents", "blog"),
            ("agents", "blog", "show"),
            ("agents", "blog", "show", "--instructions"),
            ("agents", "blog", "set", "name", "X"),
            ("agents", "blog", "integrations", "list"),
            ("agents", "blog", "integrations", "zd", "actions", "enable", "reply"),
            ("agents", "blog", "files", "list"),
            ("agents", "blog", "tasks", "list"),
            ("agents", "blog", "skills", "list"),
            ("agents", "blog", "skills", "show", "translation"),
            ("agents", "blog", "skills"),
            ("agents", "blog", "add", "zendesk"),
            ("agents", "blog", "remove", "zendesk"),
        ]
        for form in forms:
            try:
                self._parses(*form)
            except SystemExit:
                raise AssertionError(f"path form did not parse: {' '.join(form)}")


class TestPathScopeDiscoverable:
    """The path-as-scope forms are real but argparse can't list them (they reshape
    into flat commands). They must therefore be advertised in --help, or they're
    invisible to anyone who didn't read the source."""

    def _agents_help(self):
        agents = next(
            a for a in eesel.build_parser()._subparsers._group_actions[0].choices.values()
            if a.prog.endswith("agents")
        )
        return agents.format_help()

    def test_agents_help_documents_the_path_scope_grammar(self):
        h = self._agents_help()
        assert "scope by path" in h
        # The shape and a few representative scoped nouns are shown.
        assert "eesel agents <id> <noun>" in h or "agents <id> integrations list" in h
        for noun in ("integrations list", "skills list", "tasks list", "files list"):
            assert noun in h, f"path-scope help omits `agents <id> {noun}`"
        assert "show --instructions" in h

    def test_top_level_help_points_at_path_scope(self):
        h = eesel.build_parser().format_help()
        assert "agents <id> <noun> <verb>" in h


class TestPathScopeVerbScoping:
    """A 'flag' noun only injects --agent for verbs whose flat parser accepts it
    (files/tasks have verbs that don't). A verb the flat parser can't scope by
    agent must NOT get a mis-injected --agent; instead it exits with an error that
    names the verb (not the agent id), so a scoped `files acl` / `tasks show`
    fails clearly rather than reshaping into a command the handler would reject."""

    def n(self, *argv):
        return eesel._normalize_path_scope_argv(list(argv))

    def test_agent_accepting_verbs_get_scoped(self):
        assert self.n("agents", "blog", "files", "show", "k") == ["files", "show", "k", "--agent", "blog"]
        assert self.n("agents", "blog", "files", "add", "--title", "t") == ["files", "add", "--title", "t", "--agent", "blog"]
        assert self.n("agents", "blog", "tasks", "count") == ["tasks", "count", "--agent", "blog"]
        assert self.n("agents", "blog", "tasks", "analytics") == ["tasks", "analytics", "--agent", "blog"]

    def test_non_accepting_verbs_exit_naming_the_verb(self, capsys):
        # A verb the flat parser can't scope by agent exits (code 2) and the error
        # names the verb, never injecting --agent for the handler to choke on.
        # `acl` takes a positional <agent>, not an --agent flag, so it stays out
        # of the flag-mode path form (unlike list/show/read/add/remove/export).
        for verb in ("acl",):
            with pytest.raises(SystemExit) as exc:
                self.n("agents", "blog", "files", verb, "x")
            assert exc.value.code == 2
            assert f"`{verb}` is not an agent-scoped `files` verb" in capsys.readouterr().err
        for verb in ("show", "cost"):
            with pytest.raises(SystemExit):
                self.n("agents", "blog", "tasks", verb, "x")
            assert f"`{verb}` is not an agent-scoped `tasks` verb" in capsys.readouterr().err


class TestPathScopeBareNounListsConsistently:
    """A bare `agents <id> <noun>` (no verb) lists, the same way on every scoped
    noun — so the grammar isn't "skills lists but tasks errors". The verb defaults
    to `list`; a following flag (`--json`) keeps that default."""

    def n(self, *argv):
        return eesel._normalize_path_scope_argv(list(argv))

    def test_flag_mode_nouns_default_to_list(self):
        assert self.n("agents", "blog", "tasks") == ["tasks", "list", "--agent", "blog"]
        assert self.n("agents", "blog", "files") == ["files", "list", "--agent", "blog"]
        assert self.n("agents", "blog", "integrations") == ["integrations", "list", "--agent", "blog"]

    def test_pos_mode_noun_defaults_to_list(self):
        assert self.n("agents", "blog", "skills") == ["skills", "list", "blog"]

    def test_default_list_keeps_a_trailing_flag(self):
        assert self.n("agents", "blog", "tasks", "--json") == ["tasks", "list", "--json", "--agent", "blog"]


class TestPathScopeUnknownHeadErrors:
    """`agents <id> <something>` where <something> isn't an agent verb or scoped
    noun exits with an error that names the bad token — not the flat parser's
    `invalid choice: '<agent-id>'`, which blamed the agent id."""

    def n(self, *argv):
        return eesel._normalize_path_scope_argv(list(argv))

    def test_not_yet_scoped_noun_names_itself(self, capsys):
        with pytest.raises(SystemExit) as exc:
            self.n("agents", "blog", "triggers", "list")
        assert exc.value.code == 2
        out = capsys.readouterr().err
        assert "`triggers` is not an agent command" in out
        # names the noun, and points at the workspace-level command for it
        assert "eesel automations triggers" in out

    def test_typo_suggests_the_real_noun(self, capsys):
        with pytest.raises(SystemExit):
            self.n("agents", "blog", "integratons", "list")
        assert "Did you mean `integrations`?" in capsys.readouterr().err

    def test_add_without_a_pool_errors_clearly(self, capsys):
        with pytest.raises(SystemExit) as exc:
            self.n("agents", "blog", "remove")
        assert exc.value.code == 2
        assert "needs an integration to remove" in capsys.readouterr().err

    def test_a_trailing_flag_head_is_left_for_argparse(self):
        # A flag (not a word) after the agent is ambiguous; leave it untouched
        # rather than erroring, so argparse handles it as before.
        assert self.n("agents", "blog", "--json") == ["agents", "blog", "--json"]


# ──────────────────────────────────────────────────────────────────────────
# Input validation — id/key rejection before the network
# ──────────────────────────────────────────────────────────────────────────


class TestValidateId:
    def test_accepts_plain_id_unchanged(self):
        assert eesel.validate_id("agent-abc123") == "agent-abc123"

    def test_accepts_uuid(self):
        assert eesel.validate_id("2b2f5b56-0415-4378-abf7-ef0b5631c856")

    def test_empty_and_none_pass_through(self):
        # "no id given" is handled downstream, not treated as malformed here.
        assert eesel.validate_id("") == ""
        assert eesel.validate_id(None) is None

    @pytest.mark.parametrize("bad", ["../creds", "a/b", "/leading", "files/x"])
    def test_rejects_any_slash(self, bad):
        with pytest.raises(SystemExit) as exc:
            eesel.validate_id(bad)
        assert exc.value.code == eesel.EXIT_VALIDATION

    def test_rejects_double_dot(self):
        with pytest.raises(SystemExit) as exc:
            eesel.validate_id("..")
        assert exc.value.code == 5

    @pytest.mark.parametrize("bad", ["a\nb", "a\x00b", "a\x1fb", "a\x7fb"])
    def test_rejects_control_chars(self, bad):
        with pytest.raises(SystemExit) as exc:
            eesel.validate_id(bad)
        assert exc.value.code == 5

    @pytest.mark.parametrize("bad", ["a?b", "a#b", "a%2e"])
    def test_rejects_url_metachars(self, bad):
        with pytest.raises(SystemExit) as exc:
            eesel.validate_id(bad)
        assert exc.value.code == 5

    def test_message_names_the_offending_input(self, capsys):
        with pytest.raises(SystemExit):
            eesel.validate_id("../../workspaces/other", "agent")
        err = capsys.readouterr().err
        assert "agent" in err
        assert "../../workspaces/other" in err


class TestValidateKey:
    def test_accepts_interior_slash(self):
        assert eesel.validate_key("files/report.md") == "files/report.md"

    def test_accepts_bare_filename(self):
        assert eesel.validate_key("report.md") == "report.md"

    def test_accepts_display_name_with_spaces(self):
        # Action references may be display names; a space is not a URL hazard.
        assert eesel.validate_key("Search tickets") == "Search tickets"

    def test_rejects_traversal_segment(self):
        with pytest.raises(SystemExit) as exc:
            eesel.validate_key("files/../secret")
        assert exc.value.code == 5

    def test_rejects_leading_slash(self):
        with pytest.raises(SystemExit) as exc:
            eesel.validate_key("/files/x")
        assert exc.value.code == 5

    def test_dotdot_only_when_a_whole_segment(self):
        # A literal ".." substring inside a segment is not traversal.
        assert eesel.validate_key("files/a..b.md") == "files/a..b.md"

    @pytest.mark.parametrize("bad", ["a?b", "a#b", "a%b", "x\x01y"])
    def test_rejects_control_and_metachars(self, bad):
        with pytest.raises(SystemExit) as exc:
            eesel.validate_key(bad)
        assert exc.value.code == 5


# ──────────────────────────────────────────────────────────────────────────
# Atomic, locked writes — a crash or race can't corrupt a session (part 1)
# ──────────────────────────────────────────────────────────────────────────


class TestAtomicWrites:
    def test_roundtrip(self, tmp_path):
        p = tmp_path / "x.json"
        eesel._atomic_write(p, json.dumps({"a": 1}))
        assert json.loads(p.read_text()) == {"a": 1}

    def test_applies_mode(self, tmp_path):
        import os, stat
        p = tmp_path / "creds.json"
        eesel._atomic_write(p, "{}", mode=0o600)
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600

    def test_creates_parent_dir(self, tmp_path):
        p = tmp_path / "nested" / "deep" / "x.json"
        eesel._atomic_write(p, "{}")
        assert p.exists()

    def test_leaves_no_temp_file_behind(self, tmp_path):
        p = tmp_path / "x.json"
        eesel._atomic_write(p, "{}")
        leftovers = [q.name for q in tmp_path.iterdir() if q.name.endswith(".tmp")]
        assert leftovers == []

    def test_credentials_write_is_atomic_and_0600(self, tmp_config):
        import os, stat
        eesel.save_creds({"env": "dev", "token": "t", "workspace_id": "w"})
        assert stat.S_IMODE(os.stat(eesel.CREDS_FILE).st_mode) == 0o600
        assert json.loads(eesel.CREDS_FILE.read_text())["token"] == "t"

    def test_concurrent_writers_never_leave_unparseable_file(self, tmp_config):
        """Many threads hammering the same session file, with a reader parsing it
        on every iteration, must never see empty/truncated/half-written JSON.

        This is the read-back that proves the "crash mid-write drops the whole
        conversation" bug is closed: the atomic replace means a reader (or a
        crash) only ever observes a complete file.
        """
        import threading
        eesel.ensure_dirs()
        errors: list = []
        stop = threading.Event()

        def writer(n: int):
            for i in range(60):
                eesel.save_session({
                    "id": "hot",
                    "messages": [{"sender": "user", "message": f"{n}-{i}"}] * (i + 1),
                })

        def reader():
            path = eesel._session_path("hot")
            while not stop.is_set():
                if path.exists():
                    try:
                        json.loads(path.read_text())
                    except (json.JSONDecodeError, ValueError) as e:
                        errors.append(str(e))

        eesel.save_session({"id": "hot", "messages": []})
        writers = [threading.Thread(target=writer, args=(n,)) for n in range(6)]
        r = threading.Thread(target=reader)
        r.start()
        for w in writers:
            w.start()
        for w in writers:
            w.join()
        stop.set()
        r.join()
        assert errors == []
        # Final file is still valid.
        assert isinstance(json.loads(eesel._session_path("hot").read_text()), dict)

    def test_failed_replace_leaves_old_file_and_no_temp(self, tmp_path, monkeypatch):
        # A failed write must not destroy the existing file or strand a temp file.
        p = tmp_path / "x.json"
        eesel._atomic_write(p, json.dumps({"good": 1}))
        monkeypatch.setattr(eesel.os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
        with pytest.raises(OSError):
            eesel._atomic_write(p, json.dumps({"bad": 2}))
        assert json.loads(p.read_text()) == {"good": 1}  # old content intact
        assert [q.name for q in tmp_path.iterdir() if q.name.endswith(".tmp")] == []


# ──────────────────────────────────────────────────────────────────────────
# EESEL_SESSION — parallel-safe sessions pinned per run (part 1)
# ──────────────────────────────────────────────────────────────────────────


class TestPinnedSession:
    def test_none_when_unset(self, monkeypatch):
        monkeypatch.delenv("EESEL_SESSION", raising=False)
        assert eesel._pinned_session_id() is None

    def test_blank_is_none(self, monkeypatch):
        monkeypatch.setenv("EESEL_SESSION", "   ")
        assert eesel._pinned_session_id() is None

    def test_returns_the_id(self, monkeypatch):
        monkeypatch.setenv("EESEL_SESSION", "run-alpha")
        assert eesel._pinned_session_id() == "run-alpha"

    def test_traversal_value_rejected_exit_5(self, monkeypatch):
        monkeypatch.setenv("EESEL_SESSION", "../creds")
        with pytest.raises(SystemExit) as exc:
            eesel._pinned_session_id()
        assert exc.value.code == 5

    def test_pin_creates_session_with_that_id_and_no_current_pointer(self, tmp_config, monkeypatch):
        monkeypatch.setenv("EESEL_SESSION", "alpha")
        creds = {"workspace_id": "w-1", "agent_id": "a-1"}
        sess = eesel.ensure_current_session(creds, agent_id="a-1")
        assert sess["id"] == "alpha"
        assert eesel.load_session("alpha") is not None
        # current.json is never written by the pinned path.
        assert not eesel.CURRENT_FILE.exists()
        assert eesel.load_current() is None

    def test_pin_leaves_existing_current_json_byte_for_byte(self, tmp_config, monkeypatch):
        eesel.set_current("human-session")
        before = eesel.CURRENT_FILE.read_bytes()
        monkeypatch.setenv("EESEL_SESSION", "alpha")
        eesel.ensure_current_session({"workspace_id": "w-1", "agent_id": "a-1"}, agent_id="a-1")
        assert eesel.CURRENT_FILE.read_bytes() == before

    def test_pin_reuses_existing_session(self, tmp_config, monkeypatch):
        monkeypatch.setenv("EESEL_SESSION", "alpha")
        creds = {"workspace_id": "w-1", "agent_id": "a-1"}
        first = eesel.ensure_current_session(creds, agent_id="a-1")
        first["messages"].append({"sender": "user", "message": "hi"})
        eesel.save_session(first)
        second = eesel.ensure_current_session(creds, agent_id="a-1")
        assert second["id"] == "alpha"
        assert second["messages"] == [{"sender": "user", "message": "hi"}]

    def test_two_pins_do_not_cross_contaminate(self, tmp_config, monkeypatch):
        creds = {"workspace_id": "w-1", "agent_id": "a-1"}
        monkeypatch.setenv("EESEL_SESSION", "alpha")
        a = eesel.ensure_current_session(creds, agent_id="a-1")
        a["messages"].append({"sender": "user", "message": "for-alpha"})
        eesel.save_session(a)
        monkeypatch.setenv("EESEL_SESSION", "beta")
        b = eesel.ensure_current_session(creds, agent_id="a-1")
        b["messages"].append({"sender": "user", "message": "for-beta"})
        eesel.save_session(b)
        alpha = eesel.load_session("alpha")
        beta = eesel.load_session("beta")
        assert [m["message"] for m in alpha["messages"]] == ["for-alpha"]
        assert [m["message"] for m in beta["messages"]] == ["for-beta"]
        assert not eesel.CURRENT_FILE.exists()

    def test_unpinned_still_uses_current_pointer(self, tmp_config, monkeypatch):
        monkeypatch.delenv("EESEL_SESSION", raising=False)
        creds = {"workspace_id": "w-1", "agent_id": "a-1"}
        first = eesel.ensure_current_session(creds, agent_id="a-1")
        # Sticky: a second call with no env var returns the same session.
        second = eesel.ensure_current_session(creds, agent_id="a-1")
        assert first["id"] == second["id"]
        assert eesel.load_current() == first["id"]

    def test_new_session_honours_explicit_id(self, tmp_config):
        sess = eesel.new_session({"workspace_id": "w-1", "agent_id": "a-1"},
                                 agent_id="a-1", name=None, switch_to=False, session_id="pinned-x")
        assert sess["id"] == "pinned-x"
        assert not eesel.CURRENT_FILE.exists()  # switch_to=False


# ──────────────────────────────────────────────────────────────────────────
# Input hardening end-to-end — reject before any network call (part 2)
# ──────────────────────────────────────────────────────────────────────────


class TestInputHardeningNoNetwork:
    @pytest.fixture(autouse=True)
    def _no_network(self, monkeypatch):
        # Any real request is a test failure: validation must fail closed first.
        def boom(*a, **k):
            raise AssertionError("network call made before validation")
        monkeypatch.setattr(eesel, "http_request", boom)
        monkeypatch.setattr(eesel, "http_request_allow_error", boom)
        monkeypatch.delenv("EESEL_BASE_URL", raising=False)
        monkeypatch.delenv("EESEL_AGENT", raising=False)

    def test_agents_traversal_target_never_becomes_a_path(self, fake_creds, monkeypatch):
        # A traversal target is no longer pre-rejected as raw input — it is
        # resolved against the agent list like any id-or-name. Matching nothing,
        # it is a clean "no such agent" (rc 1) and never becomes a URL path
        # segment. (The one below would only reach a URL if it were an agent's
        # real id, which the central choke point would then reject.)
        monkeypatch.setattr(eesel, "fetch_agents",
                            lambda creds: [{"agent_id": "agent-abc123", "name": "Support Bot"}])
        args = argparse.Namespace(agents_cmd="show", agent_id="../../workspaces/other",
                                  show_instructions=False, json=False)
        assert eesel.cmd_agents(args) == 1

    def test_skills_add_traversal_rejected(self, fake_creds):
        args = argparse.Namespace(skills_cmd="add", agent="a-1", skill_id="../x", force=True)
        with pytest.raises(SystemExit) as exc:
            eesel.cmd_skills(args)
        assert exc.value.code == 5

    def test_files_export_traversal_key_never_becomes_a_path(self, fake_creds, monkeypatch):
        # A `--document-key` is matched client-side against the agent's own files,
        # not pre-validated as raw input (a real filename may carry `% # ?`). A
        # key that can't belong to this agent is a clean rejection (rc 1) and
        # never becomes a URL path segment.
        monkeypatch.setattr(eesel, "fetch_agents",
                            lambda creds: [{"agent_id": "agent-test-456", "name": "Bot"}])
        args = argparse.Namespace(document_id=None, document_key="files/../secret",
                                  format="md", output=None, agent=None)
        assert eesel.cmd_files_export(args) == 1

    def test_tasks_show_control_char_rejected(self, fake_creds):
        with pytest.raises(SystemExit) as exc:
            eesel.resolve_task_id(fake_creds, "abc\ndef")
        assert exc.value.code == 5

    def test_wellformed_key_passes_validation(self):
        # A legitimate key with interior slashes is not rejected.
        assert eesel.validate_key("files/report.md") == "files/report.md"


# ──────────────────────────────────────────────────────────────────────────
# Central URL-path choke point — traversal fails closed inside the HTTP helper
# even if a caller forgot to validate its id (part 3)
# ──────────────────────────────────────────────────────────────────────────


class TestUrlPathChokePoint:
    @pytest.mark.parametrize("url", [
        "https://api.example.com/agents/../secret",
        "https://api.example.com/agents/../../workspaces/other/mcp-servers",
        "https://api.example.com/documents/%2e%2e/export-link",   # encoded ..
        "https://api.example.com/agents/..%2Fsecret/tools",       # encoded / hides ..
        "https://api.example.com/agents/./triggers",              # single-dot segment
    ])
    def test_rejects_traversal_path(self, url):
        with pytest.raises(SystemExit) as exc:
            eesel.assert_url_path_safe(url)
        assert exc.value.code == eesel.EXIT_VALIDATION

    def test_rejects_control_char_in_path(self):
        with pytest.raises(SystemExit) as exc:
            eesel.assert_url_path_safe("https://api.example.com/agents/a%00b/tools")
        assert exc.value.code == eesel.EXIT_VALIDATION

    @pytest.mark.parametrize("url", [
        "https://api.example.com/agents/agent-abc123/triggers",
        "https://api.example.com/documents/2b2f5b56-0415-4378-abf7-ef0b5631c856/export-link",
        # An interior '..' that is not a whole segment is a legitimate key part.
        "https://api.example.com/documents/files/a..b.md/export-link",
    ])
    def test_allows_ordinary_paths(self, url):
        assert eesel.assert_url_path_safe(url) is None

    def test_allows_metachars_in_query_string(self):
        # A title/filename passed as a query value legitimately carries % # ? —
        # only the path is guarded, so these must not trip the check.
        url = "https://api.example.com/documents?prefix=files/Report%20100%25.md&q=a#b?c"
        assert eesel.assert_url_path_safe(url) is None

    def test_allows_encoded_display_name_in_path(self):
        # A display name resolved to a key and run through urllib.parse.quote
        # decodes to an ordinary string, so the encoded % does not read as a
        # traversal or control char.
        seg = eesel.urllib.parse.quote("Search % discounts", safe="")
        url = f"https://api.example.com/agents/a1/tools/{seg}"
        assert eesel.assert_url_path_safe(url) is None

    def test_http_request_aborts_before_sending_on_traversal(self, monkeypatch):
        # The guard runs inside http_request, so a traversal URL never reaches
        # urlopen — proving the choke point is fail-closed regardless of caller.
        def boom(*a, **k):
            raise AssertionError("request sent despite traversal path")
        monkeypatch.setattr(eesel.urllib.request, "urlopen", boom)
        with pytest.raises(SystemExit) as exc:
            eesel.http_request("GET", "https://api.example.com/agents/../secret", token="t")
        assert exc.value.code == eesel.EXIT_VALIDATION


# ──────────────────────────────────────────────────────────────────────────
# id-or-name lookups: a human name/title/filename with URL metacharacters
# resolves to a slash-free id instead of being rejected as raw input (part 3)
# ──────────────────────────────────────────────────────────────────────────


class TestNameLookupsAllowMetachars:
    def test_agent_name_with_slash_resolves(self, monkeypatch):
        # An agent literally named "Support/Billing" must resolve by exact name;
        # the raw name is never validated, only the resolved (slash-free) id.
        agents = [{"agent_id": "agent-xyz789", "name": "Support/Billing"}]
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: agents)
        agent = eesel.resolve_agent_or_error({"token": "t"}, "Support/Billing")
        assert agent["agent_id"] == "agent-xyz789"

    def test_agent_env_override_name_with_slash_resolves(self, fake_creds, monkeypatch):
        agents = [{"agent_id": "agent-xyz789", "name": "Support/Billing"}]
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: agents)
        monkeypatch.setenv("EESEL_AGENT", "Support/Billing")
        out = eesel.apply_agent_env_override({"agent_id": None, "token": "t"})
        assert out["agent_id"] == "agent-xyz789"

    def test_agent_filter_name_with_slash_resolves(self, monkeypatch):
        agents = [{"agent_id": "agent-xyz789", "name": "Support/Billing"}]
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: agents)
        assert eesel.resolve_agent_filter({"token": "t"}, "Support/Billing") == "agent-xyz789"

    def test_scheduled_job_title_with_percent_resolves(self, monkeypatch):
        # Job titled "Q3 report (50% sample)" — a '50%' title substring must
        # resolve, not be rejected on the '%'.
        jobs = [{"id": "sch-1", "config": {"title": "Q3 report (50% sample)"}}]
        monkeypatch.setattr(eesel, "fetch_all_scheduled_jobs", lambda creds: jobs)
        assert eesel.resolve_scheduled_job({"token": "t"}, "50%")["id"] == "sch-1"
        assert eesel.resolve_scheduled_job_strict({"token": "t"}, "50%")["id"] == "sch-1"

    def test_mcp_server_name_with_slash_and_hash_resolves(self, monkeypatch):
        # A server whose name is a URL ("https://mcp.example.com/sse") or carries
        # a '#' must resolve by exact name, not be rejected on '/' or '#'.
        servers = [
            {"id": "srv-1", "name": "https://mcp.example.com/sse"},
            {"id": "srv-2", "name": "staging #2"},
        ]
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds, **k: servers)
        assert eesel._resolve_one_mcp_server({"token": "t"}, "https://mcp.example.com/sse")["id"] == "srv-1"
        assert eesel._resolve_one_mcp_server({"token": "t"}, "staging #2")["id"] == "srv-2"

    def test_resolved_id_still_validated(self, monkeypatch):
        # Defense in depth: if resolution somehow yields an id that would traverse
        # a URL path, it is still rejected (exit 5) rather than passed through.
        agents = [{"agent_id": "../../workspaces/other", "name": "Evil"}]
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: agents)
        with pytest.raises(SystemExit) as exc:
            eesel.resolve_agent_or_error({"token": "t"}, "Evil")
        assert exc.value.code == eesel.EXIT_VALIDATION


# ──────────────────────────────────────────────────────────────────────────
# EESEL_SESSION vs an explicit agent — never silently route to the wrong agent
# ──────────────────────────────────────────────────────────────────────────


class TestPinnedSessionAgentConflict:
    def test_explicit_agent_conflict_fails_loud(self, tmp_config, monkeypatch, capsys):
        # A session pinned via EESEL_SESSION belongs to agent A; an explicit
        # --agent/EESEL_AGENT names agent B. Routing the turn to A would swap the
        # target invisibly, so the run must abort with EXIT_VALIDATION.
        monkeypatch.setenv("EESEL_SESSION", "pinned-run")
        creds = {"workspace_id": "w-1", "agent_id": "agent-A"}
        eesel.ensure_current_session(creds, agent_id="agent-A")  # create for A
        with pytest.raises(SystemExit) as exc:
            eesel.ensure_current_session(creds, agent_id="agent-B", agent_explicit=True)
        assert exc.value.code == eesel.EXIT_VALIDATION
        assert "agent" in capsys.readouterr().err.lower()

    def test_auto_selected_agent_conflict_uses_pinned_with_note(self, tmp_config, monkeypatch, capsys):
        # When the agent was auto-picked (not explicitly requested), the pin still
        # wins with an informational note — no abort.
        monkeypatch.setenv("EESEL_SESSION", "pinned-run")
        creds = {"workspace_id": "w-1", "agent_id": "agent-A"}
        eesel.ensure_current_session(creds, agent_id="agent-A")
        sess = eesel.ensure_current_session(creds, agent_id="agent-B", agent_explicit=False)
        assert sess["agent_id"] == "agent-A"
        assert "pinned session" in capsys.readouterr().err.lower()

    def test_matching_explicit_agent_reuses_pinned(self, tmp_config, monkeypatch):
        # No conflict: the explicit agent equals the pinned session's agent.
        monkeypatch.setenv("EESEL_SESSION", "pinned-run")
        creds = {"workspace_id": "w-1", "agent_id": "agent-A"}
        first = eesel.ensure_current_session(creds, agent_id="agent-A", agent_explicit=True)
        again = eesel.ensure_current_session(creds, agent_id="agent-A", agent_explicit=True)
        assert first["id"] == again["id"] == "pinned-run"


# ──────────────────────────────────────────────────────────────────────────
# Credentials temp file is never world-readable, even briefly (part 3)
# ──────────────────────────────────────────────────────────────────────────


class TestCredentialsTempPermissions:
    def test_temp_created_with_0600_not_default_umask(self, tmp_path, monkeypatch):
        # The bytes must never touch a file other local users can read. Capture
        # the mode the temp file is *created* with (os.open), not just its final
        # mode, so a create-at-0644-then-chmod window would be caught here.
        real_open = os.open
        seen: list[int] = []

        def spy_open(path, flags, mode=0o777, *a, **k):
            seen.append(mode)
            return real_open(path, flags, mode, *a, **k)

        monkeypatch.setattr(eesel.os, "open", spy_open)
        p = tmp_path / "credentials.json"
        eesel._atomic_write(p, '{"token": "secret"}', mode=0o600)
        assert seen and all(m == 0o600 for m in seen)

    def test_temp_write_never_group_or_world_readable(self, tmp_path):
        # A permissive process umask must not widen the credentials temp file.
        import stat
        old = os.umask(0)
        try:
            p = tmp_path / "credentials.json"
            eesel._atomic_write(p, '{"token": "secret"}', mode=0o600)
            assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
        finally:
            os.umask(old)


# ──────────────────────────────────────────────────────────────────────────
# Machine-output contract: emit(), --fields, NDJSON, --dry-run, schema
# (self-describing & previewable CLI)
# ──────────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_output_globals():
    """Restore the output-contract module globals before and after each test.

    Handlers read these globals; a test that flips one (e.g. to JSON) must not
    leak that into the next test, which may call a handler directly and rely on
    the human/no-op defaults.
    """
    saved = (eesel._OUTPUT_FORMAT, eesel._OUTPUT_FIELDS, eesel._DRY_RUN, eesel._REVEAL_SECRETS)
    eesel._OUTPUT_FORMAT, eesel._OUTPUT_FIELDS, eesel._DRY_RUN, eesel._REVEAL_SECRETS = "human", None, False, False
    # The impersonator-status lookup is memoized per token for a process's life;
    # clear it between tests so a cached verdict from one test can't leak into
    # another that reuses the same token with a different mocked response.
    eesel._IMPERSONATE_STATUS_CACHE.clear()
    yield
    eesel._OUTPUT_FORMAT, eesel._OUTPUT_FIELDS, eesel._DRY_RUN, eesel._REVEAL_SECRETS = saved
    eesel._IMPERSONATE_STATUS_CACHE.clear()


class TestProjectFields:
    def test_keeps_only_requested_top_level_keys(self):
        row = {"agent_id": "a1", "name": "Bot", "prompt": "long", "is_active": True}
        assert eesel._project_fields(row, ["agent_id", "name"]) == {"agent_id": "a1", "name": "Bot"}

    def test_applies_elementwise_to_a_list(self):
        rows = [{"a": 1, "b": 2}, {"a": 3, "b": 4}]
        assert eesel._project_fields(rows, ["a"]) == [{"a": 1}, {"a": 3}]

    def test_unknown_field_is_omitted_not_an_error(self):
        assert eesel._project_fields({"a": 1}, ["a", "nope"]) == {"a": 1}

    def test_scalar_payload_passes_through(self):
        assert eesel._project_fields("hello", ["a"]) == "hello"
        assert eesel._project_fields(["x", "y"], ["a"]) == ["x", "y"]


class TestWantJson:
    def test_true_from_per_command_flag(self):
        assert eesel._want_json(type("A", (), {"json": True})()) is True

    def test_true_from_global_format(self, monkeypatch):
        monkeypatch.setattr(eesel, "_OUTPUT_FORMAT", "json")
        assert eesel._want_json(type("A", (), {})()) is True

    def test_false_by_default(self):
        assert eesel._want_json(type("A", (), {})()) is False


class TestEmit:
    def test_masks_secrets_by_default(self, capsys):
        eesel.emit({"name": "x", "access_token": "sk-123"})
        payload = json.loads(capsys.readouterr().out)
        assert payload == {"name": "x", "access_token": "***"}

    def test_reveal_true_leaves_secrets_raw(self, capsys):
        eesel.emit({"access_token": "sk-123"}, reveal=True)
        assert json.loads(capsys.readouterr().out)["access_token"] == "sk-123"

    def test_reveal_none_defers_to_global(self, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "_REVEAL_SECRETS", True)
        eesel.emit({"access_token": "sk-123"})
        assert json.loads(capsys.readouterr().out)["access_token"] == "sk-123"

    def test_fields_argument_projects(self, capsys):
        eesel.emit({"a": 1, "b": 2}, fields=["a"])
        assert json.loads(capsys.readouterr().out) == {"a": 1}

    def test_global_fields_projects_when_no_arg(self, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "_OUTPUT_FIELDS", ["b"])
        eesel.emit({"a": 1, "b": 2})
        assert json.loads(capsys.readouterr().out) == {"b": 2}

    def test_list_streams_ndjson_when_json_and_piped(self, monkeypatch, capsys):
        # JSON active + not a TTY (capsys) → one object per line.
        monkeypatch.setattr(eesel, "_OUTPUT_FORMAT", "json")
        monkeypatch.setattr(eesel, "_is_tty", lambda: False)
        eesel.emit([{"a": 1}, {"a": 2}])
        lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
        assert [json.loads(l) for l in lines] == [{"a": 1}, {"a": 2}]

    def test_list_is_one_pretty_array_on_a_tty(self, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "_OUTPUT_FORMAT", "json")
        monkeypatch.setattr(eesel, "_is_tty", lambda: True)
        eesel.emit([{"a": 1}, {"a": 2}])
        assert json.loads(capsys.readouterr().out) == [{"a": 1}, {"a": 2}]

    def test_list_is_one_array_when_format_human_even_if_piped(self, monkeypatch, capsys):
        # A handler invoked directly (no main()) leaves _OUTPUT_FORMAT="human";
        # its list --json output must stay a parseable whole array, not NDJSON —
        # this is what keeps the pre-existing direct-handler json.loads tests green.
        monkeypatch.setattr(eesel, "_is_tty", lambda: False)
        eesel.emit([{"a": 1}, {"a": 2}])
        assert json.loads(capsys.readouterr().out) == [{"a": 1}, {"a": 2}]


class TestExtractGlobalOutputFlags:
    def test_extracts_booleans_anywhere(self):
        rest, vals = eesel._extract_global_output_flags(["agents", "create", "--dry-run", "--json"])
        assert rest == ["agents", "create"]
        assert vals["dry_run"] is True and vals["json"] is True

    def test_fields_consumes_following_token(self):
        rest, vals = eesel._extract_global_output_flags(["agents", "list", "--fields", "a,b"])
        assert rest == ["agents", "list"] and vals["fields"] == "a,b"

    def test_fields_inline_equals(self):
        rest, vals = eesel._extract_global_output_flags(["--fields=a,b", "x"])
        assert rest == ["x"] and vals["fields"] == "a,b"

    def test_fields_does_not_swallow_a_following_flag(self):
        # `--fields --json` must leave --json intact rather than take it as the
        # fields value (which would silently disable JSON). With no real value,
        # fields stays unset and the following flag is still parsed.
        rest, vals = eesel._extract_global_output_flags(["schema", "--fields", "--json"])
        assert rest == ["schema"]
        assert vals["fields"] is None
        assert vals["json"] is True

    def test_fields_at_end_with_no_value_stays_unset(self):
        rest, vals = eesel._extract_global_output_flags(["agents", "list", "--fields"])
        assert rest == ["agents", "list"]
        assert vals["fields"] is None

    def test_passes_through_unrelated_tokens(self):
        rest, vals = eesel._extract_global_output_flags(["agents", "list", "--plain"])
        assert rest == ["agents", "list", "--plain"]
        # legacy/platform were added as global platform-override flags.
        assert vals == {"json": False, "dry_run": False, "secrets": False, "fields": None, "legacy": False, "platform": False}


class TestConfigureOutput:
    def test_env_output_json_sets_json_format(self, monkeypatch):
        monkeypatch.setenv("EESEL_OUTPUT", "json")
        args = type("A", (), {"json": False})()
        eesel._configure_output(args, {"json": False, "dry_run": False, "fields": None}, None)
        assert eesel._OUTPUT_FORMAT == "json"

    def test_fields_parsed_into_list(self, monkeypatch):
        monkeypatch.delenv("EESEL_OUTPUT", raising=False)
        eesel._configure_output(type("A", (), {"json": True})(), {"json": True, "dry_run": False, "fields": "a, b ,c"}, None)
        assert eesel._OUTPUT_FIELDS == ["a", "b", "c"]

    def test_dry_run_flag_sets_global(self, monkeypatch):
        monkeypatch.delenv("EESEL_OUTPUT", raising=False)
        eesel._configure_output(type("A", (), {"json": False})(), {"json": False, "dry_run": True, "fields": None}, None)
        assert eesel._DRY_RUN is True

    def test_secrets_needs_sysadmin(self, monkeypatch):
        monkeypatch.delenv("EESEL_OUTPUT", raising=False)
        monkeypatch.setattr(eesel, "_is_sysadmin", lambda creds: False)
        eesel._configure_output(type("A", (), {"json": False, "secrets": True})(), {"json": False, "dry_run": False, "fields": None}, {"token": "t"})
        assert eesel._REVEAL_SECRETS is False
        monkeypatch.setattr(eesel, "_is_sysadmin", lambda creds: True)
        eesel._configure_output(type("A", (), {"json": False, "secrets": True})(), {"json": False, "dry_run": False, "fields": None}, {"token": "t"})
        assert eesel._REVEAL_SECRETS is True


class TestWriteRequestDryRun:
    def test_dry_run_prints_resolved_request_and_exits_zero(self, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "_DRY_RUN", True)
        called = []
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: called.append(a) or {})
        with pytest.raises(SystemExit) as exc:
            eesel.write_request("POST", "https://api/agents", token="t", body={"name": "X"})
        assert exc.value.code == 0
        assert called == []  # no real call was made
        payload = json.loads(capsys.readouterr().out)
        assert payload == {"method": "POST", "url": "https://api/agents", "body": {"name": "X"}}

    def test_dry_run_masks_secret_in_previewed_body(self, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "_DRY_RUN", True)
        with pytest.raises(SystemExit):
            eesel.write_request("POST", "https://api/x", body={"api_key": "sk-9"})
        assert json.loads(capsys.readouterr().out)["body"]["api_key"] == "***"

    def test_passthrough_when_not_dry_run(self, monkeypatch):
        monkeypatch.setattr(eesel, "_DRY_RUN", False)
        monkeypatch.setattr(eesel, "http_request", lambda method, url, **k: {"ok": method})
        assert eesel.write_request("DELETE", "https://api/x", token="t") == {"ok": "DELETE"}

    def test_allow_error_passthrough_returns_tuple(self, monkeypatch):
        monkeypatch.setattr(eesel, "_DRY_RUN", False)
        monkeypatch.setattr(eesel, "http_request_allow_error", lambda method, url, **k: (400, {"error": "bad"}))
        assert eesel.write_request("POST", "https://api/x", body={}, allow_error=True) == (400, {"error": "bad"})


class TestSchema:
    def _schema(self):
        parser = eesel.build_parser(staff=True)
        return eesel._serialize_parser(parser)

    def test_lists_every_top_level_command(self):
        s = self._schema()
        names = set(s["subcommands"])
        for expected in ("agents", "integrations", "automations", "mcp", "files", "skills", "workspace", "schema"):
            assert expected in names

    def test_flag_reports_names_required_and_enum_choices(self):
        s = self._schema()
        show = s["subcommands"]["files"]["subcommands"]["show"]
        fmt = next(f for f in show["flags"] if "--format" in f["names"])
        assert fmt["choices"] == ["md", "html"]  # matches the parser's enum
        assert fmt["takes_value"] is True

    def test_every_command_resolves_to_a_real_handler(self):
        s = self._schema()
        missing = []

        def walk(node, path):
            subs = node.get("subcommands", {})
            if not subs and "handler" not in node:
                missing.append(".".join(path))
            for name, sub in subs.items():
                walk(sub, path + [name])

        walk(s, [])
        assert missing == []

    def test_handler_names_exist_on_the_module(self):
        s = self._schema()

        def walk(node):
            if "handler" in node:
                assert hasattr(eesel, node["handler"]), node["handler"]
            for sub in node.get("subcommands", {}).values():
                walk(sub)

        walk(s)

    def test_endpoint_annotation_attached_to_writes(self):
        s = self._schema()
        create = s["subcommands"]["agents"]["subcommands"]["create"]
        assert create["endpoint"] == "POST /agents"

    def test_no_dead_endpoint_keys(self):
        # Every key in the hand-kept endpoint map points at a command that
        # actually exists in the parser tree.
        s = self._schema()
        paths = set()

        def walk(node, path):
            if path:
                paths.add(".".join(path))
            for name, sub in node.get("subcommands", {}).items():
                walk(sub, path + [name])

        walk(s, [])
        dead = [k for k in eesel._COMMAND_ENDPOINTS if k not in paths]
        assert dead == []

    def test_endpoint_values_match_a_real_request_call(self):
        # `test_no_dead_endpoint_keys` proves each KEY names a real command; this
        # pins each VALUE ("POST /agents") against the method+path the CLI's
        # request helpers actually issue, so a wrong annotation (wrong verb or
        # wrong path) is caught rather than silently misleading an agent.
        #
        # The check is static: parse the CLI source and collect the (method,
        # path) of every call to the request helpers (http_request /
        # http_request_allow_error / write_request, and GET-only http_fetch /
        # http_download). URL f-strings are rendered to a template with each
        # `{...}` interpolation collapsed to `{}`; the leading `{api_url}` and any
        # trailing glued query/suffix placeholder are stripped so a path segment
        # (`/agents/{}`) is distinguished from an appended query (`/integrations`
        # + `{qs}`). Then every endpoint value must appear among the collected
        # calls. This confirms the annotation corresponds to a real call with
        # that verb and path shape; it does not prove the call is reached by that
        # exact subcommand (branching handlers make several keys share a handler).
        request_funcs = {"http_request", "http_request_allow_error", "write_request"}
        fetch_funcs = {"http_fetch", "http_download"}  # GET-only helpers

        tree = ast.parse((_HERE / "eesel").read_text())

        def render(node, name_values):
            """Render a str constant or f-string to a template. A FormattedValue
            that is a bare name present in `name_values` is inlined with that
            literal; every other interpolation becomes `{}`."""
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            if isinstance(node, ast.JoinedStr):
                parts = []
                for v in node.values:
                    if isinstance(v, ast.Constant):
                        parts.append(str(v.value))
                    elif (isinstance(v, ast.FormattedValue)
                          and isinstance(v.value, ast.Name)
                          and v.value.id in name_values):
                        parts.append(name_values[v.value.id])
                    else:
                        parts.append("{}")
                return "".join(parts)
            return None

        # Module-level one-line `return "<f-string>"` helpers (e.g.
        # `_mcp_server_url`) so a call passing a literal argument (`"/toggle"`)
        # inlines it and resolves to the real path.
        helpers = {}
        for fn in tree.body:
            if (isinstance(fn, ast.FunctionDef) and len(fn.body) == 1
                    and isinstance(fn.body[0], ast.Return)
                    and isinstance(fn.body[0].value, (ast.JoinedStr, ast.Constant))):
                helpers[fn.name] = ([a.arg for a in fn.args.args], fn.body[0].value)

        def resolve(node, assigns):
            """Possible URL templates for a url expression: a literal/f-string, a
            variable assigned one earlier in the function, or a call to a simple
            return-only helper."""
            if isinstance(node, (ast.Constant, ast.JoinedStr)):
                t = render(node, {})
                return {t} if t is not None else set()
            if isinstance(node, ast.Name):
                return set(assigns.get(node.id, set()))
            if isinstance(node, ast.Call):
                fname = (node.func.attr if isinstance(node.func, ast.Attribute)
                         else getattr(node.func, "id", None))
                if fname in helpers:
                    params, ret = helpers[fname]
                    name_values = {
                        p: a.value for p, a in zip(params, node.args)
                        if isinstance(a, ast.Constant) and isinstance(a.value, str)
                    }
                    t = render(ret, name_values)
                    return {t} if t is not None else set()
            return set()

        def norm_path(tpl):
            if tpl is None:
                return None
            m = re.search(r"/.*", tpl)
            if not m:
                return None
            path = m.group(0).split("?")[0]
            path = re.sub(r"\{[^}]*\}", "{}", path)
            # A trailing `{}` not preceded by `/` is a glued query/suffix, not a
            # path segment (e.g. `/integrations` + `{qs}`) — drop it.
            while path.endswith("{}") and not path.endswith("/{}"):
                path = path[:-2]
            return path.rstrip("/") or "/"

        actual = set()
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            assigns: dict = {}
            for stmt in ast.walk(fn):
                if isinstance(stmt, ast.Assign):
                    templates = resolve(stmt.value, assigns)
                    for tgt in stmt.targets:
                        if isinstance(tgt, ast.Name) and templates:
                            assigns.setdefault(tgt.id, set()).update(templates)
            for call in ast.walk(fn):
                if not isinstance(call, ast.Call):
                    continue
                name = (call.func.attr if isinstance(call.func, ast.Attribute)
                        else getattr(call.func, "id", None))
                if name in fetch_funcs and call.args:
                    for t in resolve(call.args[0], assigns):
                        p = norm_path(t)
                        if p:
                            actual.add(("GET", p))
                elif name in request_funcs and len(call.args) >= 2:
                    method = call.args[0].value if isinstance(call.args[0], ast.Constant) else None
                    if method:
                        for t in resolve(call.args[1], assigns):
                            p = norm_path(t)
                            if p:
                                actual.add((method, p))

        def norm_ep(path):
            return re.sub(r"\{[^}]*\}", "{}", path).rstrip("/") or "/"

        # Residual gap: `integrations connect` POSTs to a path the connector
        # definition supplies at runtime (`option.endpoint`), so no path literal
        # exists in the source to cross-check — the annotation is a hand-written
        # approximation of the server's shape. Verified by reading the handler,
        # not statically here.
        unverifiable = {"integrations.connect"}

        unmatched = []
        for key, value in eesel._COMMAND_ENDPOINTS.items():
            if key in unverifiable:
                continue
            # An entry may document the legacy v2 endpoint after " · legacy: ";
            # verify the primary (new-platform) clause here — the legacy fetch_*
            # helpers have their own dedicated URL tests.
            value = value.split(" · legacy: ")[0]
            method, path = value.split(" ", 1)
            if path.endswith("/*"):
                # Wildcard family (e.g. billing → GET /subscription/*): satisfied
                # by any real call sharing the verb and path prefix.
                prefix = norm_ep(path[:-1])
                matched = any(m == method and p.startswith(prefix) for m, p in actual)
            else:
                matched = (method, norm_ep(path)) in actual
            if not matched:
                unmatched.append(f"{key}: {value}")

        assert unmatched == [], (
            "endpoint annotations with no matching request call in the source: "
            + ", ".join(unmatched)
        )

    def test_cmd_schema_emits_valid_json(self, capsys):
        eesel.cmd_schema(type("A", (), {})())
        parsed = json.loads(capsys.readouterr().out)
        assert parsed["prog"] == "eesel"
        assert "agents" in parsed["subcommands"]

    def test_legacy_supported_annotated(self):
        s = self._schema()
        agents = s["subcommands"]["agents"]["subcommands"]
        assert agents["list"]["legacy_supported"] is True
        assert agents["show"]["legacy_supported"] is True
        assert agents["create"]["legacy_supported"] is False
        assert agents["remove"]["legacy_supported"] is False
        tasks = s["subcommands"]["tasks"]["subcommands"]
        assert tasks["show"]["legacy_supported"] is True
        assert tasks["count"]["legacy_supported"] is False
        integ = s["subcommands"]["integrations"]["subcommands"]
        assert integ["show"]["legacy_supported"] is True
        assert integ["available"]["legacy_supported"] is False
        ws = s["subcommands"]["workspace"]["subcommands"]
        assert ws["members"]["legacy_supported"] is True
        assert ws["set"]["legacy_supported"] is False
        # Wholly-unsupported nouns and universal commands.
        assert s["subcommands"]["files"]["legacy_supported"] is False
        assert s["subcommands"]["schema"]["legacy_supported"] is True

    def test_legacy_endpoint_documented(self):
        s = self._schema()
        assert "legacy: GET /namespaces" in s["subcommands"]["agents"]["subcommands"]["list"]["endpoint"]
        assert "legacy:" in s["subcommands"]["integrations"]["subcommands"]["list"]["endpoint"]
        assert "legacy:" in s["subcommands"]["tasks"]["subcommands"]["show"]["endpoint"]


class TestOutputContractThroughMain:
    """End-to-end through main() — the path real usage and agents take."""

    def test_json_list_is_ndjson_when_piped(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "_is_tty", lambda: False)
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "a1", "name": "One"}, {"agent_id": "a2", "name": "Two"}])
        assert eesel.main(["agents", "list", "--json"]) == 0
        lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
        assert [json.loads(l)["agent_id"] for l in lines] == ["a1", "a2"]

    def test_env_output_json_matches_json_flag(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "_is_tty", lambda: False)
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "a1", "name": "One"}])
        monkeypatch.setenv("EESEL_OUTPUT", "json")
        assert eesel.main(["agents", "list"]) == 0
        lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
        assert json.loads(lines[0])["agent_id"] == "a1"

    def test_fields_projection_through_main(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "_is_tty", lambda: False)
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "a1", "name": "One", "prompt": "big"}])
        assert eesel.main(["agents", "list", "--json", "--fields", "agent_id,name"]) == 0
        assert json.loads(capsys.readouterr().out.splitlines()[0]) == {"agent_id": "a1", "name": "One"}

    def test_no_flag_output_unchanged_and_not_json(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "a1b2c3d4e5f6", "name": "One", "is_active": True}])
        assert eesel.main(["agents", "list"]) == 0
        out = capsys.readouterr().out
        assert "[on]" in out and "One" in out  # human table, not JSON

    def test_dry_run_create_makes_no_call(self, fake_creds, monkeypatch, capsys):
        def boom(*a, **k):
            raise AssertionError("dry-run must not hit the network")

        monkeypatch.setattr(eesel, "http_request", boom)
        with pytest.raises(SystemExit) as exc:
            eesel.main(["agents", "create", "--name", "Probe", "--dry-run"])
        assert exc.value.code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["method"] == "POST"
        assert payload["url"].endswith("/agents")
        assert payload["body"]["name"] == "Probe"

    def test_dry_run_flag_before_subcommand(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no call")))
        with pytest.raises(SystemExit) as exc:
            eesel.main(["--dry-run", "agents", "create", "--name", "Probe"])
        assert exc.value.code == 0
        assert json.loads(capsys.readouterr().out)["body"]["name"] == "Probe"

    def test_post_read_is_not_intercepted_by_dry_run(self, fake_creds, monkeypatch, capsys):
        # tasks list is POST /workspace/tasks — a read. --dry-run must NOT
        # short-circuit it; it still returns data.
        monkeypatch.setattr(eesel, "_is_tty", lambda: False)
        monkeypatch.setattr(eesel, "workspace_token", lambda creds: "wt")
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"tasks": [{"task_id": "t1"}], "has_next": False, "next_page": None})
        rc = eesel.main(["--dry-run", "tasks", "list", "--json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["tasks"][0]["task_id"] == "t1"


class TestRedactionScope:
    """Redaction masks only string secret material — verify it spares numeric
    counts and booleans whose key names collide with a secret-hint substring."""

    def test_preserves_numeric_count_under_token_hinted_key(self):
        red = eesel._redact_secrets({"input_tokens": 1234, "output_tokens": 5, "access_token": "sk-1"})
        assert red == {"input_tokens": 1234, "output_tokens": 5, "access_token": "***"}

    def test_preserves_boolean_presence_flag(self):
        assert eesel._redact_secrets({"has_auth_token": True}) == {"has_auth_token": True}

    def test_still_masks_string_secret(self):
        assert eesel._redact_secrets({"client_secret": "shh"}) == {"client_secret": "***"}


class TestEmitRedactBeforeProject:
    def test_property_entry_value_masked_even_when_projected(self, capsys):
        # The {key,value} property shape marks `value` secret via its sibling
        # `key`. Redaction must run before projection, or `--fields value`
        # (which drops `key`) would leak the raw value.
        payload = [{"key": "x_access_token", "value": "SECRET"}]
        eesel.emit(payload, fields=["value"])
        parsed = json.loads(capsys.readouterr().out)
        assert parsed == [{"value": "***"}]


class TestTasksExportDryRun:
    def test_export_dry_run_previews_and_makes_no_export_call(self, fake_creds, monkeypatch, capsys):
        calls = []

        def rec(method, url, **k):
            calls.append((method, url))
            return {"agents": [], "message": "ok"}

        monkeypatch.setattr(eesel, "http_request", rec)
        monkeypatch.setattr(eesel, "workspace_token", lambda creds: "wt")
        with pytest.raises(SystemExit) as exc:
            eesel.main(["tasks", "export", "--dry-run"])
        assert exc.value.code == 0
        # The export POST was previewed, never actually sent.
        assert not any("/tasks/export" in u for _, u in calls)
        assert "/tasks/export" in json.loads(capsys.readouterr().out)["url"]


# ──────────────────────────────────────────────────────────────────────────
# Legacy v2 platform — detection
# ──────────────────────────────────────────────────────────────────────────


class TestResolvePlatform:
    """`resolve_platform(creds, args)` decides legacy vs platform:
    explicit flag → cached value → a one-time license probe (fail-open)."""

    def test_legacy_flag_forces_legacy_without_network(self, tmp_config, fake_creds, monkeypatch):
        creds = dict(fake_creds, platform="platform")  # opposite cache, must be ignored

        def no_net(*a, **k):
            raise AssertionError("resolve_platform must not hit the network when a flag is set")

        monkeypatch.setattr(eesel, "http_request_allow_error", no_net)
        args = argparse.Namespace(legacy=True, platform=False)
        assert eesel.resolve_platform(creds, args) == "legacy"

    def test_platform_flag_forces_platform(self, tmp_config, fake_creds):
        creds = dict(fake_creds, platform="legacy")  # opposite cache, must be ignored
        args = argparse.Namespace(legacy=False, platform=True)
        assert eesel.resolve_platform(creds, args) == "platform"

    def test_flag_override_is_not_persisted(self, tmp_config, fake_creds, monkeypatch):
        creds = dict(fake_creds)
        creds.pop("platform", None)
        eesel.save_creds(creds)
        monkeypatch.setattr(eesel, "http_request_allow_error", lambda *a, **k: (200, {}))
        eesel.resolve_platform(creds, argparse.Namespace(legacy=True, platform=False))
        # A forced value never writes the cache.
        assert "platform" not in (eesel.load_creds() or {})

    def test_cached_value_used_without_network(self, tmp_config, fake_creds, monkeypatch):
        creds = dict(fake_creds, platform="legacy")
        calls = []
        monkeypatch.setattr(eesel, "http_request_allow_error", lambda *a, **k: calls.append(1) or (200, {}))
        args = argparse.Namespace(legacy=False, platform=False)
        assert eesel.resolve_platform(creds, args) == "legacy"
        assert calls == []

    def test_detects_legacy_from_license_and_caches(self, tmp_config, fake_creds, monkeypatch):
        creds = dict(fake_creds)
        creds.pop("platform", None)
        eesel.save_creds(creds)
        monkeypatch.setattr(eesel, "http_request_allow_error", lambda method, url, **k: (200, {"isPlatform": False}))
        args = argparse.Namespace(legacy=False, platform=False)
        assert eesel.resolve_platform(creds, args) == "legacy"
        assert creds["platform"] == "legacy"  # cached on the dict
        assert (eesel.load_creds() or {}).get("platform") == "legacy"  # and persisted

    def test_detects_platform_from_license(self, tmp_config, fake_creds, monkeypatch):
        creds = dict(fake_creds)
        creds.pop("platform", None)
        monkeypatch.setattr(eesel, "http_request_allow_error", lambda method, url, **k: (200, {"isPlatform": True}))
        args = argparse.Namespace(legacy=False, platform=False)
        assert eesel.resolve_platform(creds, args) == "platform"

    def test_fails_open_to_platform_on_probe_error(self, tmp_config, fake_creds, monkeypatch):
        creds = dict(fake_creds)
        creds.pop("platform", None)

        def boom(*a, **k):
            raise SystemExit(eesel.EXIT_SERVER)

        monkeypatch.setattr(eesel, "http_request_allow_error", boom)
        args = argparse.Namespace(legacy=False, platform=False)
        assert eesel.resolve_platform(creds, args) == "platform"

    def test_fails_open_to_platform_on_non_200(self, tmp_config, fake_creds, monkeypatch):
        creds = dict(fake_creds)
        creds.pop("platform", None)
        monkeypatch.setattr(eesel, "http_request_allow_error", lambda method, url, **k: (500, {"error": "boom"}))
        args = argparse.Namespace(legacy=False, platform=False)
        assert eesel.resolve_platform(creds, args) == "platform"


class TestPlatformFlags:
    """`--legacy` / `--platform` are global flags: declared for help/schema,
    lifted from anywhere in argv, and mutually exclusive."""

    def test_extractor_lifts_legacy_after_subcommand(self):
        rest, vals = eesel._extract_global_output_flags(["agents", "list", "--legacy"])
        assert rest == ["agents", "list"]
        assert vals["legacy"] is True
        assert vals["platform"] is False

    def test_extractor_lifts_platform_before_subcommand(self):
        rest, vals = eesel._extract_global_output_flags(["--platform", "whoami"])
        assert rest == ["whoami"]
        assert vals["platform"] is True
        assert vals["legacy"] is False

    def test_parser_declares_legacy_flag(self):
        args = eesel.build_parser(staff=False).parse_args(["--legacy", "agents", "list"])
        assert args.legacy is True

    def test_parser_declares_platform_flag(self):
        args = eesel.build_parser(staff=False).parse_args(["--platform", "agents", "list"])
        assert args.platform is True

    def test_main_rejects_both_flags(self, tmp_config, fake_creds):
        with pytest.raises(SystemExit) as exc:
            eesel.main(["agents", "list", "--legacy", "--platform"])
        assert exc.value.code == eesel.EXIT_USAGE


class TestNamespaceResolve:
    """Legacy namespaces (bots): fetch + resolve by id / id-prefix / name,
    mirroring the agent resolver."""

    NS = [
        {"id": "ns-abc123", "namespace": "Support Bot", "connections": ["c1", "c2"], "isOwner": True},
        {"id": "ns-def456", "namespace": "Sales Bot", "connections": [], "isOwner": True},
    ]

    def test_fetch_reads_namespaces_key(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "http_request", lambda method, url, **k: {"namespaces": self.NS})
        assert eesel.fetch_namespaces(fake_creds) == self.NS

    def test_fetch_accepts_bare_list(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: self.NS)
        assert eesel.fetch_namespaces(fake_creds) == self.NS

    def test_fetch_hits_namespaces_endpoint(self, fake_creds, monkeypatch):
        seen = {}
        monkeypatch.setattr(eesel, "http_request", lambda method, url, **k: seen.update(method=method, url=url) or {"namespaces": []})
        eesel.fetch_namespaces(fake_creds)
        assert seen["method"] == "GET" and seen["url"].endswith("/namespaces")

    def test_resolve_by_exact_id(self):
        assert eesel.resolve_namespace(self.NS, "ns-abc123")["namespace"] == "Support Bot"

    def test_resolve_by_id_prefix(self):
        assert eesel.resolve_namespace(self.NS, "ns-abc")["id"] == "ns-abc123"

    def test_resolve_by_name(self):
        assert eesel.resolve_namespace(self.NS, "Sales Bot")["id"] == "ns-def456"

    def test_blank_target_matches_nothing(self):
        assert eesel.resolve_namespace(self.NS, "  ") is None

    def test_strict_unique(self):
        one, cands = eesel.resolve_namespace_strict(self.NS, "ns-abc123")
        assert one["id"] == "ns-abc123" and cands == []

    def test_strict_ambiguous_returns_candidates(self):
        dupes = [{"id": "a", "namespace": "Dup"}, {"id": "b", "namespace": "Dup"}]
        one, cands = eesel.resolve_namespace_strict(dupes, "Dup")
        assert one is None and len(cands) == 2


class TestLegacyConnectionsData:
    CONNS = [
        {"connectionId": "c1", "connectionType": "eesel", "connectionName": "eesel core"},
        {"connectionId": "c2", "connectionType": "zendesk", "connectionName": "ACME ZD"},
    ]

    def test_fetch_connections_hits_namespace_scoped_endpoint(self, fake_creds, monkeypatch):
        seen = {}
        monkeypatch.setattr(eesel, "http_request", lambda method, url, **k: seen.update(url=url) or self.CONNS)
        assert eesel.fetch_namespace_connections(fake_creds, "ns-1") == self.CONNS
        assert seen["url"].endswith("/namespaces/ns-1/connections")

    def test_fetch_connections_reads_connections_key(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"connections": self.CONNS})
        assert eesel.fetch_namespace_connections(fake_creds, "ns-1") == self.CONNS

    def test_fetch_connection_config_returns_entries(self, fake_creds, monkeypatch):
        entries = [{"name": "customPrompt", "value": "Be nice"}]
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"configurationEntries": entries})
        assert eesel.fetch_connection_config(fake_creds, "c1") == entries

    def test_fetch_connection_config_passes_params(self, fake_creds, monkeypatch):
        seen = {}
        monkeypatch.setattr(eesel, "http_request", lambda method, url, **k: seen.update(url=url) or {"configurationEntries": []})
        eesel.fetch_connection_config(fake_creds, "c1", params="customPrompt")
        assert "params=customPrompt" in seen["url"]

    def test_get_namespace_prompt_reads_eesel_customprompt(self, fake_creds, monkeypatch):
        def fake(method, url, **k):
            if url.endswith("/connections"):
                return self.CONNS
            if "/connections/c1/configuration" in url:
                return {"configurationEntries": [{"name": "customPrompt", "value": "You are helpful."}]}
            return {}

        monkeypatch.setattr(eesel, "http_request", fake)
        assert eesel.get_namespace_prompt(fake_creds, "ns-1") == "You are helpful."

    def test_get_namespace_prompt_empty_when_no_eesel_connection(self, fake_creds, monkeypatch):
        monkeypatch.setattr(
            eesel, "http_request",
            lambda method, url, **k: [{"connectionId": "c2", "connectionType": "zendesk"}] if url.endswith("/connections") else {},
        )
        assert eesel.get_namespace_prompt(fake_creds, "ns-1") == ""


class TestLegacySessionsData:
    def test_fetch_session_hits_scoped_endpoint(self, fake_creds, monkeypatch):
        seen = {}
        monkeypatch.setattr(eesel, "http_request", lambda method, url, **k: seen.update(url=url) or {"sessionId": "s1", "messages": []})
        eesel.fetch_session(fake_creds, "ns-1", "s1")
        assert seen["url"].endswith("/v2/namespaces/ns-1/sessions/s1")

    def test_fetch_sessions_follows_cursor_to_fill_limit(self, fake_creds, monkeypatch):
        pages = [
            {"sessions": [{"sessionId": "s1"}, {"sessionId": "s2"}], "lastEvaluatedKey": "k1"},
            {"sessions": [{"sessionId": "s3"}], "lastEvaluatedKey": None},
        ]
        calls = []

        def fake(method, url, **k):
            calls.append(url)
            return pages[len(calls) - 1]

        monkeypatch.setattr(eesel, "http_request", fake)
        got = eesel.fetch_sessions(fake_creds, "ns-1", limit=10)
        assert [s["sessionId"] for s in got] == ["s1", "s2", "s3"]
        assert len(calls) == 2  # followed the cursor exactly once

    def test_fetch_sessions_stops_at_limit(self, fake_creds, monkeypatch):
        monkeypatch.setattr(
            eesel, "http_request",
            lambda method, url, **k: {"sessions": [{"sessionId": "a"}, {"sessionId": "b"}, {"sessionId": "c"}], "lastEvaluatedKey": "more"},
        )
        got = eesel.fetch_sessions(fake_creds, "ns-1", limit=2)
        assert len(got) == 2

    def test_fetch_sessions_passes_search(self, fake_creds, monkeypatch):
        seen = {}
        monkeypatch.setattr(eesel, "http_request", lambda method, url, **k: seen.update(url=url) or {"sessions": [], "lastEvaluatedKey": None})
        eesel.fetch_sessions(fake_creds, "ns-1", limit=5, search="refund")
        assert "search=refund" in seen["url"]


class TestLegacyAgentsCommand:
    """`agents list/show` on a legacy workspace serves bots (namespaces)."""

    NS = [
        {"id": "ns-abc123def", "namespace": "Support Bot", "connections": ["c1", "c2"], "isOwner": True},
        {"id": "ns-def456ghi", "namespace": "Sales Bot", "connections": [], "isOwner": True},
    ]

    def _legacy(self, monkeypatch):
        monkeypatch.setattr(eesel, "resolve_platform", lambda creds, args=None: "legacy")

    def test_list_shows_bots(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "fetch_namespaces", lambda creds: self.NS)
        assert eesel.cmd_agents(_parse("agents", "list")) == 0
        out = capsys.readouterr().out
        assert "Support Bot" in out and "Sales Bot" in out

    def test_list_empty_state(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "fetch_namespaces", lambda creds: [])
        assert eesel.cmd_agents(_parse("agents", "list")) == 0
        # empty-state note goes to stderr via info(), like `(no agents)` does
        assert "no bots" in capsys.readouterr().err.lower()

    def test_list_json_emits_namespaces(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "fetch_namespaces", lambda creds: self.NS)
        assert eesel.cmd_agents(_parse("agents", "list", "--json")) == 0
        parsed = json.loads(capsys.readouterr().out)
        assert [n["id"] for n in parsed] == ["ns-abc123def", "ns-def456ghi"]

    def test_show_includes_prompt(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "fetch_namespaces", lambda creds: self.NS)
        monkeypatch.setattr(eesel, "get_namespace_prompt", lambda creds, nid: "You are a support bot.")
        assert eesel.cmd_agents(_parse("agents", "show", "ns-abc123def")) == 0
        out = capsys.readouterr().out
        assert "Support Bot" in out and "You are a support bot." in out

    def test_show_not_found(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "fetch_namespaces", lambda creds: self.NS)
        assert eesel.cmd_agents(_parse("agents", "show", "nope")) == 1
        assert "no bot matches" in capsys.readouterr().err.lower()

    def test_write_verb_blocked_on_legacy(self, tmp_config, fake_creds, monkeypatch):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "fetch_namespaces", lambda creds: self.NS)
        with pytest.raises(SystemExit) as exc:
            eesel.cmd_agents(_parse("agents", "create", "--name", "x"))
        assert exc.value.code == eesel.EXIT_VALIDATION


class TestLegacyInstructionsCommand:
    """`instructions` on legacy prints the bot's customPrompt to stdout."""

    NS = [{"id": "ns-1", "namespace": "Bot", "connections": ["c1"]}]

    def _legacy(self, monkeypatch):
        monkeypatch.setattr(eesel, "resolve_platform", lambda creds, args=None: "legacy")
        monkeypatch.setattr(eesel, "fetch_namespaces", lambda creds: self.NS)

    def test_prints_customprompt_to_stdout(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "get_namespace_prompt", lambda creds, nid: "Be concise.")
        assert eesel.cmd_instructions(_parse("instructions", "ns-1")) == 0
        # header goes to stderr; only the prompt lands on stdout (redirect-friendly)
        assert capsys.readouterr().out.strip() == "Be concise."

    def test_empty_prompt_is_clean(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "get_namespace_prompt", lambda creds, nid: "")
        assert eesel.cmd_instructions(_parse("instructions", "ns-1")) == 0
        assert capsys.readouterr().out.strip() == ""


class TestLegacyIntegrationsCommand:
    """`integrations` on legacy serves the bot's (namespace's) connections."""

    NS = [{"id": "ns-1", "namespace": "Bot", "connections": ["c1"], "isOwner": True}]
    CONNS = [
        {"connectionId": "c1", "connectionType": "eesel", "connectionName": "eesel core"},
        {"connectionId": "c2", "connectionType": "zendesk", "connectionName": "ACME ZD"},
    ]

    def _legacy(self, monkeypatch):
        monkeypatch.setattr(eesel, "resolve_platform", lambda creds, args=None: "legacy")
        monkeypatch.setattr(eesel, "fetch_namespaces", lambda creds: self.NS)

    def test_list_shows_connections(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "fetch_namespace_connections", lambda creds, nid: self.CONNS)
        assert eesel.cmd_integrations(_parse("integrations", "list")) == 0
        out = capsys.readouterr().out
        assert "c1" in out and "zendesk" in out and "ACME ZD" in out

    def test_list_json_emits_connections(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "fetch_namespace_connections", lambda creds, nid: self.CONNS)
        assert eesel.cmd_integrations(_parse("integrations", "list", "--json")) == 0
        parsed = json.loads(capsys.readouterr().out)
        assert [c["connectionId"] for c in parsed] == ["c1", "c2"]

    def test_list_empty_state(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "fetch_namespace_connections", lambda creds, nid: [])
        assert eesel.cmd_integrations(_parse("integrations", "list")) == 0
        # empty-state note goes to stderr via info(), like the other lists
        assert "no connections" in capsys.readouterr().err.lower()

    def test_list_scopes_named_bot(self, tmp_config, fake_creds, monkeypatch):
        self._legacy(monkeypatch)
        seen = {}
        monkeypatch.setattr(eesel, "fetch_namespace_connections",
                            lambda creds, nid: seen.update(nid=nid) or [])
        # A two-bot workspace needs the bot named; --agent resolves it.
        monkeypatch.setattr(eesel, "fetch_namespaces", lambda creds: [
            {"id": "ns-1", "namespace": "Bot One"}, {"id": "ns-2", "namespace": "Bot Two"}])
        assert eesel.cmd_integrations(_parse("integrations", "list", "--agent", "Bot Two")) == 0
        assert seen["nid"] == "ns-2"

    def test_show_renders_config_entries(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "fetch_connection",
                            lambda creds, cid: {"connectionId": "c2", "connectionType": "zendesk", "connectionName": "ACME ZD"})
        monkeypatch.setattr(eesel, "fetch_connection_config",
                            lambda creds, cid, params=None: [{"name": "subdomain", "value": "acme"}, {"name": "customPrompt", "value": "Be nice"}])
        assert eesel.cmd_integrations(_parse("integrations", "show", "c2")) == 0
        out = capsys.readouterr().out
        assert "subdomain" in out and "acme" in out
        # customPrompt is not a secret — its value is shown in full
        assert "customPrompt" in out and "Be nice" in out

    def test_show_masks_secret_config_value(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "_REVEAL_SECRETS", False)
        monkeypatch.setattr(eesel, "fetch_connection",
                            lambda creds, cid: {"connectionId": "c2", "connectionType": "zendesk"})
        monkeypatch.setattr(eesel, "fetch_connection_config",
                            lambda creds, cid, params=None: [{"name": "accessToken", "value": "sk-secret"}])
        assert eesel.cmd_integrations(_parse("integrations", "show", "c2")) == 0
        out = capsys.readouterr().out
        assert "sk-secret" not in out and "***" in out

    def test_show_json_masks_secret_config_value(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "_REVEAL_SECRETS", False)
        monkeypatch.setattr(eesel, "fetch_connection",
                            lambda creds, cid: {"connectionId": "c2", "connectionType": "zendesk"})
        monkeypatch.setattr(eesel, "fetch_connection_config",
                            lambda creds, cid, params=None: [{"name": "accessToken", "value": "sk-secret"}])
        assert eesel.cmd_integrations(_parse("integrations", "show", "c2", "--json")) == 0
        parsed = json.loads(capsys.readouterr().out)
        entry = next(e for e in parsed["configurationEntries"] if e["name"] == "accessToken")
        assert entry["value"] == "***"

    def test_write_verb_blocked_on_legacy(self, tmp_config, fake_creds, monkeypatch):
        self._legacy(monkeypatch)
        with pytest.raises(SystemExit) as exc:
            eesel.cmd_integrations(_parse("integrations", "sync", "zendesk"))
        assert exc.value.code == eesel.EXIT_VALIDATION


class TestLegacyTasksCommand:
    """`tasks` on legacy serves the bot's (namespace's) chat sessions."""

    NS = [{"id": "ns-1", "namespace": "Bot", "connections": ["c1"], "isOwner": True}]
    SESSIONS = [
        {"sessionId": "s1", "title": "Refund question", "lastUpdated": "2026-07-01", "resolution": "resolved", "aiCsat": 5},
        {"sessionId": "s2", "title": "Where is my order"},
    ]

    def _legacy(self, monkeypatch):
        monkeypatch.setattr(eesel, "resolve_platform", lambda creds, args=None: "legacy")
        monkeypatch.setattr(eesel, "fetch_namespaces", lambda creds: self.NS)

    def test_list_shows_sessions(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "fetch_sessions", lambda creds, nid, **k: self.SESSIONS)
        assert eesel.cmd_tasks(_parse("tasks", "list")) == 0
        out = capsys.readouterr().out
        assert "s1" in out and "Refund question" in out and "s2" in out

    def test_list_passes_scope_and_limit(self, tmp_config, fake_creds, monkeypatch):
        self._legacy(monkeypatch)
        seen = {}
        monkeypatch.setattr(eesel, "fetch_sessions", lambda creds, nid, **k: seen.update(nid=nid, **k) or [])
        assert eesel.cmd_tasks(_parse("tasks", "list", "--limit", "10")) == 0
        assert seen["nid"] == "ns-1" and seen["limit"] == 10

    def test_list_json_emits_sessions(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "fetch_sessions", lambda creds, nid, **k: self.SESSIONS)
        assert eesel.cmd_tasks(_parse("tasks", "list", "--json")) == 0
        parsed = json.loads(capsys.readouterr().out)
        assert [s["sessionId"] for s in parsed] == ["s1", "s2"]

    def test_list_empty_state(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "fetch_sessions", lambda creds, nid, **k: [])
        assert eesel.cmd_tasks(_parse("tasks", "list")) == 0
        assert "no tasks" in capsys.readouterr().err.lower()

    def test_show_renders_transcript(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "fetch_session", lambda creds, nid, sid: {
            "sessionId": "s1", "title": "Refund", "messages": [
                {"userMessage": "Where is my refund?", "agentMessage": "It is processing."},
            ]})
        assert eesel.cmd_tasks(_parse("tasks", "show", "s1")) == 0
        out = capsys.readouterr().out
        assert "Where is my refund?" in out and "It is processing." in out

    def test_show_truncates_without_full(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        long_msg = "x" * 500
        monkeypatch.setattr(eesel, "fetch_session", lambda creds, nid, sid: {
            "sessionId": "s1", "messages": [{"userMessage": long_msg, "agentMessage": "ok"}]})
        assert eesel.cmd_tasks(_parse("tasks", "show", "s1")) == 0
        assert long_msg not in capsys.readouterr().out  # truncated without --full
        assert eesel.cmd_tasks(_parse("tasks", "show", "s1", "--full")) == 0
        assert long_msg in capsys.readouterr().out  # whole message with --full

    def test_show_json_is_raw(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        monkeypatch.setattr(eesel, "fetch_session", lambda creds, nid, sid: {"sessionId": "s1", "messages": []})
        assert eesel.cmd_tasks(_parse("tasks", "show", "s1", "--json")) == 0
        assert json.loads(capsys.readouterr().out)["sessionId"] == "s1"

    def test_count_blocked_on_legacy(self, tmp_config, fake_creds, monkeypatch):
        self._legacy(monkeypatch)
        with pytest.raises(SystemExit) as exc:
            eesel.cmd_tasks(_parse("tasks", "count"))
        assert exc.value.code == eesel.EXIT_VALIDATION

    def test_export_blocked_on_legacy(self, tmp_config, fake_creds, monkeypatch):
        self._legacy(monkeypatch)
        with pytest.raises(SystemExit) as exc:
            eesel.cmd_tasks(_parse("tasks", "export"))
        assert exc.value.code == eesel.EXIT_VALIDATION


class TestLegacySupportsClassification:
    """`legacy_supports(args)` is the single source of truth for which commands
    have a read-only meaning on the legacy v2 platform."""

    @pytest.mark.parametrize("argv", [
        ("agents", "list"), ("agents", "show", "ns-1"),
        ("integrations", "list"), ("integrations", "show", "c1"),
        ("tasks", "list"), ("tasks", "show", "s1"),
        ("workspace", "show"), ("workspace", "members"),
        ("instructions",), ("whoami",), ("login",), ("logout",),
        ("link", "https://x.preprod.eesel.xyz"), ("schema",),
    ])
    def test_supported(self, argv):
        assert eesel.legacy_supports(_parse(*argv)) is True

    @pytest.mark.parametrize("argv", [
        ("agents", "create", "--name", "x"), ("agents", "set", "ns-1", "--name", "y"),
        ("agents", "remove", "ns-1", "-f"),
        ("integrations", "sync", "zendesk"), ("integrations", "remove", "c1", "-f"),
        ("tasks", "count"), ("tasks", "analytics"), ("tasks", "export"),
        ("workspace", "extend-trial"),
        ("files", "list"), ("skills", "list", "a"), ("mcp", "list"),
        ("chat", "hi"), ("new",), ("billing", "show"),
    ])
    def test_unsupported(self, argv):
        assert eesel.legacy_supports(_parse(*argv)) is False

    def test_bare_agents_defaults_to_list_supported(self):
        assert eesel.legacy_supports(_parse("agents")) is True

    def test_bare_workspace_defaults_to_show_supported(self):
        assert eesel.legacy_supports(_parse("workspace")) is True

    def test_bare_tasks_defaults_to_list_supported(self):
        assert eesel.legacy_supports(_parse("tasks")) is True

    def test_bare_integrations_defaults_to_list_supported(self):
        assert eesel.legacy_supports(_parse("integrations")) is True


class TestGuardPlatformCommand:
    """`_guard_platform_command` refuses unsupported commands on legacy before
    any handler runs, and stays out of the way otherwise."""

    def _legacy(self, monkeypatch):
        monkeypatch.setattr(eesel, "resolve_platform", lambda creds, args=None: "legacy")

    def _platform(self, monkeypatch):
        monkeypatch.setattr(eesel, "resolve_platform", lambda creds, args=None: "platform")

    def test_refuses_unsupported_on_legacy(self, fake_creds, monkeypatch):
        self._legacy(monkeypatch)
        with pytest.raises(SystemExit) as exc:
            eesel._guard_platform_command(_parse("files", "list"), fake_creds)
        assert exc.value.code == eesel.EXIT_VALIDATION

    def test_allows_supported_on_legacy_without_resolving(self, fake_creds, monkeypatch):
        # A supported command returns before touching resolve_platform.
        def boom(*a, **k):
            raise AssertionError("supported commands must not resolve the platform")
        monkeypatch.setattr(eesel, "resolve_platform", boom)
        assert eesel._guard_platform_command(_parse("agents", "list"), fake_creds) is None

    def test_noop_on_new_platform(self, fake_creds, monkeypatch):
        self._platform(monkeypatch)
        assert eesel._guard_platform_command(_parse("files", "list"), fake_creds) is None

    def test_no_creds_no_flag_is_noop_without_network(self, monkeypatch):
        def boom(*a, **k):
            raise AssertionError("must not resolve platform without creds or a flag")
        monkeypatch.setattr(eesel, "resolve_platform", boom)
        assert eesel._guard_platform_command(_parse("files", "list"), None) is None

    def test_message_names_the_command(self, fake_creds, monkeypatch, capsys):
        self._legacy(monkeypatch)
        with pytest.raises(SystemExit):
            eesel._guard_platform_command(_parse("tasks", "count"), fake_creds)
        assert "tasks count" in capsys.readouterr().err

    def test_end_to_end_through_main_refuses(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "resolve_platform", lambda creds, args=None: "legacy")
        with pytest.raises(SystemExit) as exc:
            eesel.main(["files", "list"])
        assert exc.value.code == eesel.EXIT_VALIDATION

    def test_end_to_end_through_main_allows_supported(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "resolve_platform", lambda creds, args=None: "legacy")
        monkeypatch.setattr(eesel, "fetch_namespaces", lambda creds: [])
        assert eesel.main(["agents", "list"]) == 0


class TestWhoamiPlatform:
    """`whoami` reports the resolved platform."""

    def test_shows_platform_legacy(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "resolve_platform", lambda creds, args=None: "legacy")
        monkeypatch.setattr(eesel, "_get_impersonate_status", lambda creds: None)
        assert eesel.cmd_whoami(_parse("whoami")) == 0
        assert "platform     : legacy (v2)" in capsys.readouterr().out

    def test_shows_platform_new(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "resolve_platform", lambda creds, args=None: "platform")
        monkeypatch.setattr(eesel, "_get_impersonate_status", lambda creds: None)
        assert eesel.cmd_whoami(_parse("whoami")) == 0
        assert "platform     : platform" in capsys.readouterr().out


class TestLegacyHelpHiding:
    """With platform_hint='legacy', build_parser trims `--help` to the read
    commands, but every hidden command stays parseable (guard gives the note)."""

    def _legacy(self):
        return eesel.build_parser(staff=False, platform_hint="legacy")

    def _child(self, parser, noun):
        return _subparsers_action(_subparsers_action(parser).choices[noun])

    def test_hides_wholly_unsupported_nouns(self):
        visible = _visible_commands(self._legacy())
        for hidden in ("files", "skills", "mcp", "settings", "chat", "new", "cost", "automations", "billing"):
            assert hidden not in visible, hidden
        for shown in ("agents", "integrations", "tasks", "workspace", "whoami", "schema"):
            assert shown in visible, shown

    def test_hides_write_subcommands_under_agents(self):
        visible = {a.dest for a in self._child(self._legacy(), "agents")._choices_actions}
        assert visible == {"list", "show"}

    def test_hides_partial_subcommands(self):
        parser = self._legacy()
        for noun, expected in [
            ("integrations", {"list", "show"}),
            ("tasks", {"list", "show"}),
            ("workspace", {"show", "members"}),
        ]:
            visible = {a.dest for a in self._child(parser, noun)._choices_actions}
            assert visible == expected, (noun, visible)

    def test_help_text_omits_hidden(self):
        help_text = self._legacy().format_help()
        assert "files" not in help_text and "skills" not in help_text

    def test_agents_help_omits_write_verbs(self):
        # Assert on the write subparsers' unique help strings — the path-scope
        # epilog legitimately references `set`/`remove`, so a bare word check
        # would be a false positive.
        agents_help = _subparsers_action(self._legacy()).choices["agents"].format_help()
        assert "Create a new agent" not in agents_help
        assert "Remove an agent" not in agents_help
        assert "Change an agent's name" not in agents_help
        # ...and they stay for the new platform.
        full = _subparsers_action(eesel.build_parser(staff=False)).choices["agents"].format_help()
        assert "Create a new agent" in full and "Remove an agent" in full

    def test_metavar_does_not_leak_hidden(self):
        # The usage-line metavar is rebuilt, so no hidden noun leaks into `{...}`.
        top = _subparsers_action(self._legacy())
        listed = set((top.metavar or "").strip("{}").split(","))
        assert "files" not in listed and "skills" not in listed

    def test_platform_hint_none_shows_everything(self):
        visible = _visible_commands(eesel.build_parser(staff=False))
        for shown in ("files", "skills", "mcp", "settings", "chat", "new", "cost", "automations", "billing"):
            assert shown in visible, shown

    def test_platform_hint_platform_shows_everything(self):
        visible = _visible_commands(eesel.build_parser(staff=False, platform_hint="platform"))
        assert "files" in visible and "skills" in visible
        agents = {a.dest for a in self._child(eesel.build_parser(staff=False, platform_hint="platform"), "agents")._choices_actions}
        assert {"create", "set", "remove"}.issubset(agents)

    def test_hidden_noun_still_parses(self):
        args = self._legacy().parse_args(["files", "list"])
        assert args.cmd == "files"

    def test_hidden_subcommand_still_parses(self):
        args = self._legacy().parse_args(["agents", "create", "--name", "X"])
        assert args.cmd == "agents" and args.agents_cmd == "create"
