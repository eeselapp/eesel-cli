"""Unit tests for the eesel CLI.

Run with: `python3 -m pytest test_eesel.py -v` from the repo root.

The CLI script has no `.py` extension, so we load it via importlib.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
import socket
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
    }
    eesel.save_creds(creds)
    return creds


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
    def test_mints_workspace_scoped_token_and_stores_active_agent(self, tmp_config, monkeypatch):
        monkeypatch.setattr(eesel, "discover_local_ids", lambda workspace_id=None: ("ws-1", "agent-1", "user-1"))

        creds = eesel.login_dev()

        _, payload_b64, _ = creds["token"].split(".")
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        assert payload["workspace_id"] == "ws-1"
        assert payload["user_id"] == "user-1"
        assert "agent_id" not in payload
        assert creds["agent_id"] == "agent-1"


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


class TestDocumentCommand:
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

        rc = eesel.cmd_document(
            type(
                "Args",
                (),
                {
                    "document_cmd": "list",
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
        rc = eesel.cmd_document(
            type(
                "Args",
                (),
                {
                    "document_cmd": "export",
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
        rc = eesel.cmd_document(
            type(
                "Args",
                (),
                {
                    "document_cmd": "export",
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
        rc = eesel.cmd_document(
            type(
                "Args",
                (),
                {
                    "document_cmd": "export",
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

        rc = eesel.cmd_document(
            type(
                "Args",
                (),
                {
                    "document_cmd": "export",
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

        rc = eesel.cmd_document(
            type(
                "Args",
                (),
                {
                    "document_cmd": "export",
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

        rc = eesel.cmd_document(
            type(
                "Args",
                (),
                {
                    "document_cmd": "export",
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
        rc = eesel.cmd_document(
            type(
                "Args",
                (),
                {
                    "document_cmd": "export",
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


class TestDocumentRead:
    # fake_creds.agent_id == "agent-test-456"
    DOCS = [
        {"id": "doc-aaa11122", "key": "files/agent-test-456/notes.md", "name": "notes.md"},
        {"id": "doc-bbb33344", "key": "outputs/skills/agent-test-456/blog/run-1/POST.md", "name": "POST.md"},
        {"id": "doc-other-99", "key": "files/other-agent/secret.md", "name": "secret.md"},
        {"id": "doc-integ-77", "key": "integrations/zendesk/acme/article-1", "name": "article-1"},
    ]

    def _args(self, **kw):
        base = {"document_cmd": "read", "target": None, "prefix": None, "format": "md"}
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
        rc = eesel.cmd_document_read(self._args(target="doc-aaa11122"))
        assert rc == 0
        assert seen["doc_id"] == "doc-aaa11122"
        assert seen["fmt"] == "md"
        out = capsys.readouterr().out
        assert out == "# Notes\nhello world\n"  # body to stdout, trailing newline added

    def test_read_header_goes_to_stderr(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._wire(monkeypatch)
        eesel.cmd_document_read(self._args(target="notes.md"))  # match by filename
        captured = capsys.readouterr()
        assert "files/agent-test-456/notes.md" in captured.err
        assert "files/agent-test-456/notes.md" not in captured.out

    def test_read_by_filename_and_html_format(self, tmp_config, fake_creds, monkeypatch):
        seen = self._wire(monkeypatch, content=b"<h1>x</h1>")
        rc = eesel.cmd_document_read(self._args(target="POST.md", format="html"))
        assert rc == 0
        assert seen["doc_id"] == "doc-bbb33344"
        assert seen["fmt"] == "html"

    def test_read_no_target_uses_interactive_menu(self, tmp_config, fake_creds, monkeypatch):
        seen = self._wire(monkeypatch)
        captured = {}

        def fake_select(options, *, title=None, initial=0):
            captured["options"] = options
            return 1  # pick the second agent-owned doc

        monkeypatch.setattr(eesel, "interactive_select", fake_select)
        rc = eesel.cmd_document_read(self._args())
        assert rc == 0
        # Only the two agent-owned docs are offered (other-agent + integrations filtered out).
        assert len(captured["options"]) == 2
        assert seen["doc_id"] == "doc-bbb33344"

    def test_read_prefix_is_passed_through_and_scopes(self, tmp_config, fake_creds, monkeypatch):
        seen = self._wire(monkeypatch)
        monkeypatch.setattr(eesel, "interactive_select", lambda *a, **k: 0)
        eesel.cmd_document_read(self._args(prefix="files/"))
        assert seen.get("prefix") == "files/"  # forwarded to fetch_documents

    def test_read_unknown_target_errors(self, tmp_config, fake_creds, monkeypatch, capsys):
        self._wire(monkeypatch)
        rc = eesel.cmd_document_read(self._args(target="nope"))
        assert rc == 1
        assert capsys.readouterr().out == ""

    def test_read_ambiguous_id_prefix_errors(self, tmp_config, fake_creds, monkeypatch, capsys):
        # Two agent-owned ids share the prefix "doc-".
        self._wire(monkeypatch)
        rc = eesel.cmd_document_read(self._args(target="doc-"))
        assert rc == 1
        assert "ambiguous" in capsys.readouterr().err

    def test_read_excludes_other_agents_doc(self, tmp_config, fake_creds, monkeypatch, capsys):
        # The other agent's doc must not be reachable by id.
        self._wire(monkeypatch)
        rc = eesel.cmd_document_read(self._args(target="doc-other-99"))
        assert rc == 1

    def test_read_no_documents_is_clean_exit(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_documents", lambda creds, **kw: [])
        rc = eesel.cmd_document_read(self._args(prefix="integrations/"))
        assert rc == 0
        assert "no documents" in capsys.readouterr().err

    def test_read_cancel_menu_returns_nonzero(self, tmp_config, fake_creds, monkeypatch):
        self._wire(monkeypatch)
        monkeypatch.setattr(eesel, "interactive_select", lambda *a, **k: None)
        assert eesel.cmd_document_read(self._args()) == 1


class TestHttpFetch:
    def test_http_download_uses_http_fetch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(eesel, "http_fetch", lambda url, *, token: b"DATA")
        out = tmp_path / "f.md"
        eesel.http_download("https://x/y", token="t", output_path=out)
        assert out.read_bytes() == b"DATA"


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


class TestAgentLabel:
    def test_includes_name_and_short_id(self):
        label = eesel._agent_label({"agent_id": "agent-abcdef123456", "name": "Support"})
        assert "Support" in label
        assert "agent-ab" in label  # 8-char prefix

    def test_marks_active(self):
        a = {"agent_id": "agent-1", "name": "Bot"}
        assert "*active" in eesel._agent_label(a, active="agent-1")
        assert "*active" not in eesel._agent_label(a, active="agent-2")

    def test_includes_agent_type(self):
        label = eesel._agent_label({"agent_id": "a", "name": "Bot", "agent_type": "knowledge_agent"})
        assert "[knowledge_agent]" in label


class TestInstructionsCommand:
    AGENTS = [
        {"agent_id": "agent-test-456", "name": "Active One", "prompt": "Be helpful and concise."},
        {"agent_id": "agent-other-9", "name": "Sales Bot", "prompt": "Always upsell."},
        {"agent_id": "agent-blank-0", "name": "Empty", "prompt": ""},
    ]

    def _args(self, agent=None):
        return type("Args", (), {"agent": agent})()

    def test_prints_active_agent_prompt(self, tmp_config, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
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

    def test_no_active_agent_errors(self, tmp_config, fake_creds, monkeypatch):
        # Active agent id doesn't match any returned agent and no target given.
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [{"agent_id": "x", "name": "X", "prompt": "p"}])
        assert eesel.cmd_instructions(self._args()) == 1


class TestAgentsUseInteractive:
    AGENTS = [
        {"agent_id": "agent-aaa", "name": "First"},
        {"agent_id": "agent-bbb", "name": "Second"},
    ]

    def _args(self, agent_id=None):
        return type("Args", (), {"agents_cmd": "use", "agent_id": agent_id})()

    def test_use_with_id_sets_active(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        rc = eesel.cmd_agents(self._args("agent-bbb"))
        assert rc == 0
        assert eesel.load_creds()["agent_id"] == "agent-bbb"

    def test_use_without_id_opens_menu_and_sets_choice(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        seen = {}

        def fake_select(options, *, title=None, initial=0):
            seen["options"] = options
            seen["initial"] = initial
            return 1  # pick "Second"

        monkeypatch.setattr(eesel, "interactive_select", fake_select)
        rc = eesel.cmd_agents(self._args(None))
        assert rc == 0
        assert eesel.load_creds()["agent_id"] == "agent-bbb"
        assert len(seen["options"]) == 2

    def test_menu_starts_on_active_agent(self, tmp_config, fake_creds, monkeypatch):
        # fake_creds active agent is "agent-test-456"; put it second in the list.
        agents = [{"agent_id": "agent-aaa", "name": "First"}, {"agent_id": "agent-test-456", "name": "Active"}]
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: agents)
        captured = {}

        def fake_select(options, *, title=None, initial=0):
            captured["initial"] = initial
            return initial

        monkeypatch.setattr(eesel, "interactive_select", fake_select)
        eesel.cmd_agents(self._args(None))
        assert captured["initial"] == 1

    def test_cancel_leaves_active_agent_unchanged(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        monkeypatch.setattr(eesel, "interactive_select", lambda *a, **k: None)
        rc = eesel.cmd_agents(self._args(None))
        assert rc == 1
        assert eesel.load_creds()["agent_id"] == "agent-test-456"  # untouched

    def test_unknown_id_errors(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self.AGENTS)
        rc = eesel.cmd_agents(self._args("ghost"))
        assert rc == 1
        assert eesel.load_creds()["agent_id"] == "agent-test-456"


class TestAgentsUnset:
    def _args(self):
        return type("Args", (), {"agents_cmd": "unset"})()

    def test_unset_clears_active_agent(self, tmp_config, fake_creds):
        assert eesel.load_creds().get("agent_id") == "agent-test-456"
        rc = eesel.cmd_agents(self._args())
        assert rc == 0
        # The key is removed entirely, leaving the rest of the creds intact.
        creds = eesel.load_creds()
        assert "agent_id" not in creds
        assert creds["workspace_id"] == "ws-test-123"
        assert creds["token"] == "test-jwt-token"

    def test_unset_when_already_unset_is_noop(self, tmp_config, fake_creds, capsys):
        eesel.cmd_agents(self._args())  # clear once
        rc = eesel.cmd_agents(self._args())  # clear again
        assert rc == 0
        assert "No active agent" in capsys.readouterr().err

    def test_unset_does_not_call_fetch_agents(self, tmp_config, fake_creds, monkeypatch):
        # Clearing is purely local — it must not hit the network.
        def boom(creds):
            raise AssertionError("fetch_agents should not be called for unset")

        monkeypatch.setattr(eesel, "fetch_agents", boom)
        assert eesel.cmd_agents(self._args()) == 0


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

        def spy(staff=False):
            seen["staff"] = staff
            return real(staff)

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

    def test_agents_use_parses_id(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["agents", "use", "my-agent"])
        assert args.cmd == "agents"
        assert args.agents_cmd == "use"
        assert args.agent_id == "my-agent"

    def test_agents_use_id_is_optional(self):
        # `agents use` with no id parses (interactive menu picks the agent).
        parser = eesel.build_parser()
        args = parser.parse_args(["agents", "use"])
        assert args.cmd == "agents"
        assert args.agents_cmd == "use"
        assert args.agent_id is None

    def test_agents_unset_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["agents", "unset"])
        assert args.cmd == "agents"
        assert args.agents_cmd == "unset"
        assert args.func is eesel.cmd_agents

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

    def test_cost_subcommand_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["cost"])
        assert args.cmd == "cost"
        assert args.session_id is None

    def test_cost_subcommand_with_session(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["cost", "abc12345"])
        assert args.session_id == "abc12345"

    def test_document_list_subcommand_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["document", "list", "--prefix", "outputs/skills", "--search", "post", "--limit", "25"])
        assert args.cmd == "document"
        assert args.document_cmd == "list"
        assert args.prefix == "outputs/skills"
        assert args.search == "post"
        assert args.limit == 25

    def test_document_export_subcommand_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["document", "export", "--document-id", "doc-123", "--format", "html"])
        assert args.cmd == "document"
        assert args.document_cmd == "export"
        assert args.document_id == "doc-123"
        assert args.format == "html"

    def test_document_defaults_to_list(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["document"])
        assert args.cmd == "document"
        assert args.document_cmd == "list"
        assert args.limit == 100

    def test_document_read_subcommand_parses(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["document", "read", "doc-123", "--prefix", "files/", "--format", "html"])
        assert args.document_cmd == "read"
        assert args.target == "doc-123"
        assert args.prefix == "files/"
        assert args.format == "html"

    def test_document_read_no_target_defaults(self):
        parser = eesel.build_parser()
        args = parser.parse_args(["document", "read"])
        assert args.document_cmd == "read"
        assert args.target is None
        assert args.prefix is None
        assert args.format == "md"

    def test_top_level_export_removed(self):
        parser = eesel.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["export", "--document-id", "doc-123"])


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


# ──────────────────────────────────────────────────────────────────────────
# Integrations / tools / triggers --all  (read-only inspectors)
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

    def test_fetch_all_scheduled_is_subset(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))
        scheduled = eesel.fetch_all_scheduled_triggers(fake_creds)
        assert [t["id"] for t in scheduled] == ["sch-1"]

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
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"allowed": True})
        assert eesel._is_sysadmin(fake_creds) is True

    def test_false_when_not_allowed(self, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "http_request", lambda *a, **k: {"allowed": False})
        assert eesel._is_sysadmin(fake_creds) is False

    def test_fails_closed_on_systemexit(self, fake_creds, monkeypatch):
        def boom(*a, **k):
            raise SystemExit("GET .../cli/impersonate → 404")

        monkeypatch.setattr(eesel, "http_request", boom)
        assert eesel._is_sysadmin(fake_creds) is False


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

    def test_json_emits_raw_payload(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        eesel.cmd_integrations(_args(json=True, secrets=False))
        payload = json.loads(capsys.readouterr().out)
        assert payload[0]["integrationType"] == "zendesk"

    def test_empty(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: [])
        rc = eesel.cmd_integrations(_args(json=False, secrets=False))
        assert rc == 0
        assert "(no integrations)" in capsys.readouterr().err


class TestToolsCommand:
    def _agents(self):
        return [{"agent_id": "agent-test-456", "name": "Support Bot"}]

    def test_lists_active_agent_tools(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "fetch_tools", lambda creds, aid: list(_TOOLS))
        rc = eesel.cmd_tools(_args(agent=None, json=False))
        out = capsys.readouterr().out
        assert rc == 0
        assert "Leave internal note" in out and "WRITE" in out and "ask" in out
        assert "Search docs" in out and "READ" in out and "always_allow" in out
        # integration column shows the resolved key.
        assert "zendesk" in out

    def test_resolves_named_agent(self, fake_creds, monkeypatch, capsys):
        captured = {}
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [
            {"agent_id": "agent-test-456", "name": "Support Bot"},
            {"agent_id": "agent-other-999", "name": "Sales Bot"}])

        def fake_tools(creds, aid):
            captured["aid"] = aid
            return []

        monkeypatch.setattr(eesel, "fetch_tools", fake_tools)
        eesel.cmd_tools(_args(agent="Sales Bot", json=False))
        assert captured["aid"] == "agent-other-999"

    def test_no_active_agent_errors(self, fake_creds, monkeypatch, capsys):
        creds = dict(fake_creds)
        creds.pop("agent_id")
        eesel.save_creds(creds)
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: [
            {"agent_id": "a1", "name": "Bot"}, {"agent_id": "a2", "name": "Bot2"}])
        monkeypatch.setattr(eesel, "fetch_tools", lambda creds, aid: pytest.fail("should not fetch"))
        rc = eesel.cmd_tools(_args(agent=None, json=False))
        assert rc == 1
        assert "No active agent" in capsys.readouterr().err

    def test_json_emits_raw_payload(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "fetch_tools", lambda creds, aid: list(_TOOLS))
        eesel.cmd_tools(_args(agent=None, json=True))
        payload = json.loads(capsys.readouterr().out)
        assert payload[0]["tool_key"] == "zendesk_leave_internal_note"

    def test_empty_tools(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_agents", lambda creds: self._agents())
        monkeypatch.setattr(eesel, "fetch_tools", lambda creds, aid: [])
        rc = eesel.cmd_tools(_args(agent=None, json=False))
        assert rc == 0
        assert "no tools" in capsys.readouterr().err


class TestTriggersAll:
    def test_all_groups_scheduled_on_top_then_by_integration(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: list(_INTEGRATIONS))
        rc = eesel.cmd_triggers(_args(triggers_cmd="list", all=True, json=False))
        out = capsys.readouterr().out
        assert rc == 0
        # scheduled group renders first, with the existing cron/title format.
        assert "scheduled (1)" in out and "Heartbeat" in out and "cron=0 9 * * *" in out
        # zendesk group (resolved via integration map) + intercom (prefix fallback).
        assert "zendesk (1)" in out and "zendesk_ticket_created" in out and "WEBHOOK" in out
        assert "intercom (1)" in out and "intercom_conversation_replied" in out
        # config shown inline for non-scheduled triggers.
        assert '"foo": "bar"' in out
        assert out.index("scheduled (1)") < out.index("zendesk (1)")

    def test_all_json_emits_raw_payload(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))
        monkeypatch.setattr(eesel, "fetch_integrations", lambda *a, **k: pytest.fail("json path must not fetch integrations"))
        eesel.cmd_triggers(_args(triggers_cmd="list", all=True, json=True))
        payload = json.loads(capsys.readouterr().out)
        assert {t["id"] for t in payload} == {"sch-1", "zd-1", "ic-1"}

    def test_all_degrades_when_integrations_unreachable(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))

        def boom(*a, **k):
            raise SystemExit("GET /integrations → 401")

        monkeypatch.setattr(eesel, "fetch_integrations", boom)
        rc = eesel.cmd_triggers(_args(triggers_cmd="list", all=True, json=False))
        out = capsys.readouterr().out
        assert rc == 0
        # zendesk integration_id can't be resolved to a type → prefix label used.
        assert "zendesk (1)" in out and "intercom (1)" in out

    def test_default_list_still_scheduled_only(self, fake_creds, monkeypatch, capsys):
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: list(_ALL_TRIGGERS))
        rc = eesel.cmd_triggers(_args(triggers_cmd="list", all=False, json=False))
        out = capsys.readouterr().out
        assert rc == 0
        assert "Heartbeat" in out
        # Non-scheduled triggers are not listed by the default view.
        assert "zendesk_ticket_created" not in out

    def test_all_redacts_secrets_in_config(self, fake_creds, monkeypatch, capsys):
        triggers = [{
            "id": "ic-1", "type": "WEBHOOK", "trigger_key": "intercom_conversation_replied",
            "config": {"access_token": "tok-LEAK", "app_id": "abc"},
            "integration_id": None, "agent_id": "a1", "agent_name": "Bot",
        }]
        monkeypatch.setattr(eesel, "fetch_all_triggers", lambda creds: triggers)
        monkeypatch.setattr(eesel, "fetch_integrations", lambda creds, agent_id=None: [])
        eesel.cmd_triggers(_args(triggers_cmd="list", all=True, json=False))
        out = capsys.readouterr().out
        assert "tok-LEAK" not in out
        assert '"access_token": "***"' in out
        assert "abc" in out  # non-secret config still shown


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


class TestMcpCreateBody:
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
        assert "Alpha" in out and "https://a" in out and "[active]" in out
        assert "Beta" in out and "[inactive]" in out

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


class TestMcpCreateCommand:
    def test_posts_base_url_and_prints_id(self, tmp_config, fake_creds, monkeypatch, capsys):
        calls = _mcp_capture(monkeypatch)
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "create", "--name", "Alpha", "--url", "https://a"))
        assert rc == 0
        assert calls[0]["method"] == "POST"
        assert calls[0]["url"].endswith("/workspaces/ws-test-123/mcp-servers")
        assert calls[0]["body"] == {"name": "Alpha", "base_url": "https://a"}
        assert "mcp-new-999" in capsys.readouterr().err  # ok() writes to stderr

    def test_config_json_is_merged(self, tmp_config, fake_creds, monkeypatch):
        calls = _mcp_capture(monkeypatch)
        rc = eesel.cmd_mcp(
            _mcp_parse("mcp", "create", "--name", "Alpha", "--url", "https://a",
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
            _mcp_parse("mcp", "create", "--name", "A", "--url", "https://a", "--config", "{not json}")
        )
        assert rc == 1
        assert calls == []
        assert "valid JSON" in capsys.readouterr().err


class TestMcpEditCommand:
    SERVERS = [
        {"id": "srv-abc123", "name": "Alpha", "base_url": "https://a", "is_active": True},
        {"id": "srv-def456", "name": "Beta", "base_url": "https://b", "is_active": True},
    ]

    def test_sends_only_provided_field(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "edit", "srv-abc123", "--name", "Renamed"))
        assert rc == 0
        assert calls[0]["method"] == "PUT"
        assert calls[0]["url"].endswith("/workspaces/ws-test-123/mcp-servers/srv-abc123")
        assert calls[0]["body"] == {"name": "Renamed"}

    def test_url_only_sends_base_url(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        eesel.cmd_mcp(_mcp_parse("mcp", "edit", "srv-abc123", "--url", "https://new"))
        assert calls[-1]["body"] == {"base_url": "https://new"}

    def test_nothing_to_update_fails(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "edit", "srv-abc123"))
        assert rc == 1
        assert calls == []

    def test_unknown_target_errors(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "edit", "nope", "--name", "X"))
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


class TestMcpDeleteCommand:
    SERVERS = [{"id": "srv-abc123", "name": "Alpha", "base_url": "https://a", "is_active": True}]

    def test_yes_flag_skips_prompt_and_deletes(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "delete", "srv-abc123", "--yes"))
        assert rc == 0
        assert calls[0]["method"] == "DELETE"
        assert calls[0]["url"].endswith("/workspaces/ws-test-123/mcp-servers/srv-abc123")

    def test_short_y_flag_also_skips_prompt(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "delete", "srv-abc123", "-y"))
        assert rc == 0
        assert calls[0]["method"] == "DELETE"

    def test_affirmative_confirmation_deletes(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        monkeypatch.setattr("builtins.input", lambda prompt="": "yes")
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "delete", "srv-abc123"))
        assert rc == 0
        assert calls[0]["method"] == "DELETE"

    def test_negative_confirmation_aborts_without_request(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        monkeypatch.setattr("builtins.input", lambda prompt="": "")  # bare Enter
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "delete", "srv-abc123"))
        assert rc == 1
        assert calls == []

    def test_unknown_target_errors_without_request(self, tmp_config, fake_creds, monkeypatch):
        monkeypatch.setattr(eesel, "fetch_mcp_servers", lambda creds: self.SERVERS)
        calls = _mcp_capture(monkeypatch, response={})
        rc = eesel.cmd_mcp(_mcp_parse("mcp", "delete", "nope", "--yes"))
        assert rc == 1
        assert calls == []
