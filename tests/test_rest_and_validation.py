# Copyright (c) 2019-2026 Splunk Inc.
"""Tests for non-JSON response handling and list_certificates validation."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from soar_sdk.exceptions import ActionFailure

from src.app import VenafiHelper
from src.actions.list_certificates import ListCertificatesParams, list_certificates


def _asset():
    return SimpleNamespace(
        base_url="https://venafi.example",
        username="u",
        password="p",
        client_id="c",
        oauth_scope="",
        auth_state=_AuthState(),
    )


class _AuthState:
    def __init__(self):
        self._d = {"venafi_token": {"access_token": "A", "refresh_token": "R"}}
        self.backend = MagicMock()
        self.backend.load_state.return_value = {}

    def get_all(self):
        return dict(self._d)

    def put_all(self, v):
        self._d = dict(v)


def _resp(status_code, text, content_type):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.headers = {"Content-Type": content_type}
    if "json" in content_type:
        r.json.return_value = json.loads(text)
    return r


def test_non_json_success_response_is_failure():
    """An HTML page returned with HTTP 200 must not be treated as success."""
    helper = VenafiHelper(MagicMock(), _asset())
    html = "<html><body>404 Not Found</body></html>"
    with (
        patch.object(helper, "_request", return_value=_resp(200, html, "text/html")),
        pytest.raises(ActionFailure),
    ):
        helper.make_rest_call("/vedsdk/certificates", method="get")


def test_json_success_response_is_parsed():
    helper = VenafiHelper(MagicMock(), _asset())
    with patch.object(
        helper, "_request", return_value=_resp(200, '{"ok": true}', "application/json")
    ):
        assert helper.make_rest_call("/vedsdk/certificates", method="get") == {
            "ok": True
        }


def _run_list(**param_kwargs):
    soar = MagicMock()
    with patch("src.actions.list_certificates.VenafiHelper") as helper_cls:
        helper_cls.return_value.make_rest_call.return_value = {"Certificates": []}
        return list_certificates.__wrapped__(
            ListCertificatesParams(**param_kwargs), soar, MagicMock()
        )


@pytest.mark.parametrize("bad_limit", [0, 1.5])
def test_invalid_limit_rejected(bad_limit):
    with pytest.raises(ActionFailure, match="limit"):
        _run_list(limit=bad_limit)


def test_negative_offset_rejected():
    with pytest.raises(ActionFailure, match="offset"):
        _run_list(offset=-1)


def test_valid_limit_offset_accepted():
    # Should not raise.
    _run_list(limit=10, offset=0)
