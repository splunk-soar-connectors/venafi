# Copyright (c) 2019-2026 Splunk Inc.
"""Coverage for the second round of review findings."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from soar_sdk.exceptions import ActionFailure

from src.app import VenafiHelper
from src.actions.create_certificate import CreateCertificateParams, create_certificate
from src.actions.list_certificates import ListCertificatesOutput, list_certificates
from src.actions.list_policies import list_policies


class _AuthState:
    def __init__(self, tokens=None):
        self._d = {"venafi_token": tokens} if tokens else {}
        self.backend = MagicMock()
        self.backend.load_state.return_value = {}

    def get_all(self):
        return dict(self._d)

    def put_all(self, v):
        self._d = dict(v)


def _asset():
    return SimpleNamespace(
        base_url="https://venafi.example",
        username="u",
        password="p",
        client_id="c",
        oauth_scope="",
        auth_state=_AuthState(),
    )


def _token_resp(json_value, raises=False):
    r = MagicMock()
    r.status_code = 200
    r.headers = {"Content-Type": "application/json"}
    r.text = "body"
    if raises:
        r.json.side_effect = ValueError("no json")
    else:
        r.json.return_value = json_value
    return r


# --- token response validation --------------------------------------------
def test_new_token_rejects_non_json():
    helper = VenafiHelper(MagicMock(), _asset())
    with (
        patch("src.app.requests.post", return_value=_token_resp(None, raises=True)),
        pytest.raises(ActionFailure),
    ):
        helper._request_new_token()


def test_new_token_rejects_missing_access_token():
    helper = VenafiHelper(MagicMock(), _asset())
    with (
        patch(
            "src.app.requests.post", return_value=_token_resp({"refresh_token": "R"})
        ),
        pytest.raises(ActionFailure, match="access_token"),
    ):
        helper._request_new_token()


def test_new_token_stores_valid_token():
    helper = VenafiHelper(MagicMock(), _asset())
    with patch(
        "src.app.requests.post",
        return_value=_token_resp({"access_token": "A", "refresh_token": "R"}),
    ):
        helper._request_new_token()
    assert helper._access_token == "A"


# --- malformed list responses ----------------------------------------------
def _list_helper(response):
    def _factory(soar, asset):
        h = MagicMock()
        h.make_rest_call.return_value = response
        return h

    return _factory


def test_list_policies_fails_on_malformed_response():
    soar = MagicMock()
    with patch("src.actions.list_policies.VenafiHelper", _list_helper({"foo": "bar"})):
        with pytest.raises(ActionFailure):
            list_policies.__wrapped__(MagicMock(), soar, MagicMock())


def test_list_certificates_fails_on_malformed_response():
    from src.actions.list_certificates import ListCertificatesParams

    soar = MagicMock()
    with (
        patch(
            "src.actions.list_certificates.VenafiHelper", _list_helper({"foo": "bar"})
        ),
        pytest.raises(ActionFailure),
    ):
        list_certificates.__wrapped__(ListCertificatesParams(), soar, MagicMock())


# --- _links alias -----------------------------------------------------------
def test_links_output_uses_underscore_alias():
    out = ListCertificatesOutput(**{"DN": "x", "_links": [{"Details": "/d"}]})
    dumped = out.model_dump(by_alias=True)
    assert "_links" in dumped


# --- create certificate cross-field requirement -----------------------------
def test_create_certificate_requires_subject_or_object_name():
    params = CreateCertificateParams(policy_dn="\\VED\\Policy\\test")
    with pytest.raises(ActionFailure, match="subject"):
        create_certificate.__wrapped__(params, MagicMock(), MagicMock())
