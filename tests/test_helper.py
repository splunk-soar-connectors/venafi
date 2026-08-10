# Copyright (c) 2019-2026 Splunk Inc.
"""Tests for VenafiHelper token handling and credential normalization."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from src.app import VenafiHelper


def _asset(auth_state, username="u", password="p", client_id="c"):
    return SimpleNamespace(
        base_url="https://venafi.example",
        username=username,
        password=password,
        client_id=client_id,
        oauth_scope="",
        auth_state=auth_state,
    )


class FakeAuthState:
    """Minimal stand-in for the SDK AssetState with an optional legacy backend."""

    def __init__(self, data=None, legacy=None):
        self._data = dict(data or {})
        self.backend = MagicMock()
        self.backend.load_state.return_value = legacy or {}

    def get_all(self):
        return dict(self._data)

    def put_all(self, new_value):
        self._data = dict(new_value)


def test_empty_state_yields_no_tokens():
    helper = VenafiHelper(MagicMock(), _asset(FakeAuthState()))
    assert helper._access_token is None
    assert helper._refresh_token is None


def test_existing_sdk_state_is_used():
    state = FakeAuthState(
        data={"venafi_token": {"access_token": "A", "refresh_token": "R"}}
    )
    helper = VenafiHelper(MagicMock(), _asset(state))
    assert helper._access_token == "A"
    assert helper._refresh_token == "R"


def test_no_legacy_migration_from_state_file():
    # Classic connector tokens (top-level "access_token") must NOT be migrated;
    # a fresh token is generated on first use instead.
    state = FakeAuthState(
        data={},
        legacy={"access_token": {"access_token": "LA", "refresh_token": "LR"}},
    )
    helper = VenafiHelper(MagicMock(), _asset(state))

    assert helper._access_token is None
    assert helper._refresh_token is None


def test_blank_scope_falls_back_to_default():
    from src import venafi_consts as consts

    helper = VenafiHelper(MagicMock(), _asset(FakeAuthState()))
    assert helper.scope == consts.VENAFI_DEFAULT_SCOPE


def test_credentials_are_stripped_in_token_request():
    helper = VenafiHelper(
        MagicMock(),
        _asset(FakeAuthState(), username="  u  ", password="  p  ", client_id="  c  "),
    )
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {"Content-Type": "application/json"}
    resp.json.return_value = {"access_token": "A", "refresh_token": "R"}
    with patch("src.app.requests.post", return_value=resp) as post:
        helper._request_new_token()

    sent = post.call_args.kwargs["json"]
    assert sent["username"] == "u"
    assert sent["password"] == "p"
    assert sent["client_id"] == "c"
