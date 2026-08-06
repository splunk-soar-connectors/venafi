# Copyright (c) 2019-2026 Splunk Inc.
"""Tests for VenafiHelper token handling and legacy state migration."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from src.app import VenafiHelper


def _asset(auth_state):
    return SimpleNamespace(
        base_url="https://venafi.example",
        username="u",
        password="p",
        client_id="c",
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


def test_legacy_state_is_migrated():
    # Classic connector stored the bundle at top-level "access_token".
    state = FakeAuthState(
        data={},
        legacy={"access_token": {"access_token": "LA", "refresh_token": "LR"}},
    )
    helper = VenafiHelper(MagicMock(), _asset(state))

    assert helper._access_token == "LA"
    assert helper._refresh_token == "LR"
    # It should be persisted under the SDK key for next time.
    assert state.get_all()["venafi_token"]["access_token"] == "LA"


def test_blank_scope_falls_back_to_default():
    from src import venafi_consts as consts

    helper = VenafiHelper(MagicMock(), _asset(FakeAuthState()))
    assert helper.scope == consts.VENAFI_DEFAULT_SCOPE
