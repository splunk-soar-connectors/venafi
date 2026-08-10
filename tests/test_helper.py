# Copyright (c) 2019-2026 Splunk Inc.
"""Test the configurable OAuth scope default (ESPM-5451)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from src import venafi_consts as consts
from src.app import VenafiHelper


class FakeAuthState:
    def __init__(self, data=None):
        self._data = dict(data or {})
        self.backend = MagicMock()
        self.backend.load_state.return_value = {}

    def get_all(self):
        return dict(self._data)

    def put_all(self, new_value):
        self._data = dict(new_value)


def _asset(oauth_scope):
    return SimpleNamespace(
        base_url="https://venafi.example",
        username="u",
        password="p",
        client_id="c",
        oauth_scope=oauth_scope,
        auth_state=FakeAuthState(),
    )


def test_blank_scope_falls_back_to_default():
    helper = VenafiHelper(MagicMock(), _asset(""))
    assert helper.scope == consts.VENAFI_DEFAULT_SCOPE


def test_custom_scope_is_used():
    helper = VenafiHelper(MagicMock(), _asset("certificate:manage"))
    assert helper.scope == "certificate:manage"


def _asset_with_state(state):
    return SimpleNamespace(
        base_url="https://venafi.example",
        username="u",
        password="p",
        client_id="c",
        oauth_scope="",
        auth_state=state,
    )


def test_token_reused_for_same_host():
    state = FakeAuthState(
        {
            "venafi_token": {
                "access_token": "A",
                "refresh_token": "R",
                "base_url": "https://venafi.example",
            }
        }
    )
    helper = VenafiHelper(MagicMock(), _asset_with_state(state))
    assert helper._access_token == "A"


def test_token_discarded_when_base_url_changes():
    state = FakeAuthState(
        {
            "venafi_token": {
                "access_token": "A",
                "refresh_token": "R",
                "base_url": "https://old-host",
            }
        }
    )
    helper = VenafiHelper(MagicMock(), _asset_with_state(state))
    assert helper._access_token is None
    assert helper._refresh_token is None
