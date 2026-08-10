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
