# Copyright (c) 2019-2026 Splunk Inc.
"""Regression tests for the 'make request' action (401 refresh/retry)."""

from unittest.mock import MagicMock, patch

from src.actions.make_request import VenafiMakeRequestParams, http_action


def _params(**kw):
    kw.setdefault("http_method", "GET")
    kw.setdefault("endpoint", "/vedsdk/certificates")
    return VenafiMakeRequestParams(**kw)


def _resp(status_code, text="{}"):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    return r


def test_refreshes_and_retries_on_401():
    asset = MagicMock()
    asset.base_url = "https://venafi.example"
    with patch("src.actions.make_request.VenafiHelper") as helper_cls:
        helper = helper_cls.return_value
        helper.auth_headers.return_value = {"Authorization": "Bearer old"}
        with patch(
            "src.actions.make_request.requests.request",
            side_effect=[_resp(401), _resp(200, '{"ok": true}')],
        ) as req:
            output = http_action.__wrapped__(_params(), MagicMock(), asset)

    # A 401 must trigger exactly one refresh and one retry.
    helper.refresh.assert_called_once()
    assert req.call_count == 2
    assert output.status_code == 200


def test_no_retry_when_first_call_succeeds():
    asset = MagicMock()
    asset.base_url = "https://venafi.example"
    with patch("src.actions.make_request.VenafiHelper") as helper_cls:
        helper = helper_cls.return_value
        helper.auth_headers.return_value = {"Authorization": "Bearer ok"}
        with patch(
            "src.actions.make_request.requests.request",
            side_effect=[_resp(200)],
        ) as req:
            output = http_action.__wrapped__(_params(), MagicMock(), asset)

    helper.refresh.assert_not_called()
    assert req.call_count == 1
    assert output.status_code == 200


def test_tls_verification_on_by_default():
    # verify_ssl must default to True so the raw request verifies TLS like the
    # other Venafi actions.
    assert _params().verify_ssl is True

    asset = MagicMock()
    asset.base_url = "https://venafi.example"
    with patch("src.actions.make_request.VenafiHelper") as helper_cls:
        helper_cls.return_value.auth_headers.return_value = {
            "Authorization": "Bearer x"
        }
        with patch(
            "src.actions.make_request.requests.request", side_effect=[_resp(200)]
        ) as req:
            http_action.__wrapped__(_params(), MagicMock(), asset)

    assert req.call_args.kwargs["verify"] is True
