# Copyright (c) 2019-2026 Splunk Inc.
"""Happy-path tests for the Venafi SDK actions."""

from unittest.mock import MagicMock, patch

import pytest
from soar_sdk.exceptions import ActionFailure

from src.actions.create_certificate import CreateCertificateParams, create_certificate
from src.actions.list_certificates import ListCertificatesParams, list_certificates
from src.actions.list_policies import list_policies
from src.actions.make_request import VenafiMakeRequestParams, http_action
from src.actions.renew_certificate import RenewCertificateParams, renew_certificate
from src.actions.revoke_certificate import RevokeCertificateParams, revoke_certificate

CERT_DN = "\\VED\\Policy\\Certificates\\test\\a.com"


def _helper_returning(module_path, response):
    """Patch a module's VenafiHelper so make_rest_call returns `response`."""
    patcher = patch(f"src.actions.{module_path}.VenafiHelper")
    helper_cls = patcher.start()
    helper_cls.return_value.make_rest_call.return_value = response
    return patcher, helper_cls.return_value


def test_list_policies_success():
    soar = MagicMock()
    patcher, _ = _helper_returning(
        "list_policies", {"Objects": [{"Name": "P1", "DN": "\\VED\\Policy\\P1"}]}
    )
    try:
        out = list_policies(MagicMock(), soar, MagicMock())
    finally:
        patcher.stop()

    assert len(out) == 1
    assert out[0].Name == "P1"
    soar.set_summary.assert_called_once()


def test_list_certificates_success():
    soar = MagicMock()
    patcher, _ = _helper_returning(
        "list_certificates", {"Certificates": [{"DN": CERT_DN, "Name": "a.com"}]}
    )
    try:
        out = list_certificates(ListCertificatesParams(), soar, MagicMock())
    finally:
        patcher.stop()

    assert len(out) == 1
    assert out[0].DN == CERT_DN
    soar.set_summary.assert_called_once()


def test_list_certificates_rejects_limit_over_100():
    with (
        patch("src.actions.list_certificates.VenafiHelper"),
        pytest.raises(ActionFailure, match="limit"),
    ):
        list_certificates(ListCertificatesParams(limit=101), MagicMock(), MagicMock())


def test_create_certificate_success():
    soar = MagicMock()
    patcher, _ = _helper_returning(
        "create_certificate", {"CertificateDN": CERT_DN, "Guid": "G-1"}
    )
    params = CreateCertificateParams(policy_dn="\\VED\\Policy\\test", subject="a.com")
    try:
        out = create_certificate(params, soar, MagicMock())
    finally:
        patcher.stop()

    assert out.CertificateDN == CERT_DN
    assert out.Guid == "G-1"
    soar.set_summary.assert_called_once()


def test_renew_certificate_success():
    soar = MagicMock()
    patcher, _ = _helper_returning("renew_certificate", {"Success": True})
    params = RenewCertificateParams(certificate_dn=CERT_DN)
    try:
        out = renew_certificate(params, soar, MagicMock())
    finally:
        patcher.stop()

    assert out.Success is True
    soar.set_summary.assert_called_once()


def test_revoke_certificate_success():
    soar = MagicMock()
    patcher, _ = _helper_returning(
        "revoke_certificate", {"Success": True, "Requested": True, "Revoked": True}
    )
    params = RevokeCertificateParams(certificate_dn=CERT_DN)
    try:
        out = revoke_certificate(params, soar, MagicMock())
    finally:
        patcher.stop()

    assert out.Success is True
    soar.set_summary.assert_called_once()


def test_make_request_success():
    asset = MagicMock()
    asset.base_url = "https://venafi.example"
    resp = MagicMock()
    resp.status_code = 200
    resp.text = '{"ok": true}'
    params = VenafiMakeRequestParams(http_method="GET", endpoint="/vedsdk/certificates")

    with patch("src.actions.make_request.VenafiHelper") as helper_cls:
        helper_cls.return_value.auth_headers.return_value = {
            "Authorization": "Bearer x"
        }
        with patch(
            "src.actions.make_request.requests.request", return_value=resp
        ) as req:
            out = http_action(params, MagicMock(), asset)

    assert out.status_code == 200
    assert req.call_args.kwargs["verify"] is True
