# Copyright (c) 2019-2026 Splunk Inc.
"""Tests for the 'get certificate' action (redaction + vault download)."""

from unittest.mock import MagicMock, patch

import pytest
from soar_sdk.exceptions import ActionFailure

from src.actions.get_certificate import GetCertificateParams, get_certificate


def _response(content, filename="cert.cer"):
    resp = MagicMock()
    resp.content = content
    resp.headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    resp.raise_for_status.return_value = None
    return resp


def _soar():
    soar = MagicMock()
    soar.get_executing_container_id.return_value = 1
    soar.vault.create_attachment.return_value = "vault-id"
    return soar


def _mock_client_get(helper_cls, response):
    client = helper_cls.return_value.build_client.return_value.__enter__.return_value
    client.get.return_value = response
    return client


def test_sensitive_params_are_redacted_and_added_to_vault():
    soar = _soar()
    params = GetCertificateParams(
        certificate_dn="\\VED\\Policy\\test\\a.com",
        keystore_password="s3cret-keystore",  # pragma: allowlist secret
        password="s3cret-password",  # pragma: allowlist secret
    )

    with patch("src.actions.get_certificate.VenafiHelper") as helper_cls:
        _mock_client_get(helper_cls, _response(b"cert-data", "cert.cer"))
        out = get_certificate(params, soar, MagicMock())

    # Passwords cleared so they never reach the serialized action result.
    assert params.keystore_password is None
    assert params.password is None
    soar.vault.create_attachment.assert_called_once()
    assert out.name == "cert.cer"
    assert out.vault_id == "vault-id"
    assert out.size == len(b"cert-data")


def test_empty_download_is_rejected():
    soar = _soar()
    params = GetCertificateParams(certificate_dn="\\VED\\Policy\\test\\a.com")

    with patch("src.actions.get_certificate.VenafiHelper") as helper_cls:
        _mock_client_get(helper_cls, _response(b"", "cert.cer"))
        with pytest.raises(ActionFailure, match="empty"):
            get_certificate(params, soar, MagicMock())
