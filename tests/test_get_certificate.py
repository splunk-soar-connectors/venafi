# Copyright (c) 2019-2026 Splunk Inc.
"""Tests for the 'get certificate' action (redaction + temp-file streaming)."""

import tempfile
from unittest.mock import MagicMock, patch

import pytest
from soar_sdk.exceptions import ActionFailure

from src.actions.get_certificate import GetCertificateParams, get_certificate


def _fake_response(chunks):
    resp = MagicMock()
    resp.iter_content.return_value = chunks
    return resp


def _soar():
    soar = MagicMock()
    soar.get_executing_container_id.return_value = 1
    soar.vault.get_vault_tmp_dir.return_value = tempfile.gettempdir()
    soar.vault.add_attachment.return_value = "vault-id"
    return soar


def test_sensitive_params_are_redacted_and_streamed_to_vault():
    soar = _soar()
    params = GetCertificateParams(
        certificate_dn="\\VED\\Policy\\test\\a.com",
        keystore_password="s3cret-keystore",  # pragma: allowlist secret
        password="s3cret-password",  # pragma: allowlist secret
    )

    with patch("src.actions.get_certificate.VenafiHelper") as helper_cls:
        helper_cls.return_value.stream_certificate.return_value = (
            _fake_response([b"cert-", b"data"]),
            "cert.cer",
        )
        out = get_certificate(params, soar, MagicMock())

    # Passwords cleared so they never reach the serialized action result.
    assert params.keystore_password is None
    assert params.password is None
    # File added from a temp path (bounded memory), not raw bytes.
    soar.vault.add_attachment.assert_called_once()
    assert out.name == "cert.cer"
    assert out.vault_id == "vault-id"
    assert out.size == len(b"cert-data")


def test_empty_download_is_rejected():
    soar = _soar()
    params = GetCertificateParams(certificate_dn="\\VED\\Policy\\test\\a.com")

    with patch("src.actions.get_certificate.VenafiHelper") as helper_cls:
        helper_cls.return_value.stream_certificate.return_value = (
            _fake_response([]),
            "cert.cer",
        )
        with pytest.raises(ActionFailure, match="empty"):
            get_certificate(params, soar, MagicMock())
