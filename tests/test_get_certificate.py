# Copyright (c) 2019-2026 Splunk Inc.
"""Regression tests for the 'get certificate' action (password redaction)."""

from unittest.mock import MagicMock, patch

from src.actions.get_certificate import GetCertificateParams, get_certificate


def _run(params):
    soar = MagicMock()
    soar.get_executing_container_id.return_value = 1
    soar.vault.create_attachment.return_value = "vault-id"
    with patch("src.actions.get_certificate.VenafiHelper") as helper_cls:
        helper = helper_cls.return_value
        helper.download_certificate.return_value = ("cert.cer", b"data")
        output = get_certificate.__wrapped__(params, soar, MagicMock())
    return output


def test_sensitive_params_are_redacted():
    params = GetCertificateParams(
        certificate_dn="\\VED\\Policy\\test\\a.com",
        keystore_password="s3cret-keystore",  # pragma: allowlist secret
        password="s3cret-password",  # pragma: allowlist secret
    )

    _run(params)

    # After the action runs, the passwords must be cleared so they never reach
    # the serialized action-result parameters.
    assert params.keystore_password is None
    assert params.password is None


def test_returns_vault_output():
    params = GetCertificateParams(certificate_dn="\\VED\\Policy\\test\\a.com")

    output = _run(params)

    assert output.name == "cert.cer"
    assert output.vault_id == "vault-id"
    assert output.size == len(b"data")
