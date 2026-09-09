# Copyright (c) 2019-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..venafi_auth import get_authenticated_client
from ..venafi_consts import VENAFI_REVOKE_CERTIFICATE_URI


class RevokeCertificateParams(Params):
    certificate_dn: str | None = Param(
        description="The Distinguished Name (DN) of the certificate to revoke",
        primary=True,
        cef_types=["venafi certificate dn"],
    )
    thumbprint: str | None = Param(
        description="The thumbprint (hash) of the certificate to revoke",
        primary=True,
        cef_types=["sha1"],
    )
    reason: float | None = Param(
        description="The reason for revocation of the certificate. 0: None, 1: User key compromised, 2: CA key compromised, 3: User changed affiliation, 4: Certificate superseded, 5: Original use no longer valid",
        value_list=["0", "1", "2", "3", "4", "5"],
    )
    comments: str | None = Param(
        description="Details about why the certificate is being revoked"
    )
    disable: bool | None = Param(
        description="The setting to manage the certificate upon revocation. If true, the certificate is disabled and no new certificate may replace it. If false, the certificate is allowed to be replaced by a new certificate"
    )


class RevokeCertificateOutput(ActionOutput):
    Requested: bool | None = None
    Revoked: bool | None = None
    Success: bool | None = None
    Warning: str | None = OutputField(
        example_values=[
            'Revocation is already completed. The certificate "\\VED\\Policy\\Partner Dev\\TLS\\Certificates\\Testing\\testfriendlyname2" revocation was requested by another request or process.'
        ]
    )


class RevokeCertificateSummary(ActionOutput):
    status: str | None = None


def _request_revocation(asset: Asset, data: dict) -> object:
    try:
        with get_authenticated_client(asset) as client:
            response = client.post(VENAFI_REVOKE_CERTIFICATE_URI, json=data)
        if response.status_code == 401:
            with get_authenticated_client(asset, refresh_token=True) as client:
                response = client.post(VENAFI_REVOKE_CERTIFICATE_URI, json=data)
        response.raise_for_status()
    except httpx.HTTPStatusError as error:
        raise ActionFailure(f"Failed to revoke certificate: {error}") from None
    except httpx.HTTPError as error:
        raise ActionFailure(f"Failed to revoke certificate: {error}") from None
    try:
        return response.json()
    except ValueError:
        raise ActionFailure(
            "Failed to revoke certificate: Venafi returned invalid JSON"
        ) from None


def revoke_certificate(
    params: RevokeCertificateParams, soar: SOARClient, asset: Asset
) -> RevokeCertificateOutput:
    if not (params.certificate_dn or params.thumbprint):
        raise ActionFailure(
            "Error: Must pass in either CertificateDN or Thumbprint parameter"
        )

    if params.reason is not None and params.reason != int(params.reason):
        raise ActionFailure("'reason' must be a whole number")
    reason = int(params.reason) if params.reason is not None else None

    data = {
        "CertificateDN": params.certificate_dn,
        "Thumbprint": params.thumbprint,
        "Reason": reason,
        "Comments": params.comments,
        "Disable": params.disable or False,
    }
    response = _request_revocation(asset, data)

    if not isinstance(response, dict) or response.get("Success") is not True:
        error = (
            response.get("Error", "The server did not confirm certificate revocation")
            if isinstance(response, dict)
            else "Invalid response"
        )
        raise ActionFailure(f"Failed to revoke certificate. Server response: {error}")

    soar.set_summary(
        RevokeCertificateSummary(status="Successfully revoked certificate")
    )
    soar.set_message("Successfully revoked certificate")
    return RevokeCertificateOutput(
        Requested=response.get("Requested"),
        Revoked=response.get("Revoked"),
        Success=response.get("Success"),
        Warning=response.get("Warning"),
    )
