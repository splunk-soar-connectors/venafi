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
from soar_sdk.action_results import ActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..venafi_auth import get_authenticated_client
from ..venafi_consts import VENAFI_RENEW_CERTIFICATE_URI


class RenewCertificateParams(Params):
    certificate_dn: str = Param(
        description="The Distinguished Name (DN) of the certificate to renew",
        primary=True,
        cef_types=["venafi certificate dn"],
    )
    pkcs10: str | None = Param(
        description="The PKCS10 formatted CSR to use for the renewal"
    )
    reenable: bool | None = Param(
        description="Option to renew a previously disabled certificate"
    )


class RenewCertificateOutput(ActionOutput):
    Success: bool | None = None


class RenewCertificateSummary(ActionOutput):
    status: str | None = None


def renew_certificate(
    params: RenewCertificateParams, soar: SOARClient, asset: Asset
) -> RenewCertificateOutput:
    data = {
        "CertificateDN": params.certificate_dn,
        "PKCS10": params.pkcs10,
        "Reenable": params.reenable or False,
    }
    try:
        with get_authenticated_client(asset) as client:
            response = client.post(VENAFI_RENEW_CERTIFICATE_URI, json=data)
        if response.status_code == 401:
            with get_authenticated_client(asset, refresh_token=True) as client:
                response = client.post(VENAFI_RENEW_CERTIFICATE_URI, json=data)
        response.raise_for_status()
    except httpx.HTTPStatusError as error:
        raise ActionFailure(f"Failed to renew certificate: {error}") from None
    except httpx.HTTPError as error:
        raise ActionFailure(f"Failed to renew certificate: {error}") from None

    try:
        response = response.json()
    except ValueError:
        raise ActionFailure(
            "Failed to renew certificate: Venafi returned invalid JSON"
        ) from None

    if not isinstance(response, dict) or response.get("Success") is not True:
        error = (
            response.get("Error", "The server did not confirm certificate renewal")
            if isinstance(response, dict)
            else "Invalid response"
        )
        raise ActionFailure(f"Failed to renew certificate. Server response: {error}")

    soar.set_summary(RenewCertificateSummary(status="Successfully renewed certificate"))
    soar.set_message("Successfully renewed certificate")
    return RenewCertificateOutput(Success=True)
