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

import json

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams, Param

from ..asset import Asset
from ..venafi_auth import get_authenticated_client
from ..venafi_consts import VENAFI_DEFAULT_TIMEOUT


class VenafiMakeRequestParams(MakeRequestParams):
    endpoint: str = Param(
        description=(
            "Venafi API endpoint to call, appended to the asset base URL "
            "(e.g. '/vedsdk/certificates'). Do not include the base URL."
        ),
        required=True,
    )
    verify_ssl: bool = Param(
        description="Whether to verify the SSL certificate. Default is True.",
        required=False,
        default=True,
    )


class VenafiMakeRequestOutput(ActionOutput):
    status_code: int = OutputField(example_values=[200])
    response_body: str = OutputField(example_values=["{}"])

    @classmethod
    def from_response(cls, response: httpx.Response) -> "VenafiMakeRequestOutput":
        return cls(status_code=response.status_code, response_body=response.text)


def _send_request(
    asset: Asset,
    params: VenafiMakeRequestParams,
    endpoint: str,
    headers: dict,
    query_params: dict | None,
    body: dict | None,
    timeout: int | float,
) -> httpx.Response:
    try:
        with get_authenticated_client(asset, verify_ssl=params.verify_ssl) as client:
            response = client.request(
                params.http_method,
                endpoint,
                headers=headers,
                params=query_params,
                json=body,
                timeout=timeout,
            )
        if response.status_code == 401:
            with get_authenticated_client(
                asset, verify_ssl=params.verify_ssl, refresh_token=True
            ) as client:
                response = client.request(
                    params.http_method,
                    endpoint,
                    headers=headers,
                    params=query_params,
                    json=body,
                    timeout=timeout,
                )
        return response
    except httpx.HTTPError as error:
        raise ActionFailure(f"Request failed: {error}") from None


def http_action(
    params: VenafiMakeRequestParams, soar: SOARClient, asset: Asset
) -> VenafiMakeRequestOutput:
    """Make an authenticated request to the Venafi API."""
    if params.endpoint.startswith(("http://", "https://")):
        raise ActionFailure(
            f"Invalid endpoint: {params.endpoint}. Do not include the base URL — "
            "it is derived from the asset configuration."
        )

    endpoint = "/" + params.endpoint.lstrip("/")

    user_headers: dict = {}
    if params.headers:
        try:
            user_headers = json.loads(params.headers)
        except (json.JSONDecodeError, TypeError) as e:
            raise ActionFailure(f"Invalid JSON headers: {params.headers}") from e

    query_params = None
    if params.query_parameters:
        try:
            query_params = json.loads(params.query_parameters)
        except (json.JSONDecodeError, TypeError):
            # Raw query string passthrough: drop any URL fragment before appending.
            query_string = params.query_parameters.split("#", 1)[0].lstrip("?")
            sep = "&" if "?" in endpoint else "?"
            endpoint = f"{endpoint}{sep}{query_string}"

    body = None
    if params.body:
        try:
            body = json.loads(params.body)
        except (json.JSONDecodeError, TypeError) as e:
            raise ActionFailure(f"Invalid JSON body: {params.body}") from e

    timeout = params.timeout or VENAFI_DEFAULT_TIMEOUT

    response = _send_request(
        asset, params, endpoint, user_headers, query_params, body, timeout
    )

    return VenafiMakeRequestOutput.from_response(response)
