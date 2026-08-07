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

import requests
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams, Param

from ..app import Asset, VenafiHelper, app
from ..venafi_consts import VENAFI_DEFAULT_TIMEOUT


class VenafiMakeRequestParams(MakeRequestParams):
    endpoint: str = Param(
        description=(
            "Venafi API endpoint to call, appended to the asset base URL "
            "(e.g. '/vedsdk/certificates'). Do not include the base URL."
        ),
        required=True,
    )


class VenafiMakeRequestOutput(ActionOutput):
    status_code: int = OutputField(example_values=[200])
    response_body: str = OutputField(example_values=["{}"])

    @classmethod
    def from_response(cls, response: requests.Response) -> "VenafiMakeRequestOutput":
        return cls(status_code=response.status_code, response_body=response.text)


@app.make_request()
def http_action(
    params: VenafiMakeRequestParams, soar: SOARClient, asset: Asset
) -> VenafiMakeRequestOutput:
    if params.endpoint.startswith(("http://", "https://")):
        raise ActionFailure(
            f"Invalid endpoint: {params.endpoint}. Do not include the base URL — "
            "it is derived from the asset configuration."
        )

    helper = VenafiHelper(soar, asset)

    base_url = asset.base_url.rstrip("/")
    endpoint = "/" + params.endpoint.lstrip("/")
    url = f"{base_url}{endpoint}"

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
            query_string = params.query_parameters.lstrip("?")
            url = f"{url}?{query_string}" if "?" not in url else f"{url}&{query_string}"

    body = None
    if params.body:
        try:
            body = json.loads(params.body)
        except (json.JSONDecodeError, TypeError) as e:
            raise ActionFailure(f"Invalid JSON body: {params.body}") from e

    timeout = params.timeout or VENAFI_DEFAULT_TIMEOUT

    def _send() -> requests.Response:
        headers = {**helper.auth_headers(), **user_headers}
        return requests.request(
            method=params.http_method,
            url=url,
            headers=headers,
            params=query_params,
            json=body,
            timeout=timeout,
            verify=params.verify_ssl,
        )

    try:
        response = _send()
        if response.status_code == 401:
            # Cached token was stale; refresh and retry once, like the other actions.
            helper.refresh()
            response = _send()
    except Exception as e:
        raise ActionFailure(f"Request failed: {e}") from e

    return VenafiMakeRequestOutput.from_response(response)
