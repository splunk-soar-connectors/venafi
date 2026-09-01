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

from __future__ import annotations

from collections.abc import Generator
from typing import Any

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from . import venafi_consts as consts
from .asset import Asset

logger = getLogger()

# Key under which the Venafi token bundle is cached in the asset auth state.
_TOKEN_STATE_KEY = "venafi_token"  # noqa: S105  # pragma: allowlist secret


def error_message(response: httpx.Response) -> str:
    """Build a readable error message from a Venafi error response."""
    content_type = response.headers.get("Content-Type", "")
    if "json" in content_type:
        try:
            data = response.json()
        except ValueError:
            data = {}
        if isinstance(data, dict):
            if data.get("error_description"):
                return str(data["error_description"])
            if data.get("Error"):
                return str(data["Error"])
        return (
            f"Error from server. Status Code: {response.status_code} "
            f"Data from server: {response.text}"
        )
    # Venafi's VEDSDK contract is JSON. A non-JSON body (e.g. an HTML page from a
    # proxy/gateway or a wrong API URL) is an unexpected intermediary response.
    return (
        f"Unexpected non-JSON response from server (Status Code: {response.status_code}). "
        "Verify the Venafi API URL and any proxy/gateway between SOAR and Venafi."
    )


# --- token state: asset.auth_state is the single source of truth ----------
def _load_token_state(asset: Asset, base_url: str) -> dict[str, Any]:
    """Return the cached token, or {} if absent or issued for a different host."""
    tokens = dict(asset.auth_state.get_all()).get(_TOKEN_STATE_KEY) or {}
    if not isinstance(tokens, dict):
        return {}
    # A cached token is only valid for the host it was issued against.
    if tokens and tokens.get("base_url") != base_url:
        return {}
    return tokens


def _save_token_state(
    asset: Asset, access_token: str, refresh_token: str | None, base_url: str
) -> None:
    state = dict(asset.auth_state.get_all())
    state[_TOKEN_STATE_KEY] = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "base_url": base_url,
    }
    asset.auth_state.put_all(state)


def _clear_token_state(asset: Asset) -> None:
    state = dict(asset.auth_state.get_all())
    state.pop(_TOKEN_STATE_KEY, None)
    asset.auth_state.put_all(state)


class VenafiAuth(httpx.Auth):
    """Inject the Venafi bearer token and refresh it on a 401.

    Venafi uses a password (resource-owner) grant, which the SDK's native OAuth
    client does not support, so token acquisition is implemented here -- but it is
    exposed as a standard httpx.Auth so action call sites use an authenticated
    httpx.Client. Tokens live only in asset.auth_state (no in-process copy).
    """

    # We need to inspect the response status to detect a 401 and refresh.
    requires_response_body = True

    def __init__(self, asset: Asset, base_url: str, scope: str) -> None:
        self._asset = asset
        self._base_url = base_url
        self._scope = scope

    def _store_from(self, response: httpx.Response) -> str:
        if response.status_code != 200:
            raise ActionFailure(error_message(response))
        try:
            data = response.json()
        except ValueError:
            raise ActionFailure(error_message(response)) from None
        access_token = data.get("access_token") if isinstance(data, dict) else None
        if not access_token:
            raise ActionFailure(
                "Venafi token response did not contain a valid access_token"
            )
        _save_token_state(
            self._asset, access_token, data.get("refresh_token"), self._base_url
        )
        return access_token

    def _request_new_token(self) -> str:
        logger.info("Requesting a new Venafi access token")
        body = {
            "username": self._asset.username.strip(),
            "password": self._asset.password.strip(),
            "client_id": self._asset.client_id.strip(),
            "scope": self._scope,
        }
        response = httpx.post(
            f"{self._base_url}{consts.VENAFI_FETCH_TOKEN_URI}",
            json=body,
            timeout=consts.VENAFI_DEFAULT_TIMEOUT,
        )
        return self._store_from(response)

    def _refresh_token(self, refresh_token: str) -> str:
        logger.info("Refreshing the Venafi access token")
        response = httpx.post(
            f"{self._base_url}{consts.VENAFI_FETCH_ACCESS_TOKEN_URI}",
            json={
                "client_id": self._asset.client_id.strip(),
                "refresh_token": refresh_token,
            },
            timeout=consts.VENAFI_DEFAULT_TIMEOUT,
        )
        if response.status_code != 200:
            # Refresh token is invalid: drop it and get a brand-new token.
            logger.info("Refresh token invalid; requesting a new token")
            _clear_token_state(self._asset)
            return self._request_new_token()
        return self._store_from(response)

    def _valid_access_token(self) -> str:
        tokens = _load_token_state(self._asset, self._base_url)
        if tokens.get("access_token"):
            return tokens["access_token"]
        if tokens.get("refresh_token"):
            return self._refresh_token(tokens["refresh_token"])
        return self._request_new_token()

    def force_new(self) -> None:
        """Discard any cached token and fetch a fresh one (used by test connectivity)."""
        _clear_token_state(self._asset)
        self._request_new_token()

    def clear(self) -> None:
        _clear_token_state(self._asset)

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response]:
        request.headers["Authorization"] = f"Bearer {self._valid_access_token()}"
        response = yield request

        if response.status_code == 401:
            logger.info("Access token rejected (401); refreshing and retrying")
            tokens = _load_token_state(self._asset, self._base_url)
            refresh_token = tokens.get("refresh_token")
            new_token = (
                self._refresh_token(refresh_token)
                if refresh_token
                else self._request_new_token()
            )
            request.headers["Authorization"] = f"Bearer {new_token}"
            yield request


class VenafiHelper:
    """Builds authenticated httpx clients for Venafi and runs JSON REST calls."""

    def __init__(self, soar: SOARClient, asset: Asset) -> None:
        self.soar = soar
        self.asset = asset
        self.base_url = asset.base_url.rstrip("/")
        # Configurable OAuth scope (ESPM-5451): blank falls back to the default scope.
        self.scope = (asset.oauth_scope or "").strip() or consts.VENAFI_DEFAULT_SCOPE
        self.auth = VenafiAuth(asset, self.base_url, self.scope)

    def build_client(self, verify: bool = True) -> httpx.Client:
        """Return an authenticated httpx client for Venafi.

        The client injects the bearer token and refreshes on a 401 automatically.
        """
        return httpx.Client(
            base_url=self.base_url,
            auth=self.auth,
            timeout=consts.VENAFI_DEFAULT_TIMEOUT,
            verify=verify,
            # requests (the classic connector) followed redirects by default; httpx
            # does not. Venafi can 307-redirect /vedsdk paths, so match that behavior.
            follow_redirects=True,
        )

    def get_token(self, force_new: bool = False) -> None:
        """Ensure a token exists. force_new discards any cached token first."""
        if force_new:
            self.auth.force_new()

    def clear_tokens(self) -> None:
        self.auth.clear()

    def make_rest_call(
        self,
        endpoint: str,
        method: str = "get",
        params: dict | None = None,
        json_body: dict | None = None,
    ) -> Any:
        """Call a Venafi JSON endpoint and return the parsed body."""
        try:
            with self.build_client() as client:
                response = client.request(
                    method, endpoint, params=params, json=json_body
                )
                response.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise ActionFailure(error_message(e.response)) from None
        except httpx.HTTPError as e:
            raise ActionFailure(f"Error connecting to Venafi: {e}") from None

        if not response.text:
            return {}
        if "json" in response.headers.get("Content-Type", ""):
            return response.json()
        # A non-JSON body on a success code is not valid Venafi data.
        raise ActionFailure(error_message(response))
