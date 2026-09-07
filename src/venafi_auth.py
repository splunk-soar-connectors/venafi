# Copyright (c) 2019-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

from typing import Any

import httpx
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from . import venafi_consts as consts
from .asset import Asset

logger = getLogger()

_TOKEN_STATE_KEY = "venafi_token"  # noqa: S105  # pragma: allowlist secret


class VenafiAuth:
    """Bridge Venafi's token endpoints and the SDK asset authentication state."""

    def __init__(self, asset: Asset) -> None:
        self._asset = asset
        self._base_url = asset.base_url.rstrip("/")
        self._scope = (asset.oauth_scope or "").strip() or consts.VENAFI_DEFAULT_SCOPE

    def _token_state(self) -> dict[str, Any]:
        tokens = self._asset.auth_state.get_all().get(_TOKEN_STATE_KEY) or {}
        if not isinstance(tokens, dict) or tokens.get("base_url") != self._base_url:
            return {}
        return tokens

    def _store_tokens(self, data: dict[str, Any]) -> str:
        access_token = data.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ActionFailure("Venafi token response did not contain an access_token")

        state = dict(self._asset.auth_state.get_all())
        state[_TOKEN_STATE_KEY] = {
            "access_token": access_token,
            "refresh_token": data.get("refresh_token"),
            "base_url": self._base_url,
        }
        self._asset.auth_state.put_all(state)
        return access_token

    def clear_token(self) -> None:
        state = dict(self._asset.auth_state.get_all())
        state.pop(_TOKEN_STATE_KEY, None)
        self._asset.auth_state.put_all(state)

    def _post_token(
        self, endpoint: str, body: dict[str, str], *, verify_ssl: bool
    ) -> dict[str, Any]:
        try:
            with httpx.Client(
                base_url=self._base_url,
                timeout=consts.VENAFI_DEFAULT_TIMEOUT,
                verify=verify_ssl,
                follow_redirects=True,
            ) as client:
                response = client.post(endpoint, json=body)
                response.raise_for_status()
        except httpx.HTTPStatusError as error:
            raise ActionFailure(f"Venafi token request failed: {error}") from None
        except httpx.HTTPError as error:
            raise ActionFailure(f"Unable to request a Venafi token: {error}") from None

        try:
            data = response.json()
        except ValueError:
            raise ActionFailure("Venafi token endpoint returned invalid JSON") from None
        if not isinstance(data, dict):
            raise ActionFailure("Venafi token endpoint returned an invalid response")
        return data

    def _request_new_token(self, *, verify_ssl: bool) -> str:
        logger.info("Requesting a new Venafi access token")
        return self._store_tokens(
            self._post_token(
                consts.VENAFI_FETCH_TOKEN_URI,
                {
                    "username": self._asset.username.strip(),
                    "password": self._asset.password.strip(),
                    "client_id": self._asset.client_id.strip(),
                    "scope": self._scope,
                },
                verify_ssl=verify_ssl,
            )
        )

    def _refresh_access_token(self, refresh_token: str, *, verify_ssl: bool) -> str:
        logger.info("Refreshing the Venafi access token")
        try:
            data = self._post_token(
                consts.VENAFI_FETCH_ACCESS_TOKEN_URI,
                {
                    "client_id": self._asset.client_id.strip(),
                    "refresh_token": refresh_token,
                },
                verify_ssl=verify_ssl,
            )
        except ActionFailure:
            logger.info("Refresh token failed; requesting a new token")
            self.clear_token()
            return self._request_new_token(verify_ssl=verify_ssl)
        return self._store_tokens(data)

    def _access_token(self, *, verify_ssl: bool) -> str:
        tokens = self._token_state()
        access_token = tokens.get("access_token")
        if isinstance(access_token, str) and access_token:
            return access_token

        refresh_token = tokens.get("refresh_token")
        if isinstance(refresh_token, str) and refresh_token:
            return self._refresh_access_token(refresh_token, verify_ssl=verify_ssl)
        return self._request_new_token(verify_ssl=verify_ssl)

    def get_authenticated_client(
        self,
        *,
        verify_ssl: bool = True,
        refresh_token: bool = False,
        force_new_token: bool = False,
    ) -> httpx.Client:
        """Return a client carrying the token held in ``asset.auth_state``."""
        if force_new_token:
            self.clear_token()

        if refresh_token:
            tokens = self._token_state()
            token = tokens.get("refresh_token")
            if isinstance(token, str) and token:
                access_token = self._refresh_access_token(token, verify_ssl=verify_ssl)
            else:
                access_token = self._request_new_token(verify_ssl=verify_ssl)
        else:
            access_token = self._access_token(verify_ssl=verify_ssl)

        return httpx.Client(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=consts.VENAFI_DEFAULT_TIMEOUT,
            verify=verify_ssl,
            follow_redirects=True,
        )


def get_authenticated_client(
    asset: Asset,
    *,
    verify_ssl: bool = True,
    refresh_token: bool = False,
    force_new_token: bool = False,
) -> httpx.Client:
    """Return an authenticated Venafi client backed by the asset token state."""
    return VenafiAuth(asset).get_authenticated_client(
        verify_ssl=verify_ssl,
        refresh_token=refresh_token,
        force_new_token=force_new_token,
    )
