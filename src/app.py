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

from typing import Any

import requests
from bs4 import BeautifulSoup
from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from . import venafi_consts as consts

logger = getLogger()

# Key under which the Venafi token bundle is cached in the asset auth state.
_TOKEN_STATE_KEY = "venafi_token"  # noqa: S105  # pragma: allowlist secret


def _parse_error_response(resp: requests.Response) -> str:
    """Build a human-readable error message from a Venafi error response."""
    content_type = resp.headers.get("Content-Type", "")

    if "json" in content_type:
        try:
            resp_json = resp.json()
        except ValueError:
            resp_json = {}
        if "error_description" in resp_json:
            return str(resp_json["error_description"])
        if "Error" in resp_json:
            return str(resp_json["Error"])
        return f"Error from server. Status Code: {resp.status_code} Data from server: {resp.text}"

    if "html" in content_type:
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = "\n".join(
                line.strip() for line in soup.text.split("\n") if line.strip()
            )
            if "404" in error_text:
                error_text = consts.VENAFI_INVALID_API_URL
        except Exception:
            error_text = "Cannot parse error details"
        return f"Status Code: {resp.status_code}. Data from server:\n{error_text}"

    return f"Error from server. Status Code: {resp.status_code} Data from server: {resp.text}"


class Asset(BaseAsset):
    base_url: str = AssetField(
        description="Venafi API URL", category=FieldCategory.CONNECTIVITY
    )
    username: str = AssetField(
        description="Venafi API Username to authenticate with",
        category=FieldCategory.CONNECTIVITY,
    )
    password: str = AssetField(
        description="Venafi API Password to authenticate with",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    client_id: str = AssetField(
        description="API Application Integration application ID",
        category=FieldCategory.CONNECTIVITY,
    )
    oauth_scope: str = AssetField(
        required=False,
        description="OAuth scope for token requests. Run Test Connectivity after changing this value on an existing asset to refresh cached tokens.",
        default="certificate:discover,delete,manage,revoke;configuration",
        category=FieldCategory.CONNECTIVITY,
    )


class VenafiHelper:
    """Wraps Venafi TPP authentication (with configurable OAuth scope) and REST calls."""

    def __init__(self, soar: SOARClient, asset: Asset) -> None:
        self.soar = soar
        self.asset = asset
        self.base_url = asset.base_url.rstrip("/")
        # Configurable OAuth scope (ESPM-5451): blank falls back to the default scope.
        self.scope = (asset.oauth_scope or "").strip() or consts.VENAFI_DEFAULT_SCOPE

        tokens = self._load_tokens()
        self._access_token: str | None = tokens.get("access_token")
        self._refresh_token: str | None = tokens.get("refresh_token")

    # --- token persistence -------------------------------------------------
    def _load_tokens(self) -> dict[str, Any]:
        tokens = dict(self.asset.auth_state.get_all()).get(_TOKEN_STATE_KEY)
        if tokens:
            return tokens
        # Migrate tokens saved by the classic (non-SDK) connector, which stored the
        # token bundle at the top level of the state file under "access_token".
        legacy = self._load_legacy_tokens()
        if legacy:
            state = dict(self.asset.auth_state.get_all())
            state[_TOKEN_STATE_KEY] = legacy
            self.asset.auth_state.put_all(state)
            return legacy
        return {}

    def _load_legacy_tokens(self) -> dict[str, Any]:
        """Best-effort read of tokens saved by the classic connector layout."""
        try:
            raw = self.asset.auth_state.backend.load_state() or {}
        except Exception:
            return {}
        legacy = raw.get("access_token")
        if isinstance(legacy, dict) and legacy.get("access_token"):
            return {
                "access_token": legacy.get("access_token"),
                "refresh_token": legacy.get("refresh_token"),
            }
        return {}

    def _save_tokens(self) -> None:
        state = dict(self.asset.auth_state.get_all())
        state[_TOKEN_STATE_KEY] = {
            "access_token": self._access_token,
            "refresh_token": self._refresh_token,
        }
        self.asset.auth_state.put_all(state)

    def clear_tokens(self) -> None:
        state = dict(self.asset.auth_state.get_all())
        state.pop(_TOKEN_STATE_KEY, None)
        self.asset.auth_state.put_all(state)
        self._access_token = None
        self._refresh_token = None

    # --- authentication ----------------------------------------------------
    def _request_new_token(self) -> None:
        logger.info("Requesting a new Venafi access token")
        url = f"{self.base_url}{consts.VENAFI_FETCH_TOKEN_URI}"
        body = {
            "username": self.asset.username,
            "password": self.asset.password,
            "client_id": self.asset.client_id,
            "scope": self.scope,
        }
        resp = requests.post(
            url,
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=consts.VENAFI_DEFAULT_TIMEOUT,
        )
        if resp.status_code != 200:
            raise ActionFailure(_parse_error_response(resp))
        data = resp.json()
        self._access_token = data.get("access_token")
        self._refresh_token = data.get("refresh_token")
        self._save_tokens()

    def _refresh_access_token(self) -> None:
        logger.info("Refreshing the Venafi access token")
        url = f"{self.base_url}{consts.VENAFI_FETCH_ACCESS_TOKEN_URI}"
        body = {"client_id": self.asset.client_id, "refresh_token": self._refresh_token}
        resp = requests.post(
            url,
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=consts.VENAFI_DEFAULT_TIMEOUT,
        )
        if resp.status_code != 200:
            # Refresh token is invalid: drop it and get a brand-new token.
            logger.info("Refresh token invalid; requesting a new token")
            self.clear_tokens()
            self._request_new_token()
            return
        data = resp.json()
        self._access_token = data.get("access_token")
        self._refresh_token = data.get("refresh_token")
        self._save_tokens()

    def get_token(self, force_new: bool = False) -> None:
        """Ensure a usable access token, obtaining or refreshing one as needed."""
        if force_new:
            self.clear_tokens()
            self._request_new_token()
            return
        if self._access_token:
            return
        if self._refresh_token:
            self._refresh_access_token()
            return
        self._request_new_token()

    def auth_headers(self) -> dict[str, str]:
        """Return authorization headers for a raw request, ensuring a valid token."""
        self.get_token()
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._access_token}",
        }

    def refresh(self) -> None:
        """Force a token refresh, used to retry a raw request after a 401."""
        self._refresh_access_token()

    # --- REST --------------------------------------------------------------
    def _request(
        self,
        endpoint: str,
        method: str,
        params: dict | None,
        json_body: dict | None,
    ) -> requests.Response:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._access_token}",
        }
        url = f"{self.base_url}{endpoint}"
        return requests.request(
            method,
            url,
            headers=headers,
            params=params,
            json=json_body,
            timeout=consts.VENAFI_DEFAULT_TIMEOUT,
        )

    def make_rest_call(
        self,
        endpoint: str,
        method: str = "get",
        params: dict | None = None,
        json_body: dict | None = None,
    ) -> Any:
        """Call a Venafi endpoint, transparently refreshing the token on a 401."""
        self.get_token()
        resp = self._request(endpoint, method, params, json_body)

        if resp.status_code == 401:
            logger.info("Access token rejected (401); refreshing and retrying")
            self._refresh_access_token()
            resp = self._request(endpoint, method, params, json_body)

        if not 200 <= resp.status_code < 399:
            raise ActionFailure(_parse_error_response(resp))

        if not resp.text:
            return {}
        if "json" in resp.headers.get("Content-Type", ""):
            return resp.json()
        # A non-JSON body on a success code (e.g. an HTML proxy/login/error page
        # returned with HTTP 200) is not valid data -- treat it as a failure.
        raise ActionFailure(_parse_error_response(resp))

    def download_certificate(self, endpoint: str, params: dict) -> tuple[str, bytes]:
        """Stream a certificate download, returning (file_name, content bytes)."""
        self.get_token()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._access_token}",
        }
        url = f"{self.base_url}{endpoint}"

        resp = requests.get(
            url,
            headers=headers,
            params=params,
            stream=True,
            timeout=consts.VENAFI_DEFAULT_TIMEOUT,
        )
        if resp.status_code == 401:
            self._refresh_access_token()
            headers["Authorization"] = f"Bearer {self._access_token}"
            resp = requests.get(
                url,
                headers=headers,
                params=params,
                stream=True,
                timeout=consts.VENAFI_DEFAULT_TIMEOUT,
            )

        try:
            if not 200 <= resp.status_code < 300:
                raise ActionFailure(
                    f"Certificate download failed. Status Code: {resp.status_code}"
                )

            content_disposition = resp.headers.get("Content-Disposition", "")
            file_name = (
                content_disposition.split('"')[1]
                if '"' in content_disposition
                else "certificate"
            )

            content = bytearray()
            for chunk in resp.iter_content(
                chunk_size=consts.VENAFI_DOWNLOAD_CHUNK_SIZE
            ):
                if chunk:
                    content.extend(chunk)

            if not content:
                raise ActionFailure("Certificate download is empty")

            return file_name, bytes(content)
        finally:
            resp.close()


app = App(
    name="Venafi",
    app_type="identity management",
    logo="logo_venafi.svg",
    logo_dark="logo_venafi_dark.svg",
    product_vendor="Venafi",
    product_name="Venafi",
    publisher="Splunk",
    appid="9e412afa-771a-4acf-a33b-fdc05c205692",
    fips_compliant=True,
    encrypt_cache_state=True,
    encrypt_ingest_state=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    logger.info("Connecting to endpoint")
    helper = VenafiHelper(soar, asset)
    try:
        # Force a fresh token so the configured scope is exercised, then verify it.
        helper.get_token(force_new=True)
        helper.make_rest_call(consts.VENAFI_VERIFY_TOKEN_URI, method="get")
    except ActionFailure:
        helper.clear_tokens()
        logger.info(consts.TEST_CONNECTIVITY_FAILED)
        raise

    soar.set_message(consts.TEST_CONNECTIVITY_SUCCESS)
    logger.info(consts.TEST_CONNECTIVITY_SUCCESS)


if __name__ == "__main__":
    app.cli()
