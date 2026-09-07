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
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from . import venafi_consts as consts
from .asset import Asset
from .venafi_auth import get_authenticated_client

logger = getLogger()


def run_test_connectivity(soar: SOARClient, asset: Asset) -> None:
    logger.info("Connecting to endpoint")
    try:
        # Force a fresh token so the configured scope is exercised, then verify it.
        with get_authenticated_client(asset, force_new_token=True) as client:
            response = client.get(consts.VENAFI_VERIFY_TOKEN_URI)
            response.raise_for_status()
        try:
            response.json()
        except ValueError:
            raise ActionFailure(
                "Venafi token verification returned invalid JSON"
            ) from None
    except httpx.HTTPStatusError as error:
        logger.info(consts.TEST_CONNECTIVITY_FAILED)
        raise ActionFailure(f"Venafi token verification failed: {error}") from None
    except httpx.HTTPError as error:
        logger.info(consts.TEST_CONNECTIVITY_FAILED)
        raise ActionFailure(f"Unable to verify Venafi token: {error}") from None
    except ActionFailure:
        logger.info(consts.TEST_CONNECTIVITY_FAILED)
        raise

    soar.set_message(consts.TEST_CONNECTIVITY_SUCCESS)
    logger.info(consts.TEST_CONNECTIVITY_SUCCESS)
