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

from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from . import venafi_consts as consts
from .asset import Asset
from .client import VenafiHelper

logger = getLogger()


def run_test_connectivity(soar: SOARClient, asset: Asset) -> None:
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
