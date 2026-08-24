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
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Params

from ..asset import Asset
from ..client import VenafiHelper
from ..venafi_consts import VENAFI_LIST_POLICIES_URI


class ListPoliciesSummary(ActionOutput):
    num_policies: int | None = None


class ListPoliciesOutput(PermissiveActionOutput):
    # Name/DN are declared first (in this order) so the table columns render as
    # Policy (0) then Policy Dn (1), matching the classic app.
    Name: str | None = OutputField(column_name="Policy", example_values=["Test"])
    DN: str | None = OutputField(
        cef_types=["venafi policy dn"],
        column_name="Policy Dn",
        example_values=["\\VED\\Policy\\Certificates\\test"],
    )
    AbsoluteGUID: str | None = OutputField(
        example_values=[
            "{TESTe447-74f4-4c8a-8972-62aff3b2fee3}{EXAMPLE63f4-0bfc-468a-b41f-d8fa477bd1c0}{EXAMPLEaa0-1de7-4be4-bfe8-fbcb7e948502}{TESTbb4b-1cde-4d48-9684-a04effa3be7f}"
        ]
    )
    GUID: str | None = OutputField(
        example_values=["{TESTbb4b-1cde-4d48-9684-a04effa3be7f}"]
    )
    Id: int | None = OutputField(example_values=[2139])
    Parent: str | None = OutputField(example_values=["\\VED\\Policy\\Certificates"])
    Revision: int | None = OutputField(example_values=[636747885144784172])
    TypeName: str | None = OutputField(example_values=["Policy"])


def list_policies(
    params: Params, soar: SOARClient, asset: Asset
) -> list[ListPoliciesOutput]:
    helper = VenafiHelper(soar, asset)
    data = {"Class": "Policy", "ObjectDN": "\\VED\\Policy", "Recursive": 1}
    response = helper.make_rest_call(
        VENAFI_LIST_POLICIES_URI, method="post", json_body=data
    )

    if not isinstance(response, dict) or not isinstance(response.get("Objects"), list):
        raise ActionFailure("Unexpected response from Venafi: missing 'Objects' list")
    objects = response["Objects"]
    soar.set_summary(ListPoliciesSummary(num_policies=len(objects)))
    soar.set_message(f"Successfully retrieved {len(objects)} policies")
    return [ListPoliciesOutput(**policy) for policy in objects]
