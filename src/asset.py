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

from soar_sdk.asset import AssetField, BaseAsset, FieldCategory


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
