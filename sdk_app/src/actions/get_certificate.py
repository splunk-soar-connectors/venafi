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
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..app import Asset, VenafiHelper, app
from ..venafi_consts import VENAFI_GET_CERTIFICATE_PARAMS, VENAFI_GET_CERTIFICATE_URI


class GetCertificateParams(Params):
    certificate_dn: str = Param(
        description="The Distinguished Name (DN) of the certificate to download",
        primary=True,
        cef_types=["venafi certificate dn"],
    )
    format: str | None = Param(
        description="The certificate format for the return data",
        default="Base64",
        value_list=["Base64", "Base64 (PKCS #8)", "DER", "JKS", "PKCS#7", "PKCS#12"],
    )
    friendly_name: str | None = Param(
        description="The label or alias to use for Base64, JKS, or PKCS #12 formats. Required for the JKS format"
    )
    include_chain: bool | None = Param(
        description="When the Format is Base64, PKCS #7, PKCS #12, or JKS, you can include the parent or root chain in the return data"
    )
    include_private_key: bool | None = Param(
        description="When the Format is Base64, PKCS #12, or JKS, you can specify whether to return the private key"
    )
    keystore_password: str | None = Param(
        description="If the Format is JKS, you must set a keystore password. Use the same requirements as required for the Password parameter",
        sensitive=True,
    )
    password: str | None = Param(
        description="If the IncludePrivateKey value is true, you must create a password. Password must be 12 characters and comprised of at least 3 of the following: uppercase alphabetic letters, lowercase alphabetic letters, numeric characters, special characters",
        sensitive=True,
    )
    root_first_order: bool | None = Param(
        description="The order of the certificate chain to trust"
    )


class GetCertificateOutput(ActionOutput):
    name: str | None = OutputField(example_values=["pge.com.cer"])
    size: float | None = OutputField(example_values=[2074])
    vault_id: str | None = OutputField(
        cef_types=["sha1", "vault id"],
        example_values=["TEST86f38c9e7c50c1998c0ce0974faab4c9TEST"],
    )


@app.action(
    description="Downloads specified certificate to the vault",
    action_type="investigate",
)
def get_certificate(
    params: GetCertificateParams, soar: SOARClient, asset: Asset
) -> GetCertificateOutput:
    helper = VenafiHelper(soar, asset)

    query: dict = {}
    for pkey, vkey in VENAFI_GET_CERTIFICATE_PARAMS.items():
        value = getattr(params, pkey, None)
        if value is not None and value != "":
            query[vkey] = value
    query["Format"] = params.format or "Base64"
    query["IncludeChain"] = params.include_chain or False
    query["IncludePrivateKey"] = params.include_private_key or False
    query["RootFirstOrder"] = params.root_first_order or False

    file_name, content = helper.download_certificate(VENAFI_GET_CERTIFICATE_URI, query)

    container_id = soar.get_executing_container_id()
    vault_id = soar.vault.create_attachment(container_id, content, file_name)

    soar.set_message("Successfully retrieved certificate and added to the vault")
    return GetCertificateOutput(name=file_name, size=len(content), vault_id=vault_id)
