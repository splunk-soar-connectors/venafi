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

import contextlib
import os
import tempfile
from pathlib import Path

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..venafi_auth import error_message, get_authenticated_client
from ..venafi_consts import (
    VENAFI_GET_CERTIFICATE_PARAMS,
    VENAFI_GET_CERTIFICATE_URI,
)


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
    name: str | None = OutputField(
        column_name="Certificate", example_values=["pge.com.cer"]
    )
    vault_id: str | None = OutputField(
        cef_types=["sha1", "vault id"],
        column_name="Vault ID",
        example_values=["TEST86f38c9e7c50c1998c0ce0974faab4c9TEST"],
    )
    size: float | None = OutputField(column_name="File Size", example_values=[2074])


_CHUNK_SIZE = 65536


def _file_name_from_headers(response: httpx.Response) -> str:
    disposition = response.headers.get("Content-Disposition", "")
    return disposition.split('"')[1] if '"' in disposition else "certificate"


def _download_certificate_to_file(
    asset: Asset, query: dict, dest_path: str
) -> tuple[str, int]:
    for attempt, refresh in enumerate((False, True)):
        try:
            with (
                get_authenticated_client(asset, refresh_token=refresh) as client,
                client.stream(
                    "GET", VENAFI_GET_CERTIFICATE_URI, params=query
                ) as response,
            ):
                if response.status_code == 401 and attempt == 0:
                    continue
                if response.is_error:
                    response.read()
                    raise ActionFailure(
                        f"Failed to download certificate: {error_message(response)}"
                    )
                file_name = _file_name_from_headers(response)
                size = 0
                with open(dest_path, "wb") as handle:
                    for chunk in response.iter_bytes(chunk_size=_CHUNK_SIZE):
                        handle.write(chunk)
                        size += len(chunk)
                if size == 0:
                    raise ActionFailure(
                        f"Certificate download is empty (status {response.status_code})"
                    )
                return file_name, size
        except httpx.HTTPError as error:
            raise ActionFailure(f"Failed to download certificate: {error}") from None
        except OSError as error:
            raise ActionFailure(
                f"Failed to write certificate to disk: {error}"
            ) from None
    raise ActionFailure("Failed to download certificate: authentication failed (401)")


def get_certificate(
    params: GetCertificateParams, soar: SOARClient, asset: Asset
) -> GetCertificateOutput:
    query: dict = {}
    for pkey, vkey in VENAFI_GET_CERTIFICATE_PARAMS.items():
        value = getattr(params, pkey, None)
        if value is not None and value != "":
            query[vkey] = value
    query["Format"] = params.format or "Base64"
    query["IncludeChain"] = params.include_chain or False
    query["IncludePrivateKey"] = params.include_private_key or False
    query["RootFirstOrder"] = params.root_first_order or False

    params.keystore_password = None
    params.password = None

    tmp_dir = soar.vault.get_vault_tmp_dir()
    fd, tmp_path = tempfile.mkstemp(dir=tmp_dir)
    os.close(fd)
    try:
        file_name, size = _download_certificate_to_file(asset, query, tmp_path)
        try:
            container_id = soar.get_executing_container_id()
            vault_id = soar.vault.add_attachment(container_id, tmp_path, file_name)
        except Exception as e:
            raise ActionFailure(
                f"Failed to store certificate in the vault: {type(e).__name__}: {e}"
            ) from e
        if not vault_id:
            raise ActionFailure(
                "Vault did not return an attachment id for the certificate"
            )
    finally:
        with contextlib.suppress(OSError):
            Path(tmp_path).unlink()

    soar.set_message("Successfully retrieved certificate and added to the vault")
    return GetCertificateOutput(name=file_name, size=size, vault_id=vault_id)
