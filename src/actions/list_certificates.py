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
from soar_sdk.params import Param, Params

from ..app import Asset, VenafiHelper, app
from ..venafi_consts import (
    VENAFI_LIST_CERTIFICATES_PARAMS,
    VENAFI_LIST_CERTIFICATES_URI,
)


class ListCertificatesParams(Params):
    limit: float | None = Param(
        description="Maximum number of certificates to return. Possible values are 1-100"
    )
    offset: float | None = Param(
        description="Number of results to skip (offset=5 begins results at page five)"
    )
    country: str | None = Param(description="Country attribute of Certificate")
    common_name: str | None = Param(
        description="Common name attribute of Certificate",
        primary=True,
        cef_types=["domain", "url"],
    )
    key_algorithm: str | None = Param(
        description="Algorithm for public key of Certificate"
    )
    key_size: float | None = Param(description="Public key size of Certificate")
    key_size_greater: float | None = Param(
        description="Find certificates with a key size greater than the specified value"
    )
    key_size_less: float | None = Param(
        description="Find certificates with a key size less than the specified value"
    )
    city: str | None = Param(description="Locality/City attribute of Certificate")
    organization: str | None = Param(
        description="Organization attribute of Certificate"
    )
    organization_unit: str | None = Param(
        description="Organization unit attribute of Certificate"
    )
    state: str | None = Param(description="State/Province attribute of Certificate")
    san_dns: str | None = Param(
        description="Subject Alternative Name (SAN) Distinguished Name Server (DNS) attribute of Certificate",
        primary=True,
        cef_types=["domain", "url"],
    )
    san_email: str | None = Param(
        description="Subject Alternative Name (SAN) Email RFC822 attribute of Certificate",
        primary=True,
        cef_types=["email"],
    )
    san_ip: str | None = Param(
        description="Subject Alternative Name (SAN) IP Address attribute of Certificate",
        primary=True,
        cef_types=["ip"],
    )
    san_upn: str | None = Param(
        description="Subject Alternative Name (SAN) User Principle Name (UPN) attribute of Certificate",
        primary=True,
        cef_types=["email"],
    )
    san_uri: str | None = Param(
        description="Subject Alternative Name (SAN) Uniform Resource Identifier (URI) attribute of Certificate",
        primary=True,
        cef_types=["url"],
    )
    serial: str | None = Param(description="Serial number attribute of Certificate")
    signature_algorithm: str | None = Param(
        description="Algorithm used to sign the Certificate"
    )
    thumbprint: str | None = Param(
        description="SHA-1 thumbprint of the Certificate",
        primary=True,
        cef_types=["sha1"],
    )
    valid_from: str | None = Param(
        description="YYYY-MM-DD or ISO 8601 format YYYY-MM-DDTHH:MM:SS.mmmmmmmZ (Find certificates by the date of issue)"
    )
    valid_to: str | None = Param(
        description="YYYY-MM-DD or ISO 8601 format YYYY-MM-DDTHH:MM:SS.mmmmmmmZ (Find certificates by expiration date)"
    )
    valid_to_greater: str | None = Param(
        description="YYYY-MM-DD or ISO 8601 format YYYY-MM-DDTHH:MM:SS.mmmmmmmZ (Find certificates that expire after a certain date)"
    )
    valid_to_less: str | None = Param(
        description="YYYY-MM-DD or ISO 8601 format YYYY-MM-DDTHH:MM:SS.mmmmmmmZ (Find certificates that expire before a certain date)"
    )


class SansOutput(ActionOutput):
    DNS: list[str] | None = OutputField(example_values=["CSR1"])
    Email: list[str] | None = OutputField(
        cef_types=["email"], example_values=["test@123.com"]
    )


class X509Output(ActionOutput):
    CN: str | None = OutputField(example_values=["example.venafi.com"])
    SANS: SansOutput | None = None
    Serial: str | None = OutputField(example_values=["TEST5338000100009FA9"])
    Thumbprint: str | None = OutputField(
        cef_types=["sha1"], example_values=["TEST15E5C9664FF67587A24BFA0CC87BA8C66B87"]
    )
    ValidFrom: str | None = OutputField(example_values=["2019-03-28T22:39:49.0000000Z"])
    ValidTo: str | None = OutputField(example_values=["2020-03-27T22:39:49.0000000Z"])


class LinksOutput(ActionOutput):
    Details: str | None = OutputField(
        example_values=[
            "/vedsdk/certificates/%TEST5827f9-938f-42fe-a1a6-475afdc51448%7d"
        ]
    )


class ListCertificatesOutput(PermissiveActionOutput):
    CreatedOn: str | None = OutputField(example_values=["2018-10-26T15:30:01.6903192Z"])
    DN: str | None = OutputField(
        cef_types=["venafi certificate dn"],
        example_values=[
            "\\VED\\Policy\\Certificates\\test\\Venafi Generated\\example.venafi.com"
        ],
    )
    Guid: str | None = OutputField(
        example_values=["{TEST27f9-938f-42fe-a1a6-475afdc5TEST}"]
    )
    Name: str | None = OutputField(example_values=["example.test.com"])
    ParentDn: str | None = OutputField(
        example_values=["\\VED\\Policy\\Certificates\\test\\Venafi Generated"]
    )
    SchemaClass: str | None = OutputField(example_values=["X509 Server Certificate"])
    X509: X509Output | None = None
    links: list[LinksOutput] | None = None


@app.action(
    description="Returns a list of certificates in Venafi",
    action_type="investigate",
    verbose="Returns certificate details and the total number of certificates that match specified search filters.",
)
def list_certificates(
    params: ListCertificatesParams, soar: SOARClient, asset: Asset
) -> list[ListCertificatesOutput]:
    helper = VenafiHelper(soar, asset)

    query: dict = {}
    for pkey, vkey in VENAFI_LIST_CERTIFICATES_PARAMS.items():
        value = getattr(params, pkey, None)
        if value is not None and value != "":
            # Send whole-number floats (e.g. key sizes) as ints so Venafi filters match.
            if isinstance(value, float) and value.is_integer():
                value = int(value)
            query[vkey] = value

    if params.limit is not None:
        if params.limit < 0:
            raise ActionFailure("'limit' must be a non-negative integer")
        query["limit"] = int(params.limit)
    if params.offset is not None:
        if params.offset < 0:
            raise ActionFailure("'offset' must be a non-negative integer")
        query["offset"] = int(params.offset)

    response = helper.make_rest_call(
        VENAFI_LIST_CERTIFICATES_URI, method="get", params=query
    )

    certificates = (
        response.get("Certificates", []) if isinstance(response, dict) else []
    )
    soar.set_message(f"Successfully retrieved {len(certificates)} certificates")
    return [ListCertificatesOutput(**cert) for cert in certificates]
