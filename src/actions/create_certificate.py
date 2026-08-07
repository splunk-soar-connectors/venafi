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

import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset, VenafiHelper, app
from ..venafi_consts import VENAFI_CREATE_CERTIFICATE_URI


class CreateCertificateParams(Params):
    policy_dn: str = Param(
        description="The folder DN for the new certificate",
        primary=True,
        cef_types=["venafi policy dn"],
    )
    subject: str | None = Param(
        description="The Common Name (CN) field for the certificate. Either the subject or object_name parameter must be filled in"
    )
    object_name: str | None = Param(
        description="The Common Name (CN) field for the certificate. Either the subject or object_name parameter must be filled in"
    )
    approvers: str | None = Param(
        description="An array of one or more identities for certificate workflow approvers"
    )
    cadn: str | None = Param(
        description="The Distinguished Name (DN) of the Trust Protection Platform Certificate Authority Template object"
    )
    ca_specific_attributes: str | None = Param(
        description="An array of name/value pairs providing any CA attributes to be stored with the Certificate object and submitted to the CA during enrollment"
    )
    city: str | None = Param(description="Locality/City attribute of Certificate")
    contacts: str | None = Param(
        description="An array of one or more identities for users or groups who receive notifications about events pertaining to the object"
    )
    country: str | None = Param(
        description="The Country field for the certificate Subject DN"
    )
    created_by: str | None = Param(
        description="The setting to identify the object that initiated enrollment or provisioning changes"
    )
    devices: str | None = Param(
        description="An array of devices that require enrollment or provisioning"
    )
    disable_automatic_renewal: bool | None = Param(
        description="The setting to control whether manual intervention is required for certificate renewal",
        default=False,
    )
    elliptical_curve: str | None = Param(
        description="P256, P384, or P521 encryption for Elliptical Curve Cryptography",
        value_list=["P256", "P384", "P521"],
    )
    key_algorithm: str | None = Param(
        description="Algorithm for public key of Certificate", value_list=["RSA", "ECC"]
    )
    key_bit_size: float | None = Param(
        description="The number of bits to allow for key generation"
    )
    management_type: str | None = Param(
        description="The level of management that Trust Protection Platform applies to the certificate",
        value_list=["Enrollment", "Provisioning", "Monitoring", "Unassigned"],
    )
    organization: str | None = Param(
        description="Organization attribute of the certificate"
    )
    organizational_unit: str | None = Param(
        description="Organizational unit attribute of the certificate"
    )
    pkcs10: str | None = Param(
        description="The PKCS10 formatted CSR for the certificate"
    )
    reenable: bool | None = Param(
        description="Option to renew a previously disabled certificate", default=False
    )
    set_work_to_do: bool | None = Param(
        description="Option to control certificate processing", default=False
    )
    state: str | None = Param(description="State/Province attribute of Certificate")
    subject_alt_names: str | None = Param(
        description="Skip parameter if the policy already specifies SAN Types. Array of subject alternative names (SANS) for the certificate. For each SAN, specify an array element with a Type and a corresponding Name. For example, SubjectAltNames:[ {Type:2, Name:www.example.com}, {Type:7, Name:122.122.122.122} ]. The Type parameter is an integer that represents the kind of SAN which can be 0:OtherName, 1: Email, 2:DNS, 6: URI, or 7:IPAddress. The Name value is the SAN Friendly name that corresponds to the Type parameter"
    )


class CreateCertificateOutput(ActionOutput):
    CertificateDN: str | None = OutputField(
        cef_types=["venafi certificate dn"],
        example_values=["\\VED\\Policy\\Certificates\\test\\test.com"],
    )
    Guid: str | None = OutputField(
        example_values=["TEST6419-8615-40ce-b556-63EXAMPLEe833b"]
    )


def _parse_json_array(raw: str | None, field_name: str) -> list:
    """Parse an optional JSON-array action parameter, defaulting to an empty list."""
    if not raw:
        return []
    try:
        return json.loads(raw)
    except (ValueError, TypeError) as e:
        raise ActionFailure(
            f"Error occurred while parsing the {field_name} parameter. Error: {e}"
        ) from None


@app.action(
    description="Enrolls a certificate in Venafi",
    action_type="generic",
    read_only=False,
    verbose="Either Subject or ObjectName parameter must be filled out.",
)
def create_certificate(
    params: CreateCertificateParams, soar: SOARClient, asset: Asset
) -> CreateCertificateOutput:
    helper = VenafiHelper(soar, asset)

    data = {
        "Approvers": _parse_json_array(params.approvers, "approvers"),
        "CADN": params.cadn,
        "CASpecificAttributes": _parse_json_array(
            params.ca_specific_attributes, "ca specific attributes"
        ),
        "City": params.city,
        "Contacts": _parse_json_array(params.contacts, "contacts"),
        "Country": params.country,
        "CreatedBy": params.created_by,
        "Devices": _parse_json_array(params.devices, "devices"),
        "DisableAutomaticRenewal": params.disable_automatic_renewal or False,
        "EllipticalCurve": params.elliptical_curve,
        "KeyAlgorithm": params.key_algorithm,
        "KeyBitSize": int(params.key_bit_size)
        if params.key_bit_size is not None
        else None,
        "ManagementType": params.management_type,
        "PolicyDN": params.policy_dn,
        "Subject": params.subject,
        "SubjectAltNames": _parse_json_array(
            params.subject_alt_names, "subject alt names"
        ),
        "ObjectName": params.object_name,
        "Organization": params.organization,
        "OrganizationalUnit": params.organizational_unit,
        "PKCS10": params.pkcs10,
        "Reenable": params.reenable or False,
        "SetWorkToDo": params.set_work_to_do or False,
        "State": params.state,
    }

    response = helper.make_rest_call(
        VENAFI_CREATE_CERTIFICATE_URI, method="post", json_body=data
    )

    if (
        not isinstance(response, dict)
        or response.get("Error")
        or not response.get("CertificateDN")
    ):
        error = (
            response.get("Error", "The server did not return a certificate DN")
            if isinstance(response, dict)
            else "Invalid response"
        )
        raise ActionFailure(f"Failed to create certificate. Server response: {error}")

    soar.set_message("Successfully created certificate")
    return CreateCertificateOutput(
        CertificateDN=response.get("CertificateDN"), Guid=response.get("Guid")
    )
