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

from soar_sdk.app import App

from .create_certificate import CreateCertificateSummary, create_certificate
from .get_certificate import get_certificate
from .list_certificates import ListCertificatesSummary, list_certificates
from .list_policies import ListPoliciesSummary, list_policies
from .make_request import http_action
from .renew_certificate import RenewCertificateSummary, renew_certificate
from .revoke_certificate import RevokeCertificateSummary, revoke_certificate


def register_actions(app: App) -> App:
    """Register all Venafi actions on the provided app."""
    app.make_request()(http_action)
    app.register_action(
        action=list_certificates,
        description="Returns a list of certificates in Venafi",
        action_type="investigate",
        verbose="Returns certificate details and the total number of certificates that match specified search filters.",
        summary_type=ListCertificatesSummary,
        render_as="table",
    )
    app.register_action(
        action=list_policies,
        description="Returns a list of all policies in Venafi",
        action_type="investigate",
        summary_type=ListPoliciesSummary,
        render_as="table",
    )
    app.register_action(
        action=get_certificate,
        description="Downloads specified certificate to the vault",
        action_type="investigate",
        render_as="table",
    )
    app.register_action(
        action=create_certificate,
        description="Enrolls a certificate in Venafi",
        action_type="generic",
        read_only=False,
        verbose="Either Subject or ObjectName parameter must be filled out.",
        summary_type=CreateCertificateSummary,
        render_as="table",
    )
    app.register_action(
        action=renew_certificate,
        description="Requests immediate renewal for an existing certificate in Venafi",
        action_type="generic",
        read_only=False,
        verbose="A renewable certificate cannot be currently processing, in error, or contain a 'Monitoring' Management Type.",
        summary_type=RenewCertificateSummary,
        render_as="table",
    )
    app.register_action(
        action=revoke_certificate,
        description="Requests to revoke an existing certificate in Venafi",
        action_type="correct",
        read_only=False,
        verbose="The caller must have write permissions to the certificate object and either the CertificateDN or the Thumbprint parameter must be provided.",
        summary_type=RevokeCertificateSummary,
        render_as="table",
    )
    return app
