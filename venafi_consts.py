# File: venafi_consts.py
#
# Copyright (c) 2019-2022 Splunk Inc.
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
VENAFI_FETCH_TOKEN_URI = '/vedauth/Authorize/Token'
VENAFI_LIST_CERTIFICATES_URI = '/vedsdk/certificates'
VENAFI_RENEW_CERTIFICATE_URI = '/vedsdk/Certificates/Renew'
VENAFI_VERIFY_TOKEN_URI = '/vedauth/Authorize/Verify'
VENAFI_CREATE_CERTIFICATE_URI = '/vedsdk/Certificates/Request'
VENAFI_LIST_POLICIES_URI = '/vedsdk/Config/FindObjectsOfClass'
VENAFI_REVOKE_CERTIFICATE_URI = '/vedsdk/Certificates/Revoke'
VENAFI_GET_CERTIFICATE_URI = '/vedsdk/Certificates/Retrieve'
VENAFI_DEFAULT_TIMEOUT = 30

TEST_CONNECTIVITY_FAILED = "Test Connectivity Failed."
TEST_CONNECTIVITY_SUCCESS = 'Test Connectivity Passed'
