# File: venafi_consts.py
# Copyright (c) 2019-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.


VENAFI_FETCH_TOKEN_URI = '/vedauth/Authorize/Token'
VENAFI_LIST_CERTIFICATES_URI = '/vedsdk/certificates'
VENAFI_RENEW_CERTIFICATE_URI = '/vedsdk/Certificates/Renew'
VENAFI_VERIFY_TOKEN_URI = '/vedauth/Authorize/Verify'
VENAFI_CREATE_CERTIFICATE_URI = '/vedsdk/Certificates/Request'
VENAFI_LIST_POLICIES_URI = '/vedsdk/Config/FindObjectsOfClass'
VENAFI_REVOKE_CERTIFICATE_URI = '/vedsdk/Certificates/Revoke'
VENAFI_GET_CERTIFICATE_URI = '/vedsdk/Certificates/Retrieve'

TEST_CONNECTIVITY_FAILED = "Test Connectivity Failed."
TEST_CONNECTIVITY_SUCCESS = 'Test Connectivity Passed'