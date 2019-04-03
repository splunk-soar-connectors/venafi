# --
# File: venafi_connector.py
#
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault as Vault

# Usage of the consts file is recommended
# from venafi_consts import *
import uuid
import os
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class VenafiConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(VenafiConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _authorize(self, action_result):
        uri = '/Authorize'
        headers = {'Content-Type': 'application/json'}
        body = {'Username': self._username, 'Password': self._password}
        ret_val, response = self._make_rest_call(uri, action_result, data=body, headers=headers, method='post')
        APIKey = response['APIKey']

        if phantom.is_fail(ret_val):
            return action_result.get_status()
        self.save_progress('Successfully generated API Key')
        headers = {'Content-Type': 'application/json', 'X-Venafi-Api-Key': APIKey}
        return headers

    def _process_empty_reponse(self, response, action_result):

        self.save_progress("{}".format(response.status_code))
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, u"Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = u'\n'.join(split_lines)
        except:
            error_text = u"Cannot parse error details"

        message = u"Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace(u'{', u'{{').replace(u'}', u'}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, u"Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        if 'ErrorDetails' in resp_json:
            message = resp_json['ErrorDetails']
        elif 'Error' in resp_json:
            message = resp_json['Error']
        # You should process the error returned in the json
        else:
            message = u"Error from server. Status Code: {0} Data from server: {1}".format(
                    r.status_code, r.text.replace(u'{', u'{{').replace(u'}', u'}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = u"Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, u"Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            headers=headers,
                            json=data,
                            verify=config.get('verify_server_cert', False),
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, u"Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")
        # generate api key
        uri = '/authorize/checkvalid'
        headers = self._authorize(action_result)
        # make rest call
        ret_val, response = self._make_rest_call(uri, action_result, params=None, headers=headers, method="get")

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        self.save_progress('Test Connectivity Passed')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_certificate(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        headers = self._authorize(action_result)
        uri = '/Certificates/Request'

        data = {
            "Approvers": param.get('approvers'),
            "CADN": param.get('cadn'),
            "CASpecificAttributes": param.get('ca_specific_attributes'),
            "City": param.get('city'),
            "Contacts": param.get('contacts'),
            "Country": param.get('country'),
            "CreatedBy": param.get('created_by'),
            "Devices": param.get('devices'),
            "DisableAutomaticRenewal": param.get('disable_automatic_renewal'),
            "EllipticalCurve": param.get('elliptical_curve'),
            "KeyAlgorithm": param.get('key_algorithm'),
            "KeyBitSize": param.get('key_bit_size'),
            "ManagementType": param.get('management_type'),
            "PolicyDN": param['policy_dn'],
            "Subject": param.get('subject'),
            "SubjectAltNames": param.get('subject_alt_names'),
            "ObjectName": param.get('object_name'),
            "Organization": param.get('organization'),
            "OrganizationalUnit": param.get('organizational_unit'),
            "PKCS10": param.get('pkcs10'),
            "Reenable": param.get("reenable"),
            "SetWorkToDo": param.get('set_work_to_do'),
            "State": param.get('state')
        }
        ret_val, response = self._make_rest_call(uri, action_result, headers=headers, data=data, method="post")

        if (phantom.is_fail(ret_val)):
            return ret_val

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['status'] = "Successfully created certificate"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_policies(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        headers = self._authorize(action_result)
        uri = '/Config/FindObjectsOfClass'

        data = {
            "Class": 'Policy',
            "ObjectDN": "\\VED\\Policy",
            "Recursive": 1
        }

        ret_val, response = self._make_rest_call(uri, action_result, headers=headers, method="post", data=data)

        if (phantom.is_fail(ret_val)):
            return ret_val

        for policy in response['Objects']:
            action_result.add_data(policy)

        summary = action_result.update_summary({})
        summary['num_policies'] = len(response['Objects'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_certificates(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        headers = self._authorize(action_result)
        uri = '/Certificates'

        # Optional Certificate filter attributes
        params = {}

        if 'limit' in param:
            params['limit'] = param['limit']
        if 'offset' in param:
            params['offset'] = param['offset']
        if 'country' in param:
            params['C'] = param['country']
        if 'common_name' in param:
            params['CN'] = param['common_name']
        # if 'issuer' in param:
        #     params['Issuer'] = param['issuer']
        if 'key_algorithm' in param:
            params['KeyAlgorithm'] = param['key_algorithm']
        if 'key_size' in param:
            params['KeySize'] = param['key_size']
        if 'key_size_greater' in param:
            params['KeySizeGreater'] = param['key_size_greater']
        if 'key_size_less' in param:
            params['KeySizeLess'] = param['key_size_less']
        if 'city' in param:
            params['L'] = param['city']
        if 'organization' in param:
            params['O'] = param['organization']
        if 'organization_unit' in param:
            params['OU'] = param['organization_unit']
        if 'state' in param:
            params['S'] = param['state']
        if 'san_dns' in param:
            params['SAN-DNS'] = param['san_dns']
        if 'san_email' in param:
            params['SAN-Email'] = param['san_email']
        if 'san_ip' in param:
            params['SAN-IP'] = param['san_ip']
        if 'san_upn' in param:
            params['SAN-UPN'] = param['san_upn']
        if 'san_uri' in param:
            params['SAN-URI'] = param['san_uri']
        if 'serial' in param:
            params['Serial'] = param['serial']
        if 'signature_algorithm' in param:
            params['SignatureAlgorithm'] = param['signature_algorithm']
        if 'thumbprint' in param:
            params['Thumbprint'] = param['thumbprint']
        if 'valid_from' in param:
            params['ValidFrom'] = param['valid_from']
        if 'valid_to' in param:
            params['ValidTo'] = param['valid_to']
        if 'valid_to_greater' in param:
            params['ValidToGreater'] = param['valid_to_greater']
        if 'valid_to_less' in param:
            params['ValidToLess'] = param['valid_to_less']

        ret_val, response = self._make_rest_call(uri, action_result, params=params, headers=headers, method="get")

        if (phantom.is_fail(ret_val)):
            return ret_val

        for certificate in response['Certificates']:
            action_result.add_data(certificate)

        summary = action_result.update_summary({})
        summary['num_certificates'] = len(response['Certificates'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_renew_certificate(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        headers = self._authorize(action_result)
        uri = '/Certificates/Renew'

        data = {
            "CertificateDN": param['certificate_dn'],
            "PKCS10": param.get("pkcs10"),
            "Reenable": param.get("reenable")
        }

        ret_val, response = self._make_rest_call(uri, action_result, headers=headers, method="post", data=data)

        if (phantom.is_fail(ret_val)):
            return ret_val

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['status'] = "Successfully renewed certificate"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_revoke_certificate(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        headers = self._authorize(action_result)
        uri = '/Certificates/Revoke'

        if not(param.get('certificate_dn') or param.get('thumbprint')):
            return RetVal(action_result.set_status(phantom.APP_ERROR, u"Error: Must pass in either CertificateDN or Thumbprint parameter"), None)

        data = {
            "CertificateDN": param.get('certificate_dn'),
            "Thumbprint": param.get('thumbprint'),
            "Reason": param.get('reason'),
            "Comments": param.get('comments'),
            "Disable": param.get('disable')
        }

        ret_val, response = self._make_rest_call(uri, action_result, headers=headers, method="post", data=data)

        if (phantom.is_fail(ret_val)):
            return ret_val

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['status'] = "Successfully revoked certificate"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_certificate(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        headers = self._authorize(action_result)
        uri = '/Certificates/Retrieve'

        # Optional Certificate filter attributes
        params = {}

        if 'certificate_dn' in param:
            params['CertificateDN'] = param['certificate_dn']
        if 'format' in param:
            params['Format'] = param['format']
        if 'friendly_name' in param:
            params['FriendlyName'] = param['friendly_name']
        if 'include_chain' in param:
            params['IncludeChain'] = param['include_chain']
        if 'include_private_key' in param:
            params['IncludePrivateKey'] = param['include_private_key']
        if 'keystore_password' in param:
            params['KeystorePassword'] = param['keystore_password']
        if 'password' in param:
            params['Password'] = param['password']
        if 'root_first_order' in param:
            params['RootFirstOrder'] = param['root_first_order']

        ret_val = self._download_file_to_vault(action_result, uri, headers=headers, params=params)

        if (phantom.is_fail(ret_val)):
            return ret_val

        summary = action_result.update_summary({})
        summary['status'] = "Successfully retrieved certificate and downloaded it to vault"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _download_file_to_vault(self, action_result, endpoint, headers, params):
        """ Download a file and add it to the vault """

        url = self._base_url + endpoint

        try:
            r = requests.get(
                url,
                headers=headers,
                params=params,
            )

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "{}".format(str(e)))

        # If file content length is 0, meaning the file is empty, then fail with the reason
        if not int(r.headers.get('Content-Length')):
            return action_result.set_status(phantom.APP_ERROR, "{}".format(r.reason))

        file_name = r.headers.get('Content-Disposition', 'filename').split('"')[1]

        if hasattr(Vault, 'get_vault_tmp_dir'):
            try:
                vault_ret = Vault.create_attachment(r.content, self.get_container_id(), file_name=file_name)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Could not add file to vault: {0}".format(e))
        else:
            guid = uuid.uuid4()
            tmp_dir = "/vault/tmp/{}".format(guid)
            zip_path = "{}/{}".format(tmp_dir, file_name)

            try:
                os.makedirs(tmp_dir)
            except Exception as e:
                msg = "Unable to create temporary folder '{}': ".format(tmp_dir)
                return action_result.set_status(phantom.APP_ERROR, msg, e)

            with open(zip_path, 'wb') as f:
                f.write(r.content)
                f.close()

            vault_path = "{}/{}".format(tmp_dir, file_name)

            vault_ret = Vault.add_attachment(vault_path, self.get_container_id(), file_name=file_name)

        if vault_ret.get('succeeded'):
            action_result.set_status(phantom.APP_SUCCESS, "Transferred file")
            action_result.add_data({
                            phantom.APP_JSON_VAULT_ID: vault_ret[phantom.APP_JSON_HASH],
                            phantom.APP_JSON_NAME: file_name,
                            phantom.APP_JSON_SIZE: vault_ret.get(phantom.APP_JSON_SIZE)
                        })
            action_result.set_status(phantom.APP_SUCCESS, "Successfully added file to vault")
        else:
            action_result.set_status(phantom.APP_ERROR, "Error adding file to vault")

        return action_result.get_status()

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'create_certificate':
            ret_val = self._handle_create_certificate(param)

        elif action_id == 'get_certificate':
            ret_val = self._handle_get_certificate(param)

        elif action_id == 'list_certificates':
            ret_val = self._handle_list_certificates(param)

        elif action_id == 'renew_certificate':
            ret_val = self._handle_renew_certificate(param)

        elif action_id == 'revoke_certificate':
            ret_val = self._handle_revoke_certificate(param)

        elif action_id == 'list_policies':
            ret_val = self._handle_list_policies(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = config['base_url'].rstrip('/')
        self._username = config['username']
        self._password = config['password']

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = VenafiConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
