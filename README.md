[comment]: # "Auto-generated SOAR connector documentation"
# Venafi

Publisher: Splunk  
Connector Version: 2\.0\.2  
Product Vendor: Venafi  
Product Name: Venafi  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app integrates with an instance of Venafi to perform generic and investigative actions

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Venafi asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | Venafi API URL
**ph\_0** |  optional  | ph | Placeholder
**username** |  required  | string | Venafi API Username to authenticate with
**password** |  required  | password | Venafi API Password to authenticate with
**client\_id** |  required  | string | API Application Integration application ID

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[list policies](#action-list-policies) - Returns a list of all policies in Venafi  
[create certificate](#action-create-certificate) - Enrolls a certificate in Venafi  
[list certificates](#action-list-certificates) - Returns a list of certificates in Venafi  
[renew certificate](#action-renew-certificate) - Requests immediate renewal for an existing certificate in Venafi  
[revoke certificate](#action-revoke-certificate) - Requests to revoke an existing certificate in Venafi  
[get certificate](#action-get-certificate) - Downloads specified certificate to the vault  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list policies'
Returns a list of all policies in Venafi

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.AbsoluteGUID | string | 
action\_result\.data\.\*\.DN | string |  `venafi policy dn` 
action\_result\.data\.\*\.GUID | string | 
action\_result\.data\.\*\.Id | numeric | 
action\_result\.data\.\*\.Name | string | 
action\_result\.data\.\*\.Parent | string | 
action\_result\.data\.\*\.Revision | numeric | 
action\_result\.data\.\*\.TypeName | string | 
action\_result\.summary\.num\_policies | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create certificate'
Enrolls a certificate in Venafi

Type: **generic**  
Read only: **False**

Either Subject or ObjectName parameter must be filled out\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**policy\_dn** |  required  | The folder DN for the new certificate | string |  `venafi policy dn` 
**subject** |  optional  | The Common Name \(CN\) field for the certificate\. Either the subject or object\_name parameter must be filled in | string | 
**object\_name** |  optional  | The Common Name \(CN\) field for the certificate\. Either the subject or object\_name parameter must be filled in | string | 
**approvers** |  optional  | An array of one or more identities for certificate workflow approvers | string | 
**cadn** |  optional  | The Distinguished Name \(DN\) of the Trust Protection Platform Certificate Authority Template object | string | 
**ca\_specific\_attributes** |  optional  | An array of name/value pairs providing any CA attributes to be stored with the Certificate object and submitted to the CA during enrollment | string | 
**city** |  optional  | Locality/City attribute of Certificate | string | 
**contacts** |  optional  | An array of one or more identities for users or groups who receive notifications about events pertaining to the object | string | 
**country** |  optional  | The Country field for the certificate Subject DN | string | 
**created\_by** |  optional  | The setting to identify the object that initiated enrollment or provisioning changes | string | 
**devices** |  optional  | An array of devices that require enrollment or provisioning | string | 
**disable\_automatic\_renewal** |  optional  | The setting to control whether manual intervention is required for certificate renewal | boolean | 
**elliptical\_curve** |  optional  | P256, P384, or P521 encryption for Elliptical Curve Cryptography | string | 
**key\_algorithm** |  optional  | Algorithm for public key of Certificate | string | 
**key\_bit\_size** |  optional  | The number of bits to allow for key generation | numeric | 
**management\_type** |  optional  | The level of management that Trust Protection Platform applies to the certificate | string | 
**organization** |  optional  | Organization attribute of the certificate | string | 
**organizational\_unit** |  optional  | Organizational unit attribute of the certificate | string | 
**pkcs10** |  optional  | The PKCS10 formatted CSR for the certificate | string | 
**reenable** |  optional  | Option to renew a previously disabled certificate | boolean | 
**set\_work\_to\_do** |  optional  | Option to control certificate processing | boolean | 
**state** |  optional  | State/Province attribute of Certificate | string | 
**subject\_alt\_names** |  optional  | Skip parameter if the policy already specifies SAN Types\. Array of subject alternative names \(SANS\) for the certificate\. For each SAN, specify an array element with a Type and a corresponding Name\. For example, SubjectAltNames\:\[ \{Type\:2, Name\:www\.example\.com\}, \{Type\:7, Name\:122\.122\.122\.122\} \]\. The Type parameter is an integer that represents the kind of SAN which can be 0\:OtherName, 1\: Email, 2\:DNS, 6\: URI, or 7\:IPAddress\. The Name value is the SAN Friendly name that corresponds to the Type parameter | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.approvers | string | 
action\_result\.parameter\.ca\_specific\_attributes | string | 
action\_result\.parameter\.cadn | string | 
action\_result\.parameter\.city | string | 
action\_result\.parameter\.contacts | string | 
action\_result\.parameter\.country | string | 
action\_result\.parameter\.created\_by | string | 
action\_result\.parameter\.devices | string | 
action\_result\.parameter\.disable\_automatic\_renewal | boolean | 
action\_result\.parameter\.disable\_automatic\_renewal | boolean | 
action\_result\.parameter\.elliptical\_curve | string | 
action\_result\.parameter\.key\_algorithm | string | 
action\_result\.parameter\.key\_bit\_size | numeric | 
action\_result\.parameter\.management\_type | string | 
action\_result\.parameter\.object\_name | string | 
action\_result\.parameter\.organization | string | 
action\_result\.parameter\.organizational\_unit | string | 
action\_result\.parameter\.pkcs10 | string | 
action\_result\.parameter\.policy\_dn | string |  `venafi policy dn` 
action\_result\.parameter\.reenable | boolean | 
action\_result\.parameter\.set\_work\_to\_do | boolean | 
action\_result\.parameter\.state | string | 
action\_result\.parameter\.subject | string | 
action\_result\.parameter\.subject\_alt\_names | string | 
action\_result\.data\.\*\.CertificateDN | string |  `venafi certificate dn` 
action\_result\.data\.\*\.Guid | string | 
action\_result\.summary\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list certificates'
Returns a list of certificates in Venafi

Type: **investigate**  
Read only: **True**

Returns certificate details and the total number of certificates that match specified search filters\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Maximum number of certificates to return\. Possible values are 1\-100 | numeric | 
**offset** |  optional  | Number of results to skip \(offset=5 begins results at page five\) | numeric | 
**country** |  optional  | Country attribute of Certificate | string | 
**common\_name** |  optional  | Common name attribute of Certificate | string |  `domain`  `url` 
**key\_algorithm** |  optional  | Algorithm for public key of Certificate | string | 
**key\_size** |  optional  | Public key size of Certificate | numeric | 
**key\_size\_greater** |  optional  | Find certificates with a key size greater than the specified value | numeric | 
**key\_size\_less** |  optional  | Find certificates with a key size less than the specified value | numeric | 
**city** |  optional  | Locality/City attribute of Certificate | string | 
**organization** |  optional  | Organization attribute of Certificate | string | 
**organization\_unit** |  optional  | Organization unit attribute of Certificate | string | 
**state** |  optional  | State/Province attribute of Certificate | string | 
**san\_dns** |  optional  | Subject Alternative Name \(SAN\) Distinguished Name Server \(DNS\) attribute of Certificate | string |  `domain`  `url` 
**san\_email** |  optional  | Subject Alternative Name \(SAN\) Email RFC822 attribute of Certificate | string |  `email` 
**san\_ip** |  optional  | Subject Alternative Name \(SAN\) IP Address attribute of Certificate | string |  `ip` 
**san\_upn** |  optional  | Subject Alternative Name \(SAN\) User Principle Name \(UPN\) attribute of Certificate | string |  `email` 
**san\_uri** |  optional  | Subject Alternative Name \(SAN\) Uniform Resource Identifier \(URI\) attribute of Certificate | string |  `url` 
**serial** |  optional  | Serial number attribute of Certificate | string | 
**signature\_algorithm** |  optional  | Algorithm used to sign the Certificate | string | 
**thumbprint** |  optional  | SHA\-1 thumbprint of the Certificate | string |  `sha1` 
**valid\_from** |  optional  | YYYY\-MM\-DD or ISO 8601 format YYYY\-MM\-DDTHH\:MM\:SS\.mmmmmmmZ \(Find certificates by the date of issue\) | string | 
**valid\_to** |  optional  | YYYY\-MM\-DD or ISO 8601 format YYYY\-MM\-DDTHH\:MM\:SS\.mmmmmmmZ \(Find certificates by expiration date\) | string | 
**valid\_to\_greater** |  optional  | YYYY\-MM\-DD or ISO 8601 format YYYY\-MM\-DDTHH\:MM\:SS\.mmmmmmmZ \(Find certificates that expire after a certain date\) | string | 
**valid\_to\_less** |  optional  | YYYY\-MM\-DD or ISO 8601 format YYYY\-MM\-DDTHH\:MM\:SS\.mmmmmmmZ \(Find certificates that expire before a certain date\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.city | string | 
action\_result\.parameter\.common\_name | string |  `domain`  `url` 
action\_result\.parameter\.country | string | 
action\_result\.parameter\.key\_algorithm | string | 
action\_result\.parameter\.key\_size | numeric | 
action\_result\.parameter\.key\_size\_greater | numeric | 
action\_result\.parameter\.key\_size\_less | numeric | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.offset | numeric | 
action\_result\.parameter\.organization | string | 
action\_result\.parameter\.organization\_unit | string | 
action\_result\.parameter\.san\_dns | string |  `domain`  `url` 
action\_result\.parameter\.san\_email | string |  `email` 
action\_result\.parameter\.san\_ip | string |  `ip` 
action\_result\.parameter\.san\_upn | string |  `email` 
action\_result\.parameter\.san\_uri | string |  `url` 
action\_result\.parameter\.serial | string | 
action\_result\.parameter\.signature\_algorithm | string | 
action\_result\.parameter\.state | string | 
action\_result\.parameter\.thumbprint | string |  `sha1` 
action\_result\.parameter\.valid\_from | string | 
action\_result\.parameter\.valid\_to | string | 
action\_result\.parameter\.valid\_to\_greater | string | 
action\_result\.parameter\.valid\_to\_less | string | 
action\_result\.parameter\.valid\_to\_less | string | 
action\_result\.data\.\*\.CreatedOn | string | 
action\_result\.data\.\*\.DN | string |  `venafi certificate dn` 
action\_result\.data\.\*\.Guid | string | 
action\_result\.data\.\*\.Name | string | 
action\_result\.data\.\*\.ParentDn | string | 
action\_result\.data\.\*\.SchemaClass | string | 
action\_result\.data\.\*\.X509\.CN | string | 
action\_result\.data\.\*\.X509\.SANS\.DNS | string | 
action\_result\.data\.\*\.X509\.SANS\.Email | string |  `email` 
action\_result\.data\.\*\.X509\.Serial | string | 
action\_result\.data\.\*\.X509\.Thumbprint | string |  `sha1` 
action\_result\.data\.\*\.X509\.ValidFrom | string | 
action\_result\.data\.\*\.X509\.ValidTo | string | 
action\_result\.data\.\*\.\_links\.\*\.Details | string | 
action\_result\.summary\.num\_certificates | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'renew certificate'
Requests immediate renewal for an existing certificate in Venafi

Type: **generic**  
Read only: **False**

A renewable certificate cannot be currently processing, in error, or contain a 'Monitoring' Management Type\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**certificate\_dn** |  required  | The Distinguished Name \(DN\) of the certificate to renew | string |  `venafi certificate dn` 
**pkcs10** |  optional  | The PKCS10 formatted CSR to use for the renewal | string | 
**reenable** |  optional  | Option to renew a previously disabled certificate | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.certificate\_dn | string |  `venafi certificate dn` 
action\_result\.parameter\.pkcs10 | string | 
action\_result\.parameter\.reenable | boolean | 
action\_result\.data\.\*\.Success | boolean | 
action\_result\.summary\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'revoke certificate'
Requests to revoke an existing certificate in Venafi

Type: **correct**  
Read only: **False**

The caller must have write permissions to the certificate object and either the CertificateDN or the Thumbprint parameter must be provided\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**certificate\_dn** |  optional  | The Distinguished Name \(DN\) of the certificate to revoke | string |  `venafi certificate dn` 
**thumbprint** |  optional  | The thumbprint \(hash\) of the certificate to revoke | string |  `sha1` 
**reason** |  optional  | The reason for revocation of the certificate\. 0\: None, 1\: User key compromised, 2\: CA key compromised, 3\: User changed affiliation, 4\: Certificate superseded, 5\: Original use no longer valid | numeric | 
**comments** |  optional  | Details about why the certificate is being revoked | string | 
**disable** |  optional  | The setting to manage the certificate upon revocation\. If true, the certificate is disabled and no new certificate may replace it\. If false, the certificate is allowed to be replaced by a new certificate | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.certificate\_dn | string |  `venafi certificate dn` 
action\_result\.parameter\.comments | string | 
action\_result\.parameter\.disable | boolean | 
action\_result\.parameter\.reason | numeric | 
action\_result\.parameter\.thumbprint | string |  `sha1` 
action\_result\.data | string | 
action\_result\.data\.\*\.Requested | boolean | 
action\_result\.data\.\*\.Revoked | boolean | 
action\_result\.data\.\*\.Success | boolean | 
action\_result\.data\.\*\.Warning | string | 
action\_result\.summary | string | 
action\_result\.summary\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get certificate'
Downloads specified certificate to the vault

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**certificate\_dn** |  required  | The Distinguished Name \(DN\) of the certificate to download | string |  `venafi certificate dn` 
**format** |  optional  | The certificate format for the return data | string | 
**friendly\_name** |  optional  | The label or alias to use for Base64, JKS, or PKCS \#12 formats\. Required for the JKS format | string | 
**include\_chain** |  optional  | When the Format is Base64, PKCS \#7, PKCS \#12, or JKS, you can include the parent or root chain in the return data | boolean | 
**include\_private\_key** |  optional  | When the Format is Base64, PKCS \#12, or JKS, you can specify whether to return the private key | boolean | 
**keystore\_password** |  optional  | If the Format is JKS, you must set a keystore password\. Use the same requirements as required for the Password parameter | string | 
**password** |  optional  | If the IncludePrivateKey value is true, you must create a password\. Password must be 12 characters and comprised of at least 3 of the following\: uppercase alphabetic letters, lowercase alphabetic letters, numeric characters, special characters | string | 
**root\_first\_order** |  optional  | The order of the certificate chain to trust | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.certificate\_dn | string |  `venafi certificate dn` 
action\_result\.parameter\.format | string | 
action\_result\.parameter\.friendly\_name | string | 
action\_result\.parameter\.include\_chain | boolean | 
action\_result\.parameter\.include\_private\_key | boolean | 
action\_result\.parameter\.keystore\_password | string | 
action\_result\.parameter\.password | string | 
action\_result\.parameter\.root\_first\_order | boolean | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.size | numeric | 
action\_result\.data\.\*\.vault\_id | string |  `sha1`  `vault id` 
action\_result\.summary\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 