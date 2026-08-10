**Unreleased**

* Ported the Venafi connector to the Splunk SOAR SDK with all seven classic actions: test connectivity, list policies, list certificates, get certificate, create certificate, renew certificate, and revoke certificate.
* Added a new make request action for authenticated calls to the Venafi API.
* Carried over the configurable asset-level OAuth scope (blank uses the default scope). [ESPM-5451]
