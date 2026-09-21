**Unreleased**

* Ported the Venafi connector to the Splunk SOAR SDK with all seven classic actions: test connectivity, list policies, list certificates, get certificate, create certificate, renew certificate, and revoke certificate.
* Added a new make request action for authenticated calls to the Venafi API.
* Action success text is now also available in `action_result.message`. The existing `action_result.summary.status` field is unchanged and remains available for backward compatibility.
