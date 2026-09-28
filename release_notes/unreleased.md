**Unreleased**

* Ported the Venafi connector to the Splunk SOAR SDK with all seven classic actions: test connectivity, list policies, list certificates, get certificate, create certificate, renew certificate, and revoke certificate.
* Added a new make request action for authenticated calls to the Venafi API.
* Create, renew, and revoke certificate keep their success text in `action_result.summary.status` (unchanged) and now also add it to `action_result.message`. Other actions use `action_result.message` only.
