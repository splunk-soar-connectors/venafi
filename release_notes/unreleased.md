**Unreleased**

* Ported the Venafi connector to the Splunk SOAR SDK with all seven classic actions: test connectivity, list policies, list certificates, get certificate, create certificate, renew certificate, and revoke certificate.
* Added a new make request action for authenticated calls to the Venafi API.
* Migration note: action success text previously exposed at `action_result.summary.status` is now returned in `action_result.message`. Update any playbooks that reference the former path.
