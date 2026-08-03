## OAuth Scope

The **OAuth Scope** asset setting controls the scope requested when the app obtains an OAuth token. The field is pre-populated with the default scope (`certificate:discover,delete,manage,revoke;configuration`), so existing assets and actions continue to work without reconfiguration.

- Set a custom value to comply with your security policy. The value must be allowed by the Venafi API Application Integration's maximum scope; otherwise the token request can fail with an `invalid_scope` error.
- After changing this value on an existing asset, run Test Connectivity to refresh the cached token.

## Base URL

The **base_url** must be the bare Venafi host, for example `https://your-venafi-host`. Do not include an API path such as `/vedsdk`; the connector appends the required API paths automatically. Including a path causes token requests to fail with an "Invalid Venafi API URL" error.
