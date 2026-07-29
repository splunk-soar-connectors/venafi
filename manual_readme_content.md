## Creating the Venafi API Application

Before configuring an asset, an API Application (OAuth integration) must exist in your Venafi instance. This is normally set up by an administrator in the Aperture UI (Defining the OAuth API Application Integration); the equivalent Web SDK request is shown below and requires an administrator bearer token. Replace the `ApplicationId` and `Scope`/`MaxScope` values so they match your organization's security policy. Include this configuration in your internal documentation so it can be imported into other Venafi instances with the same settings:

**POST** `/vedsdk/oauth/CreateApplication`

```json
{
    "ApplicationId": "<your-application-id>",
    "Scope": "certificate:approve,delete,discover,manage,revoke;codesign:delete,manage;configuration:delete,manage;ssh:approve,delete,discover,manage;statistics",
    "MaxScope": "certificate:approve,delete,discover,manage,revoke;codesign:delete,manage;configuration:delete,manage;ssh:approve,delete,discover,manage;statistics",
    "Name": "Splunk SOAR",
    "Vendor": "Splunk",
    "Description": "Splunk SOAR",
    "Url": ""
}
```

The `ApplicationId` you choose becomes the **client_id** value in the asset configuration. `MaxScope` defines the maximum permissions the integration can ever request, and `Scope` is the default scope granted.

## OAuth Scope

The optional **OAuth Scope** asset setting controls the scope requested when the app obtains an OAuth token.

- Leave it **blank** to use the default scope (`certificate:discover,delete,manage,revoke;configuration`). Existing assets and actions continue to work without reconfiguration.
- Set a custom value to comply with a stricter security policy. The value must stay within the API Application's `MaxScope`; requesting anything beyond `MaxScope` results in a reduced or rejected token.

## Base URL

The **base_url** must be the bare Venafi host, for example `https://your-venafi-host`. Do not include an API path such as `/vedsdk`; the connector appends the required API paths automatically. Including a path causes token requests to fail with an "Invalid Venafi API URL" error.
