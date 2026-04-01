# Cisco SSE Usage Reporter

`Cisco SSE Usage Reporter` is a Python 3 command-line application that helps identify usage of Cisco Umbrella and Cisco Secure Access as it relates to Secure Internet Access (`SIA`) and Secure Private Access (`SPA`) subscription utilization.

The tool is intended to give administrators a practical way to estimate adoption by service, generate supporting logs, and optionally correlate roaming computer identities with SAML user identities.

## What This Application Measures

### Secure Internet Access (`SIA`)

This application measures SIA usage by the number of registered `Roaming Computers` in the organization.

This relates to the `Umbrella Roaming Module`, which is part of `Cisco Secure Client`.

Important notes:

- SIA subscriptions are also required for clients that access the internet through `PAC` configuration.
- SIA subscriptions are also required for clients that access the internet through a branch office tunnel into the `SSE` platform.
- Those clients are **not** counted by this application.
- The script assumes inactive Roaming Computers are configured to be auto-deleted after 60 days.  Otherwise, they are counted.
- It is generally considered a best practice to deploy the `Roaming Module` for DNS-layer protection, even when SIA traffic is acquired through another method.

### Secure Private Access (`SPA`)

This application measures SPA usage by users who access either:

- `Remote Access VPN`
- `Zero Trust Network Access (ZTNA)`

Important notes:

- This application does **not** count users who exclusively use `ZTNA browser-only` access.
- This application does **not** count users who access private applications through a branch office tunnel into the `SSE` platform.

## Product Support

The application supports two Cisco platforms:

- `Cisco Umbrella`
- `Cisco Secure Access`

The CLI prompts for the target product first, then uses the appropriate API host and endpoint set for that platform.

Current behavior:

- `Cisco Umbrella`
  - Supports `SWG / SIA` counting in this tool
  - `VPN` and `ZTNA` are currently not counted in the Umbrella path (Remote Access VPN requires the Meraki API)
- `Cisco Secure Access`
  - Supports `SWG`
  - Supports `Remote Access VPN`
  - Supports `ZTNA`

## SWG Identity Correlation

The application includes an optional feature to correlate `Roaming Computer` identities, typically computer names, with `SAML` user identities.

This process is time-intensive because the application must query the `Web Proxy Activity Log` to identify user-to-device relationships. For large organizations, this step may take more than an hour.

To make repeated runs faster, the application builds and reuses a permanent local cache of successful SWG correlations.

Default cache location:

- `~/.sse_user_counter/swg_correlation_cache.json`

Example on macOS:

- `/Users/<your-user>/.sse_user_counter/swg_correlation_cache.json`

When the application starts, it will ask:

> Do you want to attempt correlation of Roaming Computer identities with SAML identities?
> (Warning: may take over an hour for large organizations. This will build a permanent cache to support faster subsequent runs.)

If you answer `no`, the application still counts roaming computers for `SIA`, but it skips username correlation.

## Output

Each run creates a timestamped output folder under `output/`.

Generated files:

- `swg_log.csv`
- `vpn_log.csv`
- `ztna_log.csv`
- `correlated_log.csv`
- `summary.json`

The service logs are intended to show the underlying data used to support the counts. Depending on the service and what the APIs return, logs may include:

- `user_name`
- `computer_name`
- `service_type`
- `device_id`
- timestamps
- explanatory notes

The correlated log consolidates service usage by user where correlation data is available.

## Running the Tool

Run interactively:

```bash
python3 main.py
```

You can also provide arguments up front:

```bash
python3 main.py \
  --product secure-access \
  --api-key YOUR_KEY \
  --api-secret YOUR_SECRET \
  --org-id YOUR_ORG_ID \
  --swg-correlate-identities yes
```

Available options:

- `--product {umbrella,secure-access}`
- `--api-key`
- `--api-secret`
- `--org-id`
- `--swg-correlate-identities {yes,no}`
- `--reporting-region {auto,us,eu}`
- `--swg-correlation-days`
- `--vpn-days`
- `--output-root`

## Runtime Behavior

The CLI provides progress updates while it runs. During long SWG correlation passes, it emits a heartbeat every 60 seconds so the user can see that the process is still active.

If the Cisco API server returns rate-limiting feedback such as `HTTP 429`, the application reports the backoff timer to the user and retries automatically.

The client also refreshes expired OAuth access tokens automatically during long runs for both `Cisco Umbrella` and `Cisco Secure Access`.

## Key Assumptions and Limitations

- `SWG / SIA` count is based on registered roaming computers.
- `SWG` username correlation depends on proxy activity and may not be available for every device.
- Devices with no usable proxy activity may still be counted for `SIA` even if no username can be correlated.
- `VPN` count is based on unique users with qualifying remote access connection events in the configured lookback window.
- `ZTNA` count is based on active registered devices returned by the available Cisco APIs.

## Cisco Documentation Used

- [Cisco Secure Access authentication](https://developer.cisco.com/docs/cloud-security/secure-access-api-authentication/)
- [Cisco Secure Access getting started](https://developer.cisco.com/docs/cloud-security/secure-access-api-getting-started/)
- [Cisco Secure Access reporting overview](https://developer.cisco.com/docs/cloud-security/secure-access-api-reference-reporting-overview/)
- [Get Remote Access Events](https://developer.cisco.com/docs/cloud-security/get-remote-access-events/)
- [Get Activity Proxy](https://developer.cisco.com/docs/cloud-security/get-activity-proxy/)
- [Get Identities](https://developer.cisco.com/docs/cloud-security/get-identities/)
- [Secure Access Zero Trust User Devices overview](https://developer.cisco.com/docs/cloud-security/secure-access-api-reference-zta-users-overview/)
- [Get Counts Device Certificates](https://developer.cisco.com/docs/cloud-security/get-counts-device-certificates/)
- [List Certificates for User](https://developer.cisco.com/docs/cloud-security/list-certificates-for-user/)
- [Cisco Umbrella authentication](https://developer.cisco.com/docs/cloud-security/umbrella-api-authentication/)
- [Cisco Umbrella getting started](https://developer.cisco.com/docs/cloud-security/umbrella-api-getting-started/)
- [Cisco Umbrella reporting overview](https://developer.cisco.com/docs/cloud-security/umbrella-api-reference-reporting-overview/)
- [Cisco Umbrella roaming computers overview](https://developer.cisco.com/docs/cloud-security/umbrella-api-reference-roaming-computers-overview/)
