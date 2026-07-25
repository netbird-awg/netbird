# Local MDM & EDR integrations

The local EDR implementation provides the REST contracts already used by the
upstream Dashboard without requiring Redis or a separate scheduler.

## Enablement

Both server flags are required:

```text
NB_LOCAL_INTEGRATIONS_ENABLED=true
NB_LOCAL_EDR_ENABLED=true
```

The Dashboard card is unlocked independently with:

```text
NETBIRD_LOCAL_EDR_ENABLED=true
```

The Dashboard flag only controls presentation. Every API operation still
requires server-side EDR permissions and the server flags above.

Optional server settings:

```text
NB_LOCAL_EDR_SYNC_INTERVAL=5m
NB_LOCAL_EDR_CACHE_MAX_AGE=30m
NB_LOCAL_EDR_SYNC_TIMEOUT=5m
NB_LOCAL_EDR_FLEETDM_HEALTH_CONCURRENCY=25
```

`NB_LOCAL_EDR_SYNC_INTERVAL` accepts values from one minute to one hour.
`NB_LOCAL_EDR_CACHE_MAX_AGE` accepts values from five minutes to 24 hours.
`NB_LOCAL_EDR_SYNC_TIMEOUT` accepts values from 30 seconds to 30 minutes and
also determines the minimum PostgreSQL worker lease. FleetDM health lookups use
between one and 100 concurrent requests.
Invalid values fall back to the defaults.

`deploy/getting-started-local.sh` enables these flags automatically for the
source-built PostgreSQL deployment.

## Supported providers

- Microsoft Intune
- CrowdStrike Falcon
- SentinelOne
- Huntress
- FleetDM

Only one provider can be enabled per account. Disable the current provider
before enabling another one.

## Storage and scheduling

The implementation requires PostgreSQL. It creates:

- `local_edr_integrations` for encrypted provider configuration and sync leases;
- `local_edr_devices` for normalized device compliance state;
- `local_edr_bypasses` for explicit administrative peer exceptions.

Provider credentials and match rules are encrypted with the Management
`DataStoreEncryptionKey`. Raw provider responses are not persisted.

PostgreSQL row locks and expiring leases coordinate workers across Management
replicas. Failed synchronization retries use bounded exponential backoff. Redis
is not used.

## Security behavior

- User-configurable provider URLs require HTTPS and pass the shared outbound
  SSRF validator, including DNS rebinding and redirect checks.
- Provider responses, page counts and device counts are bounded.
- FleetDM fetches the cached `/hosts/:id/health` report with bounded
  concurrency only for hosts that match peers in the configured NetBird groups
  and only when disk encryption, policy, or vulnerable software rules require
  it. Online-only rules do not add per-host requests.
- Missing compliance fields, stale snapshots, ambiguous serial numbers and
  ambiguous hostnames fail closed.
- Cache freshness transitions actively revalidate and disconnect affected
  peers; they do not wait for a client reconnect.
- Configuration, the initial device snapshot and account validator settings
  are committed in one PostgreSQL transaction.
- Bypass creation and revocation require both EDR update and Peer update
  permissions.
- Bypasses are cleared when the integration is disabled or deleted, and are
  removed automatically after the peer becomes compliant.
- Secrets are omitted from API responses and audit event metadata.
- Synchronization errors are exposed to authorized Dashboard users without
  returning provider credentials.

## Operations

The upstream Dashboard calls:

```text
/api/integrations/edr/intune
/api/integrations/edr/falcon
/api/integrations/edr/sentinelone
/api/integrations/edr/huntress
/api/integrations/edr/fleetdm
/api/peers/edr/bypassed
/api/peers/{peer-id}/edr/bypass
```

Creating or enabling an integration validates its credentials by fetching a
device snapshot before committing the configuration. A configured provider
whose cached snapshot exceeds `NB_LOCAL_EDR_CACHE_MAX_AGE` blocks scoped peers
unless an authorized administrator has explicitly bypassed that peer.

Before production rollout, validate each configured vendor tenant with a
read-only API credential and confirm that serial number or hostname values
match the metadata reported by the deployed NetBird clients.
