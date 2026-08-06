# Local Generic SCIM synchronization

The local SCIM implementation backs the existing Dashboard **Identity Provider
Sync** cards for Generic SCIM, Microsoft Entra SCIM, and JumpCloud. It is an
opt-in local extension and does not modify the upstream Azure or Google pull
connectors.

## Enablement

The Management container requires all of the following:

```text
NB_LOCAL_INTEGRATIONS_ENABLED=true
NB_LOCAL_SCIM_ENABLED=true
DataStoreEncryptionKey=<stable base64-encoded 32-byte key>
PostgreSQL
```

`deploy/getting-started-local.sh` enables these flags and generates a stable
data-store encryption key. Losing that key makes staged SCIM resources
unreadable, so it must be included in encrypted backups.

The Dashboard configuration API remains compatible with upstream:

```text
POST   /api/integrations/scim-idp
GET    /api/integrations/scim-idp
GET    /api/integrations/scim-idp/{id}
PUT    /api/integrations/scim-idp/{id}
DELETE /api/integrations/scim-idp/{id}
POST   /api/integrations/scim-idp/{id}/token
GET    /api/integrations/scim-idp/{id}/logs
```

The provider Base URL is:

```text
https://<netbird-domain>/api/scim/v2
```

## Security model

- Provisioning tokens contain 256 bits of randomness. Only a SHA-256 digest
  and a short display hint are stored.
- SCIM User and Group documents are encrypted with AES-256-GCM before they are
  stored. Equality lookup columns use keyed hashes.
- The protocol endpoint accepts only its SCIM Bearer token; NetBird JWT/PAT
  authentication is bypassed only for the exact `/api/scim/v2` route depth.
- Requests are limited to 1 MiB and 200 list results per page. In-memory
  pre-authentication and per-integration limits allow 600 requests per minute.
- Configuration endpoints use the existing `identity_providers` backend
  permissions. Dashboard permissions alone are not trusted.
- Database leases use `FOR UPDATE SKIP LOCKED` on PostgreSQL and are renewed
  during long synchronization runs. Redis is not required.

TLS termination is mandatory. Base64 values in Dashboard requests are not
encryption.

## Synchronization semantics

SCIM writes are durable staging events. A successful SCIM HTTP response means
the event was stored; a PostgreSQL worker applies it to NetBird shortly after.
An integration revision prevents an older worker from clearing a newer event.

Groups are created first. SCIM Group membership is then mapped to NetBird user
`AutoGroups`. `group_prefixes` controls which groups are provisioned, while
`user_group_prefixes` controls which users are eligible for provisioning.
Empty prefix lists mean all.

For embedded Dex, configure `connector_id`; the worker uses Dex-compatible user
IDs. For external Auth0-style connections, `prefix` is prepended to the SCIM
external identifier.

Safety defaults:

- An email, user ID, or group-name conflict is skipped; ownership is never
  silently transferred from a manual or different integration.
- Inactive, deleted, or out-of-scope users are blocked instead of physically
  deleted.
- Deleted groups are no longer assigned to users but are not automatically
  removed from NetBird, because they may be referenced by policies or routes.
- Deleting the SCIM configuration removes its token and encrypted staging data,
  but does not delete already provisioned NetBird users or groups.

## Supported SCIM operations

- Users and Groups: create, get, list, replace, patch, and delete.
- Discovery: Schemas, ResourceTypes, and ServiceProviderConfig.
- Equality filters: `userName eq` and `externalId eq`.
- Group member add/remove patches, including
  `members[value eq "<user-id>"]`.

Bulk, sorting, password changes, and physical deprovisioning are intentionally
not supported in the first phase.
