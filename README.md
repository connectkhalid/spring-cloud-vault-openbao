# OpenBao-backed application vault service

For a step-by-step local test, see [QUICKSTART.md](QUICKSTART.md).

Successful credential exchanges and authenticated API requests are written to the terminal as concise `AUDIT` log events. Request bodies, bearer tokens, client secrets, and key material are not logged.

This Spring Boot service gives each configured application an isolated OpenBao namespace. Applications authenticate to the service with mock-IAM client credentials, then call the service API with a short-lived signed bearer token. The service maps that identity to an app-specific OpenBao token and namespace. The temporary provisioning token is never used at runtime; an optional separately configured management token is used only by admin endpoints.

Ordinary values are written to KV v2. Transit generates asymmetric key pairs and HMAC signing keys. The service returns key material only to the owning app; private and symmetric key responses are marked no-store and are never written to audit logs. HMAC keys can optionally expire and rotate on the client's next key request. The app policy permits the corresponding Transit exports only in that app's isolated namespace.

The OpenAPI 3.0.3 contract is served at `GET /openapi.yaml`. It groups every API under `controls`, `secrets`, `symmetric-key`, or `asymmetric-key` and documents bearer authentication, DTO schemas, and error responses.

## Requirements and startup

- Java 21 or newer
- Maven 3.9 or newer
- An initialized, unsealed OpenBao server

Provision an app namespace and engines using an operator token only for this setup step:

```powershell
$env:OPENBAO_TOKEN = '<temporary operator token>'
.\scripts\provision-openbao-app.ps1 -AppId demo-app -NamespaceName demo-app
```

The script prints the app-scoped periodic OpenBao token once. The service renews configured app tokens hourly. Store the token as `APP_ONE_OPENBAO_TOKEN`, then clear the operator token from the shell. Configure the app's client secret, a random signing secret of at least 32 bytes, namespace and token before starting the service:

```powershell
$env:APP_TOKEN_SIGNING_SECRET = '<random value, at least 32 characters>'
$env:APP_ONE_CLIENT_SECRET = '<client secret for demo-app>'
$env:APP_ONE_OPENBAO_TOKEN = '<app-scoped token from provisioning>'
$env:APP_ONE_NAMESPACE = 'apps/demo-app'
# Optional; set a unique random value (at least 32 characters) to enable central emergency rotation.
$env:ROTATION_OPERATOR_SECRET = '<separate operator secret>'
```

Run with `mvn spring-boot:run`. The sample app ID is `demo-app`. Add further entries under `vault-service.iam.apps` in `application.yml` or a protected external configuration file, with a separate client secret, namespace and OpenBao token for each app. Do not commit populated credentials.

The key type list defaults to common OpenBao Transit asymmetric types. Set `OPENBAO_SUPPORTED_KEY_TYPES` to a comma-separated list that matches the installed OpenBao version; the list is an API allowlist because Transit does not expose a standard endpoint that enumerates algorithms supported by the server.

Optional HMAC key expiry uses a 30-day lifetime and begins renewal 24 hours before expiry by default. Override these with `SYMMETRIC_KEY_DEFAULT_TTL` and `SYMMETRIC_KEY_RENEWAL_WINDOW` (ISO-8601 durations).

### Administrator login and OpenBao management

Set `ADMIN_USERNAME` and a unique `ADMIN_PASSWORD` of at least 32 characters to enable administrator login, and set `OPENBAO_ADMIN_TOKEN` to a dedicated OpenBao management token. In addition to namespace, ACL policy, and token-role management, it needs permission to create/revoke scoped tokens and read/write the integration identity registry. Admin login is disabled unless all three values are configured. The OpenBao token is used only by management services and is never returned by the API. The registry uses KV v2 at `secret/data/_service/integration-identities/*` in the root namespace by default; configure `OPENBAO_IDENTITY_REGISTRY_NAMESPACE` to use another namespace with the configured KV mount.

At minimum, add these paths to the management token's ACL in the registry namespace (root by default):

```hcl
path "secret/data/_service/integration-identities/*" {
  capabilities = ["create", "update", "read"]
}
path "secret/metadata/_service/integration-identities/*" {
  capabilities = ["read", "list", "delete"]
}
path "auth/token/roles/*" {
  capabilities = ["create", "update", "read", "delete"]
}
path "auth/token/create/*" {
  capabilities = ["update"]
}
path "auth/token/revoke" {
  capabilities = ["update"]
}
```

The management token also needs the namespace and ACL policy permissions used by the existing admin endpoints. Token-role creation and scoped token issuance/revocation must be permitted in each target integration namespace.

```http
POST /api/auth/admin-token
Content-Type: application/json

{"username":"vault-admin","password":"..."}
```

Use the returned bearer token for the admin endpoints:

- `POST /api/v1/admin/namespaces` with `{"name":"billing","parent":"apps"}` creates a namespace. Omit `parent` to create at root.
- `PUT /api/v1/admin/policies` creates or replaces a namespaced ACL policy using `namespace`, `name`, and OpenBao HCL `policy`; `GET` and `DELETE` use `namespace` and `name` query parameters, while `GET /api/v1/admin/policies/list?namespace=apps/billing` lists names.
- `PUT /api/v1/admin/roles` creates or replaces an OpenBao token role with `namespace`, `name`, `allowedPolicies`, `period` (OpenBao duration such as `24h`), and `orphan`; `GET` and `DELETE` use query parameters, while `GET /api/v1/admin/roles/list?namespace=apps/billing` lists names. Roles cannot grant the `root` policy.
- `GET /api/v1/admin/namespaces` lists namespaces.
- `POST /api/v1/admin/identities/{id}` creates a separately authenticated integration identity in a namespace. Supply `namespace` and one or more existing namespaced ACL policies. The response includes a generated `clientSecret` once; store it securely. `GET /api/v1/admin/identities` lists identities, and `GET /api/v1/admin/identities/{id}` inspects one without returning its credential.
- `PUT /api/v1/admin/identities/{id}` replaces its policy assignment and rotates its OpenBao token. The identity remains bound to its original namespace. `POST /api/v1/admin/identities/{id}/rotate-secret` rotates its client credential and returns it once. Use `/disable` and `/enable` to revoke or reissue its OpenBao token; `DELETE` removes the identity and revokes its token.

Admin operations are audited. App identities cannot access these endpoints, and the admin identity cannot use app-scoped secret or key operations. Configured app identities remain in protected service configuration; admin-managed integration identities are stored in the OpenBao KV v2 registry and receive individual scoped tokens. Policy bodies remain OpenBao ACL HCL, so grant only the needed capabilities. For KV v2, `read` on `secret/data/*` allows reads, `create` allows creating new secrets, `update` allows replacing existing secrets, and `delete` on `secret/metadata/*` allows the API's permanent delete operation. A client that should both create and update needs both `create` and `update`.

Errors from authentication, validation, business rules, and OpenBao are returned as `timestamp`, numeric `status`, stable `code`, human-readable `message`, `path`, and `fieldErrors`. Failures are also written to the audit log with the actor, route, status, code, and message.

For production, serve the Spring API over TLS, store all credentials in a managed secret source, restrict network access to OpenBao, and rotate any credential that has been exposed.

## API

### Exchange app credentials

```http
POST /api/auth/token
Content-Type: application/json

{"clientId":"demo-app","clientSecret":"..."}
```

Response: `accessToken`, `tokenType`, `expiresIn` (seconds). Send the token as `Authorization: Bearer <accessToken>` to protected routes.

### Store and read app secrets

```http
PUT /api/v1/secrets/database
Authorization: Bearer <accessToken>
Content-Type: application/json

{"data":{"username":"app-user","password":"..."}}
```

Use `GET /api/v1/secrets/{name}` to retrieve a secret and `DELETE /api/v1/secrets/{name}` to permanently remove its KV v2 metadata and versions. Secret endpoints return typed DTOs (`name`, `data`, and KV `version` for reads; `name` and `version` for writes), while secret values remain an arbitrary JSON object. Names allow letters, digits, dot, underscore and hyphen.

Example read response:

```json
{"name":"database","data":{"username":"app-user","password":"..."},"version":1}
```

### Request an asymmetric key pair

```http
POST /api/v1/keys/service-signing
Authorization: Bearer <accessToken>
Content-Type: application/json

{"type":"rsa-2048"}
```

Use `GET /api/v1/keys/types` to read supported types. A new named key is generated once. The creation response includes its PEM `publicKey`, `privateKey`, and `keyId`; later requests return the active pair. The private key is exported from Transit only for the authenticated owning app and is never logged. Responses containing private material use `Cache-Control: no-store`; serve the API over HTTPS.

The authentication service retrieves the active pair with `GET /api/v1/keys/{alias}/key-pair` and signs its tokens locally. Verifiers retrieve the public-key set with `GET /api/v1/keys/{alias}/public-keys` and select a key using the token's `kid` (matching the API's `keyId`). This service does not sign application tokens or payloads with the managed asymmetric key; mock IAM still issues its short-lived HMAC-signed API bearer tokens.

### Request an HMAC signing key

Use `POST /api/v1/symmetric-keys/{alias}` with the app bearer token:

```json
{"expirationEnabled":true}
```

The response contains `key` (Base64 HMAC-SHA-256 material), `keyId`, `refreshAt`, and `expiresAt`. With expiration disabled, both timestamps are null and the key does not rotate automatically. Expiration mode is fixed for an alias; use a new alias to change it. A client should request the key again before signing when `refreshAt` arrives. At that request, the service provisions and publishes a new active key. Retrieve a previous version for verification with `GET /api/v1/symmetric-keys/{alias}/versions/{keyId}` until its `expiresAt`; the endpoint returns `410` after expiry. Any holder of a raw HMAC key can also sign with it, so protect and expire local copies. Responses containing key material use `Cache-Control: no-store`.

OpenBao requires the Transit key to be exportable for local signing; that setting cannot later be disabled. Keep the HMAC export ACL limited to the service token and namespace, and never give clients the underlying OpenBao token.

### Configure and run rotation

Set a per-alias interval, in seconds, with `PUT /api/v1/keys/{alias}/rotation-policy`:

```json
{"enabled":true,"intervalSeconds":7776000}
```

An external scheduler periodically calls `POST /api/v1/keys/{alias}/rotation-policy/run` using the owning app's bearer token. The endpoint returns `disabled`, `not-due`, or `rotated`; a due run creates and immediately activates a new key. The scheduler receives no private key. The authentication service fetches the current pair from `/key-pair`; verifiers continue to receive old public keys as `verify-only` until explicitly revoked.

For suspected compromise, an app can call `POST /api/v1/keys/{alias}/emergency-rotation` to immediately activate a new key and revoke the old public key. A central operator can use the same endpoint with `{"targetAppId":"demo-app"}` to target any configured app. Obtain the operator bearer token from `POST /api/auth/token` using `clientId` `rotation-operator` and the separately configured `ROTATION_OPERATOR_SECRET`. Emergency revocation may invalidate existing tokens, and verifiers must promptly refresh their key set.

Manual stage, inspection, activation, cancellation, and prior-public-key revocation endpoints remain available. The algorithm is fixed for an alias; use a new alias to change type. Permanently delete an alias and its Transit keys with `DELETE /api/v1/keys/{alias}`. Older aliases created as non-exportable cannot return private material; rotate to an exportable key version or migrate to a new alias. Rerun `scripts/provision-openbao-app.ps1` to grant the required private-key export permission.

Supported values include `rsa-2048`, `rsa-3072`, `rsa-4096`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, and `ed25519`. Add newer Transit asymmetric types, such as ML-DSA types when supported by the installed OpenBao version, to `OPENBAO_SUPPORTED_KEY_TYPES`.

## Isolation model

- Mock IAM registration maps each client ID to exactly one namespace and one app-scoped OpenBao token.
- Rotation-operator credentials are separately configured and are accepted only by the emergency-rotation endpoint; target app access uses that app's scoped OpenBao token.
- The API derives the app identity from a verified signed token; callers cannot pass a namespace or OpenBao token in request data.
- The provisioning script creates the KV v2 and Transit mounts and an ACL policy in that app's namespace. Runtime policy paths never include another app's data.
- The Spring Cloud Vault starter is included for Spring Vault integration; its automatic global config bootstrap is disabled because a single service instance serves multiple per-app tokens and namespaces.
