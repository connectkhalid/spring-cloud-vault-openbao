# Quickstart: OpenBao Vault Service with Postman

This guide provisions one app, starts the Spring service, then exercises the APIs in Postman. Terminal commands are used only for OpenBao provisioning and local service setup; all API examples below are Postman requests.

## Prerequisites

- OpenBao is running at `http://127.0.0.1:8200`, initialized, and unsealed.
- Java 21 or newer and Maven 3.9 or newer are installed.
- Postman is installed.
- The project is in `F:\Projects\spring-cloud-vault`.

The local service uses HTTP by default. Use TLS and protected credential storage outside a local test.

## 1. Provision the demo app

In PowerShell, provision `demo-app`. The temporary operator token is used only by this setup command:

```powershell
Set-Location 'F:\Projects\spring-cloud-vault'
$env:OPENBAO_TOKEN = '<temporary OpenBao provisioning token>'
.\scripts\provision-openbao-app.ps1 -AppId demo-app -NamespaceName demo-app
```

Copy the printed app-scoped token for the next step. Do not put it in Postman or commit it. Remove the temporary operator token:

```powershell
Remove-Item Env:OPENBAO_TOKEN
```

If PowerShell blocks the script, allow scripts for the current PowerShell process and rerun the provisioning command:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## 2. Configure and start the service

In the PowerShell window that will run the service, generate local IAM credentials:

```powershell
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:APP_TOKEN_SIGNING_SECRET = [Convert]::ToBase64String($bytes)

$clientBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($clientBytes)
$clientSecret = [Convert]::ToBase64String($clientBytes)
[Environment]::SetEnvironmentVariable('APP_ONE_CLIENT_SECRET', $clientSecret, 'User')
$env:APP_ONE_CLIENT_SECRET = $clientSecret

$rotationBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rotationBytes)
$rotationSecret = [Convert]::ToBase64String($rotationBytes)
[Environment]::SetEnvironmentVariable('ROTATION_OPERATOR_SECRET', $rotationSecret, 'User')
$env:ROTATION_OPERATOR_SECRET = $rotationSecret

$env:APP_ONE_OPENBAO_TOKEN = '<app token printed by provisioning>'
$env:APP_ONE_NAMESPACE = 'apps/demo-app'
Remove-Variable clientSecret, clientBytes, rotationSecret, rotationBytes, bytes
```

Admin API access is optional. To try it, configure an administrator username, a unique password of at least 32 characters, and a separate OpenBao management token with namespace, ACL policy, and token-role permissions. Do not use the temporary provisioning token as the runtime management token.

```powershell
$adminBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($adminBytes)
$adminPassword = [Convert]::ToBase64String($adminBytes)
[Environment]::SetEnvironmentVariable('ADMIN_USERNAME', 'vault-admin', 'User')
[Environment]::SetEnvironmentVariable('ADMIN_PASSWORD', $adminPassword, 'User')
[Environment]::SetEnvironmentVariable('OPENBAO_ADMIN_TOKEN', '<dedicated OpenBao management token>', 'User')
$env:ADMIN_USERNAME = 'vault-admin'
$env:ADMIN_PASSWORD = $adminPassword
$env:OPENBAO_ADMIN_TOKEN = '<dedicated OpenBao management token>'
Remove-Variable adminPassword, adminBytes
```

Start the service from the project directory:

```powershell
mvn spring-boot:run
```

Keep this window open. The service reads configuration at startup and renews configured app tokens hourly. Stop and restart it after changing environment variables. Audit events omit request bodies, passwords, bearer tokens, and key material.

## 3. Set up a Postman environment and authenticate

Create a Postman environment named `Vault Local` with these variables:

| Variable | Initial value |
|---|---|
| `baseUrl` | `http://localhost:8080` |
| `appClientId` | `demo-app` |
| `appClientSecret` | The value generated in Step 2 |
| `accessToken` | *(blank)* |
| `rotationOperatorSecret` | The value generated in Step 2 |
| `rotationOperatorToken` | *(blank)* |
| `adminUsername` | `vault-admin` if admin access is configured |
| `adminPassword` | The value generated in Step 2 |
| `adminToken` | *(blank)* |

Keep these values in a local Postman environment and do not export or share the secrets. Do not add the OpenBao app or admin token to Postman; the service uses those credentials internally.

Create a request named **App Login**:

- Method: `POST`
- URL: `{{baseUrl}}/api/auth/token`
- Headers: `Content-Type: application/json`
- Body: **raw** > **JSON**

```json
{
  "clientId": "{{appClientId}}",
  "clientSecret": "{{appClientSecret}}"
}
```

In the request's **Scripts > Post-response** tab, save the returned bearer token:

```javascript
pm.environment.set("accessToken", pm.response.json().accessToken);
```

For subsequent app requests, set **Authorization > Bearer Token** to `{{accessToken}}`. Postman will send `Authorization: Bearer {{accessToken}}`.

## 4. Store, read, and delete a secret

Create a **Write Secret** request:

- Method: `PUT`
- URL: `{{baseUrl}}/api/v1/secrets/database`
- Authorization: Bearer Token `{{accessToken}}`
- Body: **raw** > **JSON**

```json
{
  "data": {
    "username": "app-user",
    "password": "replace-with-test-value"
  }
}
```

Duplicate the request and change the method to `GET` to read it. Use `DELETE` on the same URL to remove the secret and its KV v2 versions; the response is `204 No Content`.

## 5. Create and retrieve an authentication key pair

Create a **Create or Get Key Pair** request:

- Method: `POST`
- URL: `{{baseUrl}}/api/v1/keys/service-signing`
- Authorization: Bearer Token `{{accessToken}}`
- Body: **raw** > **JSON**

```json
{
  "type": "rsa-2048"
}
```

The response includes `keyId`, `publicKey`, and `privateKey`. The private key is returned only to the owning app; this API response uses `Cache-Control: no-store`. Use HTTPS outside a local test and keep the private key in the authentication service's protected secret storage. Postman will display the private key in the response, so do not save or share that response, export it, or include it in a shared collection. This service does not sign application tokens with the asymmetric key.

Create a **Get Active Key Pair** request with method `GET` and URL `{{baseUrl}}/api/v1/keys/service-signing/key-pair`. It returns the current pair after a rotation. Verifiers can get the public-key set with `GET {{baseUrl}}/api/v1/keys/service-signing/public-keys` and select a key by `keyId`/token `kid`.

To inspect configured algorithms, send `GET {{baseUrl}}/api/v1/keys/types` with the app bearer token.

Older aliases created as non-exportable cannot return private material. Rotate such an alias to a new exportable key version or migrate to a new alias. Re-run the provisioning script if the app policy predates private-key export permission.

## 5a. Request an optional-expiry HMAC signing key

Send **POST** `{{baseUrl}}/api/v1/symmetric-keys/bank-signing` with the app bearer token:

```json
{
  "expirationEnabled": true
}
```

The response provides Base64 HMAC-SHA-256 key material, `keyId`, `refreshAt`, and `expiresAt`. The default lifetime is 30 days and renewal begins 24 hours before expiry. The client should request the key again before signing at `refreshAt`; that request provisions and returns the next active key. To retrieve a previous key for verification, use `GET {{baseUrl}}/api/v1/symmetric-keys/bank-signing/versions/{{keyId}}` before its expiry. The service returns `410 Gone` after expiry. A no-expiry alias uses `{"expirationEnabled":false}`; an alias cannot switch expiry modes later. Treat returned HMAC material as a signing secret because anyone holding it can also sign.

The provisioning policy grants HMAC key export only inside the app's OpenBao namespace. Keep the client bearer token private; never log or cache HMAC key responses.

## 6. Configure and run scheduled rotation

Create a **Set Rotation Policy** request:

- Method: `PUT`
- URL: `{{baseUrl}}/api/v1/keys/service-signing/rotation-policy`
- Authorization: Bearer Token `{{accessToken}}`
- Body: **raw** > **JSON**

```json
{
  "enabled": true,
  "intervalSeconds": 7776000
}
```

This example sets a 90-day interval. Configure an external scheduler to call `POST {{baseUrl}}/api/v1/keys/service-signing/rotation-policy/run` periodically with the app bearer token. The response status is `disabled`, `not-due`, or `rotated`; the scheduler receives no private key. After a rotation, the authentication service fetches the active pair using `/key-pair`. The previous public key remains available as `verify-only` until revoked.

## 7. Trigger emergency rotation

The owning app can force an immediate rotation and revoke its prior active public key with:

- Method: `POST`
- URL: `{{baseUrl}}/api/v1/keys/service-signing/emergency-rotation`
- Authorization: Bearer Token `{{accessToken}}`
- Body: none

To trigger rotation centrally, first create a **Rotation Operator Login** request:

- Method: `POST`
- URL: `{{baseUrl}}/api/auth/token`
- Headers: `Content-Type: application/json`
- Body: **raw** > **JSON**

```json
{
  "clientId": "rotation-operator",
  "clientSecret": "{{rotationOperatorSecret}}"
}
```

In **Scripts > Post-response**, save the token:

```javascript
pm.environment.set("rotationOperatorToken", pm.response.json().accessToken);
```

Then send the emergency request with Bearer Token `{{rotationOperatorToken}}` and this JSON body:

```json
{
  "targetAppId": "demo-app"
}
```

Emergency revocation can invalidate existing tokens. Verifiers should refresh their public-key set promptly.

## 8. Admin login, namespaces, policies, and roles

This section requires the admin credentials and dedicated `OPENBAO_ADMIN_TOKEN` configured in Step 2. Create an **Admin Login** request:

- Method: `POST`
- URL: `{{baseUrl}}/api/auth/admin-token`
- Headers: `Content-Type: application/json`
- Body: **raw** > **JSON**

```json
{
  "username": "{{adminUsername}}",
  "password": "{{adminPassword}}"
}
```

In **Scripts > Post-response**, save the returned token:

```javascript
pm.environment.set("adminToken", pm.response.json().accessToken);
```

Use Bearer Token `{{adminToken}}` for the following requests.

Create a namespace with **POST** `{{baseUrl}}/api/v1/admin/namespaces` and this body:

```json
{
  "name": "quickstart",
  "parent": "apps"
}
```

The resulting namespace is `apps/quickstart`. Omit `parent` to create a root namespace. List namespaces with `GET {{baseUrl}}/api/v1/admin/namespaces`.

Create an ACL policy with **PUT** `{{baseUrl}}/api/v1/admin/policies`:

```json
{
  "namespace": "apps/quickstart",
  "name": "quickstart-reader",
  "policy": "path \"secret/data/*\" {\n  capabilities = [\"read\"]\n}\n"
}
```

Get or delete a policy using `GET` or `DELETE {{baseUrl}}/api/v1/admin/policies?namespace=apps%2Fquickstart&name=quickstart-reader`. List names with `GET {{baseUrl}}/api/v1/admin/policies/list?namespace=apps%2Fquickstart`.

Create an OpenBao token role with **PUT** `{{baseUrl}}/api/v1/admin/roles`:

```json
{
  "namespace": "apps/quickstart",
  "name": "quickstart-reader-role",
  "allowedPolicies": ["quickstart-reader"],
  "period": "24h",
  "orphan": true
}
```

Get or delete a role using `GET` or `DELETE {{baseUrl}}/api/v1/admin/roles?namespace=apps%2Fquickstart&name=quickstart-reader-role`. List names with `GET {{baseUrl}}/api/v1/admin/roles/list?namespace=apps%2Fquickstart`. Roles cannot grant the `root` policy. These APIs manage OpenBao token roles; configured app client registrations remain in service configuration. Namespace creation does not mount KV or Transit engines or register an app; those remain separate provisioning/configuration steps.

### Create an integration identity with limited secret access

Create a KV v2 ACL policy in the target namespace with only the intended capabilities. For example, a reader policy:

```json
{
  "namespace": "apps/quickstart",
  "name": "bank-config-reader",
  "policy": "path \"secret/data/*\" { capabilities = [\"read\"] }\n"
}
```

A writer that can read and replace existing values needs `read`, `create`, and `update` on `secret/data/*`. To allow deletion through this API, also grant `delete` on `secret/metadata/*`.

Create an identity and assign one or more existing policies using **POST** `{{baseUrl}}/api/v1/admin/identities/bank-reader`:

```json
{
  "namespace": "apps/quickstart",
  "policies": ["bank-config-reader"]
}
```

The response includes a generated client secret once. Use it with `POST {{baseUrl}}/api/auth/token` as the `clientSecret`; the `clientId` is the identity ID (`bank-reader`). Each identity receives a dedicated OpenBao token limited to its assigned policies. Admins can change its policy assignment with `PUT /api/v1/admin/identities/{id}`, rotate the client secret with `POST /api/v1/admin/identities/{id}/rotate-secret`, disable or enable it with the corresponding action endpoint, and remove it with `DELETE`.

The registry is stored at `secret/data/_service/integration-identities/*` in the root namespace by default. Ensure the mount exists and grant the management token `create`, `update`, and `read` on that data path plus `read`, `list`, and `delete` on its metadata path. The management token also needs permissions for token role creation, role-scoped token creation, and token revocation in the integration namespace. Set `OPENBAO_IDENTITY_REGISTRY_NAMESPACE` if the registry should use another namespace with a KV v2 mount.

## 9. Delete a key alias

Use `DELETE {{baseUrl}}/api/v1/keys/service-signing` with the app bearer token to delete the alias and all tracked Transit keys. This returns `204 No Content` and may invalidate tokens that depend on those keys.

## Error responses

API errors use a consistent JSON shape:

```json
{
  "timestamp": "2026-10-29T10:00:00Z",
  "status": 400,
  "code": "VALIDATION_FAILED",
  "message": "Request validation failed",
  "path": "/api/v1/keys/service-signing",
  "fieldErrors": {
    "type": "must not be blank"
  }
}
```

Failures are also recorded in the service audit log. Request bodies, credentials, bearer tokens, and private key contents are excluded from those logs.

## Troubleshooting and cleanup

- **Login returns `401`:** Check the app ID and `APP_ONE_CLIENT_SECRET` configured in Postman and the service process.
- **Admin login returns `403`:** Confirm `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and `OPENBAO_ADMIN_TOKEN` were all set before the service started.
- **OpenBao returns `403`:** Confirm the app token, `APP_ONE_NAMESPACE=apps/demo-app`, and provisioning policy. Admin operations also require a management token with the requested capabilities.
- **Key type is rejected:** Make sure `OPENBAO_SUPPORTED_KEY_TYPES` matches the algorithms supported by the installed OpenBao version.
- **Stop the service:** Press `Ctrl+C` in the service PowerShell window.
- **Remove local user environment secrets:** Clear `APP_ONE_CLIENT_SECRET`, `ROTATION_OPERATOR_SECRET`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and `OPENBAO_ADMIN_TOKEN` from the Windows user environment when finished.
- **Credential exposure:** Revoke any exposed app, rotation-operator, or admin OpenBao token, then provision a replacement. Do not export or share Postman environments containing credentials.
