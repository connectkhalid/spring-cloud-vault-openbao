[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
    [string] $AppId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
    [string] $NamespaceName,

    [string] $Address = $(if ($env:OPENBAO_ADDR) { $env:OPENBAO_ADDR } else { 'http://127.0.0.1:8200' }),
    [string] $KvMount = 'secret',
    [string] $TransitMount = 'transit'
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($env:OPENBAO_TOKEN)) {
    throw 'Set OPENBAO_TOKEN to a temporary operator token before provisioning.'
}

$baseUri = $Address.TrimEnd('/')
$headers = @{ 'X-Vault-Token' = $env:OPENBAO_TOKEN }
$policyName = "app-$AppId"

function Invoke-OpenBao {
    param(
        [Parameter(Mandatory = $true)][string] $Method,
        [Parameter(Mandatory = $true)][string] $Path,
        [string] $Namespace,
        [object] $Body
    )
    $requestHeaders = @{} + $headers
    if ($Namespace) { $requestHeaders['X-Vault-Namespace'] = $Namespace }
    $arguments = @{ Method = $Method; Uri = "$baseUri/v1/$Path"; Headers = $requestHeaders }
    if ($null -ne $Body) {
        $arguments['ContentType'] = 'application/json'
        $arguments['Body'] = ConvertTo-Json -InputObject $Body -Depth 20 -Compress
    }
    Invoke-RestMethod @arguments
}

# Create the shared parent namespace if needed, then create the app's child namespace.
try { Invoke-OpenBao -Method GET -Path 'sys/namespaces/apps' | Out-Null }
catch { Invoke-OpenBao -Method POST -Path 'sys/namespaces/apps' -Body @{} | Out-Null }
try { Invoke-OpenBao -Method GET -Path "sys/namespaces/$NamespaceName" -Namespace 'apps' | Out-Null }
catch { Invoke-OpenBao -Method POST -Path "sys/namespaces/$NamespaceName" -Namespace 'apps' -Body @{} | Out-Null }
$namespace = "apps/$NamespaceName"

# Enable app-local KV v2 and Transit mounts. Existing mounts are left intact.
try { Invoke-OpenBao -Method GET -Path "sys/mounts/$KvMount" -Namespace $namespace | Out-Null }
catch {
    Invoke-OpenBao -Method POST -Path "sys/mounts/$KvMount" -Namespace $namespace -Body @{
        type = 'kv'
        options = @{ version = '2' }
    } | Out-Null
}
try { Invoke-OpenBao -Method GET -Path "sys/mounts/$TransitMount" -Namespace $namespace | Out-Null }
catch { Invoke-OpenBao -Method POST -Path "sys/mounts/$TransitMount" -Namespace $namespace -Body @{ type = 'transit' } | Out-Null }

$policy = @"
path "$KvMount/data/*" {
  capabilities = ["create", "update", "read"]
}
path "$KvMount/metadata/*" {
  capabilities = ["read", "list", "delete"]
}
path "$TransitMount/keys/*" {
  capabilities = ["create", "update", "read", "delete"]
}
path "$TransitMount/export/public-key/*" {
  capabilities = ["read"]
}
path "$TransitMount/export/private-key/*" {
  capabilities = ["read"]
}
path "$TransitMount/export/hmac-key/*" {
  capabilities = ["read"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}
"@
Invoke-OpenBao -Method PUT -Path "sys/policies/acl/$policyName" -Namespace $namespace -Body @{ policy = $policy } | Out-Null

$tokenResponse = Invoke-OpenBao -Method POST -Path 'auth/token/create' -Namespace $namespace -Body @{
    policies = @($policyName)
    no_default_policy = $true
    orphan = $true
    renewable = $true
    period = '24h'
    display_name = "spring-vault-$AppId"
}

Write-Output "Namespace: $namespace"
Write-Output "Policy: $policyName"
Write-Output 'Set this value as APP_ONE_OPENBAO_TOKEN (or the matching app token environment variable):'
Write-Output $tokenResponse.auth.client_token
