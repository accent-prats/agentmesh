// Culprit serverless architecture - target infrastructure (proposal,
// 2026-11-10). Deploys the managed-services-only, no-VM stack the
// proposal describes: a Durable Functions app (the scheduled/event-
// driven/ad-hoc pipeline), its required Storage Account (Task Hub +
// Functions runtime storage), Application Insights, a Key Vault for
// secrets, a user-assigned Managed Identity, and Azure Database for
// PostgreSQL - Flexible Server for persistence. The optional Console
// (Container Apps) is deliberately NOT included here - per management's
// "mostly scheduled, unattended" requirement, it's a later, lower-
// priority phase (see the proposal doc's Phase 3), not part of the
// core deliverable this template provisions.
//
// NOT YET DEPLOYED OR VALIDATED - no `az`/Bicep CLI was available in
// this session to run `az bicep build` or `az deployment group
// what-if` against it. Run both before applying this for real; see
// this repo's culprit/culprit/serverless/README.md for the full list
// of what has and hasn't been verified.

@description('Short name used to derive every resource name, e.g. "culprit-prod" or "culprit-lab"')
param namePrefix string

@description('Azure region for every resource')
param location string = resourceGroup().location

@description('PostgreSQL administrator login')
param postgresAdminLogin string

@secure()
@description('PostgreSQL administrator password')
param postgresAdminPassword string

@description('Anthropic API key, stored in Key Vault - set it there after deployment if you prefer not to pass it here')
@secure()
param anthropicApiKey string = ''

@description('Fernet key encrypting the Azure/Datadog settings Culprit stores at rest (culprit/security/crypto.py) - generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())". Left empty, the app silently falls back to a hardcoded, publicly-known dev-only key - a real production risk, not a convenience default, so this should never be left empty outside a throwaway demo.')
@secure()
param culpritEncryptionKey string = ''

@description('Image tag to deploy - defaults to :latest; set this explicitly on every real deployment once a CI pipeline exists, so a Function App restart cannot silently pick up a newer, untested image')
param imageTag string = 'latest'

var storageAccountName = toLower(replace('${namePrefix}sa', '-', ''))
var functionAppName = '${namePrefix}-pipeline'
var appInsightsName = '${namePrefix}-insights'
var keyVaultName = '${namePrefix}-kv'
var postgresServerName = '${namePrefix}-pg'
var planName = '${namePrefix}-plan'
var identityName = '${namePrefix}-identity'
var registryName = toLower(replace('${namePrefix}acr', '-', ''))

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityName
  location: location
}

resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
  }
}

// Found while preparing the implementation/deployment proposal
// (2026-11-10): the Function App below needs a real container registry
// to pull its image from - a previous version of this template left
// that as an unresolved `<acr-or-registry>` placeholder, silently
// assuming one already existed. Provisioning it here means the
// deployment is genuinely self-sufficient under a fresh subscription,
// not dependent on a registry someone has to remember to set up
// separately. Basic SKU - cheapest tier, ample for one image with a
// handful of tags; Azure Container Registry doesn't do GB-second
// serverless billing, so this is the one resource in this template
// that is NOT fully consumption-priced - a small, fixed, roughly $5/mo
// cost, not something a schedule-based workload avoids regardless of
// hosting approach.
resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: registryName
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
  }
}

// AcrPull - lets the Function App's managed identity pull the image
// without a registry username/password ever being stored anywhere.
resource acrPullRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, identity.id, 'AcrPull')
  scope: registry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    accessPolicies: []
  }
}

// Key Vault Secrets User - lets the Function App's managed identity read
// secrets at runtime without any credential ever living in an app
// setting as plain text.
resource keyVaultSecretsUserRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, identity.id, 'KeyVaultSecretsUser')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource anthropicSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (!empty(anthropicApiKey)) {
  parent: keyVault
  name: 'anthropic-api-key'
  properties: {
    value: anthropicApiKey
  }
}

resource databaseUrlSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'culprit-database-url'
  properties: {
    value: 'postgresql+psycopg://${postgresAdminLogin}:${postgresAdminPassword}@${postgres.properties.fullyQualifiedDomainName}/culprit'
  }
}

// Found while preparing the manual (no-Bicep) deployment proposal
// (2026-11-13): an earlier version of this template never set
// CULPRIT_ENCRYPTION_KEY at all, silently leaving a real deployment on
// the hardcoded dev-only fallback key (culprit/security/crypto.py) -
// the same class of gap as the earlier missing Container Registry, just
// security-shaped instead of deployment-shaped. Conditional, same
// pattern as anthropicSecret: if the caller doesn't pass one, it's
// absent here too and the app setting below is left blank, matching the
// existing "degrade to insecure dev-only key" behavior rather than
// pretending a value exists that doesn't.
resource encryptionKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (!empty(culpritEncryptionKey)) {
  parent: keyVault
  name: 'culprit-encryption-key'
  properties: {
    value: culpritEncryptionKey
  }
}

resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2023-06-01-preview' = {
  name: postgresServerName
  location: location
  sku: {
    // Burstable - the cheapest tier that still auto-scales; an episodic,
    // scheduled workload is exactly the Burstable use case Azure
    // documents this SKU family for.
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  properties: {
    version: '16'
    administratorLogin: postgresAdminLogin
    administratorLoginPassword: postgresAdminPassword
    storage: {
      storageSizeGB: 32
    }
    backup: {
      backupRetentionDays: 7
    }
  }
}

resource postgresDatabase 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2023-06-01-preview' = {
  parent: postgres
  name: 'culprit'
}

// Allows any Azure service (including this Function App) to reach the
// server - tighten this to a VNet-integrated rule once the Function
// App's outbound networking is finalized; left broad here because the
// exact outbound IP range depends on the hosting plan choice below,
// which this template deliberately leaves open (Consumption vs.
// Premium is a cost/cold-start tradeoff for the pilot environment to
// decide, not something to bake in here).
resource postgresFirewallAllowAzure 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2023-06-01-preview' = {
  parent: postgres
  name: 'AllowAzureServices'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

// Linux Elastic Premium plan, not Consumption - found in review
// 2026-11-10: this Function App is deployed as a custom container
// (`functionApp.kind` below includes `container`, `linuxFxVersion` is a
// `DOCKER|...` reference), and Azure Functions custom containers are
// not supported on the classic Consumption (Dynamic/Y1) plan - only
// Premium (Elastic Premium) or Dedicated (App Service) plans support a
// Linux custom container. An earlier version of this template paired
// a Consumption plan with a custom-container Function App, which would
// have failed to run at all. EP1 is the smallest Elastic Premium tier -
// still consumption-billed per the proposal's cost framing, just with a
// plan type that actually supports this deployment shape.
resource hostingPlan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: planName
  location: location
  kind: 'elastic'
  sku: {
    name: 'EP1'
    tier: 'ElasticPremium'
  }
  properties: {
    reserved: true
    maximumElasticWorkerCount: 5
  }
}

resource functionApp 'Microsoft.Web/sites@2023-01-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux,container'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    serverFarmId: hostingPlan.id
    // Required because this app has only a user-assigned identity (no
    // system-assigned one) - found in review 2026-11-10: without this,
    // the @Microsoft.KeyVault(...) references below default to resolving
    // via a system-assigned identity that doesn't exist here, and would
    // fail to resolve at runtime, silently leaving CULPRIT_DATABASE_URL/
    // ANTHROPIC_API_KEY unset.
    keyVaultReferenceIdentity: identity.id
    siteConfig: {
      linuxFxVersion: 'DOCKER|${registry.properties.loginServer}/culprit-serverless:${imageTag}'
      // Pulls the image via the Function App's own managed identity,
      // not a registry username/password - pairs with the AcrPull role
      // assignment above. acrUserManagedIdentityID must be the full
      // resource ID (not the app setting form) for a user-assigned
      // identity pull.
      acrUseManagedIdentityCreds: true
      acrUserManagedIdentityID: identity.id
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storage.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storage.listKeys().keys[0].value}'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'python'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: appInsights.properties.InstrumentationKey
        }
        {
          name: 'CULPRIT_SCHEDULE_CRON'
          value: '0 0 4 * * *'
        }
        {
          name: 'CULPRIT_DATABASE_URL'
          value: '@Microsoft.KeyVault(SecretUri=${databaseUrlSecret.properties.secretUri})'
        }
        {
          name: 'ANTHROPIC_API_KEY'
          value: empty(anthropicApiKey) ? '' : '@Microsoft.KeyVault(SecretUri=${anthropicSecret.properties.secretUri})'
        }
        {
          name: 'CULPRIT_ENCRYPTION_KEY'
          value: empty(culpritEncryptionKey) ? '' : '@Microsoft.KeyVault(SecretUri=${encryptionKeySecret.properties.secretUri})'
        }
      ]
    }
  }
  dependsOn: [
    keyVaultSecretsUserRole
    acrPullRole
  ]
}

output functionAppName string = functionApp.name
output functionAppPrincipalId string = identity.properties.principalId
output postgresFullyQualifiedDomainName string = postgres.properties.fullyQualifiedDomainName
output keyVaultName string = keyVault.name
output containerRegistryLoginServer string = registry.properties.loginServer
