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

var storageAccountName = toLower(replace('${namePrefix}sa', '-', ''))
var functionAppName = '${namePrefix}-pipeline'
var appInsightsName = '${namePrefix}-insights'
var keyVaultName = '${namePrefix}-kv'
var postgresServerName = '${namePrefix}-pg'
var planName = '${namePrefix}-plan'
var identityName = '${namePrefix}-identity'

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

// Linux Consumption plan - the default, cheapest choice matching the
// "pay only for actual pipeline runtime" framing in the proposal doc.
// Swap `sku.name`/`sku.tier` to an Elastic Premium plan (e.g. "EP1") if
// the scheduled timer's cold-start latency turns out to matter in
// practice - that's a one-line change here, not a redeploy of anything
// else in this template.
resource hostingPlan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: planName
  location: location
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {
    reserved: true
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
    siteConfig: {
      linuxFxVersion: 'DOCKER|<acr-or-registry>/culprit-serverless:latest'
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
      ]
    }
  }
  dependsOn: [
    keyVaultSecretsUserRole
  ]
}

output functionAppName string = functionApp.name
output functionAppPrincipalId string = identity.properties.principalId
output postgresFullyQualifiedDomainName string = postgres.properties.fullyQualifiedDomainName
output keyVaultName string = keyVault.name
