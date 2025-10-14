[README (1).md](https://github.com/user-attachments/files/22909041/README.1.md)
# TalonVigil

> Governance-first, compliance-ready security automation for Azure Sentinel and Log Analytics

TalonVigil is a modular framework that deploys Azure Sentinel and Log Analytics with audit-grade defaults. It provides reusable Bicep templates, playbooks, and branded dashboards to help organizations and individuals rapidly onboard, detect threats, and maintain compliance without manual overhead.

## 📋 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Architecture](#️-architecture)
- [Configuration](#-configuration)
- [Analytics & Queries](#-analytics--queries)
- [Deployment Examples](#-deployment-examples)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [License](#-license)

 ✨ Features

 🏢 Enterprise Ready
- Automated Deployment**: Provision Sentinel + LAW with Infrastructure as Code (Bicep/ARM)
- Audit-Ready Defaults**: Diagnostic settings, tagging, and policy wiring built-in
- Compliance Mapping**: Governance dashboards aligned with SOC2/NIST frameworks
- Branded Dashboards**: Clear, trust-building visuals for stakeholders and auditors

 🔧 Modular & Extensible
- Reusable Templates**: Modular packs for analytic rules, workbooks, and playbooks
- Personal EGI Mode**: Lightweight "Email Guarding Intelligence" for individuals/families
- Custom Analytics**: Easy-to-deploy detection rules and hunting queries
- Multi-Tenant Support**: Scalable architecture for MSPs and large organizations

 🚀 Quick Start

 Prerequisites

```bash
# Install Azure CLI (Ubuntu/Debian)
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

 Install Bicep CLI
az bicep install

 Login to Azure
az login

 Set your subscription
az account set --subscription "your-subscription-id"
```

 Installation

```bash
 Clone the repository
git clone https://github.com/repo-ranger21/talon-vigil.git
cd talon-vigil

 Make deployment scripts executable
chmod +x scripts/*.sh

 Deploy core Sentinel + Log Analytics Workspace
az deployment sub create \
  --location eastus \
  --template-file infra/sentinel/core/phase3-sentinel.bicep \
  --parameters rgName=TalonVigil-RG workspaceName=TalonVigil-LAW

 Verify deployment
az monitor log-analytics workspace show \
  --resource-group TalonVigil-RG \
  --workspace-name TalonVigil-LAW
```

 PowerShell Alternative

```powershell
 Connect to Azure and set subscription
Connect-AzAccount
Set-AzContext -SubscriptionId "your-subscription-id"

 Deploy TalonVigil infrastructure
New-AzSubscriptionDeployment `
  -Location "East US" `
  -TemplateFile "infra/sentinel/core/phase3-sentinel.bicep" `
  -rgName "TalonVigil-RG" `
  -workspaceName "TalonVigil-LAW"

 Verify Log Analytics Workspace
Get-AzOperationalInsightsWorkspace `
  -ResourceGroupName "TalonVigil-RG" `
  -Name "TalonVigil-LAW"
```

 🏗️ Architecture

```
TalonVigil/
├── infra/                  # Infrastructure as Code templates
│   ├── sentinel/          # Azure Sentinel deployments
│   ├── monitoring/        # Log Analytics and monitoring
│   └── shared/           # Shared resources and modules
├── analytics/             # Detection rules and queries
│   ├── rules/            # Analytic rules (KQL)
│   ├── hunting/          # Hunting queries
│   └── watchlists/       # Threat intelligence feeds
├── playbooks/            # Automated response workflows
├── workbooks/            # Custom dashboards and reports
├── config/               # Configuration files
└── docs/                 # Documentation and guides
```

 ⚙️ Configuration

 Workspace Configuration

```yaml
 config/workspace.yml
workspace:
  name: TalonVigil-LAW
  resourceGroup: TalonVigil-RG
  location: eastus
  sku: PerGB2018
  retentionInDays: 90
  dailyQuotaGb: 10

dataConnectors:
  - name: AzureActiveDirectory
    enabled: true
    tables:
      - SigninLogs
      - AuditLogs
      - RiskyUsers
  - name: Office365
    enabled: true
    tables:
      - ExchangeAdmin
      - SharePointAdmin
      - TeamsAdmin
  - name: AzureActivity
    enabled: true
    subscriptions:
      - "subscription-id-1"
      - "subscription-id-2"

alertRules:
  enableBuiltInRules: true
  customRulesPath: ./analytics/rules/
  severity:
    high: true
    medium: true
    low: false

playbooks:
  autoResponse: true
  notificationEmail: security@company.com
  teamsWebhook: "https://outlook.office.com/webhook/..."
```

 Parameters File

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "workspaceName": {
      "value": "TalonVigil-LAW"
    },
    "resourceGroupName": {
      "value": "TalonVigil-RG"
    },
    "location": {
      "value": "eastus"
    },
    "retentionInDays": {
      "value": 90
    },
    "dailyQuotaGb": {
      "value": 10
    },
    "enableDefender": {
      "value": true
    },
    "tags": {
      "value": {
        "Environment": "Production",
        "Project": "TalonVigil",
        "Owner": "Security Team",
        "CostCenter": "IT-SEC-001"
      }
    }
  }
}
```

 📊 Analytics & Queries

 Core Bicep Template

```bicep
// infra/sentinel/core/main.bicep
@description('Name of the Log Analytics Workspace')
param workspaceName string

@description('Location for all resources')
param location string = resourceGroup().location

@description('Log retention in days')
@minValue(30)
@maxValue(730)
param retentionInDays int = 90

@description('Daily ingestion quota in GB')
param dailyQuotaGb int = 10

@description('Resource tags')
param tags object = {}

// Log Analytics Workspace
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    workspaceCapping: {
      dailyQuotaGb: dailyQuotaGb
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
      disableLocalAuth: false
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// Microsoft Sentinel
resource sentinelOnboarding 'Microsoft.SecurityInsights/onboardingStates@2023-02-01' = {
  scope: logAnalyticsWorkspace
  name: 'default'
  properties: {}
}

// Data Collection Rule for Azure Activity Logs
resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: '${workspaceName}-dcr'
  location: location
  tags: tags
  properties: {
    dataSources: {
      platformTelemetry: [
        {
          streams: [
            'Microsoft-AzureActivity'
          ]
          name: 'azureActivity'
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: logAnalyticsWorkspace.id
          name: 'destination-log'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Microsoft-AzureActivity'
        ]
        destinations: [
          'destination-log'
        ]
      }
    ]
  }
}

output workspaceId string = logAnalyticsWorkspace.id
output workspaceName string = logAnalyticsWorkspace.name
output sentinelResourceId string = sentinelOnboarding.id
```

 Security Analytics Queries

```kusto
// Detect suspicious sign-ins from unfamiliar locations
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0  // Successful sign-ins
| where RiskLevelDuringSignIn in ("medium", "high")
| extend 
    LocationDetails = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    DeviceInfo = strcat(DeviceDetail.deviceId, " (", DeviceDetail.operatingSystem, ")")
| summarize 
    SignInCount = count(),
    Locations = make_set(LocationDetails),
    IPAddresses = make_set(IPAddress),
    Devices = make_set(DeviceInfo),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName, AppDisplayName
| where SignInCount > 5
| order by SignInCount desc

// Hunt for potential privilege escalation
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in (
    "Add member to role",
    "Add eligible member to role", 
    "Assign role to user",
    "Add app role assignment to user"
)
| where Result == "success"
| extend 
    Actor = tostring(InitiatedBy.user.userPrincipalName),
    ActorApp = tostring(InitiatedBy.app.displayName),
    Target = tostring(TargetResources[0].userPrincipalName),
    Role = tostring(TargetResources[0].displayName),
    RoleId = tostring(TargetResources[0].id)
| project 
    TimeGenerated, 
    Actor, 
    ActorApp, 
    Target, 
    Role, 
    OperationName,
    CorrelationId,
    ResultReason
| order by TimeGenerated desc

// Detect bulk file downloads (potential data exfiltration)
OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation in ("FileDownloaded", "FileAccessed")
| where ResultStatus == "Succeeded"
| summarize 
    DownloadCount = count(),
    UniqueFiles = dcount(OfficeObjectId),
    Files = make_set(OfficeObjectId, 50),
    Sites = make_set(Site_Url)
    by UserId, ClientIP
| where DownloadCount > 50 or UniqueFiles > 20
| order by DownloadCount desc

// Monitor for new email forwarding rules
ExchangeAdmin
| where TimeGenerated > ago(24h)
| where CmdletName in ("New-InboxRule", "Set-InboxRule")
| where Parameters contains "ForwardTo" or Parameters contains "RedirectTo"
| extend 
    ForwardingAddress = extract(@"ForwardTo[^;]*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", 1, Parameters),
    RuleName = extract(@"Name[^;]*?'([^']*)'", 1, Parameters)
| project 
    TimeGenerated,
    UserOriented,
    ForwardingAddress,
    RuleName,
    Parameters,
    ClientIP
| order by TimeGenerated desc
```

 Threat Hunting Queries

```kusto
// Advanced persistent threat indicators
let suspiciousCommands = dynamic([
    "powershell", "cmd.exe", "wscript", "cscript", 
    "regsvr32", "rundll32", "mshta", "certutil"
]);
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where ProcessCommandLine has_any (suspiciousCommands)
| where ProcessCommandLine contains "download" or 
        ProcessCommandLine contains "invoke" or
        ProcessCommandLine contains "base64"
| summarize 
    ProcessCount = count(),
    Devices = make_set(DeviceName),
    Commands = make_set(ProcessCommandLine, 10)
    by AccountName, FileName
| where ProcessCount > 5
| order by ProcessCount desc

// Detect potential credential stuffing attacks
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0  // Failed sign-ins
| summarize 
    FailedAttempts = count(),
    UniqueUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 20),
    ErrorCodes = make_set(ResultType)
    by IPAddress, AppDisplayName
| where FailedAttempts > 100 and UniqueUsers > 10
| order by FailedAttempts desc
```

 🚀 Deployment Examples

 Single Command Deployment

```bash
 Deploy everything with default settings
./scripts/deploy.sh --subscription "your-sub-id" --location "eastus"
```

 Custom Deployment with Parameters

```bash
 Deploy with custom configuration
az deployment sub create \
  --location eastus \
  --template-file infra/main.bicep \
  --parameters @config/production.parameters.json \
  --parameters workspaceName="MyCompany-Sentinel" \
  --parameters retentionInDays=180 \
  --parameters dailyQuotaGb=50
```

### Multi-Environment Setup

```bash
 Development environment
az deployment sub create \
  --location eastus \
  --template-file infra/main.bicep \
  --parameters @config/dev.parameters.json

 Production environment  
az deployment sub create \
  --location eastus \
  --template-file infra/main.bicep \
  --parameters @config/prod.parameters.json
```

 📚 Documentation

- [Deployment Guide](docs/deployment.md)** - Step-by-step setup instructions
- [Configuration Reference](docs/configuration.md)** - Detailed configuration options
- [Analytics Rules](docs/analytics.md)** - Guide to detection rules and queries
- [Playbooks](docs/playbooks.md)** - Automated response workflows
- [Compliance Mapping](docs/compliance.md)** - SOC2, NIST, and other frameworks
- [API Reference](docs/api.md)** - Integration and automation APIs

 🤝 Contributing

We welcome contributions from the community! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on our code of conduct and development process.

🎯 High-Impact Areas

- 📝 Analytics Rules**: New detection templates for emerging threats
- 📊 Compliance Mappings**: SOC2, HIPAA, ISO 27001 framework alignments  
- 🎨 Dashboard UX**: Improvements to workbooks and visual reporting
- 📚 Documentation**: Tutorials, guides, and best practices

 Quick Contributing Steps

```bash
 Fork and clone the repository
git clone https://github.com/your-username/talon-vigil.git
cd talon-vigil

 Create a feature branch
git checkout -b feature/amazing-feature

 Make your changes and test
./scripts/test.sh

 Commit your changes
git commit -m 'Add amazing feature'

 Push to your fork
git push origin feature/amazing-feature

 Open a Pull Request
gh pr create --title "Add amazing feature" --body "Description of changes"
```

 📜 License

This project is licensed under the MIT License - see the [`LICENSE`](LICENSE) file for details.

---

<div align="center">

⭐ Star this repository if you find it useful!**

Made with ❤️ by the [TalonVigil Team](https://github.com/repo-ranger21)

</div>
