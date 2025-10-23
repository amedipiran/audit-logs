<#
  setup-audit-logs.ps1
  Purpose:
    - Create a Resource Group
    - Create an ADLS Gen2 (StorageV2 with HNS)
    - Create three containers: audit-activity, audit-resource, audit-entra
    - Apply a lifecycle policy: keep in Hot (default) for 91 days, then move to Archive
    - Create an Action Group (email) via ARM REST (no Az.Monitor receiver cmdlets)
    - Create Activity Log Alerts for diagnostic setting changes via ARM REST
    - Enable Diagnostic Settings:
        * Subscription Activity Logs  -> Storage (via REST)
        * Microsoft Entra (Audit & Sign-in) -> Storage (via REST)

  Notes:
    - Run this in PowerShell 7+ (pwsh).
    - Requires Az modules for auth + storage (Az.Accounts, Az.Resources, Az.Storage).
    - You should have Owner/Contributor on the subscription and storage account.
#>

[CmdletBinding(PositionalBinding = $false)]
param(
  [Parameter(Mandatory=$true)]
  [string] $SubscriptionId,

  [string] $ResourceGroupName = "rg-audit-archive-prod",

  [ValidateSet(
    'westeurope','northeurope','swedencentral','uksouth','ukwest',
    'francecentral','germanywestcentral','switzerlandnorth',
    'eastus','eastus2','centralus','westus','westus2','westus3'
  )]
  [string] $Location = "westeurope",

  # Storage Account name. If empty, a random valid name will be generated.
  [string] $StorageAccountName = "",

  # SKU: Archive tier is supported for LRS/GRS/RA-GRS (NOT ZRS/GZRS/RA-GZRS)
  [ValidateSet('Standard_LRS','Standard_GRS','Standard_RAGRS')]
  [string] $SkuName = "Standard_GRS",

  # Notification email for the Action Group (alerts)
  [Parameter(Mandatory=$true)]
  [string] $NotificationEmail
)

#region Helpers / Pre-flight
if ([string]::IsNullOrWhiteSpace($StorageAccountName)) {
  # Storage account names: globally unique, lowercase, 3-24 chars, alphanumeric only.
  $StorageAccountName = ("st" + (Get-Random)).ToLower()
}

# Ensure needed modules are available
$needed = @("Az.Accounts","Az.Resources","Az.Storage")
$missing = $needed | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
if ($missing) {
  Write-Host "⚠️  Missing modules: $($missing -join ', ')." -ForegroundColor Yellow
  Write-Host "    Install with: Install-Module $($missing -join ',') -Scope CurrentUser -Force" -ForegroundColor Yellow
  # We continue; if unavailable at runtime, cmdlets will throw with clear errors.
}
Import-Module Az.Storage -ErrorAction SilentlyContinue | Out-Null
#endregion

Write-Host "🔐 Logging in to Azure and selecting subscription..." -ForegroundColor Cyan
Connect-AzAccount -Subscription $SubscriptionId | Out-Null
Select-AzSubscription -SubscriptionId $SubscriptionId

try {
  # --------------------------------------------------------------------
  # 1) Resource Group + ADLS Gen2 + Containers
  # --------------------------------------------------------------------
  Write-Host "🧱 Ensuring Resource Group '$ResourceGroupName' in '$Location'..." -ForegroundColor Cyan
  $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
  if (-not $rg) {
    $rg = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction Stop
  }

  Write-Host ("💾 Creating ADLS Gen2 Storage Account '{0}' (SKU={1})..." -f $StorageAccountName, $SkuName) -ForegroundColor Cyan
  $existingSt = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
  if (-not $existingSt) {
    $null = New-AzStorageAccount `
      -ResourceGroupName $ResourceGroupName `
      -Name $StorageAccountName `
      -Location $Location `
      -SkuName $SkuName `
      -Kind StorageV2 `
      -EnableHierarchicalNamespace $true `
      -AllowBlobPublicAccess $false `
      -AllowSharedKeyAccess $true `
      -MinimumTlsVersion TLS1_2 `
      -ErrorAction Stop
  } else {
    Write-Host "   Storage account already exists; continuing." -ForegroundColor DarkYellow
  }

  $st  = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
  $ctx = $st.Context

  Write-Host "🗂️  Creating containers (audit-activity, audit-resource, audit-entra)..." -ForegroundColor Cyan
  foreach ($suffix in @("activity","resource","entra")) {
    $cName = "audit-$suffix"
    $null = New-AzStorageContainer -Name $cName -Context $ctx -ErrorAction SilentlyContinue
  }

  # --------------------------------------------------------------------
  # 2) Lifecycle policy (Archive after 91 days) — via Az.Storage cmdlets
  # --------------------------------------------------------------------
  Write-Host "📦 Applying lifecycle policy (Archive after 91 days)..." -ForegroundColor Cyan

  # Build the action: move base blobs to Archive after 91 days
  $action = Add-AzStorageAccountManagementPolicyAction `
    -BaseBlobAction TierToArchive `
    -DaysAfterModificationGreaterThan 91

  # Scope the rule to the three containers (prefixes are container roots)
  $filter = New-AzStorageAccountManagementPolicyFilter `
    -PrefixMatch "audit-activity","audit-resource","audit-entra" `
    -BlobType blockBlob

  # Create the rule object
  $rule = New-AzStorageAccountManagementPolicyRule `
    -Name "archive-after-91" `
    -Action $action `
    -Filter $filter

  # Apply (create or update) the policy on the storage account
  Set-AzStorageAccountManagementPolicy `
    -ResourceGroupName $ResourceGroupName `
    -StorageAccountName $StorageAccountName `
    -Rule $rule | Out-Null

  # Verify & capture names for summary (portal-visible)
  $pol = Get-AzStorageAccountManagementPolicy `
    -ResourceGroupName $ResourceGroupName `
    -StorageAccountName $StorageAccountName -ErrorAction SilentlyContinue

  if ($pol -and $pol.Rules) {
    $ruleNames = ($pol.Rules | ForEach-Object { $_.Name }) -join ", "
  } else {
    $ruleNames = "(none found)"
  }

  # --------------------------------------------------------------------
  # 3) Action Group (email) via ARM REST
  # --------------------------------------------------------------------
  Write-Host "📣 Creating/ensuring Action Group for notifications (REST)..." -ForegroundColor Cyan
  $actionGroupName = "ag-audit-ops"
  $shortName       = "auditops"
  $agResourceId    = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.insights/actionGroups/$actionGroupName"

  $agPayload = @"
{
  "location": "Global",
  "properties": {
    "groupShortName": "$shortName",
    "enabled": true,
    "emailReceivers": [
      { "name": "OpsEmail", "emailAddress": "$NotificationEmail", "useCommonAlertSchema": true }
    ]
  }
}
"@
  Invoke-AzRestMethod -Method PUT -Path "$agResourceId?api-version=2023-01-01" -Payload $agPayload | Out-Null

  # --------------------------------------------------------------------
  # 4) Activity Log alerts (diag settings write/delete) via REST
  # --------------------------------------------------------------------
  Write-Host "🚨 Creating Activity Log alerts for diagnostic setting updates/deletions (REST)..." -ForegroundColor Cyan
  function Ensure-ActivityLogAlertRest {
    param([string] $AlertName, [string] $OperationNameValue, [string] $Description)
    $alertId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.insights/activityLogAlerts/$AlertName"
@"
{
  "location": "$Location",
  "properties": {
    "enabled": true,
    "scopes": ["/subscriptions/$SubscriptionId"],
    "condition": { "allOf": [ { "field": "operationName", "equals": "$OperationNameValue" } ] },
    "actions": { "actionGroups": [ { "actionGroupId": "$agResourceId" } ] },
    "description": "$Description"
  }
}
"@ | ForEach-Object {
      Invoke-AzRestMethod -Method PUT -Path "$alertId?api-version=2021-09-01" -Payload $_ | Out-Null
    }
  }
  Ensure-ActivityLogAlertRest -AlertName "ala-diagsetting-updated" -OperationNameValue "Microsoft.Insights/diagnosticSettings/write"  -Description "Diagnostic setting created or updated"
  Ensure-ActivityLogAlertRest -AlertName "ala-diagsetting-deleted" -OperationNameValue "Microsoft.Insights/diagnosticSettings/delete" -Description "Diagnostic setting deleted"

  # --------------------------------------------------------------------
  # 5) Subscription Activity Logs -> Storage (via REST)
  # --------------------------------------------------------------------
  Write-Host "📝 Enabling Diagnostic Settings for Subscription Activity Logs -> Storage (REST)..." -ForegroundColor Cyan
  $subResourceId = "/subscriptions/$SubscriptionId"
  $dsName        = "ds-activity-to-storage"
  $dsResourceId  = "$subResourceId/providers/microsoft.insights/diagnosticSettings/$dsName"

  $categories = @("Administrative","Policy","Security","ServiceHealth","Alert","Recommendation","Autoscale","ResourceHealth")
  $logsArray = @(); foreach ($cat in $categories) { $logsArray += @{ category = $cat; enabled = $true } }

  $dsPayload = @{ properties = @{ storageAccountId = $st.Id; logs = $logsArray; metrics = @(@{ category = "AllMetrics"; enabled = $true; timeGrain = "PT1M" }) } } | ConvertTo-Json -Depth 8
  Invoke-AzRestMethod -Method PUT -Path "$dsResourceId?api-version=2021-05-01-preview" -Payload $dsPayload | Out-Null

  # --------------------------------------------------------------------
  # 6) Microsoft Entra Logs -> Storage (via REST)
  # --------------------------------------------------------------------
  Write-Host "🔐 Enabling Microsoft Entra (Azure AD) Audit/Sign-in logs -> Storage..." -ForegroundColor Cyan
  $entraDiagName   = "ds-entra-to-storage"
  $entraResourceId = "/providers/microsoft.aadiam/diagnosticSettings/$entraDiagName"
  $entraApiVersion = "2021-05-01-preview"

  $entraPayload = @"
{
  "properties": {
    "storageAccountId": "$($st.Id)",
    "logs": [
      { "category": "AuditLogs", "enabled": true },
      { "category": "SignInLogs", "enabled": true },
      { "category": "NonInteractiveUserSignInLogs", "enabled": true },
      { "category": "ServicePrincipalSignInLogs", "enabled": true },
      { "category": "ManagedIdentitySignInLogs", "enabled": true },
      { "category": "ProvisioningLogs", "enabled": true }
    ],
    "metrics": []
  }
}
"@
  Invoke-AzRestMethod -Method PUT -Path "$entraResourceId?api-version=$entraApiVersion" -Payload $entraPayload | Out-Null

  # --------------------------------------------------------------------
  # Summary
  # --------------------------------------------------------------------
  Write-Host ""
  Write-Host "✅ Setup completed successfully!" -ForegroundColor Green
  Write-Host ("   Resource Group        : {0}" -f $ResourceGroupName)
  Write-Host ("   Storage Account       : {0}" -f $StorageAccountName)
  Write-Host ("   Region                : {0}" -f $Location)
  Write-Host ("   SKU                   : {0}" -f $SkuName)
  Write-Host ("   Lifecycle Rules       : {0}" -f $ruleNames)
  Write-Host ("   Action Group (email)  : {0}" -f $NotificationEmail)
  Write-Host ("   Alerts created        : Diagnostic write/delete (Activity Log)")
  Write-Host ("   Sub Activity Logs DS  : Enabled (via REST)")
  Write-Host ("   Entra Logs DS         : Enabled (Audit, Sign-in, etc.)")
  Write-Host ""

} catch {
  Write-Host "❌ Error: $($_.Exception.Message)" -ForegroundColor Red
  throw
}