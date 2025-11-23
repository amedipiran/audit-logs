[CmdletBinding(PositionalBinding=$false)]
param(
  [Parameter(Mandatory)] [string] $TenantId,
  [Parameter(Mandatory)] [string] $NotificationEmail,

  [ValidateSet('westeurope','northeurope','swedencentral','uksouth','ukwest','francecentral','germanywestcentral','switzerlandnorth','eastus','eastus2','centralus','westus','westus2','westus3')]
  [string] $Location = 'swedencentral',

  [string] $ResourceGroup = 'rg-audit-log-exec',
  [string] $ContainerName = 'audit',

  [int] $DaysToArchive = 91,

  [int] $DaysToDelete  = 91,

  # Built zip from build-audit-zip.ps1
  [string] $ZipPath = '.\audit-timer.zip'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$ConfirmPreference     = 'None'
$PSDefaultParameterValues['*:Confirm'] = $false

function Initialize-Modules {
  $mods = @(
    'Az.Accounts','Az.Resources','Az.Storage','Az.Monitor',
    'Az.Functions','Az.Websites','Az.ApplicationInsights','Az.OperationalInsights'
  )
  $need = @()
  foreach($m in $mods){
    if(-not (Get-Module -ListAvailable -Name $m)){
      $need += $m
    }
  }
  if($need){
    Install-Module -Name $need -Scope CurrentUser -Force -AllowClobber
  }
  foreach($m in $mods){
    Import-Module $m -ErrorAction Stop
  }
}

function Get-ShortHash([string]$s){
  [BitConverter]::ToString(
    (New-Object Security.Cryptography.SHA1Managed).ComputeHash([Text.Encoding]::UTF8.GetBytes($s))
  ).Replace('-','').Substring(0,8).ToLower()
}

function Get-StableStorageName([string]$subId){
  $raw = ('stauditlogexec' + (Get-ShortHash $subId)).ToLower()
  if($raw.Length -gt 24){
    $raw = $raw.Substring(0,24)
  }
  $raw
}

function Get-StableFuncName([string]$subId){
  "fn-audit-log-exec-" + (Get-ShortHash $subId)
}

function Register-Provider([string]$ns){
  $rp = Get-AzResourceProvider -ProviderNamespace $ns -ErrorAction SilentlyContinue
  if(-not $rp -or $rp.RegistrationState -ne 'Registered'){
    Register-AzResourceProvider -ProviderNamespace $ns | Out-Null
  }
}

function Get-ResourceGroup([string]$name,[string]$loc){
  $rg = Get-AzResourceGroup -Name $name -ErrorAction SilentlyContinue
  if(-not $rg){
    $rg = New-AzResourceGroup -Name $name -Location $loc
  }
  $rg
}

function Get-StorageAccount([string]$rg,[string]$loc,[string]$name,[bool]$AllowSharedKey = $false){
  $st = Get-AzStorageAccount -ResourceGroupName $rg -Name $name -ErrorAction SilentlyContinue
  if($st){ return $st }

  New-AzStorageAccount `
    -ResourceGroupName $rg -Name $name -Location $loc `
    -SkuName 'Standard_GRS' -Kind StorageV2 -EnableHierarchicalNamespace $true `
    -AllowBlobPublicAccess $false -AllowSharedKeyAccess $AllowSharedKey -MinimumTlsVersion TLS1_2 | Out-Null

  Get-AzStorageAccount -ResourceGroupName $rg -Name $name
}

function Set-ContainerAAD($stName,[string]$container){
  $ctx = New-AzStorageContext -StorageAccountName $stName -UseConnectedAccount
  if(-not (Get-AzStorageContainer -Context $ctx -Name $container -ErrorAction SilentlyContinue)){
    New-AzStorageContainer -Name $container -Context $ctx -Permission Off | Out-Null
  }
}

function Set-LifecycleArchivePolicy([string]$rg,[string]$stName,[string]$prefix){
  $deleteAfter = $DaysToArchive + $DaysToDelete

  $action = Add-AzStorageAccountManagementPolicyAction `
    -BaseBlobAction TierToArchive `
    -DaysAfterModificationGreaterThan $DaysToArchive

  $action = Add-AzStorageAccountManagementPolicyAction `
    -InputObject $action `
    -BaseBlobAction Delete `
    -DaysAfterModificationGreaterThan $deleteAfter

  $filter = New-AzStorageAccountManagementPolicyFilter `
    -PrefixMatch @("$prefix/") `
    -BlobType blockBlob

  $ruleName = "archive-$DaysToArchive-delete-$deleteAfter"

  $rule = New-AzStorageAccountManagementPolicyRule `
    -Name   $ruleName `
    -Action $action `
    -Filter $filter

  Set-AzStorageAccountManagementPolicy `
    -ResourceGroupName  $rg `
    -StorageAccountName $stName `
    -Rule $rule | Out-Null
}

function Enable-SubscriptionActivityLogsToStorage([string]$subscriptionId,[string]$stResourceId){
  $scope = "/subscriptions/$subscriptionId"
  $path  = "$scope/providers/microsoft.insights/diagnosticSettings/ds-activity-to-storage?api-version=2021-05-01-preview"

  $categories = @(
    'Administrative','Policy','Security','ServiceHealth',
    'Alert','Recommendation','Autoscale','ResourceHealth'
  )

  $payload = @{
    properties = @{
      storageAccountId = $stResourceId
      logs    = ($categories | ForEach-Object { @{ category = $_; enabled = $true } })
      metrics = @(
        @{
          category  = 'AllMetrics'
          enabled   = $true
          timeGrain = 'PT1M'
        }
      )
    }
  } | ConvertTo-Json -Depth 8

  Invoke-AzRestMethod -Method PUT -Path $path -Payload $payload | Out-Null
}

function Set-ActionGroup([string]$homeSubId,[string]$rg,[string]$email){
  $id = "/subscriptions/$homeSubId/resourceGroups/$rg/providers/microsoft.insights/actionGroups/ag-audit-email"

  $payload = @{
    location   = 'global'
    properties = @{
      groupShortName = 'audit'
      enabled        = $true
      emailReceivers = @(@{
        name                 = 'default'
        emailAddress         = $email
        useCommonAlertSchema = $true
      })
    }
  } | ConvertTo-Json -Depth 8

  Invoke-AzRestMethod -Method PUT -Path ($id + '?api-version=2021-09-01') -Payload $payload | Out-Null
  return $id
}

Import-Module Az.Monitor -Force

function Set-AuditFailureAlert([string]$homeSubId,[string]$rg,[string]$fnName,[string]$actionGroupId){
  $alertName = 'audit-fn-failures'
  $scope     = "/subscriptions/$homeSubId"
  $fnResourceId = "/subscriptions/$homeSubId/resourceGroups/$rg/providers/Microsoft.Web/sites/$fnName"

  Write-Host "---- Creating Activity Log Alert (cmdlet) ----"
  Write-Host "AlertName:  $alertName"
  Write-Host "Scope:      $scope"
  Write-Host "FunctionId: $fnResourceId"
  Write-Host "ActionGrp:  $actionGroupId"
  Write-Host "----------------------------------------------"

  $ag = New-AzActivityLogAlertActionGroupObject -Id $actionGroupId

  $condCategory = New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject `
    -Field "category" `
    -Equal "Administrative"

  $condStatus = New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject `
    -Field "status" `
    -Equal "Failed"

  $condResource = New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject `
    -Field "resourceId" `
    -Equal $fnResourceId

  $result = New-AzActivityLogAlert `
    -Name $alertName `
    -ResourceGroupName $rg `
    -Location "global" `
    -Scope @($scope) `
    -Action @($ag) `
    -Condition @($condCategory, $condStatus, $condResource) `
    -Enabled $true `
    -Description "Alert on failed management operations for the audit Function App"

  Write-Host "✅ Activity Log Alert created."
  Write-Host "Result Id: $($result.Id)"
}

function New-FlexFunctionApp([string]$homeSubId,[string]$rg,[string]$name,[string]$loc){
  $siteId = "/subscriptions/$homeSubId/resourceGroups/$rg/providers/Microsoft.Web/sites/$name"
  $payload = @{
    location   = $loc
    kind       = "functionapp,linux,containerapp"
    properties = @{
      siteConfig = @{ linuxFxVersion = "" }
      httpsOnly  = $true
    }
    sku = @{
      name = "FC1"
      tier = "FlexConsumption"
    }
  } | ConvertTo-Json -Depth 12

  Invoke-AzRestMethod -Method PUT   -Path ($siteId + "?api-version=2023-12-01") -Payload $payload | Out-Null
  Invoke-AzRestMethod -Method PATCH -Path ($siteId + "?api-version=2023-12-01") `
    -Payload (@{ identity = @{ type = "SystemAssigned" } } | ConvertTo-Json) | Out-Null

  Update-AzFunctionAppSetting -Name $name -ResourceGroupName $rg -AppSetting @{
    'FUNCTIONS_WORKER_RUNTIME'      = 'powershell'
    'FUNCTIONS_EXTENSION_VERSION'   = '~4'
    'WEBSITE_TIME_ZONE'             = 'W. Europe Standard Time'
    'AzureWebJobsSecretStorageType' = 'files'
  } -Force | Out-Null

  Get-AzWebApp -Name $name -ResourceGroupName $rg
}

function New-ClassicFunctionApp([string]$rg,[string]$name,[string]$loc,[string]$storageName){
  $app = New-AzFunctionApp -Name $name -ResourceGroupName $rg -Location $loc `
          -StorageAccountName $storageName -OSType Linux -Runtime PowerShell -RuntimeVersion 7.4 -FunctionsVersion 4

  Update-AzFunctionAppSetting -Name $name -ResourceGroupName $rg -AppSetting @{
    'WEBSITE_RUN_FROM_PACKAGE'      = '1'
    'AzureWebJobsSecretStorageType' = 'files'
  } -Force | Out-Null

  $app
}

function Grant-RoleAssignment(
  [string]$objectId,
  [string]$scope,
  [string]$role,
  [string]$subscriptionName = $null  # optional, for nicer warnings
){
  if ([string]::IsNullOrWhiteSpace($objectId)) {
    Write-Error "Grant-RoleAssignment: objectId is empty for scope '$scope' and role '$role'"
    return
  }

  Write-Host "Grant-RoleAssignment: scope='$scope', role='$role', objectId='$objectId'"

  $exists = Get-AzRoleAssignment `
    -ObjectId $objectId `
    -Scope $scope `
    -RoleDefinitionName $role `
    -ErrorAction SilentlyContinue

  if ($exists) {
    Write-Host "  -> Role '$role' already assigned on '$scope'"
    return
  }

  try {
    New-AzRoleAssignment `
      -ObjectId $objectId `
      -Scope $scope `
      -RoleDefinitionName $role `
      -ErrorAction Stop | Out-Null

    Write-Host "  -> Role '$role' granted on '$scope'"
  }
  catch {

    $details   = $null
    $fullText  = $_.Exception.Message
    if ($_.Exception.Response -and $_.Exception.Response.Content) {
      $details  = $_.Exception.Response.Content
      $fullText = $fullText + " " + $details
    }

    $subIdFromScope = $null
    if ($scope -match "/subscriptions/([^/]+)") {
      $subIdFromScope = $Matches[1]
    }

    $label = if ($subscriptionName -and $subIdFromScope) {
      "$subscriptionName ($subIdFromScope)"
    } elseif ($subIdFromScope) {
      $subIdFromScope
    } else {
      $scope
    }

    if ($fullText -like "*Forbidden*" -or $fullText -like "*AuthorizationFailed*") {
      Write-Warning @"
Skipping role assignment '$role' on subscription $label.
Reason: The current user/service principal does not have permission to assign roles here.
To use this audit service for this subscription, your account must have 'Owner'
(or a role with 'Microsoft.Authorization/roleAssignments/write', e.g. 'User Access Administrator')
on the subscription. This subscription will be skipped, the rest of the deployment continues.
"@

      return
    }

    Write-Error ("  -> Failed to grant role '{0}' on '{1}': {2}" -f $role, $scope, $_.Exception.Message)
    if ($details) {
      Write-Host "  -> Details: $details"
    }
    throw
  }
}

function Get-PublishingBasicAuth([string]$rg,[string]$name){
  $pp = Join-Path ([IO.Path]::GetTempPath()) ("pp-" + [guid]::NewGuid() + ".xml")
  try{
    Get-AzWebAppPublishingProfile -ResourceGroupName $rg -Name $name -Format WebDeploy -OutputFile $pp | Out-Null
    [xml]$xml = Get-Content -LiteralPath $pp
    $pub  = $xml.publishData.publishProfile | Where-Object { $_.publishMethod -eq 'MSDeploy' } | Select-Object -First 1
    $b64  = [Convert]::ToBase64String(
      [Text.Encoding]::ASCII.GetBytes("$($pub.userName)`:$($pub.userPWD)")
    )
    return @{ Authorization = "Basic $b64" }
  } finally {
    Remove-Item $pp -Force -ErrorAction SilentlyContinue
  }
}

function ZipDeploy([string]$rg,[string]$name,[string]$zipPath){
  $hdr = Get-PublishingBasicAuth -rg $rg -name $name
  $uri = "https://$name.scm.azurewebsites.net/api/zipdeploy?isAsync=true"
  Invoke-RestMethod -Headers $hdr -Method POST -Uri $uri -InFile $zipPath -ContentType "application/zip" | Out-Null
  return $hdr
}

function Wait-LatestDeployment([hashtable]$hdr,[string]$name,[int]$timeoutSec=600){
  $uri = "https://$name.scm.azurewebsites.net/api/deployments/latest"
  $sw  = [Diagnostics.Stopwatch]::StartNew()
  while($sw.Elapsed.TotalSeconds -lt $timeoutSec){
    $d = Invoke-RestMethod -Headers $hdr -Uri $uri -Method GET -ErrorAction SilentlyContinue
    if($d -and $d.status -eq 4){
      return $true
    }
    Start-Sleep -Seconds 3
  }
  return $false
}

function Sync-FunctionTriggers([string]$sub,[string]$rg,[string]$name){
  $api = "2024-11-01"
  az rest --method post --only-show-errors `
    --url "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Web/sites/$name/syncfunctiontriggers?api-version=$api" | Out-Null
}

function Add-PortalCors([string]$rg,[string]$fn){
  az functionapp cors add -g $rg -n $fn --allowed-origins https://portal.azure.com    | Out-Null
  az functionapp cors add -g $rg -n $fn --allowed-origins https://ms.portal.azure.com | Out-Null
}

function Get-HostKeys([string]$sub,[string]$rg,[string]$fn){
  $api     = "2024-11-01"
  $listUrl = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Web/sites/$fn/host/default/listkeys?api-version=$api"

  $tryList = {
    try {
      $res = az rest --method post --only-show-errors --url $listUrl --output json
      if($LASTEXITCODE -eq 0 -and $res){
        $obj = $res | ConvertFrom-Json
        if($obj.masterKey){ return $obj }
      }
    } catch { }
    return $null
  }

  $keys = & $tryList
  if($keys){ return $keys }

  # warmup
  Sync-FunctionTriggers -sub $sub -rg $rg -name $fn
  az webapp restart -g $rg -n $fn | Out-Null
  Start-Sleep -Seconds 10

  $keys = & $tryList
  if($keys){ return $keys }

  # Create a master key if missing
  $newKey = -join ((48..57+65..90+97..122) | Get-Random -Count 64 | ForEach-Object { [char]$_ })
  $setUrl = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Web/sites/$fn/host/default/setmasterkey?api-version=$api"

  try {
    az rest --method post --only-show-errors --url $setUrl --body ("{`"properties`":{`"masterKey`":`"$newKey`"}}") | Out-Null
  } catch { }

  Start-Sleep -Seconds 5
  $keys = & $tryList
  if($keys){ return $keys }

  Write-Warning "Host keys still unavailable after init attempts."
  return $null
}

function Set-LogAnalyticsWorkspace([string]$rg,[string]$loc,[string]$name){
  $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $rg -Name $name -ErrorAction SilentlyContinue
  if(-not $ws){
    $ws = New-AzOperationalInsightsWorkspace -ResourceGroupName $rg -Name $name -Location $loc -Sku PerGB2018
  }
  return $ws
}

function Set-AppInsights([string]$rg,[string]$loc,[string]$name,[string]$workspaceResourceId){
  $ai = Get-AzApplicationInsights -ResourceGroupName $rg -Name $name -ErrorAction SilentlyContinue
  if(-not $ai){
    $ai = New-AzApplicationInsights `
      -ResourceGroupName $rg `
      -Name $name `
      -Location $loc `
      -WorkspaceResourceId $workspaceResourceId `
      -Kind web
  }
  return $ai
}

# ------------------- EXECUTION -------------------

Initialize-Modules

try { Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue } catch {}
try { Clear-AzContext    -Scope Process -Force -ErrorAction SilentlyContinue } catch {}
Disable-AzContextAutosave -Scope Process | Out-Null

Connect-AzAccount -Tenant $TenantId | Out-Null

$allSubs = Get-AzSubscription -TenantId $TenantId |
  Where-Object { $_.State -eq 'Enabled' } |
  Sort-Object -Property Name

if(-not $allSubs){
  throw "No Enabled subscriptions in tenant $TenantId"
}

Write-Host ""
Write-Host "Available subscriptions in tenant $TenantId" -ForegroundColor Cyan
for($i = 0; $i -lt $allSubs.Count; $i++){
  "{0,3}. {1,-44} {2}" -f ($i+1), $allSubs[$i].Name, $allSubs[$i].Id | Write-Host
}

$pick = Read-Host "Select a subscription number"
if(-not ($pick -as [int]) -or $pick -lt 1 -or $pick -gt $allSubs.Count){
  throw "Invalid selection."
}

$chosen   = $allSubs[$pick-1]
$HomeSubId = $chosen.Id

Set-AzContext -SubscriptionId $chosen.Id -Tenant $TenantId | Out-Null
try {
  az account clear --only-show-errors | Out-Null
  az login --tenant $TenantId --use-device-code --only-show-errors 1>$null
  az account set --subscription $chosen.Id --only-show-errors | Out-Null
} catch {}

Write-Host "🏠 Deployment subscription (chosen): $($chosen.Name) ($HomeSubId)"

'Microsoft.Web','Microsoft.Storage','Microsoft.Insights','Microsoft.OperationalInsights' |
  ForEach-Object { Register-Provider $_ }

Get-ResourceGroup -name $ResourceGroup -loc $Location | Out-Null

$stName = Get-StableStorageName -subId $HomeSubId
$st     = Get-StorageAccount -rg $ResourceGroup -loc $Location -name $stName -AllowSharedKey:$false

Set-ContainerAAD          -stName $st.StorageAccountName -container $ContainerName
Set-LifecycleArchivePolicy -rg $ResourceGroup -stName $st.StorageAccountName -prefix $ContainerName

$actionGroupId = Set-ActionGroup -homeSubId $HomeSubId -rg $ResourceGroup -email $NotificationEmail

# Raw activity logs from azure
<# foreach($s in $allSubs){
  try {
    Enable-SubscriptionActivityLogsToStorage -subscriptionId $s.Id -stResourceId $st.Id
    Write-Host "📝 Activity Logs → Storage enabled for $($s.Name)"
  } catch {
    Write-Warning "Failed enabling diagnostics on $($s.Name): $($_.Exception.Message)"
  }
} #>

$fnName = Get-StableFuncName -subId $HomeSubId
Write-Host "🔧 Creating FLEX Function App..."

try {
  New-FlexFunctionApp -homeSubId $HomeSubId -rg $ResourceGroup -name $fnName -loc $Location | Out-Null
  Write-Host "⚙️  Flex Function App created: $fnName"
} catch {
  Write-Warning "Flex create failed: $($_.Exception.Message)"
  Write-Warning "Falling back to Linux Consumption…"

  $funcStName = ("stfunc" + (Get-ShortHash $HomeSubId)).ToLower()
  if($funcStName.Length -gt 24){
    $funcStName = $funcStName.Substring(0,24)
  }

  $funcSt = Get-StorageAccount -rg $ResourceGroup -loc $Location -name $funcStName -AllowSharedKey:$true
  New-ClassicFunctionApp -rg $ResourceGroup -name $fnName -loc $Location -storageName $funcSt.StorageAccountName | Out-Null

  Write-Host "⚙️  Linux Consumption Function App created: $fnName"
}

$siteNow = Get-AzWebApp -Name $fnName -ResourceGroupName $ResourceGroup
if(-not $siteNow.Identity -or $siteNow.Identity.Type -ne 'SystemAssigned'){
  Set-AzWebApp -Name $fnName -ResourceGroupName $ResourceGroup -AssignIdentity $true | Out-Null
  $siteNow = Get-AzWebApp -Name $fnName -ResourceGroupName $ResourceGroup
}
$miPrincipalId = $siteNow.Identity.PrincipalId

Update-AzFunctionAppSetting -Name $fnName -ResourceGroupName $ResourceGroup -AppSetting @{
  'AUDIT_RG'          = $ResourceGroup
  'AUDIT_ST_ACCOUNT'  = $st.StorageAccountName
  'AUDIT_CONTAINER'   = $ContainerName
  'AUDIT_PREFIX'      = 'AzActivity'
  'AUDIT_HOME_SUB'    = $HomeSubId
  'AUDIT_TENANT_ID'   = $TenantId
  'WEBSITE_TIME_ZONE' = 'W. Europe Standard Time'
} -Force | Out-Null

Update-AzFunctionAppSetting -ResourceGroupName $ResourceGroup -Name $fnName -AppSetting @{
  "AzureWebJobsStorage__blobServiceUri"   = "https://$($st.StorageAccountName).blob.core.windows.net"
  "AzureWebJobsStorage__queueServiceUri"  = "https://$($st.StorageAccountName).queue.core.windows.net"
  "AzureWebJobsStorage__credential"       = "managedidentity"
} -Force | Out-Null

$stScope = "/subscriptions/$HomeSubId/resourceGroups/$ResourceGroup/providers/Microsoft.Storage/storageAccounts/$($st.StorageAccountName)"
Grant-RoleAssignment -objectId $miPrincipalId -scope $stScope -role 'Storage Blob Data Contributor'

foreach($s in $allSubs){
  $scope = "/subscriptions/$($s.Id)"

  Grant-RoleAssignment -objectId $miPrincipalId `
                       -scope $scope `
                       -role 'Reader' `
                       -subscriptionName $s.Name

  Grant-RoleAssignment -objectId $miPrincipalId `
                       -scope $scope `
                       -role 'Monitoring Reader' `
                       -subscriptionName $s.Name
}

$wsName = "law-audit"
$aiName = "appi-" + $fnName

$ws = Set-LogAnalyticsWorkspace -rg $ResourceGroup -loc $Location -name $wsName
$ai = Set-AppInsights         -rg $ResourceGroup -loc $Location -name $aiName -workspaceResourceId $ws.ResourceId

if($ai.ConnectionString){
  Update-AzFunctionAppSetting -Name $fnName -ResourceGroupName $ResourceGroup -AppSetting @{
    'APPLICATIONINSIGHTS_CONNECTION_STRING'   = $ai.ConnectionString
    'APPINSIGHTS_PROFILERFEATURE_VERSION'     = '1.0.0'
    'APPINSIGHTS_SNAPSHOTFEATURE_VERSION'     = '1.0.0'
    'DiagnosticServices_EXTENSION_VERSION'    = '~3'
    'XDT_MicrosoftApplicationInsights_Mode'   = 'recommended'
  } -Force | Out-Null
}

Add-PortalCors -rg $ResourceGroup -fn $fnName

Set-AuditFailureAlert -homeSubId $HomeSubId -rg $ResourceGroup -fnName $fnName -actionGroupId $actionGroupId

if(-not (Test-Path $ZipPath)){
  throw "Zip not found: $ZipPath. Run build-audit-zip.ps1 first."
}

$hdr = ZipDeploy -rg $ResourceGroup -name $fnName -zipPath $ZipPath
if(-not (Wait-LatestDeployment -hdr $hdr -name $fnName -timeoutSec 600)){
  throw "ZipDeploy did not reach Success within timeout."
}

$currSub = (Get-AzContext).Subscription.Id
Sync-FunctionTriggers -sub $currSub -rg $ResourceGroup -name $fnName
az webapp restart -g $ResourceGroup -n $fnName | Out-Null

$keys = Get-HostKeys -sub $currSub -rg $ResourceGroup -fn $fnName
if($keys -and $keys.masterKey){
  Write-Host "✅ Host master key is available." -ForegroundColor Green
} else {
  Write-Warning "Host keys not reported by ARM; the function will still run, but the Portal Keys blade may lag briefly."
}

Write-Host ""
Write-Host "✅ Deployment complete" -ForegroundColor Green
Write-Host "Function App:   $fnName  (RG: $ResourceGroup)"
Write-Host "Storage:        $($st.StorageAccountName)  (RG: $ResourceGroup)  Container: $ContainerName"
Write-Host "App Insights:   $aiName  (RG: $ResourceGroup)"
Write-Host "Workspace:      $wsName  (RG: $ResourceGroup)"
Write-Host "MI ObjectId:    $miPrincipalId"