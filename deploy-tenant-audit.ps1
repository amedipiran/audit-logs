# deploy-tenant-audit.ps1 — PowerShell 7+
[CmdletBinding(PositionalBinding=$false)]
param(
  # Mandatory: scope sign-in to this tenant
  [Parameter(Mandatory)] [string] $TenantId,

  [Parameter(Mandatory)] [string] $NotificationEmail,

  [ValidateSet('westeurope','northeurope','swedencentral','uksouth','ukwest','francecentral','germanywestcentral','switzerlandnorth','eastus','eastus2','centralus','westus','westus2','westus3')]
  [string] $Location = 'swedencentral',

  [string] $ArchiveResourceGroup = 'rg-audit-archive',
  [string] $JobsResourceGroup = 'rg-audit-jobs',
  [string] $ContainerName = 'audit',

  # Built zip from build-audit-zip.ps1
  [string] $ZipPath = '.\audit-timer.zip'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$ConfirmPreference     = 'None'
$PSDefaultParameterValues['*:Confirm'] = $false

function Initialize-Modules {
  $mods = @('Az.Accounts','Az.Resources','Az.Storage','Az.Monitor',
            'Az.Functions','Az.Websites','Az.ApplicationInsights','Az.OperationalInsights')
  $need = @()
  foreach($m in $mods){ if(-not (Get-Module -ListAvailable -Name $m)){ $need += $m } }
  if($need){ Install-Module -Name $need -Scope CurrentUser -Force -AllowClobber }
  foreach($m in $mods){ Import-Module $m -ErrorAction Stop }
}

function Get-ShortHash([string]$s){
  [BitConverter]::ToString(
    (New-Object Security.Cryptography.SHA1Managed).ComputeHash([Text.Encoding]::UTF8.GetBytes($s))
  ).Replace('-','').Substring(0,8).ToLower()
}
function Get-StableStorageName([string]$subId){
  $raw=('staudit' + (Get-ShortHash $subId)).ToLower()
  if($raw.Length -gt 24){ $raw=$raw.Substring(0,24) }; $raw
}
function Get-StableFuncName([string]$subId){ "fn-audit-flex-" + (Get-ShortHash $subId) }

function Register-Provider([string]$ns){
  $rp = Get-AzResourceProvider -ProviderNamespace $ns -ErrorAction SilentlyContinue
  if(-not $rp -or $rp.RegistrationState -ne 'Registered'){
    Register-AzResourceProvider -ProviderNamespace $ns | Out-Null
  }
}

function Get-ResourceGroup([string]$name,[string]$loc){
  $rg = Get-AzResourceGroup -Name $name -ErrorAction SilentlyContinue
  if(-not $rg){ $rg = New-AzResourceGroup -Name $name -Location $loc }
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
  $action = Add-AzStorageAccountManagementPolicyAction -BaseBlobAction TierToArchive -DaysAfterModificationGreaterThan 91
  $filter = New-AzStorageAccountManagementPolicyFilter -PrefixMatch @("$prefix/") -BlobType blockBlob
  $rule   = New-AzStorageAccountManagementPolicyRule -Name 'archive-after-91' -Action $action -Filter $filter
  Set-AzStorageAccountManagementPolicy -ResourceGroupName $rg -StorageAccountName $stName -Rule $rule | Out-Null
}

function Enable-SubscriptionActivityLogsToStorage([string]$subscriptionId,[string]$stResourceId){
  $scope="/subscriptions/$subscriptionId"
  $dsName='ds-activity-to-storage'
  $path="$scope/providers/microsoft.insights/diagnosticSettings/$dsName?api-version=2021-05-01-preview"
  $categories=@('Administrative','Policy','Security','ServiceHealth','Alert','Recommendation','Autoscale','ResourceHealth')
  $payload=@{
    properties=@{
      storageAccountId=$stResourceId
      logs=($categories | ForEach-Object { @{category=$_;enabled=$true} })
      metrics=@(@{category='AllMetrics';enabled=$true;timeGrain='PT1M'})
    }
  } | ConvertTo-Json -Depth 8
  Invoke-AzRestMethod -Method PUT -Path $path -Payload $payload | Out-Null
}

function Set-ActionGroup([string]$homeSubId,[string]$rg,[string]$email){
  $id="/subscriptions/$homeSubId/resourceGroups/$rg/providers/microsoft.insights/actionGroups/ag-audit-email"
  $payload=@{
    location='global'
    properties=@{
      groupShortName='audit'
      enabled=$true
      emailReceivers=@(@{name='default';emailAddress=$email;useCommonAlertSchema=$true})
    }
  } | ConvertTo-Json -Depth 8
  Invoke-AzRestMethod -Method PUT -Path ($id + '?api-version=2021-09-01') -Payload $payload | Out-Null
}

function New-FlexFunctionApp([string]$homeSubId,[string]$rg,[string]$name,[string]$loc){
  $siteId="/subscriptions/$homeSubId/resourceGroups/$rg/providers/Microsoft.Web/sites/$name"
  $payload=@{
    location = $loc
    kind     = "functionapp,linux,containerapp"
    properties = @{
      siteConfig = @{ linuxFxVersion = "" }
      httpsOnly  = $true
    }
    sku = @{ name = "FC1"; tier = "FlexConsumption" }
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

function Grant-RoleAssignment([string]$objectId,[string]$scope,[string]$role){
  try{
    $exists = Get-AzRoleAssignment -ObjectId $objectId -Scope $scope -RoleDefinitionName $role -ErrorAction SilentlyContinue
    if(-not $exists){ New-AzRoleAssignment -ObjectId $objectId -Scope $scope -RoleDefinitionName $role | Out-Null }
    return $true
  } catch {
    Write-Warning "Role assignment failed: role='$role' scope='$scope' objectId='$objectId' : $($_.Exception.Message)"
    return $false
  }
}

function Get-PublishingBasicAuth([string]$rg,[string]$name){
  $pp  = Join-Path ([IO.Path]::GetTempPath()) ("pp-" + [guid]::NewGuid() + ".xml")
  try{
    Get-AzWebAppPublishingProfile -ResourceGroupName $rg -Name $name -Format WebDeploy -OutputFile $pp | Out-Null
    [xml]$xml = Get-Content -LiteralPath $pp
    $pub  = $xml.publishData.publishProfile | Where-Object { $_.publishMethod -eq 'MSDeploy' } | Select-Object -First 1
    $b64  = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($pub.userName)`:$($pub.userPWD)"))
    return @{ Authorization = "Basic $b64" }
  } finally { Remove-Item $pp -Force -ErrorAction SilentlyContinue }
}

function ZipDeploy([string]$rg,[string]$name,[string]$zipPath){
  $hdr = Get-PublishingBasicAuth -rg $rg -name $name
  $uri = "https://$name.scm.azurewebsites.net/api/zipdeploy?isAsync=true"
  Invoke-RestMethod -Headers $hdr -Method POST -Uri $uri -InFile $zipPath -ContentType "application/zip" | Out-Null
  return $hdr
}

function Wait-LatestDeployment([hashtable]$hdr,[string]$name,[int]$timeoutSec=600){
  $uri = "https://$name.scm.azurewebsites.net/api/deployments/latest"
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while($sw.Elapsed.TotalSeconds -lt $timeoutSec){
    $d = Invoke-RestMethod -Headers $hdr -Uri $uri -Method GET -ErrorAction SilentlyContinue
    if($d -and $d.status -eq 4){ return $true }  # 4 = Success
    Start-Sleep -Seconds 3
  }
  return $false
}

function Sync-FunctionTriggers([string]$sub,[string]$rg,[string]$name){
  $api="2024-11-01"
  az rest --method post --only-show-errors `
    --url "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Web/sites/$name/syncfunctiontriggers?api-version=$api" | Out-Null
}

function Add-PortalCors([string]$sub,[string]$rg,[string]$fn){
  az functionapp cors add -g $rg -n $fn --subscription $sub --allowed-origins https://portal.azure.com    | Out-Null
  az functionapp cors add -g $rg -n $fn --subscription $sub --allowed-origins https://ms.portal.azure.com | Out-Null
}

function Resolve-ClientIp {
  $cands = @(
    'https://api.ipify.org',
    'https://ifconfig.me'
  )
  foreach($u in $cands){
    try{
      $ip = (Invoke-RestMethod -Uri $u -Method GET -TimeoutSec 10).ToString().Trim()
      if($ip -match '^\d{1,3}(\.\d{1,3}){3}$'){ return $ip }
    } catch {}
  }
  Write-Warning "Could not resolve public client IP; continuing without client IP allow rule."
  return $null
}

function Ensure-AzCliSubscription([string]$subId){
  try{
    az account set --subscription $subId --only-show-errors | Out-Null
  } catch {
    Write-Warning "az account set failed for $subId ($($_.Exception.Message))"
  }
}

function Add-PortalNetworkAccess([string]$sub,[string]$rg,[string]$fn){
  Ensure-AzCliSubscription $sub

  az webapp config access-restriction add -g $rg -n $fn --subscription $sub `
    --rule-name "Allow-AzureCloud" --priority 100 --action Allow --service-tag AzureCloud `
    --only-show-errors 2>$null | Out-Null

  az webapp config access-restriction add -g $rg -n $fn --subscription $sub `
    --scm-site true --rule-name "Allow-AzureCloud-SCM" --priority 100 --action Allow --service-tag AzureCloud `
    --only-show-errors 2>$null | Out-Null

  $ip = Resolve-ClientIp
  if($ip){
    az webapp config access-restriction add -g $rg -n $fn --subscription $sub `
      --rule-name "Allow-ClientIP" --priority 90 --action Allow --ip-address "$ip/32" `
      --only-show-errors 2>$null | Out-Null

    az webapp config access-restriction add -g $rg -n $fn --subscription $sub `
      --scm-site true `
      --rule-name "Allow-ClientIP-SCM" --priority 90 --action Allow --ip-address "$ip/32" `
      --only-show-errors 2>$null | Out-Null
  }

  Update-AzFunctionAppSetting -Name $fn -ResourceGroupName $rg -AppSetting @{
    'SCM_BASIC_AUTH_DISABLED' = '0'
  } -Force | Out-Null
}

function Enable-AppLogStreaming([string]$sub,[string]$rg,[string]$fn){
  Ensure-AzCliSubscription $sub
  az webapp log config -g $rg -n $fn --subscription $sub `
    --application-logging filesystem --level information | Out-Null
}

function Get-HostKeys([string]$sub,[string]$rg,[string]$fn){
  $api="2024-11-01"
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

  Sync-FunctionTriggers -sub $sub -rg $rg -name $fn
  az webapp restart -g $rg -n $fn --subscription $sub | Out-Null
  Start-Sleep -Seconds 10

  $keys = & $tryList
  if($keys){ return $keys }

  $newKey = -join ((48..57+65..90+97..122) | Get-Random -Count 64 | % {[char]$_})
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

# Sign in
$ctx = Get-AzContext -ErrorAction SilentlyContinue
if(-not $ctx -or -not $ctx.Tenant -or $ctx.Tenant.Id -ne $TenantId){
  Connect-AzAccount -Tenant $TenantId | Out-Null
}

# Collect enabled subs in tenant
$subs = Get-AzSubscription -TenantId $TenantId | Where-Object { $_.State -eq 'Enabled' } | Sort-Object -Property Name
if(-not $subs){ throw "No Enabled subscriptions in tenant $TenantId" }

# Home sub for shared resources
$HomeSubId = $subs[0].Id
Set-AzContext -SubscriptionId $HomeSubId | Out-Null
Write-Host "🏠 Home subscription: $($subs[0].Name) ($HomeSubId)"

# Providers (home sub)
'Microsoft.Web','Microsoft.Storage','Microsoft.Insights','Microsoft.OperationalInsights' | ForEach-Object { Register-Provider $_ }

# Resource groups (home sub)
$rgArchive = Get-ResourceGroup -name $ArchiveResourceGroup -loc $Location
$rgJobs    = Get-ResourceGroup -name $JobsResourceGroup    -loc $Location

# Shared storage (home sub)
$stName = Get-StableStorageName -subId $HomeSubId
$st     = Get-StorageAccount -rg $ArchiveResourceGroup -loc $Location -name $stName -AllowSharedKey:$false
Set-ContainerAAD -stName $st.StorageAccountName -container $ContainerName
Set-LifecycleArchivePolicy -rg $ArchiveResourceGroup -stName $st.StorageAccountName -prefix $ContainerName

# Action group (home sub)
Set-ActionGroup -homeSubId $HomeSubId -rg $ArchiveResourceGroup -email $NotificationEmail

# Enable Subscription Activity Logs -> Storage on each sub
foreach($s in $subs){
  try{
    Enable-SubscriptionActivityLogsToStorage -subscriptionId $s.Id -stResourceId $st.Id
    Write-Host "📝 Activity Logs → Storage enabled for $($s.Name)"
  } catch { Write-Warning "Failed enabling diagnostics on $($s.Name): $($_.Exception.Message)" }
}

# Function App (home sub)
$fnName = Get-StableFuncName -subId $HomeSubId
Write-Host "🔧 Creating FLEX Function App..."
$site = $null
try {
  $site = New-FlexFunctionApp -homeSubId $HomeSubId -rg $JobsResourceGroup -name $fnName -loc $Location
  Write-Host "⚙️  Flex Function App created: $fnName"
} catch {
  Write-Warning "Flex create failed: $($_.Exception.Message)"
  Write-Warning "Falling back to Linux Consumption…"
  $funcStName = ("stfunc" + (Get-ShortHash $HomeSubId)).ToLower()
  if($funcStName.Length -gt 24){ $funcStName = $funcStName.Substring(0,24) }
  $funcSt = Get-StorageAccount -rg $JobsResourceGroup -loc $Location -name $funcStName -AllowSharedKey:$true
  $site = New-ClassicFunctionApp -rg $JobsResourceGroup -name $fnName -loc $Location -storageName $funcSt.StorageAccountName
  Write-Host "⚙️  Linux Consumption Function App created: $fnName"
}

# Ensure MSI
$siteNow = Get-AzWebApp -Name $fnName -ResourceGroupName $JobsResourceGroup
if(-not $siteNow.Identity -or $siteNow.Identity.Type -ne 'SystemAssigned'){
  Set-AzWebApp -Name $fnName -ResourceGroupName $JobsResourceGroup -AssignIdentity $true | Out-Null
  $siteNow = Get-AzWebApp -Name $fnName -ResourceGroupName $JobsResourceGroup
}
$miPrincipalId = $siteNow.Identity.PrincipalId

# App settings (job config)
Update-AzFunctionAppSetting -Name $fnName -ResourceGroupName $JobsResourceGroup -AppSetting @{
  'AUDIT_RG'          = $ArchiveResourceGroup
  'AUDIT_ST_ACCOUNT'  = $st.StorageAccountName
  'AUDIT_CONTAINER'   = $ContainerName
  'AUDIT_PREFIX'      = 'AzActivity'
  'AUDIT_HOME_SUB'    = $HomeSubId
  'AUDIT_TENANT_ID'   = $TenantId
  'WEBSITE_TIME_ZONE' = 'W. Europe Standard Time'
} -Force | Out-Null

# Use MI for AzureWebJobsStorage
Update-AzFunctionAppSetting -ResourceGroupName $JobsResourceGroup -Name $fnName -AppSetting @{
  "AzureWebJobsStorage__blobServiceUri" = "https://$($st.StorageAccountName).blob.core.windows.net"
  "AzureWebJobsStorage__queueServiceUri" = "https://$($st.StorageAccountName).queue.core.windows.net"
  "AzureWebJobsStorage__credential"      = "managedidentity"
} -Force | Out-Null

# Grant MI data access on archive storage (fails if role lacks permission)
$failedGrants = @()
$stScope = "/subscriptions/$HomeSubId/resourceGroups/$ArchiveResourceGroup/providers/Microsoft.Storage/storageAccounts/$($st.StorageAccountName)"
if(-not (Grant-RoleAssignment -objectId $miPrincipalId -scope $stScope -role 'Storage Blob Data Contributor')){
  $failedGrants += "Storage Blob Data Contributor@$stScope"
}

# Reader/Monitoring Reader on every subscription (continue on forbidden)
foreach($s in $subs){
  $scope="/subscriptions/$($s.Id)"
  $ok1 = Grant-RoleAssignment -objectId $miPrincipalId -scope $scope -role 'Reader'
  $ok2 = Grant-RoleAssignment -objectId $miPrincipalId -scope $scope -role 'Monitoring Reader'
  if(-not ($ok1 -and $ok2)){ $failedGrants += "$($s.Id):Reader+MonitoringReader" }
}

# Observability
$wsName  = "law-audit"
$aiName  = "appi-" + $fnName
$ws = Set-LogAnalyticsWorkspace -rg $JobsResourceGroup -loc $Location -name $wsName
$ai = Set-AppInsights         -rg $JobsResourceGroup -loc $Location -name $aiName -workspaceResourceId $ws.ResourceId
if($ai.ConnectionString){
  Update-AzFunctionAppSetting -Name $fnName -ResourceGroupName $JobsResourceGroup -AppSetting @{
    'APPLICATIONINSIGHTS_CONNECTION_STRING' = $ai.ConnectionString
    'APPINSIGHTS_PROFILERFEATURE_VERSION'   = '1.0.0'
    'APPINSIGHTS_SNAPSHOTFEATURE_VERSION'   = '1.0.0'
    'DiagnosticServices_EXTENSION_VERSION'  = '~3'
    'XDT_MicrosoftApplicationInsights_Mode' = 'recommended'
  } -Force | Out-Null
}

# Cors for testing
Add-PortalCors          -sub $HomeSubId -rg $JobsResourceGroup -fn $fnName
Add-PortalNetworkAccess -sub $HomeSubId -rg $JobsResourceGroup -fn $fnName
Enable-AppLogStreaming  -sub $HomeSubId -rg $JobsResourceGroup -fn $fnName

# Deploy code
if(-not (Test-Path $ZipPath)){ throw "Zip not found: $ZipPath. Run build-audit-zip.ps1 first." }
$hdr = ZipDeploy -rg $JobsResourceGroup -name $fnName -zipPath $ZipPath
if(-not (Wait-LatestDeployment -hdr $hdr -name $fnName -timeoutSec 600)){
  throw "ZipDeploy did not reach Success within timeout."
}

# Warmup & keys
$currSub = (Get-AzContext).Subscription.Id
Sync-FunctionTriggers -sub $currSub -rg $JobsResourceGroup -name $fnName
az webapp restart -g $JobsResourceGroup -n $fnName --subscription $currSub | Out-Null

$keys = Get-HostKeys -sub $currSub -rg $JobsResourceGroup -fn $fnName
if($keys -and $keys.masterKey){
  Write-Host "✅ Host master key is available." -ForegroundColor Green
} else {
  Write-Warning "Host keys not reported by ARM; the function will still run, but the Portal Keys blade may lag briefly."
}

Write-Host ""
Write-Host "✅ Deployment complete" -ForegroundColor Green
Write-Host "Function App:   $fnName  (RG: $JobsResourceGroup)"
Write-Host "Storage:        $($st.StorageAccountName)  (RG: $ArchiveResourceGroup)  Container: $ContainerName"
Write-Host "App Insights:   $aiName  (RG: $JobsResourceGroup)"
Write-Host "Workspace:      $wsName  (RG: $JobsResourceGroup)"
Write-Host "MI ObjectId:    $miPrincipalId"

if($failedGrants.Count -gt 0){
  Write-Host ""
  Write-Host "⚠️  Role grants FAILED on (function will skip these subs at runtime):" -ForegroundColor Yellow
  Write-Host "   " ($failedGrants -join "`n   ")
}