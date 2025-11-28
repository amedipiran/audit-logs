[CmdletBinding(PositionalBinding=$false)]
param(
  # This runs every sixth hour
  [string] $Cron = '0 0 */6 * * *'
)

$ErrorActionPreference = 'Stop'

function New-TmpDir {
  $root = Join-Path ([IO.Path]::GetTempPath()) ("fn-" + [guid]::NewGuid())
  New-Item -ItemType Directory -Path $root -Force | Out-Null
  $root
}

$root = New-TmpDir
try {
  # host.json
  @'
{
  "version": "2.0",
  "managedDependency": { "enabled": true },
  "extensionBundle": {
    "id": "Microsoft.Azure.Functions.ExtensionBundle",
    "version": "[4.*, 5.0.0)"
  }
}
'@ | Set-Content -Path (Join-Path $root 'host.json') -Encoding UTF8

  # requirements.psd1 
  @'
@{
  "Az.Accounts"  = "2.*"
  "Az.Resources" = "6.*"
  "Az.Monitor"   = "5.*"
  "Az.Storage"   = "6.*"
}
'@ | Set-Content -Path (Join-Path $root 'requirements.psd1') -Encoding UTF8

  # ===== AuditTimer =====
  $timerDir = New-Item -ItemType Directory -Path (Join-Path $root 'AuditTimer') -Force

  @"
{
  "bindings": [
    { "name": "Timer", "type": "timerTrigger", "direction": "in", "schedule": "$Cron" }
  ],
  "scriptFile": "run.ps1"
}
"@ | Set-Content -Path (Join-Path $timerDir 'function.json') -Encoding UTF8

  @'
param($Timer)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

Write-Host "=== AuditTimer START $(Get-Date -Format u) ==="
if ($Timer.IsPastDue) { Write-Warning "Timer is running late." }

function Get-BlobText {
  param([object]$Context, [string]$Container, [string]$BlobName)
  try {
    $tmp = New-TemporaryFile
    $dl  = Get-AzStorageBlobContent -Context $Context -Container $Container -Blob $BlobName `
            -Destination $tmp -Force -ErrorAction SilentlyContinue
    if ($dl -and (Test-Path $tmp)) { return Get-Content -Path $tmp -Raw }
    return $null
  } finally {
    if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
  }
}

function Put-BlobText {
  param([object]$Context, [string]$Container, [string]$BlobName, [string]$Text)
  $tmp = New-TemporaryFile
  try {
    Set-Content -Path $tmp -Value $Text -Encoding UTF8
    Set-AzStorageBlobContent -Context $Context -Container $Container -File $tmp -Blob $BlobName -Force | Out-Null
  } finally {
    if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
  }
}


$RG          = $env:AUDIT_RG
$ST_ACCOUNT  = $env:AUDIT_ST_ACCOUNT
$CONTAINER   = $env:AUDIT_CONTAINER
$PREFIX      = if ($env:AUDIT_PREFIX) { $env:AUDIT_PREFIX } else { 'AzActivity' }
$HOME_SUB    = $env:AUDIT_HOME_SUB  
$TENANT_ID   = $env:AUDIT_TENANT_ID 

if ([string]::IsNullOrWhiteSpace($RG) -or
    [string]::IsNullOrWhiteSpace($ST_ACCOUNT) -or
    [string]::IsNullOrWhiteSpace($CONTAINER)) {
  throw "Missing settings: AUDIT_RG='$RG' AUDIT_ST_ACCOUNT='$ST_ACCOUNT' AUDIT_CONTAINER='$CONTAINER'"
}

Import-Module Az.Accounts
Import-Module Az.Resources
Import-Module Az.Monitor
Import-Module Az.Storage

Write-Host "Connecting with Managed Identity..."
Connect-AzAccount -Identity -WarningAction SilentlyContinue | Out-Null
$ctxNow = Get-AzContext
Write-Host "Context Tenant: $($ctxNow.Tenant.Id)  Subscription: $($ctxNow.Subscription.Id)"

if ($HOME_SUB) {
  try {
    Select-AzSubscription -SubscriptionId $HOME_SUB | Out-Null
    Write-Host "Selected AUDIT_HOME_SUB=$HOME_SUB"
  } catch {
    Write-Warning "Could not Select-AzSubscription $HOME_SUB : $($_.Exception.Message)"
  }
}

$stObj = Get-AzStorageAccount -ResourceGroupName $RG -Name $ST_ACCOUNT
if (-not $stObj) { throw "Storage account not found: RG=$RG Name=$ST_ACCOUNT" }
$stCtx = New-AzStorageContext -StorageAccountName $ST_ACCOUNT -UseConnectedAccount

if (-not (Get-AzStorageContainer -Context $stCtx -Name $CONTAINER -ErrorAction SilentlyContinue)) {
  try {
    New-AzStorageContainer -Name $CONTAINER -Context $stCtx -Permission Off -ErrorAction Stop | Out-Null
    Write-Host "Created container '$CONTAINER'"
  }
  catch [Microsoft.WindowsAzure.Commands.Storage.Common.ResourceAlreadyExistException] {
    # Container was created by something else (infra script / previous run) – that's fine.
    Write-Host "Container '$CONTAINER' already exists (caught in function)."
  }
}

$nowUtc = (Get-Date).ToUniversalTime()
$dayUtc = $nowUtc.Date
$from   = $dayUtc
$to     = $nowUtc
Write-Host "Query window: $($from.ToString('u')) → $($to.ToString('u'))"

$subs = @()
try {
  $subs = Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' }
} catch {
  Write-Warning "Get-AzSubscription failed: $($_.Exception.Message)"
}

if (($subs | Measure-Object).Count -eq 0 -and $ctxNow -and $ctxNow.Subscription -and $ctxNow.Subscription.Id) {
  $subs = @([pscustomobject]@{ Id = $ctxNow.Subscription.Id; Name="(current-context)"; State="Enabled" })
  Write-Host "Fallback: using current context subscription $($ctxNow.Subscription.Id)"
}

Write-Host "Discovered subscriptions: $(@($subs).Count)"

$totalNew = 0
foreach ($s in $subs) {
  try {
    Write-Host ""
    Write-Host ("--- [{0}] ({1}) ---------------------------------------------------" -f $s.Name,$s.Id)
    Select-AzSubscription -SubscriptionId $s.Id | Out-Null

    Write-Host "Get-AzActivityLog..."
    $logs = $null
    try {
      $logs = Get-AzActivityLog -StartTime $from -EndTime $to -WarningAction SilentlyContinue |
              Select-Object `
                EventDataId,CorrelationId,OperationName,Status,Level,ResourceId,ResourceGroupName,SubscriptionId, `
                Category,SubStatus,Caller,EventTimestamp,SubmissionTimestamp, `
                ResourceProviderName,ResourceType,Resource, `
                ActivityLogAlertId,ActivityStatus,ActivityStatusValue
    } catch {
      Write-Warning "Get-AzActivityLog error: $($_.Exception.Message)"
      continue
    }

    $total = ($logs | Measure-Object).Count
    Write-Host "Fetched: $total events"

    $indexPrefix = "indexes/$($s.Id)/"
    $processed   = [System.Collections.Generic.HashSet[string]]::new()

    $indexBlobs = Get-AzStorageBlob -Context $stCtx -Container $CONTAINER -Prefix $indexPrefix -ErrorAction SilentlyContinue
    $indexCount = 0

    foreach ($b in $indexBlobs) {
      $indexCount++
      $idxTxt = Get-BlobText -Context $stCtx -Container $CONTAINER -BlobName $b.Name
      if (-not $idxTxt) { continue }

      $idxIds = $idxTxt -split "`n"
      foreach ($id in $idxIds) {
        $trim = $id.Trim()
        if ($trim) { [void]$processed.Add($trim) }
      }
    }

    Write-Host "Found $indexCount index blobs for subscription $($s.Id)"
    Write-Host "Total distinct EventDataIds in all indexes: $($processed.Count)"


    $new = foreach ($e in $logs) { 
      if ($e.EventDataId -and -not $processed.Contains($e.EventDataId)) { $e } 
    }
    $new = $new | Where-Object { $_ }
    $newCount = ($new | Measure-Object).Count
    Write-Host "New events after dedupe (across all days): $newCount"
    if ($newCount -eq 0) { continue }

    $yyyy   = $dayUtc.ToString('yyyy')
    $MM     = $dayUtc.ToString('MM')
    $dd     = $dayUtc.ToString('dd')
    $baseDir = "activity/$($s.Id)/$yyyy/$MM/$dd"

    $createdBlobs = 0

    foreach ($e in $new | Sort-Object EventTimestamp) {
      $safeId = if ($e.EventDataId) { 
        ($e.EventDataId -replace '[^a-zA-Z0-9\-]', '_') 
      } else { 
        [guid]::NewGuid().ToString() 
      }

      $ts = $e.EventTimestamp.ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
      $fileName = "$PREFIX" + "_${ts}_$safeId.csv"
      $blobPath = "$baseDir/$fileName"

      $csvLines = $e | ConvertTo-Csv -NoTypeInformation
      $csvText  = $csvLines -join "`r`n"

      Put-BlobText -Context $stCtx -Container $CONTAINER -BlobName $blobPath -Text $csvText
      $createdBlobs++
    }

    Write-Host "Created $createdBlobs per-event CSV blobs for subscription $($s.Id)"

    $indexPathToday = "indexes/$($s.Id)/$yyyy/$MM/$dd/processed_ids.txt"

    $todayIds = $new |
      Where-Object { $_.EventDataId } |
      Select-Object -ExpandProperty EventDataId -Unique

    Put-BlobText -Context $stCtx -Container $CONTAINER -BlobName $indexPathToday -Text ($todayIds -join "`n")

    Write-Host "Wrote today's index: $indexPathToday with $(@($todayIds).Count) EventDataIds"

    $totalNew += $newCount
    Write-Host "SUCCESS: wrote $newCount new events"
  } catch {
    Write-Error ("[{0}] Outer error: {1}" -f $s.Id, ($_ | Out-String))
  }
}

Write-Host ""
Write-Host "Total new rows across subs: $totalNew"
Write-Host "=== AuditTimer END $(Get-Date -Format u) ==="
'@ | Set-Content -Path (Join-Path $timerDir 'run.ps1') -Encoding UTF8

  # ZIP
  $zip = Join-Path $PWD 'audit-timer.zip'
  if (Test-Path $zip) { Remove-Item $zip -Force }
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [IO.Compression.ZipFile]::CreateFromDirectory($root, $zip)

  Write-Host "✅ Built $zip" -ForegroundColor Green
}
finally {
  if (Test-Path $root) { Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue }
}