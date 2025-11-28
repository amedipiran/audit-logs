# Azure Audit Log Archiver

This solution deploys an Azure Functions timer that periodically exports **Azure Activity Logs** (subscription-level audit logs) for all enabled subscriptions in a tenant into a **central ADLS Gen2 storage account**, with lifecycle rules for archiving and deletion.

The README is based on the current scripts:

- `build-audit-zip.ps1` – builds the function app package (`audit-timer.zip`).
- `deploy-tenant-audit.ps1` – deploys storage, Function App, monitoring, roles, and zip package.

---

## What the solution does

In **one chosen subscription** (interactive selector), the deployment script:

- Creates or reuses a **resource group** (default: `rg-az-audit-log-exec`).
- Creates or reuses an **ADLS Gen2 storage account** with a deterministic name per subscription  
  `stazauditlogexec<8-char-hash>`.
- Ensures a **container** (default: `audit`) exists via ARM and sets `publicAccess = None`.
- Applies a **lifecycle policy** on the storage account for the given container prefix:
  - Archive blobs after `DaysToArchive` (default `91` days).
  - Delete blobs after `DaysToArchive + DaysToDelete` (default `182` days total).
- Creates or reuses an **Action Group** (`ag-audit-email`) for email alerts.
- Creates a **Function App** (Flex Consumption first, fallback to Linux Consumption):
  - Name: `fn-az-audit-log-exec-<8-char-hash>`
  - System-assigned managed identity enabled.
  - App settings wired for storage, tenant, and time zone.
- Creates or reuses:
  - **Log Analytics Workspace**: `law-audit`
  - **Application Insights**: `appi-fn-az-audit-log-exec-<hash>` (workspace-based).
- Grants the Function App managed identity:
  - `Storage Blob Data Contributor` on the storage account.
  - `Reader` and `Monitoring Reader` on **each enabled subscription** in the tenant.
- Deploys the timer function code from `audit-timer.zip` using **Kudu Zip Deploy**.
- Syncs function triggers, restarts the Function App, and ensures **host keys** are initialized.
- Adds **CORS** for the Azure portal so the Functions UI can call management endpoints.
- Creates an **Activity Log Alert** that notifies on failed administrative operations for the Function App.

The **timer function** (`AuditTimer`) then runs every six hours and:

1. Authenticates with **Managed Identity**.
2. For each enabled subscription:
   - Reads existing **index blobs** (`indexes/<subId>/.../processed_ids.txt`) to know which Activity Log `EventDataId`s were already stored.
   - Queries **Activity Logs** for the current UTC day up to "now".
   - Deduplicates events by `EventDataId` across all previous indexes.
   - Writes **per-event CSV blobs** under:
     `activity/<subId>/YYYY/MM/DD/AzActivity_<timestamp>_<EventDataId>.csv`
   - Writes/updates `processed_ids.txt` for the day with all `EventDataId`s processed.

---

## Repository layout (expected)

```text
/
├─ build-audit-zip.ps1        # Builds the function app package (audit-timer.zip)
├─ deploy-tenant-audit.ps1    # Deployment script for the tenant + central subscription
└─ audit-timer.zip            # Function app package built by build-audit-zip.ps1
```

> If you change the layout, update `-ZipPath` in `deploy-tenant-audit.ps1`.

---

## Prerequisites

### Azure / Identity

- An **Azure AD (Entra ID) tenant** GUID (used as `-TenantId`).
- At least one **Enabled** subscription in that tenant.
- Your user or service principal must have **sufficient RBAC** (see below).

### Roles and permissions (RBAC)

For the **deployment** subscription (the one you pick interactively):

- On the **subscription scope** (or equivalent):
  - `Owner` **or** combination of roles that allow:
    - Creating resource groups, storage, function apps, LAW, Application Insights.
    - Registering resource providers.
- On the **storage account** scope:
  - To let the script grant the Function App identity **Storage Blob Data Contributor**:
    - `Owner` or `User Access Administrator` on the storage account or above.

For **reading audit blobs** later:

- On the **storage account** scope:
  - `Storage Blob Data Reader` for users who should browse the `audit` container.

> In many organizations, assigning data-plane roles (like `Storage Blob Data Reader`) requires a **Global Administrator** in Entra ID to grant the role. Even if you are an Owner on the subscription, you might not be allowed to assign this role yourself.

### Tools / runtimes

On the machine where you run the scripts:

- **PowerShell 7+** (`pwsh`)
- **Azure PowerShell** Az modules (the script will auto-install what’s missing under `CurrentUser`):
  - `Az.Accounts`
  - `Az.Resources`
  - `Az.Storage`
  - `Az.Monitor`
  - `Az.Functions`
  - `Az.Websites`
  - `Az.ApplicationInsights`
  - `Az.OperationalInsights`
- **Azure CLI** (`az`)
  - Used for:
    - `az login --use-device-code`
    - `az account set ...`
    - `az rest` for function trigger sync and host keys
    - `az functionapp cors add`

### Network / endpoints

The machine and Function App must be able to reach:

- `https://management.azure.com`
- `https://login.microsoftonline.com` and `https://device.login.microsoftonline.com`
- `https://{your-site}.scm.azurewebsites.net` (Kudu)
- `https://{your-site}.azurewebsites.net`

### Resource Providers (auto-registered)

The deployment script registers these if needed:

- `Microsoft.Web`
- `Microsoft.Storage`
- `Microsoft.Insights`
- `Microsoft.OperationalInsights`

---

## REST / ARM APIs used (with versions)

These are the key REST APIs used by `deploy-tenant-audit.ps1` and called via `Invoke-AzRestMethod` or `az rest`:

### Storage container (private, ADLS Gen2)

```http
PUT /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}
    /providers/Microsoft.Storage/storageAccounts/{storageAccountName}
    /blobServices/default/containers/{containerName}?api-version=2023-05-01
```

Used in `Set-ContainerAAD` to ensure the container exists and set:

```json
{
  "properties": {
    "publicAccess": "None"
  }
}
```

### Subscription diagnostic settings → storage

```http
PUT /subscriptions/{subscriptionId}
    /providers/microsoft.insights/diagnosticSettings/{name}
    ?api-version=2021-05-01-preview
```

Used in `Enable-SubscriptionActivityLogsToStorage` to send **Activity Logs** to the central storage account.

### Action Group

```http
PUT /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}
    /providers/microsoft.insights/actionGroups/{actionGroupName}
    ?api-version=2021-09-01
```

Used in `Set-ActionGroup` to create `ag-audit-email` with one email receiver.

### Function App (Flex Consumption)

```http
PUT   /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}
      /providers/Microsoft.Web/sites/{siteName}?api-version=2023-12-01

PATCH /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}
      /providers/Microsoft.Web/sites/{siteName}?api-version=2023-12-01
```

Used in `New-FlexFunctionApp` to:
- Create a **Linux function app** on **Flex Consumption** (`sku: FC1`).
- Assign a **system-assigned managed identity**.

### Function trigger sync

```http
POST /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}
     /providers/Microsoft.Web/sites/{siteName}/syncfunctiontriggers
     ?api-version=2024-11-01
```

Called in `Sync-FunctionTriggers` using `az rest` after zip deployment.

### Function host keys (master key)

```http
POST /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}
     /providers/Microsoft.Web/sites/{siteName}/host/default/listkeys
     ?api-version=2024-11-01

POST /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}
     /providers/Microsoft.Web/sites/{siteName}/host/default/setmasterkey
     ?api-version=2024-11-01
```

Used in `Get-HostKeys`:

- First tries `listkeys`.  
- If no keys are returned, it:
  - Syncs triggers.
  - Restarts the app.
  - Optionally calls `setmasterkey` with a newly generated key.
  - Tries `listkeys` again.

### Kudu Zip Deploy (not ARM)

```http
POST https://{siteName}.scm.azurewebsites.net/api/zipdeploy?isAsync=true
```

Used in `ZipDeploy` with **Basic Auth** (publishing profile) to upload `audit-timer.zip`.

---

## How the timer function works

The function package is built by `build-audit-zip.ps1` and contains:

- `host.json` – Functions host configuration.
- `requirements.psd1` – Az module dependencies for the Functions runtime.
- `AuditTimer/function.json` – timer trigger binding.
- `AuditTimer/run.ps1` – main logic.

### host.json

```json
{
  "version": "2.0",
  "managedDependency": { "enabled": true },
  "extensionBundle": {
    "id": "Microsoft.Azure.Functions.ExtensionBundle",
    "version": "[4.*, 5.0.0)"
  }
}
```

### requirements.psd1

```powershell
@{
  "Az.Accounts"  = "2.*"
  "Az.Resources" = "6.*"
  "Az.Monitor"   = "5.*"
  "Az.Storage"   = "6.*"
}
```

The Functions runtime will manage these module versions at runtime.

### Timer trigger (function.json)

```json
{
  "bindings": [
    { "name": "Timer", "type": "timerTrigger", "direction": "in", "schedule": "0 0 */6 * * *" }
  ],
  "scriptFile": "run.ps1"
}
```

Default **cron**: every 6 hours.

### Environment variables used by the function

Set by the deployment script on the Function App:

- `AUDIT_RG` – Resource group name hosting the storage account.
- `AUDIT_ST_ACCOUNT` – Storage account name.
- `AUDIT_CONTAINER` – Container where data and indexes are stored.
- `AUDIT_PREFIX` – File prefix for event CSV files (default `AzActivity`).
- `AUDIT_HOME_SUB` – Home subscription where infra lives.
- `AUDIT_TENANT_ID` – Tenant ID.
- `WEBSITE_TIME_ZONE` – `W. Europe Standard Time` (set both in app config and Flex function app settings).

### High-level algorithm (run.ps1)

1. Validate required env vars (`AUDIT_RG`, `AUDIT_ST_ACCOUNT`, `AUDIT_CONTAINER`).
2. Import Az modules (`Accounts`, `Resources`, `Monitor`, `Storage`).
3. `Connect-AzAccount -Identity` (managed identity of the Function App).
4. If `AUDIT_HOME_SUB` is set, call `Select-AzSubscription` to stabilize context.
5. Get the storage account and a `New-AzStorageContext -UseConnectedAccount` context.
6. Ensure the container exists:
   - If `New-AzStorageContainer` throws `ResourceAlreadyExistException`, the function logs that it already exists and continues.
7. Compute the query window:
   - `from = current-day UTC (00:00)`
   - `to   = now UTC`
8. Get all enabled subscriptions:
   - `Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }`
   - If this fails, fallback to the current context subscription.
9. For each subscription:
   - `Select-AzSubscription` to that subscription.
   - Call `Get-AzActivityLog -StartTime $from -EndTime $to` selecting relevant fields.
   - Load existing index blobs under `indexes/<subId>/...` and build a `HashSet<string>` of known `EventDataId`s.
   - Filter logs to only those where `EventDataId` is not in the set.
   - For each new event:
     - Build a safe file name based on timestamp and sanitized `EventDataId`.
     - Convert event to CSV (`ConvertTo-Csv`) and upload via `Put-BlobText` to `activity/<subId>/YYYY/MM/DD/...`.
   - Write `processed_ids.txt` for that day with all `EventDataId`s processed.
10. Summarize:
    - Log number of new events across all subscriptions.

---

## Deployment step by step

### 1. Build the function package

From the repo root (where `build-audit-zip.ps1` lives):

```powershell
pwsh ./build-audit-zip.ps1
```

This script:

- Creates a temporary folder.
- Writes `host.json`, `requirements.psd1`, and the `AuditTimer` function files.
- Zips everything into `audit-timer.zip` in the current directory.
- Deletes the temp folder.

After this step you should have:

```text
./audit-timer.zip
```

### 2. Deploy infrastructure + function

From the same directory:

```powershell
pwsh ./deploy-tenant-audit.ps1 `
  -TenantId "<YOUR_TENANT_GUID>" `
  -NotificationEmail "you@example.com" `
  -Location "swedencentral" `
  -ResourceGroup "rg-az-audit-log-exec" `
  -ContainerName "audit" `
  -ZipPath ".\audit-timer.zip" `
  -DaysToArchive 91 `
  -DaysToDelete 91
```

What happens:

1. **Modules** are initialized (install/import Az modules if needed).
2. Any previous Az context is cleared and `Connect-AzAccount -Tenant <TenantId>` is executed.
3. All **Enabled** subscriptions in the tenant are listed and you see a prompt:

   ```text
   Available subscriptions in tenant <TenantId>
     1. Sub A     <subId1>
     2. Sub B     <subId2>
     3. Sub C     <subId3>

   Select a subscription number:
   ```

4. You choose one number. That subscription becomes the **deployment subscription** (`$HomeSubId`).
5. Az context is set to that subscription and tenant.
6. Azure CLI is aligned to the same tenant + subscription:

   ```powershell
   az account clear
   az login --tenant <TenantId> --use-device-code
   az account set --subscription <HomeSubId>
   ```

7. Resource providers are registered if needed.
8. Resource group, storage account, container (via ARM), lifecycle rule, Action Group, Function App, Log Analytics workspace, App Insights, roles, CORS, alert, and app settings are created or updated.
9. `audit-timer.zip` is deployed via Kudu Zip Deploy.
10. Function triggers are synced, the Function App is restarted, and host keys are verified.

At the end you should see something like:

```text
✅ Deployment complete
Function App:   fn-az-audit-log-exec-xxxxxxxx  (RG: rg-az-audit-log-exec)
Storage:        stazauditlogexecxxxxxxxx       (RG: rg-az-audit-log-exec)  Container: audit
App Insights:   appi-fn-az-audit-log-exec-xxxxxxxx  (RG: rg-az-audit-log-exec)
Workspace:      law-audit                      (RG: rg-az-audit-log-exec)
MI ObjectId:    <guid>
```

### 3. Validate in the Azure portal

1. **Resource group**
   - Open `rg-az-audit-log-exec` (or your custom RG name).
   - Confirm:
     - Storage account
     - Function App
     - Log Analytics workspace
     - Application Insights
     - (Plan resource if using Consumption)
2. **Storage account**
   - Go to **Data storage → Containers**.
   - Confirm container `audit` exists.
   - Under **Data management → Lifecycle management**, check the rule with name similar to `archive-91-delete-182`.
3. **Function App**
   - Under **Configuration → Application settings**, verify the `AUDIT_*` keys and `APPLICATIONINSIGHTS_CONNECTION_STRING`.
   - Under **Functions**, verify that `AuditTimer` exists.
4. **Action Group**
   - Under **Monitor → Alerts → Action groups**, verify `ag-audit-email`.
5. **Activity Log Alert**
   - Under **Monitor → Alerts → Alert rules**, verify an alert named `audit-fn-failures`.

### 4. Verify logs are written

- Wait for the timer to run (or trigger it manually from the Functions portal).  
- Then in the storage account:
  - Open container `audit`.
  - Navigate into `activity/<subId>/YYYY/MM/DD/` and look for `AzActivity_*.csv` files.
  - Under `indexes/<subId>/YYYY/MM/DD/`, check `processed_ids.txt`.

---

## Troubleshooting

- **`Zip not found: .\audit-timer.zip`**
  - Run `pwsh ./build-audit-zip.ps1` first.
  - Or adjust `-ZipPath` in the deploy command.
- **Role assignment warnings (`Forbidden` or `AuthorizationFailed`)**
  - Your identity may lack permission to assign roles.
  - A user with `Owner` or `User Access Administrator` must assign:
    - `Storage Blob Data Contributor` to the Function App managed identity.
    - `Storage Blob Data Reader` to users who should read the blobs.
- **Diagnostic settings failing on some subscriptions**
  - You might lack rights in those subscriptions.
  - Configure them manually later if needed.
- **Host keys warning**
  - If `Get-HostKeys` cannot retrieve keys immediately, the script logs a warning.
  - The Function App usually becomes ready shortly after; this does not block execution.

---

## Clean-up

To remove all resources created in the deployment subscription:

1. (Optional) Remove subscription diagnostic settings pointing to this storage account.
2. Delete the resource group:

```powershell
Remove-AzResourceGroup -Name "rg-az-audit-log-exec" -Force -AsJob
```

You can then verify that the Function App, storage account, LAW, and App Insights are gone.

---

## Quick start

```powershell
# Build function package
pwsh ./build-audit-zip.ps1

# Deploy everything (interactive subscription selection)
pwsh ./deploy-tenant-audit.ps1 `
  -TenantId "<TENANT_GUID>" `
  -NotificationEmail "you@example.com"
```

After that, the system will automatically archive Azure Activity Logs to the central `audit` container using the schedule in the timer function.
