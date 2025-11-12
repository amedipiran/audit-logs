# Azure Audit Log Archiver — Deployment Guide

This README explains **exactly** how to package and deploy the *Azure Audit Log Archiver* using the provided PowerShell script. It covers prerequisites, required permissions, module requirements, REST APIs used, how the script behaves (single login + single subscription), and how to validate and troubleshoot the deployment.

---

## What the solution does

In **one selected subscription** (you pick it interactively once after logging into the tenant), the script will:

- Ensure a single **Resource Group** (default: `rg-audit-log-exec`).
- Ensure an **ADLS Gen2 Storage Account** (stable name per-subscription, e.g. `stauditlogexec<hash>`) and a **container** (default: `audit`).
- Apply a **Lifecycle Management policy**: archive blobs after 91 days under the given prefix.
- Create an **Action Group** (`ag-audit-email`) with your notification email.
- Create a **Function App** (Flex Consumption if possible; fallback to Linux Consumption) named `fn-audit-log-exec<hash>`.
- Wire **Managed Identity** to the Function App and grant **Storage Blob Data Contributor** on the storage account.
- Create a **Log Analytics Workspace** (`law-audit`) and an **Application Insights** component (`appi-<functionName>`) linked to that workspace.
- Enable **Subscription Activity Logs → Storage** diagnostics across **all Enabled subscriptions** in the tenant (best-effort; skips where you lack permission).
- **Zip-deploy your functions package** (`audit-timer.zip`) to the Function App, **sync triggers**, restart, and verify **host keys** exist.

> **Everything is deployed into a single resource group** that you choose via the `-ResourceGroup` parameter (default `rg-audit-log-exec`).

---

## Repository layout (expected)

```
/
├─ build-audit-zip.ps1        # Builds the function app package (audit-timer.zip)
├─ deploy-tenant-audit.ps1    # The deployment script described in this README
├─ src/                       # Your function code (ps1/run.ps1/function.json etc.)
└─ audit-timer.zip            # Output produced by build-audit-zip.ps1
```

> If you keep a different structure, ensure `-ZipPath` in the deploy script points to the right file.

---

## Prerequisites

### 1) Permissions (RBAC)

You need **Owner** on the subscriptions to create and configure the resources below. To enable diagnostics on *other* subscriptions in the tenant, you’ll also need at least **Monitoring Contributor** or equivalent on those subscriptions. Minimum effective roles per resource:

- **Resource Group / Storage / Function App / LAW / App Insights**: *Owner*.
- **Role assignment to Function App’s Managed Identity** (Storage Blob Data Contributor on the Storage Account): *User Access Administrator* or *Owner* on the Storage Account scope.
- **Diagnostic settings at subscription scope**: *Monitoring Contributor* or *Owner* on each target subscription.


### 2) Tools

- **PowerShell 7+** (`pwsh`): required.
- **Azure PowerShell (Az) modules**: the script will auto-install missing modules under CurrentUser scope.
- **Azure CLI** (`az`): required for some calls (CORS, function trigger sync, and host key operations).

### 3) Network/Endpoints you must be able to reach

- `management.azure.com` (ARM)
- `*.azurewebsites.net` (Kudu zipdeploy + function admin endpoints)
- `login.microsoftonline.com` / `device.login.microsoftonline.com` (Auth)

### 4) Resource Providers registered in the subscription

The script ensures these are registered:
- `Microsoft.Web`
- `Microsoft.Storage`
- `Microsoft.Insights`
- `Microsoft.OperationalInsights`

---

## REST/ARM APIs used by the script

These are invoked via `Invoke-AzRestMethod` or `az rest`:

- **Subscription Diagnostic Settings → Storage**
  - `PUT /subscriptions/{subId}/providers/microsoft.insights/diagnosticSettings/{name}?api-version=2021-05-01-preview`
- **Action Group**
  - `PUT /subscriptions/{subId}/resourceGroups/{rg}/providers/microsoft.insights/actionGroups/{name}?api-version=2021-09-01`
- **Function App (Flex Consumption)**
  - `PUT /subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{name}?api-version=2023-12-01`
  - `PATCH …/sites/{name}?api-version=2023-12-01` (assign system identity)
- **Function triggers sync**
  - `POST …/sites/{name}/syncfunctiontriggers?api-version=2024-11-01`
- **Function host keys (portal readiness / master key)**
  - `POST …/sites/{name}/host/default/listkeys?api-version=2024-11-01`
  - `POST …/sites/{name}/host/default/setmasterkey?api-version=2024-11-01`
- **Kudu Zip Deploy** (not ARM; per-site SCM endpoint)
  - `POST https://{site}.scm.azurewebsites.net/api/zipdeploy?isAsync=true`

> **Log Analytics Workspace** and **Application Insights** are primarily created via Az cmdlets. App Insights is workspace-based (`-WorkspaceResourceId`). Newer Az versions will change output types for `Get/New-AzApplicationInsights` (the script remains compatible).

---

## Build first: package your functions

Before deploying, **build the functions package**. Example `build-audit-zip.ps1` pattern:

```powershell
pwsh ./build-audit-zip.ps1
# This should create: ./audit-timer.zip
```

If you don’t have a build script, simply zip your function app root into `audit-timer.zip` and place it next to `deploy-tenant-audit.ps1`, or change `-ZipPath` accordingly.

---

## Deploy

Run the deployment script in PowerShell 7+:

```powershell
pwsh ./deploy-tenant-audit.ps1 `
  -TenantId "<YOUR_TENANT_GUID>" `
  -NotificationEmail "you@example.com" `
  -Location "swedencentral" `
  -ResourceGroup "rg-audit-log-exec" `
  -ContainerName "audit" `
  -ZipPath ".\audit-timer.zip"
```

### ⚠️ Important — Subscription Selection During Login

When you run the script, you will be prompted to log in and choose a subscription interactively:

```
Id                    : user@example.com
Type                  : User
Tenants               : {11111111-2222-3333-4444-555555555555}
Credential            :
ExtendedProperties    : {[Tenants, 11111111-2222-3333-4444-555555555555],
                        [Subscriptions, aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee,
                         ffffffff-1111-2222-3333-444444444444]}

Please select the account you want to login with.

Retrieving subscriptions for the selection...
[Tenant and subscription selection]

No      Subscription name                       Subscription ID                             Tenant name
----    ------------------------------------    ----------------------------------------    --------------------------
[1]     Alpha Test                              11111111-aaaa-bbbb-cccc-222222222222
[2]     Another Test                            33333333-bbbb-cccc-dddd-444444444444
[3]     Subscription X                          55555555-cccc-dddd-eeee-666666666666
Select a subscription number: 2
To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the provided code.

Select a tenant and subscription: 3

Available subscriptions in tenant cc5cd634-cdbc-4fa2-aec1-4ebaa651d0d8
  1. Alpha Test                                   11111111-aaaa-bbbb-cccc-222222222222
  2. Another test                                 33333333-bbbb-cccc-dddd-444444444444
  3. Subscription X                            55555555-cccc-dddd-eeee-666666666666

Select a subscription number: 3
To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code G9QZ7UVAW to authenticate.
```

> **It is critical that you choose the same subscription that belongs to the account you just logged in with (`Connect-AzAccount`).**
>
> This ensures that the deployment context between PowerShell and the Azure CLI remains consistent.
>  
> Selecting a subscription from another tenant or one where your account is only a guest can cause failures in role assignment, storage setup, or diagnostic configuration.

Once you confirm the login in your browser (via the device login code), both **Azure PowerShell** and **Azure CLI** will automatically use that same subscription for all subsequent operations.

---

### Interactive login + single subscription

- The script **logs out/clears context**, then **logs in once** to the tenant you specify.
- You will see a numbered list of **Enabled subscriptions** in that tenant.
- **Pick one**; that subscription becomes the **deployment subscription** for **all** resources.
- The script also pins **Azure CLI** to the same subscription (for subsequent `az` calls).

> Everything is created in the chosen subscription and resource group. Diagnostic settings to other subscriptions are configured best-effort.

---

## Parameters

- `-TenantId` (**required**): Tenant GUID to log into.
- `-NotificationEmail` (**required**): Email used by the Action Group.
- `-Location`: Azure region for all resources (default `swedencentral`).
- `-ResourceGroup`: Single RG that contains **everything** (default `rg-audit-log-exec`).
- `-ContainerName`: Storage container name (default `audit`).
- `-ZipPath`: Path to the built functions zip (default `.\audit-timer.zip`).

---

## What gets created (names are stable per subscription)

- **Resource Group**: `rg-audit-log-exec` (or your override).
- **Storage Account**: `stauditlogexec<hash>` (ADLS Gen2, HNS enabled)
  - **Container**: `audit`
  - **Lifecycle Policy**: Archive after 91 days (prefix = container name)
- **Action Group**: `ag-audit-email` (global)
- **Function App**: `fn-audit-log-exec<hash>`
  - Flex Consumption by default; fallback to Linux Consumption if Flex fails.
  - Managed identity enabled; granted *Storage Blob Data Contributor* on the storage account.
  - App settings include `APPLICATIONINSIGHTS_CONNECTION_STRING` when available.
- **Log Analytics Workspace**: `law-audit`
- **Application Insights**: `appi-fn-audit-log-exec<hash>` (workspace-based)
- **Subscription Diagnostics → Storage**: on **all Enabled subscriptions** in tenant (best effort).

---

## Validate the deployment

1. **Resource Group**: open the RG in the portal; you should see 5+ resources (Storage, Function App, App Service plan (if Consumption), Action Group (global), LAW, App Insights).
2. **Storage**: in the `audit` container, verify the container exists; lifecycle management rule is visible under **Data Management → Lifecycle management**.
3. **Diagnostic settings**: for each subscription, open **Monitor → Activity log → Export to a storage account**; ensure there’s a diagnostic setting named `ds-activity-to-storage` pointing to your storage account.
4. **Function App**:
   - **Configuration → Application settings**: confirm your settings (e.g., `APPLICATIONINSIGHTS_CONNECTION_STRING`, `AUDIT_*` keys).
   - **Functions**: confirm your functions are listed after sync (the script runs sync + restart).
5. **Application Insights**: open `appi-…` and check **Live Metrics** or **Logs** after some time for function telemetry.
6. **Action Group**: verify it exists (`ag-audit-email`) and test a notification if you like.

---

## Troubleshooting

- **`Zip not found`** — run `build-audit-zip.ps1` (or create the zip manually) and confirm `-ZipPath`.
- **Stuck at subscription picker** — ensure PowerShell 7, stable internet, and that you are consenting to device login if prompted.
- **`ResourceNotFound` for LAW** — transient; the script uses `New-AzOperationalInsightsWorkspace`, but if you see races, re-run (LAW creation is idempotent). If you want strict polling, add a provisioning-state poll after creation.
- **Role assignment warnings** — your account may lack `User Access Administrator` on the storage account scope. Assign **Storage Blob Data Contributor** to the Function App’s **managed identity** manually.
- **Host keys unavailable warning** — the Function App may still be warming up. Keys typically appear shortly; the app will still run.
- **Diagnostic settings failures on some subs** — you might lack rights in those subscriptions. Configure manually later from **Monitor → Activity log**.
- **Application Insights “breaking change” warnings** — These are **informational** about future Az changes. The script uses workspace-based Insights already and remains compatible.

---

## Clean-up

To remove everything created by the script in the chosen subscription:

1. **Delete diagnostic settings** at subscription scope (optional): remove the `ds-activity-to-storage` diagnostic setting if you wish.
2. **Delete the resource group**:
   ```powershell
   Remove-AzResourceGroup -Name "<YourRG>" -Force -AsJob
   ```

---

## Notes on idempotency

- The script **ensures** (create-if-missing) for RG, storage, container, diagnostic settings, LAW, App Insights, Function App, Action Group, role assignments, and app settings.
- Re-running the script is safe; it updates or skips existing resources.

---

## Security

- Storage public access is **disabled**.
- Function App uses **system-assigned managed identity**.
- Function secrets are stored as **files** by default (set by app settings).

---

## Versioning & Compatibility

- PowerShell 7.5+ recommended.
- Azure PowerShell (Az) regularly updates. The script remains compatible with upcoming `Get/New-AzApplicationInsights` output-type changes.
- ARM API versions listed above are current as of this doc and may change; adjust if Azure introduces newer stable versions in your environment.

---

## Quick Start (TL;DR)

```powershell
# 1) Build functions
pwsh ./build-audit-zip.ps1   # produces ./audit-timer.zip

# 2) Deploy (interactive subscription picker, single login)
pwsh ./deploy-tenant-audit.ps1 `
  -TenantId "<TENANT_GUID>" `
  -NotificationEmail "you@example.com"
```

Done. All resources land in **one RG**; diagnostics enabled across tenant subscriptions where you have rights.
