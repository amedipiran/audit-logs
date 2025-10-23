# audit-logs
# 🧾 Azure Audit Log Archiving Setup Script

## Overview

This PowerShell script (`setup-audit-logs.ps1`) automates the **end-to-end setup** of Azure Audit Log archiving and lifecycle management using a single command.

It creates and configures the following resources automatically:

| Component | Purpose |
|------------|----------|
| **Resource Group** | Dedicated group for audit-log archiving resources |
| **Storage Account (ADLS Gen2)** | Central storage for logs (Activity, Resource, and Entra) |
| **Containers** | `audit-activity`, `audit-resource`, and `audit-entra` for separation of log types |
| **Lifecycle Management Policy** | Moves blobs to the *Archive* tier after 91 days |
| **Action Group (Email)** | Sends email alerts when Diagnostic Settings are created, modified, or deleted |
| **Activity Log Alerts** | Automatically notifies you if audit log settings are changed or removed |
| **Diagnostic Settings (REST API)** | Sends both Subscription and Microsoft Entra logs into the archive storage |

---

## ⚙️ Prerequisites

Before running the script, ensure the following are true:

1. You have **PowerShell 7+ (pwsh)** installed  
   ```bash
   pwsh --version
   ```
   If not, install from: [https://aka.ms/powershell](https://aka.ms/powershell)

2. You have the **Az PowerShell modules** installed:
   ```powershell
   Install-Module Az.Accounts,Az.Resources,Az.Storage -Scope CurrentUser -Force -AllowClobber
   ```

3. You are an **Owner** or **Contributor** on the Azure Subscription you’re configuring.

4. Archive tier is supported only on these SKUs:  
   `Standard_LRS`, `Standard_GRS`, or `Standard_RAGRS`.  
   (⚠️ Archive is **not** supported on ZRS/GZRS/RA-GZRS.)

---

## 🚀 Usage

Open PowerShell 7 (`pwsh`) and navigate to the folder where the script is located:

```bash
cd ~/Desktop/RG-Audit-Logs
```

Run the script (replace Subscription ID and email address with your own):

```powershell
./setup-audit-logs.ps1 `
  -SubscriptionId "00000000-0000-0000-0000-000000000000" `
  -NotificationEmail "your.email@example.com" `
  -SkuName Standard_GRS
```

### Optional parameters
| Parameter | Description | Default |
|------------|-------------|----------|
| `-ResourceGroupName` | Name of the resource group to create/use | `rg-audit-archive-prod` |
| `-Location` | Azure region for resources | `westeurope` |
| `-StorageAccountName` | Custom storage account name (must be globally unique) | Randomly generated |
| `-SkuName` | Redundancy type (LRS/GRS/RAGRS) | `Standard_GRS` |

---

## ✅ What It Does

1. Logs you into Azure and selects your subscription.  
2. Creates a resource group if it doesn’t exist.  
3. Creates an ADLS Gen2 (StorageV2) account.  
4. Creates three blob containers: `audit-activity`, `audit-resource`, and `audit-entra`.  
5. Applies a **Lifecycle Policy** that archives blobs after 91 days.  
6. Creates an **Action Group** for email notifications (via ARM REST).  
7. Creates **Activity Log Alerts** for diagnostic setting updates/deletions.  
8. Enables **Diagnostic Settings** for:
   - Subscription Activity Logs → Storage
   - Microsoft Entra (Audit + Sign-in) Logs → Storage

---

## 🔍 Verify Lifecycle Rule in Portal

1. Go to [Azure Portal](https://portal.azure.com).
2. Search for your **Storage Account** (e.g., `st123456789`).
3. In the left menu, navigate to **Data management → Lifecycle management**.
4. Confirm the rule:
   - Name: `archive-after-91`
   - Action: Move to Archive after 91 days
   - Filter Prefixes: `audit-activity`, `audit-resource`, `audit-entra`
   - Status: Enabled ✅

If not visible immediately, click **Refresh** once or twice.

You can also verify from PowerShell:
```powershell
Get-AzStorageAccountManagementPolicy `
  -ResourceGroupName rg-audit-archive-prod `
  -StorageAccountName st123456789 |
  Select-Object -Expand Rules
```

---

## 🧠 Notes

- Lifecycle actions run **once per day**, so moves to Archive will occur on a delay.
- Archive tier retrieval can take **hours**, so this is intended for compliance retention.
- You can add extra rules later (e.g., delete after 365 days) directly from the portal.
- The script can be rerun safely — it is **idempotent** (will update existing resources).

---

## 📄 Example Output

```
🧱 Ensuring Resource Group 'rg-audit-archive-prod' in 'westeurope'...
💾 Creating ADLS Gen2 Storage Account 'st123456789' (SKU=Standard_GRS)...
🗂️  Creating containers (audit-activity, audit-resource, audit-entra)...
📦 Applying lifecycle policy (Archive after 91 days)...
📣 Creating/ensuring Action Group for notifications (REST)...
🚨 Creating Activity Log alerts for diagnostic setting updates/deletions (REST)...
📝 Enabling Diagnostic Settings for Subscription Activity Logs -> Storage (REST)...
🔐 Enabling Microsoft Entra (Azure AD) Audit/Sign-in logs -> Storage...

✅ Setup completed successfully!
   Resource Group        : rg-audit-archive-prod
   Storage Account       : st123456789
   Region                : westeurope
   SKU                   : Standard_GRS
   Lifecycle Rules       : archive-after-91
   Action Group (email)  : your.email@example.com
   Alerts created        : Diagnostic write/delete (Activity Log)
   Sub Activity Logs DS  : Enabled (via REST)
   Entra Logs DS         : Enabled (Audit, Sign-in, etc.)
```
---

**Author:** Piran Amedi  
**Script Name:** `setup-audit-logs.ps1`  
**Version:** 1.0  
**License:** MIT
