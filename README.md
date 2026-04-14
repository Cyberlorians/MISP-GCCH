# MISP to Microsoft Sentinel via the NEW Upload API (GCC-H)

**Authored by: Michael Crane and Matt Larkin**

The old method using `microsoftgraph/security-api-solutions` and the Graph API `ThreatIndicators.ReadWrite.OwnedBy` permission is **deprecated**. Microsoft replaced it with the [Threat Intelligence Upload STIX Objects API](https://learn.microsoft.com/en-us/azure/sentinel/stix-objects-api). This guide assumes MISP is already installed and running with feeds enabled. Below are the steps to connect MISP feeds to Microsoft Sentinel using the new API.

> **Scripts:** Both [`config.py`](https://github.com/Cyberlorians/MISP-GCCH/blob/main/config.py) and [`script.py`](https://github.com/Cyberlorians/MISP-GCCH/blob/main/script.py) referenced in this guide are available in the [MISP-GCCH](https://github.com/Cyberlorians/MISP-GCCH) repo. Download them or copy the contents below.

| | Old Method (Dead) | New Method (This Guide) |
|---|---|---|
| **API** | Microsoft Graph `tiIndicators` | Sentinel STIX Upload API (Preview) |
| **Permission** | `ThreatIndicators.ReadWrite.OwnedBy` | Sentinel Contributor (RBAC) |
| **Script** | `git clone microsoftgraph/security-api-solutions` | `config.py` + `script.py` (below) |
| **Connector** | Threat Intelligence Platforms (required) | Threat Intelligence Upload API (no connect needed) |
| **Endpoint (GCC-H)** | `graph.microsoft.us` | `api.ti.sentinel.azure.us` |

---

## Create Entra App Registration

1. Sign in to `https://portal.azure.us`
2. Navigate to **Microsoft Entra ID → App registrations → New registration**
   - Name: `misp2sentinel`
   - Single tenant
3. Record the **Application (client) ID** and **Directory (tenant) ID**
4. Under **Certificates & secrets → New client secret** — copy the Value immediately

> No Graph API permissions are needed. The new API uses RBAC only.

---

## Assign Sentinel Contributor Role

1. Navigate to your **Log Analytics workspace** (the one backing Sentinel)
2. **Access control (IAM) → Add role assignment**
3. Role: **Microsoft Sentinel Contributor**
4. Members: select the `misp2sentinel` service principal
5. Review + assign

Record your **Workspace ID** (GUID) from the Overview page.

---

## GCC-H Endpoints

Commercial and GCC-H use different URLs. Get these wrong and nothing works.

| Purpose | Commercial | GCC-H (Fairfax) |
|---|---|---|
| Token | `login.microsoftonline.com` | `login.microsoftonline.us` |
| Scope | `management.azure.com/.default` | `management.usgovcloudapi.net/.default` |
| Upload API | `api.ti.sentinel.azure.com` | `api.ti.sentinel.azure.us` |

```
POST https://api.ti.sentinel.azure.us/workspaces/{WorkspaceID}/threat-intelligence-stix-objects:upload?api-version=2024-02-01-preview
```

> **GCC-H Connector Typo:** The connector page in the portal shows `threatintelligence-stix-objects:upload` (no hyphen). This is **wrong** and returns 404. The working URL uses `threat-intelligence-stix-objects:upload` (WITH hyphen), matching the [official docs](https://learn.microsoft.com/en-us/azure/sentinel/stix-objects-api).

> **Feature Availability Docs:** Microsoft's docs may show this as "Not Available" for GCC-H. The API **does work** in GCC-H as of April 2026. Confirmed — 4,495 indicators uploaded successfully.

---

## Setup the Script on MISP Server

SSH to the MISP server and run the following:

```bash
sudo mkdir -p /opt/misp2sentinel
sudo chown $USER:$USER /opt/misp2sentinel
cd /opt/misp2sentinel

sudo apt install -y python3.12-venv
python3 -m venv venv
source venv/bin/activate
pip install pymisp requests urllib3
```

> **Note:** `sudo mkdir` creates the directory as root. The `chown` command gives your user ownership so `python3 -m venv` and `pip install` work without permission errors.

Download [`config.py`](https://raw.githubusercontent.com/Cyberlorians/MISP-GCCH/refs/heads/main/config.py) and [`script.py`](https://raw.githubusercontent.com/Cyberlorians/MISP-GCCH/refs/heads/main/script.py) from the repo:

```bash
cd /opt/misp2sentinel
wget -O config.py https://raw.githubusercontent.com/Cyberlorians/MISP-GCCH/refs/heads/main/config.py
wget -O script.py https://raw.githubusercontent.com/Cyberlorians/MISP-GCCH/refs/heads/main/script.py
```

---

## Configure

Edit `/opt/misp2sentinel/config.py` with your environment values. The file is commented — fill in the placeholders:

- **tenant_id / client_id / client_secret** — from the App Registration step above
- **workspace_id** — Log Analytics Workspace GUID from the Overview page
- **misp_key** — your MISP admin API key (40-char string)

> **Finding your MISP API key:** Run `sudo cat /root/misp_settings.txt` on the MISP server. The installer saves the admin API key there. You can also find it in the MISP web UI under **Administration → List Auth Keys**.

---

## Run

```bash
cd /opt/misp2sentinel
source venv/bin/activate
python3 script.py
```

Expected output:
```
2026-04-13 20:58:28 [INFO] Access token acquired from https://login.microsoftonline.us/...
2026-04-13 20:58:28 [INFO] Retrieved 5000 IDS-flagged attributes from MISP (last 7 days)
2026-04-13 20:58:28 [INFO] Converted: 4495 indicators, Skipped: 505 (unsupported types)
2026-04-13 20:58:29 [INFO] Batch 0-100: 100 indicators uploaded
...
2026-04-13 20:58:46 [INFO] COMPLETE: Uploaded=4495, Errors=0, Skipped=505
```

---

## Cron Job

Create the log file first:

```bash
sudo touch /var/log/misp2sentinel.log
sudo chown $USER:$USER /var/log/misp2sentinel.log
```

Then add the cron entry:

```bash
sudo crontab -e
```

Add this line to sync every 6 hours:

```
0 */6 * * * /opt/misp2sentinel/venv/bin/python3 /opt/misp2sentinel/script.py >> /var/log/misp2sentinel.log 2>&1
```

---

## Verify in Sentinel

The new Upload API writes to the **`ThreatIntelIndicators`** table, NOT the legacy `ThreatIntelligenceIndicator` table. The connector page still references the old table — it's out of date.

```kql
ThreatIntelIndicators
| where SourceSystem == "MISP"
| summarize Count=count() by tostring(Data.pattern_type)
| order by Count desc
```

> The connector status will always show "Disconnected" and "Data received: 0" — this is expected. It says so right on the connector page: *"The 'Status' of the connector will not appear as 'Connected' here, because the data is ingested by making an API call."*

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `401 Unauthorized` | Check client_secret hasn't expired. Verify tenant_id. |
| `403 Forbidden` (Sentinel) | Sentinel Contributor role must be on the workspace, not the resource group. |
| `403 Forbidden` (MISP) | Wrong API key. MISP 2.5 uses hashed keys in `auth_keys` table — the legacy `users.authkey` column is empty. Get the real key from `sudo cat /root/misp_settings.txt` or the MISP UI under Administration → List Auth Keys. |
| `404 Not Found` | Verify workspace_id is the GUID. Make sure URL has `threat-intelligence-stix-objects` (WITH hyphen). |
| `0 attributes found` | MISP feeds may not be fetched yet. Run: `sudo -u www-data /var/www/MISP/app/Console/cake Server fetchFeed 1 all` |
| No data in Sentinel | Query `ThreatIntelIndicators` (new table), NOT `ThreatIntelligenceIndicator` (legacy). |
| Commercial vs GCC-H | All three endpoints must use `.us` not `.com`: login, scope, and API base. |

---

## References

- [Threat Intelligence Upload API (MS Learn)](https://learn.microsoft.com/en-us/azure/sentinel/stix-objects-api)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [dcodev1702 Sentinel TI Upload PoC](https://github.com/dcodev1702/Sentinel-TI-Upload-with-Mock-TI-API)
- [Old Method (Deprecated)](https://github.com/microsoftgraph/security-api-solutions)
