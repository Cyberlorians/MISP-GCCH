# ---------------------------------------------------------------
# MISP to Microsoft Sentinel - Configuration (GCC-H)
# ---------------------------------------------------------------
# Edit the values below with your environment details.
# Then run:  python3 script.py
# ---------------------------------------------------------------

# -- Entra ID (from App Registration step) --
# Azure Portal > Microsoft Entra ID > App registrations > your app
tenant_id      = "<your-tenant-id>"           # Directory (tenant) ID from the app's Overview page
client_id      = "<your-app-client-id>"       # Application (client) ID from the app's Overview page
client_secret  = "<your-client-secret>"       # Secret Value from Certificates & secrets (copy at creation)

# -- GCC-H Endpoints --
# These are pre-set for GCC-H. Do NOT change unless you are on Commercial.
# Commercial would use: login.microsoftonline.com / management.azure.com / api.ti.sentinel.azure.com
authority_url  = "https://login.microsoftonline.us"
scope          = "https://management.usgovcloudapi.net/.default"
api_base       = "https://api.ti.sentinel.azure.us"
api_version    = "2024-02-01-preview"

# -- Sentinel Workspace --
# Log Analytics workspace backing Sentinel. Found on the workspace Overview page.
workspace_id   = "<your-workspace-guid>"      # Log Analytics Workspace ID (GUID), NOT the name

# -- MISP --
# Since this script runs on the MISP server itself, domain is localhost.
# API key: sudo cat /root/misp_settings.txt  or  MISP web UI -> Administration -> List Auth Keys
misp_domain    = "https://127.0.0.1"          # Leave as-is if script runs on the MISP server
misp_key       = "<your-misp-api-key>"        # MISP admin API key (40-char string)
misp_verifycert = False                       # False for self-signed cert (default MISP install)

# -- Sync Settings --
days_to_expire = 30         # How long indicators stay valid in Sentinel before expiring
days_lookback  = 7          # Pull MISP attributes created/modified in the last N days
action         = "alert"    # "alert" = detect only, "block" = block + alert (requires EDR)
passiveOnly    = False      # True = only push to_ids attributes flagged for IDS
source_system  = "MISP"     # Shows as SourceSystem in Sentinel's ThreatIntelIndicators table
batch_size     = 100        # Max STIX objects per API call (API hard limit is 100, do not increase)
