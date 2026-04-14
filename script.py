#!/usr/bin/env python3
"""
MISP to Microsoft Sentinel — STIX Upload Script (GCC-H)

Pulls IOCs from MISP, converts to STIX 2.1, uploads to Sentinel
via the Threat Intelligence Upload API (Preview).

Usage:
    1. Edit config.py with your values
    2. python3 script.py

Author: Michael Crane (Cyberlorians)
API Ref: https://learn.microsoft.com/en-us/azure/sentinel/stix-objects-api
"""

import json
import uuid
import logging
import sys
from datetime import datetime, timedelta, timezone

import requests
import urllib3
from pymisp import PyMISP
import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/misp2sentinel.log")
    ]
)
log = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# STEP 1: GET ACCESS TOKEN
# ──────────────────────────────────────────────
def get_access_token():
    """Acquire OAuth2 token via client_credentials grant."""
    token_url = f"{config.authority_url}/{config.tenant_id}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "scope": config.scope
    }
    resp = requests.post(token_url, data=data, timeout=30)
    resp.raise_for_status()
    token = resp.json().get("access_token")
    log.info("Access token acquired from %s", token_url)
    return token


# ──────────────────────────────────────────────
# STEP 2: PULL MISP ATTRIBUTES
# ──────────────────────────────────────────────
def get_misp_attributes():
    """Pull attributes from MISP for the configured lookback."""
    misp = PyMISP(config.misp_domain, config.misp_key, ssl=config.misp_verifycert)
    date_from = (datetime.now(timezone.utc) - timedelta(days=config.days_lookback)).strftime("%Y-%m-%d")

    # First try: IDS-flagged attributes (preferred for TI)
    results = misp.search(
        controller="attributes",
        to_ids=True,
        date_from=date_from,
        limit=5000,
        pythonify=True
    )

    if results:
        log.info("Retrieved %d IDS-flagged attributes from MISP (last %d days)", len(results), config.days_lookback)
        return results

    # Fallback: all attributes of supported types (feeds may not set to_ids)
    log.info("No IDS-flagged attributes found. Trying all supported types...")
    supported = ["ip-src", "ip-dst", "domain", "hostname", "url", "md5", "sha1", "sha256", "email-src", "email-dst", "filename"]
    results = misp.search(
        controller="attributes",
        type_attribute=supported,
        date_from=date_from,
        limit=5000,
        pythonify=True
    )

    log.info("Retrieved %d attributes (all types) from MISP (last %d days)", len(results), config.days_lookback)
    return results


# ──────────────────────────────────────────────
# STEP 3: CONVERT TO STIX 2.1
# ──────────────────────────────────────────────
def _safe_split(v, idx):
    """Split compound value on '|' and return part at idx, or None if missing."""
    parts = v.split('|')
    return parts[idx] if idx < len(parts) else None

STIX_PATTERN_MAP = {
    "ip-src":        lambda v: f"[ipv4-addr:value = '{v}']",
    "ip-dst":        lambda v: f"[ipv4-addr:value = '{v}']",
    "ip-src|port":   lambda v: f"[ipv4-addr:value = '{_safe_split(v, 0)}']" if '|' in v else None,
    "ip-dst|port":   lambda v: f"[ipv4-addr:value = '{_safe_split(v, 0)}']" if '|' in v else None,
    "domain":        lambda v: f"[domain-name:value = '{v}']",
    "hostname":      lambda v: f"[domain-name:value = '{v}']",
    "url":           lambda v: f"[url:value = '{v}']",
    "md5":           lambda v: f"[file:hashes.'MD5' = '{v}']",
    "sha1":          lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    "sha256":        lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    "email-src":     lambda v: f"[email-addr:value = '{v}']",
    "email-dst":     lambda v: f"[email-addr:value = '{v}']",
    "filename":      lambda v: f"[file:name = '{v}']",
    "filename|md5":  lambda v: f"[file:hashes.'MD5' = '{_safe_split(v, 1)}']" if '|' in v else None,
    "filename|sha1": lambda v: f"[file:hashes.'SHA-1' = '{_safe_split(v, 1)}']" if '|' in v else None,
    "filename|sha256": lambda v: f"[file:hashes.'SHA-256' = '{_safe_split(v, 1)}']" if '|' in v else None,
}

TLP_MARKING = {
    "tlp:white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "tlp:clear": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "tlp:green": "marking-definition--089a6ecb-cc15-43cc-9494-767639779123",
    "tlp:amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "tlp:red":   "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def attribute_to_stix(attr):
    """Convert a MISP attribute to a STIX 2.1 indicator object."""
    pattern_fn = STIX_PATTERN_MAP.get(attr.type)
    if not pattern_fn:
        return None

    pattern = pattern_fn(attr.value)
    if not pattern:
        return None
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    created = attr.timestamp.strftime("%Y-%m-%dT%H:%M:%S.000Z") if hasattr(attr, "timestamp") and attr.timestamp else now
    valid_until = (datetime.now(timezone.utc) + timedelta(days=config.days_to_expire)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, f'misp-{attr.uuid}')}",
        "created": created,
        "modified": now,
        "name": f"MISP: {attr.type} - {attr.value[:80]}",
        "description": f"MISP attribute (type: {attr.type}, category: {attr.category})",
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": created,
        "valid_until": valid_until,
        "labels": ["misp", attr.category] if hasattr(attr, "category") else ["misp"],
        "confidence": 70
    }

    # TLP markings
    if hasattr(attr, "Tag") and attr.Tag:
        for tag in attr.Tag:
            tag_name = tag.name.lower() if hasattr(tag, "name") else ""
            for tlp_key, marking_id in TLP_MARKING.items():
                if tlp_key in tag_name:
                    indicator["object_marking_refs"] = [marking_id]
                    break

    return indicator


# ──────────────────────────────────────────────
# STEP 4: UPLOAD TO SENTINEL
# ──────────────────────────────────────────────
def upload_to_sentinel(token, stix_objects):
    """Upload STIX objects to Sentinel via the TI Upload API."""
    url = (
        f"{config.api_base}/workspaces/{config.workspace_id}"
        f"/threat-intelligence-stix-objects:upload"
        f"?api-version={config.api_version}"
    )

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    total_uploaded = 0
    total_errors = 0

    for i in range(0, len(stix_objects), config.batch_size):
        batch = stix_objects[i:i + config.batch_size]
        payload = {
            "sourcesystem": config.source_system,
            "stixobjects": batch
        }

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=60)

            if resp.status_code == 200:
                body = resp.text.strip()
                if body:
                    result = resp.json()
                    errors = result.get("errors", [])
                    if errors:
                        log.warning("Batch %d-%d: %d validation errors", i, i + len(batch), len(errors))
                        for err in errors[:5]:
                            log.warning("  Index %d: %s", err.get("recordIndex"), err.get("errorMessages"))
                        total_errors += len(errors)
                    total_uploaded += len(batch) - len(errors)
                else:
                    total_uploaded += len(batch)
                    log.info("Batch %d-%d: %d indicators uploaded", i, i + len(batch), len(batch))
            elif resp.status_code == 429:
                log.warning("Rate limited. Response: %s", resp.text)
                total_errors += len(batch)
            else:
                log.error("Batch %d-%d failed: HTTP %d - %s", i, i + len(batch), resp.status_code, resp.text[:500])
                total_errors += len(batch)
        except requests.exceptions.RequestException as e:
            log.error("Batch %d-%d request failed: %s", i, i + len(batch), str(e))
            total_errors += len(batch)

    return total_uploaded, total_errors


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main():
    log.info("=" * 60)
    log.info("MISP to Sentinel STIX Upload — Starting")
    log.info("=" * 60)

    token = get_access_token()

    attributes = get_misp_attributes()
    if not attributes:
        log.info("No attributes found. Exiting.")
        return

    log.info("Converting to STIX 2.1 indicators...")
    stix_objects = []
    skipped = 0
    for attr in attributes:
        obj = attribute_to_stix(attr)
        if obj:
            stix_objects.append(obj)
        else:
            skipped += 1

    log.info("Converted: %d indicators, Skipped: %d unsupported types", len(stix_objects), skipped)

    if not stix_objects:
        log.info("No STIX indicators to upload. Exiting.")
        return

    log.info("Uploading %d indicators to Sentinel (batches of %d)...", len(stix_objects), config.batch_size)
    uploaded, errors = upload_to_sentinel(token, stix_objects)

    log.info("=" * 60)
    log.info("COMPLETE — Uploaded: %d | Errors: %d | Skipped: %d", uploaded, errors, skipped)
    log.info("=" * 60)


if __name__ == "__main__":
    main()
