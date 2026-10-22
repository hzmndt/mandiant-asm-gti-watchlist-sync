# Mandiant ASM CPE to GTI Target Technology Watchlist Sync

A Python utility that automatically extracts fingerprinted Common Platform Enumeration (CPE 2.3) records from **Mandiant Attack Surface Management (ASM)** via the Google Threat Intelligence (GTI) v3 API, converts them into the required GTI Target Technology Watchlist format, and synchronizes them into a **GTI Target Technology Watchlist** configuration for automated CVE matching, prioritization, and alert generation.

---

## Overview & Architecture

### The Problem
Organizations running Mandiant ASM continuously discover and fingerprint internet-facing software assets (servers, web frameworks, operating systems, and network appliances) represented as CPE 2.3 strings:
```text
cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*
cpe:2.3:s:cloudflare:cloudflare::*:*:*:*:*:*
cpe:2.3:a:php:php:8.1.2:*:*:*:*:*:*:*
```

To monitor these assets for new vulnerabilities, Google Threat Intelligence provides **Target Technology Watchlists** (`technology_watchlist`). However:
- The GTI Target Technology Watchlist backend API expects technologies formatted as `<vendor> <product> [version]`.
- Raw CPE 2.3 strings sent directly to the API without client-side parsing do not trigger downstream CVE matchers.
- Manual copy-pasting of thousands of asset fingerprints across multiple ASM projects into the GTI web interface is labor-intensive and error-prone.

### How This Tool Solves It
```
┌────────────────────────┐
│ Mandiant ASM API v3    │
│ (/asm/search/techno...)│
└───────────┬────────────┘
            │
            ▼
┌────────────────────────────────────────────────────────┐
│ CPE 2.3 Normalizer & Parser                            │
│ cpe:2.3:a:apache:http_server:2.4.54 ->                 │
│ "apache http_server 2.4.54"                            │
└───────────┬────────────────────────────────────────────┘
            │
            ▼
┌────────────────────────────────────────────────────────┐
│ GTI API Key Token Exchange & Project Auto-Discovery     │
│ 1. GET /api/v3/users/{key} -> Group -> gti_gcp_project │
│ 2. POST /exchange/api-key -> OAuth 2.0 Bearer Token    │
└───────────┬────────────────────────────────────────────┘
            │
            ▼
┌────────────────────────────────────────────────────────┐
│ GTI Target Technology Watchlist Upsert (Merge/Replace) │
│ POST /v1beta/projects/{project}/configurations:upsert  │
│ -> Active CVE Matching & Priority Alerts               │
└────────────────────────────────────────────────────────┘
```

---

## Installation

### Prerequisites
- Python 3.9+
- A Google Threat Intelligence (GTI) / VirusTotal v3 API key with ASM and Threat Intelligence permissions.

### Setup
```bash
git clone https://github.com/hzmndt/mandiant-asm-gti-watchlist-sync.git
cd mandiant-asm-gti-watchlist-sync

pip install -r requirements.txt
chmod +x sync_asm_cpe_to_gti_watchlist.py
```

Set your API key as an environment variable:
```bash
export GTI_API_KEY="your_gti_v3_api_key_here"
# or
export VT_API_KEY="your_gti_v3_api_key_here"
```

---

## Usage

### 1. Discover ASM Projects and Existing GTI Watchlists
List all ASM projects accessible to your API key, along with your current GTI Target Technology Watchlists:
```bash
./sync_asm_cpe_to_gti_watchlist.py --list-asm-projects --list-watchlists
```

Example output:
```text
=== Mandiant ASM Projects ===
 * ID: 12345   | Name: example_asm_project      | Role: owner    | Org: Example Organization
   ID: 67890   | Name: staging_asm_env          | Role: member   | Org: Example Organization
=============================

=== GTI Target Technology Watchlists ===
  - Name: Example Org Tech Watchlist
    Resource: projects/gti-00000000-0000-0000-0000-00/configurations/00000000-0000-0000-0000-000000000000
    State:    ENABLED
    Items:    42 technologies
    Sample:   apache http_server 2.4.54, nginx 1.18.0, php 8.1.2
=========================================
```

### 2. Preview Extracted CPEs (Safe Dry-Run Mode)
Preview the technologies that would be pulled and normalized from an ASM project without modifying GTI:
```bash
./sync_asm_cpe_to_gti_watchlist.py \
  --asm-project-id 12345 \
  --watchlist-name "Example Org Tech Watchlist" \
  --dry-run
```

### 3. Export Extracted CPEs to Files
Export raw CPE records with asset metadata, clean CPE lists, and formatted watchlist entries:
```bash
./sync_asm_cpe_to_gti_watchlist.py \
  --asm-project-id 12345 \
  --export-json asm_technologies.json \
  --export-cpe-txt cpe_list.txt \
  --export-watchlist-txt watchlist_entries.txt \
  --dry-run
```

### 4. Apply Changes to GTI Watchlist (`--apply`)
Synchronize the normalized technologies into your GTI Target Technology Watchlist:

#### Option A: Merge into an Existing Watchlist (Preserves Existing Items)
```bash
./sync_asm_cpe_to_gti_watchlist.py \
  --asm-project-id 12345 \
  --watchlist-name "Example Org Tech Watchlist" \
  --mode merge \
  --apply
```

#### Option B: Create a Dedicated Watchlist with Custom CVE Alert Thresholds
```bash
./sync_asm_cpe_to_gti_watchlist.py \
  --asm-project-id 12345 \
  --watchlist-name "Mandiant ASM Production Watchlist" \
  --priority-min P2 \
  --cvss-min 7.0 \
  --epss-min 0.5 \
  --risk-rating-min HIGH \
  --apply
```

---

## Command-Line Reference

| Argument | Description | Default |
| :--- | :--- | :--- |
| `-k`, `--api-key` | GTI / VirusTotal API v3 key | `$GTI_API_KEY` or `$VT_API_KEY` |
| `--gti-project-id` | Override GTI GCP project ID | Auto-discovered from group profile |
| `-p`, `--asm-project-id` | Mandiant ASM project ID | Primary project |
| `--asm-project-name` | Mandiant ASM project name | None |
| `--list-asm-projects` | List all accessible ASM projects and exit | `False` |
| `--asm-query` | Filter query for ASM technologies | `first_seen_after:2000-01-01` |
| `--cpe-types` | Comma-separated CPE types (`application,service,os,hardware`) | All |
| `--page-size` | Batch page size for ASM API pagination | `1000` |
| `--max-pages` | Maximum pages to fetch from ASM | Unlimited |
| `--strip-versions` | Match `<vendor> <product>` only across all versions | `False` |
| `--collapse-same-vendor-product`| Collapse identical vendor/product (e.g. `php php` -> `php`) | `False` |
| `--list-watchlists` | List existing GTI watchlists and exit | `False` |
| `-w`, `--watchlist-name`| Display name for the Target Technology Watchlist | `"Mandiant ASM Watchlist"` |
| `--watchlist-id` | Update specific watchlist by configuration ID/name | None |
| `--mode` | Synchronization mode (`merge` or `replace`) | `merge` |
| `--priority-min` | Minimum alert priority (`P0`, `P1`, `P2`, `P3`, `P4`) | `P2` |
| `--cvss-min` | Minimum CVSS threshold score | `7.0` |
| `--epss-min` | Minimum EPSS threshold score | `0.5` |
| `--risk-rating-min` | Minimum risk rating (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) | `HIGH` |
| `--export-json` | Export full technology records to JSON | None |
| `--export-cpe-txt` | Export unique CPE strings to text file | None |
| `--export-watchlist-txt` | Export formatted watchlist entries to text file | None |
| `--apply` | Write updates to GTI (runs in dry-run mode if omitted) | `False` |
| `--dry-run` | Explicitly specify dry-run mode | `True` unless `--apply` |

---

## License
Apache 2.0
