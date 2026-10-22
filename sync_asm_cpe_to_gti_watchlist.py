#!/usr/bin/env python3
"""Sync CPEs from Mandiant Attack Surface Management (ASM) to GTI Target Technology Watchlist.

This script:
1. Queries Mandiant ASM via GTI API v3 (https://www.virustotal.com/api/v3/asm)
   to list projects and pull fingerprinted technologies/CPEs.
2. Normalizes and converts raw CPE 2.3 strings into the format required by
   GTI's Target Technology Watchlist (<vendor> <product> [version]).
3. Auto-discovers the organization's GTI GCP project ID from the GTI API key.
4. Exchanges the GTI API key for an OAuth 2.0 Bearer token.
5. Lists, merges, and upserts the technologies into a GTI Target Technology Watchlist
   configuration (https://threatintelligence.googleapis.com/v1beta/projects/{project}/configurations:upsert).
"""

import argparse
import json
import os
import re
import sys
import urllib.parse
from typing import Any, Dict, List, Optional, Set

import requests

VT_BASE_URL = "https://www.virustotal.com/api/v3"
ASM_BASE_URL = f"{VT_BASE_URL}/asm"
IDP_TOKEN_URL = (
    "https://idp.prod.identity.proactive.virustotal.com/realms/master/exchange/api-key"
)
GTI_API_BASE_URL = "https://threatintelligence.googleapis.com/v1beta"


# ==============================================================================
# 1. CPE Parsing & GTI Technology Watchlist Formatting
# ==============================================================================

def split_cpe_components(cpe_str: str) -> List[str]:
    """Splits a CPE 2.3 string on unescaped colons."""
    parts: List[str] = []
    current: List[str] = []
    escaped = False

    for char in cpe_str:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def clean_cpe_token(token: str) -> str:
    """Unescapes backslash sequences and normalizes whitespace."""
    token = token.strip()
    token = re.sub(r"\\(.)", r"\1", token)
    return token.strip()


def cpe_to_watchlist_entry(
    cpe_str: str,
    include_version: bool = True,
    collapse_same_vendor_product: bool = False,
) -> Optional[str]:
    """Converts a CPE 2.3 string into GTI Target Technology Watchlist format.

    GTI Target Technology Watchlist expects entries in the form:
      <vendor> <product> [version]
    Raw CPE 2.3 strings (cpe:2.3:a:vendor:product:version:...) are converted to
    space-separated vendor/product/version strings for API ingestion and CVE matching.
    """
    if not cpe_str or not cpe_str.startswith("cpe:2.3:"):
        return None

    parts = split_cpe_components(cpe_str)
    if len(parts) < 5:
        return None

    vendor = clean_cpe_token(parts[3])
    product = clean_cpe_token(parts[4])
    version = clean_cpe_token(parts[5]) if len(parts) > 5 else ""

    if not vendor or vendor in ("*", "-") or not product or product in ("*", "-"):
        return None

    if collapse_same_vendor_product and vendor.lower() == product.lower():
        base = vendor
    else:
        base = f"{vendor} {product}"

    if include_version and version and version not in ("*", "-"):
        return f"{base} {version}"

    return base


# ==============================================================================
# 2. Mandiant ASM API Client
# ==============================================================================

class MandiantASMClient:
    """Client for Mandiant ASM endpoints exposed via GTI API v3."""

    def __init__(self, api_key: str, timeout: int = 30):
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "Mandiant-CPE-GTI-Sync/1.0",
        })

    def list_projects(self) -> List[Dict[str, Any]]:
        """Lists all Mandiant ASM projects accessible with this API key."""
        url = f"{ASM_BASE_URL}/projects"
        resp = self.session.get(url, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        return data.get("result", [])

    def fetch_technologies(
        self,
        project_id: Any,
        search_query: str = "first_seen_after:2000-01-01",
        page_size: int = 1000,
        max_pages: Optional[int] = None,
        cpe_types: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Fetches all fingerprinted technologies / CPEs from an ASM project."""
        encoded_query = urllib.parse.quote(search_query) if search_query.strip() else ""
        url = f"{ASM_BASE_URL}/search/technologies/{encoded_query}"

        headers = {"PROJECT-ID": str(project_id)}
        page_token = None
        all_hits: List[Dict[str, Any]] = []
        page_num = 0

        while True:
            page_num += 1
            params: Dict[str, Any] = {"page_size": page_size}
            if page_token:
                params["page_token"] = page_token

            resp = self.session.get(url, headers=headers, params=params, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            result = data.get("result", {})
            hits = result.get("hits", [])

            for hit in hits:
                if cpe_types:
                    hit_type = (hit.get("cpe_type") or "").lower()
                    if hit_type not in cpe_types:
                        continue
                all_hits.append(hit)

            total_pages = result.get("total_pages", 1)
            print(
                f"  -> Page {page_num}/{total_pages}: Retrieved {len(hits)} technologies "
                f"(total accumulated: {len(all_hits)})",
                file=sys.stderr,
            )

            if max_pages and page_num >= max_pages:
                print(f"  Reached max pages limit ({max_pages}). Stopping pagination.", file=sys.stderr)
                break

            if not result.get("more"):
                break

            page_token = result.get("next_page_token")
            if not page_token:
                break

        return all_hits


# ==============================================================================
# 3. GTI Watchlist & Identity Client
# ==============================================================================

class GTIWatchlistClient:
    """Client for GTI Watchlists and token exchange."""

    def __init__(self, api_key: str, timeout: int = 30):
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    def resolve_gti_gcp_project(self) -> str:
        """Resolves the organization's GTI GCP project ID from the API key."""
        user_url = f"{VT_BASE_URL}/users/{self.api_key}"
        resp = self.session.get(user_url, headers={"x-apikey": self.api_key}, timeout=self.timeout)
        resp.raise_for_status()
        user_data = resp.json().get("data", {})
        attributes = user_data.get("attributes", {})
        privileges = attributes.get("privileges", {})

        group_id = None
        for priv_key in ("alerts-technology-watchlist", "google-threat-intel", "tenants", "activity-logs"):
            priv = privileges.get(priv_key, {})
            if priv.get("granted") and priv.get("inherited_from"):
                group_id = priv.get("inherited_from")
                break

        if not group_id:
            raise RuntimeError(
                "Could not find an active GTI organization group associated with this API key. "
                "Please specify --gti-project-id manually."
            )

        group_url = f"{VT_BASE_URL}/groups/{group_id}"
        resp = self.session.get(group_url, headers={"x-apikey": self.api_key}, timeout=self.timeout)
        resp.raise_for_status()
        group_data = resp.json().get("data", {})
        group_attrs = group_data.get("attributes", {})

        gti_project = group_attrs.get("gti_gcp_project")
        if not gti_project:
            raise RuntimeError(
                f"Group '{group_id}' does not have 'gti_gcp_project' configured. "
                "Please specify --gti-project-id manually."
            )

        return gti_project

    def exchange_bearer_token(self) -> str:
        """Exchanges the GTI API key for an OAuth 2.0 Bearer token."""
        payload = {"api_key": self.api_key}
        resp = self.session.post(IDP_TOKEN_URL, json=payload, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        token = data.get("access_token")
        if not token:
            raise RuntimeError(f"Token exchange response missing 'access_token': {data}")
        return token

    def list_technology_watchlists(
        self, bearer_token: str, gti_project_id: str
    ) -> List[Dict[str, Any]]:
        """Lists existing technology_watchlist configurations in the project."""
        url = f"{GTI_API_BASE_URL}/projects/{gti_project_id}/configurations"
        headers = {
            "Authorization": f"Bearer {bearer_token}",
            "x-goog-user-project": gti_project_id,
        }
        params = {
            "filter": 'detail.detail_type="technology_watchlist"',
            "pageSize": 100,
        }
        resp = self.session.get(url, headers=headers, params=params, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        return data.get("configurations", [])

    def upsert_technology_watchlist(
        self,
        bearer_token: str,
        gti_project_id: str,
        technologies: List[str],
        watchlist_name: str,
        watchlist_id: Optional[str] = None,
        description: str = "Synchronized from Mandiant Attack Surface Management (ASM)",
        mode: str = "merge",
        existing_config: Optional[Dict[str, Any]] = None,
        priority_min: str = "P2",
        cvss_min: float = 7.0,
        epss_min: float = 0.5,
        risk_rating_min: str = "HIGH",
        exploitation_states: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Creates or updates a GTI Target Technology Watchlist."""
        url = f"{GTI_API_BASE_URL}/projects/{gti_project_id}/configurations:upsert"
        headers = {
            "Authorization": f"Bearer {bearer_token}",
            "x-goog-user-project": gti_project_id,
            "Content-Type": "application/json",
        }

        if exploitation_states is None:
            exploitation_states = [
                "EXPLOITATION_STATE_CONFIRMED",
                "EXPLOITATION_STATE_WIDESPREAD",
                "EXPLOITATION_STATE_SUSPECTED",
            ]

        alert_threshold = {
            "priorityMinimum": priority_min,
            "cvssScoreMinimum": cvss_min,
            "epssScoreMinimum": epss_min,
            "exploitationStates": exploitation_states,
            "riskRatingMinimum": risk_rating_min,
        }

        final_technologies: List[str] = []
        seen_lower: Set[str] = set()

        if existing_config and mode == "merge":
            existing_techs = (
                existing_config.get("detail", {})
                .get("technologyWatchlist", {})
                .get("technologies", [])
            )
            for t in existing_techs:
                t_clean = t.strip()
                if t_clean and t_clean.lower() not in seen_lower:
                    seen_lower.add(t_clean.lower())
                    final_technologies.append(t_clean)

            existing_threshold = (
                existing_config.get("detail", {})
                .get("technologyWatchlist", {})
                .get("alertThreshold")
            )
            if existing_threshold:
                alert_threshold = existing_threshold

            provider = existing_config.get("provider", "technology_watchlist")
            state = existing_config.get("state", "ENABLED")
            resource_name = existing_config.get("name")
        else:
            provider = "technology_watchlist"
            state = "ENABLED"
            if watchlist_id:
                if watchlist_id.startswith("projects/"):
                    resource_name = watchlist_id
                else:
                    resource_name = f"projects/{gti_project_id}/configurations/{watchlist_id}"
            else:
                resource_name = None

        for t in technologies:
            t_clean = t.strip()
            if t_clean and t_clean.lower() not in seen_lower:
                seen_lower.add(t_clean.lower())
                final_technologies.append(t_clean)

        body: Dict[str, Any] = {
            "displayName": watchlist_name,
            "provider": provider,
            "state": state,
            "description": description,
            "detail": {
                "detailType": "technology_watchlist",
                "technologyWatchlist": {
                    "technologies": final_technologies,
                    "alertThreshold": alert_threshold,
                },
            },
        }

        if resource_name:
            body["name"] = resource_name

        resp = self.session.post(url, headers=headers, json=body, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()


# ==============================================================================
# 4. CLI Argument Parser & Main Flow
# ==============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pull CPEs from Mandiant ASM and sync to GTI Target Technology Watchlist.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1. List Mandiant ASM projects and GTI watchlists
  %(prog)s --list-asm-projects --list-watchlists

  # 2. Preview CPE extraction from an ASM project in dry-run mode
  %(prog)s --asm-project-id 12345 --dry-run

  # 3. Pull CPEs, export to files, and dry-run merge into a watchlist
  %(prog)s --asm-project-id 12345 \\
           --watchlist-name "Example Org Tech Watchlist" \\
           --export-json asm_cpes.json \\
           --export-cpe-txt cpe_list.txt \\
           --export-watchlist-txt watchlist_items.txt \\
           --dry-run

  # 4. Apply changes (upsert/merge into GTI Watchlist)
  %(prog)s --asm-project-id 12345 \\
           --watchlist-name "Example Org Tech Watchlist" \\
           --mode merge \\
           --apply
""",
    )

    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "-k", "--api-key",
        default=os.environ.get("GTI_API_KEY") or os.environ.get("VT_API_KEY"),
        help="GTI / VirusTotal API v3 key (defaults to $GTI_API_KEY or $VT_API_KEY).",
    )
    auth_group.add_argument(
        "--gti-project-id",
        help="GTI GCP project ID (e.g. gti-00000000-0000-0000-0000-00). Auto-discovered from API key if omitted.",
    )

    asm_group = parser.add_argument_group("Mandiant ASM Options")
    asm_group.add_argument(
        "-p", "--asm-project-id",
        help="ASM Project ID (number or string, e.g. 12345).",
    )
    asm_group.add_argument(
        "--asm-project-name",
        help="ASM Project Name (e.g. 'example_asm_project'). Used to look up project ID if --asm-project-id is omitted.",
    )
    asm_group.add_argument(
        "--list-asm-projects",
        action="store_true",
        help="List all accessible Mandiant ASM projects and exit.",
    )
    asm_group.add_argument(
        "--asm-query",
        default="first_seen_after:2000-01-01",
        help="Search query to filter ASM technologies (default: 'first_seen_after:2000-01-01').",
    )
    asm_group.add_argument(
        "--cpe-types",
        help="Comma-separated CPE types to include: application,service,os,hardware (default: all).",
    )
    asm_group.add_argument(
        "--page-size",
        type=int,
        default=1000,
        help="Page size for ASM technologies query (1-1000, default 1000).",
    )
    asm_group.add_argument(
        "--max-pages",
        type=int,
        help="Maximum pages to fetch from ASM (useful for sampling or quick testing).",
    )

    cpe_group = parser.add_argument_group("CPE & Watchlist Formatting Options")
    cpe_group.add_argument(
        "--strip-versions",
        action="store_true",
        help="Strip versions from CPEs, matching against vendor & product only (broad matching).",
    )
    cpe_group.add_argument(
        "--collapse-same-vendor-product",
        action="store_true",
        help="If vendor == product (e.g. 'php php'), collapse to single name ('php').",
    )

    gti_group = parser.add_argument_group("GTI Target Technology Watchlist Options")
    gti_group.add_argument(
        "--list-watchlists",
        action="store_true",
        help="List existing GTI Target Technology Watchlists in the project and exit.",
    )
    gti_group.add_argument(
        "-w", "--watchlist-name",
        default="Mandiant ASM Watchlist",
        help="Display name of the GTI Target Technology Watchlist (default: 'Mandiant ASM Watchlist').",
    )
    gti_group.add_argument(
        "--watchlist-id",
        help="Specific watchlist configuration ID or resource name to update (optional).",
    )
    gti_group.add_argument(
        "--mode",
        choices=["merge", "replace"],
        default="merge",
        help="Merge with existing watchlist technologies or replace completely (default: merge).",
    )
    gti_group.add_argument(
        "--priority-min",
        choices=["P0", "P1", "P2", "P3", "P4"],
        default="P2",
        help="Alert threshold minimum priority (default: P2).",
    )
    gti_group.add_argument(
        "--cvss-min",
        type=float,
        default=7.0,
        help="Alert threshold minimum CVSS score (default: 7.0).",
    )
    gti_group.add_argument(
        "--epss-min",
        type=float,
        default=0.5,
        help="Alert threshold minimum EPSS score (default: 0.5).",
    )
    gti_group.add_argument(
        "--risk-rating-min",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNRATED"],
        default="HIGH",
        help="Alert threshold minimum risk rating (default: HIGH).",
    )

    output_group = parser.add_argument_group("Output & Execution Mode")
    output_group.add_argument(
        "--export-json",
        help="Save raw extracted CPE records with metadata to a JSON file.",
    )
    output_group.add_argument(
        "--export-cpe-txt",
        help="Save raw unique CPE strings (one per line) to a text file.",
    )
    output_group.add_argument(
        "--export-watchlist-txt",
        help="Save formatted GTI watchlist entries (one per line) to a text file.",
    )
    output_group.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes to GTI. If omitted, runs in DRY-RUN mode without modifying GTI.",
    )
    output_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Explicitly run in dry-run mode (default behavior unless --apply is passed).",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    api_key = args.api_key
    if not api_key:
        print(
            "Error: No GTI/VirusTotal API key provided. Set GTI_API_KEY/VT_API_KEY env var or pass --api-key.",
            file=sys.stderr,
        )
        return 1

    asm_client = MandiantASMClient(api_key=api_key)
    gti_client = GTIWatchlistClient(api_key=api_key)

    if args.list_asm_projects:
        print("\n=== Mandiant ASM Projects ===")
        projects = asm_client.list_projects()
        if not projects:
            print("  No ASM projects found.")
        for p in projects:
            p_id = p.get("id")
            p_name = p.get("name")
            p_org = p.get("organization_name")
            p_role = p.get("role")
            p_primary = p.get("primary", False)
            star = "*" if p_primary else " "
            print(f" {star} ID: {p_id:<7} | Name: {p_name:<24} | Role: {p_role:<8} | Org: {p_org}")
        print("=============================\n")
        if not args.list_watchlists and not args.asm_project_id and not args.asm_project_name:
            return 0

    if args.list_watchlists:
        print("\n=== GTI Target Technology Watchlists ===")
        gti_project = args.gti_project_id or gti_client.resolve_gti_gcp_project()
        bearer_token = gti_client.exchange_bearer_token()
        watchlists = gti_client.list_technology_watchlists(bearer_token, gti_project)
        if not watchlists:
            print("  No Technology Watchlists found.")
        for w in watchlists:
            w_name = w.get("displayName")
            w_id = w.get("name")
            w_state = w.get("state")
            w_techs = (
                w.get("detail", {})
                .get("technologyWatchlist", {})
                .get("technologies", [])
            )
            print(f"  - Name: {w_name}")
            print(f"    Resource: {w_id}")
            print(f"    State:    {w_state}")
            print(f"    Items:    {len(w_techs)} technologies")
            if w_techs:
                sample = ", ".join(w_techs[:5])
                if len(w_techs) > 5:
                    sample += f", ... (+{len(w_techs)-5} more)"
                print(f"    Sample:   {sample}")
            print()
        print("=========================================\n")
        if not args.asm_project_id and not args.asm_project_name:
            return 0

    asm_project_id = args.asm_project_id
    if not asm_project_id:
        projects = asm_client.list_projects()
        if args.asm_project_name:
            matching = [p for p in projects if p.get("name") == args.asm_project_name]
            if not matching:
                print(f"Error: No ASM project found matching name '{args.asm_project_name}'.", file=sys.stderr)
                return 1
            asm_project_id = matching[0].get("id")
        else:
            primaries = [p for p in projects if p.get("primary")]
            if primaries:
                asm_project_id = primaries[0].get("id")
                print(f"[*] No ASM project specified. Defaulting to primary project: '{primaries[0].get('name')}' (ID: {asm_project_id})")
            elif projects:
                asm_project_id = projects[0].get("id")
                print(f"[*] No ASM project specified. Defaulting to first project: '{projects[0].get('name')}' (ID: {asm_project_id})")
            else:
                print("Error: No ASM projects accessible with this API key.", file=sys.stderr)
                return 1

    print(f"\n[1/4] Pulling technologies from Mandiant ASM project ID: {asm_project_id}...")
    cpe_types_set = (
        {t.strip().lower() for t in args.cpe_types.split(",") if t.strip()}
        if args.cpe_types
        else None
    )

    tech_hits = asm_client.fetch_technologies(
        project_id=asm_project_id,
        search_query=args.asm_query,
        page_size=args.page_size,
        max_pages=args.max_pages,
        cpe_types=cpe_types_set,
    )
    print(f"[*] Retrieved {len(tech_hits)} raw technology records from ASM.")

    print("\n[2/4] Normalizing CPE 2.3 strings to GTI Target Technology Watchlist format...")
    cpe_records: Dict[str, Dict[str, Any]] = {}
    watchlist_entries: Set[str] = set()
    skipped_count = 0

    for hit in tech_hits:
        raw_cpe = hit.get("cpe")
        if not raw_cpe or not raw_cpe.startswith("cpe:2.3:"):
            skipped_count += 1
            continue

        raw_cpe = raw_cpe.strip()
        wl_entry = cpe_to_watchlist_entry(
            raw_cpe,
            include_version=not args.strip_versions,
            collapse_same_vendor_product=args.collapse_same_vendor_product,
        )

        if not wl_entry:
            skipped_count += 1
            continue

        watchlist_entries.add(wl_entry)

        if raw_cpe not in cpe_records:
            cpe_records[raw_cpe] = {
                "cpe": raw_cpe,
                "watchlist_entry": wl_entry,
                "vendor": hit.get("vendor"),
                "product": hit.get("product"),
                "version": hit.get("version"),
                "cpe_type": hit.get("cpe_type"),
                "name": hit.get("name"),
                "count": 0,
            }
        cpe_records[raw_cpe]["count"] += 1

    sorted_watchlist_entries = sorted(watchlist_entries, key=lambda s: s.lower())
    print(f"[*] Processed {len(cpe_records)} unique valid CPEs.")
    print(f"[*] Formatted into {len(sorted_watchlist_entries)} unique GTI Watchlist entries (<vendor> <product> [version]).")
    if skipped_count:
        print(f"[*] Skipped {skipped_count} invalid or incomplete technology records.")

    if args.export_json:
        with open(args.export_json, "w", encoding="utf-8") as f:
            json.dump(list(cpe_records.values()), f, indent=2)
        print(f"[+] Exported raw CPE records to: {args.export_json}")

    if args.export_cpe_txt:
        with open(args.export_cpe_txt, "w", encoding="utf-8") as f:
            for c in sorted(cpe_records.keys()):
                f.write(f"{c}\n")
        print(f"[+] Exported unique CPE list to: {args.export_cpe_txt}")

    if args.export_watchlist_txt:
        with open(args.export_watchlist_txt, "w", encoding="utf-8") as f:
            for item in sorted_watchlist_entries:
                f.write(f"{item}\n")
        print(f"[+] Exported GTI Watchlist entries to: {args.export_watchlist_txt}")

    print("\n--- Sample Converted Watchlist Entries (first 10) ---")
    for sample in sorted_watchlist_entries[:10]:
        print(f"  • {sample}")
    if len(sorted_watchlist_entries) > 10:
        print(f"  ... and {len(sorted_watchlist_entries)-10} more.")
    print("----------------------------------------------------\n")

    print("[3/4] Preparing GTI Target Technology Watchlist sync...")
    gti_project = args.gti_project_id or gti_client.resolve_gti_gcp_project()
    print(f"[*] GTI Organization GCP Project: {gti_project}")

    bearer_token = gti_client.exchange_bearer_token()
    existing_watchlists = gti_client.list_technology_watchlists(bearer_token, gti_project)

    target_config = None
    if args.watchlist_id:
        for w in existing_watchlists:
            if w.get("name") == args.watchlist_id or w.get("name", "").endswith(f"/{args.watchlist_id}"):
                target_config = w
                break
    else:
        for w in existing_watchlists:
            if w.get("displayName") == args.watchlist_name:
                target_config = w
                break

    if target_config:
        print(f"[*] Found existing watchlist '{target_config.get('displayName')}' ({target_config.get('name')}).")
        existing_items = (
            target_config.get("detail", {})
            .get("technologyWatchlist", {})
            .get("technologies", [])
        )
        print(f"[*] Existing technologies in watchlist: {len(existing_items)}")
    else:
        print(f"[*] Watchlist '{args.watchlist_name}' does not exist yet. Will create a new configuration.")

    if not args.apply:
        print("\n[4/4] DRY-RUN MODE (No changes written to GTI)")
        print(f"  Watchlist Name:  {args.watchlist_name}")
        print(f"  Sync Mode:       {args.mode}")
        if target_config and args.mode == "merge":
            combined_len = len(
                set([t.lower() for t in existing_items] + [t.lower() for t in sorted_watchlist_entries])
            )
            print(f"  Merge Preview:   {len(existing_items)} existing + {len(sorted_watchlist_entries)} new -> {combined_len} unique technologies.")
        else:
            print(f"  Upload Count:    {len(sorted_watchlist_entries)} technologies.")
        print("\n[!] To execute this sync against your live GTI environment, run with '--apply':")
        cmd_args = [arg for arg in sys.argv[1:] if arg not in ("--dry-run",)]
        if "--apply" not in cmd_args:
            cmd_args.append("--apply")
        print(f"    python3 {sys.argv[0]} {' '.join(cmd_args)}\n")
        return 0

    print("\n[4/4] APPLYING CHANGES TO GTI TARGET TECHNOLOGY WATCHLIST...")
    res = gti_client.upsert_technology_watchlist(
        bearer_token=bearer_token,
        gti_project_id=gti_project,
        technologies=sorted_watchlist_entries,
        watchlist_name=args.watchlist_name,
        watchlist_id=args.watchlist_id,
        mode=args.mode,
        existing_config=target_config,
        priority_min=args.priority_min,
        cvss_min=args.cvss_min,
        epss_min=args.epss_min,
        risk_rating_min=args.risk_rating_min,
    )
    final_tech_count = len(
        res.get("detail", {})
        .get("technologyWatchlist", {})
        .get("technologies", [])
    )
    print(f"\n[SUCCESS] Successfully synced {final_tech_count} technologies to GTI Watchlist!")
    print(f"  Resource Name: {res.get('name')}")
    print(f"  Display Name:  {res.get('displayName')}")
    print(f"  State:         {res.get('state')}")
    print(f"  CVE Matching:  Active (Thresholds: Priority>={args.priority_min}, CVSS>={args.cvss_min}, EPSS>={args.epss_min})\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
