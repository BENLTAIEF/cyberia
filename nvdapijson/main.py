import requests
import time
import json
import os
from datetime import datetime, timedelta
from calendar import monthrange
from pathlib import Path

# ── Config NVD ────────────────────────────────────────────────
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
if not NVD_API_KEY:
    raise ValueError("NVD_API_KEY environment variable is required")
NVD_URL     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_HEADERS = {"apiKey": NVD_API_KEY, "User-Agent": "Mozilla/5.0"}

# ── Config volume ─────────────────────────────────────────────
OUTPUT_DIR  = os.environ.get("OUTPUT_DIR", "/data")   # monté depuis l'hôte
START_YEAR  = int(os.environ.get("START_YEAR",  "2023"))
START_MONTH = int(os.environ.get("START_MONTH", "1"))
SEVERITY    = os.environ.get("SEVERITY", "")           # vide = tous


def get_cves_for_month(year: int, month: int) -> list:
    last_day = monthrange(year, month)[1]
    params = {
        "pubStartDate":   datetime(year, month, 1).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate":     datetime(year, month, last_day, 23, 59, 59).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": 2000,
        "startIndex":     0,
    }
    if SEVERITY:
        params["cvssV3Severity"] = SEVERITY.upper()

    all_cves = []
    while True:
        try:
            resp = requests.get(NVD_URL, params=params, headers=NVD_HEADERS, timeout=30)
            if resp.status_code in (403, 503):
                print(f"    Rate limit ({resp.status_code}) — pause 30s")
                time.sleep(30)
                continue
            resp.raise_for_status()
            data  = resp.json()
            vulns = data.get("vulnerabilities", [])
            all_cves.extend(vulns)
            total = data.get("totalResults", 0)
            params["startIndex"] += len(vulns)
            print(f"    {params['startIndex']}/{total} CVEs récupérés")
            if params["startIndex"] >= total or len(vulns) == 0:
                break
            time.sleep(0.6)
        except requests.exceptions.RequestException as e:
            print(f"    Erreur réseau : {e} — retry 10s")
            time.sleep(10)

    return all_cves


def run():
    today  = datetime.utcnow()
    cursor = datetime(START_YEAR, START_MONTH, 1)

    while cursor <= today:
        year, month = cursor.year, cursor.month

        # Dossier par année sur le volume monté
        folder = Path(OUTPUT_DIR) / str(year)
        folder.mkdir(parents=True, exist_ok=True)
        filepath = folder / f"{year}-{month:02d}.json"

        is_current_month = (year == today.year and month == today.month)

        # Skip si fichier déjà présent (sauf mois courant)
        if not is_current_month and filepath.exists():
            print(f"  ⏭  {year}-{month:02d} déjà présent ({filepath}), skip")
        else:
            print(f"  ⬇  {year}-{month:02d} en cours...")
            cves = get_cves_for_month(year, month)

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(cves, f, indent=2, ensure_ascii=False)

            print(f"  ✅ {filepath} — {len(cves)} CVEs")
            time.sleep(1)

        cursor = datetime(year + 1, 1, 1) if month == 12 else datetime(year, month + 1, 1)

    print("\nIngestion terminée ✅")


if __name__ == "__main__":
    run()