"""
Téléchargement complet de l'API FIRST EPSS
https://api.first.org/data/v1/epss

- Pagination automatique (total ~327 000 CVEs)
- Requêtes asynchrones (aiohttp) avec concurrence contrôlée
- Retry exponentiel sur erreurs réseau / rate-limit
- Sauvegarde incrémentale en JSONL + export CSV final
- Progress bar tqdm

Usage :
    pip install aiohttp tqdm
    python main.py
    python main.py --output epss.csv --limit 10000 --concurrency 5
"""

import asyncio
import argparse
import csv
import json
import logging
import time
from pathlib import Path

import aiohttp
from tqdm.asyncio import tqdm as async_tqdm

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_URL = "https://api.first.org/data/v1/epss"
DEFAULT_PAGE_SIZE = 10000   # réduit à 100 si l'API rejette les grandes pages
DEFAULT_CONCURRENCY = 5     # requêtes parallèles simultanées
DEFAULT_OUTPUT = "epss_full.csv"
JSONL_CACHE = "epss_cache.jsonl"
MAX_RETRIES = 5
RETRY_BACKOFF = 2.0         # secondes, doublé à chaque retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def fetch_page(
    session: aiohttp.ClientSession,
    offset: int,
    limit: int,
    semaphore: asyncio.Semaphore,
) -> list[dict]:
    """Récupère une page et retourne la liste de records."""
    params = {"offset": offset, "limit": limit}
    attempt = 0
    delay = RETRY_BACKOFF

    async with semaphore:
        while attempt < MAX_RETRIES:
            try:
                async with session.get(BASE_URL, params=params) as resp:
                    if resp.status == 429:
                        retry_after = int(resp.headers.get("Retry-After", delay))
                        log.warning("Rate-limit (429) – attente %ss", retry_after)
                        await asyncio.sleep(retry_after)
                        attempt += 1
                        continue

                    resp.raise_for_status()
                    payload = await resp.json(content_type=None)
                    return payload["data"]

            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                attempt += 1
                if attempt >= MAX_RETRIES:
                    log.error("Échec offset=%d après %d tentatives : %s", offset, MAX_RETRIES, exc)
                    raise
                log.warning("Erreur offset=%d (tentative %d/%d) : %s – retry dans %.1fs",
                            offset, attempt, MAX_RETRIES, exc, delay)
                await asyncio.sleep(delay)
                delay *= 2

    return []


async def probe_limit(session: aiohttp.ClientSession, requested_limit: int) -> tuple[int, int]:
    """
    Sonde l'API pour obtenir le total réel et la limite effective
    (l'API peut plafonner le limit silencieusement).
    """
    params = {"offset": 0, "limit": requested_limit}
    async with session.get(BASE_URL, params=params) as resp:
        resp.raise_for_status()
        payload = await resp.json(content_type=None)

    total = payload["total"]
    effective_limit = payload["limit"]  # valeur réelle appliquée par l'API

    if effective_limit != requested_limit:
        log.warning(
            "L'API a plafonné limit=%d → %d. Pagination ajustée.",
            requested_limit, effective_limit,
        )

    log.info("Total CVEs : %d | Page size effective : %d | Pages estimées : %d",
             total, effective_limit, -(-total // effective_limit))

    return total, effective_limit


def write_jsonl(records: list[dict], path: Path, mode: str = "a") -> None:
    with path.open(mode, encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def jsonl_to_csv(jsonl_path: Path, csv_path: Path) -> int:
    """Convertit le fichier JSONL cache en CSV final. Retourne le nb de lignes."""
    fieldnames = ["cve", "epss", "percentile", "date"]
    count = 0
    with jsonl_path.open("r", encoding="utf-8") as fin, \
         csv_path.open("w", newline="", encoding="utf-8") as fout:
        writer = csv.DictWriter(fout, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for line in fin:
            line = line.strip()
            if line:
                writer.writerow(json.loads(line))
                count += 1
    return count


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main(output: str, limit: int, concurrency: int) -> None:
    output_path = Path(output)
    cache_path = Path(JSONL_CACHE)

    # Nettoyage cache précédent
    if cache_path.exists():
        log.info("Suppression du cache précédent : %s", cache_path)
        cache_path.unlink()

    timeout = aiohttp.ClientTimeout(total=60)
    connector = aiohttp.TCPConnector(limit=concurrency * 2)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        # 1. Sonde initiale
        total, effective_limit = await probe_limit(session, limit)

        # 2. Construction des offsets
        offsets = list(range(0, total, effective_limit))
        semaphore = asyncio.Semaphore(concurrency)

        # 3. Téléchargement parallèle avec progress bar
        tasks = [
            fetch_page(session, offset, effective_limit, semaphore)
            for offset in offsets
        ]

        start = time.perf_counter()
        results = await async_tqdm.gather(
            *tasks,
            desc="Téléchargement pages",
            unit="page",
        )
        elapsed = time.perf_counter() - start

    # 4. Écriture JSONL (aplatissement des pages)
    total_records = 0
    for page_records in results:
        if page_records:
            write_jsonl(page_records, cache_path, mode="a")
            total_records += len(page_records)

    log.info("Pages téléchargées : %d | Records : %d | Durée : %.1fs",
             len(offsets), total_records, elapsed)

    # 5. Conversion JSONL → CSV
    log.info("Export CSV → %s", output_path)
    written = jsonl_to_csv(cache_path, output_path)
    log.info("CSV écrit : %d lignes", written)

    # 6. Nettoyage cache
    cache_path.unlink(missing_ok=True)
    log.info("Terminé. Fichier : %s (%.1f MB)",
             output_path, output_path.stat().st_size / 1_048_576)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Téléchargement EPSS API")
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help=f"Fichier CSV de sortie (défaut: {DEFAULT_OUTPUT})")
    parser.add_argument("--limit", type=int, default=DEFAULT_PAGE_SIZE,
                        help=f"Taille de page demandée (défaut: {DEFAULT_PAGE_SIZE})")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                        help=f"Requêtes parallèles (défaut: {DEFAULT_CONCURRENCY})")
    args = parser.parse_args()

    asyncio.run(main(args.output, args.limit, args.concurrency))