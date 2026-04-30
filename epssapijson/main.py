import gzip
import io
import os
import re
from datetime import date, datetime
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

EPSS_BASE = "https://epss.empiricalsecurity.com"
HEADER_RE = re.compile(r"#model_version:(?P<v>[^,]+),score_date:(?P<d>[^,\s]+)")
OUTPUT_DIR  = "/data"   # monté depuis l'hôte

def _session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update({"User-Agent": "vaudoise-epss-pipeline/1.0"})
    return s


def download_epss(target_date: date | None = None, out_dir: Path = Path("./data")) -> dict:
    """Télécharge le CSV EPSS et renvoie metadata + chemin local."""
    out_dir.mkdir(parents=True, exist_ok=True)

    if target_date is None:
        url = f"{EPSS_BASE}/epss_scores-current.csv.gz"
        suffix = "current"
    else:
        url = f"{EPSS_BASE}/epss_scores-{target_date:%Y-%m-%d}.csv.gz"
        suffix = target_date.isoformat()

    with _session() as s:
        r = s.get(url, timeout=60, stream=True)
        r.raise_for_status()
        gz_bytes = r.content

    # Décompression + extraction du header de version
    with gzip.GzipFile(fileobj=io.BytesIO(gz_bytes)) as gz:
        first_line = gz.readline().decode("utf-8").strip()

    m = HEADER_RE.match(first_line)
    if not m:
        raise ValueError(f"Header EPSS inattendu : {first_line!r}")

    model_version = m.group("v")
    score_date = datetime.fromisoformat(m.group("d").replace("Z", "+00:00")).date()

    # Persistance avec naming traçable
    fname = f"/{OUTPUT_DIR}/epss_{score_date.isoformat()}_{model_version}.csv.gz"
    fpath = out_dir / fname
    fpath.write_bytes(gz_bytes)

    return {
        "path": fpath,
        "score_date": score_date,
        "model_version": model_version,
        "size_bytes": len(gz_bytes),
        "url": url,
    }

if __name__ == "__main__":
    meta = download_epss()
    print(meta)