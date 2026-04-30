"""
extract_certeu_advisories.py — Extraction CERT-EU Security Advisories depuis 2020
Sortie : un fichier JSONL par année dans ./certeu_data/
"""
import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://cert.europa.eu/publications/security-advisories"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
CVSS_RE = re.compile(r"CVSS(?:[^0-9]{0,30}?)(\d+\.\d+)", re.IGNORECASE)
SECTION_RE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)
REF_RE = re.compile(r"\[(\d+)\]\s*(https?://\S+)")

SECTION_ALIASES = {
    "summary": "summary",
    "technical details": "technical_details",
    "technical detail": "technical_details",
    "affected products": "affected_products",
    "products affected": "affected_products",
    "affected product": "affected_products",
    "recommendations": "recommendations",
    "recommendation": "recommendations",
    "references": "references",
    "reference": "references",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("certeu")


# --------------------------------------------------------------------------
# HTTP session with retries
# --------------------------------------------------------------------------
def make_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=4,
        backoff_factor=2.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update({
        "User-Agent": "cve-research-pipeline/1.0",
        "Accept": "text/markdown, text/plain, */*",
    })
    return s


# --------------------------------------------------------------------------
# Section splitting
# --------------------------------------------------------------------------
def split_sections(body: str) -> dict[str, str]:
    """Découpe le corps markdown en sections sur les H1, normalise les noms."""
    sections: dict[str, str] = {}
    matches = list(SECTION_RE.finditer(body))
    if not matches:
        return sections

    for i, m in enumerate(matches):
        raw_title = m.group(1).strip()
        key = SECTION_ALIASES.get(raw_title.lower(), f"_other:{raw_title}")
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        sections[key] = body[start:end].strip()

    return sections


def parse_references(refs_section: str | None) -> list[dict]:
    """Extrait [{index, url}, ...] depuis la section References."""
    if not refs_section:
        return []
    return [
        {"index": int(m.group(1)), "url": m.group(2).rstrip(".,;)")}
        for m in REF_RE.finditer(refs_section)
    ]


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
def parse_markdown(advisory_id: str, raw: str) -> dict:
    """Extrait le frontmatter YAML + sections + métadonnées."""
    frontmatter, body = {}, raw

    if raw.startswith("---"):
        try:
            end = raw.index("---", 3)
            frontmatter = yaml.safe_load(raw[3:end]) or {}
            body = raw[end + 3:].lstrip()
        except (ValueError, yaml.YAMLError):
            log.warning(f"{advisory_id}: frontmatter parse failed, using full body")

    sections = split_sections(body)
    references_struct = parse_references(sections.get("references"))

    cves = sorted(set(CVE_RE.findall(body)))
    cvss_match = CVSS_RE.search(body)
    cvss = float(cvss_match.group(1)) if cvss_match else None

    title = (frontmatter.get("title") or "").strip()
    release_date = frontmatter.get("release_date") or frontmatter.get("date")

    return {
        "advisory_id": f"CERT-EU-SA-{advisory_id}",
        "source": "CERT-EU",
        "advisory_type": "security_advisory",
        "raw_id": advisory_id,
        "title": title,
        "release_date": str(release_date) if release_date else None,
        "history": frontmatter.get("history"),
        "cves": cves,
        "cve_count": len(cves),
        "cvss_score": cvss,
        "url": f"{BASE}/{advisory_id}/",
        "url_markdown": f"{BASE}/{advisory_id}/markdown",
        "summary": sections.get("summary"),
        "technical_details": sections.get("technical_details"),
        "affected_products": sections.get("affected_products"),
        "recommendations": sections.get("recommendations"),
        "references": sections.get("references"),
        "references_urls": references_struct,
        "body_markdown": body,
        "frontmatter": frontmatter,
        "unknown_sections": [k.split(":", 1)[1] for k in sections if k.startswith("_other:")],
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }


# --------------------------------------------------------------------------
# Fetch one advisory
# --------------------------------------------------------------------------
def fetch_advisory(session: requests.Session, advisory_id: str) -> dict | None:
    url = f"{BASE}/{advisory_id}/markdown"
    r = session.get(url, timeout=20)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return parse_markdown(advisory_id, r.text)


# --------------------------------------------------------------------------
# Extract one year
# --------------------------------------------------------------------------
def extract_year(
    year: int,
    out_dir: Path,
    throttle: float = 0.5,
    max_seq: int = 250,
    miss_limit: int = 15,
) -> int:
    """Itère YYYY-001..YYYY-NNN et écrit chaque advisory dans un JSONL."""
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"certeu_advisories_{year}.jsonl"

    count = 0
    consecutive_miss = 0

    with make_session() as session, out_file.open("w", encoding="utf-8") as fh:
        for n in range(1, max_seq + 1):
            advisory_id = f"{year}-{n:03d}"

            try:
                data = fetch_advisory(session, advisory_id)
            except requests.HTTPError as e:
                log.warning(f"{advisory_id}: HTTP {e.response.status_code} → skip")
                consecutive_miss += 1
                if consecutive_miss >= miss_limit:
                    break
                continue
            except requests.RequestException as e:
                log.error(f"{advisory_id}: network error: {e} → skip")
                continue

            if data is None:
                consecutive_miss += 1
                if consecutive_miss >= miss_limit:
                    log.info(
                        f"{year}: stopping after {miss_limit} consecutive misses "
                        f"(last tried: {advisory_id})"
                    )
                    break
                continue

            consecutive_miss = 0
            fh.write(json.dumps(data, ensure_ascii=False, default=str) + "\n")
            count += 1
            log.info(
                f"{advisory_id}: OK | "
                f"{data['cve_count']} CVEs | "
                f"CVSS={data['cvss_score']} | "
                f"{(data['title'] or '')[:60]}"
            )
            time.sleep(throttle)

    log.info(f"{year}: {count} advisories saved → {out_file}")
    return count


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main(start_year: int = 2020, end_year: int | None = None):
    end_year = end_year or datetime.now().year
    out_dir = Path("D:/work/github/data/certeu/jsonl")
    total = 0
    for year in range(start_year, end_year + 1):
        total += extract_year(year, out_dir)
    log.info(f"=== DONE: {total} advisories extracted from {start_year} to {end_year} ===")


if __name__ == "__main__":
    main()