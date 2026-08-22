"""
fetch_nvd_cves.py
------------------
Pulls real CVE records from the NVD REST API (v2.0) to serve as the
candidate pool for the Exploit Prioritizer dataset.

Usage:
    python fetch_nvd_cves.py --start-year 2018 --end-year 2025 --out data/nvd_raw.json

Notes on rate limits:
  - Without an API key: 5 requests / 30 seconds (this script sleeps 6s between calls)
  - With an API key (free, from https://nvd.nist.gov/developers/request-an-api-key):
    50 requests / 30 seconds -> pass --api-key YOUR_KEY
  - The script writes incrementally and supports --resume, so if it gets
    interrupted (or rate-limited) you can just re-run it.
  - NVD rejects (404) any single request whose pubStartDate/pubEndDate span
    exceeds 120 days, so this script automatically splits the requested
    year range into <=120-day windows internally -- you still just pass
    --start-year/--end-year.
"""
import argparse
import json
import os
import time
import urllib.request
import urllib.error

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000  # NVD max per page


def fetch_page(start_index, api_key=None, pub_start=None, pub_end=None):
    params = f"resultsPerPage={PAGE_SIZE}&startIndex={start_index}"
    if pub_start and pub_end:
        params += f"&pubStartDate={pub_start}&pubEndDate={pub_end}"
    url = f"{NVD_BASE}?{params}"
    req = urllib.request.Request(url)
    if api_key:
        req.add_header("apiKey", api_key)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def extract_record(vuln):
    cve = vuln.get("cve", {})
    cve_id = cve.get("id")

    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    metrics = cve.get("metrics", {})
    cvss_score, cvss_vector, severity = None, None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss_data = m.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = m.get("baseSeverity") or cvss_data.get("baseSeverity")
            break

    cwe_ids = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwe_ids.append(d["value"])

    return {
        "cve_id": cve_id,
        "description": desc,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "cwe": cwe_ids[0] if cwe_ids else None,
        "published": cve.get("published"),
    }


def daterange_chunks(start_year, end_year, max_days=120):
    """NVD API rejects (404) any pubStartDate/pubEndDate range over 120
    days -- split the requested year range into <=120-day windows."""
    from datetime import date, timedelta
    start = date(start_year, 1, 1)
    end = date(end_year, 12, 31)
    cur = start
    while cur <= end:
        chunk_end = min(cur + timedelta(days=max_days - 1), end)
        yield cur, chunk_end
        cur = chunk_end + timedelta(days=1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start-year", type=int, default=2018)
    ap.add_argument("--end-year", type=int, default=2025)
    ap.add_argument("--out", default="data/nvd_raw.json")
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"))
    ap.add_argument("--resume", action="store_true",
                     help="Skip date windows already present in --out")
    ap.add_argument("--max-per-window", type=int, default=8000,
                     help="Cap records per 120-day window to keep dataset size sane")
    args = ap.parse_args()

    sleep_s = 2.5 if args.api_key else 6.5

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    records = []
    done_windows = set()
    if args.resume and os.path.exists(args.out):
        with open(args.out, encoding="utf-8") as f:
            existing = json.load(f)
        records = existing.get("records", [])
        done_windows = set(existing.get("done_windows", existing.get("done_years", [])))
        print(f"[resume] loaded {len(records)} existing records, "
              f"{len(done_windows)} windows already done")

    for win_start, win_end in daterange_chunks(args.start_year, args.end_year):
        window_key = f"{win_start.isoformat()}_{win_end.isoformat()}"
        if window_key in done_windows:
            print(f"[skip] {window_key} already fetched")
            continue

        pub_start = f"{win_start.isoformat()}T00:00:00.000"
        pub_end = f"{win_end.isoformat()}T23:59:59.999"

        window_records = []
        start_index = 0
        total_results = None

        while True:
            try:
                page = fetch_page(start_index, args.api_key, pub_start, pub_end)
            except urllib.error.HTTPError as e:
                if e.code == 403 or e.code == 429:
                    print(f"  [rate-limited] sleeping 30s and retrying...")
                    time.sleep(30)
                    continue
                raise

            total_results = page.get("totalResults", 0)
            vulns = page.get("vulnerabilities", [])
            for v in vulns:
                rec = extract_record(v)
                if rec["description"]:
                    window_records.append(rec)

            print(f"  [{window_key}] fetched {start_index + len(vulns)}/{total_results}")
            start_index += PAGE_SIZE
            time.sleep(sleep_s)

            if start_index >= total_results or len(window_records) >= args.max_per_window:
                break

        window_records = window_records[: args.max_per_window]
        records.extend(window_records)
        done_windows.add(window_key)

        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"records": records, "done_windows": sorted(done_windows)}, f)
        print(f"[+] Window {window_key} done: {len(window_records)} records "
              f"(total so far: {len(records)})")

    print(f"\n[done] Total CVE records saved to {args.out}: {len(records)}")


if __name__ == "__main__":
    main()
