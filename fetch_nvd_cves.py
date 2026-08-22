"""
fetch_nvd_cves.py
------------------
Pulls real CVE records from the NVD REST API (v2.0) to serve as the
candidate pool for the Exploit Prioritizer dataset.

CVSS selection order:
    CVSS v4.0 -> v3.1 -> v3.0 -> v2.0

For every CVE, the script stores the CVSS score together with the
version and source used.

Usage:
    python fetch_nvd_cves.py \
        --start-year 2018 \
        --end-year 2025 \
        --out data/nvd_raw.json

Notes on rate limits:
  - Without an API key: the script uses a conservative delay between calls.
  - With an API key:
        pass --api-key YOUR_KEY
  - The script writes incrementally and supports --resume, so if it gets
    interrupted or rate-limited, it can continue from completed windows.
  - NVD rejects any single pubStartDate/pubEndDate range exceeding
    approximately 120 days, so the requested year range is split into
    smaller windows automatically.
"""

import argparse
import json
import os
import time
import urllib.request
import urllib.error


NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Conservative page size to reduce large-response timeouts.
PAGE_SIZE = 500


def fetch_page(
    start_index,
    api_key=None,
    pub_start=None,
    pub_end=None,
):
    """
    Fetch one page from the NVD CVE API.
    """

    params = (
        f"resultsPerPage={PAGE_SIZE}"
        f"&startIndex={start_index}"
    )

    if pub_start and pub_end:
        params += (
            f"&pubStartDate={pub_start}"
            f"&pubEndDate={pub_end}"
        )

    url = f"{NVD_BASE}?{params}"

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "RedTeamFramework/2.0"
        },
    )

    if api_key:
        req.add_header(
            "apiKey",
            api_key,
        )

    with urllib.request.urlopen(
        req,
        timeout=120,
    ) as resp:

        return json.loads(
            resp.read().decode(
                "utf-8"
            )
        )


def extract_record(vuln):
    """
    Convert one NVD vulnerability record into the format used by the
    framework dataset.

    CVSS preference:
        v4.0 -> v3.1 -> v3.0 -> v2.0

    The selected CVSS version is explicitly recorded so later dataset
    analysis can distinguish which scoring version was consumed.
    """

    cve = vuln.get(
        "cve",
        {},
    )

    cve_id = cve.get(
        "id"
    )

    # ── English description ────────────────────────────────────────────────
    desc = ""

    for d in cve.get(
        "descriptions",
        [],
    ):

        if d.get("lang") == "en":

            desc = d.get(
                "value",
                "",
            )

            break

    # ── CVSS extraction ────────────────────────────────────────────────────
    metrics = cve.get(
        "metrics",
        {},
    )

    cvss_score = None
    cvss_vector = None
    cvss_version = None
    severity = None

    version_keys = (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    )

    for key, version in version_keys:

        entries = metrics.get(
            key,
            [],
        )

        if not entries:
            continue

        for metric in entries:

            cvss_data = metric.get(
                "cvssData",
                {},
            )

            score = cvss_data.get(
                "baseScore"
            )

            if score is None:
                continue

            try:
                cvss_score = float(
                    score
                )

            except (
                TypeError,
                ValueError,
            ):
                continue

            cvss_vector = cvss_data.get(
                "vectorString"
            )

            severity = (
                cvss_data.get(
                    "baseSeverity"
                )
                or metric.get(
                    "baseSeverity"
                )
            )

            cvss_version = version

            break

        if cvss_score is not None:
            break

    # ── CWE extraction ─────────────────────────────────────────────────────
    cwe_ids = []

    for weakness in cve.get(
        "weaknesses",
        [],
    ):

        for d in weakness.get(
            "description",
            [],
        ):

            value = d.get(
                "value",
                "",
            )

            if value.startswith(
                "CWE-"
            ):
                cwe_ids.append(
                    value
                )

    return {
        "cve_id":
            cve_id,

        "description":
            desc,

        "cvss_score":
            cvss_score,

        "cvss_vector":
            cvss_vector,

        "cvss_version":
            cvss_version,

        "cvss_source":
            "NVD",

        "severity":
            severity,

        "cwe":
            (
                cwe_ids[0]
                if cwe_ids
                else None
            ),

        "published":
            cve.get(
                "published"
            ),
    }


def daterange_chunks(
    start_year,
    end_year,
    max_days=120,
):
    """
    Split the requested time range into <=120-day windows because the
    NVD API does not accept large publication-date ranges in one query.
    """

    from datetime import date, timedelta

    start = date(
        start_year,
        1,
        1,
    )

    end = date(
        end_year,
        12,
        31,
    )

    cur = start

    while cur <= end:

        chunk_end = min(
            cur
            + timedelta(
                days=max_days - 1
            ),
            end,
        )

        yield (
            cur,
            chunk_end,
        )

        cur = (
            chunk_end
            + timedelta(
                days=1
            )
        )


def main():

    ap = argparse.ArgumentParser()

    ap.add_argument(
        "--start-year",
        type=int,
        default=2018,
    )

    ap.add_argument(
        "--end-year",
        type=int,
        default=2025,
    )

    ap.add_argument(
        "--out",
        default="data/nvd_raw.json",
    )

    ap.add_argument(
        "--api-key",
        default=os.environ.get(
            "NVD_API_KEY"
        ),
    )

    ap.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Skip date windows already "
            "present in --out"
        ),
    )

    ap.add_argument(
        "--max-per-window",
        type=int,
        default=8000,
        help=(
            "Cap records per 120-day "
            "window to keep dataset "
            "size manageable"
        ),
    )

    args = ap.parse_args()

    # Conservative delays for NVD rate limits.
    sleep_s = (
        2.5
        if args.api_key
        else 6.5
    )

    os.makedirs(
        os.path.dirname(
            args.out
        )
        or ".",
        exist_ok=True,
    )

    records = []
    done_windows = set()

    # ── Resume support ─────────────────────────────────────────────────────
    if (
        args.resume
        and os.path.exists(
            args.out
        )
    ):

        with open(
            args.out,
            encoding="utf-8",
        ) as f:

            existing = json.load(
                f
            )

        records = existing.get(
            "records",
            [],
        )

        done_windows = set(
            existing.get(
                "done_windows",
                existing.get(
                    "done_years",
                    [],
                ),
            )
        )

        print(
            f"[resume] loaded "
            f"{len(records)} existing "
            f"records, "
            f"{len(done_windows)} "
            f"windows already done"
        )

    # ── Fetch each date window ─────────────────────────────────────────────
    for (
        win_start,
        win_end,
    ) in daterange_chunks(
        args.start_year,
        args.end_year,
    ):

        window_key = (
            f"{win_start.isoformat()}"
            f"_"
            f"{win_end.isoformat()}"
        )

        if window_key in done_windows:

            print(
                f"[skip] "
                f"{window_key} "
                f"already fetched"
            )

            continue

        pub_start = (
            f"{win_start.isoformat()}"
            f"T00:00:00.000"
        )

        pub_end = (
            f"{win_end.isoformat()}"
            f"T23:59:59.999"
        )

        window_records = []
        start_index = 0
        total_results = None

        while True:

            try:

                page = fetch_page(
                    start_index,
                    args.api_key,
                    pub_start,
                    pub_end,
                )

            except urllib.error.HTTPError as e:

                if e.code in (
                    403,
                    429,
                ):

                    print(
                        "  [rate-limited] "
                        "sleeping 30s and "
                        "retrying..."
                    )

                    time.sleep(
                        30
                    )

                    continue

                raise

            except TimeoutError:

                print(
                    "  [timeout] "
                    "NVD response timed out. "
                    "Retrying in 15s..."
                )

                time.sleep(
                    15
                )

                continue

            except urllib.error.URLError as e:

                print(
                    f"  [network error] "
                    f"{e}. "
                    f"Retrying in 15s..."
                )

                time.sleep(
                    15
                )

                continue

            total_results = page.get(
                "totalResults",
                0,
            )

            vulns = page.get(
                "vulnerabilities",
                [],
            )

            for vuln in vulns:

                record = extract_record(
                    vuln
                )

                if record[
                    "description"
                ]:

                    window_records.append(
                        record
                    )

            print(
                f"  [{window_key}] "
                f"fetched "
                f"{start_index + len(vulns)}"
                f"/"
                f"{total_results}"
            )

            start_index += PAGE_SIZE

            time.sleep(
                sleep_s
            )

            if (
                start_index
                >= total_results
                or len(
                    window_records
                )
                >= args.max_per_window
            ):

                break

        # Limit each window if requested.
        window_records = (
            window_records[
                :args.max_per_window
            ]
        )

        records.extend(
            window_records
        )

        done_windows.add(
            window_key
        )

        # Save after each completed window.
        with open(
            args.out,
            "w",
            encoding="utf-8",
        ) as f:

            json.dump(
                {
                    "records":
                        records,

                    "done_windows":
                        sorted(
                            done_windows
                        ),
                },
                f,
            )

        print(
            f"[+] Window "
            f"{window_key} done: "
            f"{len(window_records)} "
            f"records "
            f"(total so far: "
            f"{len(records)})"
        )

    print(
        f"\n[done] Total CVE "
        f"records saved to "
        f"{args.out}: "
        f"{len(records)}"
    )


if __name__ == "__main__":
    main()
