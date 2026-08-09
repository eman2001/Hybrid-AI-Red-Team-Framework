"""
build_priority_dataset_v2.py
-------------------------------
Builds data/training_data_v2.csv from KEV + EDB metadata + Metasploit
index + NVD CVSS -- the real-data exploit prioritizer dataset.

Labeling rule:
    HIGH:   in KEV (actively exploited) OR (has Metasploit module AND cvss>=7.0)
    MEDIUM: has public exploit AND 4.0<=cvss<7.0, OR has Metasploit module and cvss<7.0
    LOW:    everything else
"""
import argparse
import csv
import json


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_kev_ids(path):
    data = load_json(path)
    vulns = data.get("vulnerabilities", data if isinstance(data, list) else [])
    return {v.get("cveID") for v in vulns if v.get("cveID")}


def load_nvd_cvss_lookup(path):
    data = load_json(path)
    records = data.get("records", data if isinstance(data, list) else [])
    lookup = {}
    for r in records:
        if r.get("cve_id") and r.get("cvss_score") is not None:
            lookup[r["cve_id"]] = r["cvss_score"]
    return lookup


def classify_priority(in_kev, has_msf, cvss):
    if cvss is None:
        cvss = 0.0
    if in_kev:
        return "high"
    if has_msf and cvss >= 7.0:
        return "high"
    if (has_msf or cvss >= 4.0) and cvss >= 4.0:
        return "medium"
    if has_msf and cvss < 7.0:
        return "medium"
    return "low"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kev", default="data/kev_catalog.json")
    ap.add_argument("--edb", default="data/edb_metadata.json")
    ap.add_argument("--msf-index", default="data/edb_to_msf_index.json")
    ap.add_argument("--nvd", default="data/nvd_raw.json")
    ap.add_argument("--out", default="data/training_data_v2.csv")
    args = ap.parse_args()

    kev_ids = load_kev_ids(args.kev)
    edb_records = load_json(args.edb)
    msf_index = load_json(args.msf_index)
    cvss_lookup = load_nvd_cvss_lookup(args.nvd)

    print(f"[+] KEV IDs: {len(kev_ids)}")
    print(f"[+] EDB records (with CVE linkage): {len(edb_records)}")
    print(f"[+] Metasploit-indexed EDB entries: {len(msf_index)}")
    print(f"[+] NVD CVSS lookup entries: {len(cvss_lookup)}")

    rows = []
    seen_cve_no_edb = set(kev_ids)

    for edb_id, rec in edb_records.items():
        has_msf = edb_id in msf_index
        port = rec.get("port")
        if port is None:
            continue
        for cve_id in rec.get("cve_ids", []):
            cvss = cvss_lookup.get(cve_id)
            if cvss is None:
                continue
            in_kev = cve_id in kev_ids
            seen_cve_no_edb.discard(cve_id)
            exploit_type = "metasploit" if has_msf else "exploitdb"
            label = classify_priority(in_kev, has_msf, cvss)
            rows.append({
                "cve_id": cve_id,
                "cvss_score": cvss,
                "exploit_type": exploit_type,
                "port": port,
                "priority_label": label,
            })

    kev_only_added = 0
    for cve_id in seen_cve_no_edb:
        cvss = cvss_lookup.get(cve_id)
        if cvss is None:
            continue
        rows.append({
            "cve_id": cve_id,
            "cvss_score": cvss,
            "exploit_type": "kev_only",
            "port": 0,
            "priority_label": "high",
        })
        kev_only_added += 1

    print(f"[+] Rows from EDB x CVE x CVSS matches: {len(rows) - kev_only_added}")
    print(f"[+] Additional KEV-only rows (no public exploit found): {kev_only_added}")
    print(f"[+] Total rows: {len(rows)}")

    from collections import Counter
    dist = Counter(r["priority_label"] for r in rows)
    print("\n  Label distribution:")
    for label in ("high", "medium", "low"):
        print(f"    {label:<8} {dist.get(label, 0)}")

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["cve_id", "cvss_score", "exploit_type",
                                                "port", "priority_label"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n[+] Saved -> {args.out}")


if __name__ == "__main__":
    main()
