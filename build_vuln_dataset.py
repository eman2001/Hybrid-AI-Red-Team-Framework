"""
build_vuln_dataset.py
------------------------
Builds data/vuln_training_data.csv for train_vuln_model.py.
"""
import argparse
import csv
import json

PORT_TO_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 512: "rexec", 513: "rlogin",
    993: "imaps", 995: "pop3s", 1099: "java-rmi", 1433: "mssql",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt",
}


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_kev_ids(path):
    data = load_json(path)
    vulns = data.get("vulnerabilities", data if isinstance(data, list) else [])
    return {v.get("cveID") for v in vulns if v.get("cveID")}


def load_nvd_lookup(path):
    data = load_json(path)
    records = data.get("records", data if isinstance(data, list) else [])
    lookup = {}
    for r in records:
        if r.get("cve_id"):
            lookup[r["cve_id"]] = r
    return lookup


def classify_label(in_kev, has_msf, cvss):
    if cvss is None:
        cvss = 0.0
    if in_kev:
        return 1
    if has_msf and cvss >= 7.0:
        return 1
    if cvss >= 4.0:
        return 2
    if has_msf and cvss < 7.0:
        return 2
    return 3


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--edb", default="data/edb_metadata.json")
    ap.add_argument("--msf-index", default="data/edb_to_msf_index.json")
    ap.add_argument("--kev", default="data/kev_catalog.json")
    ap.add_argument("--nvd", default="data/nvd_raw.json")
    ap.add_argument("--out", default="data/vuln_training_data.csv")
    args = ap.parse_args()

    edb_records = load_json(args.edb)
    msf_index = load_json(args.msf_index)
    kev_ids = load_kev_ids(args.kev)
    nvd_lookup = load_nvd_lookup(args.nvd)

    print(f"[+] EDB records: {len(edb_records)}")
    print(f"[+] Metasploit-indexed entries: {len(msf_index)}")
    print(f"[+] KEV IDs: {len(kev_ids)}")
    print(f"[+] NVD lookup entries: {len(nvd_lookup)}")

    rows = []
    skipped_missing_fields = 0

    for edb_id, rec in edb_records.items():
        port = rec.get("port")
        exploit_name = rec.get("exploit_name")
        if port is None or not exploit_name:
            continue

        has_msf = edb_id in msf_index
        service = PORT_TO_SERVICE.get(port, "other")

        for cve_id in rec.get("cve_ids", []):
            nvd_rec = nvd_lookup.get(cve_id)
            if not nvd_rec:
                continue

            attack_vector = nvd_rec.get("attack_vector")
            privileges_required = nvd_rec.get("privileges_required")
            exploitability = nvd_rec.get("exploitability_score")
            severity = nvd_rec.get("severity")
            cvss = nvd_rec.get("cvss_score")

            if attack_vector is None or privileges_required is None or exploitability is None:
                skipped_missing_fields += 1
                continue

            rows.append({
                "cve_id": cve_id,
                "exploit_name": exploit_name,
                "service": service,
                "port": port,
                "auth_required": 0 if privileges_required == "NONE" else 1,
                "remote": 1 if attack_vector == "NETWORK" else 0,
                "severity": severity or "UNKNOWN",
                "exploitability": exploitability,
                "label": classify_label(cve_id in kev_ids, has_msf, cvss),
            })

    print(f"[+] Rows built: {len(rows)}")
    print(f"[+] Rows skipped (missing NVD extra fields): {skipped_missing_fields}")

    from collections import Counter
    dist = Counter(r["label"] for r in rows)
    print("\n  Label distribution (1=high, 2=medium, 3=low):")
    for label in (1, 2, 3):
        print(f"    {label}   {dist.get(label, 0)}")

    fieldnames = ["cve_id", "exploit_name", "service", "port", "auth_required",
                  "remote", "severity", "exploitability", "label"]
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n[+] Saved -> {args.out}")


if __name__ == "__main__":
    main()
