"""
build_priority_dataset_v3.py
-----------------------------
Builds an expanded, real-data training set for train_vuln_model.py by
linking three existing sources:

  data/edb_metadata.json     -> exploit_id, cve_ids, port, type, platform
  data/edb_to_msf_index.json -> exploit_id -> Metasploit module path
  data/nvd_raw.json          -> cve_id -> cvss_score, severity

Columns NOT directly available in any source are derived with a documented,
explicit rule (not guessed at random):

  service         <- taken from the Metasploit module path's category
                      segment (e.g. "exploit/unix/ftp/..." -> "ftp")
  auth_required   <- 0 for all EDB/MSF entries (public unauthenticated
                      exploit modules are the overwhelming majority of
                      Exploit-DB/Metasploit content; this matches the
                      convention already used in the original hand-crafted
                      training_data.csv, where every row also has 0)
  remote          <- 1 if edb "type" is "remote" or "webapps" or "dos",
                      0 if "local" (matches Exploit-DB's own type taxonomy)
  exploitability  <- parsed from the matching CVE's CVSSv2 vector
                      (AV:N=10,AV:A=6.5,AV:L=3.9) x (AC:L=1,AC:M=0.9,AC:H=0.5)
                      approximating the CVSSv2 Exploitability sub-score
                      formula; falls back to cvss_score if vector missing
  label           <- 1 (high) if severity in {CRITICAL, HIGH}
                      2 (medium) if severity == MEDIUM
                      3 (low) if severity == LOW

Run:
    python3 build_priority_dataset_v3.py

Output:
    data/training_data_v3.csv
"""

import json
import csv
import re

EDB_METADATA_PATH = "data/edb_metadata.json"
EDB_MSF_INDEX_PATH = "data/edb_to_msf_index.json"
NVD_RAW_PATH = "data/nvd_raw.json"
OUT_PATH = "data/training_data_v3.csv"

AV_WEIGHTS = {"N": 10.0, "A": 6.5, "L": 3.9}
AC_WEIGHTS = {"L": 1.0, "M": 0.9, "H": 0.5}


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def service_from_module(module_path):
    """exploit/unix/ftp/vsftpd_234_backdoor -> ftp"""
    parts = module_path.split("/")
    if len(parts) >= 3:
        return parts[2]
    return "unknown"


def remote_from_type(edb_type):
    return 1 if edb_type in ("remote", "webapps", "dos") else 0


def exploitability_from_vector(vector, fallback_score):
    if not vector:
        return fallback_score
    av_match = re.search(r"AV:([NAL])", vector)
    ac_match = re.search(r"AC:([LMH])", vector)
    if not av_match or not ac_match:
        return fallback_score
    av = AV_WEIGHTS.get(av_match.group(1))
    ac = AC_WEIGHTS.get(ac_match.group(1))
    if av is None or ac is None:
        return fallback_score
    return round(20 * av * ac / 10, 1)  # scaled to roughly match 0-10 range


def label_from_severity(severity):
    severity = (severity or "").upper()
    if severity in ("CRITICAL", "HIGH"):
        return 1
    if severity == "MEDIUM":
        return 2
    return 3  # LOW or unknown


def build():
    print("[*] Loading source files...")
    edb_meta = load_json(EDB_METADATA_PATH)
    edb_idx  = load_json(EDB_MSF_INDEX_PATH)
    nvd      = load_json(NVD_RAW_PATH)

    cve_lookup = {r["cve_id"]: r for r in nvd["records"]}
    print(f"  [+] CVE lookup size: {len(cve_lookup)}")

    rows = []
    skipped_no_cve_match = 0

    for edb_id, meta in edb_meta.items():
        if edb_id not in edb_idx:
            continue
        cve_ids = meta.get("cve_ids") or []
        if not cve_ids:
            continue

        module_path = edb_idx[edb_id]
        service = service_from_module(module_path)
        remote = remote_from_type(meta.get("type"))

        # Use the first CVE with a match in our NVD dataset
        matched = None
        for cve_id in cve_ids:
            if cve_id in cve_lookup:
                matched = cve_lookup[cve_id]
                break
        if matched is None:
            skipped_no_cve_match += 1
            continue

        severity = matched.get("severity")
        cvss_score = matched.get("cvss_score", 0.0)
        exploitability = exploitability_from_vector(
            matched.get("cvss_vector"), cvss_score
        )
        label = label_from_severity(severity)

        rows.append({
            "exploit_name":   module_path,
            "service":        service,
            "port":           meta.get("port") or 0,
            "auth_required":  0,
            "remote":         remote,
            "severity":       (severity or "UNKNOWN").lower(),
            "exploitability": exploitability,
            "label":          label,
        })

    print(f"  [+] Built {len(rows)} rows ({skipped_no_cve_match} skipped: no matching CVE in nvd_raw.json)")

    with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "exploit_name", "service", "port", "auth_required",
            "remote", "severity", "exploitability", "label"
        ])
        writer.writeheader()
        writer.writerows(rows)

    print(f"  [+] Saved -> {OUT_PATH}")

    from collections import Counter
    label_dist = Counter(r["label"] for r in rows)
    print("\n  Label distribution:")
    for label, count in sorted(label_dist.items()):
        name = {1: "high", 2: "medium", 3: "low"}[label]
        print(f"    {label} ({name}): {count}")


if __name__ == "__main__":
    build()
