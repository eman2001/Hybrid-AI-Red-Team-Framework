"""
enrich_nvd_extra_fields.py
-----------------------------
Parses the cvss_vector already present in each nvd_raw.json record to add
attack_vector, privileges_required, and exploitability_score locally --
no NVD API calls needed, runs in seconds.
"""
import argparse
import json
import os
import re
import tempfile

AV3 = {"N": ("NETWORK", 0.85), "A": ("ADJACENT_NETWORK", 0.62),
       "L": ("LOCAL", 0.55), "P": ("PHYSICAL", 0.2)}
AC3 = {"L": 0.77, "H": 0.44}
PR3_UNCHANGED = {"N": ("NONE", 0.85), "L": ("LOW", 0.62), "H": ("HIGH", 0.27)}
PR3_CHANGED = {"N": ("NONE", 0.85), "L": ("LOW", 0.68), "H": ("HIGH", 0.5)}
UI3 = {"N": 0.85, "R": 0.62}

AV2 = {"L": ("LOCAL", 0.395), "A": ("ADJACENT_NETWORK", 0.646), "N": ("NETWORK", 1.0)}
AC2 = {"H": 0.35, "M": 0.61, "L": 0.71}
AU2 = {"M": ("LOW", 0.45), "S": ("LOW", 0.56), "N": ("NONE", 0.704)}


def parse_v3(vector):
    def get(field):
        m = re.search(rf"/{field}:([A-Z])", "/" + vector)
        return m.group(1) if m else None

    av_key, ac_key, pr_key, ui_key, s_key = (
        get("AV"), get("AC"), get("PR"), get("UI"), get("S")
    )
    if not all([av_key, ac_key, pr_key, ui_key]):
        return None

    av_name, av_w = AV3.get(av_key, (None, None))
    ac_w = AC3.get(ac_key)
    pr_table = PR3_CHANGED if s_key == "C" else PR3_UNCHANGED
    pr_name, pr_w = pr_table.get(pr_key, (None, None))
    ui_w = UI3.get(ui_key)

    if None in (av_w, ac_w, pr_w, ui_w):
        return None

    exploitability = round(8.22 * av_w * ac_w * pr_w * ui_w, 1)
    return {
        "attack_vector": av_name,
        "privileges_required": pr_name,
        "exploitability_score": exploitability,
    }


def parse_v2(vector):
    def get(field):
        m = re.search(rf"(?:^|/){field}:([A-Za-z])", vector)
        return m.group(1).upper() if m else None

    av_key, ac_key, au_key = get("AV"), get("AC"), get("Au")
    if not all([av_key, ac_key, au_key]):
        return None

    av_name, av_w = AV2.get(av_key, (None, None))
    ac_w = AC2.get(ac_key)
    au_name, au_w = AU2.get(au_key, (None, None))

    if None in (av_w, ac_w, au_w):
        return None

    exploitability = round(20 * av_w * ac_w * au_w, 1)
    return {
        "attack_vector": av_name,
        "privileges_required": au_name,
        "exploitability_score": exploitability,
    }


def enrich_record(rec):
    vector = rec.get("cvss_vector")
    if not vector:
        rec.setdefault("attack_vector", None)
        rec.setdefault("privileges_required", None)
        rec.setdefault("exploitability_score", None)
        return rec, False

    parsed = parse_v3(vector) if vector.startswith("CVSS:3") else parse_v2(vector)
    if parsed is None:
        rec.setdefault("attack_vector", None)
        rec.setdefault("privileges_required", None)
        rec.setdefault("exploitability_score", None)
        return rec, False

    rec["attack_vector"] = parsed["attack_vector"]
    rec["privileges_required"] = parsed["privileges_required"]
    rec["exploitability_score"] = parsed["exploitability_score"]
    return rec, True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="data/nvd_raw.json")
    ap.add_argument("--out", dest="out", default="data/nvd_raw.json")
    args = ap.parse_args()

    print(f"[*] Loading {args.inp} ...")
    with open(args.inp, encoding="utf-8") as f:
        data = json.load(f)

    records = data.get("records", [])
    print(f"[+] {len(records)} records loaded")

    enriched_count = 0
    for i, rec in enumerate(records):
        records[i], ok = enrich_record(rec)
        if ok:
            enriched_count += 1

    print(f"[+] Successfully enriched {enriched_count}/{len(records)} records "
          f"({len(records) - enriched_count} had no parseable cvss_vector)")

    data["records"] = records

    out_dir = os.path.dirname(args.out) or "."
    fd, tmp_path = tempfile.mkstemp(dir=out_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp_path, args.out)
    except Exception:
        os.unlink(tmp_path)
        raise

    print(f"[+] Saved -> {args.out}")


if __name__ == "__main__":
    main()
