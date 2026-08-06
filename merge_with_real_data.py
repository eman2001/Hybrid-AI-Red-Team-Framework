"""
merge_with_real_data.py
=========================
Merges the full-coverage generated dataset with the real, human-collected
post_exploit_training.csv. Refuses to merge silently if the schemas don't
match -- you said the real file wasn't available when this was built, so
this script validates rather than assumes.

Expected real-file columns (must match generate_post_exploit_data.py):
    os_type, privilege_level, hashdump_success, sysinfo_success,
    network_enum, process_list, local_exploit_suggested, label

If your real file uses different column names or label text, either:
  (a) rename its columns/labels to match the generated schema before
      running this script, or
  (b) edit FEATURE_SPACE / LABELS in generate_post_exploit_data.py to
      match your real file, then regenerate, then merge.

Real rows are kept as-is (no relabeling, no noise) since they are ground
truth. An "explanation" column is added to real rows only if missing, and
a "source" column is added to both parts so you can always trace which
rows came from where.

Usage:
    python merge_with_real_data.py \\
        --generated data/post_exploit_generated.csv \\
        --real data/post_exploit_training.csv \\
        --out data/post_exploit_merged.csv
"""

import argparse
import sys

import pandas as pd

from generate_post_exploit_data import BOOLEAN_FIELDS, LABELS

REQUIRED_COLUMNS = ["os_type", "privilege_level"] + BOOLEAN_FIELDS + ["label"]


def validate_schema(df: pd.DataFrame, path: str) -> None:
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        print(
            f"ERROR: '{path}' is missing required columns: {missing}\n"
            f"Required columns are: {REQUIRED_COLUMNS}\n"
            f"Found columns: {list(df.columns)}\n\n"
            "Rename the columns in your real file to match, or edit "
            "generate_post_exploit_data.py to match your real schema and "
            "regenerate, then re-run this merge.",
            file=sys.stderr,
        )
        sys.exit(1)

    unknown_labels = set(df["label"].unique()) - set(LABELS)
    if unknown_labels:
        print(
            f"ERROR: '{path}' contains label values not in the taxonomy: "
            f"{unknown_labels}\nExpected one of: {LABELS}\n\n"
            "Either relabel these rows to the closest matching category, "
            "or extend LABELS in generate_post_exploit_data.py and add a "
            "corresponding rule to determine_next_action if this is a "
            "genuinely new category.",
            file=sys.stderr,
        )
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Merge generated + real post-exploitation data")
    parser.add_argument("--generated", type=str, default="data/post_exploit_generated.csv")
    parser.add_argument("--real", type=str, default="data/post_exploit_training.csv")
    parser.add_argument("--out", type=str, default="data/post_exploit_merged.csv")
    args = parser.parse_args()

    generated = pd.read_csv(args.generated)
    validate_schema(generated, args.generated)
    generated["source"] = "generated"

    try:
        real = pd.read_csv(args.real)
    except FileNotFoundError:
        print(
            f"'{args.real}' not found -- proceeding with generated data only. "
            "Re-run this script once your real file is available so the "
            "20 ground-truth rows are included.",
            file=sys.stderr,
        )
        generated.to_csv(args.out, index=False)
        print(f"Wrote {len(generated)} rows (generated only) -> {args.out}")
        return

    validate_schema(real, args.real)
    if "explanation" not in real.columns:
        real["explanation"] = "Real observed session (ground truth)."
    real["source"] = "real"

    merged = pd.concat([generated, real], ignore_index=True)
    merged = merged.sample(frac=1.0, random_state=42).reset_index(drop=True)
    merged.to_csv(args.out, index=False)

    print(f"Merged {len(generated)} generated + {len(real)} real -> {len(merged)} rows")
    print(f"Saved -> {args.out}")
    print("\nClass balance (merged):")
    print(merged["label"].value_counts())
    print("\nSource breakdown:")
    print(merged["source"].value_counts())


if __name__ == "__main__":
    main()
