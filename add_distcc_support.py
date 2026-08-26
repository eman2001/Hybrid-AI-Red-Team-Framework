#!/usr/bin/env python3
"""
add_distcc_support.py
----------------------
1. يضيف المنفذ 3632 (و6667 احتياطًا) لنطاق فحص nmap.
2. يضيف distccd كقاعدة fallback مباشرة في VulnCorrelator
   (exploit path كامل، فيتخطى exploit_correlator resolution تلقائيًا
   لأن resolve_msf_module بيرجّع أي مسار يبدأ بـ "exploit/" كما هو).
يأخذ نسخة احتياطية من كل ملف يعدّله.
"""
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NMAP_FILE = ROOT / "engine" / "modules" / "scanner" / "nmap_parser.py"
CORR_FILE = ROOT / "engine" / "modules" / "vulnerability" / "vuln_correlator.py"


def backup(path: Path):
    bak = path.with_suffix(path.suffix + ".bak_before_distcc_patch")
    if not bak.exists():
        shutil.copy2(path, bak)
        print(f"  [backup] {bak.name}")


def patch_nmap():
    if not NMAP_FILE.exists():
        print(f"[FATAL] لم أجد {NMAP_FILE}")
        sys.exit(1)
    text = NMAP_FILE.read_text(encoding="utf-8")
    backup(NMAP_FILE)

    OLD = '    SCAN_ARGS = "-sV -sC -O --open --host-timeout 120s"'
    NEW = (
        '    SCAN_ARGS = (\n'
        '        "-sV -sC -O --open --host-timeout 120s "\n'
        '        "-p 1-1000,3632,6667,8009,8080,8180"\n'
        '    )'
    )

    if OLD not in text:
        print("[WARN] Patch (SCAN_ARGS): لم يُطابَق النص -- تخطيته. راجعيه يدويًا.")
    else:
        text = text.replace(OLD, NEW, 1)
        print("  [patch] SCAN_ARGS الآن يشمل المنفذ 3632 (distccd) و6667 (UnrealIRCd)")
        NMAP_FILE.write_text(text, encoding="utf-8")


def patch_correlator():
    if not CORR_FILE.exists():
        print(f"[FATAL] لم أجد {CORR_FILE}")
        sys.exit(1)
    text = CORR_FILE.read_text(encoding="utf-8")
    backup(CORR_FILE)

    OLD = '    "mssql":  {"exploit": "mssql",  "type": "hydra",     "severity": "medium"},\n}'
    NEW = (
        '    "mssql":  {"exploit": "mssql",  "type": "hydra",     "severity": "medium"},\n'
        '    "distccd": {"exploit": "exploit/unix/misc/distcc_exec", '
        '"type": "metasploit", "severity": "critical"},\n'
        '}'
    )

    if OLD not in text:
        print("[WARN] Patch (SERVICE_FALLBACK): لم يُطابَق النص -- تخطيته. راجعيه يدويًا.")
    else:
        text = text.replace(OLD, NEW, 1)
        print("  [patch] distccd أُضيفت لـ SERVICE_FALLBACK -- exploit path كامل، "
              "سيتخطى exploit_correlator تلقائيًا")
        CORR_FILE.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    print("== 1/2: patching nmap_parser.py ==")
    patch_nmap()
    print()
    print("== 2/2: patching vuln_correlator.py ==")
    patch_correlator()
    print()
    print("=" * 50)
    print("خلص! الآن شغّلي:")
    print("  export MSF_RPC_PASS=redteam123")
    print("  ./run_logged.sh")

