#!/usr/bin/env python3
"""
fix_lhost_bug.py
-----------------
يصلح خطأ "Invalid option 'LHOST'" اللي بيصير لما بعض الـ payloads
(متل cmd/unix/interact) ما بتقبل LHOST/LPORT، بس الكود كان يحاول
يعيّنهم بدون فحص.
"""
import shutil
import sys
from pathlib import Path

TARGET = Path("engine/modules/exploiter/exploit_simulation.py")

def backup(path: Path):
    bak = path.with_suffix(path.suffix + ".bak_before_lhost_fix2")
    if not bak.exists():
        shutil.copy2(path, bak)
        print(f"  [backup] {bak.name}")

def main():
    if not TARGET.exists():
        print(f"[FATAL] لم أجد {TARGET}")
        sys.exit(1)

    text = TARGET.read_text(encoding="utf-8")
    backup(TARGET)

    OLD = (
        '                payload = client.modules.use("payload", payload_name)\n'
        '                payload["LHOST"] = lhost\n'
        '                payload["LPORT"] = int(lport)\n'
    )

    NEW = (
        '                payload = client.modules.use("payload", payload_name)\n'
        '                if "LHOST" in payload.options:\n'
        '                    payload["LHOST"] = lhost\n'
        '                if "LPORT" in payload.options:\n'
        '                    payload["LPORT"] = int(lport)\n'
    )

    if OLD not in text:
        print("[WARN] النص الأصلي لم يُطابَق -- لم يتم أي تعديل.")
        print("       راجعي الملف يدويًا أو ابعتي المحتوى الحالي.")
        sys.exit(1)

    text = text.replace(OLD, NEW, 1)
    TARGET.write_text(text, encoding="utf-8")
    print("  [patch] تم إصلاح LHOST/LPORT ليتحقق من payload.options أولاً")

if __name__ == "__main__":
    main()

