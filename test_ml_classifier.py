"""
test_ml_classifier.py
----------------------
اختبار مستقل لـ MLClassifier (engine/modules/mitre/ml_classifier.py)
بمدخلات تجريبية (سياقات وهمية) لمعرفة:
  - هل الموديل المدرب (mitre_classifier.pkl) عم يتحمل ويشتغل فعلياً
  - أو هل عم يرجع لـ fallback keyword matching
  - وشو بالضبط الـ tactic/confidence/source اللي بيرجعهم لكل سيناريو
"""

import sys
import os

# تأكدي إن مسار المشروع صح بحيث import engine.* يشتغل
sys.path.insert(0, os.path.abspath("."))

from engine.modules.mitre.ml_classifier import MLClassifier


def run_case(clf, label, context):
    print(f"\n{'='*60}")
    print(f"[TEST] {label}")
    print(f"  input context: {context}")
    result = clf.predict(context)
    if result is None:
        print("  -> No prediction (empty/irrelevant context)")
        return
    print(f"  -> technique_id   : {result.get('technique_id')}")
    print(f"  -> technique_name : {result.get('technique_name')}")
    print(f"  -> tactic         : {result.get('tactic')}")
    print(f"  -> confidence     : {result.get('confidence')}")
    print(f"  -> source         : {result.get('source')}   "
          f"({'MODEL' if result.get('source') == 'ml' else 'FALLBACK/KEYWORD'})")


def main():
    print("Loading MLClassifier...")
    clf = MLClassifier()
    print(f"Model ready (trained .pkl loaded): {clf._ready}")
    print(f"Fallback mode active             : {clf._fallback}")

    # ── حالات تجريبية متنوعة ──────────────────────────────────────
    test_cases = [
        ("Lateral movement via SMB",
         {"exploit": "exploit/windows/smb/ms17_010_eternalblue",
          "service": "smb", "cve": "CVE-2017-0144", "edb_title": "EternalBlue"}),

        ("Credential access via brute force",
         {"exploit": "", "service": "ssh",
          "post_commands": ["hydra", "brute", "password"]}),

        ("Privilege escalation",
         {"exploit": "local_exploit_suggester",
          "post_commands": ["sudo", "getsystem", "privesc"]}),

        ("Discovery commands",
         {"exploit": "", "service": "",
          "post_commands": ["sysinfo", "getuid", "arp", "netstat"]}),

        ("Empty / irrelevant context (edge case)",
         {"exploit": "", "service": "", "cve": "", "edb_title": ""}),

        ("Web-based Jenkins exploit",
         {"exploit": "exploit/multi/http/jenkins_script_console",
          "service": "http", "edb_title": "Jenkins Script Console RCE"}),
    ]

    for label, ctx in test_cases:
        run_case(clf, label, ctx)

    print(f"\n{'='*60}")
    print("[SUMMARY]")
    if clf._ready:
        print("✓ الموديل المدرب (RandomForest) اشتغل فعلياً — تحققي من"
              " الحقل source='ml' بكل نتيجة فوق.")
    else:
        print("⚠ الموديل مش محمّل — كل النتائج فوق جايّة من fallback"
              " keyword matching (source='ml_fallback').")
        print("  تأكدي إنه models/mitre_classifier.pkl موجود بالمسار"
              " الصحيح من مكان تشغيل السكريبت.")


if __name__ == "__main__":
    main()
