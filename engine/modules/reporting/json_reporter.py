"""
reporting/json_reporter.py
----------------------------
Saves any data structure as a formatted JSON report file.
"""

import json
import os
from datetime import datetime
from engine.config.settings import REPORT_JSON_DIR, REPORT_DATE_FORMAT


class JsonReporter:

    def save(
        self,
        data: dict,
        filename: str | None = None,
        output_dir: str | None = None
    ) -> str:

        # إذا تم تحديد مجلد مخصص للتقرير
        save_dir = output_dir if output_dir else REPORT_JSON_DIR

        # اسم افتراضي للملف إذا لم يتم تمريره
        if not filename:
            ts = datetime.now().strftime(REPORT_DATE_FORMAT)
            filename = f"report_{ts}.json"

        # إذا filename يحتوي على مسار كامل
        if os.path.dirname(filename):
            path = filename
            os.makedirs(os.path.dirname(path), exist_ok=True)

        else:
            os.makedirs(save_dir, exist_ok=True)
            path = os.path.join(save_dir, filename)

        # حفظ JSON
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                data,
                f,
                indent=2,
                ensure_ascii=False,
                default=str
            )

        print(f"  [JSON] Report saved → {path}")

        return path
