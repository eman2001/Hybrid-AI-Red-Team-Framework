"""
patch_ml_classifier.py
------------------------
يصلّح عدم تطابق الـ normalization بين train_mitre_model.py و
ml_classifier.py: يضيف نفس دالة normalize() (استبدال /_- بمسافات)
جوا ml_classifier.py، ويطبّقها على النص قبل ما يروح للـ vectorizer.
"""

import re

path = "engine/modules/mitre/ml_classifier.py"
with open(path, encoding="utf-8") as f:
    content = f.read()

with open(path + ".bak", "w", encoding="utf-8") as f:
    f.write(content)
print("✅ نسخة احتياطية: engine/modules/mitre/ml_classifier.py.bak")

# ── 1) أضيفي دالة normalize مطابقة لنفس الموجودة بـ train_mitre_model.py
if "_normalize_for_model" not in content:
    marker = "MODEL_PATH = \"models/mitre_classifier.pkl\""
    if marker not in content:
        print("❌ ما لقيت MODEL_PATH بالشكل المتوقع -- لازم تعديل يدوي.")
    else:
        addition = marker + '''

def _normalize_for_model(text: str) -> str:
    """نفس normalize() تماما اللي استخدمها train_mitre_model.py وقت
    التدريب (استبدال / _ - بمسافات) -- لازم تطابق حرفيا وقت الاستدلال
    عشان الكلمات متل 'local_exploit_suggester' تتفكك لنفس الشكل اللي
    شافه الموديل بالتدريب."""
    return re.sub(r"[/_\\-]", " ", text.lower())'''
        content = content.replace(marker, addition, 1)
        print("✅ تمت إضافة _normalize_for_model()")

# ── 2) طبّقي الدالة على النص جوا _model_predict قبل الـ transform ────
old_block = '''    def _model_predict(self, text: str, context: dict) -> dict | None:
        try:
            if hasattr(self._fe, "transform_one"):
                X = self._fe.transform_one(context)
            else:
                X = self._fe.transform([text])'''

new_block = '''    def _model_predict(self, text: str, context: dict) -> dict | None:
        try:
            normalized_text = _normalize_for_model(text)
            if hasattr(self._fe, "transform_one"):
                X = self._fe.transform_one(context)
            else:
                X = self._fe.transform([normalized_text])'''

if old_block not in content:
    print("❌ ما لقيت الـ block المتوقع جوا _model_predict -- لازم تعديل يدوي.")
else:
    content = content.replace(old_block, new_block, 1)
    print("✅ تم تطبيق normalize قبل transform جوا _model_predict")

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("\n✅ خلص التعديل. شغّلي الآن: python3 test_ml_classifier.py")
