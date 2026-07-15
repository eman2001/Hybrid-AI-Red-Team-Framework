"""
modules/mitre/ml_resolver.py
------------------------------
Alias مطلوب في الـ spec.
المشروع يستخدم ml_classifier.py داخلياً —
هذا الملف يوفر الاسم المطلوب بدون تكرار الكود.
"""

from engine.modules.mitre.ml_classifier import MLClassifier


class MLResolver(MLClassifier):
    """
    Spec-required alias for MLClassifier.
    نفس الـ API تماماً — predict(context) → dict.
    """
    pass


__all__ = ["MLResolver", "MLClassifier"]
