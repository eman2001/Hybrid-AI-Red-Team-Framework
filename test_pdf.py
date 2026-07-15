import json

from engine.modules.reporting.pdf_reporter import PdfReporter


json_file = "reports/SIM-CF7571BB/attack_report_20260710_222036.json"


with open(json_file, "r", encoding="utf-8") as f:
    report = json.load(f)


pdf = PdfReporter()


output = pdf.save(
    report,
    "test_report.pdf",
    "reports/test"
)


print("Generated:")
print(output)
