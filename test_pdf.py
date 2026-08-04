from engine.modules.reporting.pdf_reporter import PdfReporter


sample_report = {

    "report_id": "TEST_001",

    "generated_at": "2026-07-31",

    "executive_summary": {

        "risk": "CRITICAL",

        "score": 100,

        "findings": 7

    },


    "ai_analysis": {

        "summary": "Critical vulnerabilities detected",

        "recommendations": [

            "Patch vulnerable services",

            "Review access controls"

        ]

    },


    "mitre_analysis": {

        "techniques": [

            {

                "techniqueID": "T1190",

                "score": 100,

                "comment": "Source: rule_exact | Confidence: 95%"

            }

        ]

    }

}



pdf = PdfReporter()


path = pdf.save(

    sample_report,

    "test_report.pdf",

    "reports/test"

)


print(path)
