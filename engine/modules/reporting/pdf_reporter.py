"""
reporting/pdf_reporter.py
---------------------------
Generates PDF reports using fpdf2 with Unicode support.
"""

import os
import textwrap
from datetime import datetime

from engine.config.settings import (
    REPORT_PDF_DIR,
    FRAMEWORK_NAME,
    FRAMEWORK_VERSION,
    REPORT_DATE_FORMAT
)

try:
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos
    _FPDF = True

except ImportError:
    _FPDF = False


FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"


class PdfReporter:

    def save(
        self,
        report_data: dict,
        filename: str | None = None,
        output_dir: str | None = None
    ) -> str:

        save_dir = output_dir or REPORT_PDF_DIR

        os.makedirs(save_dir, exist_ok=True)

        ts = datetime.now().strftime(REPORT_DATE_FORMAT)

        filename = filename or f"report_{ts}.pdf"

        path = os.path.join(save_dir, filename)


        if _FPDF:

            self._build_pdf(
                report_data,
                path
            )

        else:

            txt_path = path.replace(".pdf", ".txt")

            with open(txt_path, "w", encoding="utf-8") as f:
                self._write_text(
                    f,
                    report_data
                )

            print(
                f"  [PDF] fpdf2 unavailable → {txt_path}"
            )

            return txt_path


        print(
            f"  [PDF] Report saved → {path}"
        )

        return path



    def _build_pdf(
        self,
        data: dict,
        path: str
    ):

        pdf = FPDF()

        pdf.set_auto_page_break(
            auto=True,
            margin=15
        )

        pdf.add_page()


        # Unicode fonts

        pdf.add_font(
            "DejaVu",
            "",
            FONT_PATH
        )

        pdf.add_font(
            "DejaVu",
            "B",
            FONT_BOLD_PATH
        )


        # Title

        pdf.set_font(
            "DejaVu",
            "B",
            16
        )

        pdf.cell(
            0,
            10,
            self._clean_text(
                f"{FRAMEWORK_NAME} - Attack Report"
            ),
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
            align="C"
        )


        pdf.set_font(
            "DejaVu",
            "",
            10
        )


        pdf.cell(
            0,
            8,
            f"Version {FRAMEWORK_VERSION} | Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
            align="C"
        )


        pdf.ln(8)



        for section, content in data.items():

            pdf.set_font(
                "DejaVu",
                "B",
                12
            )


            pdf.multi_cell(
                180,
                7,
                str(section).upper()
            )


            pdf.set_font(
                "DejaVu",
                "",
                9
            )


            text = self._clean_text(content)


            for line in text.split("\n"):

                if not line.strip():
                    continue


                pdf.multi_cell(
                    180,
                    5,
                    line
                )


            pdf.ln(4)



        pdf.output(path)




    def _clean_text(
        self,
        data
    ):

        if isinstance(data, dict):

            lines = []

            for k, v in list(data.items())[:50]:

                lines.append(
                    f"{k}: {str(v)}"
                )

            raw = "\n".join(lines)


        elif isinstance(data, list):

            raw = "\n".join(
                str(x)
                for x in data[:50]
            )


        else:

            raw = str(data)



        replacements = {

            "—": "-",
            "–": "-",
            "“": '"',
            "”": '"',
            "’": "'",
            "→": "->",

        }


        for old, new in replacements.items():

            raw = raw.replace(
                old,
                new
            )



        fixed_lines = []


        for line in raw.split("\n"):

            fixed_lines.extend(
                textwrap.wrap(
                    line,
                    width=90,
                    break_long_words=True,
                    break_on_hyphens=True
                )
            )


        return "\n".join(fixed_lines)




    @staticmethod
    def _write_text(
        f,
        data: dict
    ):

        for section, content in data.items():

            f.write(
                "\n" + "=" * 60 + "\n"
            )

            f.write(
                str(section) + "\n"
            )

            f.write(
                "=" * 60 + "\n"
            )

            f.write(
                str(content)
            )

            f.write("\n")
