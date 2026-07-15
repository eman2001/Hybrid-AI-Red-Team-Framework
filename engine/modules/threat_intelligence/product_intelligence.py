"""
threat_intelligence/product_intelligence.py
---------------------------------------------
End-of-life / patch status intelligence for common products.
"""

from datetime import date

EOL_PRODUCTS = {
    "vsftpd 2.3.4":  date(2011, 7, 4),
    "samba 3.5.0":   date(2013, 1, 1),
    "apache 2.2":    date(2017, 12, 31),
    "openssl 1.0.2": date(2019, 12, 31),
    "windows xp":    date(2014, 4, 8),
    "windows 7":     date(2020, 1, 14),
}


class ProductIntelligence:

    def is_eol(self, product: str, version: str) -> bool:
        key = f"{product.lower()} {version.lower()}".strip()
        for eol_key, eol_date in EOL_PRODUCTS.items():
            if eol_key in key:
                return date.today() > eol_date
        return False

    def eol_risk(self, product: str, version: str) -> str:
        return "CRITICAL" if self.is_eol(product, version) else "OK"
