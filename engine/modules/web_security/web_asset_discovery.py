"""
Web Asset Discovery - Discovers JS, CSS, images, etc.
Based on OWASP Top 10 2025 - A06 Vulnerable Components
"""

import re
from urllib.parse import urljoin

class WebAssetDiscovery:
    def __init__(self):
        self.asset_patterns = {
            'javascript': r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']',
            'stylesheet': r'<link[^>]*rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+\.css[^"\']*)["\']',
            'image': r'<img[^>]*src=["\']([^"\']+\.(jpg|jpeg|png|gif|webp|svg)[^"\']*)["\']',
        }
    
    def discover(self, url, html_content):
        assets = {'javascript': [], 'stylesheet': [], 'image': []}
        for asset_type, pattern in self.asset_patterns.items():
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                asset_url = match[0] if isinstance(match, tuple) else match
                full_url = urljoin(url, asset_url)
                assets[asset_type].append(full_url)
        return assets
