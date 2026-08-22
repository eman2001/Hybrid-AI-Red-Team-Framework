"""
threat_intelligence/cvss_engine.py
----------------------------------
CVSS base-score lookup and severity-band classification.

Version preference:
    CVSS v4.0
    CVSS v3.1
    CVSS v3.0
    CVSS v2.0

Sources:
    1. CVEProject/cvelistV5
    2. NVD API

The engine compares the CVSS records returned by both sources and selects
the newest available CVSS version. If no external score is available, None
is returned and the caller keeps its existing finding-level fallback.

Cached entries store:
    {
        "score": <float>,
        "version": <str>,
        "source": <str>
    }
"""

import json
import urllib.request
from pathlib import Path

from engine.config.settings import (
    VULN_NVD_API_URL,
    VULN_NVD_API_KEY,
)


_CACHE_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "cvss_github_cache.json"
)


_VERSION_RANK = {
    "4.0": 4,
    "3.1": 3,
    "3.0": 2,
    "2.0": 1,
}


class CvssEngine:

    def __init__(self):
        self._cache = self._load_cache()

    # ============================================================
    # Public API
    # ============================================================

    def score(self, cve: str):
        """
        Return the preferred CVSS base score for a CVE.

        Selection order across all available sources:

            CVSS v4.0
            CVSS v3.1
            CVSS v3.0
            CVSS v2.0

        Returns None when no score can be retrieved.
        """

        if not cve:
            return None

        cve = cve.upper().strip()

        # --------------------------------------------------------
        # Check modern structured cache
        # --------------------------------------------------------

        cached = self._cache.get(cve)

        if isinstance(cached, dict):
            score = cached.get("score")

            if score is not None:
                try:
                    return float(score)
                except (TypeError, ValueError):
                    pass

        # --------------------------------------------------------
        # Old cache compatibility
        # --------------------------------------------------------

        # Older versions stored only a number.
        # We do not know which CVSS version produced that number,
        # so the engine performs fresh source lookups where possible
        # rather than treating the old cache value as a preferred
        # versioned result.
        old_cached_score = None

        if isinstance(cached, (int, float)):
            old_cached_score = float(cached)

        # --------------------------------------------------------
        # Collect candidates from both sources
        # --------------------------------------------------------

        candidates = []

        github_result = self._github_lookup(cve)

        if github_result is not None:
            candidates.append(github_result)

        nvd_result = self._nvd_lookup(cve)

        if nvd_result is not None:
            candidates.append(nvd_result)

        # --------------------------------------------------------
        # Select newest CVSS version
        # --------------------------------------------------------

        if candidates:

            best = max(
                candidates,
                key=lambda result: _VERSION_RANK.get(
                    result.get("version"),
                    0,
                ),
            )

            self._cache[cve] = best
            self._save_cache()

            return float(best["score"])

        # --------------------------------------------------------
        # Final compatibility fallback to old numeric cache
        # --------------------------------------------------------

        if old_cached_score is not None:
            return old_cached_score

        return None

    def details(self, cve: str):
        """
        Return structured information about the selected CVSS score.

        Example:
            {
                "score": 10.0,
                "version": "4.0",
                "source": "NVD"
            }

        Calling this method also performs lookup when necessary.
        """

        score = self.score(cve)

        if score is None:
            return None

        cached = self._cache.get(
            cve.upper().strip()
        )

        if isinstance(cached, dict):
            return cached

        # Old-cache compatibility
        return {
            "score": score,
            "version": "unknown",
            "source": "legacy_cache",
        }

    def band(self, score: float) -> str:
        """
        Convert the base score to the qualitative severity band
        used by the framework.
        """

        try:
            score = float(score)
        except (TypeError, ValueError):
            return "NONE"

        if score >= 9.0:
            return "CRITICAL"

        if score >= 7.0:
            return "HIGH"

        if score >= 4.0:
            return "MEDIUM"

        if score >= 0.1:
            return "LOW"

        return "NONE"

    # ============================================================
    # CVEProject / cvelistV5
    # ============================================================

    def _github_lookup(self, cve: str):
        """
        Retrieve the newest available CVSS record from
        CVEProject/cvelistV5.

        Returns:
            {
                "score": float,
                "version": str,
                "source": "CVEProject"
            }

        or None.
        """

        try:

            parts = cve.split("-")

            if len(parts) < 3:
                return None

            year = parts[1]
            number = parts[2].zfill(4)

            bucket = (
                number[:-3] + "xxx"
            )

            url = (
                "https://raw.githubusercontent.com/"
                "CVEProject/cvelistV5/"
                f"main/cves/{year}/{bucket}/{cve}.json"
            )

            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent":
                        "redteam-framework"
                },
            )

            with urllib.request.urlopen(
                request,
                timeout=10,
            ) as response:

                data = json.loads(
                    response.read()
                )

            containers = data.get(
                "containers",
                {},
            )

            # CVE records may contain metrics from both CNA
            # and ADP containers. Collect all available metrics.
            metric_blocks = []

            cna = containers.get(
                "cna",
                {},
            )

            metric_blocks.extend(
                cna.get(
                    "metrics",
                    [],
                )
                or []
            )

            for adp in containers.get(
                "adp",
                [],
            ) or []:

                metric_blocks.extend(
                    adp.get(
                        "metrics",
                        [],
                    )
                    or []
                )

            candidates = []

            version_keys = (
                ("cvssV4_0", "4.0"),
                ("cvssV3_1", "3.1"),
                ("cvssV3_0", "3.0"),
                ("cvssV2_0", "2.0"),
            )

            for metric in metric_blocks:

                for key, version in version_keys:

                    if key not in metric:
                        continue

                    cvss_data = metric.get(
                        key,
                        {},
                    )

                    score = cvss_data.get(
                        "baseScore"
                    )

                    if score is None:
                        continue

                    try:
                        score = float(score)
                    except (
                        TypeError,
                        ValueError,
                    ):
                        continue

                    candidates.append(
                        {
                            "score": score,
                            "version": version,
                            "source": "CVEProject",
                        }
                    )

            if not candidates:
                return None

            return max(
                candidates,
                key=lambda result:
                    _VERSION_RANK.get(
                        result["version"],
                        0,
                    ),
            )

        except Exception:
            return None

    # ============================================================
    # NVD
    # ============================================================

    def _nvd_lookup(self, cve: str):
        """
        Retrieve the newest available CVSS record from NVD.

        Preference:
            v4.0 -> v3.1 -> v3.0 -> v2.0

        An API key is optional. When configured, it is included
        to obtain the higher NVD request-rate allowance.
        """

        try:

            url = (
                f"{VULN_NVD_API_URL}"
                f"?cveId={cve}"
            )

            headers = {
                "User-Agent":
                    "redteam-framework"
            }

            if VULN_NVD_API_KEY:
                headers["apiKey"] = (
                    VULN_NVD_API_KEY
                )

            request = urllib.request.Request(
                url,
                headers=headers,
            )

            with urllib.request.urlopen(
                request,
                timeout=10,
            ) as response:

                data = json.loads(
                    response.read()
                )

            vulnerabilities = data.get(
                "vulnerabilities",
                [],
            )

            if not vulnerabilities:
                return None

            metrics = (
                vulnerabilities[0]
                .get("cve", {})
                .get("metrics", {})
            )

            candidates = []

            version_keys = (
                ("cvssMetricV40", "4.0"),
                ("cvssMetricV31", "3.1"),
                ("cvssMetricV30", "3.0"),
                ("cvssMetricV2", "2.0"),
            )

            for key, version in version_keys:

                entries = metrics.get(
                    key,
                    [],
                )

                if not entries:
                    continue

                for entry in entries:

                    cvss_data = entry.get(
                        "cvssData",
                        {},
                    )

                    score = cvss_data.get(
                        "baseScore"
                    )

                    if score is None:
                        continue

                    try:
                        score = float(score)
                    except (
                        TypeError,
                        ValueError,
                    ):
                        continue

                    candidates.append(
                        {
                            "score": score,
                            "version": version,
                            "source": "NVD",
                        }
                    )

            if not candidates:
                return None

            return max(
                candidates,
                key=lambda result:
                    _VERSION_RANK.get(
                        result["version"],
                        0,
                    ),
            )

        except Exception:
            return None

    # ============================================================
    # Cache
    # ============================================================

    def _load_cache(self) -> dict:

        try:

            return json.loads(
                _CACHE_PATH.read_text(
                    encoding="utf-8"
                )
            )

        except Exception:
            return {}

    def _save_cache(self):

        try:

            _CACHE_PATH.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            _CACHE_PATH.write_text(
                json.dumps(
                    self._cache,
                    indent=2,
                ),
                encoding="utf-8",
            )

        except Exception:
            pass
