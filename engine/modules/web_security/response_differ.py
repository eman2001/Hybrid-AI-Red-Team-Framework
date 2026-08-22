"""
web_security/response_differ.py
--------------------------------
Pure comparison utility: given two HTTP responses (a "baseline" and a
"probe"), reports HOW they differ -- status code, body content,
JSON structure (shape, independent of values), and timing.

No network calls, no payload construction, no target interaction --
this module only compares data it is handed. It is shared by every
checker in web_security/ so they all use one consistent, testable
definition of "the responses differ" instead of each checker
reinventing its own ad-hoc string comparison.
"""

import json
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, Optional


@dataclass
class HttpResponse:
    """
    Minimal HTTP response container used across web_security/.
    http_utils.HttpClient methods return this type.
    """
    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0

    @property
    def json_body(self) -> Optional[Any]:
        """Best-effort JSON parse of `body`. Returns None if it isn't JSON."""
        if not self.body:
            return None
        try:
            return json.loads(self.body)
        except (json.JSONDecodeError, TypeError):
            return None


@dataclass
class ResponseDiff:
    """Result of comparing two HttpResponse objects."""
    status_changed:         bool
    baseline_status:        int
    probe_status:           int

    body_changed:            bool
    similarity_score:        float   # 0.0 (totally different) .. 1.0 (identical)
    length_delta:             int     # probe body length - baseline body length

    json_structure_changed:  bool    # shape (keys/types), independent of values
    baseline_is_json:        bool
    probe_is_json:           bool

    timing_changed:           bool
    baseline_elapsed:         float
    probe_elapsed:            float
    timing_delta:             float

    def as_evidence_dict(self) -> dict:
        """Compact, JSON-serializable form for embedding in a WebFinding's
        evidence/baseline/probe fields."""
        return {
            "status_changed":        self.status_changed,
            "baseline_status":       self.baseline_status,
            "probe_status":          self.probe_status,
            "body_changed":          self.body_changed,
            "similarity_score":      round(self.similarity_score, 3),
            "length_delta":          self.length_delta,
            "json_structure_changed": self.json_structure_changed,
            "timing_changed":        self.timing_changed,
            "timing_delta":          round(self.timing_delta, 3),
        }


class ResponseDiffer:
    """
    Stateless comparator. One instance can be reused across many
    diff() calls; thresholds are configurable at construction time so
    callers aren't stuck with one global sensitivity.
    """

    def __init__(self,
                 body_similarity_threshold: float = 0.98,
                 timing_delta_threshold: float = 1.5):
        """
        body_similarity_threshold: below this SequenceMatcher ratio,
            bodies are considered "changed" (1.0 = identical).
        timing_delta_threshold: minimum absolute seconds difference
            before timing is considered "changed". Kept fairly high by
            default (1.5s) since network jitter alone can easily
            produce 200-500ms swings between two ordinary requests --
            a low threshold would make every diff() call report a
            timing change that means nothing.
        """
        self._body_threshold = body_similarity_threshold
        self._timing_threshold = timing_delta_threshold

    # ── structure comparison ────────────────────────────────────────
    def _shape(self, value: Any) -> Any:
        """
        Reduce a parsed JSON value to its "shape": key sets and value
        *types*, not values themselves. Two JSON bodies with the same
        keys/types but different data (e.g. two different user
        records) have the same shape; a body that gained/lost a field,
        or changed a field's type, has a different shape.
        """
        if isinstance(value, dict):
            return {k: self._shape(v) for k, v in sorted(value.items())}
        if isinstance(value, list):
            # Represent a list by the shape of its first element (if any)
            # plus its emptiness -- comparing every element's shape would
            # falsely flag "changed" for lists that just have a different
            # number of same-shaped items.
            if not value:
                return "list:empty"
            return ["list", self._shape(value[0])]
        return type(value).__name__

    # ── main entry point ────────────────────────────────────────────
    def diff(self, baseline: HttpResponse, probe: HttpResponse) -> ResponseDiff:
        status_changed = baseline.status != probe.status

        baseline_body = baseline.body or ""
        probe_body = probe.body or ""
        similarity = SequenceMatcher(None, baseline_body, probe_body).ratio() \
            if (baseline_body or probe_body) else 1.0
        body_changed = similarity < self._body_threshold
        length_delta = len(probe_body) - len(baseline_body)

        baseline_json = baseline.json_body
        probe_json = probe.json_body
        baseline_is_json = baseline_json is not None
        probe_is_json = probe_json is not None

        json_structure_changed = False
        if baseline_is_json and probe_is_json:
            json_structure_changed = self._shape(baseline_json) != self._shape(probe_json)
        elif baseline_is_json != probe_is_json:
            # one side is JSON and the other isn't -- that's a structural
            # change worth flagging (e.g. an error page returned instead
            # of the expected JSON payload)
            json_structure_changed = True

        timing_delta = probe.elapsed - baseline.elapsed
        timing_changed = abs(timing_delta) >= self._timing_threshold

        return ResponseDiff(
            status_changed=status_changed,
            baseline_status=baseline.status,
            probe_status=probe.status,
            body_changed=body_changed,
            similarity_score=similarity,
            length_delta=length_delta,
            json_structure_changed=json_structure_changed,
            baseline_is_json=baseline_is_json,
            probe_is_json=probe_is_json,
            timing_changed=timing_changed,
            baseline_elapsed=baseline.elapsed,
            probe_elapsed=probe.elapsed,
            timing_delta=timing_delta,
        )

