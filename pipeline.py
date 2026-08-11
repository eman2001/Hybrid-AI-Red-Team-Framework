"""
pipeline.py
-----------
A generic, domain-neutral example of validating and propagating "operation
state" through a multi-stage data pipeline:

    Job Executor -> Result Normalizer -> Decision Engine -> Workflow Graph -> Report

The core idea: a failed, ambiguous, or malformed result from an opaque
executor must NEVER be silently represented downstream as a successful,
completed step. Every stage passes along an explicit, typed state rather
than letting later stages re-derive "success" from incidental structure
(object existence, presence of metadata, presence of a graph node, etc.).

This module has no dependency on any external system. The "Job Executor"
here is a stand-in for literally any long-running task: a file conversion,
a payment capture, a batch ETL step, a provisioning call, etc.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# 1. Generic data model
# ---------------------------------------------------------------------------

class OperationState(Enum):
    """
    The full, closed set of states an operation result can be normalized
    into. Nothing downstream is allowed to invent a fifth state, and
    nothing downstream is allowed to treat any non-SUCCESS state as
    equivalent to SUCCESS.
    """
    SUCCESS = "success"        # executor explicitly reported success
    FAILURE = "failure"        # executor explicitly reported failure
    UNVERIFIED = "unverified"  # executor gave a well-formed result but no
                                # explicit success/failure signal at all
    INVALID = "invalid"        # result is malformed / untyped / unusable


@dataclass(frozen=True)
class NormalizedResult:
    """
    The single object every downstream stage is allowed to consume.
    Nothing downstream is allowed to look at the raw executor payload
    directly -- only at this normalized, explicit representation.
    """
    operation_id: Optional[str]
    state: OperationState
    reason: str                 # human-readable justification for the state
    metadata: dict = field(default_factory=dict)
    raw: Any = None              # original payload, kept for audit/debug only

    @property
    def is_success(self) -> bool:
        """The ONLY correct way to ask "did this operation succeed?".
        Deliberately not used internally by the graph/report layer, which
        checks state via explicit enum comparison instead of this
        convenience predicate -- see the requirement that success must
        never be inferred implicitly."""
        return self.state is OperationState.SUCCESS


# ---------------------------------------------------------------------------
# 2. Result normalization function
# ---------------------------------------------------------------------------

def normalize_result(raw_result: Any) -> NormalizedResult:
    """
    Convert an opaque executor result into a NormalizedResult with an
    explicit state.

    Design rule: this function performs NO inference. A result can only
    become SUCCESS if it is a well-formed dict containing an explicit
    boolean `success: True`. Every other shape of input is routed to
    FAILURE, UNVERIFIED, or INVALID -- never silently upgraded.
    """

    # --- Structural validation -------------------------------------------------
    if not isinstance(raw_result, dict):
        return NormalizedResult(
            operation_id=None,
            state=OperationState.INVALID,
            reason=f"Executor result is not a dict (got {type(raw_result).__name__})",
            raw=raw_result,
        )

    operation_id = raw_result.get("operation_id")
    if not isinstance(operation_id, str) or not operation_id.strip():
        return NormalizedResult(
            operation_id=None,
            state=OperationState.INVALID,
            reason="Missing or invalid 'operation_id' field",
            raw=raw_result,
        )

    metadata = raw_result.get("metadata", {})
    if not isinstance(metadata, dict):
        return NormalizedResult(
            operation_id=operation_id,
            state=OperationState.INVALID,
            reason="'metadata' field is present but not a dict",
            raw=raw_result,
        )

    # --- Status validation -------------------------------------------------
    if "success" not in raw_result:
        # A well-formed envelope with no explicit signal at all is NOT a
        # failure and NOT a success -- it is unverified. Downstream stages
        # must treat this as "cannot confirm completion", not "assume ok".
        return NormalizedResult(
            operation_id=operation_id,
            state=OperationState.UNVERIFIED,
            reason="Executor result did not include a 'success' field",
            metadata=metadata,
            raw=raw_result,
        )

    success_value = raw_result["success"]
    if not isinstance(success_value, bool):
        # e.g. success: 1, success: "true", success: None -- ambiguous
        # truthy/falsy values are explicitly rejected rather than coerced.
        return NormalizedResult(
            operation_id=operation_id,
            state=OperationState.INVALID,
            reason=f"'success' field is not boolean (got {type(success_value).__name__}: {success_value!r})",
            metadata=metadata,
            raw=raw_result,
        )

    if success_value is True:
        return NormalizedResult(
            operation_id=operation_id,
            state=OperationState.SUCCESS,
            reason="Executor explicitly reported success",
            metadata=metadata,
            raw=raw_result,
        )

    return NormalizedResult(
        operation_id=operation_id,
        state=OperationState.FAILURE,
        reason="Executor explicitly reported failure",
        metadata=metadata,
        raw=raw_result,
    )


# ---------------------------------------------------------------------------
# 3. Decision Engine
# ---------------------------------------------------------------------------

class DecisionAction(Enum):
    ADVANCE = "advance"     # allowed to enter the workflow graph as completed
    QUARANTINE = "quarantine"  # record the failure, do not advance
    HOLD = "hold"           # unverified -- needs manual review / retry
    REJECT = "reject"       # invalid input -- never entered the workflow


_DECISION_TABLE: dict[OperationState, DecisionAction] = {
    OperationState.SUCCESS: DecisionAction.ADVANCE,
    OperationState.FAILURE: DecisionAction.QUARANTINE,
    OperationState.UNVERIFIED: DecisionAction.HOLD,
    OperationState.INVALID: DecisionAction.REJECT,
}


def decide(result: NormalizedResult) -> DecisionAction:
    """
    Maps a NormalizedResult's state to a routing decision using an
    explicit lookup table (not conditionals scattered across the
    codebase). Only OperationState.SUCCESS ever maps to ADVANCE.
    """
    return _DECISION_TABLE[result.state]


# ---------------------------------------------------------------------------
# 4. Generic workflow / graph builder
# ---------------------------------------------------------------------------

class NodeStatus(Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    UNVERIFIED = "unverified"
    REJECTED = "rejected"


@dataclass
class WorkflowNode:
    operation_id: Optional[str]
    status: NodeStatus
    reason: str
    metadata: dict


class InvalidGraphTransition(Exception):
    """Raised if code attempts to mark a non-advanced result as completed."""


class WorkflowGraph:
    """
    Represents the pipeline's downstream view of executed operations.
    The graph is intentionally "dumb": it does not re-derive success from
    metadata or from the mere presence of a node. It only ever reflects the
    state handed to it by the Decision Engine.
    """

    _STATE_TO_STATUS: dict[OperationState, NodeStatus] = {
        OperationState.SUCCESS: NodeStatus.COMPLETED,
        OperationState.FAILURE: NodeStatus.FAILED,
        OperationState.UNVERIFIED: NodeStatus.UNVERIFIED,
        OperationState.INVALID: NodeStatus.REJECTED,
    }

    def __init__(self) -> None:
        self.nodes: list[WorkflowNode] = []

    def add_result(self, result: NormalizedResult) -> WorkflowNode:
        # Defense in depth: even though `decide()` already gates this,
        # the graph independently re-derives status from `result.state`
        # via explicit enum mapping -- never from object presence, never
        # from metadata contents, never from the absence of an exception.
        status = self._STATE_TO_STATUS[result.state]

        if status is NodeStatus.COMPLETED and result.state is not OperationState.SUCCESS:
            # Unreachable given the mapping above, but kept as an explicit
            # invariant check so future edits to this class can't silently
            # break the "no implicit success" guarantee.
            raise InvalidGraphTransition(
                f"Refusing to mark operation {result.operation_id!r} as "
                f"COMPLETED from state {result.state!r}"
            )

        node = WorkflowNode(
            operation_id=result.operation_id,
            status=status,
            reason=result.reason,
            metadata=result.metadata,
        )
        self.nodes.append(node)
        return node

    def completed_operations(self) -> list[WorkflowNode]:
        return [n for n in self.nodes if n.status is NodeStatus.COMPLETED]

    def non_completed_operations(self) -> list[WorkflowNode]:
        return [n for n in self.nodes if n.status is not NodeStatus.COMPLETED]


# ---------------------------------------------------------------------------
# 5. Report
# ---------------------------------------------------------------------------

@dataclass
class Report:
    total: int
    completed: int
    failed: int
    unverified: int
    rejected: int

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "completed": self.completed,
            "failed": self.failed,
            "unverified": self.unverified,
            "rejected": self.rejected,
        }


def build_report(graph: WorkflowGraph) -> Report:
    counts = {status: 0 for status in NodeStatus}
    for node in graph.nodes:
        counts[node.status] += 1
    return Report(
        total=len(graph.nodes),
        completed=counts[NodeStatus.COMPLETED],
        failed=counts[NodeStatus.FAILED],
        unverified=counts[NodeStatus.UNVERIFIED],
        rejected=counts[NodeStatus.REJECTED],
    )


# ---------------------------------------------------------------------------
# End-to-end pipeline glue
# ---------------------------------------------------------------------------

def run_pipeline(
    raw_results: list[Any],
    graph: Optional[WorkflowGraph] = None,
) -> tuple[WorkflowGraph, Report]:
    """
    Runs a batch of raw (opaque) executor results through:
    normalize -> decide -> graph.add_result -> report

    Note that `decide()` is consulted purely for routing/logging purposes
    in this simplified example; the graph itself independently re-checks
    state before ever marking a node COMPLETED (see WorkflowGraph.add_result).
    """
    graph = graph if graph is not None else WorkflowGraph()

    for raw in raw_results:
        result = normalize_result(raw)
        _action = decide(result)  # e.g. could drive retries, alerts, routing
        graph.add_result(result)

    report = build_report(graph)
    return graph, report
