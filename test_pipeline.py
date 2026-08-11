"""
test_pipeline.py
-----------------
Unit tests for the normalizer, decision engine, and workflow graph.

Covers the required scenarios:
  1. Explicit success
  2. Explicit failure
  3. Missing status
  4. Invalid status type
  5. Successful operation with downstream metadata
  6. Failed operation with downstream metadata

Plus edge cases:
  - Non-dict input
  - Missing / empty operation_id
  - metadata present but wrong type
  - Truthy-but-not-boolean success values (e.g. 1, "true")
  - Graph never marks a non-SUCCESS result as COMPLETED
  - Batch pipeline run with a mix of states
"""

import unittest

from pipeline import (
    DecisionAction,
    NodeStatus,
    OperationState,
    WorkflowGraph,
    build_report,
    decide,
    normalize_result,
    run_pipeline,
)


class TestNormalizeResult(unittest.TestCase):

    # 1. Explicit success
    def test_explicit_success(self):
        raw = {"success": True, "operation_id": "123", "metadata": {}}
        result = normalize_result(raw)
        self.assertEqual(result.state, OperationState.SUCCESS)
        self.assertTrue(result.is_success)
        self.assertEqual(result.operation_id, "123")

    # 2. Explicit failure
    def test_explicit_failure(self):
        raw = {"success": False, "operation_id": "124", "metadata": {}}
        result = normalize_result(raw)
        self.assertEqual(result.state, OperationState.FAILURE)
        self.assertFalse(result.is_success)

    # 3. Missing status
    def test_missing_status(self):
        raw = {"operation_id": "125", "metadata": {}}
        result = normalize_result(raw)
        self.assertEqual(result.state, OperationState.UNVERIFIED)
        self.assertFalse(result.is_success)

    # 4. Invalid status type
    def test_invalid_status_type(self):
        raw = {"success": "yes", "operation_id": "126", "metadata": {}}
        result = normalize_result(raw)
        self.assertEqual(result.state, OperationState.INVALID)
        self.assertFalse(result.is_success)

    def test_invalid_status_type_integer_truthy(self):
        # success=1 looks "truthy" but must NOT be coerced to True
        raw = {"success": 1, "operation_id": "127", "metadata": {}}
        result = normalize_result(raw)
        self.assertEqual(result.state, OperationState.INVALID)

    # 5. Successful operation with downstream metadata
    def test_success_with_metadata(self):
        raw = {
            "success": True,
            "operation_id": "128",
            "metadata": {"duration_ms": 42, "records_processed": 1000},
        }
        result = normalize_result(raw)
        self.assertEqual(result.state, OperationState.SUCCESS)
        self.assertEqual(result.metadata["records_processed"], 1000)

    # 6. Failed operation with downstream metadata
    def test_failure_with_metadata(self):
        raw = {
            "success": False,
            "operation_id": "129",
            "metadata": {"error_code": "TIMEOUT", "attempts": 3},
        }
        result = normalize_result(raw)
        self.assertEqual(result.state, OperationState.FAILURE)
        # Metadata is preserved for diagnostics, but must not change state.
        self.assertEqual(result.metadata["error_code"], "TIMEOUT")
        self.assertFalse(result.is_success)

    # --- Edge cases -----------------------------------------------------

    def test_non_dict_result(self):
        for bad_value in (None, "success", 42, [], object()):
            with self.subTest(bad_value=bad_value):
                result = normalize_result(bad_value)
                self.assertEqual(result.state, OperationState.INVALID)

    def test_missing_operation_id(self):
        raw = {"success": True, "metadata": {}}
        result = normalize_result(raw)
        self.assertEqual(result.state, OperationState.INVALID)

    def test_empty_operation_id(self):
        raw = {"success": True, "operation_id": "   ", "metadata": {}}
        result = normalize_result(raw)
        self.assertEqual(result.state, OperationState.INVALID)

    def test_metadata_wrong_type(self):
        raw = {"success": True, "operation_id": "130", "metadata": "none"}
        result = normalize_result(raw)
        self.assertEqual(result.state, OperationState.INVALID)

    def test_success_false_with_empty_dict_result(self):
        # An entirely empty dict must never be treated as success.
        result = normalize_result({})
        self.assertEqual(result.state, OperationState.INVALID)

    def test_existence_of_object_does_not_imply_success(self):
        # A well-formed-looking, non-empty payload with no 'success' key
        # still must not be treated as success -- object existence and
        # metadata presence are not success signals.
        raw = {"operation_id": "131", "metadata": {"anything": "here"}}
        result = normalize_result(raw)
        self.assertNotEqual(result.state, OperationState.SUCCESS)
        self.assertEqual(result.state, OperationState.UNVERIFIED)


class TestDecisionEngine(unittest.TestCase):

    def test_success_advances(self):
        result = normalize_result({"success": True, "operation_id": "1"})
        self.assertEqual(decide(result), DecisionAction.ADVANCE)

    def test_failure_quarantines(self):
        result = normalize_result({"success": False, "operation_id": "1"})
        self.assertEqual(decide(result), DecisionAction.QUARANTINE)

    def test_unverified_holds(self):
        result = normalize_result({"operation_id": "1"})
        self.assertEqual(decide(result), DecisionAction.HOLD)

    def test_invalid_rejects(self):
        result = normalize_result("not-a-dict")
        self.assertEqual(decide(result), DecisionAction.REJECT)


class TestWorkflowGraph(unittest.TestCase):

    def test_success_becomes_completed_node(self):
        graph = WorkflowGraph()
        result = normalize_result({"success": True, "operation_id": "1"})
        node = graph.add_result(result)
        self.assertEqual(node.status, NodeStatus.COMPLETED)
        self.assertIn(node, graph.completed_operations())

    def test_failure_never_becomes_completed(self):
        graph = WorkflowGraph()
        result = normalize_result({"success": False, "operation_id": "1"})
        node = graph.add_result(result)
        self.assertEqual(node.status, NodeStatus.FAILED)
        self.assertNotIn(node, graph.completed_operations())

    def test_unverified_never_becomes_completed(self):
        graph = WorkflowGraph()
        result = normalize_result({"operation_id": "1"})
        node = graph.add_result(result)
        self.assertEqual(node.status, NodeStatus.UNVERIFIED)
        self.assertNotIn(node, graph.completed_operations())

    def test_invalid_never_becomes_completed(self):
        graph = WorkflowGraph()
        result = normalize_result({"operation_id": "1", "success": "maybe"})
        node = graph.add_result(result)
        self.assertEqual(node.status, NodeStatus.REJECTED)
        self.assertNotIn(node, graph.completed_operations())

    def test_no_state_ever_silently_upgrades_to_completed(self):
        # Exhaustively verify: for every non-SUCCESS OperationState, the
        # resulting node status must never be COMPLETED.
        graph = WorkflowGraph()
        samples = {
            OperationState.FAILURE: {"success": False, "operation_id": "a"},
            OperationState.UNVERIFIED: {"operation_id": "b"},
            OperationState.INVALID: {"operation_id": "c", "success": None},
        }
        for expected_state, raw in samples.items():
            result = normalize_result(raw)
            self.assertEqual(result.state, expected_state)
            node = graph.add_result(result)
            self.assertNotEqual(node.status, NodeStatus.COMPLETED)


class TestEndToEndPipeline(unittest.TestCase):

    def test_batch_report_counts(self):
        raw_results = [
            {"success": True, "operation_id": "1", "metadata": {}},
            {"success": False, "operation_id": "2", "metadata": {"err": "x"}},
            {"operation_id": "3"},                       # unverified
            {"operation_id": "4", "success": "yes"},      # invalid
            "garbage",                                    # invalid
            {"success": True, "operation_id": "5", "metadata": {"n": 10}},
        ]
        graph, report = run_pipeline(raw_results)

        self.assertEqual(report.total, 6)
        self.assertEqual(report.completed, 2)
        self.assertEqual(report.failed, 1)
        self.assertEqual(report.unverified, 1)
        self.assertEqual(report.rejected, 2)

        completed_ids = {n.operation_id for n in graph.completed_operations()}
        self.assertEqual(completed_ids, {"1", "5"})

    def test_report_as_dict(self):
        graph, report = run_pipeline([{"success": True, "operation_id": "1"}])
        self.assertEqual(
            report.as_dict(),
            {"total": 1, "completed": 1, "failed": 0, "unverified": 0, "rejected": 0},
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
