"""Tests for BusinessFlowMapper and flow_context injection in bug_dossier."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure project root on path
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from shared.business_flow_mapper import BusinessFlowMapper, run


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _make_minimal_crawl_raw() -> dict:
    """Create a minimal crawl_raw.json structure for testing."""
    return {
        "target": "http://localhost:3000",
        "anonymous": {
            "http_traffic": [
                {
                    "method": "GET",
                    "url": "http://localhost:3000/products",
                    "response_status": 200,
                    "postData": None,
                    "form_fields": None,
                    "response_json_keys": ["products", "id", "name"],
                },
                {
                    "method": "POST",
                    "url": "http://localhost:3000/cart/add",
                    "response_status": 302,
                    "postData": "product_id=1&qty=1",
                    "form_fields": [
                        {"name": "product_id", "type": "hidden", "value": "1"},
                        {"name": "qty", "type": "number", "value": "1"},
                    ],
                },
                {
                    "method": "GET",
                    "url": "http://localhost:3000/cart",
                    "response_status": 200,
                    "postData": None,
                    "form_fields": None,
                    "response_json_keys": ["items", "total"],
                },
            ],
            "pages": [
                {
                    "label": "home",
                    "url": "http://localhost:3000/",
                    "links": [],
                    "forms": [
                        {
                            "method": "POST",
                            "action": "http://localhost:3000/cart/add",
                            "text": "",
                            "inputs": [
                                {"name": "product_id", "type": "hidden", "value": "1"},
                                {"name": "qty", "type": "number", "value": "1"},
                            ],
                        }
                    ],
                    "buttons": [{"index": 0, "text": "Add to Cart", "type": "submit"}],
                },
            ],
            "observed_actions": [
                {
                    "name": "goto:home",
                    "status": "ok",
                    "before_url": "about:blank",
                    "after_url": "http://localhost:3000/",
                    "detail": {"target": "http://localhost:3000/"},
                },
                {
                    "name": "add_to_basket",
                    "status": "ok",
                    "before_url": "http://localhost:3000/products",
                    "after_url": "http://localhost:3000/cart",
                    "detail": {"selector": "button:has-text('Add to Cart')"},
                },
            ],
            "workflow_graph": {
                "nodes": [
                    {"id": "/", "kind": "page", "url": "http://localhost:3000/", "methods": ["GET"]},
                    {"id": "/cart/add", "kind": "endpoint", "url": "http://localhost:3000/cart/add", "methods": ["POST"]},
                    {"id": "/cart", "kind": "page", "url": "http://localhost:3000/cart", "methods": ["GET"]},
                ],
                "edges": [
                    {"from": "/", "to": "/cart/add", "type": "form", "method": "POST"},
                    {"from": "/cart/add", "to": "/cart", "type": "observed_action", "label": "add_to_basket"},
                ],
            },
            "api_hints": [],
            "business_chain": [],
        },
        "authenticated": [],
    }


def _make_valid_flows_response() -> dict:
    """Return a valid business_flows response."""
    return {
        "flow_count": 1,
        "flows": [{
            "id": "FLOW-001",
            "name": "Dat hang",
            "type": "purchase",
            "confidence": "OBSERVED",
            "steps": [
                {
                    "order": 1,
                    "step_name": "browse_products",
                    "endpoint": "/products",
                    "method": "GET",
                    "params_observed": [],
                    "state_before": None,
                    "state_after": "browsing",
                    "forms": [],
                    "redirects_to": None,
                    "response_status": 200,
                    "state_change_verified": False,
                },
                {
                    "order": 2,
                    "step_name": "add_to_cart",
                    "endpoint": "/cart/add",
                    "method": "POST",
                    "form_fields_observed": ["product_id", "qty"],
                    "sample_values": {"product_id": "1", "qty": "1"},
                    "state_before": "cart_empty",
                    "state_after": "cart_has_items",
                    "response_status": 302,
                    "response_redirect": "/cart",
                    "state_change_verified": True,
                    "object_created": None,
                },
            ],
            "vulnerable_steps": [{
                "step_order": 2,
                "pattern": "BLF-07",
                "reason": "qty parameter may accept negative values",
                "test_payload": {"qty": "-1"},
                "expected_behavior": "cart count decreases below 0",
            }],
            "evidence_endpoints": ["/products", "/cart/add", "/cart"],
            "provenance": "crawl_observed",
        }],
    }


# ═══════════════════════════════════════════════════════════════════════
# TESTS: BusinessFlowMapper
# ═══════════════════════════════════════════════════════════════════════

class TestBusinessFlowMapperRun(unittest.TestCase):
    """Test BusinessFlowMapper.run() produces correct output."""

    def test_run_produces_flows_json_file(self):
        """run() should write business_flows.json to the workspace."""
        with tempfile.TemporaryDirectory() as tmp:
            # Write crawl_raw.json
            raw = _make_minimal_crawl_raw()
            Path(tmp, "crawl_raw.json").write_text(json.dumps(raw), encoding="utf-8")

            # Mock the LLM call to return valid flows
            with patch.object(BusinessFlowMapper, "_call_llm") as mock_llm:
                mock_llm.return_value = json.dumps(_make_valid_flows_response())

                mapper = BusinessFlowMapper(tmp, "http://localhost:3000")
                flows = mapper.run()

            # Check output file exists
            output_path = Path(tmp, "business_flows.json")
            self.assertTrue(output_path.exists())

            # Check structure
            self.assertIn("flows", flows)
            self.assertIn("flow_count", flows)
            self.assertIn("generated_at", flows)
            self.assertIn("model_used", flows)

            # Check flow count
            self.assertEqual(flows["flow_count"], 1)
            self.assertEqual(len(flows["flows"]), 1)

    def test_run_returns_flows_with_correct_schema(self):
        """Each flow should have required fields."""
        with tempfile.TemporaryDirectory() as tmp:
            raw = _make_minimal_crawl_raw()
            Path(tmp, "crawl_raw.json").write_text(json.dumps(raw), encoding="utf-8")

            with patch.object(BusinessFlowMapper, "_call_llm") as mock_llm:
                mock_llm.return_value = json.dumps(_make_valid_flows_response())
                mapper = BusinessFlowMapper(tmp, "http://localhost:3000")
                flows = mapper.run()

            flow = flows["flows"][0]
            required_fields = ["id", "name", "type", "confidence", "steps", "vulnerable_steps", "evidence_endpoints"]
            for field in required_fields:
                self.assertIn(field, flow, f"Missing field: {field}")

            # Check steps
            self.assertTrue(len(flow["steps"]) >= 2)
            for step in flow["steps"]:
                self.assertIn("endpoint", step)
                self.assertIn("method", step)
                self.assertIn("order", step)

    def test_empty_crawl_raw_returns_empty_flows(self):
        """Empty/invalid crawl data should return empty flows without crashing."""
        with tempfile.TemporaryDirectory() as tmp:
            flows = run(tmp, {}, "http://localhost:3000")
            self.assertEqual(flows["flow_count"], 0)
            self.assertEqual(flows["flows"], [])

            # File should still be written
            self.assertTrue(Path(tmp, "business_flows.json").exists())

    def test_missing_crawl_raw_file_returns_empty_flows(self):
        """If crawl_raw.json doesn't exist, should return empty flows."""
        with tempfile.TemporaryDirectory() as tmp:
            mapper = BusinessFlowMapper(tmp, "http://localhost:3000")
            flows = mapper.run()
            self.assertEqual(flows["flow_count"], 0)

    def test_llm_failure_returns_empty_flows(self):
        """If LLM call fails, should return empty flows gracefully."""
        with tempfile.TemporaryDirectory() as tmp:
            raw = _make_minimal_crawl_raw()
            Path(tmp, "crawl_raw.json").write_text(json.dumps(raw), encoding="utf-8")

            with patch.object(BusinessFlowMapper, "_call_llm") as mock_llm:
                mock_llm.return_value = ""  # LLM failure
                mapper = BusinessFlowMapper(tmp, "http://localhost:3000")
                flows = mapper.run()

            self.assertEqual(flows["flow_count"], 0)


class TestParseLlmResponse(unittest.TestCase):
    """Test JSON parsing of LLM responses."""

    def setUp(self):
        self.mapper = BusinessFlowMapper("/tmp", "http://localhost:3000")

    def test_parse_valid_json(self):
        """Parse a clean JSON response."""
        raw = json.dumps(_make_valid_flows_response())
        result = self.mapper._parse_llm_response(raw)
        self.assertEqual(result["flow_count"], 1)
        self.assertEqual(len(result["flows"]), 1)

    def test_parse_json_with_markdown_fences(self):
        """Parse JSON wrapped in ``` fences."""
        raw = '```json\n' + json.dumps(_make_valid_flows_response()) + '\n```'
        result = self.mapper._parse_llm_response(raw)
        self.assertEqual(result["flow_count"], 1)

    def test_parse_json_with_preamble(self):
        """Parse JSON preceded by explanatory text."""
        preamble = "Here are the business flows I identified:\n\n"
        raw = preamble + json.dumps(_make_valid_flows_response())
        result = self.mapper._parse_llm_response(raw)
        self.assertEqual(result["flow_count"], 1)

    def test_parse_invalid_json_returns_empty(self):
        """Invalid JSON should return empty flows."""
        result = self.mapper._parse_llm_response("this is not json at all")
        self.assertEqual(result["flow_count"], 0)
        self.assertEqual(result["flows"], [])

    def test_parse_empty_flows_normalized(self):
        """LLM returns flows without flow_count — should be added."""
        raw = json.dumps({"flows": [{"id": "FLOW-001", "name": "Test", "steps": [{"order": 1, "endpoint": "/test", "method": "GET"}]}]})
        result = self.mapper._parse_llm_response(raw)
        self.assertEqual(result["flow_count"], 1)

    def test_parse_flows_without_steps_filtered(self):
        """Flows without steps should be filtered out."""
        raw = json.dumps({
            "flow_count": 2,
            "flows": [
                {"id": "FLOW-001", "name": "Empty", "steps": []},
                {"id": "FLOW-002", "name": "Valid", "steps": [{"order": 1, "endpoint": "/test", "method": "GET"}]},
            ]
        })
        result = self.mapper._parse_llm_response(raw)
        self.assertEqual(result["flow_count"], 1)
        self.assertEqual(result["flows"][0]["id"], "FLOW-002")


class TestCompactPayload(unittest.TestCase):
    """Test payload compaction for LLM context."""

    def setUp(self):
        self.mapper = BusinessFlowMapper("/tmp", "http://localhost:3000")

    def test_compact_preserves_structure(self):
        """Compaction should keep essential fields."""
        raw = _make_minimal_crawl_raw()
        compact = self.mapper._compact_payload(raw)
        self.assertIn("target", compact)
        self.assertIn("anonymous", compact)

    def test_compact_trims_large_traffic(self):
        """Large http_traffic should be trimmed."""
        raw = _make_minimal_crawl_raw()
        # Inflate traffic
        raw["anonymous"]["http_traffic"] = [
            {"method": "GET", "url": f"http://localhost:3000/page{i}", "response_status": 200}
            for i in range(200)
        ]
        compact = self.mapper._compact_payload(raw)
        self.assertLessEqual(len(compact["anonymous"]["http_traffic"]), 80)


class TestBuildLlmMessages(unittest.TestCase):
    """Test LLM message construction."""

    def setUp(self):
        self.mapper = BusinessFlowMapper("/tmp", "http://localhost:3000")

    def test_messages_have_system_and_user(self):
        """Messages should contain exactly 2 messages: system + user."""
        raw = _make_minimal_crawl_raw()
        compact = self.mapper._compact_payload(raw)
        messages = self.mapper._build_llm_messages(compact)
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]["role"], "system")
        self.assertEqual(messages[1]["role"], "user")

    def test_user_message_contains_crawl_data(self):
        """User message should contain the crawl data text."""
        raw = _make_minimal_crawl_raw()
        compact = self.mapper._compact_payload(raw)
        messages = self.mapper._build_llm_messages(compact)
        user_content = messages[1]["content"]
        self.assertIn("HTTP TRAFFIC", user_content)
        self.assertIn("/cart/add", user_content)


# ═══════════════════════════════════════════════════════════════════════
# TESTS: Module-level run() function
# ═══════════════════════════════════════════════════════════════════════

class TestModuleLevelRun(unittest.TestCase):
    """Test the public run() function."""

    def test_run_with_valid_data(self):
        """run() should produce flows and write file."""
        with tempfile.TemporaryDirectory() as tmp:
            raw = _make_minimal_crawl_raw()
            # Write crawl_raw.json so mapper can load it from disk
            Path(tmp, "crawl_raw.json").write_text(json.dumps(raw), encoding="utf-8")

            with patch.object(BusinessFlowMapper, "_call_llm") as mock_llm:
                mock_llm.return_value = json.dumps(_make_valid_flows_response())
                flows = run(tmp, raw, "http://localhost:3000")

            self.assertGreater(flows["flow_count"], 0)
            self.assertEqual(len(flows["flows"]), 1)

            # Verify file was written
            output_path = Path(tmp, "business_flows.json")
            self.assertTrue(output_path.exists(), f"business_flows.json should exist at {output_path}")

    def test_run_with_none_crawl_raw(self):
        """run() with None crawl_raw should return empty flows."""
        with tempfile.TemporaryDirectory() as tmp:
            flows = run(tmp, None, "http://localhost:3000")
            self.assertEqual(flows["flow_count"], 0)


# ═══════════════════════════════════════════════════════════════════════
# TESTS: flow_context injection in bug_dossier
# ═══════════════════════════════════════════════════════════════════════

class TestFlowContextInjection(unittest.TestCase):
    """Test that enrich_bugs injects flow_context into graph_context."""

    def test_flow_context_injected_into_bug(self):
        """enrich_bugs should include flow_context in graph_context when flows exist."""
        from shared.bug_dossier import enrich_bugs

        with tempfile.TemporaryDirectory() as tmp:
            # Write business_flows.json
            flows_data = {
                "generated_at": "2026-05-31T00:00:00Z",
                "model_used": "test",
                "flow_count": 1,
                "flows": [{
                    "id": "FLOW-001",
                    "name": "Cart Flow",
                    "type": "purchase",
                    "confidence": "OBSERVED",
                    "steps": [
                        {
                            "order": 1,
                            "step_name": "view_cart",
                            "endpoint": "/cart",
                            "method": "GET",
                            "params_observed": [],
                            "state_before": "cart_has_items",
                            "state_after": "cart_displayed",
                            "forms": [],
                            "redirects_to": None,
                            "response_status": 200,
                            "state_change_verified": False,
                        },
                        {
                            "order": 2,
                            "step_name": "add_to_cart",
                            "endpoint": "/cart/add",
                            "method": "POST",
                            "form_fields_observed": ["product_id", "qty"],
                            "state_before": "cart_empty",
                            "state_after": "cart_has_items",
                            "response_status": 302,
                            "state_change_verified": True,
                        },
                    ],
                    "vulnerable_steps": [{
                        "step_order": 2,
                        "pattern": "BLF-07",
                        "reason": "qty may accept negative",
                        "test_payload": {"qty": "-1"},
                        "expected_behavior": "cart count < 0",
                    }],
                    "evidence_endpoints": ["/cart", "/cart/add"],
                    "provenance": "crawl_observed",
                }],
            }
            Path(tmp, "business_flows.json").write_text(
                json.dumps(flows_data), encoding="utf-8"
            )

            # Write minimal risk-bug.json
            bugs = [{
                "id": "BUG-001",
                "endpoint": "/cart/add",
                "method": "POST",
                "pattern_id": "BLF-07",
                "title": "Quantity manipulation",
            }]
            Path(tmp, "risk-bug.json").write_text(
                json.dumps(bugs), encoding="utf-8"
            )

            # Write minimal crawl_raw.json (needed by enrich_bugs)
            Path(tmp, "crawl_raw.json").write_text(
                json.dumps(_make_minimal_crawl_raw()), encoding="utf-8"
            )

            # Run enrichment
            enriched = enrich_bugs(tmp, bugs)
            self.assertEqual(len(enriched), 1)

            gc = enriched[0].get("graph_context", {})
            self.assertIn("flow_context", gc, "flow_context should be injected into graph_context")

            fc = gc["flow_context"]
            self.assertGreater(len(fc.get("flows", [])), 0, "Should have at least 1 matched flow")
            self.assertEqual(fc["flows"][0]["id"], "FLOW-001")

            # Check vulnerable steps are preserved
            vuln_steps = fc["flows"][0].get("vulnerable_steps", [])
            self.assertEqual(len(vuln_steps), 1)
            self.assertEqual(vuln_steps[0]["pattern"], "BLF-07")

    def test_no_flow_context_when_no_flows_file(self):
        """Without business_flows.json, graph_context should not have flow_context."""
        from shared.bug_dossier import enrich_bugs

        with tempfile.TemporaryDirectory() as tmp:
            bugs = [{
                "id": "BUG-001",
                "endpoint": "/admin",
                "method": "GET",
                "pattern_id": "BAC-01",
            }]
            Path(tmp, "risk-bug.json").write_text(json.dumps(bugs), encoding="utf-8")
            Path(tmp, "crawl_raw.json").write_text(
                json.dumps(_make_minimal_crawl_raw()), encoding="utf-8"
            )

            enriched = enrich_bugs(tmp, bugs)
            self.assertEqual(len(enriched), 1)

            gc = enriched[0].get("graph_context", {})
            # flow_context should not be present (no business_flows.json written)
            self.assertNotIn("flow_context", gc)

    def test_flow_context_matches_endpoint(self):
        """Flow context should only match bugs whose endpoint appears in flow steps."""
        from shared.business_flow_mapper import BusinessFlowMapper

        mapper = BusinessFlowMapper("/tmp", "http://localhost:3000")

        # This should match — /cart/add is in the flow
        with tempfile.TemporaryDirectory() as tmp:
            flows_data = _make_valid_flows_response()
            Path(tmp, "business_flows.json").write_text(
                json.dumps(flows_data), encoding="utf-8"
            )

            from shared.bug_dossier import _collect_flow_context

            # Should match: /cart/add is in FLOW-001 steps
            fc = _collect_flow_context(tmp, "/cart/add", "POST")
            self.assertGreater(len(fc.get("flows", [])), 0)

            # Should NOT match: /nonexistent is not in any flow
            fc_empty = _collect_flow_context(tmp, "/nonexistent", "GET")
            self.assertEqual(len(fc_empty.get("flows", [])), 0)


# ═══════════════════════════════════════════════════════════════════════
# TESTS: VulnHunterAgent business flows integration
# ═══════════════════════════════════════════════════════════════════════

class TestVulnHunterFlowsIntegration(unittest.TestCase):
    """Test VulnHunterAgent loads and uses business flows."""

    def test_build_user_prompt_includes_flows(self):
        """_build_user_prompt should include flows section when flows provided."""
        from agents.vuln_hunter_agent import _build_user_prompt

        flows = _make_valid_flows_response()["flows"]
        prompt = _build_user_prompt("recon content", "playbook", flows)

        self.assertIn("OBSERVED BUSINESS FLOWS", prompt)
        self.assertIn("FLOW-001", prompt)
        self.assertIn("Dat hang", prompt)
        self.assertIn("/cart/add", prompt)

    def test_build_user_prompt_without_flows(self):
        """_build_user_prompt should work without flows."""
        from agents.vuln_hunter_agent import _build_user_prompt

        prompt = _build_user_prompt("recon content", "playbook")
        self.assertNotIn("OBSERVED BUSINESS FLOWS", prompt)

    def test_build_user_prompt_shows_vulnerable_steps(self):
        """Prompt should include vulnerable step info."""
        from agents.vuln_hunter_agent import _build_user_prompt

        flows = _make_valid_flows_response()["flows"]
        prompt = _build_user_prompt("recon content", "playbook", flows)
        self.assertIn("BLF-07", prompt)
        self.assertIn("VULN step", prompt)


if __name__ == "__main__":
    unittest.main()
