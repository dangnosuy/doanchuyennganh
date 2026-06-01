import json
import tempfile
import unittest
from pathlib import Path

from agents.blue_team import BlueTeamAgent
from agents.exec_agent import ExecAgent
from agents.manage_agent import ManageAgent
from agents.red_team import RedTeamAgent
from agents.vuln_hunter_agent import VulnHunterAgent
from shared.bug_dossier import load_and_enrich_risk_bugs


def _sample_bug() -> dict:
    return {
        "id": "BUG-001",
        "category": "BAC",
        "pattern_id": "BAC-03",
        "candidate_type": "EVIDENCE_BACKED",
        "evidence_status": "CRAWL_OBSERVED",
        "title": "Cart item update IDOR",
        "risk_level": "HIGH",
        "endpoint": "/api/cart-items/{id}",
        "method": "PUT",
        "hypothesis": "Basket item id is directly mutable.",
        "exploit_approach": "Change the id and compare ownership.",
        "verify_method": "Verify owner/account id differs from current user.",
        "auth_required": True,
        "auth_credentials_needed": ["user"],
        "request_params": ["id", "quantity"],
        "http_examples": [{
            "method": "PUT",
            "path": "/api/cart-items/12",
            "status": 200,
            "request_body": "{\"quantity\": 1}",
            "response_snippet": "{\"status\":\"success\",\"data\":{\"ownerId\":6,\"id\":12}}",
            "auth_session": "user",
            "provenance": "crawl",
        }],
        "status": "PENDING",
    }


def _write_sample_workspace(run_dir: Path) -> None:
    crawl_raw = {
        "target": "http://localhost:3000",
        "anonymous": {"http_traffic": [], "workflow_graph": {"nodes": [], "edges": []}},
        "authenticated": [{
            "label": "user",
            "cookies": [],
            "data": {
                "http_traffic": [{
                    "method": "PUT",
                    "url": "http://localhost:3000/api/cart-items/12",
                    "postData": "{\"quantity\": 1}",
                    "response_status": 200,
                    "response_headers": {"content-type": "application/json"},
                    "response_body": "{\"status\":\"success\",\"data\":{\"ownerId\":6,\"id\":12,\"quantity\":1}}",
                    "resource_type": "fetch",
                    "parent_url": "http://localhost:3000/#/cart",
                }],
                "workflow_graph": {
                    "nodes": [
                        {"id": "/#/cart", "kind": "page", "methods": []},
                        {"id": "/api/cart-items/12", "kind": "endpoint", "methods": ["PUT"]},
                    ],
                    "edges": [{
                        "from": "/#/cart",
                        "to": "/api/cart-items/12",
                        "type": "request",
                        "method": "PUT",
                        "status": 200,
                    }],
                },
                "business_chain": [{
                    "step": "cart_update_quantity",
                    "method": "PUT",
                    "endpoint": "/api/cart-items/12",
                    "status": 200,
                }],
                "api_hints": [{
                    "method": "PUT",
                    "path": "/api/cart-items/{id}",
                    "source": "/main.js",
                    "reason": "cart service static JS",
                }],
            },
        }],
    }
    (run_dir / "crawl_raw.json").write_text(json.dumps(crawl_raw), encoding="utf-8")
    (run_dir / "risk-bug.json").write_text(json.dumps([_sample_bug()]), encoding="utf-8")
    (run_dir / "recon.md").write_text(
        "# Recon\n\n"
        + ("prefix\n" * 900)
        + "## Guided Workflow Graph\nPUT /api/cart-items/12 from cart page\n\n"
        + "## Guided Auth And API Hints\ncart_update_quantity\n",
        encoding="utf-8",
    )


class DossierEnrichmentTests(unittest.TestCase):
    def test_load_and_enrich_normalizes_examples_and_attaches_graph_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            _write_sample_workspace(run_dir)

            bugs = load_and_enrich_risk_bugs(str(run_dir))

        self.assertEqual(len(bugs), 1)
        bug = bugs[0]
        example = bug["http_examples"][0]
        self.assertIn("PUT /api/cart-items/12 HTTP/1.1", example["request"])
        self.assertEqual(example["response_status"], 200)
        self.assertEqual(example["session_label"], "user")
        self.assertEqual(example["auth_session"], "user")
        self.assertTrue(bug["graph_context"]["business_chain"])
        self.assertTrue(bug["graph_context"]["edges"])
        self.assertTrue(any("BAC-03 proof" in rule for rule in bug["evidence_rules"]))

    def test_vulnhunter_raw_endpoint_match_returns_prompt_compatible_example(self):
        raw_endpoints = [{
            "method": "PUT",
            "path": "/api/cart-items/12",
            "status": 200,
            "request": {"body": "{\"quantity\":99}"},
            "response": {"body_snippet": "{\"quantity\":99}", "headers": {"content-type": "application/json"}},
            "auth_session": "user",
            "provenance": "crawl",
        }]

        examples = VulnHunterAgent._match_raw_endpoints("/api/cart-items/{id}", "PUT", raw_endpoints)

        self.assertEqual(examples[0]["response_status"], 200)
        self.assertEqual(examples[0]["session_label"], "user")
        self.assertIn("PUT /api/cart-items/12 HTTP/1.1", examples[0]["request"])


class AgentContextRenderingTests(unittest.TestCase):
    def test_manage_context_pack_keeps_late_graph_section(self):
        recon = "# Recon\n" + ("noise\n" * 1200) + "## Guided Workflow Graph\nimportant graph\n"

        packed = ManageAgent._build_manager_recon_pack(recon)

        self.assertIn("Guided Workflow Graph", packed)
        self.assertIn("important graph", packed)

    def test_red_blue_prompts_include_normalized_example_and_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            _write_sample_workspace(run_dir)
            bug = load_and_enrich_risk_bugs(str(run_dir))[0]

        red = object.__new__(RedTeamAgent)
        red.target_url = "http://localhost:3000"
        red.memory_store = None
        red.set_current_bug(bug)
        self.assertIn("PUT /api/cart-items/12 HTTP/1.1", red.system_prompt)
        self.assertIn("Guided Workflow / Graph Context", red.system_prompt)

        blue = object.__new__(BlueTeamAgent)
        blue.target_url = "http://localhost:3000"
        blue.memory_store = None
        blue.set_current_bug(bug)
        self.assertIn("PUT /api/cart-items/12 HTTP/1.1", blue.system_prompt)
        self.assertIn("Guided Workflow / Graph Context", blue.system_prompt)
        self.assertIn("evidence_ref=<METHOD path/status", blue.system_prompt)

    def test_exec_context_includes_graph_and_evidence_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            _write_sample_workspace(run_dir)
            bug = load_and_enrich_risk_bugs(str(run_dir))[0]

            exec_agent = object.__new__(ExecAgent)
            exec_agent.working_dir = str(run_dir)
            exec_agent.recon_context = ""
            context = exec_agent._build_tool_execution_context(
                current_bug=bug,
                artifact_prefix="BUG-001",
                bearer_token="tok",
                cookie_header="",
                auth_mechanism="jwt_bearer",
            )

        self.assertIn("CURRENT BUG GUIDED GRAPH CONTEXT", context)
        self.assertIn("cart_update_quantity", context)
        self.assertIn("CURRENT BUG EVIDENCE RULES", context)


if __name__ == "__main__":
    unittest.main()
