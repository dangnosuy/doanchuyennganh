import argparse
import json
import tempfile
import unittest
from pathlib import Path
from urllib.request import urlopen

from agents.crawl_agent import CrawlAgent
from agents.vuln_hunter_agent import VulnHunterAgent
from agents.vuln_hunter_agent import _build_user_prompt
from tools import crawler


class GuidedCrawlerContractTests(unittest.TestCase):
    def test_cookie_header_is_converted_to_playwright_cookies(self):
        cookies = crawler._parse_cookie_header("sid=abc; role=user", "http://localhost:3000")

        self.assertEqual(
            cookies,
            [
                {"name": "sid", "value": "abc", "domain": "localhost", "path": "/"},
                {"name": "role", "value": "user", "domain": "localhost", "path": "/"},
            ],
        )

    def test_cli_headers_parse_authorization(self):
        headers = crawler._headers_from_cli(["Authorization: Bearer abc.def", "X-Test: yes"])

        self.assertEqual(headers["Authorization"], "Bearer abc.def")
        self.assertEqual(headers["X-Test"], "yes")

    def test_storage_values_are_replayed_without_app_specific_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text(json.dumps({
                "cookies": [],
                "origins": [{
                    "origin": "http://localhost:3000",
                    "localStorage": [
                        {"name": "token", "value": "tok"},
                        {"name": "bid", "value": "6"},
                        {"name": "email", "value": "test@gmail.com"},
                    ],
                }],
            }), encoding="utf-8")

            values = crawler._storage_values_from_state(str(path), "http://localhost:3000")
            script = crawler._auth_bootstrap_script(values)

        self.assertEqual(values["bid"], "6")
        self.assertIn("sessionStorage.setItem(key, value)", script)
        self.assertNotIn("basketId", script)

    def test_workflow_graph_contains_request_and_action_edges(self):
        state = crawler.GuidedState(target="http://localhost:3000", max_pages=5)
        state.pages.append({
            "url": "http://localhost:3000/#/search",
            "title": "Search",
            "links": [{"href": "http://localhost:3000/#/cart"}],
            "forms": [],
        })
        state.http_traffic.append({
            "method": "PUT",
            "url": "http://localhost:3000/api/cart-items/12",
            "response_status": 200,
            "parent_url": "http://localhost:3000/#/cart",
        })
        state.observed_actions.append({
            "name": "add_to_cart",
            "before_url": "http://localhost:3000/#/search",
            "after_url": "http://localhost:3000/#/cart",
        })

        graph = crawler._build_workflow_graph(state)

        node_ids = {node["id"] for node in graph["nodes"]}
        self.assertIn("/api/cart-items/12", node_ids)
        self.assertTrue(
            any(
                edge.get("type") == "request"
                and edge.get("method") == "PUT"
                and edge.get("to") == "/api/cart-items/12"
                for edge in graph["edges"]
            )
        )
        self.assertTrue(any(edge.get("label") == "add_to_cart" for edge in graph["edges"]))

    def test_cli_result_contract_for_missing_playwright(self):
        try:
            urlopen("http://localhost:3000", timeout=2).close()
        except Exception:
            self.skipTest("localhost:3000 is not running")

        parser = argparse.Namespace(
            url="http://localhost:3000",
            max_pages=1,
            max_rounds=1,
            timeout=3,
            headless=True,
            storage_state="",
            ai_guided=False,
            ai_steps=0,
            header=[],
            cookie_header="",
        )
        result = crawler.run_guided_crawl(parser)

        for key in ("http_traffic", "cookies", "external_links", "pages", "observed_actions", "workflow_graph"):
            self.assertIn(key, result)
        self.assertIn("nodes", result["workflow_graph"])
        self.assertIn("edges", result["workflow_graph"])

    def test_ai_policy_allows_mapping_navigation_but_blocks_destructive_clicks(self):
        self.assertFalse(crawler._is_blocked_navigation("Admin dashboard"))
        self.assertFalse(crawler._is_blocked_navigation("Checkout page"))
        self.assertTrue(crawler._is_blocked_navigation("Logout"))
        self.assertTrue(crawler._is_blocked_action("Delete account"))
        self.assertFalse(crawler._is_blocked_action("Add to Basket"))
        self.assertTrue(crawler._is_allowed_stateful_click("Add to Cart"))

    def test_planner_json_extracts_object_from_model_text(self):
        parsed = crawler._planner_json_from_text('```json\n{"action_id":"A02","reason":"map cart"}\n```')

        self.assertEqual(parsed["action_id"], "A02")
        self.assertEqual(parsed["reason"], "map cart")

    def test_ai_fallback_prefers_business_action_over_generic_login(self):
        state = crawler.GuidedState(target="http://localhost:3000", max_pages=5)
        selected = crawler._fallback_candidate([
            {
                "action_id": "A01",
                "action_type": "navigate",
                "label": "Login",
                "current_endpoint": "/#/",
                "target_endpoint": "/#/login",
                "risk": "read_only_navigation",
                "score": -10,
            },
            {
                "action_id": "A02",
                "action_type": "click",
                "label": "Add to Basket",
                "current_endpoint": "/#/",
                "target_endpoint": "/#/",
                "risk": "bounded_state_changing",
                "score": 30,
            },
        ], state)

        self.assertEqual(selected["action_id"], "A02")

    def test_ai_fallback_avoids_known_no_effect_clicks(self):
        state = crawler.GuidedState(target="http://localhost:3000", max_pages=5)
        state.request_chains.append({
            "action_type": "click",
            "label": "search",
            "before_endpoint": "/#/basket",
            "after_endpoint": "/#/basket",
            "emitted_requests": [],
        })
        selected = crawler._fallback_candidate([
            {
                "action_id": "A01",
                "action_type": "click",
                "label": "search",
                "current_endpoint": "/#/basket",
                "target_endpoint": "/#/basket",
                "risk": "safe_click",
                "score": 10,
            },
            {
                "action_id": "A02",
                "action_type": "navigate",
                "label": "Search page",
                "current_endpoint": "/#/basket",
                "target_endpoint": "/#/search",
                "risk": "read_only_navigation",
                "score": 10,
            },
        ], state)

        self.assertEqual(selected["action_id"], "A02")

    def test_memory_aware_fallback_prefers_uncovered_surface(self):
        state = crawler.GuidedState(target="http://localhost:3000", max_pages=5)
        state.memory.covered_surfaces.add("commerce")
        state.memory.tried_actions.add((
            "/#/cart",
            "navigate",
            "cart",
            "/#/cart",
        ))

        selected = crawler._fallback_candidate([
            {
                "action_id": "A01",
                "action_type": "navigate",
                "label": "Cart",
                "current_endpoint": "/#/cart",
                "target_endpoint": "/#/cart",
                "risk": "read_only_navigation",
                "score": 50,
                "memory_surfaces": ["commerce"],
            },
            {
                "action_id": "A02",
                "action_type": "navigate",
                "label": "Admin dashboard",
                "current_endpoint": "/#/cart",
                "target_endpoint": "/#/admin",
                "risk": "read_only_navigation",
                "score": 20,
                "memory_surfaces": ["access_control"],
            },
        ], state)

        self.assertEqual(selected["action_id"], "A02")

    def test_request_chain_projects_to_business_chain_and_graph(self):
        state = crawler.GuidedState(target="http://localhost:3000", max_pages=5)
        state.http_traffic.append({
            "method": "POST",
            "url": "http://localhost:3000/cart/add",
            "response_status": 302,
            "resource_type": "document",
            "postData": "product_id=1&qty=1",
        })
        candidate = {
            "action_id": "A01",
            "action_type": "click",
            "label": "Add to Cart",
            "risk": "bounded_state_changing",
        }

        crawler._append_request_chain(
            state,
            candidate,
            "http://localhost:3000/product/1",
            "http://localhost:3000/cart",
            0,
            "ok",
            "map cart flow",
        )
        graph = crawler._build_workflow_graph(state)

        self.assertEqual(state.request_chains[0]["action_id"], "A01")
        self.assertEqual(state.business_chain[0]["endpoint"], "/cart/add")
        self.assertTrue(any(edge.get("type") == "request_chain" for edge in graph["edges"]))
        self.assertTrue(any(edge.get("type") == "chain_request" for edge in graph["edges"]))

    def test_graph_coverage_evaluator_reports_business_gaps(self):
        state = crawler.GuidedState(target="http://localhost:3000", max_pages=5)
        state.pages.append({
            "url": "http://localhost:3000/#/cart",
            "title": "Cart",
            "links": [{"href": "http://localhost:3000/#/checkout"}],
            "forms": [],
        })
        state.http_traffic.append({
            "method": "PUT",
            "url": "http://localhost:3000/api/cart-items/12",
            "response_status": 200,
            "parent_url": "http://localhost:3000/#/cart",
        })

        graph = crawler._build_workflow_graph(state)
        coverage = crawler._evaluate_graph_coverage(state, graph)

        self.assertGreater(coverage["score"], 0)
        self.assertTrue(coverage["surfaces"]["commerce"]["covered"])
        self.assertFalse(coverage["surfaces"]["access_control"]["covered"])
        self.assertIn("Explore access_control routes/actions if in scope.", coverage["recommendations"])


class CrawlReconWorkflowSectionTests(unittest.TestCase):
    def test_recon_renders_guided_workflow_graph(self):
        raw_payload = {
            "anonymous": {
                "workflow_graph": {
                    "nodes": [
                        {"id": "/#/search", "methods": []},
                        {"id": "/api/cart-items/12", "methods": ["PUT"]},
                    ],
                    "edges": [
                        {
                            "from": "/#/cart",
                            "to": "/api/cart-items/12",
                            "type": "request",
                            "method": "PUT",
                            "status": 200,
                        }
                    ],
                }
            }
        }

        section = CrawlAgent._render_workflow_graph_recon_section(raw_payload)

        self.assertIn("Guided Workflow Graph", section)
        self.assertIn("/api/cart-items/12", section)
        self.assertIn("PUT", section)

    def test_recon_renders_api_hints_and_business_chain(self):
        raw_payload = {
            "authenticated": [{
                "label": "user",
                "data": {
                    "auth_bootstrap": {"has_token": True, "verified": True, "checks": []},
                    "business_chain": [
                        {"step": "cart_update_quantity", "method": "PUT", "endpoint": "/api/cart-items/12", "status": 200}
                    ],
                    "api_hints": [
                        {"method": "PUT", "path": "/api/cart-items/{id}", "source": "/main.js", "reason": "cart service static JS"}
                    ],
                },
            }]
        }

        section = CrawlAgent._render_static_api_hints_recon_section(raw_payload)

        self.assertIn("Guided Auth And API Hints", section)
        self.assertIn("cart_update_quantity", section)
        self.assertIn("/api/cart-items/{id}", section)

    def test_recon_renders_graph_coverage(self):
        raw_payload = {
            "anonymous": {
                "crawl_memory": {
                    "coverage_gaps": ["access_control"],
                    "repeated_endpoint_hits": [{"endpoint": "/#/cart", "hits": 4}],
                },
                "graph_coverage": {
                    "score": 45,
                    "node_count": 4,
                    "edge_count": 5,
                    "state_changing_edge_count": 1,
                    "request_chain_edge_count": 2,
                    "surfaces": {
                        "commerce": {"covered": True},
                        "access_control": {"covered": False},
                    },
                    "recommendations": ["Explore access_control routes/actions if in scope."],
                },
            }
        }

        section = CrawlAgent._render_graph_coverage_recon_section(raw_payload)

        self.assertIn("Crawl Graph Coverage Evaluation", section)
        self.assertIn("45", section)
        self.assertIn("access_control", section)
        self.assertIn("/#/cart", section)


class VulnHunterEvidenceTests(unittest.TestCase):
    def test_vulnhunter_prompt_allows_literal_route_templates(self):
        prompt = _build_user_prompt("Static JS API Hints: /api/cart/{id}/coupon/{code}", "PLAYBOOK")

        self.assertIn("/api/cart/{id}", prompt)
        self.assertIn("PLAYBOOK", prompt)

    def test_invalid_nan_endpoint_is_rejected(self):
        self.assertTrue(VulnHunterAgent._is_invalid_endpoint("/api/orders/NaN"))
        self.assertFalse(VulnHunterAgent._is_invalid_endpoint("/api/orders/6"))

    def test_state_changing_endpoint_matches_raw_observed_method(self):
        raw_endpoints = [
            {
                "method": "PUT",
                "path": "/api/cart-items/12",
                "status": 200,
                "request": {"body": '{"quantity":99}'},
                "response": {"body_snippet": '{"quantity":99}', "headers": {"content-type": "application/json"}},
                "auth_session": "user",
                "provenance": "crawl",
            }
        ]

        examples = VulnHunterAgent._match_raw_endpoints("/api/cart-items/{id}", "PUT", raw_endpoints)

        self.assertEqual(len(examples), 1)
        self.assertEqual(examples[0]["method"], "PUT")
        self.assertEqual(examples[0]["provenance"], "crawl")

    def test_action_discovery_is_grounded_in_nearby_schema(self):
        bug = {"method": "POST", "endpoint": "/api/cart-items"}
        raw_endpoints = [
            {
                "method": "GET",
                "path": "/api/cart-items",
                "status": 200,
                "request": {"body": None},
                "response": {
                    "body_snippet": '{"quantity": 10, "limitPerUser": 5}',
                    "headers": {"content-type": "application/json"},
                },
                "auth_session": "anonymous",
                "provenance": "crawl",
            }
        ]

        example = VulnHunterAgent._build_action_discovery_example(bug, raw_endpoints)

        self.assertIsNotNone(example)
        self.assertEqual(example["provenance"], "action_discovery")
        self.assertEqual(example["discovery"]["candidate_method"], "POST")

    def test_action_discovery_rejects_read_only_user_collection(self):
        bug = {"method": "POST", "endpoint": "/api/users"}
        raw_endpoints = [
            {
                "method": "GET",
                "path": "/api/users",
                "status": 200,
                "request": {"body": None},
                "response": {
                    "body_snippet": '{"data":[{"id":1,"email":"a@b.test","role":"user"}]}',
                    "headers": {"content-type": "application/json"},
                },
                "auth_session": "user",
                "provenance": "crawl",
            }
        ]

        example = VulnHunterAgent._build_action_discovery_example(bug, raw_endpoints)

        self.assertIsNone(example)

    def test_action_discovery_rejects_order_history_post_guess(self):
        bug = {"method": "POST", "endpoint": "/api/audit-history"}
        raw_endpoints = [
            {
                "method": "GET",
                "path": "/api/audit-history",
                "status": 200,
                "request": {"body": None},
                "response": {
                    "body_snippet": '{"data":[{"orderId":"abc","totalPrice":10}]}',
                    "headers": {"content-type": "application/json"},
                },
                "auth_session": "user",
                "provenance": "crawl",
            }
        ]

        example = VulnHunterAgent._build_action_discovery_example(bug, raw_endpoints)

        self.assertIsNone(example)

    def test_dedupe_prefers_crawl_observed_over_action_discovery(self):
        action_bug = {
            "id": "BUG-001",
            "endpoint": "/api/cart-items/{id}",
            "method": "PUT",
            "candidate_type": "ACTION_DISCOVERY",
            "evidence_status": "ACTION_DISCOVERY",
            "risk_level": "HIGH",
            "confidence": "LOW",
            "http_examples": [{
                "method": "GET",
                "path": "/api/cart-items",
                "status": 200,
                "provenance": "action_discovery",
            }],
        }
        observed_bug = {
            "id": "BUG-002",
            "endpoint": "/api/cart-items/12",
            "method": "PUT",
            "candidate_type": "EVIDENCE_BACKED",
            "evidence_status": "CRAWL_OBSERVED",
            "risk_level": "HIGH",
            "confidence": "HIGH",
            "http_examples": [{
                "method": "PUT",
                "path": "/api/cart-items/12",
                "status": 200,
                "provenance": "crawl",
            }],
        }

        bugs = VulnHunterAgent._dedupe_and_rank_candidates([action_bug, observed_bug])

        self.assertEqual(len(bugs), 1)
        self.assertEqual(bugs[0]["id"], "BUG-002")
        self.assertEqual(bugs[0]["evidence_status"], "CRAWL_OBSERVED")

    def test_deterministic_candidates_add_generic_state_changing_put(self):
        hunter = object.__new__(VulnHunterAgent)
        hunter._raw_payload = {"authenticated": [{"label": "user", "data": {"api_hints": []}}]}
        raw_endpoints = [
            {
                "method": "PUT",
                "path": "/api/cart-items/12",
                "status": 200,
                "request": {"body": '{"quantity":1}'},
                "response": {
                    "body_snippet": '{"id":12,"quantity":1}',
                    "headers": {"content-type": "application/json"},
                    "json_keys": ["data.id", "data.quantity"],
                    "numeric_fields": ["data.quantity"],
                },
                "auth_session": "user",
                "provenance": "crawl",
            }
        ]

        bugs = hunter._add_deterministic_candidates([], raw_endpoints)

        self.assertTrue(any(b["endpoint"] == "/api/cart-items/{id}" and b["method"] == "PUT" for b in bugs))


if __name__ == "__main__":
    unittest.main()
