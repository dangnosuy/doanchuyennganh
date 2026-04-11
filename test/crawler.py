"""Backward-compatibility shim — imports from tools.crawler.

Existing code (agent.py, debate.py) can still do:
    from crawler import BrowserAgent, run_crawl
"""

from tools.crawler import BrowserAgent, run_crawl, BLACKLISTED_KEYWORDS, STATIC_EXTENSIONS

__all__ = ["BrowserAgent", "run_crawl", "BLACKLISTED_KEYWORDS", "STATIC_EXTENSIONS"]
