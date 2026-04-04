"""
Web application scanning engine.

Contains the orchestration, crawling, and exploitation modules:
  - orchestrator: Main scan execution orchestrator
  - crawler: Spider/crawler for discovering endpoints
  - parallel_engine: Concurrent execution of detection modules
  - injector: Payload injection and mutation engine
  - validator: Vulnerability confirmation and proof-of-concept
  - rate_limiter: Request rate limiting and throttling
  - scope_enforcer: Scope constraint validation
  - auth_handler: Authentication context management
  - attack_surface: Attack surface mapping
  - js_renderer: Headless browser automation
  - oob: Out-of-band (OOB) exploitation support
  - iast_sensor: Interactive AST sensor (if available)
"""
