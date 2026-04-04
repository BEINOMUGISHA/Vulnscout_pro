"""
Vulnerability detection modules.

Each detector module checks for a specific vulnerability class:
  - sqli: SQL Injection (error-based, blind, time-based)
  - xss: Cross-Site Scripting (reflected, stored, DOM-based)
  - xxe: XML External Entity attacks
  - ssrf: Server-Side Request Forgery
  - idor: Insecure Direct Object Reference
  - auth_bypass: Authentication bypass techniques
  - jwt_detector: JWT token vulnerabilities
  - graphql_detector: GraphQL-specific attacks
  - broken_auth: Session and authentication flaws
  - misconfig: Security misconfigurations
  - sensitive_data: Hardcoded secrets and data leaks
  - server_side: Server-side template injection, RCE
  - business_logic: Business logic vulnerabilities
  - api_scanner: REST API-specific issues
  - llm_detector: LLM prompt injection and jailbreak
  
  - base_detector: Base class for all detectors
  - registry: Detector discovery and registry
"""
