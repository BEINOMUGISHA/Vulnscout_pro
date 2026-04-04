"""
FastAPI middleware components.

Middleware stack (applied in reverse order):
  1. CORSMiddleware — handles cross-origin requests
  2. SecurityHeadersMiddleware — injects security headers
  3. LoggingMiddleware — structured request/response logging
  4. AuthMiddleware — JWT and API key validation
"""
