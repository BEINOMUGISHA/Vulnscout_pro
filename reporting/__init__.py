"""
Report generation and export modules.

  - builder: Main report builder orchestration
  - builders: Report template builders
    - technical_detail: Technical vulnerability details
    - executive_summary: C-level summary report
    - compliance_builder: Regulatory compliance mapping
    - remediation_guide: Fix guide and recommendations
  - exporters: Format-specific exporters
    - pdf_exporter: PDF generation
    - html_exporter: HTML generation
    - json_exporter: JSON structure export
    - csv_exporter: CSV tabular export
    - sarif_exporter: SARIF format (IDE integration)
  - templates: Jinja2 HTML templates for reports
"""
