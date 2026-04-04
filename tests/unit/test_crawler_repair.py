import asyncio
import sys
import os
from pathlib import Path

# Add project root to PYTHONPATH
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from typing import Dict
from urllib.parse import urljoin
from core.scanner.crawler import Crawler, CrawlResult
from bs4 import BeautifulSoup

async def test_crawler_parse_form_logic():
    crawler = Crawler()
    html = """
    <html>
        <body>
            <form action="/submit" method="POST">
                <input name="username" type="text" value="admin">
                <input name="age" type="number" value="30">
                <input name="agree" type="checkbox" checked>
                <input name="file_upload" type="file">
            </form>
        </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    form_tag = soup.find("form")
    
    result = crawler._parse_form(form_tag, "http://localhost")
    
    assert result["action"] == "http://localhost/submit"
    assert result["method"] == "POST"
    assert len(result["inputs"]) == 4
    
    inputs_by_name = {i["name"]: i for i in result["inputs"]}
    
    assert inputs_by_name["username"]["param_type"] == "string"
    assert inputs_by_name["age"]["param_type"] == "integer"
    assert inputs_by_name["agree"]["param_type"] == "boolean"
    assert inputs_by_name["file_upload"]["param_type"] == "file"

async def test_crawler_parse_html_fallback():
    # This test ensures _parse_html doesn't throw NameError
    crawler = Crawler()
    result = CrawlResult(url="http://localhost", method="GET")
    html = "<html><body><p>Hello</p></body></html>"
    
    # Should not raise NameError
    crawler._parse_html(html, result, "http://localhost")
    assert result.page_title == "Hello" or result.page_title == ""

async def run_tests():
    print("Running crawler regression tests...")
    try:
        await test_crawler_parse_form_logic()
        print("✓ test_crawler_parse_form_logic passed")
        await test_crawler_parse_html_fallback()
        print("✓ test_crawler_parse_html_fallback passed")
        print("\nAll crawler tests passed!")
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(run_tests())
