
import asyncio
import aiohttp
import sys

async def test_endpoint(url):
    print(f"[*] Testing {url}...")
    try:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            async with session.get(url, timeout=10) as resp:
                print(f"[+] Status: {resp.status}")
                print(f"[+] Headers: {dict(resp.headers)}")
                body = await resp.text()
                print(f"[+] Body length: {len(body)}")
                print(f"[+] Preview: {body[:100]}...")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_net.py <url>")
    else:
        asyncio.run(test_endpoint(sys.argv[1]))
