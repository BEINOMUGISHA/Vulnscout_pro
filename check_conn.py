
import asyncio
import aiohttp
import sys

async def check():
    url = "https://www.google.com"
    print(f"Checking connectivity to {url}...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as response:
                print(f"Success! Status: {response.status}")
                return True
    except Exception as e:
        print(f"Failed to connect: {type(e).__name__}: {e}")
        return False

if __name__ == "__main__":
    asyncio.run(check())
