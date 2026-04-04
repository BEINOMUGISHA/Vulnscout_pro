import sys
print("Starting script...")
import asyncio
print("Imported asyncio")
import os
print("Imported os")

sys.path.append(r"c:\Users\beino\Desktop\vulnscout_pro")
print("Appended to path")

print("Importing Crawler...")
from core.scanner.crawler import Crawler
print("Imported Crawler successfully!")

async def main():
    print("Testing crawler initialization...")
    crawler = Crawler(api_fuzzing=False, respect_robots=False)
    
    print("Starting crawl generator...")
    async for result in crawler.crawl("https://example.com"):
        print(f"Yielded: {result.url}")

if __name__ == "__main__":
    asyncio.run(main())
