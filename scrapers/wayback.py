import asyncio
import aiohttp
import requests


async def _fetch_url(session: aiohttp.ClientSession, url: str, timeout: int) -> list:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status != 200:
                return []
            data = await resp.json(content_type=None)
            if not data or len(data) < 2:
                return []
            return [row[2] for row in data[1:] if len(row) > 2]
    except Exception:
        return []


async def search_wayback_async(domain: str, timeout: int = 20) -> list:
    """
    Async Wayback CDX query — splits into two requests (http + https) and runs in parallel.
    """
    urls = [
        f"http://web.archive.org/cdx/search/cdx?url=*{domain}/*&output=json&collapse=urlkey&fl=original&filter=statuscode:200",
        f"http://web.archive.org/cdx/search/cdx?url=*{domain}/*&output=json&collapse=urlkey&fl=original&filter=statuscode:301",
    ]
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*[_fetch_url(session, u, timeout) for u in urls])
    combined = list({url for batch in results for url in batch})
    return combined


def search_wayback_archives(domain: str) -> list:
    """Sync wrapper around the async Wayback fetcher."""
    try:
        return asyncio.run(search_wayback_async(domain))
    except Exception as e:
        print(f"Wayback error: {e}")
        return []
