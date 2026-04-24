import asyncio
import aiohttp
import socket
from typing import Optional


async def fetch_crtsh(session: aiohttp.ClientSession, domain: str) -> list[str]:
    """
    Queries crt.sh certificate transparency logs for all subdomains ever issued
    a TLS certificate for the target domain.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=25)) as resp:
            if resp.status != 200:
                return []
            data = await resp.json(content_type=None)
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub and domain in sub:
                        subdomains.add(sub)
            return sorted(subdomains)
    except Exception as e:
        print(f"crt.sh error: {e}")
        return []


def resolve_host(hostname: str) -> Optional[str]:
    """Returns IP if hostname resolves (is live), None if dead."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


async def enumerate_subdomains(domain: str) -> list[dict]:
    """
    Fetches subdomains from crt.sh and checks DNS liveness for each.
    Returns list of {subdomain, ip, live} dicts.
    """
    async with aiohttp.ClientSession() as session:
        subdomains = await fetch_crtsh(session, domain)

    results = []
    loop = asyncio.get_event_loop()
    for sub in subdomains:
        ip = await loop.run_in_executor(None, resolve_host, sub)
        results.append({"subdomain": sub, "ip": ip, "live": ip is not None})

    return results
