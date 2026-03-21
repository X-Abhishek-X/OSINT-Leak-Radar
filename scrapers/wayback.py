import requests


def search_wayback_archives(domain: str) -> list:
    """
    Queries the Internet Archive CDX API for all URLs indexed for a domain.
    Finds endpoints that existed years ago but might still be exposed —
    forgotten dev servers, .env files indexed accidentally, etc.

    CDX schema: [urlkey, timestamp, original, mimetype, statuscode, digest, length]
    """
    url = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url=*{domain}/*&output=json&collapse=urlkey"
    )
    try:
        response = requests.get(url, timeout=15)
        if response.status_code != 200:
            return []
        data = response.json()
        if not data or len(data) < 2:
            return []
        # Row 0 is the header; original URL is index 2
        return [row[2] for row in data[1:] if len(row) > 2]
    except Exception as e:
        print(f"Wayback module error: {e}")
        return []
