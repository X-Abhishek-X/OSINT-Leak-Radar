# OSINT-Leak-Radar

Scans the Wayback Machine's archive index for a target domain and surfaces URLs matching sensitive file patterns — `.env` files, SQL dumps, private keys, and config files that got crawled and indexed before anyone noticed.

The idea: companies make mistakes. A developer commits a `.env` to a staging server, it gets indexed by web crawlers, the server gets decommissioned, but the archive copy lives on. This tool queries the [Internet Archive CDX API](http://web.archive.org/cdx/search/cdx) for every URL ever indexed under a domain, then filters for the ones that look like they shouldn't be public.

---

### What it finds

Matches against patterns like:

| Pattern | What it catches |
|---|---|
| `*.env` | Exposed environment files (API keys, DB passwords) |
| `*.sql`, `*.sql.gz` | Database dumps |
| `*.pem`, `id_rsa` | Private keys |
| `credentials.xml` | Jenkins, Android keystores |
| `config.php` | CMS database credentials |
| `db_backup*` | Named backup archives |

---

### Usage

```bash
git clone https://github.com/X-Abhishek-X/OSINT-Leak-Radar.git
cd OSINT-Leak-Radar
pip install -r requirements.txt

python radar.py scan example.com
```

Output:

```
📡 OSINT-LEAK-RADAR initializing for target: example.com
🔍 Querying Wayback CDX API...

┌─────────────────────────────────────────────────────────────────┐
│         Critical Exposures for example.com                      │
├────────────┬───────────────────┬────────────────────────────────┤
│ Confidence │ Leak Type         │ URL                            │
├────────────┼───────────────────┼────────────────────────────────┤
│ 98%        │ Critical File Leak│ http://example.com/.env        │
│ 98%        │ Critical File Leak│ http://staging.example.com/... │
└────────────┴───────────────────┴────────────────────────────────┘
```

Results show URLs that were historically indexed — they may or may not still be live. Check each manually.

---

### How it works

1. `GET http://web.archive.org/cdx/search/cdx?url=*{domain}/*&output=json&collapse=urlkey`
2. Parse every URL the archive has ever crawled for that domain
3. Run regex pattern matching against each URL path
4. Display matches in a rich table sorted by sensitivity

The CDX endpoint returns deduplicated URLs and is free to query. No authentication needed.

---

### Limitations

- Only finds URLs the Wayback Machine has indexed — not a live scan
- A result doesn't mean the file is still accessible; verify manually
- Large domains (e.g. google.com) will return huge CDX responses — target subdomains instead

---

### Legal

For authorised security testing and defensive reconnaissance only. Always ensure you have permission before scanning a domain you don't own.

---

### License

MIT
