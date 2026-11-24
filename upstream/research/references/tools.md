# Tools for js-collect

Check that a tool exists and that its flags match your installed version (`<tool> -h`) before relying on this table. Tool flags change between releases.

| Stage | Purpose | Options |
|-------|---------|---------|
| 1 | Passive URL and archived-body discovery | `waymore`, `gau`, `waybackurls` |
| 2a | JS-aware live crawl | `katana` (JS parsing flags), `gospider`, `hakrawler` |
| 2b | Chunk enumeration | read the bundler manifest by hand (webpack runtime, Vite/Rollup manifest, Next.js `_buildManifest.js`); a purpose-built chunk-enumeration tool may help but verify it exists first |
| 2c | Browser capture | Burp, Caido, mitmproxy, Chrome DevTools MCP, Playwright, Puppeteer |
| 2c | TLS impersonation (only if allowed by the program) | `curl_cffi` via `scoped_fetch.py --impersonate` |
| 4a | Sourcemap extraction | read `sourcesContent` with a short script, or a sourcemap-extractor tool (e.g. `sourcemapper`) |
| 4b | Unpack / unminify / deobfuscate | `webcrack`, `wakaru`, `js-beautify`, Prettier |
| 5 | URL and path extraction | `jsluice` |

## Notes

- Dependencies for `scripts/scoped_fetch.py`: Python 3.8+ standard library only. `curl_cffi` is needed only for `--impersonate`.
- Passive tools query third-party archives and do not contact the target, but they still have their own rate limits and API key requirements.
- Anything you add to this table should be a tool you have actually run. Remove entries you can't confirm.
