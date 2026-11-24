---
name: js-collect
description: Find, download, store, and prepare all JavaScript for a web target during authorized bug bounty or security testing. Use this skill whenever the user wants to gather JS files, spider a site for scripts, find lazy-loaded chunks, pull historical JS from archives, recover sourcemaps, fetch JS behind bot protection, or un-minify and deobfuscate bundles. Trigger on phrases like "collect the JS", "grab all javascript", "download the bundles", "get sourcemaps", "find the chunks", "prep JS for analysis", or "look at their frontend", even if the user does not say "collect". Run this BEFORE js-sinks and js-analyse.
---

# JS Collect

Goal: a complete, deduplicated, organized, readable local copy of every JavaScript asset a target serves or has served, so `js-sinks` and `js-analyse` get clean input.

This skill only collects and prepares. Sink/gadget mapping lives in `js-sinks`; endpoints, secrets, libraries, and the feature map live in `js-analyse`.

> **Authorized testing only.** Stay inside the program's scope and rate limits. Do Stage 0 before the first request to the target.

Bundled files:
- `scripts/scoped_fetch.py`: the only way to download from the target (enforces scope, rate, redirects, storage, manifest)
- `references/tools.md`: tool table, install notes, and what to verify before relying on a tool

## Stage 0: Scope and rules contract

Do this first. If anything is missing, stop before sending any request to the target.

1. **Scope file.** Create `js-collect-output/<target>/scope.txt`, one host or wildcard per line (`example.com`, `*.example.com`; note the wildcard does not match the apex). Prefix `!` for exclusions. Copy these from the program page, don't guess.
2. **Rate file.** Create `rate.txt` with the requests/second ceiling (default `2`).
3. **Check the program's rules** and record the answers in `manifest.json` under `run_contract`:
   - Is automated scanning/spidering/crawling allowed?
   - Is working around bot protection (TLS impersonation, challenge solving) allowed? These are separate questions. If the second is not clearly yes, the answer is no.
4. If automation is unclear, ask the user. If bot-protection workarounds are not allowed, limit yourself to the user's own browser session (step 3 of the Stage 2c ladder).

Passive archive lookups in Stage 1 make no requests to the target, so Stage 0 gates active stages only.

## Stage 1: Passive discovery (no requests to the target)

Run before crawling. It costs the target nothing and shows the historical surface first.

- Use an archive aggregator (`waymore`, `gau`, or `waybackurls`; see `references/tools.md`) to list historical URLs, filter to `.js`.
- Where the tool can fetch archived **response bodies**, keep them under `historical/<date>/`. A URL list gives names; an archived body gives old code.
- Historical bundles often keep removed endpoints, old API versions, and values later cleaned up. Treat this as recon, not a fallback.

## Stage 2: Active collection

All requests to the target go through the scoped fetcher:

```bash
python scripts/scoped_fetch.py --dir js-collect-output/<target> --via "katana crawl" --urls-file js_urls.txt
```

### 2a. Live crawl
- Crawl in-scope hosts with a JS-aware crawler (`katana` with JS parsing, or `gospider`/`hakrawler`), keeping its rate flag at or below `rate.txt`.
- Collect every `<script src>`, `<link rel="modulepreload">`, `<link rel="preload" as="script">`, service worker, web worker, and `import()` / `importScripts()` target.
- Save inline `<script>` blocks to `inline/`, named after the page they came from.

### 2b. Lazy-loaded chunks (don't skip)
A page fetch yields the entry bundle only. Other chunks exist as strings the bundler assembles at runtime.
- Read the loader/manifest: webpack `__webpack_require__.u`, Vite/Rollup manifest, Next.js `_buildManifest.js` and `_ssgManifest.js`, Nuxt/Angular/SvelteKit equivalents. List every chunk name and request each one.
- Walk the app in a browser, once per role you have: visit every route, open modals and tabs, and capture JS requests from the network log or proxy history.
- Record each chunk's `discovered_via`. A chunk named in the live manifest is higher confidence than one seen only in an archive.

### 2c. If plain fetching is blocked
Escalate one step at a time; stop at the first that works, and record `method_used`.
1. Plain request through `scoped_fetch.py`.
2. Realistic headers plus cookies from your own session (`--header "Cookie: ..."`).
3. Your own browser through an interceptor (Burp, Caido, mitmproxy) or Chrome DevTools MCP. You are loading pages as a normal user and recording what loads.
4. Scripted browser (Playwright/Puppeteer) for repeatable collection.
5. TLS impersonation (`--impersonate chrome124 --confirm-program-allows-bypass`). **Only if the program explicitly allows working around bot protection.** Use one fixed, consistent fingerprint. Do not rotate fingerprints or solve challenges.

If a page is blocked and out of scope, stop. Never defeat protections on out-of-scope assets.

## Stage 3: Store

```
js-collect-output/<target>/
├── scope.txt, rate.txt
├── manifest.json        # run_contract + one entry per fetched file
├── cas/sha256/<hash>    # content-addressed bytes (dedupes identical bundles)
├── raw/                 # logical names pointing at CAS objects. Never edit.
├── inline/              # extracted inline scripts
├── historical/<date>/   # archived versions
├── sourcemaps/          # .map files and recovered sources
├── processed/           # beautified / unpacked / deobfuscated
├── flows_endpoints.txt  # URLs and paths extracted from JS (Stage 5)
└── summary.md           # collection summary (Stage 6)
```

- `scoped_fetch.py` writes `cas/`, `raw/`, and `manifest.json` for you. For files from other tools (archives, proxy exports), put the bytes through the same layout and add manifest entries by hand.
- Manifest fields per file: `url`, `sha256`, `logical_path`, `discovered_via`, `method_used`, `sourcemap_status`, `size_bytes`, `date_collected`.
- Re-run collection later and diff `sha256` values to find new or changed code.
- Keep a `processed/` to `raw/` mapping for every file you transform.

## Stage 4: Recover and un-obfuscate

Least effort first. Stop once the code is readable enough.

### 4a. Sourcemaps (always first)
- Look for `//# sourceMappingURL=` and try `<file>.js.map`. Fetch maps through `scoped_fetch.py` too.
- If the map has `sourcesContent`, extract it to `sourcemaps/` for original files and folder structure.
- If `sourcesContent` is missing, the map's `sources` paths still reveal the original tree; note it.
- Record per-file status: `found`, `missing`, `blocked` (the `.js` serves but the `.map` returns 403/404), `inline-only` (data URI), `empty`. "Blocked" is worth noting in the summary.

### 4b. Unminify and unpack
1. Unpack bundles into modules and unminify (`webcrack`; `wakaru` as a complement).
2. Beautify only (`js-beautify` or Prettier) when nothing else applies.
3. For string-array rotators, control-flow flattening, or encoded strings, use an AST-based deobfuscator, then re-beautify.
4. For stubborn cases, run only the string-decoder function in an isolated sandbox, never the whole bundle.

Write everything to `processed/` and keep the mapping to `raw/`.

## Stage 5: Light extraction

Extract URLs and paths from the processed tree with an AST-based extractor (for example `jsluice urls`), normalize and dedupe them into `flows_endpoints.txt`. This is the bridge to `js-analyse`. Secrets, API grouping, libraries, and sinks are handled downstream.

## Stage 6: Summary and handoff

Write `summary.md` with:
- Counts: files, inline scripts, historical versions
- Chunks discovered vs. retrieved
- Sourcemaps by status (`found` / `missing` / `blocked` / `inline-only` / `empty`)
- Files still obfuscated after Stage 4, with reasons
- Stages skipped and anything uncollectable, with the specific reason

Then hand the folder to **`js-sinks`** (sink and gadget mapping) and **`js-analyse`**.

## Guardrails

- Every target request goes through `scripts/scoped_fetch.py`. It refuses out-of-scope URLs, re-checks scope on each redirect, and enforces `rate.txt`.
- No writes to `raw/` other than through the fetcher; derived files go elsewhere.
- If a stage yields no new URLs or files, skip the rest of that stage instead of re-crawling. Record blocked stages and move on; don't retry in a loop.
- No bot-protection workarounds unless Stage 0 recorded explicit permission.
