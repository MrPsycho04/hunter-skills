# JavaScript Collection — HackerOne field guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Ordered by yield — do these first.



1. **Seed from the live HTML.** Fetch every in-scope URL and extract `src=` from `<script>` tags. Modern apps hide 80%+ of their code in hashed bundles you can only discover from the page that loads them.

2. **Enumerate subdomains first.** JS often lives on `assets.`, `static.`, `cdn.`, `s3.`, `*.cloudfront.net`, `*.azureedge.net`, or a separate `*.dev`/`*.staging` host. Subdomains you miss are JS you never collect.

3. **Query historical URLs** (Wayback/Common Crawl via `gau`, `waybackurls`) and filter for `.js`, `.js.map`, `.mjs`, `.json` config files. Old, forgotten bundles are gold: they often still contain the secrets the current build removed.

4. **Crawl with JS rendering** (`katana -jc`, `gospider`) — client-side routers (React/Vue/Angular/Next) only emit script URLs after JavaScript executes.

5. **Hunt source maps.** A public `.js.map` turns minified spaghetti into original TypeScript with comments, `process.env` references, and internal filenames. Report #638635 (Trint, ▲102) was found this way.

6. **Check the asset host's directory and path patterns** — `/assets/webpack/`, `/static/js/`, `/_next/static/chunks/`, `/packs/js/`. Next.js/Nuxt/Webpack apps leak their whole build manifest.

7. **Collect with status/size metadata**, not just URLs. A `200` that returns an HTML error page is not a JS file; dedupe by content hash.



## Techniques from real reports



| Report | Program | Bounty | Lesson for collection |

|---|---|---:|---|

| [#638635](https://hackerone.com/reports/638635) | Trint Ltd | — (▲102) | Source maps sat **next to** minified files at `/static/js/app.<hash>.js.map`; always request the `.map` sibling. |

| [#1481207](https://hackerone.com/reports/1481207) | GitLab | — (▲161) | Failed asset loads revealed exact webpack chunk names (`/assets/webpack/top_nav.<hash>.chunk.js`) via DevTools after a `<base>` injection — a reminder to record chunk paths from the browser, not only from HTML. |

| [#1717210](https://hackerone.com/reports/1717210) | Semrush | — (▲56) | Build-time env vars were baked into a webpack bundle — collect **build artifacts**, not just API responses. |

| [#1160407](https://hackerone.com/reports/1160407) | GitLab | — (▲83) | `assets.gitlab-static.net` cache poisoning — asset hosts are in scope when they serve the app's JS. |

| [#90367](https://hackerone.com/reports/90367) | HackerOne | — | Public uncompiled CSS + source maps; "dev artifacts on prod" is a recurring, low-effort find. |

| [#1444682](https://hackerone.com/reports/1444682) | Shopify | $9,400 | XSS on a `*.shopifycloud.com` asset host — never stop at the main domain. |

| [#3085742](https://hackerone.com/reports/3085742) | Bykea | — (▲128) | "Hardcoded zombie endpoint" found in-app — old JS can expose forgotten APIs. |
