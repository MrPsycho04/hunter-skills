---
name: fintech-graphql
description: "Hunt fintech-specific GraphQL vulnerabilities: money-movement mutations (transfers, redemptions, withdrawals, card top-ups), ledger/balance/portfolio query IDOR, decimal-precision and rounding abuse, idempotency-key bypass enabling double-spend, KYC/PII field-level authorization gaps, and admin-override mutations reachable via mass assignment. Distinct from graphql, which owns generic GraphQL discovery and IDOR/mutation methodology — this skill owns the delta introduced when a GraphQL layer sits in front of a ledger, wallet, payments, banking, brokerage, or lending backend, where a resolver bug moves real money instead of just leaking data. Use when hunting a fintech, banking, payments, wallet, neobank, brokerage, or lending target that exposes a GraphQL API, or when a schema/response includes balance, transfer, ledger, redeem, quote, KYC, or account-linking fields."
---

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters

## Why Fintech GraphQL Is a Different Risk Class

Generic GraphQL bugs (IDOR, mass assignment, introspection, batching abuse — see `graphql`)
still apply here, but the blast radius changes completely: a resolver bug in a SaaS app leaks
data, the same class of bug in a ledger mutation **moves money**. Three properties make fintech
GraphQL backends a distinct hunting surface:

- **Money-movement mutations are almost always resolvers over a double-entry ledger.** A single
  GraphQL mutation (`transferFunds`, `redeemRewards`, `withdrawToBank`) can trigger multiple
  ledger writes (debit + credit + fee) that must be atomic. GraphQL's flexible input shape and
  alias batching make it easy to desynchronize those writes.
- **Decimals are attacker-controlled input, not display formatting.** Amounts, exchange rates,
  interest, and rewards points are usually passed as GraphQL scalars (`Float`, `String`, custom
  `Decimal`/`Money` scalar). How the resolver parses and rounds that value is exploitable surface
  in its own right — this barely exists in non-financial GraphQL APIs.
- **KYC/PII fields sit next to routine account fields in the same type.** `User` or `Account`
  types commonly expose `ssnLast4`, `routingNumber`, `kycStatus`, `governmentIdUrl`, or
  `linkedBankAccount` alongside `displayName` and `email` — one missing field-level authorization
  check on a type used everywhere in the schema fans out to every query that touches it.

---

## Attack Surface Signals

**URL / schema naming patterns (in addition to `graphql`'s generic `/graphql` list):**
```
/graphql/ledger
/graphql/payments
/api/wallet/graphql
/internal/ledger-graphql
/banking/graphql
```

**Field/type names worth grepping schema introspection or JS bundles for:**
```
balance, availableBalance, pendingBalance, ledgerEntry, ledgerEntries
transferFunds, withdraw, redeem, topUp, reverseTransaction, adjustBalance
kycStatus, ssnLast4, routingNumber, accountNumber, governmentIdUrl
quoteExchangeRate, interestAccrued, rewardsPoints, portfolioValue
idempotencyKey, clientMutationId
```

**Tech-stack tells specific to this vertical:**
- Plaid/Stripe/Dwolla/Marqeta wrapped behind an internal GraphQL gateway (`bankLink`, `plaidLinkToken` mutations)
- Apollo Federation with a dedicated `ledger` or `payments` subgraph — check for the subgraph's own introspection being reachable directly, bypassing the gateway's stitched-down schema
- Custom `Money`/`Decimal`/`BigDecimal` GraphQL scalar in the schema (`scalar Money`) — the parser for this scalar is worth fuzzing directly

Run `graphql`'s discovery + introspection methodology first to get the schema; everything
below assumes you already have (or have partially enumerated) a schema with money-movement types.

---

## Step-by-Step Hunting Methodology

1. **Map every mutation that touches balance, whether directly or as a side effect.** Not just
   `transfer*`/`withdraw*` — also `redeemRewards`, `applyCoupon`, `upgradeTier`,
   `closeAccount` (often refunds a balance), `disputeTransaction` (often provisionally credits).

2. **For each money-movement mutation, identify the ledger write shape.** Does one mutation call
   produce one ledger entry or several (debit sender, credit receiver, fee entry)? Multi-entry
   writes are the ones worth racing — see Stage 4.

3. **Test idempotency-key handling.** Send the identical mutation (same `idempotencyKey` /
   `clientMutationId`) twice, back-to-back and with a delay. A ledger write on the second call
   means idempotency isn't enforced server-side — replay = double-execute.

4. **Test decimal/precision edge cases** on every amount-accepting argument — see Payload section.
   Confirm server-side rounding matches client-displayed rounding; a mismatch is directly
   monetizable.

5. **Probe cross-account IDOR on account/portfolio node IDs**, same as `idor`/`graphql`,
   but specifically test whether a `transferFunds`-style mutation validates that the
   **source account belongs to the authenticated caller** — not just that *some* account with
   that ID exists. This is the fintech-specific IDOR: authz on the *source* of a debit is easy to
   forget when authz on the *destination* of a credit was correctly implemented (crediting an
   arbitrary account "looks safe" to a developer; debiting one clearly isn't, so it gets checked
   — but sometimes only one direction does).

6. **Check field-level authorization on KYC/PII fields** by querying the shared `User`/`Account`
   type from every context that returns it — not just the profile screen. A `transaction` type
   that embeds `counterparty { ssnLast4 }` is a common place for the check to be missing, because
   the developer authorized the top-level `transaction` query but didn't re-check field access on
   the nested `counterparty`.

7. **Look for admin-tier mutations reachable via mass assignment**, not just a missing auth
   check — e.g. an input object with a client-settable `status` or `override` field that a normal
   user's mutation shouldn't expose but that the resolver accepts anyway
   (`updateTransaction(input: {id, status: "COMPLETED", amount: "..."})`).

8. **Test currency-argument consistency.** Send a transfer/quote mutation with mismatched
   `sourceCurrency`/`targetCurrency` combinations the UI never generates (e.g. self-transfer with
   a currency conversion) and check whether the resolver's FX-rate lookup and the ledger write use
   the same rate — a TOCTOU window here is a direct arbitrage bug.

9. **Combine alias batching with money-movement mutations** to test for double-spend — see
   `race-condition` for the parallel-HTTP escalation once alias batching alone confirms the
   resolver isn't serializing writes per-account.

---

## Common Root Causes

1. **Client-side amount/fee validation only.** The UI computes and displays the correct amount;
   the resolver trusts whatever the GraphQL client actually sends, because "the app always sends
   the right value."
2. **Non-atomic multi-entry ledger writes.** Debit, credit, and fee entries are written as
   separate sequential statements instead of inside a single transaction/lock — the race window
   this creates is exactly what alias batching + parallel HTTP exploits.
3. **`Money`/`Decimal` scalar falls back to native float parsing** under edge-case input
   (scientific notation, oversized strings), reintroducing floating-point rounding error into a
   system that was supposed to guarantee fixed-point precision.
4. **Idempotency keys are stored but never checked before executing the write** — the key is
   logged for support/debugging purposes, not used as a dedup gate.
5. **Field-level authorization implemented per top-level query, not per type.** A `User`/`Account`
   type's sensitive fields are protected when queried directly (`me { ssnLast4 }`) but not when
   the same type is returned nested inside an unrelated query (`transaction { counterparty {...} }`).
6. **Source-account ownership check missing while destination-account existence check is
   present** — see methodology step 5. Debiting looks dangerous so it gets reviewed; the "does
   this account belong to the caller" check quietly only gets applied to the credited side.
7. **Admin/internal mutations reuse the same input type as the public mutation**, just with extra
   optional fields — nothing at the resolver layer strips those fields for non-admin callers.

---

## Gate 0 Validation

Money-movement findings need a stricter bar than a typical GraphQL IDOR — "the query returns
someone else's balance" is real impact; "I sent a malformed amount and got a 400" is not.

1. **Did an actual ledger write occur, and can you show it?** Query the account balance before
   and after — a state change (not just a `200`/success response body) is the proof.
2. **Is the win deterministic, not a timing fluke?** For race/double-spend findings, reproduce
   twice from a clean state. If it only works under specific load conditions, document the window
   honestly rather than claiming guaranteed exploitability.
3. **Does the finding move value the attacker didn't have, or reveal data they shouldn't see** —
   not just "the mutation accepted an unexpected input type and the API returned an error
   message." A verbose GraphQL error leaking a stack trace on a malformed `Money` scalar is a
   `info-disclosure`-class finding, not a fintech-logic one — don't conflate the two in a report.

---

## Related Skills & Chains

- **`graphql`** — parent skill for generic GraphQL discovery, introspection bypass, node-ID
  IDOR, and alias-batching mechanics. Load this skill first; `fintech-graphql` assumes that
  methodology and only adds the money-movement-specific delta.
- **`logic-and-design`** — coupon/reward double-redemption and other logic-flaw patterns
  generalize directly to `redeemRewards`/`applyCoupon`-style mutations here.
- **`race-condition`** — the escalation path once alias batching alone confirms a
  money-movement mutation doesn't serialize writes: combine with parallel-HTTP / single-packet
  attack for a deterministic double-spend PoC.
- **`api-misconfig`** — mass assignment and JWT-claim tampering patterns apply directly to
  admin-shaped GraphQL input objects reachable by normal users.
- **`idor`** — the source-account-vs-destination-account asymmetric authz pattern (step 5) is
  a fintech-specific instance of the general IDOR-on-mutation-argument class.
- **`evidence-hygiene`** — balance screenshots and ledger-entry PoCs need the same cookie/PII
  redaction discipline as any other capture, plus care that a real account number/balance from a
  live financial account is never included verbatim.
- **`triage-validation`** — apply Gate 0 above before drafting; a fintech program's triage team
  will kill anything without a demonstrated ledger state change immediately.

---

## Web-Research Methodology Additions (2026)

> Fresh-source pass: PortSwigger Web Security Academy GraphQL topic, GitLab CVE-2026-19478 / CVE-2026-19650 (August 2026), Shopify idempotency engineering/community reports, and 2026 GraphQL security tooling writeups. Extends the existing methodology — it does not replace Gate 0.

### A. Discovery checklist — concrete surfaces, inputs, configs to look for

1. **Confirm the endpoint before schema work.** Send the universal query `query{__typename}` to candidate paths; a GraphQL service includes `{"data":{"__typename":"query"}}` in its response. Common paths: `/graphql`, `/api`, `/api/graphql`, `/graphql/api`, `/graphql/graphql`, plus a `/v1` suffix variant. Then retry the probe as GET and as `POST` with `x-www-form-urlencoded` — method/content-type flexibility is the CSRF and introspection-bypass primitive.
2. **Introspection probe and bypasses.** Probe with `{"query":"{__schema{queryType{name}}}"}`. If a regex blocks `__schema{`, insert whitespace/newline/comma (ignored by GraphQL, not by naive regex):
   ```
   {"query":"query{__schema\n{queryType{name}}}"}
   GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
   ```
   For a full introspection query, delete the `onOperation`, `onFragment`, and `onField` directives if it fails. If introspection is fully disabled, use Apollo **suggestions** ("Did you mean 'productInformation'?") and Clairvoyance to reconstruct the schema; Apollo Server v4+ can disable this with `hideSchemaDetailsFromClientErrors`.
3. **GitLab CVE-2026-19650 / CVE-2026-19478 pattern (patched 2026-08-17).** Two GraphQL issues from one directive family:
   - **CVE-2026-19650 (CVSS 7.1, CWE-352)** — multiplex query handling stored the pre-filter document in shared tracer state; each query in a batch overwrote the previous one, so the document a query was *validated* as differed from the one it *executed* as. A batch with a benign read first and a mutation marked `@gl_introduced` second passed the GET "read-only" check and executed the mutation → mutations over GET = CSRF. `@contain_future_fields` had the same cross-query flag leak.
   - **CVE-2026-19478 (CVSS 9.4, CWE-94)** — `@gl_introduced(version:"99.0")` on an arbitrary field name caused a synthesized resolver-less field; graphql-ruby resolved it by calling the method of that name on the underlying object → unauthenticated read-only query reaching state-changing model methods.
   Hunt for: custom `@` directives, version/feature-flag directives, per-batch shared state, and field names being interpreted as code/method names.
4. **Idempotency surface inventory.** Shopify's payment service puts `idempotencyKey` in mutation input (`ChargeCreate`, `clientBuyerId`, `clientTransactionId`), but its `storeCreditAccountCredit` mutation has drawn 2025 community reports of no API-level idempotency → duplicate credits/debits from retries, Flow retries, timeouts, and connection resets. Map every mutation that changes a balance and check whether a dedup key exists *and is enforced*.
5. **Field-level authz ≠ object-level authz.** Walk the graph field-by-field under at least two authenticated roles and diff what each can read on the *same query*. Nested fields are the weak point: `transaction { counterparty { ssnLast4 } }` can lack the check that `me { ssnLast4 }` has.
6. **Federation/tech tells.** Apollo Federation with a dedicated `ledger` or `payments` subgraph — probe the subgraph's own introspection/endpoint directly, bypassing the gateway's stitched-down schema. Look for custom `scalar Money` / `Decimal` / `BigDecimal` and fuzz that scalar parser.
7. **Classic GraphQL recon still applies:** IDOR via arguments (query a delisted `product(id:3)`), pagination DoS (`first:10000`), excessive errors, introspection leakage.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

1. **Alias batching to bypass per-request rate limiting.** One HTTP request, N operations — the limiter sees one request. PortSwigger's canonical brute-force shape:
   ```
   mutation {
     bruteforce0:login(input:{password:"123456",username:"carlos"}){token success}
     bruteforce1:login(input:{password:"password",username:"carlos"}){token success}
     ...
     bruteforce99:login(input:{password:"12345678",username:"carlos"}){token success}
   }
   ```
   Re-target this at OTP/redeem/withdraw mutations: a rate limiter counting HTTP requests instead of operations is a direct double-spend/OTP-brute primitive.
2. **Multiplex/directive state confusion.** Send a batch where one query carries `@gl_introduced` or a future field and another is a benign read, then observe whether the mutation executes. Test whether a flag set by one query switches behavior for all queries in the batch. This is the generalizable lesson from CVE-2026-19650.
3. **Mutations over GET / content-type confusion.** If the endpoint accepts GET or `x-www-form-urlencoded` and does not validate content type or enforce CSRF tokens, build a cross-site form that submits a money-movement mutation. `application/json` POST with validated content type is the safe configuration — find deployments that aren't.
4. **Idempotency replay.** Send the identical mutation with the same `idempotencyKey`/`clientMutationId` twice — back-to-back and with a delay. Then reuse the key across sessions/accounts. A second ledger write or a key accepted for a different principal means idempotency is logged but not used as a dedup gate.
5. **Asymmetric source/destination authz.** Test that `transferFunds` validates the *source* account belongs to the caller, not merely that an account with that ID exists. Crediting an arbitrary account "looks safe" and is often checked; debiting one is where the missing ownership check hides.
6. **Decimal/precision fuzzing on custom scalars.** Scientific notation, oversized numeric strings, `0.001` rounding, negative amounts, and currency mismatch (`sourceCurrency`/`targetCurrency` self-transfer with conversion). Compare server-side rounding to client-displayed rounding — a mismatch is monetizable.
7. **Suggestion-based schema recovery** when introspection is disabled; feed recovered type names into field-level authz tests.

### C. Validation / proof bar — how to confirm and avoid false positives (confabulation is NOT a finding for AI classes)

1. **Gate 0 still governs (existing).** Show an actual ledger write — balance before/after, transaction/ledger-entry IDs. A `200` or a success body is not proof.
2. **CSRF-over-GET needs a real state change in a victim browser.** Induce a logged-in victim's browser to issue the forged mutation and show the resulting debit/credit. A mutation that merely returns `200` but writes nothing is not CSRF.
3. **Rate-limit bypass proof.** Compare behavior at 2 vs. 100 aliases in a single request, showing the limiter counts requests not operations. For money endpoints, show the additional operation actually executed (extra ledger entries), not just extra error messages.
4. **Idempotency proof.** Show a second distinct ledger entry / transaction ID created by the replay — duplicate HTTP responses alone are not a double-execute.
5. **Field-level authz proof.** Show a verifiable B-account PII value (order ID, email, ticket number) returned nested under A's session, with a same-account control for comparison.
6. **Do not conflate classes.** A verbose GraphQL error leaking a stack trace on a malformed `Money` scalar is an `info-disclosure` finding, not a fintech-logic finding (Gate 0 item 3). Score separately.
7. **Determinism for race/double-spend.** Reproduce twice from a clean state. If it needs specific load conditions, document the window honestly rather than claiming guaranteed exploitation.
8. **No confabulation analogue here, but avoid "schema-theatre" reports** — a field existing in introspection or being accepted as input is not impact. Show the resolver performing a harmful action or returning protected data.

### D. Sources — numbered list of URLs you actually fetched

1. https://www.ox.security/blog/gitlab-graphql-cve-2026-19478-19650/ (CVE-2026-19478 CWE-94 code injection via `@gl_introduced`, CVE-2026-19650 CWE-352 multiplex mutation-over-GET; webfetched)
2. https://portswigger.net/web-security/graphql (endpoint discovery, universal query, introspection bypass, alias-based rate-limit bypass, GraphQL CSRF, prevention; webfetched)
3. https://shopify.engineering/building-resilient-graphql-apis-using-idempotency (`ChargeCreate` with `idempotencyKey`; double-charge failure modes)
4. https://community.shopify.dev/t/idempotency-key-for-store-credit-update-apis/17501 (2025-2026 reports of duplicate store-credit credit/debit without idempotency)
5. https://escape.tech/blog/best-graphql-security-tools/ (field-level authz via multi-role diffing, batching/rate-limit abuse in 2026)
6. https://wundergraph.com/blog/the_complete_graphql_security_guide_fixing_the_13_most_common_graphql_vulnerabilities_to_make_your_api_production_ready (13 GraphQL vulnerability classes, CSRF/introspection/excessive errors)
