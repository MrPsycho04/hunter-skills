---
name: bbhunt-fintech-graphql
description: "Hunt money-movement mutations, balance IDOR, decimal-precision abuse and idempotency-key bypass. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Fintech GraphQL-specific hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Step-by-Step Hunting Methodology

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
   — but sometimes 

### Web-Research Methodology Additions (2026)

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
   - **CVE-2026-19650 (CVSS 7.1, CWE-352)** — multiplex query handling stored the pre-filter document in shared tracer state; each query in a batch overwrote the previous one, so the document a query was *validated* as differed from the one it *executed* as. A batch with 

### Step-by-Step Hunting Methodology

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

5. **Probe cross-account IDOR on account/portfolio node IDs**, same as `hunt-idor`/`hunt-graphql`,
   but specifically test whether a `transferFunds`-style mutation validates that the
   **source account belongs to the authenticated caller** — not just that *some* account with
   that ID exists. This is the fintech-specific IDOR: authz on the *source* of a debit is easy to
   forget when authz on the *destination* of a credit was correctly implemented (crediting an
   arbitrary account "looks safe" to a developer; debiting one clearly isn't, so it gets checked
   — but 

### Signals and surfaces

### Attack Surface Signals

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

### Attack Surface Signals

**URL / schema naming patterns (in addition to `hunt-graphql`'s generic `/graphql` list):**
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

Run `hunt-graphql`'s discovery + introspection methodology first to get the schema; everything
below assumes you already have (or have partially enumerated) a schema with money-movement types.

---

### Techniques, payloads and bypasses

### Common Root Causes

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
   optional fields — 

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
4. **Idempotency replay.** Send the identical mutation with the same `idempotencyKey`/`clientMutationId` twice — back-to-back and with a delay. Then reuse the key across sessions/accounts. A second ledger write or a key accepted for a

### Payload & Detection Patterns

**Idempotency-key replay test:**
```graphql
mutation {
  transferFunds(input: {
    idempotencyKey: "test-key-001"
    sourceAccountId: "acc_1"
    destAccountId: "acc_2"
    amount: "10.00"
  }) { transactionId status }
}
```
Send twice with the identical `idempotencyKey`. Two successful, distinct `transactionId` values
= idempotency not enforced.

**Decimal-precision / rounding probes:**
```graphql
mutation { transferFunds(input: {sourceAccountId:"acc_1", destAccountId:"acc_2", amount: "0.001"}) { transactionId } }
mutation { transferFunds(input: {sourceAccountId:"acc_1", destAccountId:"acc_2", amount: "9999999999999999.99"}) { transactionId } }
mutation { transferFunds(input: {sourceAccountId:"acc_1", destAccountId:"acc_2", amount: "1e2"}) { transactionId } }
mutation { transferFunds(input: {sourceAccountId:"acc_1", destAccountId:"acc_2", amount: "-50.00"}) { transactionId } }
```
Sub-cent amounts test truncate-vs-round handling (repeat N times to accumulate a rounding-error
balance drift); scientific notation and oversized values test whether the `Money`/`Decimal`
scalar parser falls back to a native float/int with overflow or precision-loss behavior; negative
amounts test whether the resolver assumes sign server-side or trusts the client's.

**Alias-batched double-spend probe (confirm before escalating to parallel HTTP):**
```graphql
mutation {
  r1: redeemRewards(input: {rewardId: "rwd_1", accountId: "acc_1"}) { success }
  r2: redeemRewards(input: {rewardId: "rwd_1", accountId: "acc_1"}) { success }
  r3: redeemRewards(input: {reward

### Validation and proof

### Gate 0 Validation

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

### C. Validation / proof bar — how to confirm and avoid false positives (confabulation is NOT a finding for AI classes)

1. **Gate 0 still governs (existing).** Show an actual ledger write — balance before/after, transaction/ledger-entry IDs. A `200` or a success body is not proof.
2. **CSRF-over-GET needs a real state change in a victim browser.** Induce a logged-in victim's browser to issue the forged mutation and show the resulting debit/credit. A mutation that merely returns `200` but writes nothing is not CSRF.
3. **Rate-limit bypass proof.** Compare behavior at 2 vs. 100 aliases in a single request, showing the limiter counts requests not operations. For money endpoints, show the additional operation actually executed (extra ledger entries), not just extra error messages.
4. **Idempotency proof.** Show a second distinct ledger entry / transaction ID created by the replay — duplicate HTTP responses alone are not a double-execute.
5. **Field-level authz proof.** Show a verifiable B-account PII value (order ID, email, ticket number) returned nested under A's session, with a same-account control for comparison.
6. **Do not conflate classes.** A verbose GraphQL error leaking a stack trace on a malformed `Money` scalar is an `info-disclosure` finding, not a fintech-logic finding (Gate 0 item 3). Score separately.
7. **Determinism for race/double-spend.** Reproduce twice from a clean state. If it needs specific load conditions, document the window honestly rather than claiming guaranteed exploitation.
8. **No confabulation analogue here, but avoid "schema-theatre" reports**

### Gate 0 Validation

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
   `hunt-source-leak`-class finding, not a fintech-logic one — don't conflate the two in a report.

---

### Escalation and related chains

### Related Skills & Chains

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

### Related Skills & Chains

- **`hunt-graphql`** — parent skill for generic GraphQL discovery, introspection bypass, node-ID
  IDOR, and alias-batching mechanics. Load this skill first; `hunt-fintech-graphql` assumes that
  methodology and only adds the money-movement-specific delta.
- **`hunt-business-logic`** — coupon/reward double-redemption and other logic-flaw patterns
  generalize directly to `redeemRewards`/`applyCoupon`-style mutations here.
- **`hunt-race-condition`** — the escalation path once alias batching alone confirms a
  money-movement mutation doesn't serialize writes: combine with parallel-HTTP / single-packet
  attack for a deterministic double-spend PoC.
- **`hunt-api-misconfig`** — mass assignment and JWT-claim tampering patterns apply directly to
  admin-shaped GraphQL input objects reachable by normal users.
- **`hunt-idor`** — the source-account-vs-destination-account asymmetric authz pattern (step 5) is
  a fintech-specific instance of the general IDOR-on-mutation-argument class.
- **`evidence-hygiene`** — balance screenshots and ledger-entry PoCs need the same cookie/PII
  redaction discipline as any other capture, plus care that a real account number/balance from a
  live financial account is never included verbatim.
- **`triage-validation`** — apply Gate 0 above before drafting; a fintech program's triage team
  will kill anything without a demonstrated ledger state change immediately.

## Source skills merged into this topic

- `hunting` — `fintech-graphql`
- `cbh` — `hunt-fintech-graphql`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 1 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 1 merged companion methodology documents
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
