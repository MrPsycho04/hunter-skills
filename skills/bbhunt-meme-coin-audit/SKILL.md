---
name: bbhunt-meme-coin-audit
description: "Detect honeypots, hidden mint authority, fee manipulation and LP-lock bypass. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Token and meme-coin audit — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Web-Research Methodology Additions (2026)

> Fresh-source pass: arXiv:2608.20271 (Aug 2026, 6.4M Solana memecoins), Solidus Labs pump.fun research, 2026 token-scanner/honeypot tooling, and the first rug-pull criminal prosecution under South Korea's Virtual Asset User Protection Act. Extends the existing 8 bug classes and fast-kill signals.

### A. Discovery checklist — concrete surfaces, inputs, configs to look for

1. **Use the new quantitative rug-prediction signals (arXiv 2608.20271, Aug 2026).** A dataset of **6.4M Solana memecoins over 7 months** (Nov 2024–Jun 2025; 6.3M PumpFun, 98k Raydium) found the vast majority exhibit rug characteristics **within one hour of launch**, and that XGBoost using only the **first 5 minutes** of trading predicts 1-hour rug outcomes (MCC ~0.39 on fused data, AUCPRC >0.8 in some settings). Feature families worth harvesting from chain data:
   - `count_tx`, `purchase_percentage`, `sale_percentage`, `unique_buyers`, `unique_sellers`
   - `buy_sell_cnt_ratio`, `buy_sell_value_ratio`, `total_sol_value`, `sell_sol_value`
   - `price_change_first_to_3_blocks`, `price_change_first_to_last`, `buy_price_std`, `sell_price_std`
   - `first_buy_time`, `first_sell_time`, `last_trade_time`, `max_price`, `min_price_after_max`
   - Creator/bundle attributes: `dev_balance`, `bundle_size`, `bundled_buys`, `creator`
   PumpFun trades are "many pools, small trades"; Raydium is "few pools, large trades" — models don't transfer between them without multi-source fusion. Treat scores as triage signals, never as proof.
2. **Two formal rug labels to use consistently** (same paper): **TVL rug** — max drawdown of total value locked below a threshold (paper uses a ~99% drop), and **Idle rug** — no trading for >80% of the token's lifetime. `Rug_t = I(MDD_t < -θ OR Idle_t > Δt)`. A token hitting either is high-risk.
3. **Base-rate reality check.** Solidus Labs scanned every pump.fun token over 14 months: 

### Signals and surfaces

### PRE-DIVE KILL SIGNALS

Check these BEFORE reading a single line of code. If any are true, skip the audit — the token is likely a rug or not worth the time.

### Solana-specific signals — 2025-2026 reality

Token-2022 transfer hooks are the new rug-pull vector. Hook authority can be set to a single key; that key can pause / blacklist / fee-on-transfer arbitrary addresses post-launch. Always check hook authority + permanent-delegate authority for Token-2022 mints:

```bash
# get mint extensions for a Token-2022 mint
spl-token display <MINT_ADDRESS> --program-id TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb
# look for: TransferHook { authority: ... }, PermanentDelegate { delegate: ... }
```

If TransferHook authority is non-null → the holder of that key can revoke transfer rights mid-trade. If PermanentDelegate is non-null → that delegate can move any holder's tokens at any time (effectively a built-in confiscation). Either alone is rug-class.

pump.fun bonding curves can be manipulated via the curve's K-parameter; mint authority retained beyond bonding-curve completion is the classic exit-scam shape. Check `mintAuthority` AFTER the curve completes — legitimate launches null it, scams retain it for the post-graduation dump.

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

1. **Five-minute on-chain pre-buy filter (BloFin 2026):** (1) mint authority revoked? (2) freeze authority revoked? (3) LP burned or locked >6 months in a verified contract? (4) top-10 holders <30% excluding pools/burn addresses? (5) is the volume real (not wash trades)? Any failed → automatic skip.
2. **Token-2022 extension check from the 12-point on-chain checklist.** Transfer fees, transfer hooks, permanent delegates on a meme token with no legitimate reason are structural red flags:
   ```
   spl-token display <MINT_ADDRESS> --program-id TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb
   # look for TransferHook { authority }, PermanentDelegate { delegate }, transfer fees
   ```
3. **Sell-simulation triage (extends existing matrix).** Simulate: buy from random wallet → transfer to a second random wallet → sell from original wallet → sell from a team-controlled wallet. Buy + transfer succeed but sell fails/reverts/>50% tax while team sell works = honeypot. Cross-check with RugCheck, Honeypot.is, GoPlus — never one source.
4. **Deferred-malice probe.** A clean scan today is not enough: check whether the owner can still raise sell tax to 100%, re-enable a transfer hook, mint, or blacklist. Inspect setter bounds (`require(fee <= MAX_FEE)` with `MAX_FEE <= 10%` is the kill condition) and whether ownership was truly renounced (not overridden).
5. **LP-lock verification, not badge trust.** Read the lock contract on-chain: unlock timestamp, lock owner (deployer?), multiple fragmented lockers, and **shorten

### Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives (confabulation is NOT a finding for AI classes)

1. **Distinguish "deployer COULD rug" from "contract IS exploitable now."** Most structural rug vectors are pre-rug warnings, not reportable bugs — route them through `triage-validation`. A bug bounty finding needs a currently exploitable path with a reproducible PoC.
2. **For due-diligence audits, require on-chain proof, not scanner output:** authority fields null on-chain at a specific slot, LP burn transaction hash, holder distribution at a pinned block, lock contract source verified. A badge/screenshot is not evidence.
3. **An ML risk score is NOT a finding** — it is a triage prior. Confabulation-style false positives here include "the model says 98% rug risk." Always confirm with the structural checks above. The arXiv authors themselves call their results a baseline not ready for deployment (false negatives carry real losses).
4. **Never trust a single rug-checker.** Deferred-malice tokens are clean for the first days and activate hooks later; cross-source verification plus owner-privilege code review is mandatory.
5. **Honeypot proof needs the exact revert/tax and function.** Show the failing `transfer`/`sell` call with calldata and the exempt-address path that succeeds — "the scanner said honeypot" is not proof.
6. **Report reproducibility.** Include exact mint/contract address, block/slot, tool commands, and the specific function/authority. A finding without an address is unverifiable.
7. **Confabulation guard (AI-class analogue).** If an AI-assi

### Escalation and related chains

### Related Skills & Chains

- **`web3-audit`** — When the target is a DeFi protocol (not just a token). Workflow primitive: this skill's 8 token-specific bug classes are a subset of `web3-audit`'s scope; if the target has lending / vault / oracle logic beyond the token contract itself, also load `web3-audit` for the broader 10 DeFi bug classes.
- **`triage-validation`** — When deciding if a rug-pull finding qualifies as a bug bounty submission. Workflow primitive: many "rug vector" observations are pre-rug warnings, not exploitable bugs in a deployed protocol; run 7Q gate to distinguish "the deployer COULD rug" (informational) from "the contract IS exploitable now" (reportable).
- **`report-writing`** — When writing up a confirmed token security finding for Immunefi / private bounty. Workflow primitive: Foundry PoC template here feeds into `report-writing`'s Immunefi body template.
- **`offensive-osint`** — When the token has off-chain infrastructure (project website, Telegram, deployer doxxing). Workflow primitive: on-chain audit is this skill's domain; deployer wallet history, social presence, and project legitimacy checks route to `offensive-osint`.
- **`bb-methodology`** — When confirming engagement mode. Workflow primitive: PART 0 separates "pre-investment due diligence" (this skill's primary use) from "Immunefi bug bounty submission" (different reporting + severity standards); the answer routes which post-audit handoff is correct.

---

## Source skills merged into this topic

- `hunting` — `meme-coin-audit`
- `cbh` — `meme-coin-audit`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
