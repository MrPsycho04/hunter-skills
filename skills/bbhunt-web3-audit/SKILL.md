---
name: bbhunt-web3-audit
description: "Audit DeFi accounting, access control, oracles, reentrancy, flash loans and proxy patterns with Foundry PoCs. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Smart-contract security audit — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Web-Research Methodology Additions (2026)

> Fresh-source pass: Immunefi's 6-Year DeFi Loss Scoreboard (Apr 2026), the DefiLlama hack database (2025–2026 incidents), OWASP Smart Contract Top 10 SC08:2026, and EIP-7702/EIP-1153 developments. This layer EXTENDS the 10 classes above with where the money actually moved in 2025-2026.

### A. Discovery checklist — concrete surfaces, inputs, configs to look for

1. **Reweight your effort using the 6-year data (Immunefi, 2026-04-27).** Total DeFi protocol losses fell ~80% from the 2022 peak ($2.62B) to $534M in 2024; 2025 rebounded to $680M but almost entirely from a handful of large incidents. Median loss per incident fell from $6M (2022) to $1.5M (2025). Crucially: **ecosystem-class attacks (flash-loan oracle manipulation, reentrancy) collapsed from ~19% of losses in 2022 to under 1% in 2025**; bridges fell 73%→3%; infrastructure failures 30.7%→10.3%. **89% of 2025 DeFi losses were protocol-logic exploits** — unique, application-specific flaws. Practical consequence: spend your time on bespoke logic and state-management bugs, not another generic flash-loan-oracle hunt.
2. **Know where the big money moved instead.** Cross-chain messaging and custodial ops: KelpDAO April 2026 — **$292M** through a single-verifier LayerZero bridge configuration (47% of LayerZero apps used the same minimal verifier setup), with up to $230M bad debt on Aave and $13B TVL withdrawals in 48h. Bybit February 2025 — **$1.5B** multisig phishing. Exchanges took >$1.6B infrastructure-class losses in 2025. Drift Protocol (Solana, 2026) — $285M via a six-month North Korean social-engineering operation combining governance manipulation with oracle abuse. Audit verifier counts, peer validation, amount reconciliation, and governance/multisig operational procedures, not just Solidity.
3. **Treat multi-chain deployment as its own risk class.** Balancer V2's **$128M** exploit (Nov 2025) hit E

### Signals and surfaces

### PRE-DIVE KILL SIGNALS (check BEFORE any code review)

> ZKsync lesson: $322M TVL + OZ audit + 750K LOC + 5 sessions = 0 findings. Large well-audited bridges are extremely hard.

1. **TVL < $500K** → max payout capped too low for effort
2. **2+ top-tier audits** (Halborn, ToB, Cyfrin, OpenZeppelin) on simple protocol → bugs already found
3. **Protocol < 500 lines, single A→B→C flow** → minimal attack surface
4. **Formula**: `max_realistic_payout = min(10% × TVL, program_cap)` — if < $10K, skip

**Soft kill:** OZ/ToB/Cyfrin audit on current version + codebase > 500K LOC → expect 40+ hours for maybe 1 finding. Only proceed if bounty floor > $50K AND you have protocol-specific expertise.

**Target scoring (go if >= 6/10):**
- TVL > $10M: +2
- Immunefi program with Critical >= $50K: +2
- No top-tier audit on current version: +2
- < 30 days since deploy: +1
- Protocol you've hunted before: +1
- Source code + natspec comments: +1
- Upgradeable proxies: +1

---

### Where pre-dive kill signals matter

TVL under $500K isn't worth the audit time unless the bounty floor is high. Audit firm already covered it = low ROI unless you find what they missed — look at the audit-report scope-exclusion section for what they EXPLICITLY didn't audit (oracles, governance, off-chain components, frontend, the admin path).

Multisig signers > 5 + timelock > 48h = low rug-pull risk; if your finding requires team-malicious assumptions, it's low-impact and likely out of scope per Immunefi's "centralization risk" exclusion. Read the program brief — most Immunefi programs explicitly downgrade or reject findings that assume admin malice.

### Techniques, payloads and bypasses

### Root Cause Patterns

**Variant 1: Phantom Yield** (Yeet protocol — 35 duplicate reports)
```solidity
function startUnstake(uint256 amount) external {
    totalSupply -= amount;  // decremented BEFORE transfer
    // aToken.balanceOf(this) still reflects old value
    // yieldAmount = aToken.balanceOf - totalSupply = phantom yield
}
```

**Variant 2: Fast Path Skips State Update** (Alchemix V3)
```solidity
function claimRedemption(uint256 tokenId) external {
    if (transmuter.balance >= amount) {
        transmuter.transfer(user, amount);
        _burn(tokenId);
        return;  // EARLY RETURN — cumulativeEarmarked, _redemptionWeight, totalDebt never updated
    }
    // Slow path: updates all state vars correctly
    alchemist.redeem(...);
}
```

**Variant 3: Update Happens in Wrong Order** (Alchemix)
```solidity
function deposit(uint256 amount) external {
    _shares = (amount * totalShares) / totalAssets;  // calculated BEFORE deposit
    totalAssets += amount;   // assets added AFTER shares calculated → wrong rate
}
```

### Variant 3: mint() Bypasses Check That deposit() Has (MetaPool)

```solidity
function deposit(uint256 assets, address receiver) public override {
    shares = _deposit(assets, receiver);  // includes receipt validation
}
function mint(uint256 shares, address receiver) public override {
    assets = convertToAssets(shares);
    _mint(receiver, shares);  // MISSING: _deposit() validation → mints without receiving assets
}
```

### Root Cause

```solidity
// VeChain Stargate — post-exit reward drain:
function _claimableDelegationPeriods(address delegator) internal view returns (uint256) {
    if (endPeriod > nextClaimablePeriod) {  // BUG: should be >=
        return 0;  // exited users get nothing
    }
    return nextClaimablePeriod - lastClaimedPeriod;  // rewards for period AFTER exit
}
```

### Root Cause Pattern

```solidity
// VULNERABLE (effects after interaction):
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success,) = msg.sender.call{value: amount}("");  // INTERACTION first
    require(success);
    balances[msg.sender] -= amount;  // EFFECT after → reentrancy window
}

// CORRECT (CEI — Checks, Effects, Interactions):
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);  // CHECK
    balances[msg.sender] -= amount;            // EFFECT
    (bool success,) = msg.sender.call{value: amount}("");  // INTERACTION last
    require(success);
}
```

### B. Techniques & bypasses — specific actionable techniques/payload shapes

1. **Donation-attack harness (first-depositor / exchange-rate).** On a fork: deposit 1 wei to get 1 share, `transfer` (not `deposit`) a large amount directly to the vault to inflate `convertToAssets()`, then have a victim deposit and observe shares rounding to 0. Check for virtual shares (`_decimalsOffset() = 9`, OpenZeppelin v4.9+). Applies to lending collateral valuation too — the Tectonic pattern.
2. **Rounding-drain test.** Call `batchSwap`/`withdraw` repeatedly with minimal amounts and assert cumulative reserve drift. Grep every `Math.mulDiv`, `*Div*`, and manual division for rounding direction — a round-*toward-user* in one path is the bug. Balancer/Bunni both died this way.
3. **Oracle failover-chain audit.** Don't stop at the primary Chainlink feed: check staleness/heartbeat, the fallback path, secondary TWAP source, confidence-interval checks (Pyth `p.conf`), and whether a low-liquidity pool price is accepted. Solido Cash and Bonzo show the secondary/fallback path is the target.
4. **Cross-chain dual-endpoint simulation.** Simulate BOTH endpoints and assert: peer/verifier configuration, signature validation, amount reconciliation across chains, replay protection, and withdrawal-deduplication. A payload passing all crypto checks can still be exploitable if amounts aren't reconciled (Verus).
5. **Read-only reentrancy probe.** During a callback in another protocol, call a view function (`getPrice`, `convertToAssets`, `balanceOf`-based valuation) and check whether it returns an inconsistent i

### Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives (confabulation is NOT a finding for AI classes)

1. **A single `forge test` invocation must prove impact** — explicit `assertEq` on drained balance / minted token / corrupted state. No manual "first deploy this, then call that" setup; those get downgraded. Immunefi auto-rejects submissions without a PoC.
2. **Severity must use the program's exact matrix**, gated on direct economic loss as a percentage of TVL. Don't invent severities; a Critical against a $500K protocol pays differently than one against a $500M protocol.
3. **Avoid admin-malice findings.** Most Immunefi programs explicitly downgrade or reject findings that assume a malicious admin/centralization risk. Show the bug is exploitable by an *unprivileged* actor now.
4. **Quantify economics.** Show net profit vs. capital and gas cost, and that the state change is deterministic from a clean fork state. Theoretical "could be exploited if X" without a runnable PoC is rejected.
5. **Confabulation analogue: don't claim an exploit from a revert-only observation or a scanner finding.** Reentrancy/donation patterns are only findings when the PoC actually drains value or corrupts state. (True confabulation is an AI-class concern; here the equivalent failure is an unproven theoretical finding.)
6. **Scope discipline.** Audit-report scope exclusions are where missed bugs live — check whether oracles, governance, off-chain components, frontend, or admin paths were explicitly NOT audited. Multisig >5 signers + timelock >48h = low rug risk, but that is not 

### Escalation and related chains

### Missing Chain ID

```solidity
// VULNERABLE: signature valid on mainnet AND testnet AND all forks
bytes32 hash = keccak256(abi.encodePacked(params));
// MISSING: block.chainid not in hash → works on any chain
```

### Related Skills & Chains

- **`meme-coin-audit`** — When the target is a meme coin / SPL token rather than a DeFi protocol. Workflow primitive: pre-dive kill signals diverge — this skill's "TVL < $500K skip" doesn't apply to meme coins where the rug check (mint authority, freeze authority, LP lock) is the entire audit; route to `meme-coin-audit` instead.
- **`triage-validation`** — When a contract finding is ready to be filed on Immunefi. Workflow primitive: Immunefi has its own report format, but the impact-validated, chain-end-to-end discipline of `triage-validation` still applies; run the 7Q gate against the Foundry PoC before submitting.
- **`report-writing`** — When writing the Immunefi report body. Workflow primitive: `report-writing`'s Immunefi template (with Foundry PoC, root cause code snippet, quantified economic impact) is the body skeleton this skill's findings feed into.
- **`offensive-osint`** — When auditing a protocol's off-chain attack surface (frontend, admin API, RPC gateways). Workflow primitive: on-chain audit is this skill's job; any web2 component of the protocol (web-frontend, admin panel, indexer API) routes to `offensive-osint` for recon.
- **`bb-methodology`** — When deciding whether to dive at all. Workflow primitive: PART 0 of `bb-methodology` confirms engagement (web3 bug bounty / private audit / smart-contract review); this skill's pre-dive kill signals replace the standard scoring rubric for that engagement type.

---

### Cross-skill routing for 2026 on-chain findings

- **Oracle manipulation via a web frontend or leaked API credential** → pair with `offensive-osint` for the off-chain leg; the on-chain PoC alone understates the chain.
- **Compromised deployer/admin key, multisig phishing, or social engineering** → `cloud-iam-deep` / `account-takeover` for the key-compromise path; note that Immunefi usually excludes centralization assumptions.
- **Rug-pull-shaped token rather than a protocol logic bug** → `meme-coin-audit`; this skill's "TVL < $500K skip" signal does not apply there.
- **Bridge/cross-chain message forgery** → keep here but simulate both endpoints; a single-chain PoC will be rejected as incomplete.

### Tools and wordlists

### Grep Patterns

```bash
# Find all accounting variables
grep -rn "totalSupply\|totalShares\|totalAssets\|totalDebt\|cumulativeReward\|rewardPerShare" contracts/

# Find all early returns in claim/redeem functions
grep -rn "\breturn\b" contracts/ -B3 | grep -B3 "if\b"

# For each early return: which state updates in normal path are skipped?
```

---

### Grep Patterns

```bash
# Find sibling function families — do ALL have the same modifier set?
grep -rn "function vote\|function poke\|function reset\|function update\|function claim\|function harvest" contracts/ -A2

# Ownership check: existence vs ownership?
grep -rn "_requireOwned\|ownerOf\|_isApprovedOrOwner\|_checkAuthorized" contracts/ -B5

# Silent modifiers
grep -rn "modifier\b" contracts/ -A8 | grep -B3 "if (" | grep -v "require\|revert"

# Uninitialized initializer
grep -rn "function initialize\b" contracts/ -A3
grep -rn "_disableInitializers()" contracts/
```

### Grep Patterns

```bash
grep -rn "function place_\|function create_\|function add_\|function open_" contracts/ -A5
grep -rn "function update_\|function modify_\|function cancel_" contracts/ -A5
grep -rn "safeApprove\b" contracts/    # safeApprove without zero-reset before
grep -rn "delete\b" contracts/ -B5 -A5  # delete before operation completes
grep -rn "function deposit\|function mint\|function withdraw\|function redeem" contracts/ -A10
```

---

### Grep Patterns

```bash
# Boundaries in comparisons
grep -rn "Period\|Epoch\|Round\|Deadline\|period\|epoch\|deadline" contracts/ -A3 | grep "[<>][^=]"

# Loop breaks
grep -rn "\bbreak\b" contracts/ -B10

# Off-by-one in array access
grep -rn "\.length\s*-\s*1\|i\s*<=\s*.*\.length\b" contracts/
```

---

### Grep Patterns

```bash
# Missing staleness check
grep -rn "latestRoundData" contracts/ -A5 | grep -v "updatedAt\|timestamp"

# Pyth price usage — confidence interval checked?
grep -rn "getPriceUnsafe\|getPrice\b" contracts/ -A8 | grep -v "conf\|confidence"

# TWAP windows — short TWAP flag
grep -rn "secondsAgo\|TWAP\|cardinality" contracts/ -A5
```

---

### Grep Patterns

```bash
grep -rn "function transfer\|function transferFrom" contracts/ -A15
grep -rn "function deposit\|function mint\|function withdraw\|function redeem" contracts/ -A10
```

---

_...and 4 more sections in `references/unified-method.md`._

## Source skills merged into this topic

- `hunting` — `web3-audit`
- `cbh` — `web3-audit`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
