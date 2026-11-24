---
name: bbhunt-meme-coin-audit
description: "Detect honeypots, hidden mint authority, fee manipulation and LP-lock bypass. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Token and meme-coin audit — unified skill

> **Complete merged skill.** Everything from 2 upstream skills across cbh, hunting is contained in this file. Unmodified originals remain in `references/` for provenance only.

## Unified upstream methodology (complete, deduplicated)

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
3. **Base-rate reality check.** Solidus Labs scanned every pump.fun token over 14 months: **98.6% collapsed into pump-and-dump or rug patterns**. In the arXiv data >80% of memecoins rug. Start from "this is a rug until proven otherwise."
4. **New EVM whitelist-scam pattern (Ichimoku Inu, detailed in the paper).** Owner-controlled hidden whitelist grants fee/tx-limit/trading exemptions:
   ```solidity
   function fullWhitelist(address target) public onlyOwner {
       authorizations[target] = true;
       isFeeExempt[target] = true;
       isTxLimitExempt[target] = true;
       isInternal[target] = true;
   }
   // _transferFrom: non-whitelisted require(tradingOpen), TX Limit, restrictWhales;
   // whitelisted addresses bypass all of it.
   ```
   Grep for `fullWhitelist`, `authorizations[`, `isFeeExempt`, `isTxLimitExempt`, `isInternal`, `restrictWhales`, `tradingOpen`.
5. **Scanner-tool matrix and its blind spots.** RugCheck (Solana: mint/freeze authority, LP burn/lock, top-holder concentration; light sell simulation), Honeypot.is (EVM: buy/sell simulation, exact buy/sell tax, gas; no holder/liquidity analysis), GoPlus (multi-chain contract risks), Token Sniffer (contract similarity), Dedaub TokIn. Honeypot.is states a token passing today can become a honeypot later if the owner retains fee-raising power — **deferred malice defeats point-in-time scans**.
6. **Real enforcement precedent.** CatFi (pump.fun, Feb 2025) — creators charged in May 2026 under South Korea's first Virtual Asset User Protection Act rug-pull prosecution ($600K damage, $8.37M peak → $12K). Confirms authorities now treat launchpad rugs as prosecutable fraud.

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
5. **LP-lock verification, not badge trust.** Read the lock contract on-chain: unlock timestamp, lock owner (deployer?), multiple fragmented lockers, and **shorten/renew permissions** (a "lock" the owner can shorten is an exit hatch). Reject 1-day locks renewed weekly.
6. **Bundle-level entity resolution and wash-trade patterns.** Use `bundle_size`/`bundled_buys` (MemeTrans-style) to detect coordinated creator wallets, and adapt the Self/Matched/Circular wash-trade features (Cao et al., BSC, PR-AUC 0.9185, mean 3.8h early warning) to Solana to distinguish real volume from manufactured activity.
7. **Fee-exempt/whitelist mapping scan** on EVM tokens: enumerate every mapping that exempts addresses from fees, tx limits, or the `tradingOpen` gate; determine whether the owner can add arbitrary addresses.

### Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives (confabulation is NOT a finding for AI classes)

1. **Distinguish "deployer COULD rug" from "contract IS exploitable now."** Most structural rug vectors are pre-rug warnings, not reportable bugs — route them through `triage-validation`. A bug bounty finding needs a currently exploitable path with a reproducible PoC.
2. **For due-diligence audits, require on-chain proof, not scanner output:** authority fields null on-chain at a specific slot, LP burn transaction hash, holder distribution at a pinned block, lock contract source verified. A badge/screenshot is not evidence.
3. **An ML risk score is NOT a finding** — it is a triage prior. Confabulation-style false positives here include "the model says 98% rug risk." Always confirm with the structural checks above. The arXiv authors themselves call their results a baseline not ready for deployment (false negatives carry real losses).
4. **Never trust a single rug-checker.** Deferred-malice tokens are clean for the first days and activate hooks later; cross-source verification plus owner-privilege code review is mandatory.
5. **Honeypot proof needs the exact revert/tax and function.** Show the failing `transfer`/`sell` call with calldata and the exempt-address path that succeeds — "the scanner said honeypot" is not proof.
6. **Report reproducibility.** Include exact mint/contract address, block/slot, tool commands, and the specific function/authority. A finding without an address is unverifiable.
7. **Confabulation guard (AI-class analogue).** If an AI-assisted audit tool claims a rug vector, verify the function exists in verified source/on-chain bytecode — do not report a hallucinated `mint()` or `blacklist()` function.

### Escalation and related chains

### Related Skills & Chains

- **`web3-audit`** — When the target is a DeFi protocol (not just a token). Workflow primitive: this skill's 8 token-specific bug classes are a subset of `web3-audit`'s scope; if the target has lending / vault / oracle logic beyond the token contract itself, also load `web3-audit` for the broader 10 DeFi bug classes.
- **`triage-validation`** — When deciding if a rug-pull finding qualifies as a bug bounty submission. Workflow primitive: many "rug vector" observations are pre-rug warnings, not exploitable bugs in a deployed protocol; run 7Q gate to distinguish "the deployer COULD rug" (informational) from "the contract IS exploitable now" (reportable).
- **`report-writing`** — When writing up a confirmed token security finding for Immunefi / private bounty. Workflow primitive: Foundry PoC template here feeds into `report-writing`'s Immunefi body template.
- **`offensive-osint`** — When the token has off-chain infrastructure (project website, Telegram, deployer doxxing). Workflow primitive: on-chain audit is this skill's domain; deployer wallet history, social presence, and project legitimacy checks route to `offensive-osint`.
- **`bb-methodology`** — When confirming engagement mode. Workflow primitive: PART 0 separates "pre-investment due diligence" (this skill's primary use) from "Immunefi bug bounty submission" (different reporting + severity standards); the answer routes which post-audit handoff is correct.

---

### Sources and related reading

### SOLANA QUICK CHECKS (NO SOURCE CODE NEEDED)

When you don't have source code, check on-chain:

```
1. MINT AUTHORITY → solana account <MINT> --output json | check mint_authority
   - Should be null
   - If Some(pubkey) → CRITICAL: can mint infinite tokens

2. FREEZE AUTHORITY → same as above, check freeze_authority
   - Should be null
   - If Some(pubkey) → CRITICAL: honeypot

3. LP STATUS → Check Raydium/Orca pool
   - LP burned? (tokens sent to 1111...1111)
   - LP locked? (in verified locker with no backdoor)
   - LP held by deployer? → CRITICAL: instant rug

4. TOP HOLDERS → Birdeye/Solscan holders tab
   - Top 10 < 30% of supply (excluding pools)
   - Creator wallets (check first transactions)

5. PROGRAM UPGRADEABILITY
   - Is the program upgradeable? → can change any logic
   - Upgrade authority should be None for immutable programs

6. TOKEN-2022 EXTENSIONS
   - Any transfer hook? → potential honeypot
   - Permanent delegate? → CRITICAL
```

---

### D. Sources — numbered list of URLs you actually fetched

1. https://arxiv.org/html/2608.20271v1 ("Catching the Rug: Early Prediction of Fraudulent Memecoins on Solana via ML", 6.4M tokens, 5-min/1-hour windows, TVL+Idle labels, feature tables, Ichimoku Inu whitelist code; webfetched)
2. https://blofin.com/en/academy/education/solana/solana-memecoin-rug-pull-safety (Solidus 98.6% pump.fun statistic, five-minute pre-buy checklist)
3. https://coincodex.com/article/94430/best-token-scanners/ (RugCheck and Honeypot.is capabilities and blind spots, 2026)
4. https://medium.com/@fxmbrand/how-to-spot-a-solana-rug-pull-the-12-point-on-chain-checklist-d2018b97904a (12-point on-chain checklist, Token-2022 extension red flags)
5. https://finance.yahoo.com/markets/crypto/articles/solana-meme-coin-surges-6-130901647.html (CatFi pump.fun rug, first ROK Virtual Asset User Protection Act prosecution, May 2026)
6. https://www.medium.com/@fxmbrand/how-to-spot-a-solana-rug-pull-the-12-point-on-chain-checklist-d2018b97904a and https://rugcheck.xyz/ / https://honeypot.is/ (cross-source verification tooling)

### Additional notes

### Hard Kills (Skip Immediately)

- **Contract not verified** on Etherscan/Solscan → Cannot audit source = cannot trust
- **Deployer wallet** has history of rug pulls (check Etherscan deployer page)
- **Token age < 1 hour** AND no known team → Too early, wait for more data
- **Mint authority retained** (Solana) AND no cap → Infinite mint = certain rug
- **Freeze authority retained** (Solana) on meme coin → Honeypot confirmed
- **Transfer hook present** (Token-2022) with mutable hook program → Honeypot vector
- **Permanent delegate** extension (Token-2022) → Can steal all holder tokens

### Soft Kills (Proceed with Extreme Caution)

- Top holder > 20% of supply (excluding DEX pools)
- LP not burned or locked in verified contract
- Contract is upgradeable / proxy with retained admin
- Less than $5K liquidity in the pool
- No social presence / anonymous deployer with no history

---

### THE ONE RULE

> **"Check ALL authorities and owner functions. The retained authority IS the rug vector."**
>
> Every rug pull requires a privileged operation: mint, blacklist, fee change, LP removal, or authority abuse. If you find the privilege, you found the bug.

---

### 1. HIDDEN MINT / UNLIMITED SUPPLY

> Common rug pattern. Deployer mints tokens post-launch, dumps on LP.

**Quick grep (EVM):**
```bash
grep -rn "function mint\|_mint(\|_balances\[.*\] +=" src/ --include="*.sol" | grep -v "test\|lib\|node_modules"
```

**Quick grep (Solana):**
```bash
grep -rn "MintTo\|mint_to\|mint_authority" src/ --include="*.rs" | grep -v "test\|target"
```

**Kill if:** MAX_SUPPLY enforced in every mint path, or mint function removed entirely.

### 2. HONEYPOT / TRANSFER RESTRICTION

> Common scam pattern. Buy works, sell blocked.

**Quick grep:**
```bash
grep -rn "blacklist\|isBlacklisted\|_bots\|maxTxAmount\|approve.*override\|tradingEnabled" src/ --include="*.sol"
```

**Solana equivalent:**
```bash
grep -rn "freeze_authority\|transfer_hook\|TransferHook\|permanent_delegate" src/ --include="*.rs"
```

**Kill if:** No blacklist mapping, no transfer hooks, no freeze authority.

### 3. FEE MANIPULATION

> Common rug pattern. Sell fee set to 99% after initial buys.

**Quick grep:**
```bash
grep -rn "setFee\|setSellFee\|_taxFee\|_sellFee" src/ --include="*.sol"
grep -rn "function set.*Fee" -A5 src/ --include="*.sol" | grep -v "require\|MAX\|<="
```

**Kill if:** Fee setter has `require(fee <= MAX_FEE)` with MAX_FEE <= 10%.

### 4. LIQUIDITY POOL DRAIN

> LP removal, migration, or manipulation to crash price.

**Quick grep:**
```bash
grep -rn "migrateLP\|emergencyWithdraw\|\.sync()\|setPair\|setRouter" src/ --include="*.sol"
```

**Kill if:** LP tokens burned to dead address, no migration function, no pair setter.

### 5. BONDING CURVE MANIPULATION

> Exploits in pump.fun-style bonding curves.

**Quick grep:**
```bash
grep -rn "virtualReserve\|setCurve\|graduate\|bonding_curve" src/ --include="*.sol" --include="*.rs"
```

**Kill if:** Curve parameters immutable, graduation permissionless.

### 6. AUTHORITY RETENTION (SOLANA)

> Retained mint/freeze/update authorities on Solana tokens.

**Quick grep:**
```bash
grep -rn "mint_authority\|freeze_authority\|update_authority\|close_authority" src/ --include="*.rs"
grep -rn "set_authority.*None" src/ --include="*.rs"  # Good sign: revocation
```

**Kill if:** All authorities = None, verified on-chain.

### 7. FAKE RENOUNCE / HIDDEN OWNERSHIP

> Ownership appears renounced but backdoor control retained.

**Quick grep:**
```bash
grep -rn "renounceOwnership.*override\|_shadowAdmin\|_backupOwner\|selfdestruct" src/ --include="*.sol"
```

**Kill if:** renounceOwnership NOT overridden, no second admin role, no selfdestruct.

### 8. SANDWICH AMPLIFICATION BY DESIGN

> Contract makes holders maximally sandwichable.

**Quick grep:**
```bash
grep -rn "swapExactTokensForETH" -A5 src/ --include="*.sol" | grep "0,"
grep -rn "swapThreshold\|_rebase\|mandatoryPool" src/ --include="*.sol"
```

**Kill if:** Auto-swap has proper slippage, no rebase mechanics.

---

### FAST RED-FLAG SWEEP

Run the 8 bug-class greps above across the source tree for fast red-flag detection. Together they catch:
- Direct mint/balance manipulation
- Blacklist and transfer restriction patterns
- Unbounded fee setters
- LP migration and emergency withdraw functions
- Fake renounce overrides
- Zero slippage auto-swaps
- All Solana authority patterns
- Token-2022 dangerous extensions

**Source grep does NOT check** (verify these out-of-band):
- On-chain state (use Etherscan/Solscan for authority verification)
- Holder distribution (use DEXTools/Birdeye)
- LP lock status (use Unicrypt/PinkLock/Solscan)
- Deployer wallet history (manual check)

---

### FOUNDRY POC TEMPLATE (TOKEN EXPLOITS)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Token.sol";

contract TokenExploitTest is Test {
    Token token;
    address owner = makeAddr("owner");
    address victim = makeAddr("victim");
    address attacker = makeAddr("attacker");

    // Uniswap V2 router (mainnet fork)
    address constant ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    function setUp() public {
        vm.createSelectFork("mainnet");
        // Deploy token as owner
        vm.startPrank(owner);
        token = new Token();
        // Add liquidity...
        vm.stopPrank();
    }

    function test_hiddenMint_rug() public {
        // Step 1: Victim buys tokens
        vm.startPrank(victim);
        // ... buy tokens on Uniswap
        vm.stopPrank();

        // Step 2: Owner mints and dumps
        vm.startPrank(owner);
        uint256 supplyBefore = token.totalSupply();
        token.mint(owner, 1_000_000_000e18);
        assertGt(token.totalSupply(), supplyBefore, "Supply should increase");
        // ... sell minted tokens
        vm.stopPrank();

        // Step 3: Victim's tokens are now worthless
        // Assert token price crashed
    }

    function test_honeypot_blacklist() public {
        // Step 1: Victim buys
        vm.startPrank(victim);
        // ... buy tokens
        vm.stopPrank();

        // Step 2: Owner blacklists victim
        vm.startPrank(owner);
        token.blacklist(victim);
        vm.stopPrank();

        // Step 3: Victim cannot sell
        vm.startPrank(victim);
        vm.expectRevert("Blacklisted");
        token.transfer(address(1), 100e18);
        vm.stopPrank();
    }

    function test_fee_manipulation_rug() public {
        // Step 1: Verify initial fee is low
        assertEq(token.sellFee(), 3); // 3%

        // Step 2: Owner sets fee to 99%
        vm.prank(owner);
        token.setFees(3, 99); // Buy 3%, Sell 99%

        // Step 3: Victim sells — loses 99% to fees
        vm.startPrank(victim);
        uint256 balanceBefore = address(victim).balance;
        // ... sell tokens
        // Assert: received almost nothing
        vm.stopPrank();
    }
}
```

---

### Operator Notes (Claude-BugHunter)

> Engagement-derived + 2026-specific additions to the vendored foundation.
> Wisdom from real authorized engagements + Phase 2 verification across
> this repo's 31+ skill-area live tests. The upstream content covers the WHAT;
> this layer covers the WHEN-IT-WORKS-vs-WHEN-IT-DOESN'T.

### Honeypot detection — beyond the obvious

`transfer()` succeeds in dry-run but fails on certain addresses (sender allowlist / blocklist). Test with: simulated buy → simulated transfer to a different address → simulated sell. If buy + transfer succeed but sell fails, it's a honeypot.

Quick triage matrix:

| Test | Honeypot Signal |
|------|----------------|
| Buy from random wallet | Succeeds (must — or no one would touch it) |
| Transfer to second random wallet | Often fails on honeypot |
| Sell from original wallet | Fails or applies > 50% tax |
| Sell from team-controlled wallet | Succeeds (the giveaway) |

Cross-source verification: solana-rugcheck, rugcheck.xyz, dexscreener risk signals, honeypot.is (EVM). Never trust a single source — rug-checkers can be fooled by deferred-malice patterns (clean for first 7 days, hook activates later).

### LP lock claims — verify, don't trust

LP-lock badges on DexScreener mean nothing without on-chain verification. Check the actual lock contract (Unicrypt, TeamFinance, Bonkbot, PinkLock) for:

- **Unlock date** — the on-chain timestamp, not the badge text
- **Lock owner** — is it the deployer's wallet? Are there multiple lockers fragmenting the LP?
- **Extension / shortening permission** — some lock contracts allow the owner to SHORTEN the lock; that's an exit hatch dressed as a lock
- **Lock contract bytecode** — verify it's the canonical locker, not a fork with backdoors

Some "locked" LPs are 1-day locks renewed weekly — visually the same as a year lock to the buyer, but the deployer can let it lapse on any Tuesday. Always read the lock contract source on the chain explorer.

### Pre-investment due diligence in under 5 minutes

The 6-question fast filter:

1. Mint authority null?
2. Freeze authority null?
3. Update authority null (for metadata immutability)?
4. LP locked in a verified contract for > 6 months?
5. Top 10 holders concentration < 30% (excluding pools/burn addresses)?
6. Bonding curve completed (for pump.fun) AND post-completion mint authority null?

Five "no"s = walk away. Three "no"s = high risk, only enter with size you'd walk away from. Two "no"s with strong narrative + thin liquidity = the canonical retail trap.

### MEV / sandwich amplification on illiquid mints

Buying into a mint with < $50K liquidity guarantees you'll be sandwiched. The bot infrastructure on Solana and Ethereum is institutionalized in 2026 — Jito MEV-share and private order-flow auctions. If your trade size > 1% of available liquidity, expect sandwich loss > 5%; > 5% of liquidity, expect > 20% slippage from sandwich alone.

Mitigations (rank by 2026 effectiveness):

1. **Jito bundles** (Solana) — submit with priority tip, atomic with no MEV window
2. **Flashbots Protect RPC** (Ethereum) — private mempool submission
3. **MEV-protected DEX aggregators** — Jupiter's slippage protection, 1inch Fusion, CoWSwap
4. **Splitting orders** — N smaller trades vs 1 large; reduces sandwich profitability per trade

If the mint is so illiquid that even split orders sandwich — that's the signal to skip the trade, not the signal to use better tooling.

---

### MEV / sandwich amplification on illiquid mints

Buying into a mint with < $50K liquidity guarantees you'll be sandwiched. The bot infrastructure on Solana and Ethereum is institutionalized in 2026 — Jito MEV-share and private order-flow auctions. If your trade size > 1% of available liquidity, expect sandwich loss > 5%; > 5% of liquidity, expect > 20% slippage from sandwich alone.

Mitigations (rank by 2026 effectiveness):

1. **Jito bundles** (Solana) — submit with priority tip, atomic with no MEV window
2. **Flashbots Protect RPC** (Ethereum) — private mempool submission
3. **MEV-protected DEX aggregators** — Jupiter's slippage protection, 1inch Fusion, CoWSwap
4. **Splitting orders** — N smaller trades vs 1 large; reduces sandwich profitability per trade

If the mint is so illiquid that even split orders sandwich — that's the signal to skip the trade, not the signal to use better tooling.

## Source skills merged into this topic

- `hunting` — `meme-coin-audit`
- `cbh` — `meme-coin-audit`

## Provenance

- `references/unified-method.md` — same deduplicated union as this file, for tooling
- `references/upstream-*.md` — unmodified original SKILL.md from each repo
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
