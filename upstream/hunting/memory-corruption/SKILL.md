---
name: memory-corruption
description: >-
  Hunt memory safety bugs in native software. Use when auditing parsers, media codecs, network daemons, browsers, or C/C++/Rust unsafe code. Backed by 892 disclosed HackerOne reports.
---

# Memory Corruption (Binary / Native) — HackerOne field guide

Built from **892** publicly disclosed HackerOne reports (2013–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **892** · paid: **291**
- Median bounty **$750** · p90 **$4,000** · max **$12,500** · total **$457,798**
- Median upvotes **5**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Internet Bug Bounty | 405 | $201,652 | 2442 |
| PlayStation | 8 | $72,500 | 2209 |
| shopify-scripts | 69 | $67,400 | 415 |
| Valve | 26 | $64,650 | 3731 |
| Open-Xchange | 23 | $10,500 | 291 |
| VLC (European Commission - DIGIT) | 4 | $6,200 | 270 |
| Mail.ru | 7 | $5,650 | 81 |
| Block.one | 4 | $5,500 | 58 |

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`file parsers` `media codecs` `network daemons` `browsers` `C/C++ extensions`

## Tools

`AFL++` · `libFuzzer` · `ASan/UBSan` · `Ghidra` · `rr`

## Escalation chains

- Memory bug -> crash -> info leak -> RCE.

## Related

- `rce` (1,399 reports)
- `dos` (66 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

## Web-Research Methodology Additions (2026)

> Fresh-source pass: MITRE 2025 CWE Top 25, CISA/FBI 2025 memory-safety guidance, CISA KEV 2025-2026 entries, AFL++ fuzzing-in-depth docs, and LLVM libFuzzer docs. Extends the HackerOne field guide with current 2026 technique and proof standards.

### A. Discovery checklist — concrete surfaces, inputs, configs to look for

1. **This class is more relevant in 2026 than ever.** MITRE's 2025 CWE Top 25: out-of-bounds write (CWE-787) ranks **5th**; classic buffer copy (CWE-120) 11th, stack overflow (CWE-121) 14th, heap overflow (CWE-122) 16th. Use-after-free (CWE-416) ranks above every buffer-overflow ID except CWE-787. Google's 2025 zero-day review: memory-safety issues (primarily UAF + OOB write) were ~**35%** of all in-the-wild exploited vulnerabilities. One 2025 Microsoft Patch Tuesday: 728/955 (76%) CVEs were memory-safety bugs. CISA KEV v2026.10.21: **413/1,754** entries (~24%) tagged with a memory-safety CWE.
2. **Prioritize internet-facing C/C++ parsers and edge devices.** 2025-2026 KEV entries cluster there: Ivanti Connect Secure **CVE-2025-0282** and **CVE-2025-22457** (CWE-121, unauth RCE), Citrix NetScaler **CVE-2025-7775** (CWE-119), Fortinet **CVE-2025-25249** (CWE-122), VMware vCenter **CVE-2024-37079** (CWE-787), Chrome Skia **CVE-2026-3909** (CWE-787), Windows Fast FAT **CVE-2025-24985** (CWE-190 → CWE-122), Insyde driver **CVE-2025-12052** (`RtlQueryRegistryValues` with `RTL_QUERY_REGISTRY_DIRECT` → untrusted registry value copied into undersized kernel buffer). Many hit KEV on day zero or day one — patch windows measured in weeks do not fit.
3. **Know the CWE family so you label findings correctly.** CWE-119 (parent, bounds), CWE-787 (OOB write — the result), CWE-120 (classic copy), CWE-121 (stack), CWE-122 (heap), CWE-125 (OOB read — leaks, not corrupts; Heartbleed CVE-2014-0160 is this), CWE-190 (integer overflow/wraparound), CWE-680 (integer → buffer overflow), CWE-193 (off-by-one), CWE-416 (UAF), CWE-134 (format string). Vendors often tag two IDs (location + effect).
4. **Target surfaces:** file/image/font/media parsers, network protocol handlers, IPC endpoints, kernel drivers, browser engines, native libraries shipped inside desktop/mobile apps, and WebAssembly runtimes (e.g. 2025 wasm3 CVE-2025-15413). Where source is unavailable, map parse points and check build hardening.
5. **Inventory the harness prerequisites:** one small function that consumes fuzzer bytes (e.g. `LLVMFuzzerTestOneInput`), a seed corpus of valid files/messages, a sanitizer-instrumented build, and a CI job. OSS-Fuzz reported >13,000 vulnerabilities and 50,000 bugs fixed across 1,000 projects by May 2025 — fuzzing works at scale.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

1. **Fuzzer choice.** AFL++ = out-of-process, robust, strong mutation engine, good for targets you can't restructure into a harness. libFuzzer = in-process, very fast, integrates with LLVM sanitizers; note the original authors moved on to **Centipede** (libFuzzer is still supported). honggfuzz is the third option. Run one sanitized instance per sanitizer type; **SAND** (AFL++) can combine sanitizers at higher throughput.
2. **AFL++ setup.**
   ```
   export AFL_USE_ASAN=1 AFL_USE_UBSAN=1 AFL_USE_CFISAN=1
   afl-clang-fast++ -fsanitize=fuzzer -o harness harness.cpp targetlib.a
   afl-fuzz -i seeds -o out -m 2048 -t 1000 -- ./harness @@
   ```
   Sanitizers: ASAN (UAF, OOB, stack/heap overflow — ~2x slowdown, ~3x memory), MSAN (uninitialized reads), UBSAN (signed overflow, UB), CFISAN (type confusion via illegal control flow), TSAN (races), LSAN (leaks; needs `__AFL_LEAK_CHECK()`). Use `-m`/`-t` to cap memory/time; `-t 5` is viable on fast idle machines. Triage with `afl-tmin` (minimize), `afl-analyze` (byte-flip color coding), and `casr-afl` (clustered reports). "Mystery 400"-style ambiguous crashes deserve a second look.
3. **libFuzzer setup.**
   ```
   clang -fsanitize=fuzzer,address -o fuzz_target fuzz_target.c targetlib.a
   ./fuzz_target CORPUS_DIR -max_len=1000 -rss_limit_mb=2048 -detect_leaks=1
   ./fuzz_target crash-<sha1> -minimize_crash=1 -runs=100000
   ```
   Useful flags: `-malloc_limit_mb`, `-max_total_time`, `-merge=1` (corpus minimization), `-jobs`/`-workers`. Exit codes: 77 for libFuzzer-reported bugs, 71 for OOM.
4. **Code review: follow the length from untrusted input to the copy/allocation.** Red flags: `strcpy`/`strcat`/`sprintf`/`gets`/`scanf("%s")` (CWE-120); `memcpy`/`read` length taken from a header field without comparing to destination size; `count * sizeof(record)` computed before allocation (CWE-190 → CWE-680); loops using `<=` against a length (CWE-193); signed lengths compared with unsigned sizes. Fix patterns: `snprintf` with a checked return, `calloc(count, size)`, C23 `ckd_mul` in `<stdckdint.h>`. Note `strncpy` is not a safe drop-in — it can leave the string unterminated.
5. **UAF exploitation mechanics (for impact assessment).** The danger is the reallocation window: after `free(obj)`, if the attacker can control what gets allocated into that slot, a field the old object treated as a function pointer becomes attacker data → type confusion. Requires heap grooming, which is why UAF is harder to find and exploit than a stack overflow. Double free and dangling pointer are adjacent variants.
6. **OOB read as the ASLR-defeating primitive.** CitrixBleed (CVE-2023-4966, CWE-119) leaked session cookies and let attackers bypass MFA without code execution. An overflow that corrupts an authorization flag likewise needs no code execution — score the data/control consequence, not just the theoretical RCE.
7. **Binary-only testing.** Check build mitigations: stack canaries (`-fstack-protector-strong` / `/GS`), FORTIFY_SOURCE=3, PIE/ASLR (`-fPIE -pie` / `/DYNAMICBASE`), NX/DEP (`-Wl,-z,noexecstack` / `/NXCOMPAT`), CFI and shadow stacks (`-fcf-protection=full` x86-64, `-mbranch-protection=standard` AArch64, `/guard:cf`). Identify imported risky functions and fuzz parse points in an isolated lab copy. Remember: CISA/FBI called buffer overflows "unforgivable defects" in February 2025.
8. **Hardening flags as a verification checklist** (OpenSSF Compiler Options Hardening Guide): `-O2 -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -fstack-protector-strong -fstack-clash-protection -fPIE -pie -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -fcf-protection=full` (x86-64) or `-mbranch-protection=standard` (AArch64). Missing flags are themselves a finding-adjacent observation and directly shape the "realistic impact" section of your report.
9. **Watch for the memory-safety/migration signal.** Google reported memory-safety bugs falling from 76% to 24% of Android vulnerabilities over six years as new development moved to memory-safe languages — while the oldest code stayed put. The practical hunting target is therefore the *boundary*: native extensions, FFI calls, third-party C libraries linked into safe-language programs, and Rust code inside `unsafe` blocks.

### Cross-skill routing for memory-safety findings

- **Crash / OOB read only, no attacker-controlled path shown** → `dos` at most; do not claim RCE.
- **Leaked token, cookie, or key from an OOB read** → chain to `session` / `account-takeover` (CitrixBleed-style session-theft bypasses MFA).
- **Overflow reached through a web-uploaded file** → pair with `file-upload` for the delivery PoC and `rce` for the impact claim.
- **Overflow in a network-facing parser on an edge appliance** → `enterprise-vpn-attack` / `vmware-vcenter-attack` for version fingerprinting and CVE mapping.

### C. Validation / proof bar — how to confirm and avoid false positives (confabulation is NOT a finding for AI classes)

1. **A crash alone is NOT a finding.** A useful report contains five items: (1) location and root cause + CWE; (2) reachability — which input, from where (remote unauth / authenticated / local), under what config; (3) evidence — minimal reproducing input and the sanitizer report, produced in a test environment; (4) realistic impact given the build's mitigations; (5) fix and retest — code-level fix, missing hardening flags, and a regression test/fuzz target. No weaponized exploit is required.
2. **Distinguish stack exhaustion from stack-based buffer overflow.** Runaway recursion exhausting the stack is a reliability bug; a fixed buffer on the stack receiving too much data is a security bug. Likewise distinguish over-read (CWE-125, disclosure) from over-write (CWE-787, corruption).
3. **Account for mitigations honestly.** Canaries, NX, ASLR, and CFI raise the cost of exploitation but do not remove the bug. Note their presence; if the impact is "crashes the VPN gateway," call it DoS, not RCE. If an OOB read leaks an address, note that it undercuts ASLR.
4. **Prove attacker-controlled reachability.** A sanitizer crash in a harness that no untrusted input can reach is not a vulnerability — show the path from network/file/IPC input to the vulnerable copy. Local-only bugs need a documented privilege-escalation path to be compelling.
5. **Don't claim RCE from a sanitizer report alone.** ASAN proves the memory error, not code execution. Only claim RCE with a credible control-flow or data-corruption path; otherwise report the bug at its demonstrated severity (crash / info leak / auth-flag corruption).
6. **Confabulation note (AI classes).** If an AI-assisted code scanner flags an overflow, verify the exact line and a reproducing input — do not report a hallucinated function or an unreachable "vulnerable" copy.

### D. Sources — numbered list of URLs you actually fetched

1. https://deepstrike.io/blog/buffer-overflow (CWE family, 2025 CWE Top 25 ranks, CISA KEV 2025-2026 table, mitigations, how testers find overflows; webfetched)
2. https://aflplus.plus/docs/fuzzing_in_depth/ (AFL++ sanitizers ASAN/MSAN/UBSAN/CFISAN/TSAN/LSAN, SAND, `-m`/`-t`, afl-tmin/analyze, casr-afl)
3. https://llvm.org/docs/LibFuzzer.html (libFuzzer `-fsanitize=fuzzer`, corpus, flags, exit codes, Centipede note)
4. https://runsafesecurity.com/blog/memory-safety-vulnerabilities/ (GTIG 2025 ~35% in-the-wild, Microsoft 76% Patch Tuesday statistic, CISA 2025 guidance, CVE examples)
5. https://codeant.ai/blogs/memory-safety-bugs-fuzzing (UAF mechanics, AFL++ vs libFuzzer process model, sanitizer cost table)
6. https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html (MITRE 2025 CWE Top 25)
