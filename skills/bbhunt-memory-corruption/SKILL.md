---
name: bbhunt-memory-corruption
description: "Use for memory-corruption bugs in native clients, parsers and appliances: overflow, use-after-free, out-of-bounds read, null deref and assertion failures. Unified from 2 upstream skills (h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Memory Safety and Native Software — unified methodology

> **Unified skill.** Built from 2 upstream skills across h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus evidence (892 valid reports, 291 paid / 33%)

Payment is not validity — zero-bounty disclosures are mined as evidence too.

### Techniques ranked across ALL valid writeups

| Technique | Reports |
|---|---:|
| public source-code / repo review | 232 |
| WAF / sanitizer / filter bypass | 209 |
| race / concurrency / timing | 201 |
| HTTP method / verb tampering | 150 |
| encoding / double-encode / null byte | 138 |
| internal service / port / container | 106 |
| third-party data / paste / breach reuse | 95 |
| error message / stack trace probing | 88 |
| file upload / filename / extension | 81 |
| OAST / DNS / HTTP callback proof | 56 |

### Parameters observed

`mrb`, `entry`, `self`, `proc`, `fsanitize`, `argc`, `argv`, `main`, `stack_keep`, `str`, `len`, `nil`, `mid`, `sig`, `val`

### Case studies (real reports, paid and unpaid)

- [2177925](https://hackerone.com/reports/2177925) PlayStation — Remote vulnerabilities in spp ($12500, high)
- [826026](https://hackerone.com/reports/826026) PlayStation — Use-After-Free In IPV6_2292PKTOPTIONS leading To Arbitrary Kernel R/W Primitives ($10000, high)
- [943231](https://hackerone.com/reports/943231) PlayStation — SOCK_RAW sockets reachable from Webkit process allows triggering double free in IP6_EXTHDR_CHECK ($10000, high)

Full payload bank, bypass frequencies, approach patterns and case-study excerpts: `references/evidence.md`.

## Corpus-backed method (this class)

1. Confirm the target is genuinely in scope and that a crash/disruption test is permitted — many programs exclude DoS-style crashes.
2. Identify the parser and input format; reproduce a deterministic crash with a minimal malformed file or message.
3. Collect the exact crash signature (stack, registers, sanitizer report) without executing untrusted target code outside a sandbox.
4. Distinguish a null deref/assert (often low impact) from an out-of-bounds write or use-after-free with attacker-controlled data.
5. If a proof of exploitability is required, state the unresolved fact explicitly; do not claim RCE from a crash alone.
6. Map the reachable attack surface: who supplies the malformed input and what privilege does the process hold.

### Signals

- Native binary, browser/library parser, firmware or appliance in scope
- Crash, assertion, or sanitizer output from malformed input
- File formats/network protocols parsed in C/C++

### Kill criteria

- Crash-only with no memory-control evidence and program excludes DoS.
- Crash reproduced only under a debugger/fuzzer with attacker-controlled build.
- Out of scope binary or third-party component.

### Escalation chains

- Parser bug -> memory disclosure -> ASLR defeat -> code execution (only when proved).

### Veteran tip

Run target-controlled code only in a sandbox with no network and bounded resources; otherwise keep it as needs-validation.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Identify native parsers reachable from untrusted input.
- Fuzz with structure-aware inputs and sanitizers (ASan/UBSan).
- Look for length/count mismatches and integer overflow before memcpy.
- Audit use-after-free lifecycles and error paths.
- Diff patches and CVE-adjacent code for incomplete fixes.

### Deeper checklist

- Identify native parsers reachable from untrusted input (images, media, archives, protocols).
- Fuzz with structure-aware inputs and sanitizers (ASan/UBSan) where possible.
- Look for length/count mismatches, integer overflow, and signedness bugs before memcpy.
- Audit use-after-free in object lifecycles and error paths.
- Check patch diffs and CVE-adjacent code for incomplete fixes.
- Prove crash with a minimal reproducer and assess exploitability.

### Web-Research Methodology Additions (2026)

> Fresh-source pass: MITRE 2025 CWE Top 25, CISA/FBI 2025 memory-safety guidance, CISA KEV 2025-2026 entries, AFL++ fuzzing-in-depth docs, and LLVM libFuzzer docs. Extends the HackerOne field guide with current 2026 technique and proof standards.

### A. Discovery checklist — concrete surfaces, inputs, configs to look for

1. **This class is more relevant in 2026 than ever.** MITRE's 2025 CWE Top 25: out-of-bounds write (CWE-787) ranks **5th**; classic buffer copy (CWE-120) 11th, stack overflow (CWE-121) 14th, heap overflow (CWE-122) 16th. Use-after-free (CWE-416) ranks above every buffer-overflow ID except CWE-787. Google's 2025 zero-day review: memory-safety issues (primarily UAF + OOB write) were ~**35%** of all in-the-wild exploited vulnerabilities. One 2025 Microsoft Patch Tuesday: 728/955 (76%) CVEs were memory-safety bugs. CISA KEV v2026.10.21: **413/1,754** entries (~24%) tagged with a memory-safety CWE.
2. **Prioritize internet-facing C/C++ parsers and edge devices.** 2025-2026 KEV entries cluster there: Ivanti Connect Secure **CVE-2025-0282** and **CVE-2025-22457** (CWE-121, unauth RCE), Citrix NetScaler **CVE-2025-7775** (CWE-119), Fortinet **CVE-2025-25249** (CWE-122), VMware vCenter **CVE-2024-37079** (CWE-787), Chrome Skia **CVE-2026-3909** (CWE-787), Windows Fast FAT **CVE-2025-24985** (CWE-190 → CWE-122), Insyde driver **CVE-2025-12052** (`RtlQueryRegistryValues` with `RTL_QUERY_REGISTRY_DIRECT` → untrusted registry value copied into undersized kernel buffer). Many hit KEV on day zero or day one — patch windows measured in weeks do not fit.
3. **Know the CWE family so you label findings correctly.** CWE-119 (parent, bounds), CWE-787 (OOB write — the result), CWE-120 (classic copy), CWE-121 (stack), CWE-122 (heap), CWE-125 (OOB read — leaks, not corrupts; Heartbleed CVE-2014-0160 is this), CWE-190 (int

### Signals and surfaces

### Signal

- Reports: **892** · paid: **291**
- Median bounty **$750** · p90 **$4,000** · max **$12,500** · total **$457,798**
- Median upvotes **5**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`file parsers` `media codecs` `network daemons` `browsers` `C/C++ extensions`

### Techniques, payloads and bypasses

### Payloads & probes

- Craft malformed length fields, counts, and chunk sizes.
- Use AFL++/libFuzzer with a seed corpus.
- ASan -> `heap-buffer-overflow`, `use-after-free`

### Bypass tricks

- Target parsers behind file uploads, media, archives, and protocols.
- Reach the code path through an unauthenticated endpoint.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **RCE on Steam Client via buffer overflow in Server Info** — `#470520` · Valve · $0 · ▲1289
  > Then, we built a unicode ROP chain with gadgets from `Steam.exe` only, to call `VirtualProtect` dynamically to make the stack executable and jump to our unicode shellcode to execute `cmd.exe`.
- **Use-After-Free In IPV6_2292PKTOPTIONS leading To Arbitrary Kernel R/W Primitives** — `#826026` · PlayStation · $10,000 · ▲741
  > Due to missing locks in option `IPV6 2292PKTOPTIONS` of `setsockopt` , it is possible to race and free the `struct ip6 pktopts ` buffer, while it is being handled by `ip6 setpktopt`.
- **Malformed .BMP file in Counter-Strike 1.6 may cause shellcode injection** — `#397545` · Valve · $0 · ▲321
  > The problem is in the LoadBMP8 function, which is executed when the player connects to the server, by loading the "overviews\%MAPNAME%.bmp" file.
- **Heap overflow happen when receiving short length key from ssh server using ssh protocol 1** — `#630462` · PuTTY (European Commission - DIGIT) · $3,646 · ▲309
  > =================================================================
- **SOCK_RAW sockets reachable from Webkit process allows triggering double free in IP6_EXTHDR_CHECK** — `#943231` · PlayStation · $10,000 · ▲298
  > The reliability of `poc.c` is very high, around 80%, whereas`ps4.c` is not very high, I guess around 20%.
- **size_t-to-int vulnerability in exFAT leads to memory corruption via malformed USB flash dri

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 19× | `quote_name()` |
| 14× | `curl_easy_pause()` |
| 11× | `curl_easy_escape()` |
| 10× | `strlen()` |
| 9× | `curl_multi_remove_handle()` |
| 9× | `mq->sendleftovers` |
| 9× | `next->text` |
| 8× | `strcpy()` |
| 8× | `redirect_url()` |
| 8× | `curl_easy_duphandle()` |
| 8× | `free()` |
| 8× | `Curl_close()` |
| 6× | `smb_send_open()` |
| 6× | `req->path` |
| 6× | `smbc->share` |
| 6× | `unpack_fields()` |
| 6× | `curl_easy_cleanup()` |
| 6× | `mev_assess()` |
| 6× | `suboption()` |
| 6× | `curl_msprintf()` |

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
   Useful flags: `-malloc_limit_mb`, `-max_total_time`, `-merge=1` (corpus minimization), `-jobs`/`-workers`. Exit codes: 77 for li

### Validation and proof

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

### C. Validation / proof bar — how to confirm and avoid false positives (confabulation is NOT a finding for AI classes)

1. **A crash alone is NOT a finding.** A useful report contains five items: (1) location and root cause + CWE; (2) reachability — which input, from where (remote unauth / authenticated / local), under what config; (3) evidence — minimal reproducing input and the sanitizer report, produced in a test environment; (4) realistic impact given the build's mitigations; (5) fix and retest — code-level fix, missing hardening flags, and a regression test/fuzz target. No weaponized exploit is required.
2. **Distinguish stack exhaustion from stack-based buffer overflow.** Runaway recursion exhausting the stack is a reliability bug; a fixed buffer on the stack receiving too much data is a security bug. Likewise distinguish over-read (CWE-125, disclosure) from over-write (CWE-787, corruption).
3. **Account for mitigations honestly.** Canaries, NX, ASLR, and CFI raise the cost of exploitation but do not remove the bug. Note their presence; if the impact is "crashes the VPN gateway," call it DoS, not RCE. If an OOB read leaks an address, note that it undercuts ASLR.
4. **Prove attacker-controlled reachability.** A sanitizer crash in a harness that no untrusted input can reach is not a vulnerability — show the path from network/file/IPC input to the vulnerable copy. Local-only bugs need a documented privilege-escalation path to be compelling.
5. **Don't claim RCE from a sanitizer report alone.** ASAN proves the memory error, not code execution. Only claim RCE with a cred

### Escalation and related chains

### Escalation chains

- Memory bug -> crash -> info leak -> RCE.

### Tools and wordlists

### Tools

`AFL++` · `libFuzzer` · `ASan/UBSan` · `Ghidra` · `rr`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_memory-corruption.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_memory-corruption.txt` | 36 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_memory-corruption.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_memory-corruption.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Identify the exact product/version, then run matching CVE templates; fuzz parsers locally with ASan.

```sh
nuclei -u https://target -tags cve,rce \
       -severity low,medium,high,critical -rl 40 -o nuclei_memory-corruption.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Source skills merged into this topic

- `h1skills` — `hackerone-memory-corruption`
- `hunting` — `memory-corruption`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 2 merged companion methodology documents
- `references/corpus-wordlists/` — 2 mined paths/params/payload lists from the HackerOne corpus
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
