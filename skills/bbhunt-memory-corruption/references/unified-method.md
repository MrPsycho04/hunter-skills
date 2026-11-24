# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

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
3. **Know the CWE family so you label findings correctly.** CWE-119 (parent, bounds), CWE-787 (OOB write — the result), CWE-120 (classic copy), CWE-121 (stack), CWE-122 (heap), CWE-125 (OOB read — leaks, not corrupts; Heartbleed CVE-2014-0160 is this), CWE-190 (integer overflow/wraparound), CWE-680 (integer → buffer overflow), CWE-193 (off-by-one), CWE-416 (UAF), CWE-134 (format string). Vendors often tag two IDs (location + effect).
4. **Target surfaces:** file/image/font/media parsers, network protocol handlers, IPC endpoints, kernel drivers, browser engines, native libraries shipped inside desktop/mobile apps, and WebAssembly runtimes (e.g. 2025 wasm3 CVE-2025-15413). Where source is unavailable, map parse points and check build hardening.
5. **Inventory the harness prerequisites:** one small function that consumes fuzzer bytes (e.g. `LLVMFuzzerTestOneInput`), a seed corpus of valid files/messages, a sanitizer-instrumented build, and a CI job. OSS-Fuzz reported >13,000 vulnerabilities and 50,000 bugs fixed across 1,000 projects by May 2025 — fuzzing works at scale.

## Signals and surfaces

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

## Techniques, payloads and bypasses

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
- **size_t-to-int vulnerability in exFAT leads to memory corruption via malformed USB flash drives** — `#1340942` · PlayStation · $10,000 · ▲280
  > Namely, `dataLength` and `size` are both 64bit wide, however the `size` argument of `sceFatfsCreateHeapVl()` is 32bit wide:
- **Malformed NAV file leads to buffer overflow and code execution in Left4Dead2.exe** — `#542180` · Valve · $10,000 · ▲268
  > Place it in your <steamapps /Left 4 Dead 2/left4dead2/maps/ directory
- **sys_fsc2h_ctrl kernel stack free** — `#2900606` · PlayStation · $10,000 · ▲236
  > Thread 4: The command CMD COMPLETE (0x20003) in sys fsc2h ctrl writes data into that local stack buffer and wakes up the thread 3.
- **Double fdrop on a socket through sys_netcontrol** — `#3320669` · PlayStation · $10,000 · ▲228
  > Remove `s2` from netevent using `netcontrol()` syscall with cmd 0x20000007
- **OOB reads in network message handlers leads to RCE** — `#807772` · Valve · $7,500 · ▲219
  > The `ShowMenu` message takes the `menu string` supplied from the server, converts it to UTF16, and stores it in a global string variable `wchar t g szMenuString[512]`.
- **RCE on CS:GO client using unsanitized entity ID in EntityMsg message** — `#584603` · Valve · $9,000 · ▲209
  > Luckily, `client panorama.dll` imports `IProcessUtils` interface from `tier0.dll` which can be used to start processes.
- **Remote vulnerabilities in spp** — `#2177925` · PlayStation · $12,500 · ▲197
  > Hence, the data that is overread from the `mbuf` is copied into `buf` (with overflow) and returned to the malicious PPPoE server with `sppp cp send()`.
- **Buffer overrun in Steam SILK voice decoder** — `#1180252` · Valve · $7,500 · ▲196
  > 4) Run `send voice packet path\to\voice payload` in the CS:GO console on device A, where `path\to\voice payload` is the absolute path to the `voice payload` file without the `C:`.
- **[Portal 2] Remote Code Execution via voice packets** — `#733267` · Valve · $5,000 · ▲173
  > Inject the following DLL into the attackers portal 2 process: {F630586} (source code: {F630587})
- **[Half-Life 1] Malformed map name leads to memory corruption and code execution** — `#402566` · Valve · $1,500 · ▲163
  > This was tested on `Half Life` 2018-08-29 on Linux, Ubuntu 18.04.
- **Use-after-free in setsockopt IPV6_2292PKTOPTIONS (CVE-2020-7457)** — `#1441103` · PlayStation · $10,000 · ▲143
  > See https://www.freebsd.org/security/advisories/FreeBSD-SA-20:20.ipv6.asc for more details.
- **Race Conditions in Popular reports feature.** — `#146845` · HackerOne · $0 · ▲125
  > POST https://hackerone.com/reports/127158/votes HTTP/1.1
- **Null Pointer Dereference by Crafted Response from AI Model** — `#2958097` · Brave Software · $0 · ▲116
  > - Server endpoint: `https://canalun.company/57e23a24db994321970941049b05d1bb`
- **Specially Crafted Closed Captions File can lead to Remote Code Execution in CS:GO and other Source Games** — `#463286` · Valve · $7,500 · ▲109
  > Buffer overflow via the closed captioning system in the function `CHudCloseCaption::SplitCommand` which can be reached via the function `CHudCloseCaption::GetNoRepeatValue`
- **Access Violation Reading in libfaad_plugin** — `#502816` · VLC (European Commission - DIGIT) · $1,121 · ▲106
  > main input debug: `file:///C:/softs/crash.mkv' successfully opened
- **Stack overflow in XML Parsing** — `#480883` · Notepad++ · $0 · ▲99
  > Vulnerability src file: notepad-plus-plus/PowerEditor/src/Notepad plus.cpp
- **Malformed .MDL triggers an Access Violation on GoldSRC (hl.exe)** — `#495793` · Valve · $0 · ▲90
  > Scope: DEFAULT BUCKET ID (Failure Bucket ID prefix)
- **Remote kernel heap overflow** — `#1350653` · PlayStation · $0 · ▲86
  > - `Settings` - `Network` - `Set Up Internet Connection` - `Use a LAN Cable` - `Custom`
- **[steam client] Opening a specific steam:// url overwrites files at an arbitrary location** — `#667242` · Valve · $750 · ▲80
  > If a user opens `steam://devkit-1/list-shortcuts?response=/tmp/testfile`, a file `/tmp/testfile` will be created containing the response to this request.
- **Access Violation Reading EXPLOITABLE_0228** — `#503208` · VLC (European Commission - DIGIT) · $1,135 · ▲77
  > 000007f9`0fbf2b9d 47893499 mov dword ptr [r9+r11 4],r14d ds:00000000`51d6c048=????????
- **CVE-2021-22901: TLS session caching disaster** — `#1180380` · curl · $0 · ▲76
  > lib/vtls/openssl.c `ossl connect step1` sets up the `ossl new session cb` sessionid callback with `SSL CTX sess set new cb`, and adds association from `data idx` and `connectdata idx` to current `conn` and `data` respectively:
- **Heap Buffer Overflow (READ: 4) in phar_parse_pharfile** — `#477344` · Internet Bug Bounty · $0 · ▲72
  > This was tracked as [PHP bug 77143](https://bugs.php.net/bug.php?id=77143)
- **CS:GO Server -> Client RCE through OOB access in CSVCMsg_SplitScreen + Info leak in HTTP download** — `#1070835` · Valve · $7,500 · ▲66
  > The bug that occurs here is that if two `Content-Length` headers are sent, but one is written with uppercase characters (`Content-Length`) and the other header with all lower case characters `content-length`, then the CS:GO code will reocognize only the first…
- **Image queue default key of 'None' and GraphQL unhandled type exception** — `#996041` · Reddit · $500 · ▲65
  > <a xlink:href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' onload='alert(88)'%3E%3C/svg%3E" test 6</a
- **VLC 4.0.0 - Stack Buffer Overflow (SEH)** — `#489102` · VLC (European Commission - DIGIT) · $2,817 · ▲62
  > When reading a RTCP PT SDES package the length for the memcpy operation is set by the rtcp sdes get name length(buf) which is taking the 9-10th bit of the buffer and making it possible to change the amount of bytes read into the new sender name variable.

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
   Useful flags: `-malloc_limit_mb`, `-max_total_time`, `-merge=1` (corpus minimization), `-jobs`/`-workers`. Exit codes: 77 for libFuzzer-reported bugs, 71 for OOM.
4. **Code review: follow the length from untrusted input to the copy/allocation.** Red flags: `strcpy`/`strcat`/`sprintf`/`gets`/`scanf("%s")` (CWE-120); `memcpy`/`read` length taken from a header field without comparing to destination size; `count * sizeof(record)` computed before allocation (CWE-190 → CWE-680); loops using `<=` against a length (CWE-193); signed lengths compared with unsigned sizes. Fix patterns: `snprintf` with a checked return, `calloc(count, size)`, C23 `ckd_mul` in `<stdckdint.h>`. Note `strncpy` is not a safe drop-in — it can leave the string unterminated.
5. **UAF exploitation mechanics (for impact assessment).** The danger is the reallocation window: after `free(obj)`, if the attacker can control what gets allocated into that slot, a field the old object treated as a function pointer becomes attacker data → type confusion. Requires heap grooming, which is why UAF is harder to find and exploit than a stack overflow. Double free and dangling pointer are adjacent variants.
6. **OOB read as the ASLR-defeating primitive.** CitrixBleed (CVE-2023-4966, CWE-119) leaked session cookies and let attackers bypass MFA without code execution. An overflow that corrupts an authorization flag likewise needs no code execution — score the data/control consequence, not just the theoretical RCE.
7. **Binary-only testing.** Check build mitigations: stack canaries (`-fstack-protector-strong` / `/GS`), FORTIFY_SOURCE=3, PIE/ASLR (`-fPIE -pie` / `/DYNAMICBASE`), NX/DEP (`-Wl,-z,noexecstack` / `/NXCOMPAT`), CFI and shadow stacks (`-fcf-protection=full` x86-64, `-mbranch-protection=standard` AArch64, `/guard:cf`). Identify imported risky functions and fuzz parse points in an isolated lab copy. Remember: CISA/FBI called buffer overflows "unforgivable defects" in February 2025.
8. **Hardening flags as a verification checklist** (OpenSSF Compiler Options Hardening Guide): `-O2 -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -fstack-protector-strong -fstack-clash-protection -fPIE -pie -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -fcf-protection=full` (x86-64) or `-mbranch-protection=standard` (AArch64). Missing flags are themselves a finding-adjacent observation and directly shape the "realistic impact" section of your report.
9. **Watch for the memory-safety/migration signal.** Google reported memory-safety bugs falling from 76% to 24% of Android vulnerabilities over six years as new development moved to memory-safe languages — while the oldest code stayed put. The practical hunting target is therefore the *boundary*: native extensions, FFI calls, third-party C libraries linked into safe-language programs, and Rust code inside `unsafe` blocks.

## Validation and proof

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
5. **Don't claim RCE from a sanitizer report alone.** ASAN proves the memory error, not code execution. Only claim RCE with a credible control-flow or data-corruption path; otherwise report the bug at its demonstrated severity (crash / info leak / auth-flag corruption).
6. **Confabulation note (AI classes).** If an AI-assisted code scanner flags an overflow, verify the exact line and a reproducing input — do not report a hallucinated function or an unreachable "vulnerable" copy.

## Escalation and related chains

### Escalation chains

- Memory bug -> crash -> info leak -> RCE.

## Tools and wordlists

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

## Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class memory-corruption --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class memory-corruption
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class memory-corruption
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class memory-corruption --min-bounty 1000
```

### Related

- `hackerone-rce` (1,399 reports)
- `hackerone-dos` (66 reports)

### Related

- `rce` (1,399 reports)
- `dos` (66 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://deepstrike.io/blog/buffer-overflow (CWE family, 2025 CWE Top 25 ranks, CISA KEV 2025-2026 table, mitigations, how testers find overflows; webfetched)
2. https://aflplus.plus/docs/fuzzing_in_depth/ (AFL++ sanitizers ASAN/MSAN/UBSAN/CFISAN/TSAN/LSAN, SAND, `-m`/`-t`, afl-tmin/analyze, casr-afl)
3. https://llvm.org/docs/LibFuzzer.html (libFuzzer `-fsanitize=fuzzer`, corpus, flags, exit codes, Centipede note)
4. https://runsafesecurity.com/blog/memory-safety-vulnerabilities/ (GTIG 2025 ~35% in-the-wild, Microsoft 76% Patch Tuesday statistic, CISA 2025 guidance, CVE examples)
5. https://codeant.ai/blogs/memory-safety-bugs-fuzzing (UAF mechanics, AFL++ vs libFuzzer process model, sanitizer cost table)
6. https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html (MITRE 2025 CWE Top 25)

## Additional notes

### Parameters observed

`id` · `name` · `usp` · `response` · `_task` · `_action` · `center` · `size` · `maptype` · `markers` · `sensor` · `scale` · `zoom` · `language` · `raw` · `password` · `plain` · `lang` · `summary` · `statement`

### RCE on Steam Client via buffer overflow in Server Info

`#470520` · Valve · $0 · critical · 2019-03-15 · ▲1289
> We wanted to prove impact and build an exploit. First, we tested it on Linux and we were able to control the execution flow instantly by overwriting the return address. However, on Linux, we were able to control two bytes of the EIP register only (e.g. 0x00004141) and we didn’t explore it further. On OSX, the process terminated with SIGABRT, which means that there’s probably a canary protection in the library on OSX.

### Use-After-Free In IPV6_2292PKTOPTIONS leading To Arbitrary Kernel R/W Primitives

`#826026` · PlayStation · $10,000 · high · 2020-07-06 · ▲741
> Due to missing locks in option IPV6 2292PKTOPTIONS of setsockopt , it is possible to race and free the struct ip6 pktopts buffer, while it is being handled by ip6 setpktopt. This structure contains pointers (ip6po pktinfo) that can be hijacked to obtain arbitrary kernel R/W primitives. As a consequence, it is easy to have kernel code execution. This vulnerability is reachable from WebKit sandbox and is available in the latest FW, that is 7.02.

### Malformed .BMP file in Counter-Strike 1.6 may cause shellcode injection

`#397545` · Valve · $0 · high · 2020-02-27 · ▲321
> With the vulnerability of the GoldSource Engine, the server is able to perform remote code execution on the client, overwriting the stack when reading the BMP file. The problem is in the LoadBMP8 function, which is executed when the player connects to the server, by loading the "overviews\%MAPNAME%.bmp" file.

### Heap overflow happen when receiving short length key from ssh server using ssh protocol 1

`#630462` · PuTTY (European Commission - DIGIT) · $3,646 · high · 2019-09-20 · ▲309
> There's no check in ssh1 login process queue function when read servkey and hostkey length from packet which may cause heap overflow. Remote code execution may be possible.

### SOCK_RAW sockets reachable from Webkit process allows triggering double free in IP6_EXTHDR_CHECK

`#943231` · PlayStation · $10,000 · high · 2021-01-12 · ▲298
> Memory corruption can be achieved by sending fragmented IPv6 packets to loopback interface due to poor and inconsistent use of IP6 EXTHDR CHECK. The macro IP6 EXTHDR CHECK can free the mbuf if the packet is sent to loopback interface. This fact is not considered in dest6 input(), frag6 input() and more.

### Cross-skill routing for memory-safety findings

- **Crash / OOB read only, no attacker-controlled path shown** → `dos` at most; do not claim RCE.
- **Leaked token, cookie, or key from an OOB read** → chain to `session` / `account-takeover` (CitrixBleed-style session-theft bypasses MFA).
- **Overflow reached through a web-uploaded file** → pair with `file-upload` for the delivery PoC and `rce` for the impact claim.
- **Overflow in a network-facing parser on an edge appliance** → `enterprise-vpn-attack` / `vmware-vcenter-attack` for version fingerprinting and CVE mapping.

## Companion methodology (merged, deduplicated)

Full text of every non-SKILL.md methodology file from the contributing skills — payload banks, technique references, reconnaissance and attack-class guides.

### Companion: hunting / references/payloads.md

# Memory Corruption (Binary / Native) — HackerOne field guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Craft malformed length fields, counts, and chunk sizes.

- Use AFL++/libFuzzer with a seed corpus.

- ASan -> `heap-buffer-overflow`, `use-after-free`



## Payload fragments observed



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



## Parameters observed



`id` · `name` · `usp` · `response` · `_task` · `_action` · `center` · `size` · `maptype` · `markers` · `sensor` · `scale` · `zoom` · `language` · `raw` · `password` · `plain` · `lang` · `summary` · `statement`



## Wordlists



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



## Nuclei



Identify the exact product/version, then run matching CVE templates; fuzz parsers locally with ASan.



```sh

nuclei -u https://target -tags cve,rce \

       -severity low,medium,high,critical -rl 40 -o nuclei_memory-corruption.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Companion: hunting / references/techniques.md

# Memory Corruption (Binary / Native) — HackerOne field guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Identify native parsers reachable from untrusted input.

- Fuzz with structure-aware inputs and sanitizers (ASan/UBSan).

- Look for length/count mismatches and integer overflow before memcpy.

- Audit use-after-free lifecycles and error paths.

- Diff patches and CVE-adjacent code for incomplete fixes.



## Bypass tricks



- Target parsers behind file uploads, media, archives, and protocols.

- Reach the code path through an unauthenticated endpoint.



## Deeper checklist



- Identify native parsers reachable from untrusted input (images, media, archives, protocols).

- Fuzz with structure-aware inputs and sanitizers (ASan/UBSan) where possible.

- Look for length/count mismatches, integer overflow, and signedness bugs before memcpy.

- Audit use-after-free in object lifecycles and error paths.

- Check patch diffs and CVE-adjacent code for incomplete fixes.

- Prove crash with a minimal reproducer and assess exploitability.



## Techniques from real reports



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

- **size_t-to-int vulnerability in exFAT leads to memory corruption via malformed USB flash drives** — `#1340942` · PlayStation · $10,000 · ▲280

  > Namely, `dataLength` and `size` are both 64bit wide, however the `size` argument of `sceFatfsCreateHeapVl()` is 32bit wide:

- **Malformed NAV file leads to buffer overflow and code execution in Left4Dead2.exe** — `#542180` · Valve · $10,000 · ▲268

  > Place it in your <steamapps /Left 4 Dead 2/left4dead2/maps/ directory

- **sys_fsc2h_ctrl kernel stack free** — `#2900606` · PlayStation · $10,000 · ▲236

  > Thread 4: The command CMD COMPLETE (0x20003) in sys fsc2h ctrl writes data into that local stack buffer and wakes up the thread 3.

- **Double fdrop on a socket through sys_netcontrol** — `#3320669` · PlayStation · $10,000 · ▲228

  > Remove `s2` from netevent using `netcontrol()` syscall with cmd 0x20000007

- **OOB reads in network message handlers leads to RCE** — `#807772` · Valve · $7,500 · ▲219

  > The `ShowMenu` message takes the `menu string` supplied from the server, converts it to UTF16, and stores it in a global string variable `wchar t g szMenuString[512]`.

- **RCE on CS:GO client using unsanitized entity ID in EntityMsg message** — `#584603` · Valve · $9,000 · ▲209

  > Luckily, `client panorama.dll` imports `IProcessUtils` interface from `tier0.dll` which can be used to start processes.

- **Remote vulnerabilities in spp** — `#2177925` · PlayStation · $12,500 · ▲197

  > Hence, the data that is overread from the `mbuf` is copied into `buf` (with overflow) and returned to the malicious PPPoE server with `sppp cp send()`.

- **Buffer overrun in Steam SILK voice decoder** — `#1180252` · Valve · $7,500 · ▲196

  > 4) Run `send voice packet path\to\voice payload` in the CS:GO console on device A, where `path\to\voice payload` is the absolute path to the `voice payload` file without the `C:`.

- **[Portal 2] Remote Code Execution via voice packets** — `#733267` · Valve · $5,000 · ▲173

  > Inject the following DLL into the attackers portal 2 process: {F630586} (source code: {F630587})

- **[Half-Life 1] Malformed map name leads to memory corruption and code execution** — `#402566` · Valve · $1,500 · ▲163

  > This was tested on `Half Life` 2018-08-29 on Linux, Ubuntu 18.04.

- **Use-after-free in setsockopt IPV6_2292PKTOPTIONS (CVE-2020-7457)** — `#1441103` · PlayStation · $10,000 · ▲143

  > See https://www.freebsd.org/security/advisories/FreeBSD-SA-20:20.ipv6.asc for more details.

- **Race Conditions in Popular reports feature.** — `#146845` · HackerOne · $0 · ▲125

  > POST https://hackerone.com/reports/127158/votes HTTP/1.1

- **Null Pointer Dereference by Crafted Response from AI Model** — `#2958097` · Brave Software · $0 · ▲116

  > - Server endpoint: `https://canalun.company/57e23a24db994321970941049b05d1bb`

- **Specially Crafted Closed Captions File can lead to Remote Code Execution in CS:GO and other Source Games** — `#463286` · Valve · $7,500 · ▲109

  > Buffer overflow via the closed captioning system in the function `CHudCloseCaption::SplitCommand` which can be reached via the function `CHudCloseCaption::GetNoRepeatValue`

- **Access Violation Reading in libfaad_plugin** — `#502816` · VLC (European Commission - DIGIT) · $1,121 · ▲106

  > main input debug: `file:///C:/softs/crash.mkv' successfully opened

- **Stack overflow in XML Parsing** — `#480883` · Notepad++ · $0 · ▲99

  > Vulnerability src file: notepad-plus-plus/PowerEditor/src/Notepad plus.cpp

- **Malformed .MDL triggers an Access Violation on GoldSRC (hl.exe)** — `#495793` · Valve · $0 · ▲90

  > Scope: DEFAULT BUCKET ID (Failure Bucket ID prefix)

- **Remote kernel heap overflow** — `#1350653` · PlayStation · $0 · ▲86

  > - `Settings` - `Network` - `Set Up Internet Connection` - `Use a LAN Cable` - `Custom`

- **[steam client] Opening a specific steam:// url overwrites files at an arbitrary location** — `#667242` · Valve · $750 · ▲80

  > If a user opens `steam://devkit-1/list-shortcuts?response=/tmp/testfile`, a file `/tmp/testfile` will be created containing the response to this request.

- **Access Violation Reading EXPLOITABLE_0228** — `#503208` · VLC (European Commission - DIGIT) · $1,135 · ▲77

  > 000007f9`0fbf2b9d 47893499 mov dword ptr [r9+r11 4],r14d ds:00000000`51d6c048=????????

- **CVE-2021-22901: TLS session caching disaster** — `#1180380` · curl · $0 · ▲76

  > lib/vtls/openssl.c `ossl connect step1` sets up the `ossl new session cb` sessionid callback with `SSL CTX sess set new cb`, and adds association from `data idx` and `connectdata idx` to current `conn` and `data` respectively:

- **Heap Buffer Overflow (READ: 4) in phar_parse_pharfile** — `#477344` · Internet Bug Bounty · $0 · ▲72

  > This was tracked as [PHP bug 77143](https://bugs.php.net/bug.php?id=77143)

- **CS:GO Server -> Client RCE through OOB access in CSVCMsg_SplitScreen + Info leak in HTTP download** — `#1070835` · Valve · $7,500 · ▲66

  > The bug that occurs here is that if two `Content-Length` headers are sent, but one is written with uppercase characters (`Content-Length`) and the other header with all lower case characters `content-length`, then the CS:GO code will reocognize only the first…

- **Image queue default key of 'None' and GraphQL unhandled type exception** — `#996041` · Reddit · $500 · ▲65

  > <a xlink:href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' onload='alert(88)'%3E%3C/svg%3E" test 6</a

- **VLC 4.0.0 - Stack Buffer Overflow (SEH)** — `#489102` · VLC (European Commission - DIGIT) · $2,817 · ▲62

  > When reading a RTCP PT SDES package the length for the memcpy operation is set by the rtcp sdes get name length(buf) which is taking the 9-10th bit of the buffer and making it possible to change the amount of bytes read into the new sender name variable.



## Case studies



### RCE on Steam Client via buffer overflow in Server Info

`#470520` · Valve · $0 · critical · 2019-03-15 · ▲1289

> We wanted to prove impact and build an exploit. First, we tested it on Linux and we were able to control the execution flow instantly by overwriting the return address. However, on Linux, we were able to control two bytes of the EIP register only (e.g. 0x00004141) and we didn’t explore it further. On OSX, the process terminated with SIGABRT, which means that there’s probably a canary protection in the library on OSX.



### Use-After-Free In IPV6_2292PKTOPTIONS leading To Arbitrary Kernel R/W Primitives

`#826026` · PlayStation · $10,000 · high · 2020-07-06 · ▲741

> Due to missing locks in option IPV6 2292PKTOPTIONS of setsockopt , it is possible to race and free the struct ip6 pktopts buffer, while it is being handled by ip6 setpktopt. This structure contains pointers (ip6po pktinfo) that can be hijacked to obtain arbitrary kernel R/W primitives. As a consequence, it is easy to have kernel code execution. This vulnerability is reachable from WebKit sandbox and is available in the latest FW, that is 7.02.



### Malformed .BMP file in Counter-Strike 1.6 may cause shellcode injection

`#397545` · Valve · $0 · high · 2020-02-27 · ▲321

> With the vulnerability of the GoldSource Engine, the server is able to perform remote code execution on the client, overwriting the stack when reading the BMP file. The problem is in the LoadBMP8 function, which is executed when the player connects to the server, by loading the "overviews\%MAPNAME%.bmp" file.



### Heap overflow happen when receiving short length key from ssh server using ssh protocol 1

`#630462` · PuTTY (European Commission - DIGIT) · $3,646 · high · 2019-09-20 · ▲309

> There's no check in ssh1 login process queue function when read servkey and hostkey length from packet which may cause heap overflow. Remote code execution may be possible.



### SOCK_RAW sockets reachable from Webkit process allows triggering double free in IP6_EXTHDR_CHECK

`#943231` · PlayStation · $10,000 · high · 2021-01-12 · ▲298

> Memory corruption can be achieved by sending fragmented IPv6 packets to loopback interface due to poor and inconsistent use of IP6 EXTHDR CHECK. The macro IP6 EXTHDR CHECK can free the mbuf if the packet is sent to loopback interface. This fact is not considered in dest6 input(), frag6 input() and more.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class memory-corruption --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class memory-corruption

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class memory-corruption

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class memory-corruption --min-bounty 1000

```
