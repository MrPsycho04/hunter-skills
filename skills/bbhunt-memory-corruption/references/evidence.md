# Evidence appendix — Memory Safety and Native Software

Mined from all **892 valid disclosed reports** for this class (291 paid, 33% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
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
| fuzzing / wordlist brute force | 55 |
| admin / privileged-role context | 51 |
| JS bundle / source-map inspection | 48 |
| parser confusion / normalization | 47 |
| parameter pollution / duplicate keys | 46 |
| cache / CDN / unkeyed header | 44 |
| git history / exposed .git | 43 |
| deserialization / gadget chain | 41 |
| second-order / stored / blind delivery | 37 |
| unauthenticated / removed-cookie test | 34 |
| subdomain / DNS / cert-transparency recon | 33 |
| API docs / Swagger / introspection | 30 |
| JWT / token / base64 decode | 28 |
| XML / SOAP / SAML / XXE | 26 |
| verbose debug / framework fingerprint | 25 |
| Content-Type / body-format switch | 20 |
| webhook / OAuth / SAML / integration abuse | 18 |
| header injection (Host / X-Forwarded / etc.) | 12 |
| DOM / HTML source inspection | 8 |
| replay / modify a captured request | 5 |
| two-account / cross-account replay | 5 |
| intercept & replay request in Burp | 3 |
| employee / developer public info | 3 |
| template injection (SSTI) | 3 |
| public bucket / storage exposure | 2 |
| response diff / status / length comparison | 2 |
| redirect chain / Location header | 2 |
| swap object ID / parameter value | 2 |
| cloud metadata / IAM abuse | 1 |
| archive / Wayback endpoint discovery | 1 |
| browser DevTools / network tab | 1 |
|  HosT/absolute-URL reset poisoning | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| source-code-review | 207 |
| curl | 165 |
| python | 96 |
| git | 91 |
| javascript-debugging | 37 |
| browser | 16 |
| devtools | 10 |
| burp | 3 |
| burp-intruder | 2 |
| shodan | 1 |
| burp-collaborator | 1 |
| collaborator/oast | 1 |
| beautifier | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| unicode | 81 |
| bypass | 55 |
| content-type | 24 |
| null byte | 20 |
| crlf | 17 |
| bypasses | 12 |
| bypass_demo | 11 |
| type confusion | 9 |
| race condition | 9 |
| chunked | 9 |
| bypassing | 7 |
| normalize | 6 |
| url-encoded | 6 |
| bypassed | 6 |
| desync | 6 |
| backslash | 5 |
| uppercase | 4 |
| %00 | 4 |
| content type | 3 |
| blind | 3 |
| normalize_filename | 2 |
| case-sensitive | 2 |
| null value | 2 |
| url encoding | 2 |
| %0d%0a | 2 |
| normalizer_normalize | 1 |
| whitelist | 1 |
| host header | 1 |

## Impact language

| Item | Count |
|---|---:|
| arbitrary code | 125 |
| remote code execution | 105 |
| password | 93 |
| rce | 91 |
| token | 84 |
| secret | 71 |
| localhost | 66 |
| credential | 52 |
| sensitive data | 34 |
| admin | 30 |
| sensitive information | 18 |
| unauthorized | 14 |
| privilege escalation | 12 |
| data leak | 10 |
| arbitrary write | 8 |
| api key | 7 |
| payment | 6 |
| arbitrary command | 5 |
| arbitrary read | 4 |
| exfiltration | 4 |

## Parameters observed

| Item | Count |
|---|---:|
| mrb | 233 |
| entry | 96 |
| self | 91 |
| proc | 91 |
| fsanitize | 68 |
| argc | 56 |
| argv | 52 |
| main | 39 |
| stack_keep | 37 |
| str | 31 |
| len | 31 |
| nil | 27 |
| mid | 23 |
| sig | 20 |
| val | 19 |
| blk | 15 |
| shell | 15 |
| fill | 15 |
| ptr | 13 |
| info | 13 |
| tree | 13 |
| bytes | 12 |
| cflags | 12 |
| fmt | 11 |
| length | 11 |
| poc | 11 |
| asan_symbolizer_path | 11 |
| name | 11 |
| type | 10 |
| data | 10 |

## Recurring approach patterns

- **2×** the fix for this bug has been committed description i have found some vulnerable code at function
  - e.g. The fix for this bug has been committed: Description: ------------ I have found some vulnerable code at function.
- **2×** remote code execution rce by carefully crafting the payload in the data packet an attacker could overwrite critical heap metadata or function pointers potentially leading to arbitrary code execution on the victim s machine with the privileges of the curl process
  - e.g. **Remote Code Execution (RCE)**: By carefully crafting the payload in the DATA packet, an attacker could overwrite critical heap metadata or function pointers, potentially leading to arbitrary code execution on the victim's machine with the privileges of the curl process.
- **2×** description summary i discovered a heap buffer over read vulnerability in libcurl s smb protocol implementation
  - e.g. ================================================================================ DESCRIPTION: ================================================================================ ## Summary: I discovered a heap buffer over-read vulnerability in libcurl's SMB protocol implementation.
- **1×** by carefully crafting the string to expand and choosing the tabsize you can limit the extent of the memory corruption to chosen objects
  - e.g. By carefully crafting the string to expand and choosing the tabsize you can limit the extent of the memory corruption to chosen objects.
- **1×** hello i found a bug on your registration sign up process
  - e.g. Hello, I found a bug on your registration/Sign UP process..
- **1×** this bug is actually quite strange found by visiting some random page that loads that poc as a frame p i tried to reduce the poc unfortunately it became unstable
  - e.g. This bug is actually quite strange (found by visiting some random page that loads that PoC as a frame:P), I tried to reduce the PoC, unfortunately it became unstable.
- **1×** i noticed that there isn t any size check when someone tries to upload a flie through the upload picture option this could generate a memory leak or also a kind of dos and is deangerous with bigger and bigger files
  - e.g. I noticed that there isn't any "size check" when someone tries to upload a flie through the "upload picture" option, this could generate a memory leak or also a kind of DoS and is deangerous with bigger and bigger files.
- **1×** after parsing a malformed mp4 file flash will keep on accessing a block of memory for timing
  - e.g. After parsing a malformed mp4 file, Flash will keep on accessing a block of memory for timing.
- **1×** after playing a mp4 file flash will keep on updating a counter that saves the current frame and duration
  - e.g. After playing a mp4 file, Flash will keep on updating a counter that saves the current frame and duration.
- **1×** after parsing a malformed mp4 file flash will not free the netstream object properly
  - e.g. After parsing a malformed mp4 file, Flash will not free the NetStream object properly.
- **1×** after playing a mp4 file flash will keep on accessing the memory saving the media object
  - e.g. After playing a mp4 file, Flash will keep on accessing the memory saving the media object.
- **1×** a simple line of actionscript could lead to a crash caused by reading inaccessable memory venus match p g2 for the given regular expression above ovector will be filled with zeros
  - e.g. A simple line of ActionScript could lead to a crash caused by reading inaccessable memory: "Venus".match("(((((((((((((((((((((((((((((((((((((((((((((((((?P<G2>)))))))))))))))))))))))))))))))))))))))))))))))))"); For the given regular expression above, ovector[99] will be filled with zeros.
- **1×** with this one i set out to find a vulnerability in php and discovered that the vulnerability that i found exists in a wider constellation of applications including bsd libc s
  - e.g. With this one I set out to find a vulnerability in PHP and discovered that the vulnerability that I found exists in a wider constellation of applications, including BSD libc's.
- **1×** when playing the attached poc swf it will run the following function code
  - e.g. When playing the attached "PoC.swf", it will run the following function/code.
- **1×** after we run it times which will cause st to st in use this is exactly what we see when playing our poc swf
  - e.g. After we run it 6 times, which will cause st(0) to st(5) "in-use" - this is exactly what we see when playing our PoC.swf.
- **1×** i found and disclosed cve to the php dev team on december and a patch was committed on december and the flaw is now fixed
  - e.g. I found and disclosed CVE-2014-9427 to the PHP dev team on 17 December 2014 ( and a patch was committed on 30 December 2014 ( and the flaw is now fixed.
- **1×** this code path can be forced by crafting a yaml document that contains an invalid php object value
  - e.g. This code path can be forced by crafting a YAML document that contains an invalid !php/object value.
- **1×** the vulnerability after the report i decided to take another look in the code on files post c and uploadbuffer c once i have nothing better to do than watch f1
  - e.g. #The Vulnerability After the Report [73491]( I decided to take another look in the code on files`post.c` and `uploadbuffer.c` (once I have nothing better to do than watch F1).
- **1×** i ve created a full exploit that reads large contiguous chunk of memory
  - e.g. 5) I've created a full exploit that reads large contiguous chunk of memory.
- **1×** bug report patch submitted and accepted description i found this vulnerability using a custom php engine fuzzer that i wrote
  - e.g. 1) Bug report: 2) Patch submitted and accepted: ---Description--- 1)I found this vulnerability using a custom PHP engine fuzzer that I wrote.
- **1×** a quick search on github shows that it s not uncommon to see code like ini set memory limit i ve created a poc that triggers the buffer over write with 0x414141414141
  - e.g. A quick search on github shows that it's not uncommon to see code like "ini_set('memory_limit', -1);" 3)I've created a POC that triggers the buffer over write with 0x414141414141.....
- **1×** but honestly i haven t tested whether any of this could actually occur
  - e.g. But honestly I haven't tested whether any of this could actually occur.
- **1×** hi i was able to bypass you email authentication
  - e.g. Hi, I was able to bypass you email authentication.
- **1×** dmarc was aimed at reducing false negatives provide authentication reporting apply sender policies at the receiving end reduce phishing be scalable in order to get started with dmarc the sending domain needs to have an spf and dkim record published
  - e.g. DMARC was aimed at: Reducing false negatives Provide authentication reporting Apply sender policies at the receiving end Reduce phishing Be scalable In order to get started with DMARC, the sending domain needs to have an SPF and DKIM record published.

## Case studies (full excerpts)

### 2177925 — Remote vulnerabilities in spp
PlayStation · $12500 · high · https://hackerone.com/reports/2177925

## Summary A malicious PPPoE server can cause denial-of-service or potentially remote code execution in kernel context on the PS4/PS5. ## Heap buffer overwrite and overread in sppp_lcp_RCR and sppp_ipcp_RCR For some reason, the PS4/PS5 is vulnerable to [CVE-2006-4304]( By having invalid options, it is possible to cause a heap buffer overwrite and overread. Namely, at [1] the length of `p[1]` is not validated to be smaller or equal to `len`. As such, at [2] the call `bcopy()` will copy with a size potentially larger than both the source and the destination. Furthermore, at [3] the return length is incremented by the malicious length. Hence, the data that is overread from the `mbuf` is copied into `buf` (with overflow) and returned to the malicious PPPoE server with `sppp_cp_send()`. For example this is some data that got sent back containing pointers: Regarding exploitability of the overwrite, note that the allocation size for `malloc()` can be influenced via the LCP header: By doing so, it is possible to trigger a copy from a bigger `mbuf` to a smaller `buf`, thus allowing to overwrite adjacent allocations with controllable data. See attachment for a proof-of-concept that leaks data and can eventually panic the device. ## Integer underflow in sppp_pap_input leading to heap-buffer overread At [1], it is possible to set `len` to a length between 0 and 5. Thus, at [2] `len - 6` ca

### 826026 — Use-After-Free In IPV6_2292PKTOPTIONS leading To Arbitrary Kernel R/W Primitives
PlayStation · $10000 · high · https://hackerone.com/reports/826026

## Summary Due to missing locks in option `IPV6_2292PKTOPTIONS` of `setsockopt` , it is possible to race and free the `struct ip6_pktopts ` buffer, while it is being handled by `ip6_setpktopt`. This structure contains pointers (`ip6po_pktinfo`) that can be hijacked to obtain arbitrary kernel R/W primitives. As a consequence, it is easy to have kernel code execution. This vulnerability is reachable from WebKit sandbox and is available in the latest FW, that is 7.02. ## Attachment Attached is a Proof-Of-Concept that achieves a Local Privilege Escalation on FreeBSD 9 and FreeBSD 12. ## Impact - In conjunction with a WebKit exploit, a fully chained remote attack can be achieved. - It is possible to steal/manipulate user data. - Dump and run pirated games.

### 943231 — SOCK_RAW sockets reachable from Webkit process allows triggering double free in IP6_EXTHDR_CHECK
PlayStation · $10000 · high · https://hackerone.com/reports/943231

## Summary Memory corruption can be achieved by sending fragmented IPv6 packets to loopback interface due to poor and inconsistent use of `IP6_EXTHDR_CHECK`. The macro `IP6_EXTHDR_CHECK` can free the mbuf if the packet is sent to loopback interface. This fact is not considered in `dest6_input()`, `frag6_input()` and more. For example in `dest6_input()`, the double pointer is not updated: Hence, when parsing next headers, the mbuf can be free'd once again, leading to a double free which behaves like a use-after-free when we allocate mbuf's again. Normally, this path would not be triggerable, because sending to loopback interface requires SOCK_RAW root privileges. **However, for some reason on the PS4 SOCK_RAW sockets can be opened in Webkit process!** Attached is `poc.c` which must run with root privileges on a FreeBSD 9 machine. It demonstrates being able to escalate privileges to kernel. Attached is also `ps4.c` which is slightly adjusted to work on the PS4 (you'd need to add includes etc to be able to compile it with your official sdk, I compiled it with a custom framework). The reliability of `poc.c` is very high, around 80%, whereas`ps4.c` is not very high, I guess around 20%. ## Impact - In conjunction with a WebKit exploit, a fully chained remote attack can be achieved. - It is possible to steal/manipulate user data. - Dump and run pirated games.

### 1340942 — size_t-to-int vulnerability in exFAT leads to memory corruption via malformed USB flash drives
PlayStation · $10000 · high · https://hackerone.com/reports/1340942

## Summary A heap-based buffer overflow can be triggered by a malformed exFAT USB flash drive. ## Vulnerability The vulnerability is in Sony's exFAT implementation where there is an integer truncation from 64bit to 32bit on a size variable that is used to allocate the up-case table: Namely, `dataLength` and `size` are both 64bit wide, however the `size` argument of `sceFatfsCreateHeapVl()` is 32bit wide: When using a big size for `dataLength`, this function will therefore only allocate a small buffer, and as a result overflow and corrupt subsequent objects on the heap when calling `UVFAT_ReadDevice()`. For example, using `sectorSize=0x200` and `dataLength=0x100000200` we have: When passing this size to `sceFatfsCreateHeapVl()`, the leading 1 is cut off to `0x200`. ## Exploitation This vulnerability allows us to allocate any buffer on the heap with size >= 512 and multiple of 512, and allows us to overflow by a multiple of 512. There are interesting objects that one could spray on the heap such as `struct usb_endpoint` which contain interesting pointers that one could corrupt. ## Impact Jailbreak the PS4/PS5 by plugging in the USB and directly getting kernel code execution.

### 542180 — Malformed NAV file leads to buffer overflow and code execution in Left4Dead2.exe
Valve · $10000 · critical · https://hackerone.com/reports/542180

## Summary In the parsing routines of NAV files (which contain the navigation mesh used by the AI for survivor bots, zombies, and the AI director spawning system) a buffer overflow exists which can be used to control the EIP register and takeover code execution. ## Proof-of-Concept 1. Download the attached c1m1_hotel.nav 2. Place it in your *<steamapps>/Left 4 Dead 2/left4dead2/maps/* directory 3. Start up Left4Dead 2 and attach a debugger 4. Enter "map c1m1_hotel" into the developer console 5. Observe that EIP becomes 0x41414102, indicating that a buffer overflow has occurred and code execution is possible ## Operating Systems Tested - Windows 10 1809 Build 17763.437 I have not tried this for MacOS or Linux, however I assume it would work on both of those platforms as well if they all share the same codebase as the Windows executable. ## Notes Because Left4Dead 2 ships on Windows with a non-ASLR enabled module (binkw32.dll), it is much easier to write up a working exploit for this vulnerability as you no longer need an additional infoleak of some kind to do serious damage and can just use ROP. ## Impact ## Impact If an attacker successfully exploits this vulnerability, the attacker can run arbitrary code on the machine of a victim. Due to the fact that Source supports sending arbitrary files to clients when connecting to a server, it is possible that you could create a fake de

### 470520 — RCE on Steam Client via buffer overflow in Server Info
Valve · no bounty (valid finding) · critical · https://hackerone.com/reports/470520

## Introduction In Steam and other valve games (CSGO, Half-Life, TF2) there is a functionality to find game servers called the server browser. In order to retrieve the information about these servers the server browser communicates with a specific UDP protocol called [server queries]( The protocol is well described in the online developers manual of Steam. We implemented a custom python server which only replies with the protocol using the same information available in the documentation. After a successful implementation of the protocol we fuzzed several parameters and noticed that the Steam client crashed when receiving replies from our custom server. More specifically, the client crashed when we replied with a large player name used in the `A2S_PLAYER` response. When attaching a debugger we noticed it crashed due to a stack-based buffer overflow. This clearly indicates that something was wrong and we investigated it further to be able to exploit the buffer overflow. After further inspection, we noticed that the overflow occurred in the `serverbrowser` library. At some point the players’ name is converted into unicode and an overflow occurs because the boundaries are not checked. Also, there’s no canary protection present, which allowed us to overwrite the return address and execute arbitrary code on Windows. ## Exploit details We wanted to prove impact and build an exploit. F

### 397545 — Malformed .BMP file in Counter-Strike 1.6 may cause shellcode injection
Valve · no bounty (valid finding) · high · https://hackerone.com/reports/397545

With the vulnerability of the GoldSource Engine, the server is able to perform remote code execution on the client, overwriting the stack when reading the BMP file. The problem is in the LoadBMP8 function, which is executed when the player connects to the server, by loading the "overviews\%MAPNAME%.bmp" file. If we send a badly formed file to this function, then we will be able to rewrite the stack of the function by setting the own code in the stack and passing program control to it. I've wrote a program that compiles file like that. The shellcode, which runs on the stack, starts the "calc.exe" process with the WinExec function. For the client to execute this file, the server must send this file to the client. The server can do this if map that is not present on the client is launched. The server must load a map with random name, for example, "definitely_missing_client_map.bsp". In this case, the name of the BMP file must also be "definitely_missing_client_map.bmp" and it must be in "overviews" folder. You also must create the "overviews\definitely_missing_client_map.txt" file, which is overview description. The nonstandard name of the map prompts the client to download the missing files (bsp, bmp and txt). Upon completion, when the client is able to see the map, the BMP file will be loaded and the binary code from BMP file will be executed on the stack. I've attached the sour

## Field playbook (unedited)

### quick

- Identify native parsers reachable from untrusted input.
- Fuzz with structure-aware inputs and sanitizers (ASan/UBSan).
- Look for length/count mismatches and integer overflow before memcpy.
- Audit use-after-free lifecycles and error paths.
- Diff patches and CVE-adjacent code for incomplete fixes.

### payloads

- Craft malformed length fields, counts, and chunk sizes.
- Use AFL++/libFuzzer with a seed corpus.
- ASan -> `heap-buffer-overflow`, `use-after-free`

### bypass

- Target parsers behind file uploads, media, archives, and protocols.
- Reach the code path through an unauthenticated endpoint.

### surface

- file parsers
- media codecs
- network daemons
- browsers
- C/C++ extensions

### tools

- AFL++
- libFuzzer
- ASan/UBSan
- Ghidra
- rr

### chain

- Memory bug -> crash -> info leak -> RCE.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class memory-corruption
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class memory-corruption --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
