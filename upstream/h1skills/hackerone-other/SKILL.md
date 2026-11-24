---
name: hackerone-other
description: >-
  Hunt miscellaneous vulnerability classes. Use when a finding does not fit a specific class or when exploring newer bug categories. Backed by 1,226 disclosed HackerOne reports.
---

# Other & emerging classes

1,226 disclosed reports did not fit a primary class. Use this as a discovery index: classify the root cause, then open the closest class skill.

## Approach

- Classify the root cause before choosing a playbook.
- Search the corpus for similar titles and technologies.
- Read the closest class skill and adapt its checklist.

## Techniques from real reports

Concrete lessons from reports outside the main classes.

- **Github access token exposure** — `#1087489` · Shopify · $50,000 · ▲1601
  > As a proof I can tell you that on the repo github.com/Shopify/shopify at commit hash `cea9c273391d` the sha512 of the README.md is…
- **WannaCrypt “Killswitch”** — `#228648` · HackerOne · $0 · ▲809
  > Original disclosure: https://www.malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html
- **Steal ALL collateral during liquidation by exploiting lack of validation in `flip.kick`** — `#684092` · BlockDev Sp. Z o.o · $0 · ▲466
  > I've attached to this report a modified version of `end.t.sol` which contains a test (`test steal all collateral using flipper`) that reproduces the attack.
- **June 2022 Incident Report** — `#1622449` · HackerOne · $0 · ▲426
  > | 2022-06-22 10:30 PDT | Call with a customer requesting an investigation into reports of an intimidating and suspicious off-platform communication from an actor with the handle "rzlr" |
- **Bypass of GitLab CI runner slash fix in YAML validation** — `#409395` · GitLab · $0 · ▲363
  > The reason is that the fix in place preventing url normalization is performed by doing the YAML validation, however this could be bypassed by setting the environment variable in `https://gitlab.com/{project id}/settings/ci cd`
- **An attacker can archive and unarchive any structured scope object on HackerOne** — `#1501611` · HackerOne · $0 · ▲318
  > This can be found by base64 encoding: gid://hackerone/StructuredScope/NUMBER
- **Bypass Email Verification -- Able to Access Internal Gitlab Services that use Login with Gitlab and Perform Check on email domain** — `#565883` · GitLab · $0 · ▲249
  > - Visit `https://gitlab.com/groups/GROUP PATH/-/saml` and setup the SAML SSO as documented
- **Spring Actuator endpoints publicly available and broken authentication** — `#838635` · LY Corporation · $12,500 · ▲234
  > Due to insufficient access control, it was possible to access the Spring Boot Actuator endpoints /heapdump and /env.
- **Github Account hijack through broken link in developer.twitter.com** — `#1031321` · X / xAI · $0 · ▲222
  > A link in https://developer.twitter.com/en/docs/twitter-api/tools-and-libraries was broken and anyone could create that account which leads to account impersonate
- **Ability To Delete User(s) Account Without User Interaction** — `#928255` · GitLab · $0 · ▲221
  > Since Gitlab doesn't verify the request with an Valid ID before triggering Right to Access/Deletion this breaches the GDPR Law(Article 15) & moreover allows an attacker to delete User Accounts without user interaction.
- **Handling of `tracking` command allows making arbitrary blind requests with user's cookies from Grammarly Extension's origin** — `#389108` · Superhuman (formerly Grammarly) · $0 · ▲202
  > `gnar.setUser`/`gnar. execQueue` / `gnar. send` / `gnar. doSend` / `gnar. enqueue`
- **HackerOne making payments in USDC (Coinbase stable coin)** — `#1220747` · HackerOne · $0 · ▲201
  > This is not new, this has been requested from many of you, and also some members of our Hacker Advisory board.
- **2020-10-09 Credential Stuffing Attack** — `#1007689` · HackerOne · $0 · ▲196
  > On October 4, 2020 and October 5, 2020, an attacker launched two [credential stuffing attacks](https://owasp.org/www-community/attacks/Credential stuffing) against HackerOne.com.
- **protected Tweet settings overwritten by other settings** — `#664038` · X / xAI · $0 · ▲178
  > ==I have deleted all data (stored data and cache), so you don't need to save any cache or history!==
- **Frans Visits Vegas Announcement** — `#251747` · Frans Visits Vegas · $0 · ▲154
  > Frans Rosén, aka, “The Swedish Ninja” (Yea, I’ve always wanted to be called that, I’ll try to make it happen by force)
- **Informations disclosure - Access to some checkout informations** — `#1064869` · Shopify · $0 · ▲150
  > It came to my attention that using the CheckoutStatus query on `https://arrive-server.shopifycloud.com/graphql` it is possible to access some checkout details, specifically the query can be called with an ID value ranging from `1` up to `48908`.
- **h1-202 leaderboard photo discloses local wifi password** — `#329798` · HackerOne · $0 · ▲145
  > Local attackers could connect to the wifi and sniff any unencypted traffic, as well as DoS the network (potentially).
- **`socket` command allows sending data over WebSockets to arbitrary origins from Grammarly Extension** — `#395729` · Superhuman (formerly Grammarly) · $0 · ▲140
  > `evil.com` connects to `ws://good.com` using WS = server at `good.com` is responsible for `Origin` header validation.
- **Build fetches jars over HTTP** — `#506161` · PortSwigger Web Security · $1,000 · ▲135
  > [Comcast continues to inject its own code into websites you visit](https://thenextweb.com/insights/2017/12/11/comcast-continues-to-inject-its-own-code-into-websites-you-visit/ ) (over HTTP)
- **[URGENT] Opportunity to publish tweets on any twitters account** — `#208978` · X / xAI · $0 · ▲119
  > Write-up of the vulnerability here: https://medium.com/@kedrisec/publish-tweets-by-any-other-user-6c9d892708e3
- **HackerOne Code sends live password-reset tokens to Segment in automatic page events** — `#4000185` · HackerOne · $200 · ▲115
  > The token appears in `context.page.search`, `context.page.url`, `properties.search`, and `properties.url`.
- **Lack of Rate Limiting on Account Creation Endpoint** — `#2915502` · XVIDEOS · $200 · ▲110
  > Set the ██████████ type to numbers and range it from `0` to `1000`.
- **SMAP bypass** — `#1048322` · PlayStation · $0 · ▲110
  > The problem is, the fault handler `copy fault` does not clear `%RFLAGS.AC`, meaning that it remains set after `copyin()`/`copyout()` returns.
- **DLL side-loading vulnerability in Sony Music Center for PC Ver. 2.7.2 (Latest version)** — `#3355766` · Sony · $0 · ▲109
  > MITRE reference: https://attack.mitre.org/techniques/T1574/001/
- **Rate limit bypass on passport.acronis.work using X-Forwarded-For request header** — `#2627062` · Acronis · $0 · ▲106
  > in case you wanted to try to login to a victims account as attacker, such as `ab@acronis.com` which I found on snov.io you can't if you aren't from bulgaria, you will be restricted due to you are not from bulgaria and you see that error `ERR-B258C8`
- **[Bypass #645264] Report title disclosure despite the program settings for email notification is set to "No Content"** — `#669438` · HackerOne · $500 · ▲104
  > I have found that email invitation for a collaborator (bounty splitting) still disclosing the Report title in email when the notification comes from `Manage Collaborator` invitation.
- **Use Github pack with Coda employee github account (search code of Coda's private repositories)** — `#676581` · Superhuman (formerly Grammarly) · $0 · ▲104
  > If you look at the requests in Burp, you will see a request to https://coda.io/embed/igvicDMruo?viewMode=gallery&disconnected=true that is loaded in an `<iframe ` (it is the document you see when you load the template).
- **HTML Injection in LinkedIn Premium Support Chat** — `#3079966` · LinkedIn · $0 · ▲102
  > `https://www.linkedin.com/premium/survey/?destRedirectURL=https%3A%2F%2Fwww.linkedin.com%2Fsearch%2Fresults%2Fall%2F%3Fkeywords%3Dtest%2520card%2520bugbounty%26origin%3DGLOBAL SEARCH HEADER%26sid%3Dn%253Bl`
- **Lack of URL normalization renders Blocked-Previews feature ineffectual** — `#1102764` · Slack · $1,000 · ▲100
  > with [Microsoft Outlook](https://hackerone.com/redirect?url=https%3A%2F%2Fslackhq.com%2Fincrease-everyday-productivity-with-office-365-apps-for-slack)).
- **Malformed save files (.sav) allow to write files with arbitrary extensions and content in GoldSrc-based games.** — `#458842` · Valve · $1,500 · ▲99
  > - sets the directory against which the engine will try to load the client library 'cl dlls/client.dll' into memory when restarted;

## Payload fragments observed

| Seen | Fragment |
|---:|---|
| 8× | `curl_multi_socket_action()` |
| 7× | `%RFLAGS.AC` |
| 7× | `jobert@mydocz.cosmic` |
| 6× | `<a>` |
| 6× | `free()` |
| 6× | `javascript:` |
| 6× | `curl_multi_perform()` |
| 5× | `multi->process` |
| 5× | `--url @file` |
| 4× | `ExternalMemoryAccounter::Increase()` |
| 4× | `__%48ost-` |
| 4× | `wcurl -- "$url` |
| 4× | `parse_netscape()` |
| 4× | `multi_run_dirty()` |
| 4× | `smbc->share` |
| 4× | `swrite()` |
| 4× | `digest->origin` |
| 3× | `copyin()` |
| 3× | `<iframe>` |
| 3× | `^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$` |

## Parameters observed

`username` · `password` · `template` · `url` · `hash` · `id` · `callback` · `ingredients[]` · `email` · `variant` · `shop` · `month` · `year` · `report_id` · `checkout_token` · `template[]` · `next` · `data` · `token` · `subject`

## Nuclei

Start broad, then classify the root cause and open the matching skill.

```sh
nuclei -u https://target -tags vuln,cve,exposure \
       -severity low,medium,high,critical -rl 40 -o nuclei_other.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures \
       -rl 40 -o nuclei_other_exposures.txt
nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \
       -rl 40 -o nuclei_other_generic.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_other.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_other.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_other.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_other.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

## Search
```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class other
```
