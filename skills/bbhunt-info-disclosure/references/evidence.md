# Evidence appendix — Information Disclosure

Mined from all **1827 valid disclosed reports** for this class (339 paid, 19% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| public source-code / repo review | 243 |
| admin / privileged-role context | 215 |
| encoding / double-encode / null byte | 162 |
| internal service / port / container | 159 |
| file upload / filename / extension | 154 |
| header injection (Host / X-Forwarded / etc.) | 142 |
| Content-Type / body-format switch | 128 |
| cache / CDN / unkeyed header | 125 |
| subdomain / DNS / cert-transparency recon | 106 |
| error message / stack trace probing | 99 |
| XML / SOAP / SAML / XXE | 92 |
| public bucket / storage exposure | 87 |
| unauthenticated / removed-cookie test | 85 |
| webhook / OAuth / SAML / integration abuse | 84 |
| HTTP method / verb tampering | 77 |
| two-account / cross-account replay | 73 |
| employee / developer public info | 65 |
| parameter pollution / duplicate keys | 64 |
| intercept & replay request in Burp | 60 |
| race / concurrency / timing | 57 |
| third-party data / paste / breach reuse | 53 |
| verbose debug / framework fingerprint | 53 |
| second-order / stored / blind delivery | 53 |
| DOM / HTML source inspection | 48 |
| fuzzing / wordlist brute force | 45 |
| API docs / Swagger / introspection | 43 |
| cloud metadata / IAM abuse | 41 |
| JWT / token / base64 decode | 36 |
| JS bundle / source-map inspection | 35 |
| WAF / sanitizer / filter bypass | 32 |
| OAST / DNS / HTTP callback proof | 28 |
|  HosT/absolute-URL reset poisoning | 28 |
| redirect chain / Location header | 27 |
| git history / exposed .git | 25 |
| swap object ID / parameter value | 22 |
| search-engine dorking | 20 |
| browser DevTools / network tab | 18 |
| parser confusion / normalization | 17 |
| response diff / status / length comparison | 14 |
| archive / Wayback endpoint discovery | 12 |
| deserialization / gadget chain | 10 |
| replay / modify a captured request | 9 |
| template injection (SSTI) | 8 |
| mass assignment / extra request fields | 3 |

## Tools mentioned

| Item | Count |
|---|---:|
| source-code-review | 205 |
| browser | 141 |
| curl | 140 |
| devtools | 76 |
| burp | 65 |
| python | 52 |
| git | 46 |
| javascript-debugging | 28 |
| burp-repeater | 16 |
| burp-intruder | 9 |
| burp-collaborator | 7 |
| collaborator/oast | 7 |
| nmap | 6 |
| beautifier | 6 |
| shodan | 5 |
| sqlmap | 4 |
| jq | 4 |
| ffuf | 3 |
| waybackurls | 3 |
| zap | 2 |

## Bypass primitives

| Item | Count |
|---|---:|
| content-type | 218 |
| bypass | 103 |
| whitelist | 33 |
| bypassed | 23 |
| bypasses | 20 |
| content type | 20 |
| host header | 19 |
| bypassing | 18 |
| blacklist | 18 |
| blind | 15 |
| url encoded | 14 |
| open redirect | 11 |
| normalized | 11 |
| lowercase | 8 |
| transfer-encoding | 7 |
| race condition | 7 |
| unicode | 5 |
| chunked | 5 |
| url encoding | 5 |
| uppercase | 4 |
| http method | 3 |
| trailing dot | 3 |
| mixed case | 3 |
| desync | 3 |
| backslash | 2 |
| %00 | 2 |
| url encode | 2 |
| normalization | 2 |

## Impact language

| Item | Count |
|---|---:|
| password | 854 |
| token | 748 |
| admin | 651 |
| secret | 447 |
| credential | 422 |
| sensitive information | 235 |
| payment | 182 |
| localhost | 155 |
| unauthorized | 121 |
| pii | 96 |
| sensitive data | 81 |
| api key | 57 |
| rce | 23 |
| arbitrary file | 18 |
| exfiltrate | 17 |
| full access | 15 |
| personally identifiable | 15 |
| exfiltration | 12 |
| unauthorised | 12 |
| financial | 12 |

## Parameters observed

| Item | Count |
|---|---:|
| max-age | 30 |
| charset | 27 |
| path | 22 |
| domain | 20 |
| name | 16 |
| type | 15 |
| col | 12 |
| height | 12 |
| username | 11 |
| sid | 10 |
| href | 7 |
| mode | 7 |
| session | 7 |
| url | 7 |
| expires | 7 |
| src | 7 |
| no_proxy | 7 |
| phpsessid | 6 |
| _ga | 6 |
| new_env | 6 |
| prove | 6 |
| query | 6 |
| __cfduid | 5 |
| csrftoken | 5 |
| email | 5 |
| class | 5 |
| value | 5 |
| template | 5 |
| password | 5 |
| debug | 5 |

## Recurring approach patterns

- **2×** hi i found an information disclosure vulnerability full path disclosure on your application
  - e.g. Hi, I found an information disclosure vulnerability/Full Path Disclosure on your application.
- **2×** proof of concept sign in as a normal user i used my personal email address on the domain
  - e.g. # Proof of concept Sign in as a normal user - I used my personal email address on the domain.
- **2×** i was able to fire this feature using gab2 subtitle chunks inside an avi file
  - e.g. I was able to fire this feature using GAB2 subtitle chunks inside an AVI file.
- **2×** even though tokens were immediately invalidated we decided to re engineer the process to eliminate any possibility of token leakage
  - e.g. Even though tokens were immediately invalidated, we decided to re-engineer the process to eliminate any possibility of token leakage.
- **2×** reference impact the secure flag is an option that can be set by the application server when sending a new cookie to the user within an http response
  - e.g. Reference:- ## Impact The secure flag is an option that can be set by the application server when sending a new cookie to the user within an HTTP Response.
- **2×** description during poking around range looking for the cisco devices i came across which resolved to the while it s a not mil host it s likely related to the dod since it hosted in the dod controlled asn
  - e.g. ##Description During poking around `██████.00/24` range - ██████████ looking for the Cisco devices, I came across `███` which resolved to the While it's a not `.mil` host, it's likely related to the DoD since it hosted in the DoD-controlled ASN.
- **2×** at the following address i have found debug log file disclose the application full path on the server
  - e.g. At the following address i have found debug.log file disclose the application full path on the server.
- **2×** i found that at least userid and password combination from that compromised db can still be used
  - e.g. I found that at least 1 userid and password combination from that compromised db can still be used.
- **2×** description hi while going through the testing of dod assets i have came across a subdomain that is vulnerable to cve
  - e.g. **Description:** Hi, While going through the testing of DoD assets, I have came across a subdomain that is vulnerable to CVE-2020-14179.
- **2×** and now we found a directory is jira sensitive
  - e.g. And now we found a directory is jira sensitive 1.
- **2×** i created this php code for testing
  - e.g. I created this PHP code for testing.
- **2×** ai disclosure i used an ai assistant claude for code review test setup and drafting
  - e.g. AI disclosure: I used an AI assistant (Claude) for code review, test setup and drafting.
- **1×** which is why i added a frontend that is tested under the following conditions
  - e.g. Which is why I added a 'frontend' that is tested under the following conditions.
- **1×** see attached hackerone2 jpg i have read this workaround in a post by sir troy hunt sending an email a notification that the user is already registered if registered or a link to continue the registration process if still not registered
  - e.g. See attached ( hackerone2.jpg ) I have read this workaround in a post by sir Troy Hunt, sending an email, a notification that the user is already registered ( if registered ) or a link to continue the registration process ( if still not registered ).
- **1×** i have tried to check if cross site tracing is possible fired up my command line and curl x trace www relateiq com
  - e.g. I have tried to check if Cross Site Tracing is possible, fired up my command line and curl -X TRACE www.relateIQ.com.
- **1×** hello while i was testing the upload method on i have found that if you try to upload a php file or any other file html in this shape test php jpg an information disclosure will happen showing the webroot of the server
  - e.g. Hello, While I was testing The upload method on , I have found that if you try to upload a php file or any other file html in this shape (test.php.jpg) , an Information Disclosure will happen showing the webroot of the server.
- **1×** i attempted email addresses threads simultaneously via burp suite intruder
  - e.g. I attempted 80 email addresses, 5 threads simultaneously via Burp Suite Intruder.
- **1×** bitcoin wallet leaks the oauth response code which can be obtained using adb logcat s coinbase command line for testing and any android application on the same phone can read the response code for the user by reading the logs
  - e.g. "BitCoin Wallet" leaks the **OAuth** Response Code which can be obtained using `adb logcat -s Coinbase` command line for testing, and any Android application on the same phone can read the response code for the user by reading the logs.
- **1×** hello i have found a full path disclosure on a website that runs a wordpress installation
  - e.g. Hello, I have found a full path disclosure on a website that runs a wordpress installation.
- **1×** hello i found a information disclosure vulnerability
  - e.g. Hello, I found a information disclosure vulnerability.
- **1×** during the import of an xml file i edited the file to url for importing xml s through url so it became and then i tried to import a random xml file i tried with this it was not a valid xml file and after the importing it showed the following error which discloses full path of the application
  - e.g. During the import of an XML file,I edited the "file" to "url" for importing XML's through URL.So it became: And then I tried to import a random XML file.I tried with this: It was not a valid XML file.And after the importing it showed the following error which discloses full path of the application.
- **1×** the information from page warning trim expects parameter to be string array given in var www vhosts lvps178 dedicated hosteurope de httpdocs localize classes phrase php on line i also added a screenshot of that fpd as attachment
  - e.g. ### The information from page: > Warning: trim() expects parameter 1 to be string, array given in /var/www/vhosts/lvps178-77-99-228.dedicated.hosteurope.de/httpdocs_localize/classes/Phrase.php on line 213 I Also Added a Screenshot of that FPD as attachment..
- **1×** hi i found a information disclosure vulnerability full path disclosure vulnerable link you can see in the page the path of the site fatal error call to undefined function deprecated file in home jaalweb stopthehacker com wp includes rss functions php on line regards florin
  - e.g. Hi, I found a information disclosure vulnerability(Full path disclosure) Vulnerable link : You can see in the page the path of the site Fatal error: Call to undefined function _deprecated_file() in /home/jaalweb/stopthehacker.com/wp-includes/rss-functions.php on line 8 Regards, Florin
- **1×** suggestion i saw that you rejected many path disclosure reports cause those are not in your hand it depends upon server settings how that will handle error messages but this case is different its not actually an error message and cant be mitigated by switching off error display
  - e.g. **Suggestion** I saw that you rejected many path disclosure reports cause those are not in your hand.It depends upon server settings,how that will handle error messages.But this case is different.Its not actually an error message.And cant be mitigated by switching off error display.

## Case studies (full excerpts)

### 2032716 — An attacker can can view any hacker email via  /SaveCollaboratorsMutation operation name
HackerOne · $12500 · high · https://hackerone.com/reports/2032716

**Summary:** An attacker can view any attacker or normal user email after send invitation via dummy report , disclose their private email. **Description:** ### Steps To Reproduce 1 - Create a dummy report and send it 2 - Add a hacker that you want to disclose his email , Max is only 2 invites per report 3 - send the invite after sending the invite the hacker will be pending status until accept the report . 4- Go the pen on the right for adding more collaborator and click on the pen and capture traffic , you will see the user email in first request, even that the user not accept the invitation yet HTTP Request : ` Example : Here is email for todayisnew , Hacker 1 rank in H1 : Video PoC : ████████ ## Impact An attacker can view any user's email registered with Hackerone as hacker .

### 186230 — Internal attachments can be exported via "Export as .zip" feature
HackerOne · $12500 · high · https://hackerone.com/reports/186230

Hello HackerOne Team This newly disclosed report: #182358 __Partial disclosure of report activity through new "Export as .zip" feature__ was not completely fix. I have found that i can still view the attachment after it is being removed on the thread. Best PoC is this #182358 since this is the newly fix and disclosed. Steps to reproduce 1. Go to 2. Export the report as .zip 3. Now extract the .zip file (`HackerOne_Report-security#182358.zip`) 4. You will see that the image is still there, but base on the thread, you guys removed it on disclosed report. I have attached the .zip file downloaded and save on my local and i can still view the removed image. __Disclosed partially removed attachment:__ {F138022} Regards Japz

### 509924 — JSON serialization of any Project model results in all Runner tokens being exposed through Quick Actions
GitLab · $12000 · critical · https://hackerone.com/reports/509924

The Quick Actions interpreter allows an attacker to reference a Project it does not have access to. The model attributes are then being serialized and returned to the user, which results in the Runner token (both encrypted and unencrypted) being returned to the user. This vulnerability is currently exploitable on GitLab.com. # Proof of concept The vulnerability is relatively straightforward to reproduce. 1. Create a project 1. Create an issue 1. Write `/move <full path of any other project>` and click "Comment", a request to `/:namespace/:project/notes` is submitted 1. Observe the JSON response that is being returned, which contains the serialized Project model: ## Impact This vulnerability gives any user who can create an Issue or comment on one the ability to obtain Runner tokens of Projects. This allows any user to register a runner for a project, which may give the attacker access to secret project variables. Given how these variables are used, this may allow an attacker to deploy arbitrary code to a victim's environment.

### 663628 — Access to multiple production Grafana dashboards
Snapchat · $10000 · high · https://hackerone.com/reports/663628

@damian89 found a production Grafana instance which displayed confidential metrics inside various dashboards. While fuzzing patterns of certain snapchat related projects, I was able to find an instance of Grafana which was accessible by a guest user. That instance contained hundreds of production dashboards, valuable data about company. Furthermore one of the custom modules was vulnerable to SQL Injection.

### 850447 — gitlab-workhorse bypass in Gitlab::Middleware::Multipart allowing files in `allowed_paths` to be read
GitLab · $10000 · critical · https://hackerone.com/reports/850447

### Summary Extracted from While testing and looking at the patch for the nuget package workhorse bypass ( I think) I came across a more widespread bypass: Using `[package]` as the field name causes the `@rewritten_fields` to contain: This is then used `parsed_field = Rack::Utils.parse_nested_query(field)` which ends up creating the hash `{"package"=>nil}` (same as package would return). This passes the validation, but the `Multipart::Handler` will then use the query params as they match instead of the payload that workhorse sends through. This also allows for any file in the following to be accessed: This could be done anywhere that accelerated uploads, eg the `UploadsController` or uploading a wiki file. Using the wiki api removes the restriction that the file needs to be owned by `git` due to `file_content: attrs[:file].read` happening instead of moving the original file: It's also fairly easy to steal incoming files tmp files that are currently opened in rails by: 1. Determine a valid PID by looping over `/proc/PID` until a `cwd` is found and readable by `git` (eg the `unicorn` worker will have `/proc/19606/cwd -> /var/opt/gitlab/gitlab-rails/working`) and traverse to a valid upload path: 1. Using this pid, use `/proc/PID/fd/XX` as the `file.path` (looking at my server a fd of 44 was the used pretty consistently for tmp files) and run it in a loop: 1. Upload a bunch of thin

### 489146 — Confidential data of users and limited metadata of programs and reports accessible via GraphQL
HackerOne · no bounty (valid finding) · critical · https://hackerone.com/reports/489146

**Summary:** The GraphQL endpoint doesn't have access controls implemented properly. **Description:** Any attacker can get personally identifiable information of users of Hackerone such as email address, backup hash codes, facebook_user_id, account_recovery_phone_number_verified_at, totp_enabled, etc. These are just some examples of fields which are getting leaked directly from GraphQL. This is the request sent to GraphQL: Sample Response: █████████ Please fix it. Thanks, Yash :) ## Impact This could potentially leak many users' info

### 542340 — Sensitive user information disclosure at bonjour.uber.com/marketplace/_rpc via the 'userUuid' parameter
Uber · no bounty (valid finding) · high · https://hackerone.com/reports/542340

It was possible for an attacker to insert another user’s UUID into the userUuid POST parameter when making a request to allowing them to retrieve personal data from the victim user’s account, as well as the user's mobile auth token, which could allow them to make requests to mobile APIs as the victim. Thanks again, @appsecure_in! Public API endpoint leaked mobile API token of a user by passing driver uuid/rider uuid in the request. Using the API token attacker could have gained full access to driver/rider account.

## Field playbook (unedited)

### quick

- Fuzz for debug endpoints: /debug, /actuator, /health, /metrics, /graphql, .env, .git, source maps.
- Check error handling for stack traces, SQL errors, internal hosts, and versions.
- Look for extra fields, deleted records, internal notes, PII, tokens in API responses.
- Enumerate cloud storage, backups, DB dumps, log archives, CI artifacts.

### payloads

- `/.git/config` `/.env` `/.DS_Store` `/server-status` `/actuator/env`
- `/api/v1/users?limit=1000` `/api/v1/users/0`
- `?fields=all` `?expand=*` `?include=deleted`
- S3 -> `https://bucket.s3.amazonaws.com/?list-type=2`

### bypass

- Bypass auth on static/debug paths with path normalization.
- Use GraphQL introspection and field suggestions.
- Check cache headers for private data.

### surface

- debug
- actuator
- health
- metrics
- env
- backup
- export
- logs
- graphql

### tools

- ffuf
- gobuster
- nuclei
- trufflehog
- waybackurls

### chain

- Info leak -> creds -> ATO.
- Debug endpoint -> RCE.
- PII leak -> compliance impact.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class info-disclosure
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class info-disclosure --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
