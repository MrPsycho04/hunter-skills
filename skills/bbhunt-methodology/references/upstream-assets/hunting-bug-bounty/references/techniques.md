# Bug Bounty Master Workflow — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## FFUF Advanced Techniques

```bash

# THE ONE RULE: Always use -ac (auto-calibrate filters noise automatically)

ffuf -w wordlist.txt -u https://target.com/FUZZ -ac



# Authenticated raw request file — IDOR testing (save Burp request to req.txt, replace ID with FUZZ)

seq 1 10000 | ffuf --request req.txt -w - -ac



# Authenticated API endpoint brute

ffuf -u https://TARGET/api/FUZZ -w wordlist.txt -H "Cookie: session=TOKEN" -ac



# Parameter discovery

ffuf -w ~/wordlists/burp-parameter-names.txt -u "https://target.com/api/endpoint?FUZZ=test" -ac -mc 200



# Hidden POST parameters

ffuf -w ~/wordlists/burp-parameter-names.txt -X POST -d "FUZZ=test" -u "https://target.com/api/endpoint" -ac



# Subdomain scan

ffuf -w subs.txt -u https://FUZZ.target.com -ac



# Filter strategies:

# -fc 404,403          Filter status codes

# -fs 1234             Filter by response size

# -fw 50               Filter by word count

# -fr "not found"      Filter regex in response body

# -rate 5 -t 10        Rate limit + fewer threads for stealth

# -e .php,.bak,.old    Add extensions

# -o results.json      Save output

```



## Quick Wins Checklist

- [ ] Subdomain takeover (`subjack`, `subzy`)

- [ ] Exposed `.git` (`/.git/config`)

- [ ] Exposed env files (`/.env`, `/.env.local`)

- [ ] Default credentials on admin panels

- [ ] JS secrets (SecretFinder, jsluice)

- [ ] Open redirects (`?redirect=`, `?next=`, `?url=`)

- [ ] CORS misconfig (test `Origin: https://evil.com` + credentials)

- [ ] S3/cloud buckets

- [ ] GraphQL introspection enabled

- [ ] Spring actuators (`/actuator/env`, `/actuator/heapdump`)

- [ ] Firebase open read (`https://TARGET.firebaseio.com/.json`)



## Framework Quick Wins



**Laravel**: `/horizon`, `/telescope`, `/.env`, `/storage/logs/laravel.log`

**WordPress**: `/wp-json/wp/v2/users`, `/xmlrpc.php`, `/?author=1`

**Node.js**: `/.env`, `/graphql` (introspection), `/_debug`

**AWS Cognito**: `/oauth2/userInfo` (leaks Pool ID), CORS reflects arbitrary origins
