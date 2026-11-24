# TRIAGE & VALIDATION — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## THE LAYER-ORDERING TRAP — read before claiming any auth bypass



**A validation error does NOT prove you passed authentication.**



This is the highest-confidence false positive in the auth-bypass class, because the

evidence looks concrete. The reasoning that fails:



> "I sent an unauthenticated request and got back `400 — field X is required`.

> A validation error means the request cleared auth and reached business logic.

> Therefore auth is missing."



That inference is only valid if auth runs *before* input handling. Many stacks put a

**global input sanitiser, body parser, or schema filter in front of the auth

middleware.** A malformed body is then rejected before auth is ever consulted, and

the response is indistinguishable from "auth passed, validation failed."



**The test: re-send with a minimal WELL-FORMED body.**



```bash

# malformed body — trips the sanitiser, which runs FIRST

curl -s -X POST https://target/api/v1/resource -d '{'

# 400 {"code":"ERR-INPUT-0001","message":"Invalid text. Only permitted

#      characters are allowed"}                      <- looks like auth bypass



# same endpoint, well-formed empty object — now auth is reached

curl -s -X POST https://target/api/v1/resource -H 'Content-Type: application/json' -d '{}'

# 401 {"code":"ERR-AUTH-0001","message":"Not authenticated. Please log in."}

```



**Only the second response tells you where the auth layer sits.**



**Lesson from an authorized engagement.** On a production API, a malformed body

returned a validation-shaped `400` on the large majority of endpoints tested. Read

as an auth bypass, that is a Critical filed against production infrastructure

covering financial and administrative operations. It was a sanitiser reacting to

the `{` character before auth ran — every one of those endpoints returned `401` to

a well-formed `{}`. The false Critical was avoided only because someone re-tested.



**Rules:**

- Layer ordering is not observable from a single response. Never infer it.

- Probe auth with the *simplest valid* body the parser will accept, not a malformed one.

- If the error text is about **input shape or character class**, you are talking to a

  parser or sanitiser, not to business logic.

- If the error text names a **domain field** (`accountId is required`) AND a

  well-formed body still returns it, that is a real signal — proceed to Q6.

- Applies equally to WAF and CDN layers: an edge block is not an origin response.



---
