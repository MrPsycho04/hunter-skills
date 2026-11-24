# LLM Ai — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Test direct prompt injection and instruction override; check system-prompt leakage.

- Test indirect injection through documents, web pages, emails, and tool outputs.

- Map agent tools and permissions for confused-deputy issues.

- Probe RAG for cross-tenant retrieval and embedding leakage.

- Test output handling: markdown/HTML injection, link rendering, code execution.



## Bypass tricks



- Encoding, roleplay, multi-turn, and translation to bypass guardrails.

- Split the payload across retrieved chunks.



## Deeper checklist



- Test direct prompt injection and instruction override; check system-prompt leakage.

- Test indirect injection through documents, web pages, emails, and tool outputs.

- Map agent tools and permissions; look for confused-deputy and SSRF/command execution.

- Probe RAG for cross-tenant retrieval and embedding leakage.

- Test output handling: markdown/HTML injection, link rendering, code execution.

- Check guardrail bypass with encoding, roleplay, and multi-turn strategies.

- Show a concrete impact: data exfiltration, unauthorized action, or cost abuse.



## Techniques from real reports



One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.



- **LLM01: Invisible Prompt Injection** — `#2372363` · HackerOne · $0 · ▲159

  > You can paste the report above into a website like this to see the hidden payload: https://www.soscisurvey.de/tools/view-chars.php or https://embracethered.com/blog/ascii-smuggler.html

- **Prompt Injection via GitHub Patch in Brave AI Chat (Leo)** — `#3086301` · Brave Software · $0 · ▲77

  > Analysis of `EngineConsumer` implementations (`EngineConsumerConversationAPI`, `EngineConsumerLlamaRemote`, `EngineConsumerClaudeRemote`, `EngineConsumerOAIRemote`) shows that `SanitizeInput` is either empty or only removes model-specific control sequences…

- **LLM03: Training Data Poisoning via ASCII decoding** — `#2370955` · HackerOne · $0 · ▲61

  > Furthermore, the AI was forced to use offensive language, as evidenced by its response: "FUCK YOU NO I WONT TRANSLATE." , ==besides that, when Hai was asked by the program manager to transalte another message, Hai rejected that claiming that hacktus asked him…

- **UI Consent Bypass via Comma Injection in `addAutoApproveTarget` — User-Approval Dialog and Persistence Layer Disagree on Target Scope, Yielding Authen** — `#3717354` · PortSwigger Web Security · $0 · ▲28

  > A single user click on the per-request approval dialog persists an attacker-controlled comma-separated hostname as multiple independent allow-list entries, because ` autoApproveTargets` is stored as a comma-joined string and `getAutoApproveTargetsList`…

- **Account/Repository Takeover via Abandoned GitHub Username in curl's href_extractor.c** — `#3295738` · curl · $0 · ▲19

  > The href extractor.c example in the curl repository (https://github.com/curl/curl/blob/master/docs/examples/href extractor.c) references an external HTML parser library hosted at https://github.com/arjunc77/htmlstreamparser.



## Case studies



### LLM01: Invisible Prompt Injection

`#2372363` · HackerOne · $0 · medium · 2024-05-13 · ▲159

> Hey team, Hai is vulnerable to invisible prompt injection via Unicode tag characters.



### Prompt Injection via GitHub Patch in Brave AI Chat (Leo)

`#3086301` · Brave Software · $0 · high · 2025-08-22 · ▲77

> The Brave AI Chat feature allows fetching .patch files from GitHub pull request pages to use as context. A combination of insufficient path sanitization during URL construction and reliance on default URL normalization allows an attacker to specify a crafted GitHub PR URL that, when processed by the Leo AI Chat feature, results in fetching a .patch file from an arbitrary public GitHub repository.



### LLM03: Training Data Poisoning via ASCII decoding

`#2370955` · HackerOne · $0 · none · 2024-05-28 · ▲61

> I have identified a vulnerability in the Hai AI chat system, following an invitation by HackerOne for a ==spot check==. This vulnerability centers around the AI's handling of ASCII encoded messages. Specifically, I found that by encoding a message into ASCII format and then asking Hai to decode and respond, the AI could be manipulated into parroting the exact content of the decoded message, irrespective of its appropriateness or alignment with its normal…



### UI Consent Bypass via Comma Injection in `addAutoApproveTarget` — User-Approval Dialog and Persistence Layer Disagree on Target Scope, Yielding Authen

`#3717354` · PortSwigger Web Security · $0 · none · 2026-06-15 · ▲28

> Burp Suite MCP Server BApp v1.2.1 fails to validate hostnames passed to addAutoApproveTarget (McpConfig.kt:52). A single user click on the per-request approval dialog persists an attacker-controlled comma-separated hostname as multiple independent allow-list entries, because autoApproveTargets is stored as a comma-joined string and getAutoApproveTargetsList re-splits on , (McpConfig.kt:73).



### Account/Repository Takeover via Abandoned GitHub Username in curl's href_extractor.c

`#3295738` · curl · $0 · medium · 2025-08-12 · ▲19

> The href extractor.c example in the curl repository (https://github.com/curl/curl/blob/master/docs/examples/href extractor.c) references an external HTML parser library hosted at https://github.com/arjunc77/htmlstreamparser. The referenced GitHub username (arjunc77) or repository (htmlstreamparser) appears to be abandoned or deleted, allowing me to register the same username and host a repository with the same name.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class llm-ai --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class llm-ai

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class llm-ai

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class llm-ai --min-bounty 1000

```
