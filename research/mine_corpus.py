#!/usr/bin/env python3
"""Mine the local HackerOne corpus for *approach* evidence per vulnerability class.

Definition of "valid" used here (documented in the skills):
    Every publicly disclosed report in the corpus is a valid/triaged finding.
    Public disclosure on HackerOne requires the report to be resolved, and a
    large share of valid findings are resolved for NO bounty (informative,
    duplicate-of-internal, low-impact, NDA/private programs, or programs that
    simply do not pay). Payment is an impact/program signal, NOT a validity test.

    Therefore: mine ALL 15,259 disclosed reports. Bounty and severity are kept
    as *weighting / evidence-tier* signals inside each class, never as a filter.

For every report we extract:
  - approach sentences (how the hunter actually found / proved the bug)
  - tools, parameters, bypass primitives, impact language
  - case studies (highest-bounty, richest writeups)

Output is a compact JSON digest + a readable Markdown summary. Nothing here
contacts the network; it only reads the local SQLite corpus.
"""
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict

DB = os.path.expanduser("~/.local/share/hackerone-reports/reports.sqlite")
OUT = os.path.dirname(os.path.abspath(__file__))

VALID_SQL = """
SELECT id, program, title, url, upvotes, bounty, vuln_type, class, severity,
       disclosed_at, reporter, weakness, body, impact
FROM reports
"""

APPROACH_RE = re.compile(
    r"\b(i|we|the researcher|the reporter)\b.{0,40}\b"
    r"(found|noticed|discovered|observed|realized|identified|learned|figured|stumbled|"
    r"saw|spotted|tried|tested|checked|sent|replayed|modified|manipulated|changed|"
    r"removed|added|injected|fuzzed|enumerated|compared|decoded|reverse.?engineer|"
    r"looked|reviewed|dissected|analyz\w*|investigat\w*|explored|probed|attempted|"
    r"was able|managed|ended up|began|started|decided|wrote|created|built|used)\b",
    re.I,
)
CONTEXT_RE = re.compile(
    r"\b(while|when|after|before|by|during|through|using|via|with)\b.{0,60}\b"
    r"(testing|browsing|looking|fuzzing|checking|reading|reviewing|exploring|"
    r"interacting| inspecting|auditing|analys|parsing|decoding|replaying|"
    r"crafting|sending|modifying|playing|clicking|registering|logging|"
    r"comparing|diffing|scanning|enumerating)\b",
    re.I,
)

TOOLS = {
    "burp": r"\bburp(\s+suite|\s+pro)?\b",
    "burp-repeater": r"\brepeater\b",
    "burp-intruder": r"\bintruder\b",
    "burp-collaborator": r"\bcollaborator\b",
    "zap": r"\bowasp zap\b|\bzap\b",
    "ffuf": r"\bffuf\b",
    "feroxbuster": r"\bferoxbuster\b",
    "gobuster": r"\bgobuster\b",
    "dirb": r"\bdirb\b",
    "nuclei": r"\bnuclei\b",
    "sqlmap": r"\bsqlmap\b",
    "dalfox": r"\bdalfox\b",
    "xsstrike": r"\bxsstrike\b",
    "xss-server": r"\bxss(?:\s|-)server\b|\bxsshunter\b",
    "interactsh": r"\binteractsh\b|\boast\b",
    "collaborator/oast": r"\bcollaborator\b|\binteractsh\b|\bburp collaborator\b",
    "gau": r"\bgau\b|\bgetallurls\b",
    "waybackurls": r"\bwaybackurls?\b|\bwayback machine\b|\bwayback\b",
    "subfinder": r"\bsubfinder\b",
    "amass": r"\bamass\b",
    "httpx": r"\bhttpx\b",
    "curl": r"\bcurl\b",
    "postman": r"\bpostman\b",
    "devtools": r"\bdevtools\b|\bdeveloper tools\b|\bchrome\b",
    "browser": r"\bfirefox\b|\bchrome\b|\bsafari\b|\bchromium\b",
    "javascript-debugging": r"\bdebugger\b|\bconsole\.log\b|\bsource map\b|\bjs bundle\b",
    "source-code-review": r"\bsource code\b|\bsourcecode\b|\bgithub\.com\b|\bgitlab\.com\b",
    "git": r"\bgit\b|\.git\b",
    "python": r"\bpython\b",
    "jq": r"\bjq\b",
    "nmap": r"\bnmap\b",
    "masscan": r"\bmasscan\b",
    "shodan": r"\bshodan\b|\bcensys\b|\bzoomeye\b",
    "dnsdump": r"\bdnsdumpster\b|\bcrt\.sh\b|\bcertificate transparency\b",
    "beautifier": r"\bbeautif\w+\b|\bprettier\b|\bunminif\w+\b",
    "decompiler": r"\bjadx\b|\bapktool\b|\bida\b|\bghidra\b|\bhopper\b|\bfrida\b",
}
TOOLS = {k: re.compile(v, re.I) for k, v in TOOLS.items()}

BYPASS_RE = re.compile(
    r"double[- ]encod\w*|url[- ]encod\w*|percent[- ]encod\w*|html[- ]encod\w*|"
    r"unicode|null byte|%00|%0d%0a|crlf|chunked|transfer[- ]encoding|"
    r"mixed case|uppercase|lowercase|case[- ]sensitiv\w*|"
    r"whitelist|blacklist|allowlist|denylist|bypass\w*|normaliz\w*|"
    r"trailing (?:dot|slash|space)|double slash|backslash|"
    r"parser confusion|desync|race condition|time[- ]based|blind|out[- ]of[- ]band|"
    r"second[- ]order|polyglot|homoglyph|open redirect|same[- ]site|"
    r"content[- ]type|http method|verb tamper|header injection|host header|"
    r"parameter pollution|mass assignment|type confusion|null value|empty value",
    re.I,
)
IMPACT_RE = re.compile(
    r"account takeover|\bato\b|remote code execution|\brce\b|"
    r"sensitive (?:data|information)|personally identifiable|\bpii\b|"
    r"credential|password|token|api key|secret|cloud metadata|metadata service|"
    r"internal network|internal service|localhost|privilege escalation|"
    r"mass (?:assig|exfil|enum|data)|arbitrary (?:file|code|command|read|write)|"
    r"full access|admin|payment|funds|financial|data leak|exfiltrat\w*|"
    r"unauthori[sz]ed|cross[- ]tenant|tenant isolation",
    re.I,
)
PARAM_RE = re.compile(r"(?:[?&]|\b)([a-zA-Z_][\w.\-\[\]]{2,35})\s*=")
CODE_BLOCK_RE = re.compile(r"```.*?```", re.S)
URL_RE = re.compile(r"https?://\S+|/users/\d+|/reports/\d+")
WS_RE = re.compile(r"\s+")
NONWORD_RE = re.compile(r"[^a-z0-9]+")

# Canonical technique signatures. Each regex maps to a *hunter action* that
# recurs in real writeups. Counting these across all valid reports gives a
# corpus-backed frequency table of HOW bugs were actually found.
TECHNIQUES = {
    "two-account / cross-account replay": r"(second|another|two|victim|attacker|other)\s+(account|user)|creat\w+ (?:a )?(?:new|second|another|two)\s+account|cross[- ]account|different user account",
    "intercept & replay request in Burp": r"intercept\w* (?:the )?request|burp suite|\brepeater\b|\bintruder\b|proxy history",
    "replay / modify a captured request": r"replay\w* (?:the )?request|modif\w+ (?:the )?request|craft\w+ (?:a )?request|resend\w* (?:the )?request",
    "swap object ID / parameter value": r"chang\w+ (?:the )?(id|parameter|value|uuid)|replac\w+ (?:the )?(id|user|value)|increment\w* (?:the )?id|sequential id|guessable id|different id",
    "HTTP method / verb tampering": r"http method|verb tamper|chang\w+ (?:the )?method|\bput\b|\bpatch\b|\bdelete\b.*request|method override|_method",
    "Content-Type / body-format switch": r"content[- ]?type|application/json|form-data|x-www-form-urlencoded|body format|convert to json",
    "header injection (Host / X-Forwarded / etc.)": r"host header|x-forwarded|user-agent|referer|custom header|header value|abs url",
    "JS bundle / source-map inspection": r"javascript (?:bundle|file)|js (?:bundle|file|\.map)|source ?map|\.js\.map|minif\w+|webpack|chunk",
    "public source-code / repo review": r"source code|sourcecode|github\.com|gitlab\.com|repository|open[- ]source|codebase",
    "git history / exposed .git": r"\.git\b|git log|commit history|git blame",
    "fuzzing / wordlist brute force": r"\bfuzz\w*|wordlist|\bffuf\b|\bdirb\b|brute[- ]forc\w*|directory enumeration",
    "archive / Wayback endpoint discovery": r"wayback|archive\.org|\bgau\b|old (?:version|endpoint)|historical (?:url|endpoint)",
    "subdomain / DNS / cert-transparency recon": r"subdomain|dns|certificate transparency|crt\.sh|shodan|censys|passive (?:dns|recon)",
    "browser DevTools / network tab": r"network tab|devtools|developer tools|inspect element|browser console|chrome developer",
    "DOM / HTML source inspection": r"view source|html source|\bdom\b|innerhtml|javascript:|document\.|window\.",
    "OAST / DNS / HTTP callback proof": r"collaborator|interactsh|\boast\b|callback|dnslog|out[- ]of[- ]band|canary|unique url",
    "second-order / stored / blind delivery": r"second[- ]order|\bstored\b|\bblind\b|persist\w+ (?:the )?payload|later (?:view|render)",
    "encoding / double-encode / null byte": r"encod\w+|double|unicode|%00|null byte|percent[- ]encod|%25|fullwidth",
    "parser confusion / normalization": r"parser|normaliz\w*|desync|smuggl\w*|canonicali[sz]|inconsisten\w+ (?:parsing|handling)",
    "cloud metadata / IAM abuse": r"169\.254\.169\.254|metadata (?:service|endpoint)|\biam\b|\bs3\b|cloud (?:credential|instance|key)|instance metadata",
    "JWT / token / base64 decode": r"\bjwt\b|decod\w+ (?:the )?(token|cookie|string)|base64|hmac|signature",
    "webhook / OAuth / SAML / integration abuse": r"webhook|\boauth\b|\bsaml\b|\boidc\b|third[- ]party|integration|redirect_uri|sso\b",
    "admin / privileged-role context": r"\badmin\b|privileg\w+|permission|user role|role[- ]based|superuser",
    "file upload / filename / extension": r"upload|filename|file name|extension|multipart|content-disposition",
    "race / concurrency / timing": r"race condition|parallel|concurren\w+|timing|thread|simultaneous|repeat\w+ (?:the )?request",
    "cache / CDN / unkeyed header": r"cache|cdn|unkeyed|edge server|varnish|akamai|cloudflare",
    "error message / stack trace probing": r"error message|stack trace|exception|verbose error|debug output|error response",
    "parameter pollution / duplicate keys": r"parameter pollution|duplicate (?:param|key|field)|array syntax|\[\]|same parameter",
    "mass assignment / extra request fields": r"mass assignment|extra field|hidden field|add\w+ (?:a |the )?field|unexpected (?:field|parameter)|isAdmin|role.*request",
    "template injection (SSTI)": r"template injection|\{\{.*\}\}|ssti|server[- ]side template",
    "deserialization / gadget chain": r"deserializ\w+|serializ\w+|gadget|ysoserial|pickle|object injection",
    "XML / SOAP / SAML / XXE": r"\bxml\b|\bsoap\b|\bsaml\b|\bxxe\b|doctype|external entit",
    "response diff / status / length comparison": r"compar\w+ (?:the )?response|diff\w+ (?:the )?response|status code|response length|different response|error (?:differs|difference)",
    "API docs / Swagger / introspection": r"swagger|openapi|api doc|documentation|introspection|graphql schema|api schema",
    "unauthenticated / removed-cookie test": r"unauthenticated|without (?:a )?token|remov\w+ (?:the )?cookie|logged out|no authentication|anonymous",
    "redirect chain / Location header": r"redirect chain|follow\w* (?:the )?redirect|location header|open redirect|\bnext=|\breturn=|redirect_uri",
    "internal service / port / container": r"\bport\b|localhost|127\.0\.0\.1|redis|elasticsearch|docker|kubernetes|internal service|internal network",
    "public bucket / storage exposure": r"s3 bucket|public bucket|blob storage|publicly accessible|storage account|directory listing",
    "search-engine dorking": r"google dork|search engine|\bintitle:|\binurl:|dork",
    "employee / developer public info": r"employee|linkedin|github profile|personal access token|developer (?:account|email)|staff",
    "third-party data / paste / breach reuse": r"pastebin|public leak|database leak|breach|dump|credentials.*found online",
    "WAF / sanitizer / filter bypass": r"\bwaf\b|sanitiz\w+|blacklist|whitelist|allowlist|filter bypass|bypass\w* (?:the )?filter",
    "verbose debug / framework fingerprint": r"debug mode|framework|stack trace|version disclosure|\bactuator\b|telescope|ignition",
    " HosT/absolute-URL reset poisoning": r"reset (?:link|token|email)|password reset|forgot password|email change|verification link",
}
TECHNIQUES = {k: re.compile(v, re.I) for k, v in TECHNIQUES.items()}

BOILERPLATE_RE = re.compile(
    r"^(description|summary|steps to reproduce|impact|hi |hello |dear |thanks|thank you|"
    r"my reporting|i am a|i'm a|bounty|reward|note:|poc|proof of concept|updated|edit:|"
    r"this report|the following|please |can you |i would like|i hope)",
    re.I,
)


def clean(text):
    if not text:
        return ""
    text = CODE_BLOCK_RE.sub(" ", text)
    text = URL_RE.sub(" ", text)
    return WS_RE.sub(" ", text).strip()


def sentences(text):
    parts = re.split(r"(?<=[.!?])\s+|\n+", clean(text))
    return [p.strip() for p in parts if 35 <= len(p) <= 420]


def norm(s):
    s = s.lower()
    s = re.sub(r"\b\d+\b", "N", s)
    s = NONWORD_RE.sub(" ", s).strip()
    return WS_RE.sub(" ", s)


def diverse_top(counter, limit, jaccard=0.62):
    """Greedily pick frequent items that are not near-duplicates."""
    picked, picked_tokens = [], []
    for phrase, count in counter.most_common(limit * 12):
        toks = set(phrase.split())
        if len(toks) < 3:
            continue
        if any(len(toks & p) / max(1, len(toks | p)) >= jaccard for p in picked_tokens):
            continue
        picked.append({"phrase": phrase, "count": count})
        picked_tokens.append(toks)
        if len(picked) >= limit:
            break
    return picked


def main():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(VALID_SQL).fetchall()
    print(f"valid reports mined: {len(rows)}")

    by_class = defaultdict(list)
    for r in rows:
        by_class[r["class"] or "other"].append(r)

    digest = {}
    all_approach = {}
    for cls, reports in sorted(by_class.items(), key=lambda kv: -len(kv[1])):
        approach = Counter()
        approach_examples = {}
        tools = Counter()
        params = Counter()
        bypasses = Counter()
        impacts = Counter()
        techniques = Counter()
        programs = Counter()
        bounties = []
        case_rows = []
        unpaid_rows = []

        for r in reports:
            body = r["body"] or ""
            impact_text = r["impact"] or ""
            raw = f"{body}\n{impact_text}"
            programs[r["program"] or "?"] += 1
            if r["bounty"]:
                bounties.append(r["bounty"])

            for s in sentences(raw):
                if BOILERPLATE_RE.match(s):
                    continue
                if not (APPROACH_RE.search(s) or CONTEXT_RE.search(s)):
                    continue
                n = norm(s)
                if len(n.split()) < 5:
                    continue
                approach[n] += 1
                approach_examples.setdefault(n, s)

            # Count canonical hunter techniques over the WHOLE writeup. A
            # zero-bounty report is still valid evidence of how a bug was found.
            for name, rx in TECHNIQUES.items():
                if rx.search(raw):
                    techniques[name] += 1

            for name, rx in TOOLS.items():
                if rx.search(raw):
                    tools[name] += 1
            for m in BYPASS_RE.finditer(raw):
                bypasses[m.group(0).lower()] += 1
            for m in IMPACT_RE.finditer(raw):
                impacts[m.group(0).lower()] += 1
            for p in PARAM_RE.findall(clean(raw)[:6000]):
                pl = p.lower()
                if pl not in {"the", "and", "for", "with", "this", "that", "from", "http", "https", "not", "you", "are", "was"}:
                    params[pl] += 1

            # Rich writeups are evidence whether or not money changed hands.
            if len(body) > 350:
                case_rows.append(r)
                if not r["bounty"]:
                    unpaid_rows.append(r)

        case_rows.sort(key=lambda r: (-(r["bounty"] or 0), -(r["upvotes"] or 0), -(len(r["body"] or ""))))
        unpaid_rows.sort(key=lambda r: (-(r["upvotes"] or 0), -(len(r["body"] or ""))))
        # Keep at least two unpaid-but-valid case studies per class so the
        # methodology reflects the full valid set, not just the paid subset.
        selected = case_rows[:5] + unpaid_rows[:2]
        cases = []
        for r in selected:
            b = clean(r["body"])
            cases.append({
                "id": r["id"],
                "program": r["program"],
                "title": r["title"],
                "bounty": r["bounty"],
                "severity": r["severity"],
                "url": r["url"],
                "excerpt": b[:1400],
            })

        bounties.sort()
        med = bounties[len(bounties) // 2] if bounties else 0
        top_approach = diverse_top(approach, 24)
        for item in top_approach:
            item["example"] = approach_examples.get(item["phrase"], "")

        digest[cls] = {
            "valid_reports": len(reports),
            "paid_reports": len(bounties),
            "median_bounty": med,
            "top_programs": programs.most_common(12),
            "tools": tools.most_common(20),
            "techniques": techniques.most_common(50),
            "bypasses": bypasses.most_common(28),
            "impacts": impacts.most_common(20),
            "parameters": params.most_common(30),
            "approach_patterns": top_approach,
            "case_studies": cases,
        }
        all_approach[cls] = approach.most_common(120)

    with open(os.path.join(OUT, "class_digest.json"), "w") as f:
        json.dump(digest, f, indent=1)
    with open(os.path.join(OUT, "approach_frequencies.json"), "w") as f:
        json.dump(all_approach, f, indent=1)

    lines = ["# Corpus mining summary", "", f"Disclosed (valid) reports mined: {len(rows)}", "",
             "Payment is an impact signal only; zero-bounty reports are valid evidence.", ""]
    for cls, d in digest.items():
        lines += [
            f"## {cls} — {d['valid_reports']} valid / {d['paid_reports']} paid ({100*d['paid_reports']/max(1,d['valid_reports']):.0f}%) / median paid ${d['median_bounty']:.0f}",
            "",
            "**Top techniques from ALL valid writeups:** " + ", ".join(f"{k}({v})" for k, v in d["techniques"][:12]),
            "",
            "**Tools:** " + ", ".join(f"{k}({v})" for k, v in d["tools"][:10]),
            "",
            "**Bypasses:** " + ", ".join(f"{k}({v})" for k, v in d["bypasses"][:12]),
            "",
            "**Top approach patterns:**",
        ]
        for a in d["approach_patterns"][:8]:
            lines.append(f"- ({a['count']}) {a['phrase']}")
        lines.append("")
    with open(os.path.join(OUT, "summary.md"), "w") as f:
        f.write("\n".join(lines))
    print("wrote class_digest.json, approach_frequencies.json, summary.md")


if __name__ == "__main__":
    main()
