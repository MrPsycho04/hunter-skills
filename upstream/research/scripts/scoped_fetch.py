#!/usr/bin/env python3
"""Scoped, rate-limited downloader for js-collect.

Every request to the target must go through this script. It:
  * refuses any URL outside scope.txt (allow list + !exclusions, host and path)
  * enforces the rate ceiling in rate.txt (requests/second)
  * re-checks scope on every redirect hop (no silent hops out of scope)
  * stores bytes content-addressed (cas/sha256/<hash>) and logs to manifest.json
  * updates manifest in place across runs (first_seen_run / changed_since_last_run)
  * isolates per-URL failures (one timeout does not abort the batch)

Usage:
  scoped_fetch.py --dir js-collect-output/target --via "katana -jc" URL [URL ...]
  scoped_fetch.py --dir ... --urls-file urls.txt
  scoped_fetch.py --dir ... --header "Cookie: session=..." URL

  --urls-file accepts one entry per line:
      URL                       (uses --via for provenance)
      URL<TAB>discovered-via    (per-URL provenance, e.g. "dj webpack chunk")
      # comment lines and blank lines are skipped

TLS impersonation is OFF by default. Enable it only if the program explicitly
allows working around bot protection:
  --impersonate chrome124 --confirm-program-allows-bypass
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode

MAX_REDIRECTS = 5
MAX_BYTES = 25 * 1024 * 1024
REDIRECT_CODES = {301, 302, 303, 307, 308}

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
}


def now():
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Scope                                                                        #
# --------------------------------------------------------------------------- #
def load_rules(path):
    """Return (allow, deny). Patterns may be host-only or host+path."""
    allow, deny = [], []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            negate = line.startswith("!")
            pat = line[1:].strip() if negate else line
            # Lowercase the host portion only; preserve path case.
            if "/" in pat:
                host, _, rest = pat.partition("/")
                pat = host.lower() + "/" + rest
            else:
                pat = pat.lower()
            (deny if negate else allow).append(pat)
    if not allow:
        sys.exit("scope.txt has no allow entries; refusing to run")
    return allow, deny


def _matches(pattern, host, host_path):
    return fnmatchcase(host_path, pattern) if "/" in pattern else fnmatchcase(host, pattern)


def in_scope(url, allow, deny):
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    host = p.hostname.lower()
    host_path = host + (p.path or "/")
    if any(_matches(d, host, host_path) for d in deny):
        return False
    return any(_matches(a, host, host_path) for a in allow)


def load_rate(path):
    try:
        with open(path, encoding="utf-8") as fh:
            rate = float(fh.read().strip())
    except (OSError, ValueError):
        rate = 2.0
    return max(rate, 0.01)


# --------------------------------------------------------------------------- #
# URL normalization (dedupe within a run)                                      #
# --------------------------------------------------------------------------- #
def normalize_url(url):
    p = urlparse(url.strip())
    if not p.scheme or not p.hostname:
        return url.strip()
    netloc = p.hostname.lower()
    if p.port:
        netloc += f":{p.port}"
    query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
    return urlunparse((p.scheme.lower(), netloc, p.path or "/", "", query, ""))


# --------------------------------------------------------------------------- #
# HTTP                                                                         #
# --------------------------------------------------------------------------- #
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def raw_get(url, headers, impersonate):
    """One request, never following redirects. Returns (status, headers, body).

    Raises ValueError for oversize bodies; lets network errors propagate.
    """
    if impersonate:
        try:
            from curl_cffi import requests as cr  # pip install curl_cffi
        except ImportError:
            sys.exit("--impersonate requires curl_cffi: pip install curl_cffi")
        r = cr.get(url, headers=headers, impersonate=impersonate,
                   allow_redirects=False, timeout=30, stream=True)
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        clen = hdrs.get("content-length")
        if clen and clen.isdigit() and int(clen) > MAX_BYTES:
            raise ValueError(f"response too large: {clen} > {MAX_BYTES}")
        body = b"".join(r.iter_content(64 * 1024))
        if len(body) > MAX_BYTES:
            raise ValueError(f"response too large: >{MAX_BYTES}")
        return r.status_code, hdrs, body

    req = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=30) as r:
            data = r.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError(f"response too large: >{MAX_BYTES}")
            return r.status, {k.lower(): v for k, v in r.headers.items()}, data
    except urllib.error.HTTPError as e:
        body = e.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            body = b""  # don't store truncated error pages
        return e.code, {k.lower(): v for k, v in e.headers.items()}, body


# --------------------------------------------------------------------------- #
# Fetcher                                                                      #
# --------------------------------------------------------------------------- #
class Fetcher:
    def __init__(self, base, via, headers, impersonate):
        self.base = base
        self.via = via
        self.headers = headers
        self.impersonate = impersonate
        self.allow, self.deny = load_rules(os.path.join(base, "scope.txt"))
        self.interval = 1.0 / load_rate(os.path.join(base, "rate.txt"))
        self.last = 0.0
        self.manifest_path = os.path.join(base, "manifest.json")

        for d in ("cas/sha256", "raw"):
            os.makedirs(os.path.join(base, d), exist_ok=True)

        if os.path.exists(self.manifest_path):
            with open(self.manifest_path, encoding="utf-8") as fh:
                self.manifest = json.load(fh)
        else:
            self.manifest = {
                "run_contract": {
                    "scope": self.allow,
                    "exclude": self.deny,
                    "rate_rps": 1.0 / self.interval,
                    "started": now(),
                },
                "files": [],
            }
        self.index = {f["url"]: f for f in self.manifest.get("files", []) if f.get("url")}

    # -- rate limiter ------------------------------------------------------ #
    def wait(self):
        delay = self.interval - (time.monotonic() - self.last)
        if delay > 0:
            time.sleep(delay)
        self.last = time.monotonic()

    # -- fetch with per-hop scope check ----------------------------------- #
    def fetch(self, url, via=None):
        via = via or self.via
        original = url
        for _ in range(MAX_REDIRECTS + 1):
            if not in_scope(url, self.allow, self.deny):
                print(f"[SKIP out of scope] {url}", file=sys.stderr)
                self.log(original, via=via, error="out_of_scope")
                return None
            self.wait()
            try:
                status, hdrs, body = raw_get(url, self.headers, self.impersonate)
            except Exception as e:
                print(f"[ERROR {type(e).__name__}] {url}: {e}", file=sys.stderr)
                self.log(original, via=via, error=f"{type(e).__name__}: {e}")
                return None
            if status in REDIRECT_CODES and "location" in hdrs:
                url = urljoin(url, hdrs["location"])
                continue
            break
        else:
            print(f"[SKIP too many redirects] {original}", file=sys.stderr)
            self.log(original, via=via, error="too_many_redirects")
            return None

        if status != 200:
            print(f"[{status}] {url}", file=sys.stderr)
            self.log(original, via=via, status=status, hdrs=hdrs)
            return None

        if via in ("katana -jc", "dj webpack chunk", "inline script", "chunk manifest"):
            ct = hdrs.get("content-type", "")
            if ct and not any(t in ct for t in ("javascript", "ecmascript", "text/plain")):
                print(f"[WARN unexpected content-type {ct!r}] {url}", file=sys.stderr)

        return self.store(original, url, body, status, hdrs, via)

    # -- storage ----------------------------------------------------------- #
    def logical_path(self, url, digest):
        name = os.path.basename(urlparse(url).path) or "index"
        cas_abs = os.path.abspath(os.path.join(self.base, "cas", "sha256", digest))
        for cand in (name, f"{digest[:8]}_{name}", f"{digest[:16]}_{name}", f"{digest}_{name}"):
            logical = os.path.join(self.base, "raw", cand)
            if os.path.islink(logical) and os.readlink(logical) == cas_abs:
                return logical
            if not os.path.lexists(logical):
                return logical
        return os.path.join(self.base, "raw", f"{digest}_{name}")

    def store(self, original, final_url, body, status, hdrs, via):
        digest = hashlib.sha256(body).hexdigest()
        cas = os.path.join(self.base, "cas", "sha256", digest)
        if not os.path.exists(cas):
            tmp = cas + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(body)
            os.replace(tmp, cas)

        logical = self.logical_path(original, digest)
        if not os.path.lexists(logical):
            try:
                os.symlink(os.path.abspath(cas), logical)
            except OSError:
                shutil.copyfile(cas, logical)

        rel = os.path.relpath(logical, self.base)
        self.log(original, via=via, status=status, hdrs=hdrs,
                 digest=digest, logical=rel, size=len(body))
        print(f"[ok] {original} -> {rel}")
        return digest

    # -- manifest ---------------------------------------------------------- #
    def log(self, url, via=None, status=None, hdrs=None, digest=None,
            logical=None, size=0, error=None):
        hdrs = hdrs or {}
        entry = self.index.get(url, {})
        changed = digest is not None and entry.get("sha256") != digest
        entry.update({
            "url": url,
            "sha256": digest,
            "logical_path": logical,
            "http_status": status,
            "size_bytes": size,
            "discovered_via": via or self.via,
            "method_used": (
                f"curl_cffi impersonate={self.impersonate}"
                if self.impersonate else "urllib"
            ),
            "content_type": hdrs.get("content-type", ""),
            "etag": hdrs.get("etag", ""),
            "last_seen_run": now(),
            "changed_since_last_run": changed,
        })
        entry.setdefault("first_seen_run", now())
        if error:
            entry["error"] = error
        else:
            entry.pop("error", None)
        self.index[url] = entry

    def save(self):
        self.manifest["files"] = list(self.index.values())
        tmp = self.manifest_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.manifest, fh, indent=2)
        os.replace(tmp, self.manifest_path)


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #
def parse_urls_file(path, default_via):
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            url, _, via = line.partition("\t")
            url = url.strip()
            if not url:
                continue
            out.append((url, (via.strip() or default_via)))
    return out


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--dir", required=True,
                    help="js-collect-output/<target> (must contain scope.txt)")
    ap.add_argument("--via", default="manual",
                    help="how the URL was discovered (default provenance for this run)")
    ap.add_argument("--urls-file",
                    help="TSV: URL[<TAB>discovered-via] per line")
    ap.add_argument("--header", action="append", default=[],
                    help='e.g. "Cookie: a=b" (repeatable)')
    ap.add_argument("--impersonate",
                    help="curl_cffi browser fingerprint, e.g. chrome124")
    ap.add_argument("--confirm-program-allows-bypass", action="store_true")
    ap.add_argument("urls", nargs="*")
    a = ap.parse_args()

    if a.impersonate and not a.confirm_program_allows_bypass:
        sys.exit("--impersonate needs --confirm-program-allows-bypass "
                 "(only use it if the program permits working around bot protection)")
    if not os.path.exists(os.path.join(a.dir, "scope.txt")):
        sys.exit("missing scope.txt in --dir; create it before any request (Stage 0)")

    entries = [(u, a.via) for u in a.urls]
    if a.urls_file:
        entries += parse_urls_file(a.urls_file, a.via)

    # Dedupe by normalized URL, keep first provenance seen.
    seen = {}
    for url, via in entries:
        key = normalize_url(url)
        if key not in seen:
            seen[key] = (url, via)

    headers = dict(DEFAULT_HEADERS)
    for h in a.header:
        k, _, v = h.partition(":")
        if k.strip():
            headers[k.strip()] = v.strip()

    f = Fetcher(a.dir, a.via, headers, a.impersonate)
    try:
        for url, via in seen.values():
            f.fetch(url, via=via)
    except KeyboardInterrupt:
        print("\n[interrupted] saving manifest...", file=sys.stderr)
    finally:
        f.save()


if __name__ == "__main__":
    main()
