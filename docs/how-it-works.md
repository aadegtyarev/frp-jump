# How it works

frp-jump is a control plane on top of [frp](https://github.com/fatedier/frp).
frp already knows how to punch NAT holes and relay TCP. What it leaves to you is
everything around that: who exists, who may reach whom, what certificate each
machine gets, and which local port a tunnel lands on. That is what frp-jump
does.

## The three pieces

```mermaid
flowchart TB
    subgraph server["your server"]
        direction TB
        api["control plane<br/>HTTPS API"]
        db[("SQLite<br/>users · devices · grants")]
        ca["private CA"]
        relay["relay · frps<br/>:7000"]
        api --- db
        api --- ca
    end

    subgraph device["each device"]
        direction TB
        agent["agent<br/>frp-jump-client run"]
        frpc["frpc"]
        ssh["~/.ssh/config"]
        agent --> frpc
        agent --> ssh
    end

    agent -->|"every 2s: heartbeat + desired state"| api
    frpc -->|"mTLS control channel"| relay
```

**The control plane** is an HTTPS API with a SQLite database behind it. It is
metadata only. No tunneled byte ever passes through it. It also runs a private
certificate authority that issues one client certificate per device at
enrollment.

**The relay** is a stock frps process, configured by the same code that
configures frpc. It only accepts connections presenting a certificate from that
CA.

**The agent** runs on every device. It asks the control plane what this device
should be doing, rewrites frpc's config to match, restarts frpc when the config
changed, and keeps the managed part of `~/.ssh/config` in sync.

Administration is `frp-jump-server` commands over SSH to the box. There is no
web interface of any kind — SSH access to the server *is* the admin boundary,
the same as it is for anything else you run there.

## Enrolling a device

Two ways in. Both end with the same thing: a client certificate, a bearer token,
and a device row in the database.

### With your SSH key

This is the normal path, once an admin has registered your public key.

```mermaid
sequenceDiagram
    participant D as device
    participant S as server

    D->>S: POST /api/agent/enroll/challenge { public_key }
    S-->>D: a random nonce
    Note over D: ssh-keygen -Y sign<br/>private key never moves
    D->>S: POST /api/agent/enroll/by-key { challenge_id, signature, name }
    Note over S: ssh-keygen -Y verify<br/>against the stored public key
    S-->>D: certificate + CA cert + bearer token + relay address
```

The signature is namespaced (`-n frp-jump-enroll`), so it can never be replayed
as, say, a signature on a git commit. Verification shells out to real OpenSSH —
no library reimplements this.

The challenge endpoint always returns a nonce, whether or not it recognises the
fingerprint. An unknown key fails at the next step, exactly like a bad
signature. A 404 here would tell an anonymous caller which keys the server
knows.

### With a one-time token

For a device you would rather not hand a personal key to, or a person who has no
key registered yet.

```sh
frp-jump-client devices add-token --name wb01   # self-service, from your own device
frp-jump-server enroll-tokens create --user me  # or minted by an admin
```

The token is shown once, expires in 24 hours, and redeems exactly once.
Redemption is an atomic conditional update, so two machines racing on the same
token cannot both win.

## Making a connection

```mermaid
sequenceDiagram
    participant L as laptop
    participant S as server
    participant W as wb01

    L->>S: POST /api/agent/connect { wb01, port 22 }
    Note over S: create a Service and a Grant<br/>with a fresh shared secret
    S-->>L: grant id
    L->>L: wake the local agent

    par wb01's next poll
        W->>S: GET /api/agent/desired-state
        S-->>W: expose port 22, secret X
        W->>W: rewrite frpc.toml, restart frpc
    and laptop's next poll
        L->>S: GET /api/agent/desired-state
        S-->>L: consume wb01:22, secret X
        L->>L: pick a local port, rewrite frpc.toml,<br/>write ~/.ssh/config
    end
```

The side that ran `connect` wakes its own agent immediately instead of waiting
out the poll interval. The other side finds out on its next poll — two seconds
by default.

Notice what the server does *not* do: it never tells a device which local port
to bind. It has no idea what is free over there. The consuming agent picks one
from its own range and remembers it, so the port stays stable across restarts
and your ssh aliases don't shift under you.

## Peer-to-peer, with a relay to fall back on

This is frp's own mechanism, wired up by frp-jump. For each connection, the
exposing device gets two frpc proxies sharing one secret — one `xtcp` (direct)
and one `stcp` (relayed). The consuming device gets two matching visitors, with
the direct one pointed at the relayed one as its fallback.

```mermaid
sequenceDiagram
    participant C as laptop · frpc
    participant R as relay · frps
    participant E as wb01 · frpc

    C->>R: I want wb01's port 22
    R->>E: someone is asking for you
    Note over C,E: both sides try to punch a UDP hole

    alt the hole opens
        C-->>E: direct connection, no relay involved
    else 500 ms elapse
        C->>R: fall back
        R->>E: relayed stream
        Note over C,E: hole-punching keeps retrying<br/>in the background
    end
```

Whichever path wins, your ssh client sees the same local port. That is the whole
point: you never have to know.

In frpc's config the pair looks like this, on the exposing side:

```toml
[[proxies]]
name = "<grant-id>-xtcp"
type = "xtcp"
secretKey = "<shared secret>"
localPort = 22
transport.useEncryption = true

[[proxies]]
name = "<grant-id>-stcp"
type = "stcp"
secretKey = "<shared secret>"
localPort = 22
transport.useEncryption = true
```

and on the consuming side:

```toml
[[visitors]]
name = "<grant-id>-stcp-visitor"
type = "stcp"
serverName = "<grant-id>-stcp"
bindPort = -1                          # takes fallback traffic only

[[visitors]]
name = "<grant-id>-xtcp-visitor"
type = "xtcp"
serverName = "<grant-id>-xtcp"
bindAddr = "127.0.0.1"
bindPort = 40000                       # the port the agent picked
fallbackTo = "<grant-id>-stcp-visitor"
fallbackTimeoutMs = 500
```

`useEncryption` covers the tunneled payload, not just the control channel. The
per-connection secret is the real gate — frp's own `allowUsers` ACL is set to
`*` and is not doing the work here.

### When peer-to-peer can't work

Some networks never punch through: a symmetric NAT, or a VPN that captures every
packet. Left alone, each new connection spends the fallback timeout failing at
something that was never going to succeed.

```sh
frp-jump-client set-p2p disabled
```

That collapses the pair above into a single relayed visitor on this device. It
affects only what this device dials out to — other devices can still reach *it*
directly, because its exposing-side proxies are untouched. The setting lives in
that device's own state, not on the server.

## The agent loop

```mermaid
flowchart TD
    start(["every agent_poll_interval_seconds"]) --> hb["heartbeat"]
    hb --> pull["fetch desired state"]
    pull --> cmp{"different from<br/>what's running?"}
    cmp -->|no| sleep["sleep"]
    cmp -->|yes| ports["allocate local ports<br/>for new connections"]
    ports --> render["render frpc.toml"]
    render --> restart["restart frpc"]
    restart --> sshcfg["refresh ~/.ssh/config"]
    sshcfg --> sleep
    sleep --> start

    hb -.->|"network error"| backoff["back off:<br/>5s → 90s"]
    backoff -.-> start
```

A failed cycle retries sooner than a healthy one, then backs off exponentially,
so an outage doesn't turn into a thundering herd when the server comes back.

`connect`, `disconnect`, and `set-p2p` drop a wake file that shortcuts the
sleep, so your own device applies changes almost immediately.

The ssh config the agent writes goes in its own managed file, pulled into your
real `~/.ssh/config` by a single `Include` line. Your own entries are never
touched.

## The data model

```mermaid
erDiagram
    USER ||--o{ DEVICE : owns
    USER ||--o{ ENROLL_TOKEN : "issued for"
    DEVICE ||--o{ SERVICE : exposes
    SERVICE ||--o{ GRANT : "reachable through"
    DEVICE ||--o{ GRANT : consumes

    USER {
        string label
        string ssh_public_key
        string ssh_key_fingerprint
    }
    DEVICE {
        string name
        string cert_serial
        string api_token_hash
        bool enabled
        datetime last_seen_at
    }
    SERVICE {
        int target_port
        string protocol
    }
    GRANT {
        string secret
    }
```

A few things worth knowing about this shape:

- **A person is an SSH public key.** No email, no password, no account record
  beyond a friendly label.
- **Device names are unique per owner, not globally.** Two people can each have
  a `laptop`. That is why admin commands that change a device require `--user`.
- **Services are synthetic.** `connect` creates them on demand from just
  (device, port). Nobody names them and nobody sees them.
- **A grant is one direction.** Laptop-to-wb01 and wb01-to-laptop are two
  separate grants with separate secrets.
- **Local ports are not in here.** They live in each agent's own state file,
  because only the device knows what is free.

Profiles — the names you pass to `--as` — are also purely local. The server
knows the connection as (device, port), nothing more.

## What this doesn't do

Two honest limits, both inherited from frp rather than chosen here.

**Traffic figures only count relayed bytes.** `frp-jump-server users show`
reports "relayed today: X in / Y out" from the relay's own counters. A
connection that is genuinely peer-to-peer never touches the relay, so it reports
zero even while moving gigabytes. frp does not account for direct traffic
anywhere, on either side.

**There is no "is this connection direct right now?" indicator.** frpc's admin
API reports proxy status on the exposing side, and has no equivalent for
visitors. Rather than guess, `status` reports what it knows and leaves it at
that.

## See also

- [Security model](security.md) — the trust boundaries and what revocation
  actually does.
- [Internals](architecture.md) — decisions, constraints, and the things that
  already surprised someone once.
