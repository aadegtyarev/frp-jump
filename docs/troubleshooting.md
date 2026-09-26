# Troubleshooting

Start here, always:

```sh
frp-jump-client doctor
```

It checks the four things everything else assumes: this device is enrolled, the
frp binary is present, the server answers, and both sides speak the same
protocol version. If one of those is broken, fix it before reading further.

Then the logs:

```sh
journalctl -u frp-jump-client -n 50
journalctl -u frp-jump-server -n 50
```

A healthy agent is quiet. Lines appear when something changes, not on every
poll.

## Quick triage

| Symptom | Jump to |
| --- | --- |
| `ssh wb01` says the host doesn't exist | [ssh doesn't know the name](#ssh-wb01-says-could-not-resolve-hostname) |
| `connect` printed "no local port yet" | [connect didn't finish](#connect-says-no-local-port-yet) |
| `ssh` hangs, then times out | [the tunnel is up but nothing answers](#ssh-connects-to-the-local-port-then-hangs) |
| A device shows as offline | [heartbeats aren't arriving](#a-device-shows-as-offline) |
| Every connection feels slow to open | [hole-punching is failing](#every-connection-takes-half-a-second-to-open) |
| The server won't start | [TLS rules](#the-server-refuses-to-start) |
| `sudo frp-jump-client` says command not found | [sudo's PATH](#sudo-frp-jump-client-command-not-found) |

---

## `ssh wb01` says "Could not resolve hostname"

The ssh entry was never written, or it was written into a config your ssh client
doesn't read.

**Check what the agent thinks:**

```sh
frp-jump-client status
```

If `wb01` appears under **Consumed** with a local address, the tunnel exists and
only the ssh config is missing.

**Check which account the agent runs as:**

```sh
systemctl show frp-jump-client -p User
```

The agent maintains the `~/.ssh/config` of *its own* account. If it runs as
`frp-jump-client` and you are `you`, it is writing a config nobody reads.

The quick fix is to point the agent at your config explicitly:

```sh
sudo systemctl edit frp-jump-client
```

```ini
[Service]
Environment=FRP_JUMP_SSH_CONFIG_PATH=/home/you/.ssh/config
```

Then `sudo systemctl restart frp-jump-client`. Note that the account running the
agent needs write access to that file.

The tidier fix is to re-enroll so the agent runs as you: stop the service,
remove the system account's data directory, then `enroll` without `sudo`
followed by `sudo install-service`. See
[which account to use](configuration.md#which-account-should-the-agent-run-as).

**Check the Include line.** The agent writes its entries to a managed file and
prepends one line to your config:

```sh
head -1 ~/.ssh/config
```

It should be `Include` followed by a path inside the agent's data directory.
Keep it at the top — ssh takes the first matching value it finds, so a `Host *`
block above it would win.

**Check the port is SSH at all.** Only 22 and 2222 get an ssh entry
automatically. For anything else:

```sh
frp-jump-client connect wb01:2022 --ssh
```

## `connect` says "no local port yet"

`connect` registers the connection on the server and then waits up to ten
seconds for the local agent to bind a port. That message means the server part
worked and the agent part didn't.

Usually the agent isn't running:

```sh
systemctl status frp-jump-client
frp-jump-client status
```

On a fresh device it may simply be slow: the first run downloads the frp
binaries. Watch it:

```sh
journalctl -u frp-jump-client -f
```

No internet on that device? The download is the only thing that needs it. Copy
the `frpc` binary into `<data_dir>/bin/` from another machine of the same
architecture.

## `ssh` connects to the local port, then hangs

The tunnel is up, and nothing is listening on the far end.

**On the exposing device:**

```sh
frp-jump-client status
```

The **Exposed** table has a "Listening" column for exactly this. If it says
"nothing is listening here", the problem is that machine's sshd, not frp-jump:

```sh
systemctl status ssh
ss -lntp | grep :22
```

**Check the device isn't disabled:**

```sh
frp-jump-client devices list
```

A disabled device keeps heartbeating but drops all its tunnels. Re-enable it
with `devices enable`, and wait one poll interval.

## A device shows as offline

"Online" means a heartbeat arrived within `device_online_threshold_seconds`, 30
by default. It is a recency check, not a live probe.

- **The agent isn't running.** `systemctl status frp-jump-client` on that box.
- **It can't reach the server.** Run `frp-jump-client doctor` there.
- **Its poll interval is longer than the threshold.** If you set
  `--poll-interval 60`, raise `device_online_threshold_seconds` to match, or it
  will look offline between every heartbeat.

## Every connection takes half a second to open

That is the hole-punch timeout expiring before falling back to the relay. It
means peer-to-peer isn't working on this network.

Common causes: outbound UDP is blocked, the NAT is symmetric, or a VPN is
capturing all traffic.

If it will never work here, stop paying for the attempt:

```sh
frp-jump-client set-p2p disabled
```

Connections then go straight to the relay. This affects only what this device
dials out to; others can still reach it directly.

To confirm it is the network rather than the config, try the same pair of
devices on a different network. There is no indicator in the CLI for "this
connection is currently direct" — frp doesn't expose one.

## The server refuses to start

```
refusing to start: api_host='0.0.0.0' is reachable from outside this machine,
and no TLS is configured.
```

Working as intended. The control-plane API carries certificates and bearer
tokens on every call. Pick one:

```sh
# serve HTTPS directly
FRP_JUMP_TLS_CERT_FILE=/etc/letsencrypt/live/example.com/fullchain.pem
FRP_JUMP_TLS_KEY_FILE=/etc/letsencrypt/live/example.com/privkey.pem

# or bind loopback and front it with nginx/Caddy
FRP_JUMP_API_HOST=127.0.0.1

# or, only if TLS really is terminated somewhere this process can't see
FRP_JUMP_ALLOW_INSECURE_BIND=true
```

Server settings live in `/etc/frp-jump/<system-user>.env`. Restart after
editing.

## `sudo frp-jump-client: command not found`

`sudo` replaces `PATH` with its own `secure_path`, which never includes a venv
or `~/.local/bin`. Use the absolute path:

```sh
sudo "$(command -v frp-jump-client)" install-service
```

`enroll` prints the correct absolute path in its "next step" hint for this
reason.

## `--system-user` fails with "would not be able to execute"

The dedicated account can't traverse into wherever the binary lives — typically
a venv inside a home directory that is mode `0750`. Three ways out:

- Install the `.deb` instead, which puts the binary somewhere world-reachable.
- Move the venv somewhere system-wide, such as `/opt`.
- Use `--user` and run the agent as yourself.

## "not enrolled" even though I enrolled it

Enrollment state lives in a data directory, and `sudo` changes which one that
is. An unprivileged `enroll` writes to your home; a `sudo enroll` may write to a
system account's directory.

```sh
frp-jump-client status              # as you
sudo -u frp-jump-client frp-jump-client status
```

Point both at the same place with `FRP_JUMP_DATA_DIR`, or re-enroll consistently
with one account.

## Protocol version mismatch

```
protocol mismatch: server speaks v2, this client speaks v1
```

The agent refuses to apply a response it may not understand, leaves whatever
tunnel is already running alone, and keeps retrying. Upgrade whichever side is
behind. Nothing breaks in the meantime.

## Starting over on one device

```sh
sudo systemctl stop frp-jump-client
frp-jump-client devices delete wb01 --yes   # from another of your devices
sudo rm -rf /var/lib/frp-jump-client        # or ~/.local/share/frp-jump
```

Then enroll it again. Deleting the device frees its name for reuse.

## Still stuck

Open an issue with the output of:

```sh
frp-jump-client doctor
frp-jump-client status
journalctl -u frp-jump-client -n 100 --no-pager
```

Those three together identify almost everything. Scrub the device id if you'd
rather not post it.
