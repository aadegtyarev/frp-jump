# Device labels and icons — plan

Status: contract for the owner's review. Nothing is implemented yet. The owner
decided on this on 2026-11-01. The Android side is in `docs/contract.md` of
frp-jump-android. When this ships, the user-facing parts move into
[cli.md](cli.md) and [how-it-works.md](how-it-works.md), and this file is
deleted.

## What and why

A device name is a short identifier such as `wb01` or `garage-pi`. It becomes
an frp proxy name and an ssh alias, so it stays strict. Once the owner has a
dozen devices, the names no longer say what each device is or where it stands.

This plan adds two things to every device. Both are stored on the server, so
every phone and every CLI of the owner sees the same values:

- **Label.** Optional free text such as «Щиток, гараж», shown next to the name.
  It never replaces the name.
- **Icon.** One value from a fixed built-in set. The device reports the kind it
  detects. The owner can override it, and the override wins. "Back to automatic"
  drops the override.

Names, connections, tunnels and the wire protocol version stay as they are.

## Scenarios

1. The owner opens the app's device list and sees «wb01» with «Щиток, гараж ·
   Онлайн» under it, next to a Wiren Board icon. The agent detected the icon;
   nobody had to set it.
2. On the device card, the owner sets the label (⋮ → «Подпись…») and picks
   "router" (⋮ → «Значок…»). The owner's second phone shows both on its next
   list refresh, and so does `frp-jump-client devices list` on the laptop.
3. From a laptop, the owner runs `frp-jump-client devices label wb01 "Щиток,
   гараж"` and `frp-jump-client devices icon wb01 router`. Later,
   `frp-jump-client devices icon wb01 auto` goes back to the detected icon.
4. The owner searches the device list for «гараж» and finds `wb01` by its label.
5. A device still runs an old agent. It reports no kind, so the app shows the
   generic device glyph until the agent is upgraded or the owner picks an icon.
6. Each phone reports `phone` itself, so on the owner's other phones and in the
   CLI it shows as a phone without any setup.

## Decided

The owner confirmed these on 2026-11-01:

- A `phone` icon is added. The Android app reports it in its own heartbeat.
- Virtual machines are not detected separately. They stay `linux`.
- Schema changes go through a small versioned-migrations table, not an ad-hoc
  `ALTER` step.
- A label is at most 64 characters.

## Data model

Three nullable columns are added to `devices`:

| Column | Type | Set by | Meaning |
| --- | --- | --- | --- |
| `label` | text, null | owner | Free text, at most 64 code points; null when unset |
| `icon` | text, null | owner | Override from the icon set; null means automatic |
| `kind` | text, null | the device itself (agent or app) | Detected value from the icon set; null when unknown or the agent is old |

The **effective icon** is `icon` if set, otherwise `kind`, otherwise the
client's generic device glyph. The server never computes it; every client
derives it the same way.

### Icon set

One enum lives in a new `common/device_display.py`, so the lean client install
can import it without sqlmodel. Values are lowercase ASCII:

| Value | Meaning | Reported by |
| --- | --- | --- |
| `linux` | Generic Linux machine (Tux) | agent, fallback |
| `wirenboard` | Wiren Board controller | agent |
| `server` | Rack or server chassis | agent (DMI) |
| `pc` | Desktop computer | agent (DMI) |
| `laptop` | Laptop | agent (DMI, battery) |
| `router` | Router | agent (OpenWrt) |
| `sbc` | Single-board or embedded computer | agent (device tree, DMI) |
| `camera` | Camera | nobody; override only |
| `home` | House, flat, dacha | nobody; override only |
| `phone` | Phone | the Android app |

`auto` is reserved as a CLI word for "drop the override". It is never stored and
never sent on the wire.

Adding a value later is backward compatible. Older servers ignore an unknown
`kind` from a device (see Heartbeat). Older clients show the generic glyph for
an unknown value.

### Label rules

These checks live in `registry.py`, so the API and any future admin command
share them. They run in this order:

1. **Raw cap.** More than 256 code points as received is rejected before
   anything else. This bounds the work done on untrusted input, including the
   work NFC normalisation does.
2. **NFC.** The text is normalised to NFC.
3. **Forbidden characters**, rejected rather than removed. This runs *before*
   stripping, so a trailing newline is an error, not something quietly dropped.
   The forbidden characters are:
   - `Cc` control characters: newlines, tabs, ESC, DEL;
   - `Cf` format characters, except U+200C ZWNJ and U+200D ZWJ. This covers the
     bidi controls U+061C, U+200E, U+200F, U+202A–U+202E and U+2066–U+2069;
   - `Co` private use;
   - `Cs` surrogates;
   - `Zl` and `Zp`, the line and paragraph separators U+2028 and U+2029;
   - letters and symbols that render blank: U+115F and U+1160 (Hangul
     choseong and jungseong fillers), U+3164 (Hangul filler), U+FFA0
     (halfwidth Hangul filler) and U+2800 (blank Braille pattern). They are
     in `L*` or `S*`, so without this entry they would pass step 5 and make
     an invisible label.

   U+FE0F, the emoji presentation selector, is a combining mark (`Mn`). It is
   allowed, as all marks are. Unassigned code points (`Cn`) are allowed, so
   whether a label is valid does not depend on the server's Unicode version.
4. **Strip.** Leading and trailing whitespace is removed. If nothing is left,
   the request means "clear", and null is stored.
5. **Visible.** What remains must contain at least one letter, digit,
   punctuation mark or symbol (categories `L*`, `N*`, `P*`, `S*`). A label of
   only joiners or combining marks is rejected. The blank-rendering letters
   from step 3 never get this far.
6. **Length.** At most **64 code points** after steps 2 and 4. A longer label is
   rejected, never cut.

These rules keep a label from injecting terminal escapes into the CLI, breaking
table rows, or reordering text so that one device's row looks like another's.
Cyrillic, punctuation, digits and emoji, including ZWJ sequences, are all
allowed. Labels need not be unique: two devices may both be «Гараж».

The error text names the rule that failed, for example "label is longer than 64
characters", "label contains a line break or control character" or "label has
no visible characters". The app shows it under the field.

## API

All routes are under `/api/agent`. **`PROTOCOL_VERSION` stays 1.** Every change
here adds optional fields, a new route or a feature flag. Bumping the version
would make every existing agent and phone stop applying desired state.

### Feature advertisement: `GET /version`

The unauthenticated version answer gains a list:

```json
{"protocol_version": 1, "package_version": "0.4.0", "features": ["device-display"]}
```

- `features` lists optional capabilities that the protocol version does not
  imply. `device-display` means the `/devices` fields, the `/display` route and
  `kind` in heartbeat are all supported.
- An old server sends no `features` key. Clients read that as an empty list.
- Clients detect support only through this list, never through the presence of
  a JSON key or a 404. The app caches the list per profile. The CLI asks before
  `devices label` or `devices icon`.
- The list exists for gating UI and commands. It is not a security boundary:
  the server still enforces everything on each route.

### Heartbeat: the device reports `kind`

`POST /heartbeat` gains an optional field:

```json
{"agent_version": "0.4.0", "kind": "wirenboard"}
```

- In the request model the field is `str | None`, deliberately **not** the enum.
  With the enum, a newer device sending a value this server does not know would
  make pydantic reject the whole heartbeat with a 422, and the device would show
  as offline. `record_heartbeat` validates the value leniently instead:
  - a known value is stored when it differs from the current one;
  - an unknown value or null leaves the stored `kind` untouched, silently.
- A disabled device's heartbeat is still accepted, as it is today. `kind` is the
  device describing itself, not an action on the account.
- Enroll does not change. The first heartbeat comes seconds after enroll, so one
  path is enough.

### Device list: new fields

Items of `GET /devices` (`OwnedDeviceOut`) gain three fields. A new server
always sends them, null when unset:

```json
{"name": "wb01", "enrolled_at": "…", "last_seen_at": "…", "enabled": true,
 "label": "Щиток, гараж", "icon": null, "kind": "wirenboard"}
```

Clients read them as optional (`d.get(...)` in Python), so an old server's
answer without them simply has no labels.

### Setting a label or icon: new route

```
POST /devices/{name}/display
{"label": "Щиток, гараж"}           # set the label, icon untouched
{"label": null}                     # clear the label ("" does the same)
{"icon": "router"}                  # override the icon
{"icon": null}                      # back to automatic
{"label": "…", "icon": "camera"}    # both at once
```

- A field left out stays as it is. The route reads pydantic's
  `model_fields_set`, so an absent field and a null field mean different
  things. An empty body is a 400.
- `icon` must be a value from the set. Anything else, `"auto"` included, is a
  400 that lists the allowed values. This route is strict where heartbeat is
  lenient: a person chose the value and should be told it is wrong.
- `label` follows the label rules above. A violation is a 400 with the reason.
- The response is the updated `OwnedDeviceOut`, so the caller can show the
  result without a second request.
- **Who may set:** the caller's token must belong to an *enabled* device
  (`get_enabled_device`, as for every other mutating route). A disabled caller
  gets 403 "this device is disabled". The target is resolved with
  `_get_owned_device_by_name`: same owner, or 404. The target may itself be
  disabled; labelling a disabled device is harmless and useful. No device can
  touch another owner's devices.
- The name `display` follows the existing one-verb-per-route style
  (`/devices/{name}/disable`). One route instead of separate `label` and `icon`
  routes lets the app save both in one atomic request.
- When two phones edit at once, the last write wins. The app sends only the
  fields the owner changed, so editing the label on one phone and the icon on
  another does not overwrite either.

A label and an icon belong to the device row. Deleting a device drops them, and
a device re-enrolled under the same name starts without them.

## CLI

### frp-jump-client

The new commands sit in the existing `devices` group, next to `disable` and
`enable`, and take the same `devices <verb> NAME` shape:

```
frp-jump-client devices label NAME TEXT
frp-jump-client devices label NAME --clear
frp-jump-client devices icon NAME ICON|auto
```

- Giving `label` both `TEXT` and `--clear`, or neither, is a usage error. `TEXT`
  is one argument, so the shell needs quotes: `"Щиток, гараж"`.
- The two commands clear their values differently, on purpose. Any word,
  including `auto`, can be a label, so clearing a label needs an option. The
  icon set is closed, so `auto` can be a reserved positional value.
- `icon NAME auto` drops the override. `--help`, and the error for a bad value,
  list the icon set.
- Before sending, both commands ask `GET /version`. Without `device-display` in
  `features`, they print "this server does not support device labels yet;
  upgrade frp-jump on the server" and exit 1. A 404 from the route itself then
  only ever means "no such device".
- On success, both print the device's resulting row in the `devices list`
  format.
- If `TEXT` starts with `-`, put `--` before it, as for any Typer argument:
  `devices label wb01 -- "-48 V, щит"`. The `--help` example shows this.
- `devices list` gains two columns:
  - **Device label:** the text, or `-`;
  - **Icon:** `router` when the owner set it; `wirenboard (auto)` when it comes
    from the device; `-` when both are null or the server is old. After
    `devices icon X auto` on a device that reports nothing, the column shows
    `-`.
- Labels are always rendered as `rich.text.Text` objects, never as strings
  passed to `console.print` or `Table.add_row`. A string would go through Rich's
  markup and `:emoji:` processing. Tests print a label of `[red]x` and one of
  `:warning:` and expect both literally.

### frp-jump-server

- `devices list` and `users show` gain a read-only **Device label** column,
  rendered the same way (`Text`).
- Naming: users already have a `label` (`users add-key --label`, the "Label"
  column of `users list`). That is the admin's handle for a person, with the
  strict name character set. A device label is free text from the owner.
  They are separate fields. In code the device field is `Device.label`, and
  on the wire it is `label` inside a device object. In CLI tables and in the
  docs it is always called "Device label", so the two never share a column
  title.
- An admin command to *set* a label is out of scope. The owner sets labels from
  their own devices.

## Detecting the kind

### Linux agent

The detector is a new module, `agent/device_kind.py`. It holds one pure
function, `detect_kind(root: Path = Path("/")) -> DeviceIcon`, which reads only
paths under `root`, so tests point it at a temporary directory. `agent/poller`
calls it once when the run loop starts, keeps the result for the life of the
process, and sends it in every heartbeat. Sending it every time costs a few
bytes and repairs the value after a server database restore.

It reads a handful of small files, starts no subprocess, and treats any read
error as "this rule does not match". The first matching rule wins:

1. `etc/wb-release` exists → `wirenboard`.
2. `etc/openwrt_release` exists → `router`.
3. **Virtual machine** → `linux`. Two signs count: a `hypervisor` flag in
   `proc/cpuinfo`, which x86 guests under KVM, Hyper-V, VMware, VirtualBox and
   Xen HVM all have, or a non-empty `sys/hypervisor/type`, which Xen PV guests
   have. This rule must come before DMI: Hyper-V reports chassis type 3,
   "Desktop", and would otherwise come out as `pc`.
4. **DMI present** (`sys/class/dmi/id/chassis_type` readable). The SMBIOS
   chassis type decides:

   | Chassis types | Result |
   | --- | --- |
   | 8, 9, 10, 14, 30, 31, 32 (portable, laptop, notebook, sub-notebook, tablet, convertible, detachable) | `laptop` |
   | 17, 23, 25, 28, 29 (main server chassis, rack mount, multi-system chassis, blade, blade enclosure) | `server` |
   | 3, 4, 5, 6, 7, 13, 15, 16, 24, 35, 36 (desktop, low-profile, pizza box, mini tower, tower, all-in-one, space-saving, lunch box, sealed-case PC, mini PC, stick PC) | `pc` |
   | 33, 34 (IoT gateway, embedded PC) | `sbc` |
   | 11 (hand held), 1 (other), 2 (unknown), anything else | go to the battery check |

   The battery check: any `sys/class/power_supply/*` entry whose `type` is
   `Battery` and whose `scope` is not `Device` → `laptop`; otherwise → `linux`.
   `scope=Device` marks a peripheral's battery (a mouse, a headset, a USB UPS),
   which says nothing about the host. A missing `scope` file counts as a host
   battery: ACPI laptop batteries usually have no `scope` at all. This check
   catches laptops whose firmware reports an unhelpful chassis type.
5. **No DMI**, and `proc/device-tree/model` exists and is not empty → `sbc`. That
   covers Raspberry Pi, Orange Pi and other ARM boards. Wiren Board has a device
   tree too, but rule 1 already caught it. The battery check does not run
   without DMI, so an ARM board with a fuel gauge, or an ARM laptop, comes out
   as `sbc`. The owner can override that.
   An ARM virtual machine without DMI (QEMU `virt`) has a device tree and no
   `hypervisor` flag, so it can come out as `sbc` too. The owner can override
   that as well.
6. Otherwise → `linux`.

Tablets (type 30) count as laptops on purpose: the set has no tablet icon, and
a laptop is the nearest match. Hand-held devices (type 11) have no fitting icon
and stay `linux` unless they have a battery. A container (LXC, Docker) sees the
host's DMI and power supplies, so an agent in a container on a laptop shows
`laptop`. The owner can override that too.

The agent has no local setting to force a kind. The owner's override on the
server does that job, and it works from any device.

### Android app

The app sends `"kind": "phone"` in every heartbeat. It detects nothing; it is
always a phone.

## Compatibility

| Combination | Result |
| --- | --- |
| Old agent or old app → new server | No `kind` sent; `kind` stays null. Clients show the generic glyph unless the owner set an icon |
| New agent → old server | The old `HeartbeatRequest` ignores the unknown `kind` field (pydantic's default `extra="ignore"`). Nothing breaks |
| New device with a value newer than the server → new server | The unknown `kind` is ignored; the stored value stays |
| Old app or old CLI → new server | The extra keys in `/version` and `/devices` are ignored: the app parses with `ignoreUnknownKeys`, and the old CLI reads keys by name |
| New app → old server | No `device-display` feature, so the app hides the edit actions and shows no labels (see the app's contract) |
| New CLI → old server | `devices label` and `devices icon` print the "upgrade the server" message. `list` shows `-` |
| Server rolled back to 0.3.x after migrating | 0.3.x code names the columns it selects, so the extra columns and the `schema_version` table are ignored. New rows get null in the new columns. Labels come back after the next upgrade |
| A newer database opened by an older migrating release | Refused at start (see Migration) |

## Migration

The codebase has no migration framework. `server/db.make_engine` calls
`SQLModel.metadata.create_all`, which creates missing tables but never adds
columns to existing ones. This feature is the first schema change after a
release, so it introduces a small versioned runner in a new module,
`server/migrations.py`.

### The version table

- `schema_version`, one row, one integer `version`. The runner creates it in
  raw SQL, **not** as a SQLModel table, so nothing creates it outside the lock
  described below.
- A missing table or row reads as version 0, the 0.3.x schema.
- The migrations are an ordered list of `(version, function)` pairs in code.
  Migration 1 adds `label`, `icon` and `kind` to `devices`. Each step checks
  `PRAGMA table_info` and adds only the columns that are missing, with
  `ALTER TABLE devices ADD COLUMN <name> VARCHAR` (nullable, no default, instant
  in SQLite whatever the table size). This makes every step idempotent. It also
  covers a fresh database: the runner has just created `devices` with the new
  columns (see below), so migration 1 adds nothing and only records the
  version.
- A future release that adds a table also bumps the version. Creating tables
  happens only while a migration is pending (see below), so a new table
  without a version bump would never be created on an existing database.

### When it runs

`make_engine` runs the runner instead of calling
`SQLModel.metadata.create_all` itself, before returning the engine. Every entry
point that touches the database goes through `make_engine`:

- `frp-jump-server run`;
- `init` and `install-service`, through `bootstrap`;
- every admin command (`users …`, `devices …`, `enroll-tokens …`), through
  `_open_db`.

The admin CLI needs this as much as `run`: its queries name the new columns as
soon as the model has them.

### Locking and concurrency

The runner works on a **raw `sqlite3` connection** opened with
`isolation_level=None` and `timeout=10`. With pysqlite's default transaction
handling, SQLAlchemy and the driver decide on their own when to emit `BEGIN`
and `COMMIT`, which is not reliable enough to hold a lock across several
statements. With `isolation_level=None`, every `BEGIN IMMEDIATE`, `COMMIT`
and `ROLLBACK` is the runner's own. `timeout=10` is the 10 s wait for the
lock.

For `:memory:`, the unit-test path with `StaticPool`, the runner uses the
engine's single shared DBAPI connection instead. A new
`sqlite3.connect(":memory:")` would be a different, empty database. It sets
`isolation_level=None` for the run and puts the old value back afterwards.

1. Read the version. If it is current, return without writing anything, so a
   database that is already up to date never needs write access.
2. Otherwise, `BEGIN IMMEDIATE`. That takes SQLite's write lock up front, so
   creating the tables, checking the version and running the `ALTER`s are one
   atomic step. The connection waits up to 10 s for the lock.
3. Under the lock:
   1. Create the model's tables and indexes. The runner emits the DDL itself
      on its own connection: SQLAlchemy's `CreateTable(..., if_not_exists=True)`
      and `CreateIndex(..., if_not_exists=True)`, compiled for SQLite. It does
      not call `metadata.create_all`, which opens and commits a transaction of
      its own and would end the `BEGIN IMMEDIATE` early.
   2. Read the version again.
   3. Apply the pending steps in order.
   4. Set the version and `COMMIT`.

   On any error, `ROLLBACK` and stop. Creating the tables inside the lock is
   what makes an empty file safe: two processes starting on a new database
   cannot both create the same tables.
4. A "duplicate column name" error from an `ALTER` counts as "already applied".
   It can only happen when another process changed the schema without this
   lock, for example with a hand-run `sqlite3`.

A second process starting at the same moment, say `run` restarting while an
admin command is open, waits on the lock, sees the new version, and does
nothing.

### Failure cases

Each case stops with a clear message and a non-zero exit:

- **No write access** with a migration pending: "the database at <path> needs a
  schema upgrade (version N → M) but is not writable by <user>; run as the
  service account (sudo frp-jump-server …) or start the service once". The
  admin wrapper already runs as the service account, so this only happens when
  the binary is run directly as another user.
- **Lock not obtained** within 10 s: "the database is busy; another frp-jump
  process holds it; retry".
- **Database newer than the code** (version above the highest known): "database
  schema version N is newer than this frp-jump supports (M); upgrade frp-jump".
  The runner does not guess its way through a schema it does not know. A
  0.3.x server has no runner, so it simply ignores the table (see
  Compatibility).

## Security

- The label is text the owner writes. Only the owner's own devices, and the
  admin's CLI on the server box, ever see it. No other user does.
- The server validates labels as described in Label rules: a raw cap first,
  then forbidden characters, a visible character and a length limit. The
  heartbeat `kind` is never stored or echoed raw; only known enum values are
  stored.
- **A label is for display only.** It must never reach a frp proxy or visitor
  name, `~/.ssh/config`, `/etc/hosts`, a file path, a shell command or a URL.
  Device names keep that job, and their strict regex. Code review checks every
  place that reads the label.
- Clients render the label as plain text: `rich.text.Text` in the CLI (no markup,
  no emoji codes), and a plain `Text` in the app (no HTML, no automatic links).
- Authorization is the existing self-service boundary: an enabled device of the
  same owner. A disabled device's token cannot change labels or icons.
- No new logging. The server does not log labels or label changes.
- Nothing limits how often a label or icon can be changed. This follows the
  "Accepted, not enforced" stance in
  [architecture.md](architecture.md#accepted-not-enforced): an authenticated
  device writing its own owner's rows on the owner's server.

When this ships, [security.md](security.md) gains a row for it: owner-written
label text, validated, display-only.

## Tests

Unit tests in the existing files, following the repo's one-to-one layout:

- `test_registry.py`: the label rules, one case per rule:
  - a valid Cyrillic label;
  - over the raw cap;
  - over 64 code points after NFC;
  - newline, ESC, a bidi override and a private-use character, each rejected;
  - ZWJ emoji accepted;
  - only ZWJ rejected;
  - spaces only clears (a newline is rejected by rule 3, not cleared);
  - each blank-rendering filler (U+3164, U+115F, U+1160, U+FFA0, U+2800),
    alone and between spaces, is rejected;
  - a trailing `\n` is rejected, not stripped.

  Also: setting and clearing the icon, and lenient `kind` (a known value is
  stored, an unknown one ignored, null keeps the stored value).
- `test_api.py`:
  - `/version` has `device-display`;
  - `/devices` items have the three keys;
  - `/display` with each body shape: label only, icon only, both, null, an empty
    body (400), a bad icon (400), `"auto"` (400);
  - another owner's device gives 404, a disabled caller 403, a disabled target
    OK;
  - a heartbeat with an unknown `kind` gives 204, not 422.
- `test_client_cmds.py`:
  - `label` with text, with `--clear`, and with neither;
  - `icon auto` output when both values are null (`-`);
  - the old-server message;
  - `[red]x` and `:warning:` printed literally in `list`.
- New `test_device_kind.py`. Each rule runs against a fake root:
  - Wiren Board, OpenWrt;
  - VM by the cpuinfo flag, VM by `sys/hypervisor`;
  - each chassis-type group, including 24, 33, 34 and 11;
  - a battery with and without `scope`, and a `scope=Device` battery;
  - a device tree without DMI;
  - unreadable files.
- New `test_migrations.py`:
  - a 0.3.x database with one device row: the row is intact, the new columns are
    null, version 1;
  - a fresh database: version 1, no `ALTER`;
  - `:memory:` with `StaticPool`: tables created and version 1 on the shared
    connection, and the app's sessions see them;
  - a second open does nothing and needs no write access;
  - a read-only file with a migration pending gives the clear error;
  - a newer version is refused;
  - **two processes** (`multiprocessing`) opening the same 0.3.x file at once:
    both succeed, each column exists once, version 1;
  - **two processes** opening the same **empty** file at once: both succeed,
    and each table exists once, at version 1.

The integration suite does not change.

## Delivery

Small PRs, each with its own tests, in this order:

1. **Migrations:** the runner, the `schema_version` table, migration 1, and the
   model columns.
2. **Server:** label and icon validation in `registry.py`, the `/version`
   features, the `/devices` fields, the `/display` route, lenient `kind` in
   heartbeat, the Device label column in `frp-jump-server devices list` and
   `users show`.
3. **Client CLI:** `devices label`, `devices icon`, the new `devices list`
   columns, and the old-server message.
4. **Agent:** `agent/device_kind.py` and `kind` in heartbeat.
5. **Docs:** `cli.md` (the new commands), `how-it-works.md` (a paragraph on
   labels and icons), `architecture.md` (the migration runner, in Decisions),
   `security.md` (the new row), CHANGELOG. This plan is deleted.

Then a release: version bump, tag, `.deb` and PyPI.

**Releasing, upgrading the server and upgrading agents each need the owner's
explicit go.** Merging the PRs does not mean any of them. In order:

1. Tag the release (needs the go).
2. Upgrade the server (needs the go): back up the database file, then install
   and restart. The migration runs at start.
3. Upgrade agents, device by device (needs the go). Until its agent is upgraded,
   a device shows the generic icon, or whatever the owner set.

The app can ship before or after the server. Against an old server it hides the
feature (see the app's contract).

## Acceptance

- After the server upgrade:
  - `devices list` from an old 0.3.x client still works;
  - every existing device keeps its name, tunnels and enabled state;
  - the database is at schema version 1, with the three new columns, all null.
- An upgraded agent shows in `frp-jump-client devices list` within one poll:
  - `wirenboard (auto)` on a Wiren Board;
  - `laptop (auto)` on a laptop;
  - `sbc (auto)` on a Raspberry Pi;
  - `linux (auto)` in a KVM or Hyper-V VM.

  A phone with the new app shows `phone (auto)`.
- Labels and icons from the CLI:
  - `devices label wb01 "Щиток, гараж"` from a laptop appears on the phone's
    list within one refresh;
  - `devices icon wb01 router` overrides the icon;
  - `devices icon wb01 auto` brings back the detected icon.
- `devices label wb01 $'a\nb'` is refused with the reason. Labels `[red]x` and
  `:warning:` print literally in `devices list`.
- An old agent left running reports no kind and keeps working. The new CLI
  against an old server prints the "upgrade the server" message.

## Out of scope

- Custom or uploaded icons, a colour per device, and an admin command to set
  labels.
- Labels for connections (the app already names connections locally) or for
  users.
- Sorting or grouping devices by label.
