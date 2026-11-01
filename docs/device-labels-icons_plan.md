# Device labels and icons — plan

Status: contract for the owner's review, nothing implemented yet. Decided by
the owner on 2026-11-01. The Android side is in `docs/contract.md` of
frp-jump-android. Once this ships, the user-facing parts move into
[cli.md](cli.md) and [how-it-works.md](how-it-works.md), and this file is
deleted.

## What and why

A device name is a short identifier (`wb01`, `garage-pi`). It becomes an frp
proxy name and an ssh alias, so it stays strict. With a dozen devices, the
owner can no longer tell what each one is or where it stands.

Two things are added to every device. Both are stored on the server, so every
phone and every CLI of the owner sees the same values:

- **Label**: free text such as «Щиток, гараж». It is optional and shown next to
  the name. It never replaces the name.
- **Icon**: one value from a fixed built-in set. The device's agent reports the
  kind it detects. The owner can override it, and the override wins. "Back to
  automatic" drops the override.

Names, connections, tunnels and the wire protocol version stay as they are.

## Scenarios

1. The owner opens the app's device list and reads «wb01» with «Щиток, гараж ·
   Онлайн» under it, beside a Wiren Board icon. The agent detected that icon,
   and nobody had to set it.
2. On the device card, the owner sets the label (⋮ → «Подпись…») and picks
   "router" (⋮ → «Значок…»). The owner's second phone shows both on its next
   list refresh, and so does `frp-jump-client devices list` on the laptop.
3. From a laptop: `frp-jump-client devices label wb01 "Щиток, гараж"` and
   `frp-jump-client devices icon wb01 router`. Later,
   `frp-jump-client devices icon wb01 auto` returns to the detected icon.
4. The owner searches the device list for «гараж» and finds `wb01` by its
   label.
5. A device still runs an old agent. It reports no kind, so the app draws the
   generic device glyph until the agent is upgraded or the owner picks an
   icon.

## Data model

Three nullable columns are added to `devices`:

| Column | Type | Set by | Meaning |
| --- | --- | --- | --- |
| `label` | text, null | owner | Free text, at most 64 characters; null when unset |
| `icon` | text, null | owner | Override from the icon set; null means automatic |
| `kind` | text, null | the device's own agent | Detected kind from the icon set; null when unknown or the agent is old |

The **effective icon** is `icon`, then `kind`, then the client's generic
device glyph. The server never computes it. Every client derives it the same
way.

### Icon set

One enum lives in `common/`, so the lean client install can import it
without sqlmodel. Values are lowercase ASCII:

| Value | Meaning | Detected? |
| --- | --- | --- |
| `linux` | Generic Linux machine (Tux) | yes, the fallback |
| `wirenboard` | Wiren Board controller | yes |
| `server` | Rack or server chassis | yes (DMI) |
| `pc` | Desktop computer | yes (DMI) |
| `laptop` | Laptop | yes (DMI, battery) |
| `router` | Router | yes (OpenWrt) |
| `sbc` | Single-board computer | yes (device tree) |
| `camera` | Camera | no, override only |
| `home` | House, flat, dacha | no, override only |

`auto` is reserved as a CLI word for "drop the override". It is never stored
and never sent on the wire.

Adding a value later is backward compatible. Older servers ignore an unknown
`kind` from an agent (see Heartbeat), and older clients draw the generic glyph
for an unknown value.

### Label rules

These checks run in `registry.py`, so the API and any future admin command
share them.

- Normalised to NFC, then leading and trailing whitespace is stripped. An
  empty result means "clear" and stores null.
- At most **64 code points** after normalisation. Anything longer is
  rejected, never cut.
- Rejected outright: control characters (Unicode `Cc`, which covers newlines,
  tabs and ESC), the line and paragraph separators U+2028 and U+2029,
  surrogates, and the bidi controls U+061C, U+200E, U+200F,
  U+202A–U+202E and U+2066–U+2069. Without these, a label cannot inject
  terminal escapes into the CLI, break table rows, or reorder text so that one
  device's row looks like another's.
- Everything else is allowed: Cyrillic, punctuation, digits, emoji (ZWJ
  sequences included).
- Labels need not be unique. Two devices may both be «Гараж».

The error text names the rule that failed ("label is longer than 64
characters", "label contains a line break or control character"). The app
shows it under the field.

## API

All routes sit under `/api/agent`. **`PROTOCOL_VERSION` stays 1.** Every change
adds optional fields or a new route. Bumping the version would make every
existing agent and phone stop applying desired state.

### Heartbeat: the agent reports `kind`

`POST /heartbeat` gets an optional field:

```json
{"agent_version": "0.4.0", "kind": "wirenboard"}
```

- The field is `str | None` in the request model, deliberately **not** the
  enum. An enum would make pydantic reject the whole heartbeat with a 422 when
  a newer agent sends a value this server does not know, and the device would
  then show as offline. `record_heartbeat` validates leniently instead:
  - a known value is stored when it differs from the current one;
  - an unknown value or null leaves the stored `kind` untouched. An unknown
    value is logged once at debug level.
- A disabled device's heartbeat is still accepted, as it is today. `kind` is
  the device describing itself, not an action on the account.
- Nothing is added to enroll. The first heartbeat comes seconds after enroll,
  so one path is enough.

### Device list: new fields

`GET /devices` items (`OwnedDeviceOut`) gain three fields. A new server
**always sends all three keys**, null when unset:

```json
{"name": "wb01", "enrolled_at": "…", "last_seen_at": "…", "enabled": true,
 "label": "Щиток, гараж", "icon": null, "kind": "wirenboard"}
```

When the keys are present, clients know the server supports this feature.
The app uses that to decide whether to offer the edit actions (see
Compatibility).

### Setting a label or icon: new route

```
POST /devices/{name}/display
{"label": "Щиток, гараж"}           # set the label, icon untouched
{"label": null}                     # clear the label ("" does the same)
{"icon": "router"}                  # override the icon
{"icon": null}                      # back to automatic
{"label": "…", "icon": "camera"}    # both at once (the app's sheet)
```

- A field that is absent stays as it is. The route reads pydantic's
  `model_fields_set`, so "absent" and "null" mean different things. An empty
  body is a 400.
- `icon` must be a value from the set. Anything else, `"auto"` included, is a
  400 that lists the allowed values. This route is strict where heartbeat is
  lenient: here a person typed the value and should be told when it is wrong.
- The label follows the label rules above. A violation is a 400 with the
  reason.
- The response is the updated `OwnedDeviceOut`, so the caller can show the
  result without a second request.
- **Who may set:** the caller's token must belong to an *enabled* device
  (`get_enabled_device`, like every other mutating route). The target is
  resolved with `_get_owned_device_by_name`: the same owner, otherwise 404.
  The target may itself be disabled, since labelling a disabled device is
  harmless and useful. No device can touch another owner's devices.
- `display` follows the existing one-verb-per-route style
  (`/devices/{name}/disable`). Using a single route rather than separate
  `label` and `icon` routes means the app's sheet saves both in one atomic
  request.
- Concurrent edits from two phones: the last write wins. Nothing heavier is
  needed for 64 characters of owner text.

A label and an icon belong to the device row. Deleting a device drops them,
and a device re-enrolled under the same name starts without them.

## CLI

### frp-jump-client

These sit under the existing `devices` group, next to `disable` and `enable`,
in the same `devices <verb> NAME` shape:

```
frp-jump-client devices label NAME TEXT
frp-jump-client devices label NAME --clear
frp-jump-client devices icon NAME ICON|auto
```

- `label` with both `TEXT` and `--clear`, or with neither, is a usage error.
  `TEXT` is one argument, so the shell quotes it: `"Щиток, гараж"`.
- `icon NAME auto` drops the override. `--help` and the error for a bad value
  list the icon set.
- On success, both print the device's resulting line: name, label, and the
  effective icon followed by `(auto)` when it comes from detection.
- Against a server that does not have the route, FastAPI answers 404 with
  detail `"Not Found"`. The CLI tells this apart from our own `no such device`
  404 and says: "this server does not support device labels yet; upgrade
  frp-jump on the server".
- `devices list` gains two columns, **Label** and **Icon** (for example
  `router`, or `wirenboard (auto)`). Against an old server the keys are
  missing and the columns show `-`.
- Rich renders `[...]` in strings as markup. Every label is printed through
  `rich.markup.escape` or a `Text` object. A label like `[red]x` must print
  literally. Unit tests cover this.

### frp-jump-server

- `devices list` and `users show` gain a Label column, read-only. They need
  the same escaping.
- An admin command to *set* a label is out of scope. The owner sets labels
  from their own devices.

## Agent: detecting the kind

The agent detects the kind once at start, caches it for the process lifetime,
and sends it on every heartbeat. Sending it every time costs a few bytes and
repairs the value after a server database restore. Detection reads a handful
of small files, runs no subprocess, and treats any read error as "not this
rule". The first rule that matches wins:

1. `/etc/wb-release` exists → `wirenboard`.
2. `/etc/openwrt_release` exists → `router`.
3. `/sys/class/dmi/id/chassis_type` (SMBIOS chassis type) reads:
   - 8, 9, 10, 14, 30, 31, 32 (portable, laptop, notebook, sub-notebook,
     tablet, convertible, detachable) → `laptop`;
   - 17, 23, 25, 28, 29 (main server chassis, rack mount, multi-system
     chassis, blade, blade enclosure) → `server`;
   - 3, 4, 5, 6, 7, 13, 15, 16, 35, 36 (desktop, low-profile, pizza box, mini
     tower, tower, all-in-one, space-saving, lunch box, mini PC, stick PC) →
     `pc`;
   - any other value (1 "other" and 2 "unknown", which is what most VMs
     report) → go on to rule 4.
4. Any `/sys/class/power_supply/*` entry with `type` = `Battery` and a
   `scope` other than `Device` → `laptop`. `scope=Device` marks a peripheral's
   battery (mouse, headset, UPS over USB HID), which says nothing about the
   host. This rule catches laptops whose DMI data is missing or wrong.
5. `/proc/device-tree/model` exists and is not empty, and DMI is absent →
   `sbc`. This covers Raspberry Pi, Orange Pi and similar ARM boards. Wiren
   Board also has a device tree, but rule 1 has already caught it.
6. Otherwise → `linux`.

Tablets (type 30) count as laptops on purpose: the set has no tablet icon,
and a laptop is the nearest match.

There is no local setting to force a kind. The owner's override on the server
does that, and it works from any device. Detection runs on Linux only. The
Android app is enrolled as a device too, but sends no `kind` (see Open
questions).

## Compatibility

| Combination | Result |
| --- | --- |
| Old agent → new server | No `kind` sent; `kind` stays null; clients draw the generic glyph unless the owner set an icon |
| New agent → old server | The old server's `HeartbeatRequest` ignores the unknown `kind` field (pydantic's default `extra="ignore"`). Nothing breaks |
| New agent with a new icon value → new server | Unknown `kind` ignored, previous value kept |
| Old app or old CLI → new server | The extra keys in `/devices` are ignored: the app parses with `ignoreUnknownKeys`, and the old CLI reads keys by name |
| New app → old server | No `label` key in `/devices`; the app hides «Подпись…» and «Значок…» and shows no labels (see the app's contract) |
| New CLI → old server | `devices label`/`icon` print the "upgrade the server" message; `list` shows `-` |
| Server rolled back after the migration | The old code selects named columns only, so the extra columns are ignored, and new rows get null in them. Labels come back once the server is upgraded again |

## Migration

The codebase has no migration framework. `server/db.make_engine` calls
`SQLModel.metadata.create_all`, which creates missing tables and does **not**
add columns to existing ones. Until now, no column had been added after the
first release.

The plan adds one small, idempotent step in `make_engine`, after
`create_all`:

- read `PRAGMA table_info(devices)`;
- for each of `label`, `icon` and `kind` that is missing, run
  `ALTER TABLE devices ADD COLUMN <name> VARCHAR` (nullable, no default,
  which is instant in SQLite whatever the table size);
- run inside one transaction, at every start. A database that already has the
  columns is left alone.

A unit test builds a database with the 0.3.x schema (no new columns, one
device row), opens it with the new `make_engine`, and checks that the row is
intact and the columns are null. A second test checks that a second open does
nothing. The installer's existing backup advice applies: copy the database
file before upgrading the server.

Whether this ad-hoc step should become a tiny versioned-migration helper is
a judgment call. One `ALTER` does not justify one now. The next column change
should decide (see Open questions).

## Security

- The label is owner-written text. Only the owner's own devices, and the
  admin's CLI on the server box, ever see it. No other user does.
- The server rejects control, line-separator and bidi characters (see Label
  rules), and the 64-code-point limit bounds the size. The heartbeat `kind`
  is never echoed raw: only known enum values are stored.
- **A label is display-only.** It must never reach a frp proxy or visitor
  name, `~/.ssh/config`, `/etc/hosts`, a file path, a shell command, a log
  line formatted as markup, or a URL. Names keep that job and their strict
  regex. A code review checks this for every place the label is read.
- Clients render it as plain text. The CLI escapes Rich markup. The app uses
  a plain `Text`, with no HTML, linkification or autolink.
- Authorization is the existing self-service boundary: an enabled device of
  the same owner. A disabled device's token cannot change labels.
- Not logged: the server does not write label text to its logs. It records
  only that a device's display fields changed.

This adds a row to the threat table in [security.md](security.md) when it
ships: "owner-written label text: validated, display-only".

## Tests

Unit tests only, in the existing files, to match the repo's one-to-one
layout:

- `test_registry.py`: the label rules, one case each (ok Cyrillic, too long,
  newline, ESC, a bidi override, whitespace-only clears, NFC); icon set and
  clear; lenient `kind` (known stored, unknown ignored, null keeps).
- `test_api.py`: `/devices` always has the three keys; `/display` with each
  body shape (label only, icon only, both, null, empty body → 400, bad icon →
  400, `"auto"` → 400); another owner's device → 404; caller disabled → 403;
  target disabled → OK; heartbeat with an unknown `kind` → 204, not 422.
- `test_client_cmds.py`: `label`/`--clear`/neither, `icon auto`, the
  old-server 404 message, markup escaping in `list`.
- A new `test_device_kind.py` (or one inside `test_agent_poller.py`): each
  detection rule against a fake root directory, plus unreadable files.
- Migration: the two tests above.

The integration suite does not change.

## Delivery

Small PRs, each with its tests, in this order:

1. **Server:** columns and migration, label and icon validation in
   `registry.py`, the `/devices` fields, the `/display` route, lenient `kind`
   in heartbeat, the Label column in `frp-jump-server devices list` and
   `users show`.
2. **Client CLI:** `devices label`, `devices icon`, the new `devices list`
   columns, the old-server message.
3. **Agent:** kind detection and `kind` in heartbeat.
4. **Docs:** `cli.md` (the new commands), `how-it-works.md` (labels and
   icons in a paragraph), `security.md` (the threat row), CHANGELOG; this plan
   deleted.

Then a release: version bump, tag, `.deb` and PyPI.

**Releasing, upgrading the server and upgrading agents each need the owner's
explicit go.** Merging the PRs does not imply any of them. In order:

1. Tag the release (go).
2. Upgrade the server: back up the database file, then install and restart
   (go). The migration runs on start.
3. Upgrade agents device by device (go). Until a device's agent is upgraded,
   its icon is the generic one or whatever the owner set.

The app side can ship before or after the server. Against an old server it
hides the feature (see the app's contract).

## Acceptance

- After the server upgrade, `devices list` from an old 0.3.x client still
  works, and all existing devices keep their names, tunnels and enabled
  state. The database has the three new columns, all null.
- An upgraded agent on a Wiren Board shows `wirenboard (auto)` in
  `frp-jump-client devices list` within one poll. On a laptop it shows
  `laptop (auto)`, on a Raspberry Pi `sbc (auto)`, and on a plain VM
  `linux (auto)`.
- `devices label wb01 "Щиток, гараж"` from a laptop appears on the phone's
  list within one refresh. `devices icon wb01 router` overrides the icon, and
  `devices icon wb01 auto` restores the detected one.
- `devices label wb01 $'a\nb'` is refused with the reason. A label of
  `[red]x` prints literally in `devices list`.
- An old agent left running reports no kind and keeps working. The new CLI
  against an old server prints the "upgrade the server" message.

## Out of scope

- Custom or uploaded icons, colours per device, and an admin command to set
  labels.
- Labels for connections (the app already names connections locally) or for
  users.
- Sorting or grouping by label.

## Open questions

1. **The phone as a device.** Each phone profile is a device in the owner's
   list. The set has no `phone`. Should a `phone` value be added, reported by
   the Android app in its heartbeat? Without one, phones show the generic
   glyph and the owner cannot pick a better one.
2. **VMs.** Should a VM (DMI vendor QEMU, VMware, Xen and so on) be detected
   as `server`, or stay `linux` as planned?
3. **Migration helper.** Keep the ad-hoc `ALTER` step, or introduce a tiny
   versioned-migration table now?
4. **Label length.** Is 64 characters enough, or too much for the list row?
   The app cuts it with an ellipsis in the list and shows it whole on the
   card.
