# signetd

The daemon. It owns the device, classifies environments from local config,
enforces policy, presents payloads for approval, and writes the audit trail.

Everything it produces today is signed with the **published test key**, so a
default verifier refuses all of it. That is deliberate — see
[`spec/countersign-v1.md`](../../spec/countersign-v1.md) §8.

## Try it

Two terminals. The daemon lives in the first one, because that is where it asks
you to approve things.

**Terminal 1 — the daemon and the device:**

```bash
cargo build --workspace
./target/debug/signetd fingerprint "postgres://user:pass@db.example.com/app"
```

Put the fingerprint it prints into `~/.config/countersign/config.toml`:

```toml
[[environment]]
label = "prod-us-east-1"
tier  = "production"
uri_fingerprints = ["<the fingerprint>"]

[policy]
default_tier = "production"
on_no_device = "deny"

[[policy.rule]]
tier = "production"
actions = ["sql.read"]
decision = "auto_approve"

[[policy.rule]]
tier = "production"
decision = "require_approval"
```

Then start it:

```bash
./target/debug/signetd run
```

It prompts *in this terminal* when something needs approving. That is the mock
standing in for the device.

**Terminal 2 — check it is up:**

```bash
./target/debug/signetd status
```

## Wiring it to Claude Code

The daemon is shared; each Claude Code client spawns its own thin bridge. Only
one process can own a device, which is why it is split this way — and it is what
lets the terminal, VS Code and the desktop app all work at once.

```bash
claude mcp add countersign -- /absolute/path/to/target/debug/signetd mcp
```

Or, per project, in `.mcp.json`:

```json
{
  "mcpServers": {
    "countersign": {
      "command": "/absolute/path/to/target/debug/signetd",
      "args": ["mcp"]
    }
  }
}
```

Use an absolute path — the bridge is spawned with an unpredictable working
directory. If your socket path ends up long (a deep `XDG_RUNTIME_DIR`), set
`COUNTERSIGN_SOCK=/tmp/countersign-$USER.sock` for both the daemon and the
clients; unix sockets cap out around 100 bytes and `signetd` will say so.

Then ask Claude to delete something it should not:

> Using countersign, request approval to run `DELETE FROM orders` on
> postgres://user:pass@db.example.com/app

Terminal 1 shows the environment, the statement, the blast-radius warnings and a
digest. Claude shows you the same digest. **Confirm they match**, then approve.

## Why the dial stays rare

`signetd` refuses any action whose namespace you have not enabled — it does not
show it and ask. A namespace becomes enabled by being named in a rule's
`actions` (or listed in `policy.presentable`).

That is deliberate and it is a security control, not tidiness. If any plugin
could make the dial light up, someone could wire a turn to "skip track", let the
habit form for a week, and then time a real `DROP TABLE` to land as you reached
for it. You would turn without reading, and the cryptography would have worked
perfectly the whole time.

Two consequences worth knowing before you configure this:

- **Put macros on the buttons, never the dial.** The device is a working macro
  pad over plain HID, with no software at all. The dial is not an input device.
- **Auto-approve generously at low severity.** Every prompt you did not need
  trains the reflex. A daemon that asks about routine reads is manufacturing the
  problem it is trying to prevent.

The device also refuses a turn that arrives too fast to have read the payload —
400 ms for something trivial, 2 s for something destructive — and any new
payload restarts that clock, so a request timed to arrive mid-gesture cannot
borrow it.

## Working over SSH

You are on your laptop with the device. The agent is on a box you SSH'd into.
This is the `ssh-agent` problem and it has the same shape as the answer.

Start the daemon with a second socket for tunnelled clients:

```bash
./target/debug/signetd run --forward
```

Then forward it, exactly as you would `SSH_AUTH_SOCK`:

```
# ~/.ssh/config
Host devbox
  RemoteForward /run/user/1000/countersign.sock /run/user/1000/countersign-forward.sock
```

On the remote host, point clients at the forwarded socket:

```bash
export COUNTERSIGN_SOCK=/run/user/1000/countersign.sock
```

**Forwarding is delegation.** Anything on that remote host can now ask — not
only the agent you meant. The blast radius is bounded, because every approval
still needs a physical turn over a payload you can read, but that display is now
the entire defence. So:

- Requests arriving on the forward socket are shown as
  `VIA FORWARDED SOCKET · …`, leading the requester line.
- A forwarded client counts as a different requester from your local one, so
  switching between them takes an acknowledgement.
- Policy can scope them. Put a tighter rule above the general one:

```toml
[[policy.rule]]
tier = "production"
origin = "forwarded"
actions = ["sql.ddl"]
decision = "deny"          # DDL from a tunnel is never even offered

[[policy.rule]]
tier = "production"
actions = ["sql"]
decision = "require_approval"
```

The two sockets exist because SSH `RemoteForward` connects back to a local
socket — a tunnelled request and a local one arrive identically, and the daemon
would otherwise be guessing.

## Device modes

| Mode | Behaviour |
|---|---|
| `--device=mock` | Prompt on the daemon's terminal. The default. Not combinable: it waits on a keyboard, which nothing can withdraw. |
| `--device=mock:auto` | Approve everything with no human. Smoke tests only — there is no approval step in it. |
| `--device=mock:script=P` | Consume `["approve","abort","expire"]` from a JSON file, in order, then abort. |
| `--device=relay` | Ask a paired phone through the relay. `signetd pair` first. A phone approves with its enclave key once enrolled (below); the relay's browser page approves with a published test key. |
| `--device=app` | The desktop app attaches over the control socket and approves with its enclave key. Produces an approval a default verifier accepts, once the key is enrolled (below). |

Modes combine with commas — `--device=app,relay` asks the app on this machine
and the phone at once. The first valid signature wins and the rest are
withdrawn; one request still yields one signature.

The mock, and the relay's browser page, sign with **published test keys**;
nothing they produce counts. An app or a phone signs with a key the daemon has
never seen the private half of, enrolled as class `enclave` — see
[`spec/device-classes-v1.md`](../../spec/device-classes-v1.md). The daemon
verifies a phone's approval against its own roster, never against the relay's
word: the relay registers keys, the daemon enrolls them, and only the second one
makes a signature count (device-class spec §6).

## Enrolling a device

A device may approve only once the daemon knows whose key it is. That is the
ceremony in [`spec/enrollment-v1.md`](../../spec/enrollment-v1.md) §2, run on
the device itself:

```bash
./target/debug/signetd enroll --subject you@example.com --display "Your Name"
```

The device shows *Enroll this device as an approver for you@example.com*, and
you hold. The record — class, public key, and the countersigned proof — lands in
`~/.config/countersign/roster.json`, the operator's own roster (the *direct*
trust model). An attached app that is not yet enrolled is shown nothing but this
ceremony; approvals wait until it is.

A phone enrolls the same way, through the relay: register it on the account
(`web/`, *Phones*), start the daemon with `--device=relay` (or `app,relay`),
run `signetd enroll`, and hold on the phone. The daemon verifies the ceremony
against the key the phone shows, looks that key up in what the relay lists to
write the record, and from then on verifies every approval against the record
— never against the relay's listing. When several kinds of device could
answer, the ceremony's screen says the record takes the class of whichever
signs.

Enrolling the mock works too, and produces a record whose class is `test`. The
record is real; the key is not.

## Plugins

A pack classifies statements in a namespace — `countersign-db` does SQL. Packs
install into `~/.config/countersign/packs/`, switched **off**:

```bash
cargo build -p countersign-db --lib --target wasm32-unknown-unknown --release
./target/debug/signetd pack info    target/wasm32-unknown-unknown/release/countersign_db.wasm
./target/debug/signetd pack install target/wasm32-unknown-unknown/release/countersign_db.wasm
./target/debug/signetd pack list
./target/debug/signetd pack enable countersign-db
```

`pack info` is the look before the install. It shows the manifest, whether
the artifact is the one the manifest pins, a module's imports — none is the
sandbox — and, for a module, what the pack answers to `describe` when asked
inside that sandbox, next to what the manifest claims. Where the two
disagree, it says so: the daemon presents what a running pack claims and no
more. A native pack is not run by `info`. Nothing is installed or switched.

`pack new <name> [--namespace NS]` writes a pack crate to start from — the
one in `templates/pack`, renamed. It compiles, its tests are the host's rules,
and its README walks from `cargo test` to `pack install`.

### The marketplace

An index and a directory per plugin (`marketplace/` in this repository for
now; pack protocol §8.4 is the format):

```bash
./target/debug/signetd pack index                    # what is listed
./target/debug/signetd pack info countersign-db      # fetched and checked here, not installed
./target/debug/signetd pack install countersign-db   # installed, off
./target/debug/signetd pack publish path/to/my_pack.wasm --into path/to/marketplace \
    --description "…" --license Apache-2.0        # staged for a pull request
```

A name that is not a path is looked up in the index. `COUNTERSIGN_INDEX` or
`--index` points at another index, a URL or a directory; a checkout's own
`marketplace/` is how a demo runs offline. Everything installed from an index
is WebAssembly, and is refused unless the index's hash, the manifest's pin and
the module agree and `describe` claims what the manifest claims — checked on
this machine, whatever the repository's CI did. `--json` on `list`, `info` and
`index` is what the Mac app reads.

Two states, and they are the two the spec already has:

- **Installed** means the directory exists. The daemon knows which namespaces
  the pack claims from its manifest, without running it.
- **On** means the pack runs and its namespaces are presentable.

The switch is a hard gate. A pack that is installed and off makes its whole
namespace **refused without asking** — not shown verbatim at the tier floor,
which is what a namespace nobody claims gets. Nobody is home to classify the
statement, and an operator who switched a pack off meant for the dial to stay
dark. The refusal names the pack and the command that turns it back on.

Anything installed from a `.wasm` runs sandboxed: the module imports nothing,
so it cannot reach a network or a filesystem, and every call is metered. A
plugin directory holding a `countersign-plugin.json` and a native executable
installs the same way and runs as a subprocess — fine for your own packs, never
what a marketplace distributes. The artifact's hash is checked every start.

With nothing installed, the daemon falls back to the `countersign-db` binary
beside its own, so a fresh checkout still classifies SQL.

## Starting over

For demos and development, a fresh start:

```bash
./target/debug/signetd wipe          # says what would go
./target/debug/signetd wipe --yes    # goes
```

It removes the roster, the audit trail, installed plugins and their switches,
the hook's replay state, the device counters and the relay pairing, and it
refuses while a daemon is listening, because a running daemon would write the
roster and the chain straight back. `config.toml` stays: that is
configuration, not data. The Mac app's enclave key is in the keychain under
the app's identity, so only the app can forget it — **Devices → Start over**
in the menu does both, and comes back with a new key and an empty roster.

## Environment

| Variable | Meaning |
|---|---|
| `COUNTERSIGN_CONFIG` | Config file path. |
| `COUNTERSIGN_SOCK` | Control socket path. |
| `COUNTERSIGN_RUNTIME_DIR` | Where the socket, mock counter, and app counters live. |
| `COUNTERSIGN_PACKS_DIR` | Where plugins install. Defaults to `<config>/packs`. |
| `COUNTERSIGN_INDEX` | The marketplace index: a URL or a directory. Defaults to this repository's `marketplace/`. |
| `XDG_CONFIG_HOME` | Root for config and the audit trail. |

## What it writes

```
~/.config/countersign/audit/chain.jsonl      digests, decisions, signatures
~/.config/countersign/audit/payloads.jsonl   the statements
~/.config/countersign/roster.json            your enrolled devices, with proofs
~/.config/countersign/packs/packs.toml       installed plugins, on or off
```

Deleting `payloads.jsonl` is supported: the chain still verifies, every
signature still verifies, and every approval still names who gave it. That is
the whole point of the split — see [`spec/audit-v1.md`](../../spec/audit-v1.md).
