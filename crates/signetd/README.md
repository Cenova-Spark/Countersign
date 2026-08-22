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
| `--device=mock` | Prompt on the daemon's terminal. The default. |
| `--device=mock:auto` | Approve everything with no human. Smoke tests only — there is no approval step in it. |
| `--device=mock:script=P` | Consume `["approve","abort","expire"]` from a JSON file, in order, then abort. |

## Environment

| Variable | Meaning |
|---|---|
| `COUNTERSIGN_CONFIG` | Config file path. |
| `COUNTERSIGN_SOCK` | Control socket path. |
| `COUNTERSIGN_RUNTIME_DIR` | Where the socket and mock counter live. |
| `XDG_CONFIG_HOME` | Root for config and the audit trail. |

## What it writes

```
~/.config/countersign/audit/chain.jsonl      digests, decisions, signatures
~/.config/countersign/audit/payloads.jsonl   the statements
```

Deleting `payloads.jsonl` is supported: the chain still verifies, every
signature still verifies, and every approval still names who gave it. That is
the whole point of the split — see [`spec/audit-v1.md`](../../spec/audit-v1.md).
