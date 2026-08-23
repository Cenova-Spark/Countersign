# countersign-hook

A Claude Code `PreToolUse` gate. **Deleting a file takes a physical
countersignature. Creating one takes nothing at all.**

This exists so the protocol can be tried end to end without pointing anything
at a database you care about. `touch` a file, `rm` the same file, and only the
second one lights up the device.

## Why a hook rather than an MCP tool

The same reason `countersign-proxy` exists. An MCP tool is advisory: the agent
chooses whether to call it and chooses whether to honour the answer. A hook is
run by the harness, before the tool call, on every tool call — the agent is not
consulted about whether the gate applies, and cannot be talked out of it by
anything in its context.

It is **not** posture C, and this crate does not claim to be. The proxy is
posture C because the database is on the far side of it and there is no route
around. This sits in front of one route to deleting a file: the shell command
the harness was asked to run. `src/detect.rs` is candid about what that misses.
The filesystem's real equivalent of the proxy is a FUSE layer or a syscall
filter returning `EPERM` for `unlink`.

Posture B-and-a-half, then. Strictly stronger than asking an agent nicely, and
strictly weaker than standing between the tool and the syscall.

## Try it

Two terminals, no hardware, and nothing outside this repository is touched.

**Terminal 1 — the daemon, which is where the device lives:**

```bash
cargo build --workspace
./target/debug/signetd run --config=demo/countersign.toml
```

**Terminal 2 — register the hook and restart Claude Code:**

`.claude/settings.json` in this repository already does this:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/target/debug/countersign-hook --accept-test-keys --deadline-ms 90000",
            "timeout": 120
          }
        ]
      }
    ]
  }
}
```

Hooks are read when a session starts, so restart Claude Code after editing it.
That is a safety property rather than an inconvenience: an agent that could
install a hook mid-session could install one that approves things.

Then ask for the two halves of the demo:

> Create an empty file at `demo/scratch.txt`.

Nothing happens. No prompt, no round trip to the daemon, no audit entry.

> Now delete `demo/scratch.txt`.

Terminal 1 shows the environment, the command, and a digest. Type `ack`, then
`turn`. The delete proceeds, and the signature covering that exact command is
in the audit trail.

Dismiss it instead — press Enter — and the tool call is denied. The agent is
told why and the refusal is recorded.

## Checking the detector without asking anyone

```bash
./target/debug/countersign-hook --explain 'touch a.txt && rm b.txt'
```

## Flags

| Flag | Meaning |
|---|---|
| `--accept-test-keys` | Accept **published test key** signatures. Demos only. |
| `--socket PATH` | `signetd` control socket. |
| `--state-dir PATH` | Where device counters are remembered between calls. |
| `--deadline-ms N` | Deny on our own initiative after this. Default 90 s. |
| `--explain CMD` | Print what the detector sees, and exit. |

`--deadline-ms` must stay **below** the harness's `timeout`. If the harness
gives up first the hook returns nothing, and nothing means "no opinion" — which
in a permissive session lets the delete through. The hook denying itself a
little early is what stops a slow approval from becoming a fail-open.

## It verifies rather than trusts

The daemon saying "approved" is not enough. The hook checks the signature
itself, against the exact command string about to run and the exact working
tree it is about to run in. The same code path refuses a forged approval from
the daemon it is talking to, which is what makes it an enforcement point rather
than a relay of someone else's opinion.

Device counters live in `--state-dir` and survive between calls. A hook is a
fresh process per tool call, so without that there would be no replay defence
here at all.

## Failure is closed

No daemon, an unparseable payload, an unverifiable signature, a counter that
cannot be persisted, a deadline reached — every one of them denies. A gate that
let deletions through whenever its daemon was down would be defeated by
stopping the daemon.

The cost is real and worth knowing before you install it: with the daemon
stopped, every `rm` in this repository is refused until you start it again. The
message says so and names the fix.

## Known friction: the acknowledgement fires every time

`signetd` keys its requester-continuity check on the control-socket connection,
because that is the only thing about a caller it can actually verify. The MCP
bridge holds one connection for a whole session, so the check means what it is
supposed to mean: *the thing asking has changed*.

A hook is a new process, and therefore a new connection, on every tool call. So
the check reads "changed" every single time, and the operator types `ack`
before `turn` on every delete — which drains the acknowledgement of the
information it was created to carry.

That is a protocol question, not a bug in this crate, and it applies to every
per-invocation enforcement point: a hook, a CLI, a cron job. Three candidate
answers, none of them taken yet:

- **Live with it.** Two words instead of one, and the acknowledgement means
  nothing. This is the current behaviour and the honest reading of it is that
  the check has been turned into ceremony.
- **Key continuity on something stabler than the connection** — the requester's
  claimed id plus its instance, say. But those are claims, and the whole reason
  the check uses the connection is that the connection is the one thing the
  daemon can verify. A check keyed on a claim can be defeated by making the
  claim.
- **Let a client register a session** across connections, and have the daemon
  verify the peer credentials it can actually see. More machinery, and the only
  option that keeps the acknowledgement meaning what it says.
