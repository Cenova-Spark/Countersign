# countersign-hook

A Claude Code `PreToolUse` gate. **Deleting a file takes a physical
countersignature. Creating one takes nothing at all.**

This exists so the protocol can be tried end to end without pointing anything
at a database you care about. `touch` a file, `rm` the same file, and only the
second one lights up the device.

## Why a hook rather than an MCP tool

The same reason `countersign-proxy` exists. An MCP tool is advisory: the agent
chooses whether to call it and chooses whether to honour the answer. A hook is
run by the harness, before the tool call, on every tool call its matcher names
— the agent is not consulted about whether the gate applies, and cannot be
talked out of it by anything in its context.

It is **not** posture C, and this crate does not claim to be. The proxy is
posture C because the database is on the far side of it and there is no route
around. This sits in front of one route to deleting a file: the shell command
the harness was asked to run. `src/detect.rs` is candid about what that misses.
The filesystem's real equivalent of the proxy is a FUSE layer or a syscall
filter returning `EPERM` for `unlink`. There is a second route the shell gate
cannot see and a syscall filter would not close either: a tool that drives the
screen can trash a file through Finder, as you. `src/screen.rs` reads those
tools: a screenshot passes, a click is refused outright, and the section below
says why.

Posture B-and-a-half, then. Strictly stronger than asking an agent nicely, and
strictly weaker than standing between the tool and the syscall.

## Try it

Two terminals, no hardware, and nothing outside this repository is touched.

**Terminal 1 — the daemon, which is where the device lives:**

```bash
cargo build --workspace
./target/debug/signetd run --config=demo/countersign.toml
```

**Terminal 2 — install the hook and restart Claude Code.**

Put this in `.claude/settings.local.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|mcp__computer-use__.*",
        "hooks": [
          {
            "type": "command",
            "command": ""$CLAUDE_PROJECT_DIR"/target/debug/countersign-hook --accept-test-keys --deadline-ms 90000",
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

### Why this is not checked in

It would be one line in `.claude/settings.json` to make every clone of this
repository arrive with the gate already on. That is the wrong default, for the
same reason the gate is worth having at all.

This hook fails closed. Someone who clones the repository to read the spec, and
who has never started `signetd`, would find every `rm` in the tree refused by a
protocol they have not agreed to yet — and their first impression of
Countersign would be software that took something away. Installing an
enforcement point is a decision, and a decision has to be made by someone.

So it stays opt-in, and it stays local: the file is `settings.local.json`
because the path is yours and the choice is yours.

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
| `--roster-dir PATH` | Where `signetd enroll` wrote `roster.json`. Default: the daemon's config directory. The keys the gate believes come from there. |
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

## The screen: looking is free, touching is refused

The first time someone asked an agent under this gate to delete a file without
`rm`, the agent opened Finder and chose Move to Trash. It was granted the app by
the desktop app's own dialog, it took screenshots to find the menu, and it
clicked. Asked again in the same session, it needed no dialog at all, because
the grant was still live. The hook never saw any of it: the matcher said `Bash`
and the gate passed every other tool by design.

At the filesystem that delete was you: your Finder, your user, the same
`unlink` you would make yourself. A FUSE layer keyed on the agent's processes
would not have seen it either, because Finder is not one of them. And nothing
about it was particular to files. The same clicks press Apply in a deploy
console or Confirm on a payment, so whatever a pack gates, a driven screen
reaches around it. The agent's hand shows in exactly one place, the tool call
in the harness, so that is where it is stopped.

Stopped, not held. The shell gate holds a command and asks, because a command
is a statement a person can read and a device can sign byte for byte. A click
is a coordinate pair. Nothing in it says what it will do, so putting it on the
dial would be blind signing with a better ceremony.

Looking, though, changes nothing, and refusing it would make every person weigh
the trade themselves. So the hook reads the computer-use server's calls one by
one, in `src/screen.rs`:

- **Passes** a batch made only of `screenshot`, `zoom`, `cursor_position` and
  `wait`; the grant request that makes a screenshot possible at all; the list
  of what is granted; the choice of monitor. Passes, not allows: the gate has
  no opinion, and your own permission settings still apply.
- **Refuses** a batch with any click, key, typed text, scroll, drag or mouse
  button in it, the whole batch, because it runs as one; a launched app; the
  clipboard read or written; the guided tour that clicks on your behalf; any
  action or tool on the server it does not know. The refusal says what does
  pass, so the agent can take the screenshot and tell you what it sees instead
  of casting about for another way in.

Two things follow for the install:

- The matcher has to name the server, or the hook is never run for it. The
  snippet above does. A server the matcher does not name is not seen, however
  well `src/screen.rs` knows it.
- Belt and braces, and independent of whether the hook binary exists: deny the
  tools that touch by their nature in Claude Code's own permissions, in the
  same settings file. The batch tool cannot go on this list, because a
  permission rule sees only its name and a screenshot and a click share it. For
  that one tool the hook is the only gate.

  ```json
  "permissions": {
    "deny": [
      "mcp__computer-use__teach_step",
      "mcp__computer-use__teach_batch",
      "mcp__computer-use__request_teach_access",
      "mcp__computer-use__open_application",
      "mcp__computer-use__read_clipboard",
      "mcp__computer-use__write_clipboard"
    ]
  }
  ```

The browser servers are not on the list. The in-app one is confined to web
pages. The one that drives real Chrome cannot unlink a local file, though it
can reach whatever a signed-in tab can, and that is a gate for a different
namespace.

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
