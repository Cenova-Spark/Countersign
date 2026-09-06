---
name: countersign-plugin
description: Turn a plain description of something that should need a person's approval ("ask me before anything deploys to production", "gate kubectl delete", "require a countersignature for payments over $1000", "make Claude ask before it pushes to main") into a working Countersign plugin — a WebAssembly pack that classifies those statements, rendered on the approval window, built, checked, installed, and tried end to end. Use this whenever the user wants to gate, guard, affirm, approve, countersign or "ask me first" for some kind of action, wants a Countersign plugin or pack for a new domain, mentions a namespace or the marketplace, or has installed Countersign and wants something of their own to test it with, even if they never say the word "plugin".
---

# A Countersign plugin from a description

A pack answers one question for the daemon: *given this statement in my
namespace, how bad is it, and what should the approval window show?* It
decides nothing — policy decides — and it connects to nothing: the statement it
sees may be production text. What you build here is a small, pure Rust crate
compiled to WebAssembly, installed switched off, and turned on by a person.

Three rules the host enforces, so write toward them rather than around them:

1. **A pack may raise severity and never lower it.** When unsure, say more.
   The honest answer costs the person one dial turn; the flattering answer
   costs them the thing the statement destroys.
2. **A pack cannot write the label or the digest.** Those two lines are the
   daemon's. Everything else on the screen — the statement, the advisory —
   is the pack's.
3. **Failure is closed.** A crash, a timeout, a malformed answer or an action
   outside the namespace all become `critical` with the cause named. There is
   no reward for a fragile pack, so keep `classify` simple and total.

And one fact that decides whether the person can *see* the pack work: **a
pack classifies what something asks for.** The Postgres proxy asks for SQL and
the Claude Code hook asks for deletes; nothing else asks for anything yet. For
any new namespace, the requester is `signetd ask` (typed by hand), the MCP
bridge's `request_approval` tool, or a client the person writes. Say this
early, so nobody waits for a pack to intercept something it cannot see.

## 1. Read the description into a namespace

Before any code, turn the prompt into a short table and show it. Most
descriptions are decided by five things:

| Decide | From the description | Example: "ask me before anything deploys to production" |
|---|---|---|
| **namespace** | the domain, one lowercase word | `deploy` |
| **actions** | the verbs inside it, 2–5, as `namespace.verb` | `deploy.plan`, `deploy.apply`, `deploy.rollback` |
| **severity** per action | none for reads, low for additive, moderate for bounded change, high for unbounded or privileged, critical for destruction | `plan` none · `apply` high, **critical when it names production** · `rollback` moderate |
| **reversible** | whether it can be undone, when known; `None` when it cannot be known | `plan` yes · `apply` no · `rollback` yes |
| **on the screen** | what a person must read before holding; the statement itself, plus an advisory line for what cannot be undone | the statement; "cannot be undone" on a production apply |

Two things people get backwards:

- **The pack does not know the environment.** The daemon adds the label and
  the tier from *its* configuration and takes the maximum of its floor and the
  pack's severity. So "production" in the statement text may raise severity —
  a pack may raise — but a pack must never lower because the text says
  "staging". Classify the statement; leave the environment to the daemon.
- **Unknown is not harmless.** A verb the pack does not recognise is
  `high`, with `reversible: None`. That is the template's default, and it is
  right: an unclassified statement in a namespace that asked for approval is
  exactly the one that should get a careful reading.

If the description is really two domains ("deploys and database migrations"),
make two packs. A namespace is the unit that is turned on and off.

`references/classify-patterns.md` has the idioms for the common shapes —
verb-first statements, flags, resources, amounts, hosts — and the mistakes to
avoid. Read it when the mapping is not obvious from the table.

## 2. Scaffold

Everything runs from the Countersign checkout with its daemon built:

```bash
ROOT=$(git rev-parse --show-toplevel)
cargo build -q -p signetd                       # once
SIGNETD=$ROOT/target/debug/signetd
```

Then scaffold. The script wraps `signetd pack new` and points the crate's one
dependency at this checkout, because the published dependency line points at
the repository and that only resolves once the work is pushed:

```bash
$ROOT/.claude/skills/countersign-plugin/scripts/new-pack.sh countersign-deploy deploy
```

This writes `$ROOT/plugins/countersign-deploy/` with `Cargo.toml`,
`src/lib.rs`, `src/main.rs`, a README and a `.gitignore`. Names are lowercase
letters, digits and hyphens; the namespace is the same shape with no dot. A
third argument puts it somewhere else.

## 3. Write `classify`

Open `src/lib.rs`. The template already has the shape: a `NAMESPACE`
constant, a stateless `ExamplePack`, `describe` claiming the namespace, and a
`classify` that decides an action, a severity and reversibility from the
first word, then renders the statement. Replace the middle with the table
from step 1 and rename `ExamplePack` to something honest.

Keep it a pure function of `req.statement` (and `req.action`, which is the
action the requester asked for — refine it inside the namespace, never leave
the namespace). No I/O, no clock, no randomness, no environment: the module
cannot reach any of them and the native build is trusted not to. Standard
library string operations are enough; a regex crate is weight the module does
not need.

Render what a person needs. `RenderLine::primary` is the statement, wrapped
or trimmed only if it is very long; `RenderLine::advisory` is context that is
not verified — "cannot be undone", "names production", a count the requester
sent in `req.hints`. Never put the environment label or the digest in a line;
the host refuses the whole answer if a pack emits those roles.

Then the tests. Keep the template's five and add one per action, each
through the `classify` helper that runs the host's own `validate`, so an
answer outside the namespace or with a forbidden line fails here rather than
in front of a person. `cargo test` in the pack directory.

## 4. Build, check, install

```bash
$ROOT/.claude/skills/countersign-plugin/scripts/build-and-check.sh $ROOT/plugins/countersign-deploy
```

That runs the tests, builds the module for `wasm32-unknown-unknown`, and
prints `signetd pack info` on it. Read the report: `imports none` is the
sandbox; `answers` must name the namespace from step 1; `pure: yes`. If the
report says the module imports something, a dependency pulled in a syscall —
remove it.

Install it, switched off, then turn it on:

```bash
$SIGNETD pack install $ROOT/plugins/countersign-deploy/target/wasm32-unknown-unknown/release/countersign_deploy.wasm
$SIGNETD pack enable countersign-deploy
```

The daemon reads the packs directory when it starts, so it has to restart.
If the Signet app is running, its Plugins tab does this: the pack is already
listed there, and flipping its switch on restarts the daemon (so do the
`enable` step there instead of on the command line, if you prefer). If a
daemon was started by hand with `signetd run`, stop and start it.

Say what "off" means while it is off: an installed pack that is off makes
its whole namespace refused without asking. Nothing is broken; the gate is
closed until a person opens it.

## 5. Try it

Ask for something, the way a requester would:

```bash
$SIGNETD ask --action deploy.apply --statement "deploy api v2.3 to prod" --target deploy://prod-eu
```

The approval window appears with what the pack made of it: the refined
action's severity on the label bar, the statement as the pack rendered it,
the advisory line if any, and the digest. The person holds, or declines, and
`ask` prints the decision and exits non-zero unless approved. Try a read, a
change and a destructive statement, and check each lands where the table
said. One thing will look off and is not: a read the pack called `none` shows
as `moderate` or so, because the daemon takes the maximum of the pack's
answer and its own floor for the environment. That is the host raising, which
it may; the pack's answer is the one that goes up from there. With `--target`
naming something the daemon's `config.toml` knows, the label and tier come
from there; with nothing named, it is an unknown target, which is production,
which is the point.

A pack that never shows up: the namespace is not presentable. Either the pack
is off, or the daemon has not restarted since it was turned on. `signetd pack
list` says which.

## 6. Publish, if it should be shared

```bash
$SIGNETD pack publish $ROOT/plugins/countersign-deploy/target/wasm32-unknown-unknown/release/countersign_deploy.wasm \
  --into $ROOT/marketplace --description "…" --license Apache-2.0 --source https://…
```

That copies the module and its manifest into `marketplace/<name>/`, writes
the index entry, and runs every check an install runs. The pull request is
the person's to open. Only do this when asked; a pack for one machine does
not need to be listed.

## What to hand back

The table from step 1, the path of the crate, the `pack info` report, and the
three `ask` commands (read, change, destroy) the person can run to see it.
Say plainly that the pack sees only what asks for its namespace, and name what
that is for them: `signetd ask` today, the MCP tool from a Claude Code session,
or a requester of their own with the TypeScript SDK.

## Traps

- The checkout's Claude Code hook gates `rm` in Bash through the daemon. Do
  not delete in tool calls; leave temporary files.
- `rustup target add wasm32-unknown-unknown` once, or the module build fails
  with a missing target.
- Do not install a pack from a path under `target/debug`; install the wasm
  module. A native binary installs too but is never listed and is never what
  this skill produces.
- Two packs claiming the same namespace: the daemon presents what the running
  pack claims; the second one on is a mistake the person should be told about.
- The daemon that the app runs uses the default socket and config directory.
  `pack install` writes there. To keep a try-out away from it, set
  `XDG_CONFIG_HOME`, `COUNTERSIGN_RUNTIME_DIR` and a short `COUNTERSIGN_SOCK`
  for both the daemon and every `signetd` call.
