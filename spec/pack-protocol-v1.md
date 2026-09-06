# Countersign domain packs — protocol v1

Status: **draft**. Normative for `countersign-pack` and `countersign-db`.
Licence: Apache-2.0.

---

## 1. Why packs are a protocol and not a trait

The daemon knows about "approval requests with a payload". It does not know what
SQL is, what a Terraform plan is, or what an npm tarball is. Everything
domain-specific — statement classification, blast-radius estimation, what to put
on the screen — lives in a pack.

A pack is **an executable speaking line-delimited JSON-RPC 2.0 on stdio**, the
same shape MCP servers and language servers use. Not a Rust trait compiled into
the daemon, and not a dynamic library.

That choice costs a process spawn and buys three things that a compiled-in trait
cannot:

- **Any language.** The person who writes `countersign-tf` should not have to
  learn Rust, and should not have to be in your build.
- **No fork pressure.** A pack that ships on its own release cadence is a pack
  that gets written. A pack that requires a PR against the daemon is a fork.
- **A real boundary.** A pack cannot reach the USB handle, the policy engine, the
  audit log, or the enrolled keys, because it is not in that address space.

That last one matters more than it looks. §4 is what it buys.

---

## 2. Framing

JSON-RPC 2.0, one message per line, UTF-8, `\n`-terminated. No `Content-Length`
headers. stdin carries requests, stdout carries responses, **stderr is for logs
and is never parsed**.

```jsonc
--> {"jsonrpc":"2.0","id":1,"method":"describe"}
<-- {"jsonrpc":"2.0","id":1,"result":{ … }}
```

A pack MUST NOT write anything to stdout that is not a response. A pack that
prints a banner on startup has broken the transport; log to stderr.

---

## 3. Methods

### 3.1 `describe`

No parameters. Called once when the host starts the pack.

```jsonc
{
  "name": "countersign-db",
  "version": "0.1.0",
  "protocol": 1,
  "actions": ["sql"],
  "pure": true
}
```

`actions` lists the **namespaces** this pack claims — `"sql"` claims
`sql.execute`, `sql.ddl`, and anything else under `sql.`. A host MUST NOT route
a request to a pack that does not claim its namespace.

`pure` asserts that `classify` performs no I/O and no network access. See §5.

### 3.2 `classify`

```jsonc
{
  "action": "sql.execute",
  "statement": "DELETE FROM orders",
  "target": { "kind": "database", "uri_fingerprint": "9f2c…" },
  "hints": { "engine": "postgres" }
}
```

`hints` is free-form and OPTIONAL. A pack MUST behave correctly with no hints
at all — an engine hint may refine a dialect judgement, but a pack that only
works when told the engine is a pack that fails on the path that matters.

The pack MUST NOT be given the environment label, the tier, or any policy
state. It classifies the statement; it does not learn how serious the
environment thinks that is. Keeping that out is what makes a pack's answer
cacheable and its behaviour independent of what it would take to get approved.

Response:

```jsonc
{
  "action": "sql.dml",
  "severity": "high",
  "reversible": false,
  "render": [
    { "role": "primary",  "text": "DELETE FROM orders" },
    { "role": "advisory", "text": "no WHERE clause — every row" }
  ],
  "advisory": { "statements": 1, "unbounded": true },
  "warnings": ["DELETE without a WHERE clause removes every row."]
}
```

| Field | Rule |
|---|---|
| `action` | Refined verb. MUST be in the same namespace as the request (§4.1). |
| `severity` | `none` < `low` < `moderate` < `high` < `critical`. |
| `reversible` | `true`, `false`, or `null` for "unknown". `null` is a legitimate and common answer; a pack MUST NOT guess `true`. |
| `render` | Ordered display lines. Roles `primary` and `advisory` **only** (§4.2). |
| `advisory` | Structured, unverified detail. Rendered with a marker, never branched on. |
| `warnings` | Human-readable strings. Advisory. |

---

## 4. The security rules

A pack is third-party code that sees production statements and influences what
the screen says. These rules are what make that acceptable, and a host that
skips them has a plugin system where a pack is an auto-approve oracle.

### 4.1 A pack classifies. Policy decides. A pack may raise, never lower.

The host computes a **floor** for the request from its own configuration before
the pack runs — from the action namespace, the target's tier, and the requester.
The effective severity is:

```
effective = max(floor, pack.severity)
```

A pack cannot move a request below the floor the daemon already set. If it
could, the first thing an attacker would ship is a pack that classifies
`DROP TABLE` as `none`.

The refined `action` is subject to the same asymmetry: it MUST fall in the
requested namespace, so a pack can turn `sql.execute` into `sql.ddl` — which
policy rules key on — but cannot turn it into `noop.ping` to escape every rule
that mentions `sql`.

### 4.2 A pack cannot write the label or the digest

`render` accepts `primary` and `advisory` roles only. A host MUST reject a
response containing a `label` or `digest` line.

Those two roles are exactly the ones the requester must not influence. The
environment label is assigned by the daemon from local config, because otherwise
an agent claims it is talking to dev. The digest is the human's cross-check
between the screen and the signed bytes. A pack that could write either could
show `local` above a production `DROP`.

### 4.3 Failure is closed

If a pack crashes, times out, returns malformed JSON, or returns a response that
violates §4.1 or §4.2, the host MUST NOT treat the request as low-severity. It
MUST fall back to the un-refined action and a configured
`severity_on_pack_failure`, which defaults to `critical`.

A dead classifier means you do not know what the statement does. The safe
reading of "I don't know" is not "probably fine".

### 4.4 Timeouts are mandatory

Hosts MUST apply a wall-clock timeout to every `classify` call (the reference
host uses 2 s) and MUST treat expiry as §4.3 failure. Classification sits in
front of a human waiting at a device; a pack that hangs must degrade to friction,
not to a hang.

---

## 5. Packs see the statement, and the statement is the sensitive thing

`statement` is production SQL. It contains table names, and it contains literal
values — which means it contains customer data, often exactly the data the
operator has policies about.

Therefore:

- A pack MUST NOT perform network I/O. `pure: true` is an assertion the pack
  author makes and the operator relies on.
- A pack SHOULD NOT read or write files beyond its own configuration.
- Hosts SHOULD run packs sandboxed, and SHOULD make the set of enabled packs an
  explicit operator decision rather than a discovery mechanism that picks up
  whatever is on `PATH`.
- Pack authors MUST NOT log statements to stderr at default verbosity.

A pack that phones home has quietly turned an approval prompt into an
exfiltration channel, and it would do so on precisely the statements the
operator cared enough about to gate.

---

## 5.1 A pack cannot make the dial light up

Worth stating plainly, because "anyone can write a pack" sounds like it should
be alarming and is not.

A pack **classifies statements it is handed**. It cannot initiate a request,
cannot cause a presentation, cannot approve, and cannot make an action reach the
device. Requests come from requesters; whether one reaches a human is decided by
local policy, which the operator writes.

So an ecosystem of thousands of packs does not mean thousands of things that can
interrupt someone. A pack that nobody routes anything to never runs, and an
action namespace nobody enabled is refused without being shown — see wire spec
§6.2.2.

What a hostile pack *can* do is lie about severity, forge a display line, or
exfiltrate the statement it was given. §4 and §5 are the answers to those three,
in that order.

## 6. Determinism

`classify` SHOULD be a pure function of its input. The same statement, the same
answer, every time.

This is not fastidiousness: the same request may be classified more than once —
by the daemon before display, and by an auditor months later reconstructing what
the human saw. A pack whose answer drifts makes that reconstruction a guess.

---

## 7. Writing a pack

Rust authors get the trait and the stdio harness from `countersign-pack`:

```rust
use countersign_pack::{run_stdio, ClassifyRequest, ClassifyResponse, Pack, PackInfo};

struct MyPack;

impl Pack for MyPack {
    fn describe(&self) -> PackInfo { /* … */ }
    fn classify(&self, req: &ClassifyRequest) -> ClassifyResponse { /* … */ }
}

fn main() -> std::io::Result<()> { run_stdio(&MyPack) }
```

In any other language, implement §2 and §3 directly. The protocol is two methods
and one response shape; that is deliberate, and it is the size it needs to stay.

---

## 8. WebAssembly packs

§5 says hosts SHOULD sandbox packs. This section is how a pack ships so that
the sandbox is not something a host grants but something the pack cannot ask
its way out of.

A WebAssembly pack is a module with an **empty import section**. Not a WASI
command with no capabilities: a module that cannot name a syscall. No network,
no filesystem, no clock, no environment — because there is nothing to import
them through. A host MUST refuse to instantiate a module that imports anything.

### 8.1 The messages do not change

The host still sends the JSON-RPC messages in §3, one per call, and still
receives one response per message. What changes is where the bytes go: into
the module's linear memory, through four exports, rather than into a pipe.

```text
memory                                 the module's linear memory
countersign_alloc(len: u32) -> u32      reserve `len` bytes; returns a pointer
countersign_call(ptr: u32, len: u32) -> u64
                                        one request line in; `(ptr << 32) | len`
                                        of one response line out. The module
                                        takes ownership of the request buffer.
countersign_free(ptr: u32, len: u32)   release a response buffer
```

A `describe` or `classify` over this transport MUST produce the byte-identical
response it would over stdio. The Rust harness's `handle_line` answers both,
and `countersign_pack::export_pack!` emits the four exports around any `Pack`
implementation; other languages implement §2 and §3 and the four exports.

### 8.2 What the host bounds

A module that imports nothing can still loop forever or grow without limit. A
host MUST meter each call in **fuel** — a deterministic instruction budget,
the same on every machine — and MUST cap the module's linear memory. Exhausting
either is a §4.3 failure: `critical`, with the cause named, never a hang and
never "probably fine". The reference host grants 500 million units per call and
64 MiB of memory.

### 8.3 What a marketplace distributes

Only this. A native executable that sees production statements has every
capability the operating system gives it, and a public directory of those is
an exfiltration channel with a storefront. Native packs remain fully supported
on an operator's own machine, installed by hand, and are never listed.

A plugin's manifest (`countersign-plugin.json`) names the module, pins its
SHA-256, and lists the namespaces `describe` will claim. A host checks the hash
**every time it starts the pack**, not only at install — a plugin directory is
ordinary files, and a classifier swapped under a good manifest is exactly the
thing that check exists to notice.

### 8.4 The index

A marketplace is a repository holding one `index.json` and a directory per
plugin, each holding that plugin's manifest and the module it names. The index
is a list of claims, one per plugin:

```jsonc
{
  "v": 1,
  "plugins": [
    {
      "name": "countersign-db",
      "version": "0.1.0",
      "description": "SQL statement classification",
      "path": "countersign-db",          // the directory beside the index: a plain name, never a path
      "sha256": "…",                     // of the module; the manifest in that directory MUST pin the same
      "actions": ["sql"],
      "pure": true
    }
  ]
}
```

A host installing from an index MUST fetch the manifest and the module from
the named directory and nowhere else; MUST refuse a `path` that is not a plain
name; MUST refuse a manifest whose pack is not WebAssembly; MUST refuse unless
the index's hash, the manifest's pin and the module's bytes all agree; and
MUST instantiate the module, confirm it imports nothing, and confirm that
`describe` claims the namespaces, the version and the purity the manifest
claims — all **before** anything is written where a daemon will find it, and
whatever the result, installed **off**. The repository's CI runs the same
checks on every pull request. A host runs them anyway, because it cannot know
that CI did.
