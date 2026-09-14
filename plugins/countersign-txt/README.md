# countersign-txt

Ask before a `.txt` file is deleted; let other files go.

A Countersign domain pack for the `fs` namespace. That is the namespace the
Claude Code hook (`countersign-hook`) asks in: every shell command that
removes something reaches `signetd` as `fs.delete`, with the command,
verbatim, as the statement. This pack reads the command and says which of
three things it is. Policy, in the daemon's `config.toml`, decides what
happens to each.

| The pack answers | When | Severity | Undo |
|---|---|---|---|
| `fs.delete.text` | a `.txt` file is named | critical | no |
| `fs.delete.other` | every path named is a file, none `.txt` | high | no |
| `fs.delete.unknown` | it removes something the pack cannot name | critical | unknown |

`unknown` covers a directory and what is inside it (`rm -r`), a pattern
(`*.log`), a variable (`$FILE`), `find -delete`, `git clean`, a script run
through `sh -c` or `python3 -c`, and any statement the pack cannot read. The
pack looks at nothing but the text — no filesystem — so it cannot know
whether `build/` holds a `.txt` file. It does not pretend to. A pack may
raise severity and never lower it, and "I cannot see what this removes" is
the case that rule was written for.

A `.txt` name anywhere among what is removed makes it `text`: `rm -rf build
notes.txt`, `sudo rm -f notes.txt`, `find . -name '*.txt' -delete`, `sh -c
"rm a.txt"`. Case does not matter (`NOTES.TXT` counts); `notes.txt.bak` is
not a `.txt` file. A piece of the command that removes nothing is ignored, so
`rm a.rs; echo done > log.txt` is `other`: writing a `.txt` file is not
deleting one.

## What "other files are fine" looks like

The pack does not decide that. It cannot — a pack that could lower severity
is a pack that could wave a `DROP TABLE` through — and switching it on makes
every `fs` request ask, because that is the daemon's default for anything
nobody wrote a rule about. The rule is the operator's, in
`~/.config/countersign/config.toml`:

```toml
[policy]
default_tier = "production"
on_no_device = "deny"

# Files named that are not .txt: let them go, and record it.
[[policy.rule]]
actions = ["fs.delete.other"]
decision = "auto_approve"

# Everything else in fs asks: a .txt file, and anything the pack could not
# see into. Add "fs.delete.unknown" to the rule above instead if a directory
# tree should go through without asking.
[[policy.rule]]
actions = ["fs"]
decision = "require_approval"
```

First match wins, so the narrow rule sits above the wide one. The hook
honours an auto-approval without a signature — no human was asked, so none
is expected — and every one is recorded in the audit chain.

## Build, check, install

```bash
cargo test
cargo build --lib --release --target wasm32-unknown-unknown
signetd pack info    target/wasm32-unknown-unknown/release/countersign_txt.wasm
signetd pack install target/wasm32-unknown-unknown/release/countersign_txt.wasm
signetd pack enable  countersign-txt
```

`pack info` shows what the module claims, asked inside the sandbox: no
imports, so it cannot reach a network, a filesystem or a clock. `pack
install` writes the manifest, pinned to the module's hash, and leaves the
pack **off**. Off is not "unclassified": an installed pack that is off makes
its whole namespace refused without asking, so the hook's deletes are refused
until `pack enable`. The daemon reads its packs at start, so restart it — the
Signet app's Plugins tab does that when its switch is flipped.

## Try it

Ask the way the hook does, one of each:

```bash
signetd ask --action fs.delete --statement "rm demo/scratch.txt"   # text: asks, critical
signetd ask --action fs.delete --statement "rm src/scratch.rs"     # other: goes through
signetd ask --action fs.delete --statement "rm -rf build"          # unknown: asks, critical
```

With nothing after `--target`, the target is unknown, which is production;
the hook names the working tree instead, `file:///path/to/checkout`, and a
`[[environment]]` entry can label that.

## Who asks in `fs`

Only the Claude Code hook today, for the shell commands it can tell are
deletes, and `signetd ask` by hand. The pack sees nothing else: a file
removed by an editor, by `Write`, or by a command the hook's detector does
not recognise never reaches it. The hook's own docs say why that set cannot
be closed from a verb list, and what closes it.

## The rules a host enforces

1. A pack may **raise** severity and never lower it.
2. A pack cannot write the environment label or the digest.
3. Failure is closed. A dead classifier means `critical`, not "probably fine".

The protocol is two methods and one response shape:
[`spec/pack-protocol-v1.md`](https://github.com/Cenova-Spark/Countersign/blob/main/spec/pack-protocol-v1.md).
