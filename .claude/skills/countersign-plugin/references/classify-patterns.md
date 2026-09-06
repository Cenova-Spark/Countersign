# Classify patterns

How the common shapes of a description become `classify`. Every pattern is a
pure function of the statement text: no I/O, no clock, no lookups.

## Contents

1. Verb-first statements
2. Resources and scopes
3. Amounts and thresholds
4. Hosts, environments and "production" in the text
5. Refining the requested action
6. Rendering
7. Mistakes that the host catches, and the ones it cannot

## 1. Verb-first statements

Most command-like statements say what they do in the first word: `deploy`,
`delete`, `kubectl`, `git`, `terraform`. Take the first word, lowercase it,
and match. For tools with subcommands, take the first two.

```rust
let words: Vec<String> = statement.split_whitespace().map(|w| w.to_ascii_lowercase()).collect();
let verb = words.first().map(String::as_str).unwrap_or("");
let sub = words.get(1).map(String::as_str).unwrap_or("");

let (action, severity, reversible) = match (verb, sub) {
    ("kubectl", "get") | ("kubectl", "describe") => ("read", Severity::None, Some(true)),
    ("kubectl", "apply") => ("apply", Severity::High, None),
    ("kubectl", "delete") => ("delete", Severity::Critical, Some(false)),
    ("kubectl", "scale") => ("scale", Severity::Moderate, Some(true)),
    _ => ("change", Severity::High, None),
};
```

The fallthrough is `high`, not `none`. A statement the pack does not
recognise is the one that most needs a person, and a pack may raise but never
lower, so guessing low buys nothing.

## 2. Resources and scopes

"Delete a pod" and "delete a namespace" are the same verb and very different
blast radii. Look for the resource word after the verb and let it raise:

```rust
let touches_namespace = words.iter().any(|w| w == "namespace" || w == "ns");
let wide = words.iter().any(|w| w == "--all" || w == "-A" || w == "--all-namespaces");
let severity = match (base, touches_namespace || wide) {
    (Severity::Critical, _) => Severity::Critical,
    (s, true) => Severity::Critical,
    (s, false) => s,
};
```

`--force`, `--yes`, `-f`, `--no-backup`, `--hard`, `--prune`: each one is a
person saying "do not ask me". That is the moment to ask. Treat them as
raising to at least `high`, and say so in an advisory line.

## 3. Amounts and thresholds

"Payments over $1000 need approval" is a threshold on a number in the text.
Parse the first number that follows a currency sign or a unit, and raise at
the threshold. Do not try to be clever about locales; parse digits, dots and
commas, and when parsing fails, treat the amount as over the threshold:

```rust
fn amount(statement: &str) -> Option<f64> {
    let start = statement.find(['$', '€', '£'])? + 1;
    let digits: String = statement[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ',')
        .filter(|c| *c != ',')
        .collect();
    digits.parse().ok()
}

let severity = match amount(statement) {
    Some(a) if a < 1000.0 => Severity::Moderate,
    Some(_) => Severity::High,
    None => Severity::High, // an amount that cannot be read is not a small one
};
```

Put the parsed amount in an advisory line so the person sees what the pack
read, and can catch a misread: `RenderLine::advisory("reads as $12,400")`.

## 4. Hosts, environments and "production" in the text

The daemon knows the environment from the *target*, not from the statement,
and it applies its own floor. So a pack must not lower because the text says
"staging". It may raise because the text says "prod": a statement that names
production is one where the requester's target and the requester's words
should agree, and a person is the one to notice when they do not.

```rust
let names_production = words.iter().any(|w| {
    let w = w.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    w == "prod" || w == "production" || w.ends_with("-prod") || w.starts_with("prod-")
});
if names_production {
    severity = severity.max(Severity::High);
    out.render.push(RenderLine::advisory("names production"));
}
```

`Severity` is ordered, so `max` is the right word: it can only go up.

## 5. Refining the requested action

`req.action` is what the requester asked for: `deploy.run`, `sql.execute`.
The pack answers with a refinement in the same namespace: `deploy.apply`,
`sql.dml`. The namespace must not change — the host treats an answer outside
it as a dead pack — because policy rules mention namespaces and a pack that
could relabel `sql.execute` as `noop.ping` could relabel its way out of every
rule.

```rust
let mut out = ClassifyResponse::new(format!("{NAMESPACE}.{action}"), severity);
```

When the requester already sent a specific verb (`deploy.rollback`) and the
statement agrees, keep it. When they disagree, the statement wins and the
disagreement is worth an advisory line: "asked as rollback, reads as apply".

## 6. Rendering

The screen is small and the person is, by premise, not paying full
attention. Render the statement first, whole, as `primary`. For a batch
(several statements in one), give the first four their own lines and collapse
the rest into a count — the SQL pack does this, because a `DROP` in position
five is where someone hiding one would put it, and "and 12 more" makes a
person look.

Advisory lines are for what is not verified: counts, amounts read from text,
"cannot be undone", "names production". Keep each under a screen's width.
Never emit a `label` or `digest` role; the host refuses the whole answer.

`reversible` is `Some(true)` only when undoing is routine (a scale-down, a
config change with history), `Some(false)` when it is not (a delete, a
payment, a publish), and `None` when the pack cannot know. `None` is honest,
and the daemon renders it as unknown rather than as safe.

## 7. Mistakes that the host catches, and the ones it cannot

Caught, and reported as a dead pack (`critical`, cause named):

- an action outside the namespace;
- a `label` or `digest` render line;
- a crash, a panic, a trap, running out of fuel or memory;
- a response that is not the protocol's shape.

Not caught, because the host cannot know your domain:

- a destructive verb mapped to `low`. Nothing stops it. The tests are the
  only guard, so write one per destructive verb that asserts `Critical` and
  `Some(false)`;
- a fallthrough to `none`. Same;
- keying on the environment word to lower severity. The daemon will not
  lower either — it takes the maximum — but the pack will have lied on
  screen about how bad it thinks the statement is.
