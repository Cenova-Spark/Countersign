//! `countersign-txt` — ask before a `.txt` file is deleted; let other files go.
//!
//! This pack claims the `fs` namespace, which is the one the Claude Code hook
//! (`countersign-hook`) asks in: every shell command that removes something
//! reaches the daemon as `fs.delete`, with the command, verbatim, as the
//! statement. The pack reads that command and answers one of three things:
//!
//! * `fs.delete.text` — a `.txt` file is named. `critical`, cannot be undone.
//! * `fs.delete.other` — every path named is a file, and none is `.txt`.
//!   `high`, cannot be undone.
//! * `fs.delete.unknown` — the command removes something the pack cannot
//!   name: a directory and what is inside it, a pattern, a variable, `find
//!   -delete`, `git clean`, a script. Any of those may hold a `.txt` file.
//!   `critical`, and whether it can be undone is unknown.
//!
//! It decides nothing. "All other files are fine" is a policy rule, and it
//! belongs in the daemon's `config.toml` — README.md has the two rules. The
//! pack only draws the distinction policy can key on, and it draws it in the
//! one direction a pack may: when it cannot see what is being removed, it
//! says so, and says `critical`.
//!
//! It also looks at nothing. No filesystem, so it cannot know whether
//! `build/` holds a `.txt` file — which is exactly why a tree is `unknown`
//! rather than "probably fine". A pack that checked would be a pack that
//! reads production paths, and a classifier that reads is one the marketplace
//! cannot list.

// The WebAssembly export glue at the bottom needs four lines of `unsafe` to
// hand buffers across the module boundary. It is allowed there and nowhere
// else in this crate.
#![deny(unsafe_code)]

use countersign_pack::{
    serde_json::json, ClassifyRequest, ClassifyResponse, Pack, PackInfo, RenderLine, Severity,
    PROTOCOL,
};

/// The namespace this pack claims: `fs.delete` and everything else under
/// `fs.`. A host never sends it anything else, and an answer outside it is
/// treated as a dead pack.
pub const NAMESPACE: &str = "fs";

/// The extension this pack guards. Compared without regard to case, so
/// `NOTES.TXT` counts; `.txt.bak` does not, because it is not a `.txt` file.
pub const GUARDED: &str = ".txt";

/// How many names get their own place on an advisory line before the rest
/// collapse into a count.
const MAX_NAMES: usize = 3;

/// Wrappers that are not themselves the command, so the verb is the next word.
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "command", "builtin", "env", "time", "nohup", "nice", "ionice", "xargs", "exec",
];

/// Verbs whose operands are paths to remove.
///
/// `delete`, `remove` and `del` are not shell commands; they are how a person
/// types the statement into `signetd ask`. The hook sends real commands.
const DELETE_VERBS: &[&str] = &[
    "rm",
    "unlink",
    "rmdir",
    "shred",
    "srm",
    "wipe",
    "trash",
    "trash-put",
    "delete",
    "remove",
    "del",
];

/// Verbs that fail on a directory unless told to recurse, so an operand
/// without `-r` can only be a file. (`rmdir` is the reverse: only an empty
/// directory, which holds no `.txt` file either.)
const FILE_ONLY_VERBS: &[&str] = &["rm", "unlink", "rmdir", "shred", "srm", "wipe", "git rm"];

/// Verbs that unlink outright. Everything else — a trash, a hand-typed
/// `delete` — may or may not be recoverable, and the pack does not guess.
const UNLINK_VERBS: &[&str] = &["rm", "unlink", "rmdir", "shred", "srm", "wipe", "git rm"];

/// Shells and interpreters whose `-c`/`-e` argument is code. What the code
/// removes is not visible from here.
const SCRIPT_RUNNERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "perl", "ruby", "node",
    "deno", "php",
];

/// What the pack made of a statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A `.txt` file is named.
    Text,
    /// Files are named; none is `.txt`.
    Other,
    /// Something is removed that the pack cannot name.
    Unknown,
}

impl Kind {
    /// The refinement under `fs.delete.`.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Text => "text",
            Kind::Other => "other",
            Kind::Unknown => "unknown",
        }
    }
}

/// The reading of one statement, before it becomes a response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reading {
    /// `.txt` files named, as written.
    pub text: Vec<String>,
    /// Files named that are not `.txt`.
    pub files: Vec<String>,
    /// Why the pack could not see what is removed, one line per cause.
    pub unseen: Vec<String>,
    /// A `-f`/`--force` was passed: the shell's own confirmation is skipped.
    pub forced: bool,
    /// Every removal the pack recognised unlinks outright, so undoing is not
    /// on the table. False when any of them is a trash or a hand-typed verb.
    pub unlinks: bool,
}

impl Reading {
    /// Which of the three answers this is.
    ///
    /// A `.txt` name anywhere wins: `rm -rf build notes.txt` is a `.txt`
    /// delete whatever else it is. Then anything unseen: a tree beside a
    /// named file is still a tree. Only when every name was read and none is
    /// `.txt` is it `other`.
    pub fn kind(&self) -> Kind {
        if !self.text.is_empty() {
            Kind::Text
        } else if !self.unseen.is_empty() || self.files.is_empty() {
            Kind::Unknown
        } else {
            Kind::Other
        }
    }
}

/// Read a statement: which `.txt` files it names, which other files, and
/// what it removes that cannot be named from the text.
///
/// A pure function of the text. It splits the way a shell would — on `;`,
/// `&&`, `||`, `|` and newlines, outside quotes — finds the verb of each
/// piece past any `sudo`/`env`/assignment, and reads the operands of the
/// pieces that remove things. A piece that does not remove anything (`cd`,
/// `ls`, a redirect into `log.txt`) is ignored: writing a `.txt` file is not
/// deleting one.
pub fn read(statement: &str) -> Reading {
    let mut reading = Reading {
        unlinks: true,
        ..Default::default()
    };
    let mut recognised = false;

    for segment in segments(statement) {
        let tokens = words(&segment);
        let Some((verb, rest)) = verb_of(&tokens) else {
            continue;
        };

        if DELETE_VERBS.contains(&verb) {
            recognised = true;
            reading.unlinks &= UNLINK_VERBS.contains(&verb);
            reading.operands(verb, rest);
        } else if verb == "git" {
            let sub = rest.iter().position(|w| !w.starts_with('-'));
            match sub.map(|i| (rest[i].as_str(), &rest[i + 1..])) {
                Some(("rm", paths)) => {
                    recognised = true;
                    reading.operands("git rm", paths);
                }
                Some(("clean", _)) => {
                    recognised = true;
                    reading
                        .unseen
                        .push("git clean removes whatever git does not track".into());
                }
                _ => {}
            }
        } else if verb == "find" && find_removes(rest) {
            recognised = true;
            reading.text_among(rest);
            reading
                .unseen
                .push("find removes every match; the matches are not visible here".into());
        } else if verb == "gio" && rest.first().map(String::as_str) == Some("trash") {
            recognised = true;
            reading.unlinks = false;
            reading.operands("trash", &rest[1..]);
        } else if SCRIPT_RUNNERS.contains(&verb) {
            if let Some(code) = flag_value(rest, "-c").or_else(|| flag_value(rest, "-e")) {
                recognised = true;
                reading.text_among(&words(&code));
                reading.unseen.push(format!(
                    "{verb} runs code; what it removes is not visible here"
                ));
            }
        }
    }

    if !recognised {
        // Nothing here read as a removal, yet the requester asked in `fs`.
        // A `.txt` name anywhere is enough to say so; failing that, the pack
        // cannot say what goes, and says that.
        reading.text_among(&words(statement));
        if reading.text.is_empty() {
            reading
                .unseen
                .push("not a removal this pack can read; what goes is not visible here".into());
        }
        reading.unlinks = false;
    }

    reading
}

impl Reading {
    /// Read the operands of one removing verb.
    fn operands(&mut self, verb: &str, rest: &[String]) {
        let mut recursive = false;
        let mut past_flags = false;
        let mut named = 0usize;
        let mut skip_next = false;

        for word in rest {
            if skip_next {
                skip_next = false;
                continue;
            }
            if !past_flags && word == "--" {
                past_flags = true;
                continue;
            }
            if !past_flags && word.starts_with('-') && word.len() > 1 {
                let short = !word.starts_with("--");
                let letters = &word[1..];
                if word == "--recursive" || (short && letters.contains(['r', 'R'])) {
                    recursive = true;
                }
                if word == "--force" || (short && letters.contains('f')) {
                    self.forced = true;
                }
                continue;
            }
            // `2>/dev/null`, `> log`: a redirect, and what follows a bare
            // `>` is its target, not a path being removed.
            if word.contains(['>', '<']) {
                skip_next = word.ends_with(['>', '<']);
                continue;
            }

            named += 1;
            // A .txt name first, even inside a pattern: `*.txt` says what it
            // is after, and a pack may raise.
            if names_text(word) {
                self.text.push(word.clone());
            } else if unreadable(word) {
                self.unseen.push(format!(
                    "{word}: a pattern or an expansion; what it matches is not visible here"
                ));
            } else if recursive {
                self.unseen
                    .push(format!("{word}: removed with everything inside it"));
            } else if FILE_ONLY_VERBS.contains(&verb) || has_extension(word) {
                self.files.push(word.clone());
            } else {
                self.unseen.push(format!("{word}: may be a directory"));
            }
        }

        if named == 0 {
            self.unseen.push(format!(
                "{verb} with nothing named; the paths come from somewhere else"
            ));
        }
    }

    /// Note every `.txt` name among some words, wherever they sit.
    fn text_among(&mut self, words: &[String]) {
        for word in words {
            if names_text(word) {
                self.text.push(word.clone());
            }
        }
    }
}

/// Does this word name a `.txt` file?
///
/// Trailing punctuation a shell or a script would not pass to the filesystem
/// is trimmed first, so `os.remove('a.txt')` and `a.txt,` both count. A
/// trailing `/` is trimmed too: something called `notes.txt/` is the pack's
/// business, not an exception to it.
fn names_text(word: &str) -> bool {
    let trimmed = word
        .trim_end_matches(['\'', '"', ')', ']', ',', ';', ':', '/', '`'])
        .trim_start_matches(['\'', '"', '(', '[', '`']);
    trimmed.to_ascii_lowercase().ends_with(GUARDED)
}

/// A pattern or an expansion: the shell decides what it names, and the
/// shell is not here.
fn unreadable(word: &str) -> bool {
    word.contains(['*', '?', '[', ']', '{', '}', '$', '`'])
}

/// Whether the last path component has an extension, which is the one weak
/// signal that a name given to `trash` is a file and not a directory.
fn has_extension(word: &str) -> bool {
    let last = word.trim_end_matches('/').rsplit('/').next().unwrap_or(word);
    match last.rfind('.') {
        Some(0) | None => false,
        Some(dot) => dot + 1 < last.len(),
    }
}

/// `find … -delete`, or `find … -exec rm …`.
fn find_removes(rest: &[String]) -> bool {
    if rest.iter().any(|w| w == "-delete") {
        return true;
    }
    rest.iter()
        .position(|w| w == "-exec" || w == "-execdir")
        .map(|pos| {
            rest[pos..]
                .iter()
                .any(|w| DELETE_VERBS.contains(&basename(w)))
        })
        .unwrap_or(false)
}

/// The verb of one segment and the words after it, past `FOO=bar`
/// assignments and wrappers like `sudo`.
fn verb_of(words: &[String]) -> Option<(&str, &[String])> {
    let mut index = 0;
    while index < words.len() {
        let word = words[index].trim_start_matches(['(', '{']);
        if word.contains('=') && !word.starts_with('-') {
            index += 1;
            continue;
        }
        if WRAPPERS.contains(&basename(word)) {
            index += 1;
            // `xargs -0 rm`, `sudo -E rm`: a wrapper's own flags.
            while index < words.len() && words[index].starts_with('-') {
                index += 1;
            }
            continue;
        }
        break;
    }
    let verb = basename(words.get(index)?.trim_start_matches(['(', '{']));
    Some((verb, &words[index + 1..]))
}

/// The value after a flag, joined back into one string.
fn flag_value(words: &[String], flag: &str) -> Option<String> {
    let position = words.iter().position(|w| w == flag)?;
    let value = words[position + 1..].join(" ");
    (!value.is_empty()).then_some(value)
}

fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// Split a command line into the pieces a shell would run separately.
///
/// Quote-aware, because `echo "rm -rf /"` is an echo and `sh -c "rm a; rm b"`
/// is one piece. Backslash escapes inside quotes are not tracked; a command
/// that needs them to be understood is one this was never going to read, and
/// an unread command is `unknown`, which asks.
fn segments(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = command.chars().peekable();

    while let Some(c) = chars.next() {
        if let Some(open) = quote {
            current.push(c);
            if c == open {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' => {
                quote = Some(c);
                current.push(c);
            }
            ';' | '\n' | '|' | '&' => {
                if (c == '|' || c == '&') && chars.peek() == Some(&c) {
                    chars.next();
                }
                out.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    out.push(current);

    out.into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Split one segment into words the way a shell would, with quotes removed
/// and a backslash escaping the next character, so `rm "my notes.txt"` names
/// one file.
fn words(segment: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = segment.chars();

    while let Some(c) = chars.next() {
        match quote {
            Some(open) if c == open => quote = None,
            Some(_) => current.push(c),
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    in_word = true;
                }
                '\\' => {
                    if let Some(next) = chars.next() {
                        current.push(next);
                        in_word = true;
                    }
                }
                c if c.is_whitespace() => {
                    if in_word {
                        out.push(std::mem::take(&mut current));
                        in_word = false;
                    }
                }
                c => {
                    current.push(c);
                    in_word = true;
                }
            },
        }
    }
    if in_word {
        out.push(current);
    }
    out
}

/// The pack. Stateless on purpose: a classifier that remembers is one whose
/// answer depends on what it saw before, which nobody can audit.
#[derive(Debug, Clone, Copy, Default)]
pub struct TxtPack;

impl Pack for TxtPack {
    fn describe(&self) -> PackInfo {
        PackInfo {
            name: env!("CARGO_PKG_NAME").into(),
            version: env!("CARGO_PKG_VERSION").into(),
            protocol: PROTOCOL,
            actions: vec![NAMESPACE.into()],
            // The promise that `classify` does no I/O. The module build makes
            // it true by construction; the native build is trusted to keep it.
            pure: true,
        }
    }

    fn classify(&self, req: &ClassifyRequest) -> ClassifyResponse {
        let statement = req.statement.trim();
        let reading = read(statement);
        let kind = reading.kind();

        let (severity, reversible) = match kind {
            Kind::Text => (Severity::Critical, reading.unlinks.then_some(false)),
            Kind::Other => (Severity::High, reading.unlinks.then_some(false)),
            Kind::Unknown => (Severity::Critical, None),
        };

        let mut out =
            ClassifyResponse::new(format!("{NAMESPACE}.delete.{}", kind.as_str()), severity);
        out.reversible = reversible;

        // The statement first, whole and verbatim. The hook binds the
        // signature to the exact command, so the exact command is what the
        // person must read.
        out.render.push(RenderLine::primary(statement));
        match kind {
            Kind::Text => out.render.push(RenderLine::advisory(format!(
                "deletes {GUARDED}: {}",
                listed(&reading.text)
            ))),
            Kind::Other => out.render.push(RenderLine::advisory(format!(
                "names {} file{}, none {GUARDED}",
                reading.files.len(),
                if reading.files.len() == 1 { "" } else { "s" }
            ))),
            Kind::Unknown => {
                for why in reading.unseen.iter().take(MAX_NAMES) {
                    out.render.push(RenderLine::advisory(why.clone()));
                }
                out.render
                    .push(RenderLine::advisory(format!("may include a {GUARDED} file")));
            }
        }
        if reading.forced {
            out.render
                .push(RenderLine::advisory("-f: the shell's own confirmation is skipped"));
        }
        if reversible == Some(false) {
            out.render.push(RenderLine::advisory("cannot be undone"));
        }
        // The requester's verb and the statement should agree. When the
        // requester asked for something other than a delete, the statement
        // wins — this pack reads removals — and the disagreement is shown.
        if req.action != format!("{NAMESPACE}.delete")
            && !req.action.starts_with(&format!("{NAMESPACE}.delete."))
        {
            out.render.push(RenderLine::advisory(format!(
                "asked as {}; read as a delete",
                req.action
            )));
        }

        out.advisory = Some(json!({
            "kind": kind.as_str(),
            "text": reading.text,
            "files": reading.files,
            "unseen": reading.unseen,
            "forced": reading.forced,
        }));
        out
    }
}

/// Up to `MAX_NAMES` names, then a count.
fn listed(names: &[String]) -> String {
    let shown = names
        .iter()
        .take(MAX_NAMES)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > MAX_NAMES {
        format!("{shown} (+{} more)", names.len() - MAX_NAMES)
    } else {
        shown
    }
}

// The WebAssembly build. The module imports nothing, so wherever it runs it
// cannot reach a network, a filesystem or a clock. `countersign_pack::wasm`
// describes the four exports this emits.
#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)]
mod wasm_exports {
    countersign_pack::export_pack!(super::TxtPack);
}

#[cfg(test)]
mod tests {
    use super::*;
    use countersign_pack::validate;

    /// The request as the Claude Code hook sends it.
    fn classify(statement: &str) -> ClassifyResponse {
        classify_as(&format!("{NAMESPACE}.delete"), statement)
    }

    fn classify_as(action: &str, statement: &str) -> ClassifyResponse {
        let req = ClassifyRequest::new(action, statement);
        let out = TxtPack.classify(&req);
        // The host's own check: inside the namespace, and no line a pack may
        // not write. A pack that fails this is treated as dead.
        validate(out, &req).expect("the answer must pass the host's rules")
    }

    fn advisories(out: &ClassifyResponse) -> Vec<&str> {
        out.render
            .iter()
            .filter(|l| l.role == countersign_pack::RenderRole::Advisory)
            .map(|l| l.text.as_str())
            .collect()
    }

    fn kind(statement: &str) -> Kind {
        read(statement).kind()
    }

    #[test]
    fn it_claims_exactly_its_namespace() {
        let info = TxtPack.describe();
        assert_eq!(info.actions, vec![NAMESPACE.to_string()]);
        assert_eq!(info.protocol, PROTOCOL);
        assert!(info.pure);
    }

    #[test]
    fn deleting_a_txt_file_is_critical_and_named_on_screen() {
        let out = classify("rm demo/scratch.txt");
        assert_eq!(out.action, "fs.delete.text");
        assert_eq!(out.severity, Severity::Critical);
        assert_eq!(out.reversible, Some(false));
        let lines = advisories(&out);
        assert!(
            lines.iter().any(|l| l.contains("demo/scratch.txt")),
            "the file is named: {lines:?}"
        );
        assert!(lines.contains(&"cannot be undone"));
    }

    #[test]
    fn other_files_are_named_and_high() {
        let out = classify("rm src/main.rs Cargo.lock");
        assert_eq!(out.action, "fs.delete.other");
        assert_eq!(out.severity, Severity::High);
        assert_eq!(out.reversible, Some(false));
        assert!(advisories(&out).contains(&"names 2 files, none .txt"));
        assert_eq!(read("rm src/main.rs Cargo.lock").files, ["src/main.rs", "Cargo.lock"]);
    }

    #[test]
    fn a_txt_anywhere_among_the_removed_wins() {
        // Wherever it sits — second operand, second command, behind sudo,
        // beside a tree — a .txt file named is a .txt file deleted.
        for command in [
            "rm a.rs b.txt",
            "rm a.rs && rm b.txt",
            "rm -rf build notes.txt",
            "sudo rm -f notes.txt",
            "cd demo && rm scratch.txt",
            "/bin/rm -- notes.txt",
            "TMPDIR=/tmp rm notes.txt",
            "rm notes.txt 2>/dev/null",
        ] {
            assert_eq!(kind(command), Kind::Text, "{command:?}");
        }
    }

    #[test]
    fn only_a_txt_extension_counts() {
        assert_eq!(kind("rm README.TXT"), Kind::Text, "case does not matter");
        assert_eq!(kind("rm notes.txt.bak"), Kind::Other, "a .bak is not a .txt");
        assert_eq!(kind("rm notes.txt2"), Kind::Other);
        assert_eq!(kind("rm txt"), Kind::Other);
        assert_eq!(kind("rm .txt"), Kind::Text, "a file called .txt is one");
    }

    #[test]
    fn quoted_paths_with_spaces_are_one_name() {
        assert_eq!(kind(r#"rm "my notes.txt""#), Kind::Text);
        assert_eq!(kind("rm 'my notes.rs'"), Kind::Other);
        assert_eq!(read("rm 'my notes.rs'").files, ["my notes.rs"]);
        assert_eq!(kind(r"rm my\ notes.txt"), Kind::Text);
    }

    #[test]
    fn a_tree_is_not_assumed_free_of_txt_files() {
        // The pack cannot look inside a directory, so it does not pretend to.
        for command in ["rm -rf build", "rm -r src", "rm -Rf x", "rm --recursive dist"] {
            let out = classify(command);
            assert_eq!(out.action, "fs.delete.unknown", "{command:?}");
            assert_eq!(out.severity, Severity::Critical);
            assert_eq!(out.reversible, None);
            let lines = advisories(&out);
            assert!(
                lines.iter().any(|l| l.contains("everything inside it")),
                "{command:?}: {lines:?}"
            );
            assert!(lines.contains(&"may include a .txt file"));
        }
    }

    #[test]
    fn patterns_scripts_and_the_unnamed_are_unseen() {
        for command in [
            "rm *.log",
            "rm $FILE",
            "rm {a,b}.rs",
            "find . -name '*.log' -delete",
            "find . -name '*.log' -exec rm {} ;",
            "git clean -fdx",
            "sh -c 'rm x.rs'",
            r#"python3 -c "import os; os.remove('a.rs')""#,
            "xargs rm",
            "rm",
            "rm --",
            "trash somedir",
        ] {
            let out = classify(command);
            assert_eq!(out.action, "fs.delete.unknown", "{command:?}");
            assert_eq!(out.severity, Severity::Critical, "{command:?}");
            assert_eq!(out.reversible, None, "{command:?}");
        }
    }

    #[test]
    fn a_pattern_or_script_that_names_txt_is_text() {
        // Over-inclusive on purpose: a pack may raise, and `*.txt` says what
        // it is after.
        for command in [
            "rm *.txt",
            "find . -name '*.txt' -delete",
            r#"sh -c "rm a.txt""#,
            r#"python3 -c "os.remove('a.txt')""#,
            "rm -rf notes.txt",
        ] {
            assert_eq!(kind(command), Kind::Text, "{command:?}");
        }
    }

    #[test]
    fn git_rm_names_files_like_rm_does() {
        assert_eq!(kind("git rm a.rs"), Kind::Other);
        assert_eq!(kind("git rm --cached a.txt"), Kind::Text);
        assert_eq!(kind("git rm -r dir"), Kind::Unknown);
        assert_eq!(kind("git commit -m 'rm notes.txt'"), Kind::Text, "not a removal the pack reads; a .txt name is enough to ask");
    }

    #[test]
    fn a_trash_is_not_claimed_undoable_either_way() {
        // Recovery from a trash depends on settings the pack cannot see, so
        // it says unknown rather than guessing. Guessing `true` is the one
        // error that turns friction into a false sense of safety.
        let out = classify("trash notes.txt");
        assert_eq!(out.action, "fs.delete.text");
        assert_eq!(out.reversible, None);
        assert!(!advisories(&out).contains(&"cannot be undone"));
        assert_eq!(classify("trash notes.rs").reversible, None);
        assert_eq!(kind("gio trash notes.rs"), Kind::Other);
    }

    #[test]
    fn the_unrecognised_is_not_assumed_harmless() {
        let out = classify("frobnicate the widgets");
        assert_eq!(out.action, "fs.delete.unknown");
        assert!(out.severity >= Severity::High);
        assert_eq!(out.reversible, None);
        // A hand-typed statement that names a .txt file is read as one.
        assert_eq!(kind("please delete notes.txt"), Kind::Text);
        assert_eq!(kind("delete notes.txt"), Kind::Text);
        assert_eq!(kind("delete notes.rs"), Kind::Other);
    }

    #[test]
    fn writing_a_txt_file_is_not_deleting_one() {
        // The only pieces read are the ones that remove something. A redirect
        // into log.txt beside `rm a.rs` is still an `other`.
        assert_eq!(kind("rm a.rs; echo done > log.txt"), Kind::Other);
        assert_eq!(kind("rm a.rs 2>/dev/null"), Kind::Other);
        assert_eq!(read("rm a.rs 2>/dev/null").files, ["a.rs"]);
        assert_eq!(kind("cat notes.txt && rm a.rs"), Kind::Other);
    }

    #[test]
    fn forcing_is_said_on_screen() {
        let out = classify("rm -f a.rs");
        assert_eq!(out.action, "fs.delete.other");
        assert!(advisories(&out).iter().any(|l| l.starts_with("-f:")));
        assert!(!advisories(&classify("rm a.rs")).iter().any(|l| l.starts_with("-f:")));
    }

    #[test]
    fn the_statement_is_what_the_person_reads() {
        let out = classify("  rm a.rs ");
        assert_eq!(out.render[0].text, "rm a.rs");
        assert_eq!(out.render[0].role, countersign_pack::RenderRole::Primary);
    }

    #[test]
    fn the_action_stays_inside_the_namespace() {
        // `validate` in the helper already refuses an escape; this checks the
        // refinement keeps `fs.delete` as its prefix, so a policy rule about
        // `fs.delete` still covers every answer.
        for command in ["rm a.txt", "rm a.rs", "rm -rf a"] {
            assert!(classify(command).action.starts_with("fs.delete."), "{command:?}");
        }
        // Asked with a different verb, the statement wins and the screen
        // says so.
        let out = classify_as("fs.remove", "rm a.txt");
        assert_eq!(out.action, "fs.delete.text");
        assert!(advisories(&out).contains(&"asked as fs.remove; read as a delete"));
        assert!(!advisories(&classify("rm a.txt")).iter().any(|l| l.starts_with("asked as")));
    }

    #[test]
    fn many_names_collapse_into_a_count() {
        let out = classify("rm a.txt b.txt c.txt d.txt e.txt");
        let lines = advisories(&out);
        assert!(
            lines.iter().any(|l| l.ends_with("(+2 more)")),
            "{lines:?}"
        );
    }
}
