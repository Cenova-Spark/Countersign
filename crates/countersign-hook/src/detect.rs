//! Does this shell command delete a file?
//!
//! # This is a string matcher, and string matchers are incomplete
//!
//! Stated first because it is the most important thing about this file. There
//! are unboundedly many ways to unlink a file from a shell, and no list of
//! verbs closes them all — `perl -e 'unlink shift'` is a delete, and so is a
//! compiled binary with no recognisable name. The honest enforcement point for
//! a filesystem is the filesystem: a FUSE layer or a syscall filter that
//! returns `EPERM` for `unlink` without a countersignature, the way
//! `countersign-proxy` is the enforcement point for a database because the
//! database is on the far side of it.
//!
//! What this buys, and it is not nothing: the gate runs in the harness, before
//! the tool call, on every call the harness's matcher sends it. An agent cannot
//! decline to consult it the way it can decline to call an MCP tool. That
//! makes it stronger than advisory mode and weaker than the proxy, and the gap
//! is this file plus the matcher: a tool the matcher does not name is never
//! seen at all. `screen` names the ones that matter and says why.
//!
//! # Which way it errs
//!
//! Toward missing, and that is worth saying plainly rather than burying. A verb
//! this does not know about goes through untouched. Splitting is quote-aware —
//! `echo "rm -rf /"` is an echo, not a delete — because a gate that cried wolf
//! would train the reflex `signetd` spends a whole README section refusing to
//! train, and a prompt nobody reads is worse than no prompt.
//!
//! So the residual risk is a false negative, and the mitigation is not a longer
//! verb list. It is moving the gate below the shell. Below the shell closes the
//! shell's routes and no others: a tool that drives Finder trashes a file as
//! the person, in the person's own process, and no syscall filter can tell the
//! two apart. That route is closed in the harness or nowhere, and `screen` is
//! where.

/// Wrappers that are not themselves the command, so the real verb is the next
/// word along.
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "command", "builtin", "env", "time", "nohup", "nice", "ionice", "xargs", "exec",
];

/// Verbs whose whole purpose is to remove something.
const DELETE_VERBS: &[&str] = &[
    "rm",
    "rmdir",
    "unlink",
    "shred",
    "srm",
    "trash",
    "trash-put",
    "wipe",
];

/// Shells that take a script as an argument, which has to be looked at too.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish"];

/// Interpreters whose `-c`/`-e` argument is code, not a path.
const INTERPRETERS: &[&str] = &["python", "python3", "perl", "ruby", "node", "deno", "php"];

/// Delete primitives inside interpreter source. Coarse on purpose: this is a
/// tripwire for the obvious way around a verb list, not a parser.
const INTERPRETER_PRIMITIVES: &[&str] = &[
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "shutil.rmtree",
    "pathlib",
    ".unlink(",
    "fs.unlink",
    "fs.rm",
    "rmSync",
    "unlinkSync",
    "rimraf",
    "File.delete",
    "FileUtils.rm",
];

/// Why a command was held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deletion {
    /// The segment that matched, for the human to read.
    pub segment: String,
    /// What matched, in words an operator can act on.
    pub reason: String,
}

/// Every part of `command` that appears to delete something.
///
/// Empty means the command is not a delete as far as this can tell, and the
/// caller lets it through untouched — no prompt, no daemon round trip, no
/// audit entry. Creating a file has to be free, or the gate is not worth
/// running.
pub fn deletions(command: &str) -> Vec<Deletion> {
    let mut found = Vec::new();
    for segment in segments(command) {
        if let Some(reason) = deletes(&segment) {
            found.push(Deletion { segment, reason });
        }
    }
    found
}

/// Whether the command deletes anything at all.
pub fn is_delete(command: &str) -> bool {
    !deletions(command).is_empty()
}

/// Split a command line into the pieces a shell would run separately.
///
/// Quote-aware, because the alternative is worse in both directions at once:
/// `echo "rm -rf /"` would split into something that looks like a delete, and
/// `python3 -c "import os; os.remove(x)"` would split into two fragments that
/// each look like nothing. The first is a prompt nobody needed and the second
/// is a delete nobody saw.
///
/// Backslash escapes inside quotes are not tracked. A command that needs them
/// to be understood is one this file was never going to parse correctly.
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
                // `&&`, `||` and `|` all end a segment; so does a lone `&`.
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

/// Why this one segment is a delete, if it is.
fn deletes(segment: &str) -> Option<String> {
    let words: Vec<&str> = segment.split_whitespace().collect();
    let mut index = 0;

    // Step past `FOO=bar` assignments and wrappers to find the real verb.
    while index < words.len() {
        let word = words[index].trim_start_matches(['(', '{']);
        if word.contains('=') && !word.starts_with('-') {
            index += 1;
            continue;
        }
        if WRAPPERS.contains(&basename(word)) {
            index += 1;
            continue;
        }
        break;
    }

    let verb = basename(words.get(index)?);
    let rest = &words[(index + 1).min(words.len())..];

    if DELETE_VERBS.contains(&verb) {
        return Some(format!("`{verb}` removes files"));
    }

    if verb == "git" {
        // `git rm` unlinks the working copy; `git clean` unlinks everything
        // the index does not know about, which is usually more than the person
        // typing it expects.
        if let Some(sub) = rest.iter().find(|w| !w.starts_with('-')) {
            if *sub == "rm" {
                return Some("`git rm` removes files from the working tree".into());
            }
            if *sub == "clean" {
                return Some("`git clean` removes untracked files".into());
            }
        }
        return None;
    }

    if verb == "find" {
        if rest.contains(&"-delete") {
            return Some("`find -delete` removes every match".into());
        }
        if let Some(pos) = rest.iter().position(|w| *w == "-exec" || *w == "-execdir") {
            if rest[pos..]
                .iter()
                .any(|w| DELETE_VERBS.contains(&basename(w)))
            {
                return Some("`find -exec` runs a remove over every match".into());
            }
        }
        return None;
    }

    if verb == "gio" && rest.first().map(|w| *w == "trash").unwrap_or(false) {
        return Some("`gio trash` removes files".into());
    }

    // `sh -c "rm x"` hides the verb one level down. Look inside rather than
    // pretending the quotes make it a different kind of command.
    if SHELLS.contains(&verb) {
        if let Some(script) = flag_value(rest, "-c") {
            if is_delete(&script) {
                return Some(format!("`{verb} -c` runs a delete"));
            }
        }
        return None;
    }

    if INTERPRETERS.contains(&verb) {
        let source = flag_value(rest, "-c").or_else(|| flag_value(rest, "-e"));
        if let Some(source) = source {
            if let Some(hit) = INTERPRETER_PRIMITIVES.iter().find(|p| source.contains(**p)) {
                return Some(format!("`{verb}` source calls `{hit}`"));
            }
        }
        return None;
    }

    None
}

/// The value passed to a flag, with one layer of quoting removed.
fn flag_value(words: &[&str], flag: &str) -> Option<String> {
    let position = words.iter().position(|w| *w == flag)?;
    let value = words[position + 1..].join(" ");
    if value.is_empty() {
        return None;
    }
    Some(unquote(&value))
}

fn unquote(text: &str) -> String {
    let trimmed = text.trim();
    for quote in ['"', '\''] {
        if trimmed.len() >= 2 && trimmed.starts_with(quote) && trimmed.ends_with(quote) {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    }
    trimmed.to_string()
}

fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creating_a_file_is_not_a_delete() {
        // The load-bearing assertion for the demo, and for the protocol's own
        // rule that the dial has to stay rare. If making a file asked, nobody
        // would read the screen by the third one.
        for benign in [
            "touch demo/scratch.txt",
            "mkdir -p demo",
            "echo hello > demo/scratch.txt",
            "cat demo/scratch.txt",
            "ls -la demo",
            "cargo build --workspace",
            "git status",
            "git add demo/scratch.txt",
        ] {
            assert!(!is_delete(benign), "{benign:?} should pass untouched");
        }
    }

    #[test]
    fn the_plain_verbs_are_caught() {
        for command in [
            "rm demo/scratch.txt",
            "rm -rf demo",
            "/bin/rm demo/scratch.txt",
            "sudo rm -f demo/scratch.txt",
            "unlink demo/scratch.txt",
            "rmdir demo",
            "shred -u demo/scratch.txt",
            "TMPDIR=/tmp rm demo/scratch.txt",
        ] {
            assert!(is_delete(command), "{command:?} should be held");
        }
    }

    #[test]
    fn a_delete_hidden_later_in_a_chain_is_caught() {
        // The obvious shape: do something harmless, then delete.
        let held = deletions("touch demo/scratch.txt && ls demo && rm demo/scratch.txt");
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].segment, "rm demo/scratch.txt");
    }

    #[test]
    fn a_delete_behind_a_shell_c_is_caught() {
        assert!(is_delete(r#"sh -c "rm demo/scratch.txt""#));
        assert!(is_delete("bash -c 'rm -rf demo'"));
    }

    #[test]
    fn an_interpreter_calling_unlink_is_caught() {
        assert!(is_delete(
            r#"python3 -c "import os; os.remove('demo/scratch.txt')""#
        ));
        assert!(is_delete(r#"node -e "require('fs').unlinkSync('x')""#));
        // …and an interpreter doing something else is not.
        assert!(!is_delete(r#"python3 -c "print(1 + 1)""#));
    }

    #[test]
    fn git_subcommands_are_distinguished() {
        assert!(is_delete("git rm demo/scratch.txt"));
        assert!(is_delete("git clean -fd"));
        assert!(!is_delete("git commit -m 'rm'"));
        assert!(!is_delete("git log --oneline"));
    }

    #[test]
    fn find_only_counts_when_it_actually_removes() {
        assert!(is_delete("find . -name '*.tmp' -delete"));
        assert!(is_delete("find . -name '*.tmp' -exec rm {} ;"));
        assert!(!is_delete("find . -name '*.tmp'"));
        assert!(!is_delete("find . -name '*.tmp' -print"));
    }

    #[test]
    fn a_quoted_delete_that_is_only_ever_printed_is_not_a_delete() {
        // A gate that cried wolf here would train the reflex the whole
        // protocol exists to defeat.
        assert!(!is_delete(r#"echo "rm -rf /""#));
        assert!(!is_delete("git commit -m 'rm the old parser'"));
    }

    #[test]
    fn a_word_that_merely_contains_rm_is_not_a_delete() {
        // `rmdir` is; `format`, `chmod` and a file called `rm.txt` are not.
        assert!(!is_delete("chmod +x scripts/build.sh"));
        assert!(!is_delete("cat rm.txt"));
        assert!(!is_delete("cargo run -- --format rm"));
    }

    #[test]
    fn every_matching_segment_is_reported_not_just_the_first() {
        // The screen should show the whole of what was asked for. A gate that
        // presented the first delete and let the second through would be worse
        // than no gate, because the human would believe they had seen it.
        let held = deletions("rm a.txt; touch b.txt; rm c.txt");
        assert_eq!(held.len(), 2);
        assert_eq!(held[0].segment, "rm a.txt");
        assert_eq!(held[1].segment, "rm c.txt");
    }
}
