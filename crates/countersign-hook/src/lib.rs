//! A Claude Code `PreToolUse` gate: no file is deleted without a
//! countersignature.
//!
//! This is the filesystem cousin of `countersign-proxy`, and it exists for the
//! same reason: **the agent is not asked to cooperate.** It does not call a
//! tool, does not decide whether to honour the answer, and does not need to
//! know Countersign exists. The harness runs this before the tool call and
//! obeys what it returns.
//!
//! It is not quite posture C, and the crate should not pretend otherwise. The
//! proxy sits between the client and the database, so there is no path around
//! it. This sits between the agent and *one* way of deleting a file — the shell
//! command the harness was asked to run — and `detect` explains at length why
//! no list of verbs closes that set. The real filesystem equivalent of the
//! proxy is a FUSE layer or a syscall filter returning `EPERM`.
//!
//! Even that would leave one route open. A tool that drives the person's own
//! screen can trash a file through Finder, or press whatever a pack gates,
//! and at the syscall that is the person. `screen` reads those tools: a
//! screenshot passes, and a click is refused outright, because there is
//! nothing in it a person could countersign.
//!
//! # What it does
//!
//! 1. Read the `PreToolUse` payload on stdin.
//! 2. If the tool is on the screen-driving server, let it look and refuse it
//!    touching; `screen` says which is which.
//! 3. Decide whether the tool call deletes a file. **If not, say nothing.**
//!    Creating a file must cost zero prompts, or the dial stops being rare.
//! 4. If it does, ask `signetd` for `fs.delete` on this working tree and block.
//! 5. **Verify the returned signature** against the exact command about to run.
//! 6. Allow only on a verified approval. Everything else is a denial.
//!
//! Step 5 is not redundant with the daemon having said "approved", for the same
//! reason it is not redundant in the proxy: the same code path would refuse a
//! forged approval from the daemon it is talking to.
//!
//! # Failure is closed
//!
//! No daemon, a malformed payload, an unverifiable signature, a store that
//! cannot be written, a deadline reached — all of them deny. A gate that let
//! deletions through whenever its daemon was down would be defeated by
//! stopping the daemon, and stopping a daemon is not a sophisticated attack.

pub mod detect;
pub mod screen;

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use countersign_verify::{
    fingerprint_uri, verify_for_execution, Decision, EnrolledDevice, Execution, FileStore,
    Registry, RustCryptoBackend, VerifyPolicy,
};
use serde::Deserialize;
use serde_json::{json, Value};
use signetd::daemon::ApprovalRequest;
use signetd::roster::LocalRoster;
use signetd::service::Client;

/// The action this gate asks about. Namespaced, like every other verb in the
/// protocol, and it has to be named in a policy rule's `actions` before the
/// daemon will present it at all.
///
/// What comes back may be more specific. A pack claiming `fs` refines the verb
/// inside its namespace — `fs.delete.text` for a `.txt` file, say — so policy
/// can tell one delete from another, and the refinement is what the device
/// signs. The gate accepts a refinement of this verb and nothing else; see
/// [`refines`].
pub const ACTION: &str = "fs.delete";

/// Whether `action` is `base` itself or a refinement of it: `fs.delete.text`
/// refines `fs.delete`; `fs.deleted` and `sql.dml` do not.
///
/// Pack protocol §4.1 lets a pack refine a verb but never move it out of the
/// namespace that was asked, which is what makes accepting a refinement safe:
/// everything under `fs.delete.` is still the delete this gate asked about.
pub fn refines(action: &str, base: &str) -> bool {
    action == base
        || action
            .strip_prefix(base)
            .is_some_and(|rest| rest.len() > 1 && rest.starts_with('.'))
}

/// How the gate is set up.
#[derive(Debug, Clone)]
pub struct Config {
    /// Path to the `signetd` control socket.
    pub socket: PathBuf,
    /// Whether to accept signatures from the published test key.
    ///
    /// False in anything real. True is how this demo works at all, which is
    /// why the flag is named after the thing it lets in.
    pub accept_test_keys: bool,
    /// Where device counters are remembered between invocations.
    ///
    /// A hook is a fresh process per tool call, so without a durable store
    /// there is no replay defence here at all — every invocation would start
    /// having seen no counters.
    pub state_dir: PathBuf,
    /// Where `signetd enroll` wrote `roster.json`: the daemon's config
    /// directory. The keys this gate believes come from there — the app's
    /// enclave key, a phone's — and from nowhere else unless
    /// `accept_test_keys` is set.
    pub roster_dir: PathBuf,
    /// How long to wait before denying on our own initiative.
    ///
    /// Deliberately shorter than the harness's hook timeout. If the harness
    /// gives up first the hook returns nothing, and nothing means "no opinion"
    /// — which in a permissive session lets the delete through. Denying
    /// ourselves a little early is what keeps a slow approval from becoming a
    /// fail-open.
    pub deadline: Duration,
}

/// What Claude Code sends on stdin before a tool runs.
///
/// Only the fields this needs. Everything else in the payload is ignored
/// rather than rejected, so a harness that adds a field does not break the
/// gate open.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HookInput {
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: Value,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub session_id: String,
}

impl HookInput {
    /// The shell command this tool call would run, if it is one.
    pub fn command(&self) -> Option<&str> {
        if self.tool_name != "Bash" {
            return None;
        }
        self.tool_input.get("command")?.as_str()
    }
}

/// What the gate decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Not a delete. Say nothing and let the normal flow continue.
    ///
    /// Distinct from `Allow`: this gate has no opinion about creating a file,
    /// and a hook that answered "allow" to everything would be quietly
    /// overriding the user's own permission settings for tool calls it was
    /// never meant to have a view on.
    Pass,
    /// A human countersigned this exact command, and the signature verified.
    Allow { reason: String },
    /// Anything else.
    Deny { reason: String },
}

impl Verdict {
    /// The JSON the harness reads, or `None` when there is nothing to say.
    pub fn to_hook_output(&self) -> Option<Value> {
        let (decision, reason) = match self {
            Verdict::Pass => return None,
            Verdict::Allow { reason } => ("allow", reason),
            Verdict::Deny { reason } => ("deny", reason),
        };
        Some(json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        }))
    }
}

/// Run the gate over one tool call.
pub fn gate(input: &HookInput, config: &Config) -> Verdict {
    // A tool on the screen-driving server is read before anything else, and
    // never reaches the daemon: a screenshot needs no approval, and there is
    // nothing in a click a person could countersign. See `screen`.
    match screen::read(&input.tool_name, &input.tool_input) {
        screen::Reading::NotThisServer => {}
        screen::Reading::Looks => return Verdict::Pass,
        screen::Reading::Drives(reason) => return Verdict::Deny { reason },
    }

    let Some(command) = input.command() else {
        return Verdict::Pass;
    };

    let held = detect::deletions(command);
    if held.is_empty() {
        return Verdict::Pass;
    }

    // The working tree is the environment. Which directory this is happening
    // in is the granularity an operator actually labels — "my scratch repo"
    // and "the deploy checkout" are different places and deserve different
    // screens — while *which files* is the statement's business.
    let cwd = if input.cwd.is_empty() {
        std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    } else {
        input.cwd.clone()
    };
    let target_uri = format!("file://{cwd}");
    let fingerprint = fingerprint_uri(&target_uri);

    // The statement is the command **verbatim**, because the command is what
    // will run. Any summarising here would be blind signing with extra steps:
    // the human would approve a description while something else executed.
    let request = ApprovalRequest {
        action: ACTION.into(),
        target_uri: None,
        uri_fingerprint: Some(fingerprint.clone()),
        target_kind: "filesystem".into(),
        statement: command.to_string(),
        advisory: Some(json!({
            "working_tree": cwd,
            "matched": held.iter().map(|d| json!({
                "segment": d.segment,
                "why": d.reason,
            })).collect::<Vec<_>>(),
        })),
        requester_id: "claude-code-hook".into(),
        requester_instance: input.session_id.clone(),
        ttl_ms: None,
    };

    match ask_with_deadline(request, config) {
        Ok(verdict) => verdict,
        Err(reason) => Verdict::Deny { reason },
    }
}

/// Ask the daemon, but never outlive our own deadline.
///
/// The approval runs on a thread so that a human who walks away cannot turn
/// this into a fail-open. If the deadline lands first the gate denies and the
/// thread is abandoned; the process is about to exit anyway.
fn ask_with_deadline(request: ApprovalRequest, config: &Config) -> Result<Verdict, String> {
    let (tx, rx) = mpsc::channel();
    let deadline = config.deadline;
    let owned = config.clone();
    std::thread::spawn(move || {
        let _ = tx.send(ask(request, &owned));
    });

    match rx.recv_timeout(deadline) {
        Ok(result) => result,
        Err(_) => Err(format!(
            "no countersignature within {}s, so this was not approved. The request may still \
             be on the daemon's terminal; dismiss it there.",
            deadline.as_secs()
        )),
    }
}

fn ask(request: ApprovalRequest, config: &Config) -> Result<Verdict, String> {
    let statement = request.statement.clone();
    let fingerprint = request
        .uri_fingerprint
        .clone()
        .ok_or("internal: no target fingerprint")?;

    let mut client = Client::connect(&config.socket).map_err(|e| {
        format!("cannot reach signetd, so nothing can be approved and nothing is deleted: {e}")
    })?;

    let response = client
        .request_approval(&request)
        .map_err(|e| format!("approval could not be obtained: {e}"))?;

    if response.decision != Decision::Approved {
        return Ok(Verdict::Deny {
            reason: format!(
                "countersign: {} — {}",
                response.decision.as_str(),
                response.explanation
            ),
        });
    }

    // Auto-approved by policy: no human was asked, so there is no signature to
    // check and none is expected.
    let Some(envelope) = response.envelope else {
        return Ok(Verdict::Allow {
            reason: format!("countersign: {}", response.explanation),
        });
    };

    // The action the device signed is the one the daemon's pack refined —
    // `fs.delete.text`, or `fs.delete` itself when nothing refined it. The
    // verifier's own action binding is exact, so the binding is done here as
    // a prefix check instead: a refinement of this gate's verb is accepted,
    // and an approval for anything else — another namespace, another verb —
    // is not spent on a delete.
    let approved_action = envelope
        .request()
        .map(|request| request.action)
        .map_err(|e| format!("the approval is malformed, so nothing is deleted: {e}"))?;
    if !refines(&approved_action, ACTION) {
        return Err(format!(
            "the approval is for {approved_action:?}, not {ACTION}, so nothing is deleted"
        ));
    }

    let registry = registry(config)?;
    let mut counters = FileStore::open(config.state_dir.join("counters.json"))
        .map_err(|e| format!("replay state unusable, so this is refused: {e}"))?;

    verify_for_execution(
        &envelope,
        &Execution {
            // Byte for byte against the command that is about to run. This is
            // the binding that stops one approval being spent on a second,
            // different delete.
            statement: &statement,
            uri_fingerprint: &fingerprint,
            // Checked above, as a prefix; `Some` here would demand an exact
            // match and refuse every refined approval.
            action: None,
        },
        &registry,
        &VerifyPolicy {
            accept_test_keys: config.accept_test_keys,
            ..Default::default()
        },
        &mut counters,
        &RustCryptoBackend,
        None,
    )
    .map_err(|e| format!("the approval did not verify, so nothing is deleted: {e}"))?;

    Ok(Verdict::Allow {
        reason: format!(
            "countersigned at the device — digest {} — {}",
            response.digest_short, response.environment
        ),
    })
}

/// The keys this gate will accept.
///
/// The roster first: every device `signetd enroll` recorded, with its class
/// and its revocation status carried across, so an approval signed by the
/// app's enclave key verifies here the way it does in the daemon. A roster
/// that will not load is an error, not an empty registry — a gate that
/// quietly believed nobody would deny every real approval and say the
/// signature was bad, which is the wrong thing to be told.
///
/// Then, only when asked, the published test keys. There are two — the one
/// `--device=mock` signs with, and the one a remote approval signs with —
/// because they are different devices and spec §4.1 keeps a counter per
/// `device_id`. Both are published, so both are refused by a default
/// verifier; enrolling them here is what `--accept-test-keys` means, and it
/// is false in anything real.
pub fn registry(config: &Config) -> Result<Registry, String> {
    let mut registry = LocalRoster::load(&config.roster_dir)
        .map_err(|e| format!("the device roster cannot be read, so nothing can be verified: {e}"))?
        .registry()
        .map_err(|e| format!("the device roster has a record a verifier rejects: {e}"))?;

    if config.accept_test_keys {
        for (derivation, operator) in [
            (signetd::device::TEST_KEY_DERIVATION, "mock-device"),
            (signetd::relay::REMOTE_TEST_KEY_DERIVATION, "remote-device"),
        ] {
            use p256::ecdsa::SigningKey;
            use sha2::{Digest, Sha256};
            let key = SigningKey::from_slice(&Sha256::digest(derivation.as_bytes()))
                .expect("the derived test scalar is valid");
            registry.enroll(
                EnrolledDevice::test_key(key.verifying_key().to_sec1_bytes().to_vec())
                    .with_operator(countersign_verify::Operator::new(operator)),
            );
        }
    }
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            socket: PathBuf::from("/nonexistent/countersign.sock"),
            accept_test_keys: true,
            state_dir: PathBuf::from("/nonexistent"),
            roster_dir: PathBuf::from("/nonexistent"),
            deadline: Duration::from_secs(5),
        }
    }

    #[test]
    fn the_keys_come_from_the_roster_and_test_keys_only_when_asked() {
        // No roster written yet and no flag: nobody is believed. That is the
        // state a fresh machine is in, and it verifies nothing rather than
        // something.
        let none = Config {
            accept_test_keys: false,
            ..config()
        };
        assert!(registry(&none).unwrap().is_empty());
        // The flag enrols the two published test keys and nothing else.
        assert!(!registry(&config()).unwrap().is_empty());
    }

    #[test]
    fn a_roster_that_will_not_load_is_an_error_not_an_empty_registry() {
        // A gate that read a damaged roster as "nobody enrolled" would deny
        // every real approval with a message about a bad signature. It should
        // say what is actually wrong.
        let dir = std::env::temp_dir().join(format!("countersign-hook-roster-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("roster.json"), "{ not a roster").unwrap();
        let bad = Config {
            roster_dir: dir,
            ..config()
        };
        let err = registry(&bad).unwrap_err();
        assert!(err.contains("roster"), "{err}");
    }

    fn bash(command: &str) -> HookInput {
        HookInput {
            tool_name: "Bash".into(),
            tool_input: json!({ "command": command }),
            cwd: "/tmp/demo".into(),
            session_id: "test".into(),
        }
    }

    #[test]
    fn creating_a_file_never_reaches_the_daemon() {
        // The socket in `config()` does not exist, so anything that tried to
        // ask would deny. Passing proves it did not try.
        assert_eq!(
            gate(&bash("touch demo/scratch.txt"), &config()),
            Verdict::Pass
        );
        assert_eq!(gate(&bash("mkdir -p demo"), &config()), Verdict::Pass);
    }

    #[test]
    fn a_tool_that_is_not_bash_is_not_this_gates_business() {
        let write = HookInput {
            tool_name: "Write".into(),
            tool_input: json!({ "file_path": "/tmp/demo/scratch.txt", "content": "" }),
            ..Default::default()
        };
        assert_eq!(gate(&write, &config()), Verdict::Pass);
    }

    #[test]
    fn a_click_is_refused_without_asking_and_a_screenshot_passes() {
        // The socket in `config()` does not exist, so a gate that asked would
        // deny with a message about signetd. This denial must not mention it:
        // nothing was asked, because nothing in a click can be countersigned.
        let click = HookInput {
            tool_name: "mcp__computer-use__computer_batch".into(),
            tool_input: json!({
                "actions": [
                    { "action": "screenshot" },
                    { "action": "left_click", "coordinate": [126, 392] }
                ]
            }),
            ..Default::default()
        };
        let Verdict::Deny { reason } = gate(&click, &config()) else {
            panic!("a click must be refused");
        };
        assert!(reason.contains("left_click"), "{reason}");
        assert!(!reason.contains("signetd"), "{reason}");

        // Looking changes nothing, so the gate has no opinion: Pass, not
        // Allow, so the person's own permission settings still apply.
        let look = HookInput {
            tool_name: "mcp__computer-use__computer_batch".into(),
            tool_input: json!({ "actions": [{ "action": "screenshot" }] }),
            ..Default::default()
        };
        assert_eq!(gate(&look, &config()), Verdict::Pass);

        // The grant passes even when its stated purpose is the delete. The
        // grant does nothing by itself; the click it would make possible is
        // what is refused, and it is refused whatever was said here.
        let grant = HookInput {
            tool_name: "mcp__computer-use__request_access".into(),
            tool_input: json!({
                "apps": ["Finder"],
                "reason": "Delete the test files using Finder"
            }),
            ..Default::default()
        };
        assert_eq!(gate(&grant, &config()), Verdict::Pass);
    }

    #[test]
    fn a_delete_with_no_daemon_is_denied_not_allowed() {
        // Failing closed is the entire posture. A gate that waved deletions
        // through whenever its daemon was down would be defeated by stopping
        // the daemon.
        let verdict = gate(&bash("rm demo/scratch.txt"), &config());
        let Verdict::Deny { reason } = verdict else {
            panic!("expected a denial, got {verdict:?}");
        };
        assert!(reason.contains("signetd"), "{reason}");
    }

    #[test]
    fn a_refined_delete_is_still_this_gates_delete() {
        // A pack claiming `fs` answers with a refinement, and that is what
        // the device signs. Everything under `fs.delete.` is accepted;
        // a lookalike verb or another namespace is not.
        assert!(refines("fs.delete", ACTION));
        assert!(refines("fs.delete.text", ACTION));
        assert!(refines("fs.delete.other", ACTION));
        assert!(!refines("fs.deleted", ACTION));
        assert!(!refines("fs.delete.", ACTION));
        assert!(!refines("fs.read", ACTION));
        assert!(!refines("sql.dml", ACTION));
        assert!(!refines("", ACTION));
    }

    #[test]
    fn passing_emits_nothing_at_all() {
        // Not `{"permissionDecision":"allow"}`. Answering "allow" to every
        // untouched tool call would silently override the user's own settings
        // for calls this gate has no view on.
        assert!(Verdict::Pass.to_hook_output().is_none());
    }

    #[test]
    fn a_denial_is_shaped_the_way_the_harness_expects() {
        let output = Verdict::Deny {
            reason: "nope".into(),
        }
        .to_hook_output()
        .unwrap();
        let specific = &output["hookSpecificOutput"];
        assert_eq!(specific["hookEventName"], "PreToolUse");
        assert_eq!(specific["permissionDecision"], "deny");
        assert_eq!(specific["permissionDecisionReason"], "nope");
    }

    #[test]
    fn a_malformed_tool_input_is_not_a_delete_and_not_a_crash() {
        let odd = HookInput {
            tool_name: "Bash".into(),
            tool_input: json!("not an object"),
            ..Default::default()
        };
        assert_eq!(gate(&odd, &config()), Verdict::Pass);
    }
}
