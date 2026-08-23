//! `countersign-hook` — the `PreToolUse` gate Claude Code runs before a tool.
//!
//! ```text
//! countersign-hook --accept-test-keys        read a PreToolUse payload on stdin
//! countersign-hook --explain 'rm -rf x'      say what it would do, ask nobody
//! ```
//!
//! Exit status is always success. The verdict travels in the JSON on stdout,
//! because a non-zero exit means "the hook broke" and this hook denying is not
//! the hook breaking.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use countersign_hook::{detect, gate, Config, HookInput, Verdict};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return ExitCode::SUCCESS;
    }

    let config = match parse(&args) {
        Ok(Parsed::Explain(command, _)) => {
            explain(&command);
            return ExitCode::SUCCESS;
        }
        Ok(Parsed::Gate(config)) => config,
        Err(message) => {
            // A misconfigured gate must not be an open one. Deny, and say what
            // to fix — the message reaches the model and the transcript.
            deny(&format!(
                "countersign-hook is misconfigured ({message}), so nothing is approved"
            ));
            return ExitCode::SUCCESS;
        }
    };

    let mut payload = String::new();
    if std::io::stdin().read_to_string(&mut payload).is_err() {
        deny("countersign-hook could not read the tool payload, so nothing is approved");
        return ExitCode::SUCCESS;
    }

    let input: HookInput = match serde_json::from_str(&payload) {
        Ok(input) => input,
        Err(e) => {
            // Unreadable means unknown, and an unknown tool call might be a
            // delete. Loud and diagnosable beats quietly permissive.
            deny(&format!(
                "countersign-hook could not parse the tool payload ({e}), so it cannot tell \
                 whether this deletes anything"
            ));
            return ExitCode::SUCCESS;
        }
    };

    if let Some(output) = gate(&input, &config).to_hook_output() {
        println!("{output}");
    }
    ExitCode::SUCCESS
}

enum Parsed {
    Gate(Config),
    Explain(String, ()),
}

fn parse(args: &[String]) -> Result<Parsed, String> {
    let mut socket = signetd::service::socket_path();
    let mut accept_test_keys = false;
    let mut state_dir = signetd::config::config_dir().join("hook-state");
    let mut deadline = Duration::from_secs(90);
    let mut explain: Option<String> = None;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| -> Result<String, String> {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match arg.as_str() {
            "--socket" => socket = PathBuf::from(value("--socket")?),
            "--state-dir" => state_dir = PathBuf::from(value("--state-dir")?),
            "--accept-test-keys" => accept_test_keys = true,
            "--deadline-ms" => {
                let raw = value("--deadline-ms")?;
                deadline = Duration::from_millis(
                    raw.parse()
                        .map_err(|_| format!("{raw:?} is not a number"))?,
                );
            }
            "--explain" => explain = Some(value("--explain")?),
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }

    if let Some(command) = explain {
        return Ok(Parsed::Explain(command, ()));
    }

    Ok(Parsed::Gate(Config {
        socket,
        accept_test_keys,
        state_dir,
        deadline,
    }))
}

/// Say what the detector sees, without asking anyone for anything.
fn explain(command: &str) {
    let held = detect::deletions(command);
    if held.is_empty() {
        println!("pass — nothing here deletes a file, so no approval is requested");
        return;
    }
    println!("hold — this needs a countersignature:");
    for deletion in held {
        println!("  {}\n      {}", deletion.segment, deletion.reason);
    }
}

fn deny(reason: &str) {
    if let Some(output) = (Verdict::Deny {
        reason: reason.to_string(),
    })
    .to_hook_output()
    {
        println!("{output}");
    }
}

fn print_help() {
    eprintln!(
        "countersign-hook {}\n\
         \n\
         A Claude Code PreToolUse gate. Deleting a file takes a physical\n\
         countersignature; creating one takes nothing at all.\n\
         \n\
         USAGE\n\
         \x20 --accept-test-keys     accept PUBLISHED TEST KEY signatures (demos only)\n\
         \x20 --socket PATH          signetd control socket\n\
         \x20 --state-dir PATH       where the replay defence is kept between calls\n\
         \x20 --deadline-ms N        deny on our own initiative after this (default 90000)\n\
         \x20 --explain CMD          print what the detector sees and exit\n\
         \n\
         Keep --deadline-ms below the harness's hook timeout. If the harness\n\
         gives up first this hook returns nothing, and nothing means no opinion.\n",
        env!("CARGO_PKG_VERSION")
    );
}
