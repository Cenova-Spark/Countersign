//! Does this tool drive the person's own screen, or only look at it?
//!
//! `detect` gates one route to the thing a pack guards: the shell command the
//! harness was asked to run. This names a second route, and it is the one
//! that stays open however far down the gate moves. A tool that injects
//! clicks and keystrokes into the desktop acts as the person, in the person's
//! own applications: it can open Finder and choose Move to Trash, press Apply
//! in a deploy console, or confirm a payment in a browser tab. At the
//! filesystem, the database or the bank that is the person — same process,
//! same user, same call — and no chokepoint keyed on the agent sees it. The
//! agent's hand shows in exactly one place, the tool call in the harness, so
//! that is where it is refused. This holds for every pack, not only the `fs`
//! one the hook happens to ask for; it is a property of the enforcement
//! point.
//!
//! # Looking is free; touching is refused
//!
//! A screenshot changes nothing. The hook lets the agent look — take a
//! screenshot, zoom into a region, ask where the cursor is, wait, ask for the
//! grant that makes a screenshot possible, choose a monitor — and refuses
//! anything that touches: a click, a key, typed text, a scroll, a drag, an
//! app launched, the clipboard written or read, a guided tour that clicks on
//! the person's behalf. A batch is read action by action, and one touching
//! action refuses the whole batch, because the batch runs as one.
//!
//! # Why refuse rather than hold
//!
//! The shell gate holds and asks. This one refuses outright. A
//! countersignature covers a statement the person reads on the screen and the
//! device signs byte for byte. A click is a coordinate pair and a keystroke is
//! a key name; nothing in either says what it will do, so putting it on the
//! dial would be blind signing with a better-looking ceremony. There is no
//! middle setting between looking and touching, and the hook does not invent
//! one.
//!
//! # Which way it errs
//!
//! Toward refusing. An action name this does not know, a batch it cannot
//! read, a tool on the server it has not met: all refused, because a gate
//! that passed what it could not name would be back to the matcher passing
//! everything but `Bash`. The other direction is the list itself: a server
//! that drives the screen under a name not here passes untouched, the same
//! way `detect` passes a delete verb it does not know, and the matcher in the
//! harness settings has to name the same server or the hook is never run for
//! it at all.

use serde_json::Value;

/// The server that drives the desktop, as a tool-name prefix.
///
/// The desktop app's computer-use server is the one there is. The browser
/// servers are deliberately not here: the in-app one is confined to web
/// pages, and the one that drives real Chrome cannot unlink a local file,
/// though it can reach anything a signed-in tab can, which is a different
/// gate's business.
pub const SERVER: &str = "mcp__computer-use__";

/// Tools on the server that only look. The grant is here because without it
/// there is no screenshot, and the grant by itself does nothing: what it
/// makes possible is read action by action below.
const LOOKING_TOOLS: &[&str] = &[
    "request_access",
    "list_granted_applications",
    "switch_display",
];

/// The tool whose input is a list of actions, each read on its own.
const BATCH: &str = "computer_batch";

/// Batch actions that only look.
const LOOKING_ACTIONS: &[&str] = &["screenshot", "zoom", "cursor_position", "wait"];

/// What the gate made of a tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading {
    /// Not a tool on the server; not this module's business.
    NotThisServer,
    /// Looks and changes nothing. The gate has no opinion.
    Looks,
    /// Touches the desktop, or cannot be read. Refused, and this is why.
    Drives(String),
}

/// Read one tool call.
pub fn read(tool_name: &str, tool_input: &Value) -> Reading {
    let Some(tool) = tool_name.strip_prefix(SERVER) else {
        return Reading::NotThisServer;
    };
    if LOOKING_TOOLS.contains(&tool) {
        return Reading::Looks;
    }
    if tool == BATCH {
        return read_batch(tool_name, tool_input);
    }
    let stated = tool_input.get("reason").and_then(Value::as_str);
    Reading::Drives(refusal(
        tool_name,
        "drives the screen rather than looking at it",
        stated,
    ))
}

/// A batch is as touching as its most touching action.
fn read_batch(tool_name: &str, tool_input: &Value) -> Reading {
    let Some(actions) = tool_input.get("actions").and_then(Value::as_array) else {
        return Reading::Drives(refusal(
            tool_name,
            "has no readable list of actions, so the gate cannot tell whether it looks or touches",
            None,
        ));
    };

    let mut touching: Vec<&str> = Vec::new();
    for action in actions {
        match action.get("action").and_then(Value::as_str) {
            Some(name) if LOOKING_ACTIONS.contains(&name) => {}
            Some(name) => touching.push(name),
            None => return Reading::Drives(refusal(
                tool_name,
                "has an action with no name, so the gate cannot tell whether it looks or touches",
                None,
            )),
        }
    }
    if touching.is_empty() {
        return Reading::Looks;
    }

    touching.sort_unstable();
    touching.dedup();
    Reading::Drives(refusal(
        tool_name,
        &format!(
            "touches the desktop, or names an action the gate does not know ({})",
            touching.join(", ")
        ),
        None,
    ))
}

/// The refusal, in words the model and the transcript both get.
///
/// It says what does pass, so the agent can take the screenshot and report
/// instead of casting about for another way in. `stated` is the purpose the
/// agent gave when it asked for a grant, when it gave one. It is a claim, and
/// nothing here turns on it; it is repeated back so the transcript records
/// what the tool call was for.
fn refusal(tool_name: &str, what: &str, stated: Option<&str>) -> String {
    let mut reason = format!(
        "countersign: {tool_name} {what}, and a click can do anything a person at the keyboard \
         can: delete a file, apply a deploy, confirm a payment, whatever a pack gates. Nothing in \
         a click can be countersigned, so it is refused rather than held. Looking is free: a \
         batch of only {} passes, as do {}.",
        LOOKING_ACTIONS.join(", "),
        LOOKING_TOOLS.join(", ")
    );
    if let Some(stated) = stated.map(str::trim).filter(|s| !s.is_empty()) {
        reason.push_str(&format!(" The stated purpose was {stated:?}."));
    }
    reason
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn batch(actions: Value) -> Value {
        json!({ "actions": actions })
    }

    fn drives(reading: Reading) -> String {
        match reading {
            Reading::Drives(reason) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_batch_that_only_looks_passes() {
        for actions in [
            json!([{ "action": "screenshot" }]),
            json!([{ "action": "screenshot", "scale": 0.5 }, { "action": "zoom", "region": [0, 0, 10, 10] }]),
            json!([{ "action": "cursor_position" }, { "action": "wait", "duration": 1 }]),
            json!([]),
        ] {
            assert_eq!(
                read("mcp__computer-use__computer_batch", &batch(actions.clone())),
                Reading::Looks,
                "{actions}"
            );
        }
    }

    #[test]
    fn one_touching_action_refuses_the_whole_batch() {
        // The transcript's shape: a screenshot to look, then the click that
        // chose Move to Trash. The batch runs as one, so it is refused as one,
        // and the refusal names the action that made it so.
        let reason = drives(read(
            "mcp__computer-use__computer_batch",
            &batch(json!([
                { "action": "screenshot" },
                { "action": "left_click", "coordinate": [126, 392] },
                { "action": "key", "text": "cmd+Delete" }
            ])),
        ));
        // The refused list names the touching actions and not the screenshot
        // beside them; the screenshot appears only in what passes.
        assert!(reason.contains("(key, left_click)"), "{reason}");

        for touching in [
            "type",
            "mouse_move",
            "left_click_drag",
            "right_click",
            "middle_click",
            "double_click",
            "triple_click",
            "scroll",
            "hold_key",
            "left_mouse_down",
            "left_mouse_up",
        ] {
            let reason = drives(read(
                "mcp__computer-use__computer_batch",
                &batch(json!([{ "action": touching }])),
            ));
            assert!(reason.contains(touching), "{reason}");
        }
    }

    #[test]
    fn a_batch_the_gate_cannot_read_is_refused() {
        // Unknown means refused, or the gate is back to passing everything
        // it did not think of. A new action name, a missing name, a list
        // that is not a list, no list at all.
        for input in [
            batch(json!([{ "action": "teleport" }])),
            batch(json!([{ "action": "Screenshot" }])),
            batch(json!([{ "coordinate": [1, 2] }])),
            batch(json!("screenshot")),
            json!({}),
            json!("not an object"),
        ] {
            drives(read("mcp__computer-use__computer_batch", &input));
        }
    }

    #[test]
    fn the_tools_that_only_look_pass_and_the_rest_are_refused() {
        for tool in [
            "mcp__computer-use__request_access",
            "mcp__computer-use__list_granted_applications",
            "mcp__computer-use__switch_display",
        ] {
            assert_eq!(read(tool, &json!({})), Reading::Looks, "{tool}");
        }
        for tool in [
            "mcp__computer-use__open_application",
            "mcp__computer-use__teach_step",
            "mcp__computer-use__teach_batch",
            "mcp__computer-use__request_teach_access",
            "mcp__computer-use__read_clipboard",
            "mcp__computer-use__write_clipboard",
            // A tool the server grows later is refused until it is read here.
            "mcp__computer-use__something_new",
        ] {
            let reason = drives(read(tool, &json!({})));
            assert!(reason.contains(tool), "{reason}");
        }
    }

    #[test]
    fn other_tools_are_not_this_modules_business() {
        // Bash has its own gate; Write and Edit create and change, which is
        // free; a mail server's trash is a different verb in a different
        // namespace, and not this hook's to refuse.
        for tool in [
            "Bash",
            "Write",
            "Edit",
            "Read",
            "mcp__gmail__trash_message",
            "computer-use",
            "",
        ] {
            assert_eq!(read(tool, &json!({})), Reading::NotThisServer, "{tool:?}");
        }
    }

    #[test]
    fn the_refusal_says_what_passes_and_repeats_a_stated_purpose() {
        let with = drives(read(
            "mcp__computer-use__request_teach_access",
            &json!({ "apps": ["Finder"], "reason": "Delete the test files using Finder" }),
        ));
        assert!(
            with.contains("Delete the test files using Finder"),
            "{with}"
        );
        assert!(with.contains("screenshot"), "{with}");
        assert!(with.contains("request_access"), "{with}");

        let blank = drives(read(
            "mcp__computer-use__request_teach_access",
            &json!({ "reason": "  " }),
        ));
        assert!(!blank.contains("stated purpose"), "{blank}");
    }
}
