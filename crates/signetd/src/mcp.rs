//! The MCP bridge — what Claude Code actually spawns.
//!
//! A thin stdio server that forwards to the daemon over the control socket. It
//! holds no key, owns no device, and makes no decisions; if it were compromised
//! the worst it could do is ask for approvals that a human would then see and
//! refuse.
//!
//! Hand-rolled rather than pulled from an SDK: MCP is JSON-RPC 2.0 over stdio,
//! this needs three methods of it, and `countersign-pack` already established
//! the framing. A dependency here would be larger than the thing it replaced.
//!
//! # There is no tool that approves anything
//!
//! `request_approval` *asks*. The only input that produces a signature is the
//! physical actuation. An agent holding every tool in this file still cannot
//! approve its own request, and that is the entire point of the product — so
//! adding an `approve` tool would not be a feature, it would be the end of one.

use std::io::{BufRead, Write};

use serde_json::{json, Value};

use crate::daemon::ApprovalRequest;
use crate::service::{socket_path, Client, ClientError};

/// The MCP revision this speaks.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// Serve MCP on stdin/stdout until EOF.
pub fn serve() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    // One connection for the life of this bridge, not one per tool call.
    //
    // The daemon keys its requester-continuity check on the connection, because
    // that is the only thing about a caller it can actually verify. Reconnecting
    // per call would make every request look like a brand-new requester and ask
    // the operator to acknowledge a change on every single approval — which is
    // precisely the fatigue the check exists to avoid.
    let mut session = Session::default();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        // Notifications get no reply; anything else does.
        if let Some(response) = handle(&line, &mut session) {
            writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
            stdout.flush()?;
        }
    }
    Ok(())
}

/// The bridge's connection to the daemon, held across calls.
#[derive(Default)]
pub struct Session {
    client: Option<Client>,
}

impl Session {
    /// The live connection, reconnecting if the daemon restarted under us.
    ///
    /// `for_approval` decides whether Signet is opened to answer. Asking for
    /// an approval is a reason to open it; asking after the device or the
    /// audit trail is a question about the machine as it stands, and opening
    /// an app would change the answer rather than report it.
    fn client(&mut self, for_approval: bool) -> Result<&mut Client, ClientError> {
        if self.client.is_none() {
            let socket = socket_path();
            self.client = Some(if for_approval {
                crate::launch::connect_for_approval(&socket)?
            } else {
                Client::connect(&socket)?
            });
        }
        Ok(self.client.as_mut().expect("just connected"))
    }

    /// Drop the connection so the next call reconnects.
    fn reset(&mut self) {
        self.client = None;
    }
}

fn handle(line: &str, session: &mut Session) -> Option<Value> {
    let request: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return Some(error(Value::Null, -32700, &e.to_string())),
    };

    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let id = request.get("id").cloned();
    let params = request.get("params").cloned().unwrap_or(Value::Null);

    // A JSON-RPC notification has no id and must not be answered.
    let id = match id {
        Some(id) if !id.is_null() => id,
        _ => return None,
    };

    Some(match method {
        "initialize" => ok(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "countersign", "version": env!("CARGO_PKG_VERSION") },
            }),
        ),
        "tools/list" => ok(id, json!({ "tools": tools() })),
        "tools/call" => call_tool(id, &params, session),
        other => error(id, -32601, &format!("unknown method {other:?}")),
    })
}

fn tools() -> Value {
    json!([
        {
            "name": "request_approval",
            "description":
                "Request a physical human countersignature for a consequential action. Blocks \
                 until a human acts at the device or the request expires. Returns a decision and, \
                 when approved, a signature bundle. You cannot approve your own request — the \
                 only input that produces a signature is the physical device.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description":
                            "Namespaced verb, e.g. sql.execute, terraform.apply, npm.publish.",
                    },
                    "target_uri": {
                        "type": "string",
                        "description":
                            "Connection URI for the target. Fingerprinted on arrival and then \
                             discarded; it is never stored or logged.",
                    },
                    "statement": {
                        "type": "string",
                        "description": "The full statement text. Never truncate it.",
                    },
                    "advisory": {
                        "type": "object",
                        "description":
                            "Optional unverified context (row counts, dependencies). Displayed \
                             marked as unverified; no policy branches on it.",
                    },
                },
                "required": ["action", "target_uri", "statement"],
            },
        },
        {
            "name": "device_status",
            "description":
                "Report whether a Countersign device is attached, its id, and whether it is a \
                 test key. Check this before attempting work that will need approval.",
            "inputSchema": { "type": "object", "properties": {} },
        },
        {
            "name": "audit_summary",
            "description": "Report how many approvals are recorded and the current chain head.",
            "inputSchema": { "type": "object", "properties": {} },
        },
    ])
}

fn call_tool(id: Value, params: &Value, session: &mut Session) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    let client = match session.client(name == "request_approval") {
        Ok(c) => c,
        Err(e) => {
            session.reset();
            return tool_error(id, &e.to_string());
        }
    };

    match name {
        "device_status" => match client.device_status() {
            Ok(status) => {
                let note = if status.is_test_key {
                    "  This is a MOCK device signing with the published test key. Nothing it \
                     signs is a real approval."
                } else {
                    ""
                };
                tool_text(
                    id,
                    &format!(
                        "Device attached: {}\nDevice id: {}\nKind: {}\nCounter: {}\nConfigured \
                         environments: {}\n{note}",
                        status.attached,
                        status.device_id,
                        status.kind,
                        status.counter,
                        status.environments,
                    ),
                )
            }
            Err(e) => tool_error(id, &e.to_string()),
        },

        "audit_summary" => match client.audit_summary() {
            Ok(summary) => tool_text(
                id,
                &format!(
                    "Recorded approvals: {}\nChain head: {}",
                    summary.entries, summary.head
                ),
            ),
            Err(e) => tool_error(id, &e.to_string()),
        },

        "request_approval" => {
            let request = ApprovalRequest {
                action: args
                    .get("action")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                target_uri: args
                    .get("target_uri")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                uri_fingerprint: None,
                target_kind: "database".into(),
                statement: args
                    .get("statement")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                advisory: args.get("advisory").cloned(),
                requester_id: "claude-code".into(),
                requester_instance: std::env::var("CLAUDE_SESSION_ID").unwrap_or_default(),
                ttl_ms: None,
            };

            if request.statement.trim().is_empty() {
                return tool_error(id, "statement is required and must not be empty");
            }

            match client.request_approval(&request) {
                Ok(response) => {
                    let approved = response.decision == countersign_verify::Decision::Approved;
                    let mut text = format!(
                        "Decision: {}\nEnvironment: {} ({})\nSeverity: {}\nDigest: {}\n\n{}",
                        response.decision.as_str(),
                        response.environment,
                        response.tier,
                        response.severity,
                        response.digest_short,
                        response.explanation,
                    );

                    if !response.warnings.is_empty() {
                        text.push_str("\n\nWarnings:\n");
                        for w in &response.warnings {
                            text.push_str(&format!("  · {w}\n"));
                        }
                    }

                    // The client-side half of the content-binding check —
                    // but only where the device was actually asked. Saying
                    // "the device displayed" about a request that policy
                    // refused before any presentation would teach the user
                    // that the sentence is boilerplate, and the digest check
                    // only works if they believe it.
                    // A signature means the device approved it. `aborted` and
                    // `expired` are only reachable by having been presented.
                    // Everything else — auto-approved, refused, no device —
                    // never got in front of anyone.
                    let reached_device = response.envelope.is_some()
                        || matches!(
                            response.decision,
                            countersign_verify::Decision::Aborted
                                | countersign_verify::Decision::Expired
                        );

                    if reached_device {
                        text.push_str(&format!(
                            "\nThe device displayed digest {} — tell the user to confirm it \
                             matched.\n",
                            response.digest_short
                        ));
                    } else {
                        text.push_str("\nThis never reached the device; no human was asked.\n");
                    }

                    if let Some(envelope) = &response.envelope {
                        text.push_str(&format!(
                            "\nSignature bundle (hand this to a verifier):\n{}\n",
                            serde_json::to_string(envelope).unwrap_or_default()
                        ));
                    }

                    if !approved {
                        text.push_str("\nThis was NOT approved. Do not proceed with the action.\n");
                    }

                    // A refusal is a normal result, not a transport failure, so
                    // it comes back as content rather than an error — but it is
                    // flagged so the model cannot read it as success.
                    tool_result(id, &text, !approved)
                }
                Err(ClientError::Daemon(message)) => tool_error(id, &message),
                Err(e) => tool_error(id, &e.to_string()),
            }
        }

        other => tool_error(id, &format!("unknown tool {other:?}")),
    }
}

fn tool_text(id: Value, text: &str) -> Value {
    tool_result(id, text, false)
}

fn tool_result(id: Value, text: &str, is_error: bool) -> Value {
    ok(
        id,
        json!({
            "content": [{ "type": "text", "text": text }],
            "isError": is_error,
        }),
    )
}

fn tool_error(id: Value, message: &str) -> Value {
    tool_result(id, &format!("countersign: {message}"), true)
}

fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error(id: Value, code: i32, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_reports_tools_and_a_protocol_version() {
        let response = handle(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            &mut Session::default(),
        )
        .unwrap();
        let result = &response["result"];
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert!(result["capabilities"]["tools"].is_object());
        assert_eq!(result["serverInfo"]["name"], "countersign");
    }

    #[test]
    fn a_notification_gets_no_reply() {
        // Answering one corrupts the stream, and `notifications/initialized`
        // arrives on every single session.
        assert!(handle(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &mut Session::default()
        )
        .is_none());
    }

    #[test]
    fn the_tool_list_exposes_no_way_to_approve() {
        // The load-bearing assertion in this file.
        let response = handle(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            &mut Session::default(),
        )
        .unwrap();
        let names: Vec<&str> = response["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();

        assert!(names.contains(&"request_approval"));
        assert!(names.contains(&"device_status"));
        assert!(
            !names
                .iter()
                .any(|n| n.contains("approve") && *n != "request_approval"),
            "no tool may approve anything: {names:?}"
        );
    }

    #[test]
    fn request_approval_declares_the_arguments_it_needs() {
        let response = handle(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
            &mut Session::default(),
        )
        .unwrap();
        let tool = response["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "request_approval")
            .unwrap();
        let required = tool["inputSchema"]["required"].as_array().unwrap();
        assert!(required.iter().any(|r| r == "statement"));
        assert!(required.iter().any(|r| r == "action"));
        assert!(required.iter().any(|r| r == "target_uri"));
    }

    #[test]
    fn an_unknown_method_is_an_error_not_a_panic() {
        let response = handle(
            r#"{"jsonrpc":"2.0","id":4,"method":"nope"}"#,
            &mut Session::default(),
        )
        .unwrap();
        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn malformed_input_answers_rather_than_hanging_the_client() {
        let response = handle("{{{not json", &mut Session::default()).unwrap();
        assert_eq!(response["error"]["code"], -32700);
    }
}
