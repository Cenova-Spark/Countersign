//! The host side: spawn a pack, ask it questions, and enforce the rules that
//! make running third-party code in front of an approval prompt acceptable.
//!
//! See `spec/pack-protocol-v1.md` §4. The three rules are:
//!
//! * a pack may raise severity and never lower it,
//! * a pack may not write the environment label or the digest,
//! * failure is closed.
//!
//! A host that skips them has a plugin system in which a pack is an
//! auto-approve oracle.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::rpc::{RpcRequest, RpcResponse};
use crate::types::{
    namespace_of, ClassifyRequest, ClassifyResponse, PackInfo, RenderLine, Severity, PROTOCOL,
};

/// Why a pack's answer could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackFailure {
    /// The process would not start.
    Spawn(String),
    /// No answer inside the timeout.
    Timeout(Duration),
    /// The process exited, or its pipes closed.
    Crashed(String),
    /// The answer was not a valid response.
    Malformed(String),
    /// The pack returned a JSON-RPC error.
    Rpc { code: i32, message: String },
    /// The refined action left the requested namespace — an attempt to escape
    /// every policy rule that mentions it.
    NamespaceEscape { requested: String, returned: String },
    /// The pack tried to write a `label` or `digest` line.
    ForbiddenRole(String),
    /// The pack claims a protocol this host does not speak.
    ProtocolMismatch { got: u32, want: u32 },
    /// A WebAssembly pack ran out of fuel — the deterministic form of a
    /// timeout. An infinite loop, or a statement too large to classify.
    Exhausted { fuel: u64 },
}

impl std::fmt::Display for PackFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use PackFailure::*;
        match self {
            Spawn(e) => write!(f, "could not start pack: {e}"),
            Timeout(d) => write!(f, "pack did not answer within {d:?}"),
            Crashed(e) => write!(f, "pack stopped responding: {e}"),
            Malformed(e) => write!(f, "pack returned an unusable response: {e}"),
            Rpc { code, message } => write!(f, "pack returned error {code}: {message}"),
            NamespaceEscape {
                requested,
                returned,
            } => write!(
                f,
                "pack refined {requested:?} to {returned:?}, leaving its namespace"
            ),
            ForbiddenRole(r) => {
                write!(
                    f,
                    "pack emitted a {r:?} render line, which only the daemon may write"
                )
            }
            ProtocolMismatch { got, want } => {
                write!(f, "pack speaks protocol {got}, this host speaks {want}")
            }
            Exhausted { fuel } => write!(
                f,
                "pack ran out of fuel ({fuel} units) before answering — a loop, or a statement \
                 too large to classify"
            ),
        }
    }
}

impl std::error::Error for PackFailure {}

/// How this host runs packs.
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// Wall-clock limit on a single `classify`.
    ///
    /// Mandatory, because classification sits in front of a human waiting at a
    /// device. A pack that hangs must degrade to friction, not to a hang.
    pub timeout: Duration,

    /// The severity assumed when a pack fails.
    ///
    /// `Critical` by default. A dead classifier means you do not know what the
    /// statement does, and the safe reading of "I don't know" is not "probably
    /// fine".
    pub severity_on_failure: Severity,

    /// Fuel granted to each call of a WebAssembly pack — the deterministic
    /// counterpart of `timeout`, which cannot interrupt an interpreter loop
    /// from outside. Ignored for process-backed packs.
    pub fuel_per_call: u64,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            severity_on_failure: Severity::Critical,
            fuel_per_call: 500_000_000,
        }
    }
}

/// How the host reaches a pack.
enum Transport {
    /// A subprocess speaking line-delimited JSON-RPC on its stdio.
    Process {
        child: Child,
        stdin: ChildStdin,
        lines: Receiver<std::io::Result<String>>,
    },
    /// A WebAssembly module with no imports, driven one line at a time
    /// through `crate::wasm`'s exports.
    #[cfg(feature = "wasm-host")]
    Wasm(Box<crate::wasm_host::WasmPack>),
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Process { child, .. } => {
                f.debug_struct("Process").field("pid", &child.id()).finish()
            }
            #[cfg(feature = "wasm-host")]
            Transport::Wasm(pack) => f.debug_tuple("Wasm").field(pack).finish(),
        }
    }
}

/// A classification, and whether it came from the pack or from the fail-closed
/// path.
///
/// `response` is always usable — the caller never has to handle an error to get
/// a severity, which is what stops "the pack broke" from becoming "so we
/// skipped the check".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    pub response: ClassifyResponse,
    /// `Some` when `response` is the fail-closed substitute rather than the
    /// pack's own answer. Worth logging; never worth ignoring.
    pub failure: Option<PackFailure>,
}

impl Classified {
    pub fn severity(&self) -> Severity {
        self.response.severity
    }
}

/// A running pack — a subprocess, or an instantiated WebAssembly module.
///
/// The two are the same thing to everyone above this struct: the protocol is
/// identical, the rules in §4 are enforced identically, and a caller cannot
/// tell which it has. Only the sandbox differs, and it differs completely.
#[derive(Debug)]
pub struct PackHost {
    transport: Transport,
    info: PackInfo,
    config: HostConfig,
    next_id: u64,
}

impl PackHost {
    /// Instantiate a WebAssembly pack and complete its `describe` handshake.
    ///
    /// The module must import nothing; see `crate::wasm_host`. This is the form
    /// a marketplace distributes, because it is the form that cannot phone
    /// home with the statement it was handed.
    #[cfg(feature = "wasm-host")]
    pub fn spawn_wasm(bytes: &[u8], config: HostConfig) -> Result<Self, PackFailure> {
        let pack = crate::wasm_host::WasmPack::instantiate(bytes, config.fuel_per_call)?;
        Self::handshake(Transport::Wasm(Box::new(pack)), config)
    }

    /// Start a pack and complete its `describe` handshake.
    pub fn spawn(mut command: Command, config: HostConfig) -> Result<Self, PackFailure> {
        command.stdin(Stdio::piped()).stdout(Stdio::piped());
        // stderr is deliberately left alone: it is the pack's log stream, and
        // capturing it into a pipe nobody drains is how a chatty pack deadlocks
        // on a full buffer.
        let mut child = command
            .spawn()
            .map_err(|e| PackFailure::Spawn(e.to_string()))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| PackFailure::Spawn("no stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| PackFailure::Spawn("no stdout".into()))?;

        // A reader thread, because a blocking pipe read has no timeout and §4.4
        // requires one.
        let (tx, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        Self::handshake(
            Transport::Process {
                child,
                stdin,
                lines,
            },
            config,
        )
    }

    fn handshake(transport: Transport, config: HostConfig) -> Result<Self, PackFailure> {
        let mut host = Self {
            transport,
            info: PackInfo {
                name: String::new(),
                version: String::new(),
                protocol: 0,
                actions: Vec::new(),
                pure: false,
            },
            config,
            next_id: 1,
        };

        let value = host.call("describe", None)?;
        let info: PackInfo =
            serde_json::from_value(value).map_err(|e| PackFailure::Malformed(e.to_string()))?;
        if info.protocol != PROTOCOL {
            return Err(PackFailure::ProtocolMismatch {
                got: info.protocol,
                want: PROTOCOL,
            });
        }
        host.info = info;
        Ok(host)
    }

    pub fn info(&self) -> &PackInfo {
        &self.info
    }

    /// Whether this pack claims the namespace of `action`.
    pub fn handles(&self, action: &str) -> bool {
        let ns = namespace_of(action);
        self.info.actions.iter().any(|a| a == ns)
    }

    /// Classify a statement, never returning less than `floor`.
    ///
    /// `floor` is the host's own assessment, computed before the pack ran. It is
    /// passed in rather than applied by the caller afterwards so that the rule
    /// cannot be forgotten at a call site.
    pub fn classify(&mut self, request: &ClassifyRequest, floor: Severity) -> Classified {
        let params = match serde_json::to_value(request) {
            Ok(v) => v,
            Err(e) => return self.fail(request, floor, PackFailure::Malformed(e.to_string())),
        };

        let raw = match self.call("classify", Some(params)) {
            Ok(v) => v,
            Err(e) => return self.fail(request, floor, e),
        };

        let response: ClassifyResponse = match serde_json::from_value(raw) {
            Ok(r) => r,
            Err(e) => return self.fail(request, floor, PackFailure::Malformed(e.to_string())),
        };

        match validate(response, request) {
            Ok(r) => Classified {
                response: r.raised_to(floor),
                failure: None,
            },
            Err(e) => self.fail(request, floor, e),
        }
    }

    /// Build the fail-closed substitute for a request the pack could not answer.
    fn fail(&self, request: &ClassifyRequest, floor: Severity, failure: PackFailure) -> Classified {
        Classified {
            response: fallback(request, floor, &self.config, &failure),
            failure: Some(failure),
        }
    }

    fn call(&mut self, method: &str, params: Option<Value>) -> Result<Value, PackFailure> {
        let id = self.next_id;
        self.next_id += 1;

        let line = serde_json::to_string(&RpcRequest::new(id, method, params))
            .map_err(|e| PackFailure::Malformed(e.to_string()))?;

        match &mut self.transport {
            #[cfg(feature = "wasm-host")]
            Transport::Wasm(pack) => {
                // One line in, one line out, and the fuel meter is the
                // timeout. No pipe, so no late answers to skip past.
                let answer = pack.call_line(&line)?;
                let response: RpcResponse = serde_json::from_str(&answer)
                    .map_err(|e| PackFailure::Malformed(e.to_string()))?;
                Self::unwrap_response(response, id)
            }
            Transport::Process {
                stdin,
                lines,
                ..
            } => {
                writeln!(stdin, "{line}").map_err(|e| PackFailure::Crashed(e.to_string()))?;
                stdin
                    .flush()
                    .map_err(|e| PackFailure::Crashed(e.to_string()))?;

                let deadline = Instant::now() + self.config.timeout;
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    let line = match lines.recv_timeout(remaining) {
                        Ok(Ok(l)) => l,
                        Ok(Err(e)) => return Err(PackFailure::Crashed(e.to_string())),
                        Err(RecvTimeoutError::Timeout) => {
                            return Err(PackFailure::Timeout(self.config.timeout))
                        }
                        Err(RecvTimeoutError::Disconnected) => {
                            return Err(PackFailure::Crashed("pack closed its output".into()))
                        }
                    };

                    if line.trim().is_empty() {
                        continue;
                    }

                    let response: RpcResponse = match serde_json::from_str(&line) {
                        Ok(r) => r,
                        Err(e) => return Err(PackFailure::Malformed(e.to_string())),
                    };

                    // A late answer to a timed-out call is still in the pipe.
                    // Matching on id drops it instead of handing it back as the
                    // answer to a different question.
                    if response.id != id {
                        continue;
                    }

                    return Self::unwrap_response(response, id);
                }
            }
        }
    }

    fn unwrap_response(response: RpcResponse, id: u64) -> Result<Value, PackFailure> {
        if response.id != id {
            return Err(PackFailure::Malformed(format!(
                "response answered id {} to a call with id {id}",
                response.id
            )));
        }
        if let Some(err) = response.error {
            return Err(PackFailure::Rpc {
                code: err.code,
                message: err.message,
            });
        }
        response
            .result
            .ok_or_else(|| PackFailure::Malformed("response had neither result nor error".into()))
    }
}

impl Drop for PackHost {
    fn drop(&mut self) {
        // Closing stdin ends `run_stdio`'s loop; kill covers a pack that ignores
        // EOF. Neither is allowed to fail loudly in a destructor. A wasm module
        // has no process to end; dropping the store is enough.
        if let Transport::Process { child, .. } = &mut self.transport {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Check a pack's answer against the rules in spec §4.1 and §4.2.
///
/// Separated from the transport so it can be tested exhaustively without
/// spawning anything — these are the checks that matter most and they should be
/// the easiest in the crate to exercise.
pub fn validate(
    response: ClassifyResponse,
    request: &ClassifyRequest,
) -> Result<ClassifyResponse, PackFailure> {
    let requested_ns = namespace_of(&request.action);
    let returned_ns = namespace_of(&response.action);
    if requested_ns != returned_ns {
        return Err(PackFailure::NamespaceEscape {
            requested: request.action.clone(),
            returned: response.action.clone(),
        });
    }

    for line in &response.render {
        if !line.role.pack_may_emit() {
            return Err(PackFailure::ForbiddenRole(
                format!("{:?}", line.role).to_lowercase(),
            ));
        }
    }

    Ok(response)
}

/// The fail-closed classification used when a pack cannot answer.
pub fn fallback(
    request: &ClassifyRequest,
    floor: Severity,
    config: &HostConfig,
    failure: &PackFailure,
) -> ClassifyResponse {
    let mut out = ClassifyResponse::new(
        // The un-refined action: without the pack, the refinement is unknown,
        // and inventing one would be a guess policy then keys on.
        request.action.clone(),
        config.severity_on_failure.max(floor),
    );
    out.reversible = None;
    out.render
        .push(RenderLine::primary(request.statement.clone()));
    out.render
        .push(RenderLine::advisory("classification unavailable"));
    out.warnings
        .push(format!("pack classification failed: {failure}"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RenderRole;

    fn req() -> ClassifyRequest {
        ClassifyRequest::new("sql.execute", "DROP TABLE users")
    }

    #[test]
    fn a_pack_may_refine_inside_its_namespace() {
        let r = ClassifyResponse::new("sql.ddl", Severity::Critical);
        assert_eq!(validate(r, &req()).unwrap().action, "sql.ddl");
    }

    #[test]
    fn a_pack_may_not_relabel_its_way_out_of_a_policy() {
        // `sql.execute` -> `noop.ping` would escape every rule mentioning sql.
        let r = ClassifyResponse::new("noop.ping", Severity::None);
        assert!(matches!(
            validate(r, &req()),
            Err(PackFailure::NamespaceEscape { .. })
        ));
    }

    #[test]
    fn a_pack_may_not_write_the_environment_label() {
        // The attack this blocks: showing "local" above a production DROP.
        let mut r = ClassifyResponse::new("sql.ddl", Severity::Critical);
        r.render.push(RenderLine {
            role: RenderRole::Label,
            text: "local".into(),
        });
        assert!(matches!(
            validate(r, &req()),
            Err(PackFailure::ForbiddenRole(_))
        ));
    }

    #[test]
    fn a_pack_may_not_write_the_digest() {
        let mut r = ClassifyResponse::new("sql.ddl", Severity::Critical);
        r.render.push(RenderLine {
            role: RenderRole::Digest,
            text: "0000 0000 0000".into(),
        });
        assert!(matches!(
            validate(r, &req()),
            Err(PackFailure::ForbiddenRole(_))
        ));
    }

    #[test]
    fn primary_and_advisory_lines_are_fine() {
        let mut r = ClassifyResponse::new("sql.ddl", Severity::Critical);
        r.render.push(RenderLine::primary("DROP TABLE users"));
        r.render.push(RenderLine::advisory("3 dependent objects"));
        assert_eq!(validate(r, &req()).unwrap().render.len(), 2);
    }

    #[test]
    fn the_fallback_is_critical_and_says_why() {
        let cfg = HostConfig::default();
        let f = fallback(
            &req(),
            Severity::None,
            &cfg,
            &PackFailure::Timeout(cfg.timeout),
        );
        assert_eq!(
            f.severity,
            Severity::Critical,
            "unknown must not read as harmless"
        );
        assert_eq!(f.action, "sql.execute", "the action stays un-refined");
        assert_eq!(f.reversible, None);
        assert!(f.warnings[0].contains("did not answer"));
        // The statement still reaches the screen — the human can read it even
        // when nothing could classify it.
        assert_eq!(f.render[0].text, "DROP TABLE users");
    }

    #[test]
    fn the_fallback_still_honours_a_higher_floor() {
        let cfg = HostConfig {
            severity_on_failure: Severity::Moderate,
            ..Default::default()
        };
        let f = fallback(
            &req(),
            Severity::Critical,
            &cfg,
            &PackFailure::Timeout(cfg.timeout),
        );
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn namespaces_match_on_the_prefix_not_the_whole_verb() {
        let r = ClassifyResponse::new("sql.dml.delete", Severity::High);
        assert!(validate(r, &req()).is_ok());
    }
}
