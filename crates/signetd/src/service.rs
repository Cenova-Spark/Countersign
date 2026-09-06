//! The control socket: one daemon, many clients.
//!
//! Claude Code spawns an MCP server per client — terminal, VS Code, and the
//! desktop app are three separate processes. Only one process can own a device,
//! so the daemon is long-lived and each of those spawns a thin bridge that
//! talks to it here.
//!
//! Framing is line-delimited JSON-RPC 2.0, the same shape the pack protocol
//! uses, because there is no reason for a reader of this codebase to learn two.
//!
//! # Localhost is not an authorization boundary
//!
//! The socket lives in the user's runtime directory with `0700` on the
//! directory and `0600` on the socket, so the filesystem is the access control.
//! Anything that can open it can request approvals — which is bounded by the
//! fact that every approval still needs a physical actuation, and the device
//! displays who asked.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::app::{AppDevices, AttachRequest, AttachResponse, Attached};
use crate::daemon::{ApprovalRequest, ApprovalResponse, Daemon, Origin, OriginKind};
use countersign_verify::EnrollmentRecord;

/// Methods the control socket accepts.
pub mod method {
    pub const APPROVAL_REQUEST: &str = "approval.request";
    pub const DEVICE_STATUS: &str = "device.status";
    pub const AUDIT_SUMMARY: &str = "audit.summary";
    pub const PING: &str = "ping";
    /// An app becomes a device on this connection. See `crate::app`.
    pub const DEVICE_ATTACH: &str = "device.attach";
    /// Run the enrollment ceremony on the attached device.
    pub const DEVICE_ENROLL: &str = "device.enroll";
    /// Pushed **to** an attached app: show this, and answer.
    pub const DEVICE_PRESENT: &str = "device.present";
    /// Pushed to an attached app: take it down, somebody else answered.
    pub const DEVICE_WITHDRAW: &str = "device.withdraw";
}

/// What `device.enroll` takes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStatus {
    pub attached: bool,
    pub device_id: String,
    pub kind: String,
    pub is_test_key: bool,
    pub counter: u64,
    pub environments: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub entries: usize,
    pub head: String,
}

/// The default socket a forwarded tunnel should land on.
pub fn forward_socket_path() -> PathBuf {
    if let Ok(explicit) = std::env::var("COUNTERSIGN_FORWARD_SOCK") {
        return PathBuf::from(explicit);
    }
    crate::daemon::runtime_dir().join("countersign-forward.sock")
}

/// The default socket path.
pub fn socket_path() -> PathBuf {
    if let Ok(explicit) = std::env::var("COUNTERSIGN_SOCK") {
        return PathBuf::from(explicit);
    }
    crate::daemon::runtime_dir().join("countersign.sock")
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// The longest a unix socket path may be.
///
/// `sun_path` is 104 bytes on macOS and 108 on Linux, and the kernel error for
/// exceeding it ("path must be shorter than SUN_LEN") explains nothing to
/// someone whose only mistake was a long home directory. Checked here so the
/// message can name the fix.
const MAX_SOCKET_PATH: usize = 100;

fn check_socket_path(path: &Path) -> std::io::Result<()> {
    if path.as_os_str().len() > MAX_SOCKET_PATH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "socket path is {} bytes, and the operating system allows at most {}:\n  {}\n\
                 Set COUNTERSIGN_SOCK to something shorter, e.g. /tmp/countersign-$USER.sock",
                path.as_os_str().len(),
                MAX_SOCKET_PATH,
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Serve the control socket, and optionally a second socket for forwarding,
/// until the process is killed.
///
/// Two listeners rather than one, because SSH `RemoteForward` connects back to
/// a local socket and the daemon otherwise cannot tell a tunnelled request from
/// a local one — they arrive identically. Giving forwarding its own socket is
/// what makes "this came from somewhere you are not sitting" a fact the daemon
/// knows rather than a guess.
pub fn serve(
    daemon: Daemon,
    path: &Path,
    forward_path: Option<&Path>,
    apps: Option<Arc<AppDevices>>,
) -> std::io::Result<()> {
    check_socket_path(path)?;

    let listener = bind_socket(path)?;
    let daemon = Arc::new(Mutex::new(daemon));

    // Every accepted connection gets an id the peer cannot choose and cannot
    // obtain from another peer. It is the only thing about a requester that
    // this daemon can actually verify, so the continuity check keys on it
    // rather than on anything the request claims about itself.
    //
    // Shared across both listeners, so a local and a forwarded client can never
    // collide on an id and look like each other.
    let connections = Arc::new(AtomicU64::new(1));

    if let Some(forward_path) = forward_path {
        check_socket_path(forward_path)?;
        let forward = bind_socket(forward_path)?;
        let daemon = Arc::clone(&daemon);
        let connections = Arc::clone(&connections);
        // Apps attach on the local socket only. A device reached through a
        // tunnel is a relay's job, with a relay's checks.
        std::thread::spawn(move || {
            accept_loop(forward, daemon, connections, OriginKind::Forwarded, None);
        });
    }

    accept_loop(listener, daemon, connections, OriginKind::Local, apps);
    Ok(())
}

fn bind_socket(path: &Path) -> std::io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        // The directory is the access control, so tighten it before the socket
        // exists rather than after.
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }

    // A socket left behind by a killed daemon would block binding. Removing it
    // is safe only because the directory is user-private.
    if path.exists() {
        if UnixStream::connect(path).is_ok() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("a signetd is already listening on {}", path.display()),
            ));
        }
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn accept_loop(
    listener: UnixListener,
    daemon: Arc<Mutex<Daemon>>,
    connections: Arc<AtomicU64>,
    kind: OriginKind,
    apps: Option<Arc<AppDevices>>,
) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("signetd: accept failed: {e}");
                continue;
            }
        };
        let daemon = Arc::clone(&daemon);
        let apps = apps.clone();
        let id = connections.fetch_add(1, Ordering::Relaxed);
        let origin = match kind {
            OriginKind::Local => Origin::new(id),
            OriginKind::Forwarded => Origin::forwarded(id),
        };
        std::thread::spawn(move || {
            if let Err(e) = handle_connection(stream, daemon, origin, apps) {
                eprintln!("signetd: connection ended: {e}");
            }
        });
    }
}

fn handle_connection(
    stream: UnixStream,
    daemon: Arc<Mutex<Daemon>>,
    origin: Origin,
    apps: Option<Arc<AppDevices>>,
) -> std::io::Result<()> {
    let reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream.try_clone()?;
    // Once this connection attaches as a device, its lines are mostly
    // *answers* to things the daemon pushed, and they go to whoever is waiting.
    let mut attached: Option<Arc<Attached>> = None;

    let result = (|| -> std::io::Result<()> {
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let parsed: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    let response = rpc_error(Value::Null, -32700, &e.to_string());
                    writeln!(writer, "{}", serde_json::to_string(&response)?)?;
                    writer.flush()?;
                    continue;
                }
            };

            // A response — no method — from an attached app is the human's
            // answer to a `device.present`. Route it; do not answer it.
            if parsed.get("method").is_none() {
                if let (Some(apps), Some(att)) = (&apps, &attached) {
                    if !apps.deliver(att, parsed) {
                        eprintln!("signetd: {} answered a call nobody was waiting on", att.name);
                    }
                }
                continue;
            }

            let response = if parsed.get("method").and_then(Value::as_str)
                == Some(method::DEVICE_ATTACH)
            {
                attach(&parsed, &stream, origin, apps.as_ref(), &mut attached)
            } else {
                dispatch(parsed, &daemon, origin)
            };
            writeln!(writer, "{}", serde_json::to_string(&response)?)?;
            writer.flush()?;
        }
        Ok(())
    })();

    if let (Some(apps), Some(_)) = (&apps, &attached) {
        apps.detach(origin.connection);
    }
    result
}

/// `device.attach`, which needs the raw stream (to push down later) and so
/// cannot go through `dispatch`.
fn attach(
    request: &Value,
    stream: &UnixStream,
    origin: Origin,
    apps: Option<&Arc<AppDevices>>,
    attached: &mut Option<Arc<Attached>>,
) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let Some(apps) = apps else {
        return rpc_error(
            id,
            -32000,
            "this daemon is not running with --device=app, so nothing can attach",
        );
    };
    if origin.kind != OriginKind::Local {
        return rpc_error(id, -32000, "a device attaches on the local socket only");
    }
    let params: AttachRequest = match serde_json::from_value(
        request.get("params").cloned().unwrap_or(Value::Null),
    ) {
        Ok(p) => p,
        Err(e) => return rpc_error(id, -32602, &e.to_string()),
    };
    let stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => return rpc_error(id, -32000, &e.to_string()),
    };
    match apps.attach(origin.connection, stream, params) {
        Ok((response, att)) => {
            eprintln!(
                "signetd: {} attached as an enclave device ({}){}",
                att.name,
                &att.device_id[..12],
                if response.enrolled { "" } else { " — not yet enrolled" }
            );
            *attached = Some(att);
            rpc_ok(id, serde_json::to_value(response).unwrap_or(Value::Null))
        }
        Err(e) => rpc_error(id, -32602, &e),
    }
}

fn dispatch(request: Value, daemon: &Arc<Mutex<Daemon>>, origin: Origin) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let params = request.get("params").cloned().unwrap_or(Value::Null);

    match method {
        method::PING => rpc_ok(id, json!({ "pong": true })),

        method::DEVICE_ENROLL => {
            if origin.kind != OriginKind::Local {
                return rpc_error(id, -32000, "enrollment is run from this machine, not through a tunnel");
            }
            let request: EnrollRequest = match serde_json::from_value(params) {
                Ok(r) => r,
                Err(e) => return rpc_error(id, -32602, &e.to_string()),
            };
            // Held across the ceremony, like any presentation.
            let mut guard = daemon.lock().expect("daemon mutex");
            match guard.enroll(&request.subject, request.display.as_deref()) {
                Ok(record) => rpc_ok(id, serde_json::to_value(record).unwrap_or(Value::Null)),
                Err(e) => rpc_error(id, -32000, &e.to_string()),
            }
        }

        method::DEVICE_STATUS => {
            // Held only long enough to read; an approval in flight elsewhere
            // would otherwise make a status call hang behind a human.
            let guard = daemon.lock().expect("daemon mutex");
            let info = guard.device_info();
            rpc_ok(
                id,
                json!(DeviceStatus {
                    attached: true,
                    device_id: info.device_id,
                    kind: info.kind,
                    is_test_key: info.is_test_key,
                    counter: info.counter,
                    environments: guard.config().environments.len(),
                }),
            )
        }

        method::AUDIT_SUMMARY => {
            let guard = daemon.lock().expect("daemon mutex");
            let head = guard.audit().log().head().unwrap_or_default();
            rpc_ok(
                id,
                json!(AuditSummary {
                    entries: guard.audit().len(),
                    head
                }),
            )
        }

        method::APPROVAL_REQUEST => {
            let request: ApprovalRequest = match serde_json::from_value(params) {
                Ok(r) => r,
                Err(e) => return rpc_error(id, -32602, &e.to_string()),
            };
            // This lock is held across the human's decision on purpose: one
            // active request on the device at a time is a protocol requirement,
            // not a limitation. A second agent waits.
            let mut guard = daemon.lock().expect("daemon mutex");
            match guard.handle(&request, origin) {
                Ok(response) => rpc_ok(id, serde_json::to_value(response).unwrap_or(Value::Null)),
                Err(e) => rpc_error(id, -32000, &e.to_string()),
            }
        }

        other => rpc_error(id, -32601, &format!("unknown method {other:?}")),
    }
}

fn rpc_ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A connection to a running daemon.
#[derive(Debug)]
pub struct Client {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next_id: u64,
}

impl Client {
    pub fn connect(path: &Path) -> Result<Self, ClientError> {
        check_socket_path(path).map_err(|e| ClientError::Connect {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
        let stream = UnixStream::connect(path).map_err(|e| ClientError::Connect {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
        Ok(Self {
            reader: BufReader::new(
                stream
                    .try_clone()
                    .map_err(|e| ClientError::Io(e.to_string()))?,
            ),
            writer: stream,
            next_id: 1,
        })
    }

    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, ClientError> {
        let id = self.next_id;
        self.next_id += 1;

        let request = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        writeln!(self.writer, "{request}").map_err(|e| ClientError::Io(e.to_string()))?;
        self.writer
            .flush()
            .map_err(|e| ClientError::Io(e.to_string()))?;

        let mut line = String::new();
        let read = self
            .reader
            .read_line(&mut line)
            .map_err(|e| ClientError::Io(e.to_string()))?;
        if read == 0 {
            return Err(ClientError::Io("daemon closed the connection".into()));
        }

        let response: Value =
            serde_json::from_str(&line).map_err(|e| ClientError::Io(e.to_string()))?;
        if let Some(error) = response.get("error") {
            return Err(ClientError::Daemon(
                error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error")
                    .to_string(),
            ));
        }
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    }

    pub fn request_approval(
        &mut self,
        request: &ApprovalRequest,
    ) -> Result<ApprovalResponse, ClientError> {
        let value = self.call(
            method::APPROVAL_REQUEST,
            serde_json::to_value(request).map_err(|e| ClientError::Io(e.to_string()))?,
        )?;
        serde_json::from_value(value).map_err(|e| ClientError::Io(e.to_string()))
    }

    pub fn device_status(&mut self) -> Result<DeviceStatus, ClientError> {
        let value = self.call(method::DEVICE_STATUS, Value::Null)?;
        serde_json::from_value(value).map_err(|e| ClientError::Io(e.to_string()))
    }

    pub fn audit_summary(&mut self) -> Result<AuditSummary, ClientError> {
        let value = self.call(method::AUDIT_SUMMARY, Value::Null)?;
        serde_json::from_value(value).map_err(|e| ClientError::Io(e.to_string()))
    }

    /// Run the enrollment ceremony on the daemon's device. Blocks for it.
    pub fn enroll(&mut self, subject: &str, display: Option<&str>) -> Result<EnrollmentRecord, ClientError> {
        let value = self.call(
            method::DEVICE_ENROLL,
            serde_json::to_value(EnrollRequest {
                subject: subject.to_string(),
                display: display.map(str::to_string),
            })
            .map_err(|e| ClientError::Io(e.to_string()))?,
        )?;
        serde_json::from_value(value).map_err(|e| ClientError::Io(e.to_string()))
    }

    /// Attach this connection as a device. What an app calls once, then keeps
    /// the connection open to be presented to.
    pub fn attach(&mut self, request: &AttachRequest) -> Result<AttachResponse, ClientError> {
        let value = self.call(
            method::DEVICE_ATTACH,
            serde_json::to_value(request).map_err(|e| ClientError::Io(e.to_string()))?,
        )?;
        serde_json::from_value(value).map_err(|e| ClientError::Io(e.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    Connect { path: PathBuf, message: String },
    Io(String),
    Daemon(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Connect { path, message } => write!(
                f,
                "cannot reach signetd at {} ({message}) — is it running? try `signetd run`",
                path.display()
            ),
            ClientError::Io(e) => write!(f, "{e}"),
            ClientError::Daemon(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ClientError {}
