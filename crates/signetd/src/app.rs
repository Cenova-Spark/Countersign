//! The app as a device: `--device=app`.
//!
//! The Mac app connects to the control socket like any client and then
//! **attaches** — `device.attach` with its enclave public key. From then on
//! the connection is a screen: the daemon pushes `device.present` down it and
//! waits for a signature to come back up, exactly as it would wait on a cable.
//!
//! Three things carry over from the relay device unchanged, because the
//! transport being local does not make the far end trusted:
//!
//! * **The signature is checked before it is believed** — against the key the
//!   app attached with, over the digest this daemon computed, with a counter
//!   ahead of every counter already accepted from that key. A mismatch is an
//!   abort, never a warning.
//! * **The key must be enrolled before it may approve.** An attached but
//!   unenrolled app is shown exactly one thing: the enrollment ceremony
//!   (`signetd enroll`). Approvals wait until the roster says whose key it is.
//! * **Nothing here decides what the class is.** The app claims `enclave`; the
//!   record the operator enrolls says `enclave`; a verifier reads the record.
//!   Device-class spec §4 — the class is never taken from the signer.
//!
//! What this device cannot check is that the key really lives in a Secure
//! Enclave. That is the claim `enclave` makes and the app's obligation
//! (device-class spec §3.1); attestation that would let a daemon confirm it is
//! reserved, not specified.

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use countersign_verify::encoding::{b64url_decode, hex_decode, hex_encode};
use countersign_verify::{is_low_s, signing_payload, DeviceClass};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::device::{Cancel, Device, DeviceInfo, DeviceOutcome, Presentation};
use crate::roster::LocalRoster;

/// What an app sends to become a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachRequest {
    /// Lowercase hex SHA-256 of `public_key_hex`'s bytes. Recomputed here.
    pub device_id: String,
    /// SEC1 uncompressed, lowercase hex.
    pub public_key_hex: String,
    /// A name a human recognises in a list of their devices.
    #[serde(default)]
    pub name: String,
    /// The class the app claims. Only `enclave` is accepted from an app; a
    /// software key is not a device (device-class spec §2).
    #[serde(default = "default_class")]
    pub class: DeviceClass,
}

fn default_class() -> DeviceClass {
    DeviceClass::Enclave
}

/// What the app hears back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachResponse {
    pub attached: bool,
    pub device_id: String,
    /// Whether the roster already knows this key. `false` means the only thing
    /// this connection will be shown is the enrollment ceremony.
    pub enrolled: bool,
    pub hint: String,
}

/// What the app answers a `device.present` with.
#[derive(Debug, Clone, Deserialize)]
struct PresentResult {
    outcome: String,
    #[serde(default)]
    signature: Option<SignedOutcome>,
}

#[derive(Debug, Clone, Deserialize)]
struct SignedOutcome {
    device_id: String,
    counter: u64,
    device_unix_ms: u64,
    signature: String,
    #[serde(default)]
    dwell_ms: Option<u64>,
}

/// One attached app connection.
pub struct Attached {
    pub connection: u64,
    pub device_id: String,
    pub name: String,
    pub public_key: Vec<u8>,
    verifying: VerifyingKey,
    writer: Mutex<UnixStream>,
    /// The call in flight, if any: its JSON-RPC id and where the answer goes.
    pending: Mutex<Option<(u64, Sender<Value>)>>,
}

impl std::fmt::Debug for Attached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attached")
            .field("connection", &self.connection)
            .field("device_id", &self.device_id)
            .field("name", &self.name)
            .finish()
    }
}

/// Everything attached right now, plus what is needed to believe them.
///
/// Shared between the control socket, which registers connections and routes
/// their answers, and [`AppDevice`], which the daemon presents to. Deliberately
/// **not** behind the daemon's own mutex: the daemon holds that across a whole
/// human decision, and the connection thread that delivers the human's answer
/// must not need it.
#[derive(Debug)]
pub struct AppDevices {
    attached: Mutex<Vec<Arc<Attached>>>,
    roster: Arc<Mutex<LocalRoster>>,
    /// Highest counter accepted per device — the daemon's own replay defence,
    /// persisted so a restart does not reopen the window.
    counters: Mutex<HashMap<String, u64>>,
    counters_path: Option<PathBuf>,
    next_rpc_id: AtomicU64,
}

impl AppDevices {
    pub fn new(roster: Arc<Mutex<LocalRoster>>) -> Self {
        Self {
            attached: Mutex::new(Vec::new()),
            roster,
            counters: Mutex::new(HashMap::new()),
            counters_path: None,
            next_rpc_id: AtomicU64::new(1),
        }
    }

    /// Remember accepted counters across restarts, in `path`.
    pub fn with_counter_file(mut self, path: &Path) -> Self {
        let loaded: HashMap<String, u64> = std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        self.counters = Mutex::new(loaded);
        self.counters_path = Some(path.to_path_buf());
        self
    }

    pub fn roster(&self) -> &Arc<Mutex<LocalRoster>> {
        &self.roster
    }

    /// Register a connection as a device.
    ///
    /// Checks what can be checked from here: the id derives from the key, the
    /// key is a P-256 point, the class is one an app may claim. Whether the
    /// key is *enrolled* is reported, not enforced — enrolling is what an
    /// unenrolled attachment is for.
    pub fn attach(
        &self,
        connection: u64,
        stream: UnixStream,
        request: AttachRequest,
    ) -> Result<(AttachResponse, Arc<Attached>), String> {
        if request.class != DeviceClass::Enclave {
            return Err(format!(
                "an app may attach as class enclave only, not {}; a software key is not a device",
                request.class
            ));
        }
        let public_key = hex_decode(&request.public_key_hex)
            .map_err(|_| "public_key_hex is not hex".to_string())?;
        if public_key.len() != 65 || public_key[0] != 0x04 {
            return Err(
                "public_key_hex must be the 65-byte SEC1 uncompressed encoding (0x04 || X || Y)"
                    .into(),
            );
        }
        let verifying = VerifyingKey::from_sec1_bytes(&public_key)
            .map_err(|_| "public key is not a point on P-256".to_string())?;
        let derived = hex_encode(&Sha256::digest(&public_key));
        if derived != request.device_id.to_ascii_lowercase() {
            return Err(format!(
                "device_id {} is not the digest of the key ({derived}); wire spec §4.2",
                request.device_id
            ));
        }

        let enrolled = self
            .roster
            .lock()
            .expect("roster mutex")
            .get(&derived)
            .is_some_and(|r| r.status.is_active());

        let attached = Arc::new(Attached {
            connection,
            device_id: derived.clone(),
            name: if request.name.is_empty() {
                "app".into()
            } else {
                request.name.chars().take(64).collect()
            },
            public_key,
            verifying,
            writer: Mutex::new(stream),
            pending: Mutex::new(None),
        });

        let mut list = self.attached.lock().expect("attached mutex");
        // One connection, one device. A re-attach on the same connection
        // replaces the earlier registration rather than doubling it.
        list.retain(|a| a.connection != connection);
        list.push(Arc::clone(&attached));

        let hint = if enrolled {
            format!("{} is enrolled and may approve", attached.name)
        } else {
            format!(
                "{} is attached but not enrolled. Run `signetd enroll --subject you@example.com` \
                 and hold on the app; until then it is shown nothing but that",
                attached.name
            )
        };
        Ok((
            AttachResponse {
                attached: true,
                device_id: derived,
                enrolled,
                hint,
            },
            attached,
        ))
    }

    /// The connection went away.
    pub fn detach(&self, connection: u64) {
        let mut list = self.attached.lock().expect("attached mutex");
        list.retain(|a| a.connection != connection);
        // A present in flight on that connection gets its channel dropped and
        // reads that as an abort — nobody is there to answer.
    }

    /// Route a JSON-RPC response line from an attached connection to the call
    /// waiting on it. Returns `false` if nothing was waiting for that id.
    pub fn deliver(&self, attached: &Attached, response: Value) -> bool {
        let id = response.get("id").and_then(Value::as_u64);
        let mut pending = attached.pending.lock().expect("pending mutex");
        match (&*pending, id) {
            (Some((want, _)), Some(got)) if *want == got => {
                let (_, tx) = pending.take().expect("checked above");
                tx.send(response).is_ok()
            }
            _ => false,
        }
    }

    pub fn attached(&self) -> Vec<Arc<Attached>> {
        self.attached.lock().expect("attached mutex").clone()
    }

    fn highest_counter(&self, device_id: &str) -> u64 {
        self.counters
            .lock()
            .expect("counters mutex")
            .get(device_id)
            .copied()
            .unwrap_or(0)
    }

    fn record_counter(&self, device_id: &str, counter: u64) -> Result<(), String> {
        let mut counters = self.counters.lock().expect("counters mutex");
        counters.insert(device_id.to_string(), counter);
        if let Some(path) = &self.counters_path {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let text = serde_json::to_string(&*counters).map_err(|e| e.to_string())?;
            // Fail closed: a counter that cannot be remembered is one that
            // could be replayed after the next restart.
            std::fs::write(path, text).map_err(|e| format!("cannot persist counter: {e}"))?;
        }
        Ok(())
    }

    fn send(&self, attached: &Attached, method: &str, params: Value) -> Result<u64, String> {
        let id = self.next_rpc_id.fetch_add(1, Ordering::Relaxed);
        let line = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let mut writer = attached.writer.lock().expect("writer mutex");
        writeln!(writer, "{line}").map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())?;
        Ok(id)
    }

    fn notify(&self, attached: &Attached, method: &str, params: Value) {
        let line = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        if let Ok(mut writer) = attached.writer.lock() {
            let _ = writeln!(writer, "{line}");
            let _ = writer.flush();
        }
    }

    /// Verify what an app handed back, against this daemon's own idea of the
    /// payload, the key the app attached with, and the counters already seen.
    fn accept(
        &self,
        attached: &Attached,
        presentation: &Presentation,
        signed: &SignedOutcome,
        enrollment: bool,
    ) -> Result<DeviceOutcome, String> {
        if signed.device_id != attached.device_id {
            return Err(format!(
                "{} answered with a signature from {}, not its own key",
                attached.name, signed.device_id
            ));
        }
        if !enrollment {
            let roster = self.roster.lock().expect("roster mutex");
            match roster.get(&attached.device_id) {
                Some(record) if record.status.is_active() => {}
                Some(_) => return Err(format!("{} is revoked", attached.name)),
                None => {
                    return Err(format!(
                        "{} is not enrolled; only the enrollment ceremony may be signed",
                        attached.name
                    ))
                }
            }
        }
        let highest = self.highest_counter(&attached.device_id);
        if signed.counter <= highest {
            return Err(format!(
                "{} returned counter {} but {highest} was already accepted — refusing as a replay",
                attached.name, signed.counter
            ));
        }
        let tbs = signing_payload(&presentation.request_digest, signed.counter, signed.device_unix_ms)
            .map_err(|e| e.to_string())?;
        let raw = b64url_decode(&signed.signature).map_err(|_| "signature is not base64url")?;
        let fixed: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| "signature is not 64 bytes".to_string())?;
        if !is_low_s(&fixed) {
            return Err("signature is high-S (wire spec §4); the app must normalize s".into());
        }
        let signature = Signature::from_slice(&fixed).map_err(|_| "malformed signature")?;
        if attached.verifying.verify(&tbs, &signature).is_err() {
            return Err(format!(
                "signature does not cover digest {}",
                presentation.request_digest
            ));
        }
        self.record_counter(&attached.device_id, signed.counter)?;
        Ok(DeviceOutcome::Approved {
            device_id: attached.device_id.clone(),
            counter: signed.counter,
            device_unix_ms: signed.device_unix_ms,
            signature: signed.signature.clone(),
            dwell_ms: signed.dwell_ms,
        })
    }
}

/// What [`Device::info`] reports when the daemon's device is the app and no
/// app is attached: a socket that answers, and nothing behind it to be shown a
/// payload. [`crate::launch`] opens Signet on exactly this.
pub const NO_APP_ATTACHED: &str = "app (none attached)";

/// The daemon's view: whatever apps are attached, as one `Device`.
pub struct AppDevice {
    apps: Arc<AppDevices>,
}

impl AppDevice {
    pub fn new(apps: Arc<AppDevices>) -> Self {
        Self { apps }
    }

    fn info_for(attached: &Attached, counter: u64) -> DeviceInfo {
        DeviceInfo {
            device_id: attached.device_id.clone(),
            kind: "app".into(),
            is_test_key: false,
            class: DeviceClass::Enclave,
            public_key_hex: hex_encode(&attached.public_key),
            counter,
        }
    }
}

impl Device for AppDevice {
    fn info(&self) -> DeviceInfo {
        match self.apps.attached().first() {
            Some(a) => Self::info_for(a, self.apps.highest_counter(&a.device_id)),
            None => DeviceInfo {
                device_id: String::new(),
                kind: NO_APP_ATTACHED.into(),
                is_test_key: false,
                class: DeviceClass::Enclave,
                public_key_hex: String::new(),
                counter: 0,
            },
        }
    }

    fn devices(&self) -> Vec<DeviceInfo> {
        self.apps
            .attached()
            .iter()
            .map(|a| Self::info_for(a, self.apps.highest_counter(&a.device_id)))
            .collect()
    }

    fn present(&mut self, presentation: &Presentation, cancel: &Cancel) -> DeviceOutcome {
        let enrollment = presentation.is_enrollment();

        // Who may be asked: for an approval, enrolled and active apps; for the
        // ceremony itself, every attached app that is *not* yet enrolled (an
        // enrolled one re-enrolling is fine too, so: every attached app).
        let candidates: Vec<Arc<Attached>> = {
            let roster = self.apps.roster.lock().expect("roster mutex");
            self.apps
                .attached()
                .into_iter()
                .filter(|a| enrollment || roster.get(&a.device_id).is_some_and(|r| r.status.is_active()))
                .collect()
        };
        if candidates.is_empty() {
            eprintln!(
                "signetd: no {} app is attached to show this to",
                if enrollment { "" } else { "enrolled " }
            );
            return DeviceOutcome::Aborted;
        }

        let (tx, rx): (Sender<(Arc<Attached>, Value)>, Receiver<_>) = mpsc::channel();
        let mut asked: Vec<Arc<Attached>> = Vec::new();
        for attached in candidates {
            let params = json!({
                "presentation": presentation,
                "arm_delay_ms": presentation.arm_delay_ms(),
                "hold_ms": presentation.hold_ms(),
                "enrollment": enrollment,
            });
            let (inner_tx, inner_rx) = mpsc::channel::<Value>();
            let id = match self.apps.send(&attached, "device.present", params) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("signetd: cannot reach {}: {e}", attached.name);
                    continue;
                }
            };
            *attached.pending.lock().expect("pending mutex") = Some((id, inner_tx));
            // Forward this app's answer onto the shared channel, tagged.
            let tx = tx.clone();
            let tagged = Arc::clone(&attached);
            std::thread::spawn(move || {
                if let Ok(value) = inner_rx.recv() {
                    let _ = tx.send((tagged, value));
                }
            });
            asked.push(attached);
        }
        drop(tx);
        if asked.is_empty() {
            return DeviceOutcome::Aborted;
        }

        let deadline = Instant::now() + Duration::from_millis(presentation.ttl_ms);
        let mut outcome = DeviceOutcome::Expired;
        let mut remaining = asked.len();
        while remaining > 0 && Instant::now() < deadline {
            if cancel.is_cancelled() {
                outcome = DeviceOutcome::Aborted;
                break;
            }
            let step = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100));
            match rx.recv_timeout(step) {
                Ok((attached, response)) => {
                    remaining -= 1;
                    let result: Option<PresentResult> = response
                        .get("result")
                        .cloned()
                        .and_then(|r| serde_json::from_value(r).ok());
                    match result {
                        Some(PresentResult {
                            outcome: ref o,
                            signature: Some(ref signed),
                        }) if o == "approved" => {
                            match self.apps.accept(&attached, presentation, signed, enrollment) {
                                Ok(approved) => {
                                    outcome = approved;
                                    break;
                                }
                                Err(why) => {
                                    eprintln!("signetd: refusing {}'s signature: {why}", attached.name);
                                    outcome = DeviceOutcome::Aborted;
                                }
                            }
                        }
                        Some(PresentResult { outcome: ref o, .. }) if o == "expired" => {
                            if outcome != DeviceOutcome::Aborted {
                                outcome = DeviceOutcome::Expired;
                            }
                        }
                        // "aborted", an approval with no signature, an error,
                        // or something unrecognised: not an approval.
                        _ => outcome = DeviceOutcome::Aborted,
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    outcome = DeviceOutcome::Aborted;
                    break;
                }
            }
        }

        // Whatever happened, nothing else is being asked about this payload
        // any more. Tell every app that has not answered so it takes the
        // screen down, and forget its pending call.
        for attached in &asked {
            let mut pending = attached.pending.lock().expect("pending mutex");
            if pending.take().is_some() {
                drop(pending);
                self.apps.notify(
                    attached,
                    "device.withdraw",
                    json!({ "request_digest": presentation.request_digest }),
                );
            }
        }
        outcome
    }
}
