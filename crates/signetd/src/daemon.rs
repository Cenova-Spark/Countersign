//! The daemon: request in, decision out, audit entry written.
//!
//! The order of operations here is the security design, so it is worth reading
//! as a sequence:
//!
//! 1. **Classify the target from local config.** The requester never supplied a
//!    label and cannot; this is the one thing it does not get to claim.
//! 2. **Compute a severity floor from the tier**, before any pack runs.
//! 3. **Ask the pack**, and take the maximum of its answer and the floor. A
//!    pack raises; it never lowers.
//! 4. **Evaluate policy** on the refined action, the tier, and the severity.
//! 5. **Present to the device** — with the label and digest lines written by
//!    the daemon, not by the pack.
//! 6. **Record the outcome**, approved or not.
//!
//! Step 6 covers refusals and aborts too. A trail that only recorded successes
//! would not answer "did anything try to drop that table last week?", which is
//! the question an incident actually starts with.

use std::path::PathBuf;

use countersign_audit::NewEntry;
use countersign_pack::{
    Classified, ClassifyRequest, PackHost, RenderLine, RenderRole, Severity, TargetRef,
};
use countersign_verify::{
    digest_display, encoding::b64url_encode, fingerprint_uri, ApprovalEnvelope, Bundle, Decision,
    Request, Requester, VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::{AuditStore, StoreError};
use crate::config::Config;
use crate::device::{now_unix_ms, Device, DeviceOutcome, Presentation};
use crate::policy::{self, Evaluation, Outcome};

/// What a client asks for.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApprovalRequest {
    /// A namespaced verb. Refined by a pack where one claims the namespace.
    pub action: String,
    /// The connection URI.
    ///
    /// Fingerprinted on arrival and then **dropped**. It is never stored, never
    /// logged, and never written to the audit trail — see
    /// [`Daemon::fingerprint_of`]. Clients that can compute the fingerprint
    /// themselves should send `uri_fingerprint` instead and keep the credential
    /// on their own side of the socket entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri_fingerprint: Option<String>,
    #[serde(default = "default_target_kind")]
    pub target_kind: String,
    pub statement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory: Option<Value>,
    #[serde(default = "default_requester_id")]
    pub requester_id: String,
    #[serde(default)]
    pub requester_instance: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_ms: Option<u64>,
}

fn default_target_kind() -> String {
    "database".into()
}

fn default_requester_id() -> String {
    "unknown".into()
}

/// What the daemon answers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResponse {
    pub decision: Decision,
    pub request_digest: String,
    /// The first 12 hex characters, grouped — the client MUST show these, and
    /// they must match what the device displayed.
    pub digest_short: String,
    pub environment: String,
    pub tier: String,
    pub severity: String,
    /// Why this happened, in one line an operator can read.
    pub explanation: String,
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Present only on `approved`. Hand this, whole, to a verifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope: Option<ApprovalEnvelope>,
}

/// Where a request came from, as far as the daemon can actually tell.
///
/// `connection` is assigned by the daemon when it accepted the socket, so a
/// process cannot choose it and cannot obtain another process's. Everything
/// else a requester says about itself is a claim (spec §2.1) and is displayed
/// as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Origin {
    pub connection: u64,
}

impl Origin {
    pub fn new(connection: u64) -> Self {
        Self { connection }
    }
}

/// The requester the device was last shown.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LastPresented {
    connection: u64,
    claimed_id: String,
}

pub struct Daemon {
    config: Config,
    device: Box<dyn Device>,
    packs: Vec<PackHost>,
    audit: AuditStore,
    /// Who the human last approved something for.
    ///
    /// The continuity check hangs off this: when the requester changes, the
    /// rhythm the operator has built is no longer about the thing in front of
    /// them, and they are made to say so before the dial will accept anything.
    last_presented: Option<LastPresented>,
}

impl Daemon {
    pub fn new(
        config: Config,
        device: Box<dyn Device>,
        packs: Vec<PackHost>,
        audit: AuditStore,
    ) -> Self {
        Self {
            config,
            device,
            packs,
            audit,
            last_presented: None,
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn audit(&self) -> &AuditStore {
        &self.audit
    }

    pub fn device_info(&self) -> crate::device::DeviceInfo {
        self.device.info()
    }

    /// Fingerprint a target, accepting either a URI or a precomputed digest.
    ///
    /// When a URI arrives it is hashed here and the original is dropped on the
    /// floor — nothing downstream of this function ever sees it, which is what
    /// keeps a password out of the audit trail even when a careless client
    /// sends one.
    pub fn fingerprint_of(request: &ApprovalRequest) -> Option<String> {
        if let Some(fp) = &request.uri_fingerprint {
            return Some(fp.to_ascii_lowercase());
        }
        request.target_uri.as_deref().map(fingerprint_uri)
    }

    /// Handle one approval request end to end.
    pub fn handle(
        &mut self,
        request: &ApprovalRequest,
        origin: Origin,
    ) -> Result<ApprovalResponse, DaemonError> {
        let Some(fingerprint) = Self::fingerprint_of(request) else {
            return Err(DaemonError::NoTarget);
        };

        // 1. The label the requester does not get to claim.
        let class = self.config.classify(&fingerprint);

        // 2 & 3. Floor from the tier, then the pack, never below the floor.
        let floor = class.tier.severity_floor();
        let classified = self.classify_with_pack(request, &fingerprint, floor);
        let severity = policy::effective_severity(class.tier, classified.response.severity);
        let refined_action = classified.response.action.clone();

        let mut warnings = classified.response.warnings.clone();
        if let Some(failure) = &classified.failure {
            warnings.push(format!("classification degraded: {failure}"));
        }
        if !class.known {
            warnings.push(format!(
                "target {} matches no configured environment, so it is treated as {}",
                &fingerprint[..12],
                class.tier.as_str()
            ));
        }

        // 4. Policy.
        let decision = policy::evaluate(
            &self.config,
            &class,
            &Evaluation {
                action: &refined_action,
                requester_id: &request.requester_id,
                severity,
                device_attached: true,
            },
        );

        // Build the signable request now: its digest is what the device shows
        // and what a verifier later recomputes.
        let wire = Request {
            v: VERSION,
            nonce: new_nonce(),
            requester: Requester {
                id: request.requester_id.clone(),
                instance: request.requester_instance.clone(),
                pid: None,
            },
            action: refined_action.clone(),
            target: countersign_verify::Target {
                kind: request.target_kind.clone(),
                uri_fingerprint: fingerprint.clone(),
            },
            statement: request.statement.clone(),
            advisory: request.advisory.clone(),
            ttl_ms: request.ttl_ms.unwrap_or(60_000),
        };
        let request_json =
            serde_json::to_string(&wire).map_err(|e| DaemonError::Internal(e.to_string()))?;
        let request_digest =
            countersign_verify::digest_of_json(&request_json).map_err(DaemonError::Jcs)?;
        let digest_short = digest_display(&request_digest);

        let (outcome, envelope) = match decision.outcome {
            Outcome::Deny { .. } => (Decision::Refused, None),
            Outcome::AutoApprove => (Decision::Approved, None),
            Outcome::RequireApproval => {
                // Has the thing asking changed since the last time a human
                // acted? A different connection is a different process, and
                // that is the discontinuity worth interrupting for.
                let requester_changed = self
                    .last_presented
                    .as_ref()
                    .is_none_or(|last| last.connection != origin.connection);

                let presentation = Presentation {
                    render: self.render_lines(
                        &class.label,
                        &classified,
                        &request.statement,
                        &digest_short,
                    ),
                    request_digest: request_digest.clone(),
                    digest_short: digest_short.clone(),
                    severity,
                    requester: describe_requester(request, &self.last_presented),
                    requester_changed,
                    ttl_ms: wire.ttl_ms,
                };

                // Recorded before the outcome, not after: the operator was
                // shown this requester whatever they then decided, and the
                // next request should be judged against what they actually
                // saw.
                self.last_presented = Some(LastPresented {
                    connection: origin.connection,
                    claimed_id: request.requester_id.clone(),
                });

                match self.device.present(&presentation) {
                    DeviceOutcome::Approved {
                        counter,
                        device_unix_ms,
                        signature,
                        dwell_ms,
                    } => {
                        let bundle = Bundle {
                            v: VERSION,
                            decision: Decision::Approved,
                            request_digest: request_digest.clone(),
                            signatures: vec![countersign_verify::DeviceSignature {
                                device_id: self.device.info().device_id,
                                counter,
                                device_unix_ms,
                                signature,
                                dwell_ms,
                            }],
                        };
                        (
                            Decision::Approved,
                            Some(ApprovalEnvelope {
                                request_json: request_json.clone(),
                                bundle,
                            }),
                        )
                    }
                    DeviceOutcome::Aborted => (Decision::Aborted, None),
                    DeviceOutcome::Expired => (Decision::Expired, None),
                }
            }
        };

        // 6. Record it, whatever happened.
        self.audit.append(NewEntry {
            at_unix_ms: now_unix_ms(),
            action: refined_action,
            target_kind: request.target_kind.clone(),
            target_fingerprint: fingerprint,
            environment_label: class.label.clone(),
            request_json,
            decision: outcome,
            severity: Some(severity.as_str().to_string()),
            signatures: envelope
                .as_ref()
                .map(|e| e.bundle.signatures.clone())
                .unwrap_or_default(),
        })?;

        Ok(ApprovalResponse {
            decision: outcome,
            request_digest,
            digest_short,
            environment: class.label,
            tier: class.tier.as_str().to_string(),
            severity: severity.as_str().to_string(),
            explanation: decision.explanation,
            warnings,
            envelope,
        })
    }

    /// Ask whichever pack claims this namespace.
    ///
    /// With no pack for the namespace, the statement is shown verbatim at the
    /// tier floor. That is honest rather than convenient: nothing classified
    /// it, so nothing may claim it is mild.
    fn classify_with_pack(
        &mut self,
        request: &ApprovalRequest,
        fingerprint: &str,
        floor: Severity,
    ) -> Classified {
        let classify = ClassifyRequest {
            action: request.action.clone(),
            statement: request.statement.clone(),
            target: Some(TargetRef {
                kind: request.target_kind.clone(),
                uri_fingerprint: fingerprint.to_string(),
            }),
            hints: None,
        };

        if let Some(pack) = self.packs.iter_mut().find(|p| p.handles(&request.action)) {
            return pack.classify(&classify, floor);
        }

        Classified {
            response: countersign_pack::ClassifyResponse {
                action: request.action.clone(),
                severity: floor,
                reversible: None,
                render: vec![RenderLine::primary(request.statement.clone())],
                advisory: None,
                warnings: vec![format!(
                    "no pack claims {:?}; the statement was not classified",
                    countersign_pack::namespace_of(&request.action)
                )],
            },
            failure: None,
        }
    }

    /// Assemble the screen.
    ///
    /// The daemon writes the first line and the last one. A pack supplies only
    /// `primary` and `advisory` content, and anything else it tried to send was
    /// already rejected by the host — but this function is where the label and
    /// digest actually come from, and they come from here precisely so a pack
    /// cannot put `local` above a production `DROP`.
    fn render_lines(
        &self,
        label: &str,
        classified: &Classified,
        statement: &str,
        digest_short: &str,
    ) -> Vec<RenderLine> {
        let mut lines = vec![RenderLine {
            role: RenderRole::Label,
            text: label.to_string(),
        }];

        let body: Vec<RenderLine> = classified
            .response
            .render
            .iter()
            .filter(|l| l.role.pack_may_emit())
            .cloned()
            .collect();

        if body.is_empty() {
            lines.push(RenderLine::primary(statement.to_string()));
        } else {
            lines.extend(body);
        }

        if self.device.info().is_test_key {
            lines.push(RenderLine::advisory("TEST KEY — not a real approval"));
        }

        lines.push(RenderLine {
            role: RenderRole::Digest,
            text: digest_short.to_string(),
        });
        lines
    }
}

/// The requester line the device shows.
///
/// The claimed id and instance are exactly that — claims — so they are labelled
/// as unverified. What is *not* a claim is that this is a different connection
/// from the last one, and that is the part the acknowledgement is keyed on.
fn describe_requester(
    request: &ApprovalRequest,
    last: &Option<LastPresented>,
) -> String {
    let claimed = if request.requester_instance.is_empty() {
        request.requester_id.clone()
    } else {
        format!("{} · {}", request.requester_id, request.requester_instance)
    };

    match last {
        Some(previous) => format!("{claimed} (claimed) — previously {}", previous.claimed_id),
        None => format!("{claimed} (claimed)"),
    }
}

/// 32 CSPRNG bytes, base64url unpadded.
///
/// Generated here rather than accepted from the requester. The wire format
/// allows a client-supplied nonce, but a daemon that mints its own cannot be
/// handed a reused one, and nothing is lost by being stricter.
fn new_nonce() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the OS must provide randomness");
    b64url_encode(&bytes)
}

#[derive(Debug)]
pub enum DaemonError {
    /// Neither a URI nor a fingerprint was supplied.
    NoTarget,
    Store(StoreError),
    Jcs(countersign_verify::JcsError),
    Internal(String),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonError::NoTarget => {
                f.write_str("request supplied neither target_uri nor uri_fingerprint")
            }
            DaemonError::Store(e) => write!(f, "{e}"),
            DaemonError::Jcs(e) => write!(f, "{e}"),
            DaemonError::Internal(e) => write!(f, "internal error: {e}"),
        }
    }
}

impl std::error::Error for DaemonError {}

impl From<StoreError> for DaemonError {
    fn from(e: StoreError) -> Self {
        DaemonError::Store(e)
    }
}

pub fn runtime_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("COUNTERSIGN_RUNTIME_DIR") {
        return PathBuf::from(dir);
    }
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join("countersign");
    }
    crate::config::config_dir().join("run")
}
