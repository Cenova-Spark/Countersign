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
    digest_display, encoding::b64url_encode, enrollment_statement, fingerprint_uri,
    ApprovalEnvelope, Bundle, Decision, EnrollmentRecord, Operator, Request, Requester,
    ENROLLMENT_ACTION, VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::sync::{Arc, Mutex};
use serde_json::Value;

use crate::audit::{AuditStore, StoreError};
use crate::config::Config;
use crate::device::{now_unix_ms, Cancel, Device, DeviceOutcome, Presentation};
use crate::roster::LocalRoster;
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

/// Which socket a request arrived on.
///
/// A forwarded socket is a delegation: anything on the far side of an SSH
/// tunnel can ask, not just the person who opened it. The blast radius is
/// bounded — every approval still needs a physical turn over a displayed
/// payload — but the display becomes the whole defence, so the daemon has to
/// know which side a request came from in order to say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OriginKind {
    /// A client on this machine.
    Local,
    /// Reached us through a forwarded socket — typically SSH `RemoteForward`.
    Forwarded,
}

impl OriginKind {
    pub fn as_str(self) -> &'static str {
        match self {
            OriginKind::Local => "local",
            OriginKind::Forwarded => "forwarded",
        }
    }
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
    pub kind: OriginKind,
}

impl Origin {
    pub fn new(connection: u64) -> Self {
        Self {
            connection,
            kind: OriginKind::Local,
        }
    }

    pub fn forwarded(connection: u64) -> Self {
        Self {
            connection,
            kind: OriginKind::Forwarded,
        }
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
    /// Namespace → pack name, for packs that are installed and switched off.
    ///
    /// A request in one of these is refused without a human being asked. Not
    /// shown verbatim at the tier floor, which is what a namespace *nobody*
    /// claims gets: here somebody claims it and the operator turned them off,
    /// and "off" has to mean the dial stays dark. See `crate::packs`.
    off_namespaces: std::collections::BTreeMap<String, String>,
    /// The operator's own devices, and where to write them. `None` for the
    /// path means in-memory only — tests, and daemons that were never asked
    /// to enroll anything.
    roster: Arc<Mutex<LocalRoster>>,
    roster_dir: Option<PathBuf>,
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
            off_namespaces: Default::default(),
            roster: Arc::new(Mutex::new(LocalRoster::default())),
            roster_dir: None,
            last_presented: None,
        }
    }

    /// Use this roster, saving it to `dir` after every enrollment.
    pub fn with_roster(mut self, roster: Arc<Mutex<LocalRoster>>, dir: PathBuf) -> Self {
        self.roster = roster;
        self.roster_dir = Some(dir);
        self
    }

    pub fn roster(&self) -> &Arc<Mutex<LocalRoster>> {
        &self.roster
    }

    /// Name the namespaces whose packs are installed but off.
    pub fn with_off_namespaces(
        mut self,
        off: std::collections::BTreeMap<String, String>,
    ) -> Self {
        self.off_namespaces = off;
        self
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
        let mut decision = policy::evaluate(
            &self.config,
            &class,
            &Evaluation {
                action: &refined_action,
                requester_id: &request.requester_id,
                severity,
                origin: origin.kind,
                device_attached: true,
            },
        );

        // 4b. A pack that is installed and off owns its namespace and has said
        // no on the operator's behalf. Overrides even a rule that would have
        // asked — the rule says what the namespace deserves, the switch says
        // whether anyone is home to classify it, and nobody is.
        let namespace = crate::config::namespace_of(&refined_action);
        if let Some(pack) = self.off_namespaces.get(namespace) {
            let reason = format!(
                "{refined_action} belongs to the {namespace} namespace, which pack {pack} \
                 classifies — and {pack} is installed but switched off. \
                 `signetd pack enable {pack}` to present it again"
            );
            decision.explanation = format!("refused: {reason}");
            decision.outcome = Outcome::Deny { reason };
        }

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
                    .map_or(true, |last| last.connection != origin.connection);

                let presentation = Presentation {
                    render: self.render_lines(
                        &class.label,
                        class.tier,
                        &classified,
                        &request.statement,
                        &digest_short,
                    ),
                    request_digest: request_digest.clone(),
                    request_json: request_json.clone(),
                    digest_short: digest_short.clone(),
                    severity,
                    requester: describe_requester(request, &self.last_presented, origin),
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

                match self.device.present(&presentation, &Cancel::none()) {
                    DeviceOutcome::Approved {
                        device_id,
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
                                device_id,
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

    /// Enroll the attached device to `subject`: the ceremony in enrollment
    /// spec §2, run through the ordinary presentation path.
    ///
    /// The device renders *Enroll this device as an approver for {subject}* and
    /// a human holds. What comes back is verified like any other approval, and
    /// then — because it is a proof of possession by the record's own key — it
    /// becomes the record's `proof`. One signing construction in the protocol;
    /// enrollment goes through it (enrollment spec §2).
    ///
    /// Which device signed decides the class. A mock or a relay signs with a
    /// published test key and enrolls as `test`; an attached app enrolls as
    /// `enclave`. The daemon does not take the class from anything the signer
    /// said about itself — it takes it from what kind of device it *is*, which
    /// the daemon built.
    pub fn enroll(&mut self, subject: &str, display: Option<&str>) -> Result<EnrollmentRecord, DaemonError> {
        let subject = subject.trim();
        if subject.is_empty() {
            return Err(DaemonError::Internal("a subject is required — an email or a stable id".into()));
        }
        let statement = enrollment_statement(subject);
        let wire = Request {
            v: VERSION,
            nonce: new_nonce(),
            requester: Requester {
                id: "signetd enroll".into(),
                instance: String::new(),
                pid: None,
            },
            action: ENROLLMENT_ACTION.into(),
            target: countersign_verify::Target {
                kind: "enrollment".into(),
                uri_fingerprint: countersign_verify::encoding::hex_encode(&sha2::Sha256::digest(subject.as_bytes())),
            },
            statement: statement.clone(),
            advisory: None,
            ttl_ms: 120_000,
        };
        let request_json =
            serde_json::to_string(&wire).map_err(|e| DaemonError::Internal(e.to_string()))?;
        let request_json = countersign_verify::canonicalize_str(&request_json).map_err(DaemonError::Jcs)?;
        let request_digest =
            countersign_verify::digest_of_json(&request_json).map_err(DaemonError::Jcs)?;
        let digest_short = digest_display(&request_digest);

        // The ceremony is as consequential as anything the device will ever
        // sign — it decides who may approve from now on — so it gets the
        // longest arm delay and the longest hold.
        let presentation = Presentation {
            render: vec![
                RenderLine { role: RenderRole::Label, text: "enrollment".into() },
                RenderLine::primary(statement.clone()),
                RenderLine::advisory(enrollment_advisory(&self.device.devices())),
                RenderLine { role: RenderRole::Digest, text: digest_short.clone() },
            ],
            request_digest: request_digest.clone(),
            request_json: request_json.clone(),
            digest_short,
            severity: Severity::Critical,
            requester: "signetd enroll (this machine)".into(),
            requester_changed: true,
            ttl_ms: wire.ttl_ms,
        };
        // Enrolling is a new requester by definition.
        self.last_presented = Some(LastPresented {
            connection: 0,
            claimed_id: "signetd enroll".into(),
        });

        let outcome = self.device.present(&presentation, &Cancel::none());
        let (decision, record) = match outcome {
            DeviceOutcome::Approved { device_id, counter, device_unix_ms, signature, dwell_ms } => {
                let signer = self
                    .device
                    .devices()
                    .into_iter()
                    .find(|d| d.device_id == device_id)
                    .ok_or_else(|| DaemonError::Internal(format!(
                        "device {device_id} signed but is not one this daemon knows"
                    )))?;
                let public_key = countersign_verify::encoding::hex_decode(&signer.public_key_hex)
                    .map_err(|_| DaemonError::Internal("device reported no public key".into()))?;
                let proof = ApprovalEnvelope {
                    request_json: request_json.clone(),
                    bundle: Bundle {
                        v: VERSION,
                        decision: Decision::Approved,
                        request_digest: request_digest.clone(),
                        signatures: vec![countersign_verify::DeviceSignature {
                            device_id: device_id.clone(),
                            counter,
                            device_unix_ms,
                            signature,
                            dwell_ms,
                        }],
                    },
                };
                let mut operator = Operator::new(subject);
                operator.display = display.map(|d| d.trim().to_string()).filter(|d| !d.is_empty());
                let mut record = EnrollmentRecord::new(&public_key, operator, now_unix_ms())
                    .with_class(signer.class);
                record.proof = Some(proof);

                {
                    let mut roster = self.roster.lock().expect("roster mutex");
                    roster.enroll(record.clone()).map_err(|e| DaemonError::Internal(e.to_string()))?;
                    if let Some(dir) = &self.roster_dir {
                        roster.save(dir).map_err(|e| DaemonError::Internal(e.to_string()))?;
                    }
                }
                (Decision::Approved, Some(record))
            }
            DeviceOutcome::Aborted => (Decision::Aborted, None),
            DeviceOutcome::Expired => (Decision::Expired, None),
        };

        // The trail records the ceremony like any other approval, whichever
        // way it went. "Who enrolled a key last Tuesday" is an audit question.
        self.audit.append(NewEntry {
            at_unix_ms: now_unix_ms(),
            action: ENROLLMENT_ACTION.into(),
            target_kind: "enrollment".into(),
            target_fingerprint: wire.target.uri_fingerprint.clone(),
            environment_label: "enrollment".into(),
            request_json,
            decision,
            severity: Some(Severity::Critical.as_str().to_string()),
            signatures: record
                .as_ref()
                .and_then(|r| r.proof.as_ref())
                .map(|p| p.bundle.signatures.clone())
                .unwrap_or_default(),
        })?;

        record.ok_or(DaemonError::NotApproved(decision))
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
        tier: crate::config::Tier,
        classified: &Classified,
        statement: &str,
        digest_short: &str,
    ) -> Vec<RenderLine> {
        // Spec §6: the label is the environment, colour-coded by tier. The
        // colour carries the whole of that today, and a colour is not a word —
        // someone who has not seen the other one has nothing to compare it
        // with, and someone who cannot tell the two apart has nothing at all.
        // So the tier is said as well as shown.
        let mut lines = vec![RenderLine {
            role: RenderRole::Label,
            text: format!("{label} · {}", tier.as_str()),
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

        // Which pack made this of it. A refined action (`fs.delete.text`) says
        // a pack looked; it does not say which one is installed and trusted to
        // decide what a delete means. Advisory, because it is provenance
        // rather than payload, and §9 leaves no room for a display field that
        // is neither.
        if let Some(pack) = self
            .packs
            .iter()
            .find(|p| p.handles(&classified.response.action))
            .map(|p| p.info().name.clone())
        {
            lines.push(RenderLine::advisory(format!("classified by {pack}")));
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
    origin: Origin,
) -> String {
    let claimed = if request.requester_instance.is_empty() {
        request.requester_id.clone()
    } else {
        format!("{} · {}", request.requester_id, request.requester_instance)
    };

    // A forwarded request comes from somewhere the operator is not sitting, and
    // that fact leads — it is the most important thing on the line.
    let prefix = match origin.kind {
        OriginKind::Local => "",
        OriginKind::Forwarded => "VIA FORWARDED SOCKET · ",
    };

    match last {
        Some(previous) => {
            format!(
                "{prefix}{claimed} (claimed) — previously {}",
                previous.claimed_id
            )
        }
        None => format!("{prefix}{claimed} (claimed)"),
    }
}

/// 32 CSPRNG bytes, base64url unpadded.
///
/// Generated here rather than accepted from the requester. The wire format
/// allows a client-supplied nonce, but a daemon that mints its own cannot be
/// handed a reused one, and nothing is lost by being stricter.
/// What class the record will carry — said on the screen before anyone holds.
///
/// Several devices may be asked at once and they need not share a class: the
/// Mac app and a phone are both `enclave`, the browser page is `test`. The
/// record takes the class of whichever signs, so when they differ the line
/// says so rather than naming one and being wrong for the other.
fn enrollment_advisory(devices: &[crate::device::DeviceInfo]) -> String {
    let classes: std::collections::BTreeSet<_> = devices.iter().map(|d| d.class).collect();
    match classes.len() {
        0 => "no device is attached to enroll".to_string(),
        1 => format!("this key will be enrolled as {}", classes.iter().next().expect("one")),
        _ => format!(
            "this key will be enrolled as the class of the device that signs: {}",
            classes.iter().map(ToString::to_string).collect::<Vec<_>>().join(" or ")
        ),
    }
}

fn new_nonce() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the OS must provide randomness");
    b64url_encode(&bytes)
}

#[derive(Debug)]
pub enum DaemonError {
    /// Neither a URI nor a fingerprint was supplied.
    NoTarget,
    /// The human did not approve — an enrollment that was declined or expired.
    NotApproved(Decision),
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
            DaemonError::NotApproved(d) => write!(f, "not approved: {}", d.as_str()),
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
