//! Standalone verification for Countersign approval signatures.
//!
//! Countersign produces:
//!
//! > Proof that a specific enrolled key was physically actuated while a
//! > specific payload was displayed on a device the requesting software does
//! > not control.
//!
//! It does **not** produce proof that a human did it. Content binding — the
//! device shows what it signs — is the genuinely novel half; a security key
//! proves actuation but has no screen, so you never learn what you touched to
//! approve.
//!
//! # What this crate is for
//!
//! This is the ecosystem surface. A GitHub Action, a Vault plugin, a Terraform
//! provider and a database wire proxy all need to check an approval, and none of
//! them should have to link a USB stack to do it. So this crate has no
//! dependency on the daemon, no HID, and no network, and it must stay that way:
//! the enforcement posture where the security claim actually holds is a proxy in
//! front of the resource, and that proxy generally runs on a different host from
//! the device.
//!
//! ```
//! use countersign_verify::{fingerprint_uri, Request, Requester, Target, VERSION};
//!
//! let request = Request {
//!     v: VERSION,
//!     nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ".into(),
//!     requester: Requester { id: "claude-code".into(), instance: "s1".into(), pid: None },
//!     action: "sql.execute".into(),
//!     target: Target {
//!         kind: "database".into(),
//!         // Credentials never travel; the daemon labels the environment itself.
//!         uri_fingerprint: fingerprint_uri("postgres://u:p@db.example.com/app"),
//!     },
//!     statement: "DROP TABLE users;".into(),
//!     advisory: None,
//!     ttl_ms: 60_000,
//! };
//!
//! // The client must show these 12 characters; so does the device. That match
//! // is how a human notices a disagreement between the two screens.
//! assert_eq!(request.digest_short().unwrap().len(), 12);
//! ```
//!
//! # Verifying at the point of execution
//!
//! [`verify_bundle`] checks the cryptography. [`verify_for_execution`] also
//! checks that the approval covers the statement and target you are about to
//! act on — without that binding, an agent holding one valid approval can reuse
//! it for everything that follows.
//!
//! # Porting
//!
//! This crate is deliberately small and dependency-light because it is meant to
//! be re-implemented in Go and TypeScript, where the CI and cloud integrations
//! live. [`jcs`] and [`encoding`] are written out rather than depended on for
//! the same reason. Keep it that way.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod bundle;
pub mod encoding;
pub mod enrollment;
pub mod jcs;
pub mod request;
pub mod verify;

pub use bundle::{ApprovalEnvelope, Bundle, Decision, DeviceSignature};
pub use enrollment::{
    accept_roster, enrollment_statement, DeviceStatus, EnrollmentError, EnrollmentRecord,
    MemoryRosterStore, Operator, Roster, RosterStore, SignedRoster, ENROLLMENT_ACTION,
};
pub use jcs::{canonicalize, canonicalize_str, JcsError};
pub use request::{
    digest_display, digest_of_json, digest_of_value, fingerprint_uri, normalize_uri, Request,
    Requester, Target, VERSION,
};
pub use verify::{
    is_low_s, signing_payload, verify_bundle, verify_for_execution, verify_signatures, Acceptance,
    CounterStore, EnrolledDevice, Execution, MemoryCounters, NoCounterStore, Registry,
    SignatureBackend, Verified, VerifiedSigner, VerifyError, VerifyPolicy,
};

#[cfg(feature = "ecdsa-p256")]
pub use verify::RustCryptoBackend;
