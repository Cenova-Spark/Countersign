//! The response bundle — what the daemon hands back, and what a verifier reads.
//!
//! See `spec/countersign-v1.md` §5.

use serde::{Deserialize, Serialize};

use crate::request::Request;

/// What happened to the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// A human turned the dial. The only variant that carries signatures.
    Approved,
    /// A human declined at the device.
    Aborted,
    /// The TTL elapsed with no actuation.
    Expired,
    /// Policy refused before the device was ever asked.
    Refused,
    /// No device was attached.
    NoDevice,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Approved => "approved",
            Decision::Aborted => "aborted",
            Decision::Expired => "expired",
            Decision::Refused => "refused",
            Decision::NoDevice => "no_device",
        }
    }
}

/// One device's signature over one request.
///
/// Only an `approved` bundle has any. There is no signed denial in this
/// protocol and there must never be one — see spec §5.2. Declining is the
/// absence of a signature, not the presence of a different one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSignature {
    /// Lowercase hex SHA-256 of the device's SEC1 uncompressed public key.
    pub device_id: String,
    /// Monotonic counter from the device's secure element. Never resets.
    pub counter: u64,
    pub device_unix_ms: u64,
    /// base64url unpadded, `r || s`, 64 bytes.
    pub signature: String,
    /// How long the human held before the detent committed.
    ///
    /// **Telemetry only.** A servo produces any dwell time you ask it for, so
    /// this is not evidence a human was present and no verifier may branch on
    /// it. If you find yourself writing `if dwell_ms > …`, re-read spec §1:
    /// the primitive proves an enrolled key was actuated over a displayed
    /// payload, not that a person did the actuating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dwell_ms: Option<u64>,
}

/// The daemon's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub v: u8,
    pub decision: Decision,
    pub request_digest: String,
    /// A list from day one, even though v1 produces exactly one entry.
    ///
    /// N-of-M — two devices, two humans, one action — is wanted by the
    /// financial and infrastructure cases, and retrofitting multi-party into a
    /// signature format is painful in a way that reserving a list is not.
    #[serde(default)]
    pub signatures: Vec<DeviceSignature>,
}

/// A bundle together with the request it covers.
///
/// This is what actually travels to a verifier, and the pairing is the point: a
/// proxy holding only a signature can check that *something* was approved. To
/// check that *this statement against this database* was approved, it needs the
/// request too.
///
/// The request is carried as **raw JSON, exactly as the requester sent it**.
/// Re-serializing through a struct silently drops any field this version does
/// not know about, and a digest over a field set that differs from the sender's
/// will not match — a forward-compatibility break that presents as a valid
/// approval being rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalEnvelope {
    pub request_json: String,
    pub bundle: Bundle,
}

impl ApprovalEnvelope {
    /// Parse the carried request. Fields this version does not know are dropped
    /// here — which is fine, because the digest is computed from
    /// `request_json`, never from the parsed struct.
    pub fn request(&self) -> Result<Request, serde_json::Error> {
        serde_json::from_str(&self.request_json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decisions_round_trip_in_snake_case() {
        let json = serde_json::to_string(&Decision::NoDevice).unwrap();
        assert_eq!(json, r#""no_device""#);
        assert_eq!(
            serde_json::from_str::<Decision>(&json).unwrap(),
            Decision::NoDevice
        );
    }

    #[test]
    fn a_bundle_without_signatures_parses() {
        // Every non-approved decision looks like this.
        let b: Bundle =
            serde_json::from_str(r#"{"v":1,"decision":"expired","request_digest":"ab12"}"#)
                .unwrap();
        assert_eq!(b.decision, Decision::Expired);
        assert!(b.signatures.is_empty());
    }

    #[test]
    fn an_envelope_keeps_the_request_bytes_it_was_given() {
        // The parsed view may lose an unknown field; the raw string must not,
        // because the raw string is what gets digested.
        let raw = r#"{"v":1,"nonce":"n","requester":{"id":"a","instance":"b"},
            "action":"sql.execute","target":{"kind":"database","uri_fingerprint":"9f"},
            "statement":"SELECT 1","ttl_ms":1000,"future_field":"kept"}"#;
        let env = ApprovalEnvelope {
            request_json: raw.to_string(),
            bundle: Bundle {
                v: 1,
                decision: Decision::Approved,
                request_digest: "00".into(),
                signatures: vec![],
            },
        };
        assert_eq!(env.request().unwrap().statement, "SELECT 1");
        assert!(env.request_json.contains("future_field"));
    }
}
