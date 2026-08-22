//! The approval request, its digest, and target fingerprinting.
//!
//! See `spec/countersign-v1.md` §2 and §3.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::encoding::hex_encode;
use crate::jcs::{self, JcsError};

/// The protocol version this crate speaks.
pub const VERSION: u8 = 1;

/// Who is asking. Every field here is a **claim** — a requester can say it is
/// anything. `signetd` may check `pid` against the peer credentials of the
/// connection; nothing else is verifiable, and nothing here should ever be the
/// basis for relaxing a policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requester {
    pub id: String,
    pub instance: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

/// What is being acted on.
///
/// Note the absence of a `label` field. The environment label is assigned by
/// the daemon from local config keyed on `uri_fingerprint`, so a requester
/// cannot claim it is talking to dev. Do not add one — see spec §2.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub kind: String,
    /// Lowercase hex SHA-256 of the normalized target URI. See
    /// [`fingerprint_uri`].
    pub uri_fingerprint: String,
}

/// An approval request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub v: u8,
    /// 32 CSPRNG bytes, base64url unpadded. Single use.
    pub nonce: String,
    pub requester: Requester,
    /// A namespaced verb: `sql.execute`, `terraform.apply`, `npm.publish`.
    pub action: String,
    pub target: Target,
    /// The **full** statement text. Never truncated — truncation is a render-
    /// time concern, and a signature over truncated text would attest to
    /// something the operator did not authorize.
    pub statement: String,
    /// Requester-supplied and unverified. An agent can lie about row counts;
    /// the device marks this content as unverified and no policy branches on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory: Option<Value>,
    pub ttl_ms: u64,
}

impl Request {
    /// `SHA-256(jcs(self))`, lowercase hex.
    pub fn digest(&self) -> Result<String, JcsError> {
        let value = serde_json::to_value(self).map_err(|e| JcsError::Malformed(e.to_string()))?;
        digest_of_value(&value)
    }

    /// The first 12 hex characters of the digest — what the device shows, and
    /// what the client MUST show alongside it (spec §6.1).
    pub fn digest_short(&self) -> Result<String, JcsError> {
        Ok(self.digest()?.chars().take(12).collect())
    }
}

/// `SHA-256(jcs(value))`, lowercase hex.
pub fn digest_of_value(value: &Value) -> Result<String, JcsError> {
    let canonical = jcs::canonicalize(value)?;
    Ok(hex_encode(&Sha256::digest(canonical.as_bytes())))
}

/// `SHA-256(jcs(json))`, lowercase hex, from the request **as received**.
///
/// Prefer this in a verifier. Re-serializing a request through your own structs
/// silently drops any field your version does not know about, and a digest over
/// a field set that differs from the sender's is a digest that will not match.
pub fn digest_of_json(json: &str) -> Result<String, JcsError> {
    let canonical = jcs::canonicalize_str(json)?;
    Ok(hex_encode(&Sha256::digest(canonical.as_bytes())))
}

/// Group the first 12 hex characters of a digest into three blocks of four, the
/// way the device renders them: `a91f 4c2e 7b03`.
///
/// The grouping is not decoration. A human comparing two 12-character hex runs
/// character by character gives up; comparing three short blocks is a glance.
pub fn digest_display(digest_hex: &str) -> String {
    digest_hex
        .chars()
        .take(12)
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Normalize a connection URI per spec §2.3 and return its lowercase-hex
/// SHA-256.
///
/// Credentials are stripped **before** hashing, which is the point: the daemon
/// recognises "the database I labelled prod" without ever receiving a password.
///
/// Normalization exists so that the same database fingerprints identically
/// however it was spelled — `postgres://h/db` and `postgres://H:5432/db` are one
/// target, and a policy keyed on the fingerprint would otherwise be trivial to
/// slip past by omitting the port.
pub fn fingerprint_uri(uri: &str) -> String {
    hex_encode(&Sha256::digest(normalize_uri(uri).as_bytes()))
}

/// The canonical form [`fingerprint_uri`] hashes. Exposed for diagnostics —
/// "why don't these two fingerprints match" is otherwise unanswerable.
pub fn normalize_uri(uri: &str) -> String {
    let (scheme, rest) = match uri.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        // No scheme at all: nothing to normalize confidently, so hash it as
        // given rather than guessing a shape and merging two distinct targets.
        None => return uri.trim().to_string(),
    };

    // Authority ends at the first '/', '?' or '#'.
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let after = &rest[auth_end..];

    // Userinfo is everything before the LAST '@' — a password may contain '@'.
    let hostport = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };

    let (host, port) = split_host_port(hostport);
    let port = port.unwrap_or_else(|| default_port(&scheme).to_string());

    // Path only; query and fragment are dropped.
    let path_end = after.find(['?', '#']).unwrap_or(after.len());
    let path = after[..path_end].trim_end_matches('/');

    format!(
        "{}://{}:{}{}",
        scheme,
        host.to_ascii_lowercase(),
        port,
        path
    )
}

/// Split `host:port`, honouring the `[::1]:5432` bracket form for IPv6.
fn split_host_port(s: &str) -> (&str, Option<String>) {
    if let Some(close) = s.strip_prefix('[').and_then(|_| s.find(']')) {
        let host = &s[..=close];
        let port = s[close + 1..].strip_prefix(':').map(str::to_string);
        return (host, port.filter(|p| !p.is_empty()));
    }
    match s.rsplit_once(':') {
        // A bare IPv6 address has many colons and no port.
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h, Some(p.to_string()))
        }
        _ => (s, None),
    }
}

/// Default ports, so that omitting the port does not create a second identity
/// for the same database.
///
/// An unknown scheme gets `0` rather than a guess: two different databases
/// sharing a made-up default would merge into one fingerprint, and merging is
/// the failure that loses a production label.
fn default_port(scheme: &str) -> u16 {
    match scheme {
        "postgres" | "postgresql" => 5432,
        "mysql" | "mariadb" => 3306,
        "mongodb" => 27017,
        "redis" | "rediss" => 6379,
        "mssql" | "sqlserver" => 1433,
        "oracle" => 1521,
        "clickhouse" => 8123,
        "cassandra" | "cql" => 9042,
        "neo4j" | "bolt" => 7687,
        "elasticsearch" | "elastic" => 9200,
        "influxdb" | "influx" => 8086,
        "cockroachdb" | "cockroach" => 26257,
        "https" => 443,
        "http" => 80,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Request {
        Request {
            v: VERSION,
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ".into(),
            requester: Requester {
                id: "claude-code".into(),
                instance: "sess-1".into(),
                pid: Some(48213),
            },
            action: "sql.execute".into(),
            target: Target {
                kind: "database".into(),
                uri_fingerprint: "9f2c".into(),
            },
            statement: "DROP TABLE users;".into(),
            advisory: Some(json!({ "rows_affected": 4200000, "reversible": false })),
            ttl_ms: 60000,
        }
    }

    #[test]
    fn the_digest_is_stable_and_field_order_independent() {
        let a = sample().digest().unwrap();
        // Same content, serialized by a different implementation with different
        // key order and spacing, must digest identically — that is the entire
        // job of canonicalization.
        let reordered = r#"{ "ttl_ms":60000, "statement":"DROP TABLE users;",
            "advisory":{"reversible":false,"rows_affected":4200000},
            "target":{"uri_fingerprint":"9f2c","kind":"database"},
            "action":"sql.execute",
            "requester":{"pid":48213,"instance":"sess-1","id":"claude-code"},
            "nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ", "v":1 }"#;
        assert_eq!(a, digest_of_json(reordered).unwrap());
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn changing_one_character_of_the_statement_changes_the_digest() {
        // Content binding, stated as a test: this is what a verifier is
        // checking when it recomputes the digest over the statement it is about
        // to run.
        let mut b = sample();
        b.statement = "DROP TABLE users".into(); // dropped the semicolon
        assert_ne!(sample().digest().unwrap(), b.digest().unwrap());
    }

    #[test]
    fn short_digests_render_in_readable_blocks() {
        let d = "a91f4c2e7b03deadbeef";
        assert_eq!(digest_display(d), "a91f 4c2e 7b03");
        assert_eq!(sample().digest_short().unwrap().len(), 12);
    }

    #[test]
    fn an_absent_advisory_is_absent_from_the_digest() {
        let mut none = sample();
        none.advisory = None;
        let canonical = jcs::canonicalize(&serde_json::to_value(&none).unwrap()).unwrap();
        assert!(!canonical.contains("advisory"), "got {canonical}");
    }

    #[test]
    fn fingerprints_ignore_credentials() {
        // The whole reason the fingerprint exists.
        assert_eq!(
            normalize_uri("postgres://alice:hunter2@db.example.com:5432/app"),
            "postgres://db.example.com:5432/app"
        );
        // A password containing '@' must not split the host off early.
        assert_eq!(
            normalize_uri("postgres://alice:p@ss@db.example.com/app"),
            "postgres://db.example.com:5432/app"
        );
    }

    #[test]
    fn the_default_port_is_applied_so_it_cannot_be_omitted_to_dodge_a_policy() {
        assert_eq!(
            fingerprint_uri("postgres://db.example.com/app"),
            fingerprint_uri("postgres://DB.Example.com:5432/app")
        );
        assert_eq!(
            fingerprint_uri("mysql://h/d"),
            fingerprint_uri("mysql://h:3306/d")
        );
    }

    #[test]
    fn query_parameters_and_trailing_slashes_do_not_split_an_identity() {
        assert_eq!(
            fingerprint_uri("postgres://h:5432/app?sslmode=require"),
            fingerprint_uri("postgres://h:5432/app/")
        );
    }

    #[test]
    fn different_databases_on_one_host_stay_different() {
        assert_ne!(
            fingerprint_uri("postgres://h/app"),
            fingerprint_uri("postgres://h/other")
        );
        assert_ne!(
            fingerprint_uri("postgres://h/app"),
            fingerprint_uri("mysql://h/app")
        );
    }

    #[test]
    fn ipv6_hosts_survive_with_and_without_a_port() {
        assert_eq!(
            normalize_uri("postgres://[::1]:5432/app"),
            "postgres://[::1]:5432/app"
        );
        assert_eq!(
            normalize_uri("postgres://[::1]/app"),
            "postgres://[::1]:5432/app"
        );
    }

    #[test]
    fn an_unknown_scheme_does_not_get_a_guessed_port() {
        // Two different targets must not merge into one fingerprint because a
        // made-up default collapsed them.
        assert_eq!(normalize_uri("weirddb://h/a"), "weirddb://h:0/a");
        assert_ne!(
            fingerprint_uri("weirddb://h/a"),
            fingerprint_uri("weirddb://h/b")
        );
    }
}
