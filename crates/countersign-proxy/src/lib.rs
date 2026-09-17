//! A PostgreSQL wire proxy that refuses statements nobody countersigned.
//!
//! This is **posture C**, and it is the only posture where the security claim
//! fully holds. In advisory mode an agent asks and then decides for itself
//! whether to honour the answer. Here it cannot: the database is on the other
//! side of this process, and a statement that has no valid, fresh, matching
//! countersignature does not reach it.
//!
//! # Why a proxy rather than more integrations
//!
//! You cannot enumerate the agents — new ones ship monthly. You *can* enumerate
//! the databases. Everything eventually speaks one of about ten wire protocols
//! to a server, so a proxy catches an editor's assistant, an unattended cron
//! job, a cloud agent, and every tool that does not exist yet, **with no
//! integration work by any of them**.
//!
//! The agent does not need to know Countersign exists. It issues a query, this
//! blocks, a human's device lights up, they turn, the query proceeds.
//!
//! # It verifies rather than trusts
//!
//! The proxy asks `signetd` for an approval and then **verifies the signature
//! itself**, against the exact statement it is about to forward and the exact
//! connection it is about to forward on. That is not redundant. It is what makes
//! this an enforcement point rather than a relay of someone else's opinion: the
//! same code path would accept an approval that arrived from anywhere, and it
//! would refuse a forged one from the daemon it is talking to.

pub mod pg;

use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use countersign_verify::{
    fingerprint_uri, verify_for_execution, Decision, EnrolledDevice, Execution, FileStore,
    Registry, RustCryptoBackend, VerifyPolicy,
};
use signetd::daemon::ApprovalRequest;
use signetd::launch::connect_for_approval;

/// How the proxy is set up.
#[derive(Debug, Clone)]
pub struct Config {
    /// Where the proxy listens, e.g. `127.0.0.1:6432`.
    pub listen: String,
    /// The real database, e.g. `127.0.0.1:5432`.
    pub upstream: String,
    /// The URI clients believe they are connecting to.
    ///
    /// Fingerprinted so the daemon can label the environment and so the
    /// signature can be bound to this target and no other. It is the operator's
    /// statement about what sits behind this proxy, not anything a client said.
    pub target_uri: String,
    /// Path to the `signetd` control socket.
    pub socket: std::path::PathBuf,
    /// Whether to accept signatures from published test keys.
    ///
    /// False in anything real. True is how a demo works at all, and it is why
    /// the flag is named after the thing it lets in.
    pub accept_test_keys: bool,
    /// Where the replay defence is kept between restarts.
    ///
    /// Durable on purpose. A proxy that forgot the highest counter it had seen
    /// would accept a replayed approval once per restart, and restarting a
    /// proxy is not a sophisticated attack.
    pub state_dir: std::path::PathBuf,
}

/// Run the proxy until the process is killed.
pub fn serve(config: Config) -> std::io::Result<()> {
    let listener = TcpListener::bind(&config.listen)?;
    serve_on(listener, config)
}

/// Run the proxy on an already-bound listener.
///
/// Split out so a test can take port 0, learn the port, and connect to it
/// without racing another process for a fixed one.
pub fn serve_on(listener: TcpListener, config: Config) -> std::io::Result<()> {
    let fingerprint = fingerprint_uri(&config.target_uri);

    eprintln!("countersign-proxy");
    eprintln!("  listening   {}", config.listen);
    eprintln!("  upstream    {}", config.upstream);
    eprintln!(
        "  target      {}",
        countersign_verify::normalize_uri(&config.target_uri)
    );
    eprintln!("  fingerprint {fingerprint}");
    eprintln!("  signetd     {}", config.socket.display());
    if config.accept_test_keys {
        eprintln!("  WARNING     accepting PUBLISHED TEST KEY signatures. Not a real deployment.");
    }
    eprintln!("\nready. statements needing approval will block until a human acts.");

    // One store for the whole proxy, not one per connection: a counter accepted
    // on one client's session must be refused on another's, which is the entire
    // point of tracking it.
    let counters = Arc::new(Mutex::new(
        FileStore::open(config.state_dir.join("counters.json"))
            .map_err(|e| std::io::Error::other(e.to_string()))?,
    ));
    eprintln!(
        "  replay state {} ({} device(s) remembered)",
        config.state_dir.join("counters.json").display(),
        counters.lock().expect("counters").len()
    );

    let config = Arc::new(config);
    let fingerprint = Arc::new(fingerprint);

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("proxy: accept failed: {e}");
                continue;
            }
        };
        let config = Arc::clone(&config);
        let fingerprint = Arc::clone(&fingerprint);
        let counters = Arc::clone(&counters);
        std::thread::spawn(move || {
            if let Err(e) = handle_client(stream, &config, &fingerprint, counters) {
                eprintln!("proxy: session ended: {e}");
            }
        });
    }
    Ok(())
}

fn handle_client(
    client: TcpStream,
    config: &Config,
    fingerprint: &str,
    counters: Arc<Mutex<FileStore>>,
) -> std::io::Result<()> {
    client.set_nodelay(true)?;
    let mut client_reader = BufReader::new(client.try_clone()?);

    // Startup, which happens before framing exists.
    let upstream = loop {
        match pg::read_startup(&mut client_reader)? {
            pg::Startup::Negotiation(_) => {
                // No TLS between client and proxy. Answering 'N' makes the
                // client fall back to plaintext rather than hang, and it is
                // stated plainly rather than hidden: see the crate README.
                pg::write_all(&mut (&client), b"N")?;
            }
            pg::Startup::Packet(bytes) | pg::Startup::Cancel(bytes) => {
                let upstream = TcpStream::connect(&config.upstream)?;
                upstream.set_nodelay(true)?;
                pg::write_all(&mut (&upstream), &bytes)?;
                break upstream;
            }
        }
    };

    // The client writer is shared: the relay thread writes the server's
    // replies, and this thread injects refusals. A refusal only happens when
    // nothing was forwarded, so the two never have anything to say at once —
    // but sharing a lock is cheaper than relying on that staying true.
    let client_writer = Arc::new(Mutex::new(client.try_clone()?));

    {
        let upstream = upstream.try_clone()?;
        let client_writer = Arc::clone(&client_writer);
        std::thread::spawn(move || {
            let mut from_server = BufReader::new(upstream);
            let mut buffer = [0u8; 16 * 1024];
            loop {
                use std::io::Read;
                match from_server.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut client = client_writer.lock().expect("client writer");
                        if client.write_all(&buffer[..n]).is_err() || client.flush().is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }

    let mut session = Session::new(config, fingerprint, counters);
    let mut to_server = upstream;

    while let Some(message) = pg::read_message(&mut client_reader)? {
        if message.is_terminate() {
            pg::write_all(&mut to_server, &message.encode())?;
            break;
        }

        // After a refusal in the extended protocol the real server discards
        // everything until Sync, then reports ready. Imitating that is what
        // stops the client waiting for a reply that is never coming.
        if session.discarding {
            if message.is_sync() {
                session.discarding = false;
                let mut client = client_writer.lock().expect("client writer");
                client.write_all(&pg::ready_for_query(b'I'))?;
                client.flush()?;
            }
            continue;
        }

        match message.sql() {
            Some(sql) if !sql.trim().is_empty() => {
                match session.authorize(&sql) {
                    Verdict::Allow => pg::write_all(&mut to_server, &message.encode())?,
                    Verdict::Refuse {
                        message: why,
                        detail,
                    } => {
                        let mut client = client_writer.lock().expect("client writer");
                        client.write_all(&pg::error_response(
                            &why,
                            Some(&detail),
                            Some("A human must countersign this on the Signet device."),
                        ))?;

                        // The simple protocol expects ready immediately; the
                        // extended one expects it only after Sync.
                        if message.tag == b'Q' {
                            client.write_all(&pg::ready_for_query(b'I'))?;
                        } else {
                            session.discarding = true;
                        }
                        client.flush()?;
                    }
                }
            }
            _ => pg::write_all(&mut to_server, &message.encode())?,
        }
    }

    Ok(())
}

/// What the proxy decided about one statement.
enum Verdict {
    Allow,
    Refuse { message: String, detail: String },
}

struct Session<'a> {
    config: &'a Config,
    fingerprint: &'a str,
    /// True between refusing an extended-protocol message and its `Sync`.
    discarding: bool,
    registry: Registry,
    counters: Arc<Mutex<FileStore>>,
}

impl<'a> Session<'a> {
    fn new(config: &'a Config, fingerprint: &'a str, counters: Arc<Mutex<FileStore>>) -> Self {
        Self {
            config,
            fingerprint,
            discarding: false,
            registry: Registry::new(),
            counters,
        }
    }

    fn authorize(&mut self, sql: &str) -> Verdict {
        let mut client = match connect_for_approval(&self.config.socket) {
            Ok(c) => c,
            Err(e) => {
                // Signet is opened first if it is closed, because a statement
                // waiting on a person is the moment it is for. When it cannot
                // be opened there are still no approvals to be had, and failing
                // closed is the only defensible answer: a proxy that waved
                // statements through whenever its daemon was down would be
                // trivially defeated by stopping the daemon.
                return Verdict::Refuse {
                    message: "countersign: cannot reach signetd, so nothing can be approved".into(),
                    detail: e.to_string(),
                };
            }
        };

        let request = ApprovalRequest {
            action: "sql.execute".into(),
            target_uri: None,
            // The operator's fingerprint for what is behind this proxy, never
            // anything the client claimed about where it thinks it is.
            uri_fingerprint: Some(self.fingerprint.to_string()),
            target_kind: "database".into(),
            statement: sql.to_string(),
            advisory: None,
            requester_id: "countersign-proxy".into(),
            requester_instance: self.config.listen.clone(),
            ttl_ms: None,
        };

        let response = match client.request_approval(&request) {
            Ok(r) => r,
            Err(e) => {
                return Verdict::Refuse {
                    message: "countersign: approval could not be obtained".into(),
                    detail: e.to_string(),
                }
            }
        };

        if response.decision != Decision::Approved {
            return Verdict::Refuse {
                message: format!("countersign: {}", response.decision.as_str()),
                detail: response.explanation,
            };
        }

        // Auto-approved: policy said this needs no human, so there is no
        // signature to check and none is expected.
        let Some(envelope) = response.envelope else {
            return Verdict::Allow;
        };

        // Verify rather than trust. The daemon said approved; this checks that
        // the signature covers *this* statement on *this* target, which is what
        // makes the proxy an enforcement point rather than a relay of someone
        // else's opinion.
        if self.registry.is_empty() {
            self.registry = build_registry(self.config.accept_test_keys);
        }

        match verify_for_execution(
            &envelope,
            &Execution {
                statement: sql,
                uri_fingerprint: self.fingerprint,
                action: None,
            },
            &self.registry,
            &VerifyPolicy {
                accept_test_keys: self.config.accept_test_keys,
                ..Default::default()
            },
            // Durable and shared across every session. A fresh nonce per
            // request already makes two digests differ, but that only holds
            // while approvals originate here; the counter is what survives an
            // approval arriving from somewhere else, and a restart.
            &mut *self.counters.lock().expect("counters"),
            &RustCryptoBackend,
            None,
        ) {
            Ok(_) => Verdict::Allow,
            Err(e) => Verdict::Refuse {
                message: "countersign: the approval did not verify".into(),
                detail: e.to_string(),
            },
        }
    }
}

/// The keys this proxy will accept.
///
/// A real deployment loads a signed roster (see `spec/enrollment-v1.md`) and
/// trusts one authority key configured out of band. Until hardware exists there
/// is exactly one device to know about, and it is the published test one.
fn build_registry(accept_test_keys: bool) -> Registry {
    let mut registry = Registry::new();
    if accept_test_keys {
        use p256::ecdsa::SigningKey;
        use sha2::{Digest, Sha256};
        let key = SigningKey::from_slice(&Sha256::digest(
            signetd::device::TEST_KEY_DERIVATION.as_bytes(),
        ))
        .expect("the derived test scalar is valid");
        registry.enroll(
            EnrolledDevice::test_key(key.verifying_key().to_sec1_bytes().to_vec())
                .with_operator(countersign_verify::Operator::new("mock-device")),
        );
    }
    registry
}
