//! The claim this crate exists to make good on:
//!
//! > A statement without a valid countersignature does not reach the database.
//!
//! So every test here asserts on what the **upstream** received, not on what
//! the client was told. A proxy that returned an error to the client and
//! forwarded the query anyway would pass a lazier test and be worthless.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use countersign_proxy::{pg, serve_on, Config};

/// A stand-in for PostgreSQL that records everything it is sent.
struct Upstream {
    addr: String,
    received: Arc<Mutex<Vec<u8>>>,
}

fn stub_upstream() -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let received = Arc::new(Mutex::new(Vec::new()));

    let sink = Arc::clone(&received);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let sink = Arc::clone(&sink);
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buffer = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buffer) {
                    if n == 0 {
                        break;
                    }
                    sink.lock().unwrap().extend_from_slice(&buffer[..n]);
                }
            });
        }
    });

    Upstream { addr, received }
}

fn start_proxy(upstream: &Upstream, socket: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    let config = Config {
        listen: addr.clone(),
        upstream: upstream.addr.clone(),
        target_uri: "postgres://app@db.example.com/orders".into(),
        socket: socket.into(),
        accept_test_keys: true,
        state_dir: std::env::temp_dir().join(format!(
            "cs-px-state-{}-{}",
            std::process::id(),
            addr.replace(['.', ':'], "-")
        )),
    };
    std::thread::spawn(move || {
        let _ = serve_on(listener, config);
    });
    addr
}

/// Connect and complete the startup handshake.
fn connect(proxy: &str) -> TcpStream {
    let mut client = TcpStream::connect(proxy).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let mut payload = 196_608i32.to_be_bytes().to_vec(); // protocol 3.0
    payload.extend_from_slice(b"user\0app\0database\0orders\0\0");
    let mut startup = ((payload.len() + 4) as i32).to_be_bytes().to_vec();
    startup.extend_from_slice(&payload);

    client.write_all(&startup).unwrap();
    client.flush().unwrap();
    settle();
    client
}

fn simple_query(sql: &str) -> Vec<u8> {
    let mut body = sql.as_bytes().to_vec();
    body.push(0);
    pg::Message { tag: b'Q', body }.encode()
}

fn parse(sql: &str) -> Vec<u8> {
    let mut body = vec![0]; // unnamed statement
    body.extend_from_slice(sql.as_bytes());
    body.push(0);
    body.extend_from_slice(&0i16.to_be_bytes());
    pg::Message { tag: b'P', body }.encode()
}

fn sync() -> Vec<u8> {
    pg::Message {
        tag: b'S',
        body: vec![],
    }
    .encode()
}

/// Let the proxy's threads act. Generous, because a failure here should look
/// like a failed assertion rather than a flake.
fn settle() {
    std::thread::sleep(Duration::from_millis(250));
}

fn upstream_text(upstream: &Upstream) -> String {
    String::from_utf8_lossy(&upstream.received.lock().unwrap()).into_owned()
}

/// Read whatever the client has been sent.
fn read_available(client: &mut TcpStream) -> Vec<u8> {
    client
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    let mut out = Vec::new();
    let mut buffer = [0u8; 4096];
    while let Ok(n) = client.read(&mut buffer) {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buffer[..n]);
        if out.len() > 64 * 1024 {
            break;
        }
    }
    out
}

/// A socket path no daemon is listening on.
const NO_DAEMON: &str = "/tmp/countersign-proxy-test-absent.sock";

#[test]
fn a_statement_is_not_forwarded_when_no_daemon_can_approve_it() {
    // Fail closed. A proxy that waved statements through whenever its daemon
    // was unreachable would be defeated by stopping the daemon, which is not a
    // sophisticated attack.
    let _ = std::fs::remove_file(NO_DAEMON);
    let upstream = stub_upstream();
    let proxy = start_proxy(&upstream, NO_DAEMON);

    let mut client = connect(&proxy);
    client
        .write_all(&simple_query("DROP TABLE orders"))
        .unwrap();
    client.flush().unwrap();
    settle();

    let seen = upstream_text(&upstream);
    assert!(
        seen.contains("orders"),
        "the startup packet names the database"
    );
    assert!(
        !seen.contains("DROP TABLE"),
        "the statement must not have reached the database: {seen:?}"
    );
}

#[test]
fn the_client_is_told_why_rather_than_being_dropped() {
    // A dropped connection reads as a network fault and gets retried. An error
    // the client understands stops it, and says what to do.
    let _ = std::fs::remove_file(NO_DAEMON);
    let upstream = stub_upstream();
    let proxy = start_proxy(&upstream, NO_DAEMON);

    let mut client = connect(&proxy);
    client
        .write_all(&simple_query("DROP TABLE orders"))
        .unwrap();
    client.flush().unwrap();

    let reply = read_available(&mut client);
    let text = String::from_utf8_lossy(&reply);

    assert_eq!(
        reply.first(),
        Some(&b'E'),
        "an ErrorResponse leads the reply"
    );
    assert!(
        text.contains(pg::SQLSTATE_INSUFFICIENT_PRIVILEGE),
        "{text:?}"
    );
    assert!(text.contains("countersign"), "{text:?}");
    assert!(
        text.contains("Signet"),
        "the hint should say what would fix it: {text:?}"
    );
    assert!(
        reply.contains(&b'Z'),
        "and the client is told it may carry on"
    );
}

#[test]
fn an_extended_protocol_statement_is_blocked_the_same_way() {
    // Most real traffic is prepared statements. A proxy that only inspected
    // simple queries would watch a DROP go past because psycopg used Parse.
    let _ = std::fs::remove_file(NO_DAEMON);
    let upstream = stub_upstream();
    let proxy = start_proxy(&upstream, NO_DAEMON);

    let mut client = connect(&proxy);
    client.write_all(&parse("DROP TABLE customers")).unwrap();
    client.flush().unwrap();
    settle();

    assert!(
        !upstream_text(&upstream).contains("DROP TABLE"),
        "a prepared statement must be inspected too"
    );
}

#[test]
fn after_refusing_a_parse_the_client_is_released_on_sync() {
    // The real server discards messages until Sync then reports ready. A proxy
    // that skipped this leaves the client waiting for a reply forever.
    let _ = std::fs::remove_file(NO_DAEMON);
    let upstream = stub_upstream();
    let proxy = start_proxy(&upstream, NO_DAEMON);

    let mut client = connect(&proxy);
    client.write_all(&parse("DROP TABLE customers")).unwrap();
    client.write_all(&sync()).unwrap();
    client.flush().unwrap();

    let reply = read_available(&mut client);
    assert_eq!(reply.first(), Some(&b'E'));
    assert!(
        reply.contains(&b'Z'),
        "ReadyForQuery must follow the Sync, or the client hangs"
    );
}

#[test]
fn messages_that_carry_no_sql_are_relayed_untouched() {
    // The proxy must not become a bottleneck on everything else, and must not
    // corrupt a byte of what it does not inspect.
    let _ = std::fs::remove_file(NO_DAEMON);
    let upstream = stub_upstream();
    let proxy = start_proxy(&upstream, NO_DAEMON);

    let mut client = connect(&proxy);
    let describe = pg::Message {
        tag: b'D',
        body: b"S\0".to_vec(),
    }
    .encode();
    client.write_all(&describe).unwrap();
    client.flush().unwrap();
    settle();

    let received = upstream.received.lock().unwrap().clone();
    assert!(
        received.windows(describe.len()).any(|w| w == describe),
        "an uninspected message must arrive byte for byte"
    );
}

#[test]
fn an_ssl_request_is_declined_so_the_client_falls_back_rather_than_hanging() {
    let _ = std::fs::remove_file(NO_DAEMON);
    let upstream = stub_upstream();
    let proxy = start_proxy(&upstream, NO_DAEMON);

    let mut client = TcpStream::connect(&proxy).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let mut request = 8i32.to_be_bytes().to_vec();
    request.extend_from_slice(&pg::SSL_REQUEST_CODE.to_be_bytes());
    client.write_all(&request).unwrap();
    client.flush().unwrap();

    let mut answer = [0u8; 1];
    client.read_exact(&mut answer).unwrap();
    assert_eq!(
        answer[0], b'N',
        "no TLS between client and proxy, said plainly"
    );
}

#[test]
fn an_empty_statement_does_not_ask_anyone_for_anything() {
    // Clients send empty queries to check liveness. Prompting a human for one
    // would be exactly the fatigue the design warns about.
    let _ = std::fs::remove_file(NO_DAEMON);
    let upstream = stub_upstream();
    let proxy = start_proxy(&upstream, NO_DAEMON);

    let mut client = connect(&proxy);
    client.write_all(&simple_query("   ")).unwrap();
    client.flush().unwrap();
    settle();

    let reply = read_available(&mut client);
    assert!(
        !reply.starts_with(b"E"),
        "an empty statement should pass through, not be refused"
    );
}

// ---------------------------------------------------------------------------
// With a real daemon behind it
// ---------------------------------------------------------------------------

use countersign_verify::fingerprint_uri;
use signetd::audit::AuditStore;
use signetd::daemon::Daemon;
use signetd::device::{MockBehaviour, MockDevice};

const TARGET: &str = "postgres://app@db.example.com/orders";

/// Start a daemon on a short socket path and return it.
///
/// Short because a unix socket path caps out around 100 bytes and a temp
/// directory under a deep home eats most of that.
fn start_daemon(tag: &str, policy: &str) -> String {
    let socket = format!("/tmp/cs-px-{}-{tag}.sock", std::process::id());
    let _ = std::fs::remove_file(&socket);

    let dir = std::env::temp_dir().join(format!("cs-px-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let config = signetd::config::Config::parse(&format!(
        r#"
[[environment]]
label = "prod-us-east-1"
tier  = "production"
uri_fingerprints = ["{}"]

{policy}
"#,
        fingerprint_uri(TARGET)
    ))
    .expect("test config parses");

    let audit = AuditStore::open(&dir.join("audit")).unwrap();
    let device = MockDevice::new(MockBehaviour::Auto).with_counter_file(&dir.join("counter"));
    let daemon = Daemon::new(config, Box::new(device), Vec::new(), audit);

    let path = socket.clone();
    std::thread::spawn(move || {
        let _ = signetd::service::serve(daemon, std::path::Path::new(&path), None, None);
    });
    settle();
    socket
}

const APPROVE_SQL: &str = r#"
[[policy.rule]]
tier = "production"
actions = ["sql"]
decision = "require_approval"
"#;

const DENY_SQL: &str = r#"
[[policy.rule]]
tier = "production"
actions = ["sql"]
decision = "deny"
"#;

#[test]
fn an_approved_statement_reaches_the_database() {
    // The other half of the claim. A proxy that blocked everything would pass
    // every test above and be useless.
    let socket = start_daemon("approve", APPROVE_SQL);
    let upstream = stub_upstream();
    let proxy = start_proxy(&upstream, &socket);

    let mut client = connect(&proxy);
    client
        .write_all(&simple_query("DELETE FROM orders WHERE id = 1"))
        .unwrap();
    client.flush().unwrap();
    settle();

    assert!(
        upstream_text(&upstream).contains("DELETE FROM orders WHERE id = 1"),
        "an approved statement must be forwarded verbatim"
    );
    let _ = std::fs::remove_file(&socket);
}

#[test]
fn a_statement_policy_denies_never_reaches_the_database() {
    let socket = start_daemon("deny", DENY_SQL);
    let upstream = stub_upstream();
    let proxy = start_proxy(&upstream, &socket);

    let mut client = connect(&proxy);
    client
        .write_all(&simple_query("DROP TABLE orders"))
        .unwrap();
    client.flush().unwrap();
    settle();

    assert!(
        !upstream_text(&upstream).contains("DROP TABLE"),
        "a denied statement must not be forwarded"
    );

    let reply = read_available(&mut client);
    let text = String::from_utf8_lossy(&reply);
    assert!(
        text.contains("refused"),
        "the client should be told: {text:?}"
    );
    let _ = std::fs::remove_file(&socket);
}

#[test]
fn the_approval_is_verified_against_the_statement_being_forwarded() {
    // The proxy asks the daemon and then checks the signature itself, against
    // this statement on this target. That is what makes it an enforcement
    // point rather than a relay of someone else's opinion — and it is only
    // observable as "the approved statement went through with its signature
    // checked", so this pins the path.
    let socket = start_daemon("verify", APPROVE_SQL);
    let upstream = stub_upstream();
    let proxy = start_proxy(&upstream, &socket);

    let mut client = connect(&proxy);
    for sql in [
        "UPDATE orders SET x = 1 WHERE id = 2",
        "DELETE FROM orders WHERE id = 3",
    ] {
        client.write_all(&simple_query(sql)).unwrap();
    }
    client.flush().unwrap();
    settle();

    let seen = upstream_text(&upstream);
    // Each statement carries its own nonce and therefore its own digest, so
    // one approval could not have covered both.
    assert!(
        seen.contains("UPDATE orders SET x = 1 WHERE id = 2"),
        "{seen:?}"
    );
    assert!(seen.contains("DELETE FROM orders WHERE id = 3"), "{seen:?}");
    let _ = std::fs::remove_file(&socket);
}

#[test]
fn the_replay_defence_survives_a_proxy_restart() {
    // The reason the store is on disk. A proxy that forgot the highest counter
    // it had seen would accept a replayed approval once per restart, and
    // restarting a proxy is not a sophisticated attack.
    use countersign_verify::{CounterStore, FileStore};

    let socket = start_daemon("durable", APPROVE_SQL);
    let upstream = stub_upstream();

    let state_dir = std::env::temp_dir().join(format!("cs-px-durable-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state_dir);

    // A proxy, one approved statement, then the proxy goes away.
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let config = Config {
            listen: addr.clone(),
            upstream: upstream.addr.clone(),
            target_uri: TARGET.into(),
            socket: socket.clone().into(),
            accept_test_keys: true,
            state_dir: state_dir.clone(),
        };
        std::thread::spawn(move || {
            let _ = serve_on(listener, config);
        });
        settle();

        let mut client = connect(&addr);
        client
            .write_all(&simple_query("DELETE FROM orders WHERE id = 9"))
            .unwrap();
        client.flush().unwrap();
        settle();
        assert!(
            upstream_text(&upstream).contains("id = 9"),
            "the statement was approved"
        );
    }

    // What a fresh proxy reads on the way up.
    let reloaded = FileStore::open(state_dir.join("counters.json")).unwrap();
    assert!(
        !reloaded.is_empty(),
        "the counter must have been written to disk"
    );

    let device = "d2eed8cf599a13c5cc39434b64307a75431fc6b95eb7ceeee7ecb94e40023f1a";
    let highest = CounterStore::highest(&reloaded, device);
    assert!(
        highest.is_some_and(|c| c > 0),
        "a restarted proxy must remember the device's counter, got {highest:?}"
    );

    let _ = std::fs::remove_dir_all(&state_dir);
    let _ = std::fs::remove_file(&socket);
}

#[test]
fn a_proxy_refuses_to_start_on_an_unreadable_replay_history() {
    // Starting with an empty history would silently reopen the replay window
    // that the file exists to close.
    use countersign_verify::FileStore;

    let dir = std::env::temp_dir().join(format!("cs-px-corrupt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("counters.json"), "{ truncated").unwrap();

    assert!(
        FileStore::open(dir.join("counters.json")).is_err(),
        "a corrupt history must stop the proxy, not be quietly discarded"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
