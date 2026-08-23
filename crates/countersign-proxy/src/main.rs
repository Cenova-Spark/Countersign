//! `countersign-proxy` — sit in front of a database and refuse what nobody
//! countersigned.
//!
//! ```text
//! countersign-proxy --listen 127.0.0.1:6432 \
//!                   --upstream 127.0.0.1:5432 \
//!                   --target postgres://user@db.example.com/app
//! ```
//!
//! Point your client at the listen address. Nothing about the client changes.

use std::path::PathBuf;
use std::process::ExitCode;

use countersign_proxy::{serve, Config};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("countersign-proxy: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }

    let mut listen = "127.0.0.1:6432".to_string();
    let mut upstream = "127.0.0.1:5432".to_string();
    let mut target: Option<String> = None;
    let mut socket = signetd::service::socket_path();
    let mut accept_test_keys = false;
    let mut state_dir = signetd::config::config_dir().join("proxy-state");

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| -> Result<String, String> {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match arg.as_str() {
            "--listen" => listen = value("--listen")?,
            "--upstream" => upstream = value("--upstream")?,
            "--target" => target = Some(value("--target")?),
            "--socket" => socket = PathBuf::from(value("--socket")?),
            "--state-dir" => state_dir = PathBuf::from(value("--state-dir")?),
            "--accept-test-keys" => accept_test_keys = true,
            other => return Err(format!("unexpected argument {other:?}; try --help")),
        }
    }

    let target_uri = target.ok_or(
        "--target is required: the URI clients believe they are reaching, so the daemon can \
         label the environment and bind the signature to it",
    )?;

    serve(Config {
        listen,
        upstream,
        target_uri,
        socket,
        accept_test_keys,
        state_dir,
    })
    .map_err(|e| e.to_string())
}

fn print_help() {
    eprintln!(
        "countersign-proxy {}\n\
         \n\
         Sit in front of a PostgreSQL server and refuse statements nobody\n\
         countersigned. Clients need no changes and no awareness of Countersign.\n\
         \n\
         USAGE\n\
         \x20 --listen ADDR          where to accept clients (default 127.0.0.1:6432)\n\
         \x20 --upstream ADDR        the real database  (default 127.0.0.1:5432)\n\
         \x20 --target URI           what clients believe they are reaching (required)\n\
         \x20 --socket PATH          signetd control socket\n\
         \x20 --state-dir PATH       where the replay defence is kept across restarts\n\
         \x20 --accept-test-keys     accept PUBLISHED TEST KEY signatures (demos only)\n\
         \n\
         There is no TLS between client and proxy: an SSLRequest is answered 'N'\n\
         and the client falls back to plaintext. Run it on loopback or over a\n\
         tunnel until that changes.\n",
        env!("CARGO_PKG_VERSION")
    );
}
