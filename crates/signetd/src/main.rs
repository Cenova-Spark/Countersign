//! `signetd` — the Countersign daemon and its client tools.
//!
//! ```text
//! signetd run                 start the daemon (owns the device)
//! signetd mcp                 stdio MCP bridge — what Claude Code spawns
//! signetd status              is a daemon running, and what is attached?
//! signetd fingerprint <uri>   compute a target fingerprint for the config
//! ```

use std::path::PathBuf;
use std::process::{Command, ExitCode};

use countersign_pack::{HostConfig, PackHost};
use signetd::audit::AuditStore;
use signetd::config::{self, Config};
use signetd::daemon::{runtime_dir, Daemon};
use signetd::device::{Device, MockAction, MockBehaviour, MockDevice};
use signetd::interactive::InteractiveDevice;
use signetd::mcp;
use signetd::service::{self, forward_socket_path, socket_path};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");

    let result = match command {
        "run" => run(&args[1..]),
        "mcp" => mcp::serve().map_err(|e| e.to_string()),
        "status" => status(),
        "fingerprint" => fingerprint(&args[1..]),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown command {other:?}; try `signetd help`")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("signetd: {message}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    eprintln!(
        "signetd {}\n\
         \n\
         USAGE\n\
         \x20 signetd run [--device=MODE] [--config=PATH]   start the daemon\n\
         \x20             [--forward[=PATH]]                  also listen for forwarded clients\n\
         \x20 signetd mcp                                   stdio MCP bridge (Claude Code spawns this)\n\
         \x20 signetd status                                report daemon and device state\n\
         \x20 signetd fingerprint <uri>                     compute a config fingerprint\n\
         \n\
         DEVICE MODES\n\
         \x20 mock            prompt on this terminal (default)\n\
         \x20 mock:auto       approve everything without asking — smoke tests only\n\
         \x20 mock:script=P   consume outcomes from a JSON array at path P\n\
         \n\
         Every mode signs with the PUBLISHED TEST KEY. Nothing signetd produces\n\
         today is a real approval, and a default verifier refuses all of it.\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn run(args: &[String]) -> Result<(), String> {
    let mut device_mode = "mock".to_string();
    let mut config_path: Option<PathBuf> = None;
    let mut forward: Option<PathBuf> = None;

    for arg in args {
        if let Some(value) = arg.strip_prefix("--device=") {
            device_mode = value.to_string();
        } else if let Some(value) = arg.strip_prefix("--config=") {
            config_path = Some(PathBuf::from(value));
        } else if arg == "--forward" {
            forward = Some(forward_socket_path());
        } else if let Some(value) = arg.strip_prefix("--forward=") {
            forward = Some(PathBuf::from(value));
        } else {
            return Err(format!("unexpected argument {arg:?}"));
        }
    }

    let config_path = config_path.unwrap_or_else(config::default_path);
    let config = Config::load_or_default(&config_path).map_err(|e| e.to_string())?;

    let run_dir = runtime_dir();
    let device = build_device(&device_mode, &run_dir)?;
    let audit_dir = config::config_dir().join("audit");
    let audit = AuditStore::open(&audit_dir).map_err(|e| e.to_string())?;
    let packs = discover_packs();

    let info = device.info();
    eprintln!("signetd {}", env!("CARGO_PKG_VERSION"));
    eprintln!("  config      {}", config_path.display());
    eprintln!("  audit       {}", audit_dir.display());
    eprintln!("  socket      {}", socket_path().display());
    eprintln!(
        "  device      {} ({})",
        info.kind,
        if info.is_test_key {
            "PUBLISHED TEST KEY — not a real approval"
        } else {
            "hardware"
        }
    );
    eprintln!("  device id   {}", info.device_id);
    eprintln!(
        "  packs       {}",
        if packs.is_empty() {
            "none found — statements will not be classified".to_string()
        } else {
            packs
                .iter()
                .map(|p| p.info().name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    eprintln!(
        "  environments {} configured, unknown targets treated as {}",
        config.environments.len(),
        config.policy.default_tier.as_str()
    );
    if let Some(path) = &forward {
        eprintln!("  forward     {}", path.display());
        eprintln!(
            "              anything reaching this socket may ask. Requests arriving on it\n\
             \x20             are shown as forwarded, and policy rules can scope them with\n\
             \x20             `origin = \"forwarded\"`."
        );
    }
    eprintln!("\nwaiting for approval requests. ctrl-c to stop.");

    let daemon = Daemon::new(config, device, packs, audit);
    service::serve(daemon, &socket_path(), forward.as_deref()).map_err(|e| e.to_string())
}

fn build_device(mode: &str, run_dir: &std::path::Path) -> Result<Box<dyn Device>, String> {
    let counter_file = run_dir.join("mock-counter");

    if mode == "mock" {
        if !InteractiveDevice::has_terminal() {
            return Err(
                "no terminal on stdin/stderr, so there is nobody to prompt; \
                 use --device=mock:auto or --device=mock:script=<file>"
                    .to_string(),
            );
        }
        return Ok(Box::new(InteractiveDevice::new(
            MockDevice::new(MockBehaviour::Auto).with_counter_file(&counter_file),
        )));
    }

    if mode == "mock:auto" {
        eprintln!(
            "signetd: WARNING --device=mock:auto approves everything with no human involved.\n\
             \x20        There is no approval step in this mode. Smoke tests only."
        );
        return Ok(Box::new(
            MockDevice::new(MockBehaviour::Auto).with_counter_file(&counter_file),
        ));
    }

    if let Some(path) = mode.strip_prefix("mock:script=") {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("cannot read script {path}: {e}"))?;
        let actions: Vec<MockAction> =
            serde_json::from_str(&text).map_err(|e| format!("invalid script {path}: {e}"))?;
        return Ok(Box::new(
            MockDevice::new(MockBehaviour::Script(actions)).with_counter_file(&counter_file),
        ));
    }

    Err(format!("unknown device mode {mode:?}; try `signetd help`"))
}

/// Find the packs shipped alongside this binary.
///
/// Deliberately not a `PATH` sweep: the pack protocol says the set of enabled
/// packs should be an explicit operator decision, not a discovery mechanism
/// that picks up whatever happens to be installed. Looking next to our own
/// executable is the narrowest thing that still works out of the box.
fn discover_packs() -> Vec<PackHost> {
    let Ok(exe) = std::env::current_exe() else {
        return Vec::new();
    };
    let Some(dir) = exe.parent() else {
        return Vec::new();
    };

    let mut packs = Vec::new();
    for name in ["countersign-db"] {
        let path = dir.join(name);
        if !path.exists() {
            continue;
        }
        match PackHost::spawn(Command::new(&path), HostConfig::default()) {
            Ok(pack) => packs.push(pack),
            Err(e) => eprintln!("signetd: pack {name} did not start: {e}"),
        }
    }
    packs
}

fn status() -> Result<(), String> {
    let path = socket_path();
    let mut client = service::Client::connect(&path).map_err(|e| e.to_string())?;

    let device = client.device_status().map_err(|e| e.to_string())?;
    let audit = client.audit_summary().map_err(|e| e.to_string())?;

    println!("daemon      running at {}", path.display());
    println!("device      {} ({})", device.kind, device.device_id);
    if device.is_test_key {
        println!("            PUBLISHED TEST KEY — a default verifier refuses these");
    }
    println!("counter     {}", device.counter);
    println!("environments {}", device.environments);
    println!("approvals   {} recorded", audit.entries);
    println!("chain head  {}", audit.head);
    Ok(())
}

fn fingerprint(args: &[String]) -> Result<(), String> {
    let uri = args.first().ok_or("usage: signetd fingerprint <uri>")?;
    let normalized = countersign_verify::normalize_uri(uri);
    let fp = countersign_verify::fingerprint_uri(uri);

    println!("{fp}");
    eprintln!("\nnormalized: {normalized}");
    eprintln!("\nAdd to your config:\n");
    eprintln!("[[environment]]");
    eprintln!("label = \"prod-us-east-1\"");
    eprintln!("tier  = \"production\"");
    eprintln!("uri_fingerprints = [\"{fp}\"]");
    Ok(())
}
