//! `signetd` — the Countersign daemon and its client tools.
//!
//! ```text
//! signetd run                 start the daemon (owns the device)
//! signetd mcp                 stdio MCP bridge — what Claude Code spawns
//! signetd status              is a daemon running, and what is attached?
//! signetd fingerprint <uri>   compute a target fingerprint for the config
//! signetd pair --code <CODE>  bind this daemon to a relay account
//! ```

use std::path::PathBuf;
use std::process::{Command, ExitCode};

use countersign_pack::{HostConfig, PackHost};
use signetd::audit::AuditStore;
use signetd::config::{self, Config};
use signetd::daemon::{runtime_dir, Daemon};
use signetd::app::{AppDevice, AppDevices};
use signetd::device::{Device, Devices, MockAction, MockBehaviour, MockDevice};
use signetd::roster::LocalRoster;
use std::sync::{Arc, Mutex};
use signetd::interactive::InteractiveDevice;
use signetd::mcp;
use signetd::packs;
use signetd::relay::{RelayConfig, RelayDevice};
use signetd::service::{self, forward_socket_path, socket_path};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");

    let result = match command {
        "run" => run(&args[1..]),
        "mcp" => mcp::serve().map_err(|e| e.to_string()),
        "status" => status(),
        "fingerprint" => fingerprint(&args[1..]),
        "pair" => pair(&args[1..]),
        "pack" => pack(&args[1..]),
        "enroll" => enroll(&args[1..]),
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
         \x20 signetd pair --relay URL --code CODE          bind this daemon to a relay account\n\
         \x20 signetd pack list                             installed plugins, and which are on\n\
         \x20 signetd pack install <dir | file.wasm> [--name N]   install a plugin, switched off\n\
         \x20 signetd pack enable|disable <name>            switch a pack's namespaces on or off\n\
         \x20 signetd pack remove <name>                    uninstall\n\
         \x20 signetd enroll --subject you@example.com [--display Name]\n\
         \x20                                               enroll the attached device to a person\n\
         \n\
         DEVICE MODES  (combine with commas: --device=app,relay)\n\
         \x20 mock            prompt on this terminal (default; not combinable)\n\
         \x20 mock:auto       approve everything without asking — smoke tests only\n\
         \x20 mock:script=P   consume outcomes from a JSON array at path P\n\
         \x20 relay           ask a paired phone through the relay — run `signetd pair` first.\n\
         \x20                 A phone signs with its enclave key once enrolled; the browser\n\
         \x20                 page signs with a published test key\n\
         \x20 app             the desktop app attaches over the socket and approves\n\
         \x20                 with its enclave key — a real approval, class `enclave`\n\
         \n\
         mock and the relay's browser page sign with PUBLISHED TEST KEYS, which a\n\
         default verifier refuses. Only an enrolled enclave — the app, a phone —\n\
         or, one day, a Signet produces an approval that counts.\n",
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
    let roster_dir = config::config_dir();
    let roster = Arc::new(Mutex::new(
        LocalRoster::load(&roster_dir).map_err(|e| e.to_string())?,
    ));
    let (device, apps) = build_devices(&device_mode, &run_dir, &roster)?;
    let audit_dir = config::config_dir().join("audit");
    let audit = AuditStore::open(&audit_dir).map_err(|e| e.to_string())?;

    // Installed plugins first. If none are installed at all, fall back to the
    // pack shipped beside this binary, so a fresh checkout still classifies
    // SQL without an install step.
    let packs_dir = packs::packs_dir();
    let loaded = packs::load(&packs_dir, HostConfig::default()).map_err(|e| e.to_string())?;
    for (name, why) in &loaded.failed {
        eprintln!("signetd: pack {name} is on but did not start, so it is treated as off: {why}");
    }
    let mut config = config;
    packs::extend_presentable(&mut config, &loaded.enabled_namespaces);
    let installed_any = !loaded.hosts.is_empty() || !loaded.off_namespaces.is_empty() || !loaded.failed.is_empty();
    let packs = if installed_any { loaded.hosts } else { discover_packs() };
    let off_namespaces = loaded.off_namespaces;

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
    {
        let roster = roster.lock().expect("roster mutex");
        eprintln!(
            "  roster      {} enrolled device(s) in {}",
            roster.records.len(),
            LocalRoster::path_in(&roster_dir).display()
        );
        if apps.is_some() && roster.active_of_class(countersign_verify::DeviceClass::Enclave).is_empty() {
            eprintln!(
                "              no enclave device is enrolled yet — attach the app, then\n\
                 \x20             `signetd enroll --subject you@example.com`"
            );
        }
    }
    eprintln!(
        "  packs       {}",
        if packs.is_empty() {
            "none on — statements will not be classified".to_string()
        } else {
            packs
                .iter()
                .map(|p| p.info().name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    if !off_namespaces.is_empty() {
        let mut by_pack: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
        for (ns, pack) in &off_namespaces {
            by_pack.entry(pack.as_str()).or_default().push(ns.as_str());
        }
        for (pack, namespaces) in by_pack {
            eprintln!(
                "  off         {pack} — {} refused without asking until `signetd pack enable {pack}`",
                namespaces.join(", ")
            );
        }
    }
    eprintln!(
        "  presentable {}",
        {
            let ns = config.policy.presentable_namespaces();
            if ns.is_empty() { "nothing — every request is refused".to_string() } else { ns.into_iter().collect::<Vec<_>>().join(", ") }
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

    let daemon = Daemon::new(config, device, packs, audit)
        .with_off_namespaces(off_namespaces)
        .with_roster(roster, roster_dir);
    service::serve(daemon, &socket_path(), forward.as_deref(), apps).map_err(|e| e.to_string())
}

/// The daemon's device, and the app registry when `app` is among the modes.
type BuiltDevices = (Box<dyn Device>, Option<Arc<AppDevices>>);

/// Build the device — or several, asked at once.
///
/// `--device=app,relay` presents to whichever answers first and withdraws the
/// rest. The interactive terminal mock is not combinable: it blocks on a
/// keyboard, which nothing can withdraw.
fn build_devices(
    modes: &str,
    run_dir: &std::path::Path,
    roster: &Arc<Mutex<LocalRoster>>,
) -> Result<BuiltDevices, String> {
    let modes: Vec<&str> = modes.split(',').map(str::trim).filter(|m| !m.is_empty()).collect();
    if modes.is_empty() {
        return Err("--device= needs at least one mode; try `signetd help`".into());
    }
    if modes.len() > 1 && modes.contains(&"mock") {
        return Err(
            "the interactive `mock` device cannot be combined with others — it waits on a \
             keyboard, which nothing can withdraw. Use mock:auto or mock:script=P in a combination"
                .into(),
        );
    }

    let mut apps: Option<Arc<AppDevices>> = None;
    let mut devices: Vec<Box<dyn Device>> = Vec::new();
    for mode in &modes {
        if *mode == "app" {
            let shared = Arc::new(
                AppDevices::new(Arc::clone(roster))
                    .with_counter_file(&run_dir.join("app-counters.json")),
            );
            devices.push(Box::new(AppDevice::new(Arc::clone(&shared))));
            apps = Some(shared);
        } else {
            devices.push(build_device(mode, run_dir, roster)?);
        }
    }
    let device: Box<dyn Device> = if devices.len() == 1 {
        devices.pop().expect("one device")
    } else {
        Box::new(Devices::new(devices))
    };
    Ok((device, apps))
}

/// `signetd enroll --subject alice@example.com [--display Alice]`
///
/// Runs the ceremony on the daemon's device and writes the record to the local
/// roster. Blocks until the human holds, declines, or the request expires.
fn enroll(args: &[String]) -> Result<(), String> {
    let mut subject: Option<String> = None;
    let mut display: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if let Some(v) = arg.strip_prefix("--subject=") {
            subject = Some(v.to_string());
        } else if arg == "--subject" {
            subject = iter.next().cloned();
        } else if let Some(v) = arg.strip_prefix("--display=") {
            display = Some(v.to_string());
        } else if arg == "--display" {
            display = iter.next().cloned();
        } else if !arg.starts_with("--") && subject.is_none() {
            subject = Some(arg.clone());
        } else {
            return Err(format!("unexpected argument {arg:?}"));
        }
    }
    let subject = subject.ok_or(
        "usage: signetd enroll --subject you@example.com [--display \"Your Name\"]\n\
         The subject is a stable identifier — an email, an employee id — not a display name.",
    )?;

    let mut client = service::Client::connect(&socket_path()).map_err(|e| e.to_string())?;
    let status = client.device_status().map_err(|e| e.to_string())?;
    eprintln!(
        "enrolling {} ({}) as an approver for {subject}",
        status.kind, if status.device_id.is_empty() { "no device attached yet".to_string() } else { status.device_id[..12].to_string() }
    );
    eprintln!("the device is showing the ceremony. Read it, acknowledge, and hold.");

    let record = client.enroll(&subject, display.as_deref()).map_err(|e| e.to_string())?;
    println!("enrolled");
    println!("  device_id  {}", record.device_id);
    println!("  class      {}", record.class());
    println!("  subject    {}", record.operator.subject);
    if let Some(d) = &record.operator.display {
        println!("  display    {d}");
    }
    println!("  roster     {}", LocalRoster::path_in(&config::config_dir()).display());
    if record.is_test_key {
        println!();
        println!("This is a PUBLISHED TEST KEY. The record is real; the key is not. A default");
        println!("verifier refuses its approvals, and that is the point of the mock.");
    }
    Ok(())
}

/// `signetd pack …` — install, list, switch, remove.
///
/// Installing switches nothing on. That is the same rule the daemon applies
/// to every namespace (wire spec §6.2.2): the default set of things that may
/// reach a human is empty, and a plugin does not get to add itself to it by
/// being present on disk.
fn pack(args: &[String]) -> Result<(), String> {
    let dir = packs::packs_dir();
    let verb = args.first().map(String::as_str).unwrap_or("list");
    let rest = &args[1.min(args.len())..];

    match verb {
        "list" | "ls" => {
            let installed = packs::list(&dir).map_err(|e| e.to_string())?;
            if installed.is_empty() {
                println!("no plugins installed in {}", dir.display());
                println!();
                println!("Install one:");
                println!("  signetd pack install path/to/plugin-dir      # holds countersign-plugin.json");
                println!("  signetd pack install path/to/pack.wasm       # a bare module; the manifest is written for you");
                return Ok(());
            }
            println!("{:<24} {:<8} {:<7} NAMESPACES", "NAME", "VERSION", "STATE");
            for p in &installed {
                let kind = p
                    .manifest
                    .pack
                    .as_ref()
                    .map(|k| format!("{:?}", k.kind).to_lowercase())
                    .unwrap_or_else(|| "-".into());
                println!(
                    "{:<24} {:<8} {:<7} {} ({kind})",
                    p.name,
                    p.manifest.version,
                    if p.enabled { "on" } else { "off" },
                    p.namespaces().join(", ")
                );
            }
            println!();
            println!("{}", dir.join(packs::STATE_FILE).display());
            Ok(())
        }

        "install" | "add" => {
            let mut source: Option<PathBuf> = None;
            let mut name: Option<String> = None;
            let mut iter = rest.iter();
            while let Some(arg) = iter.next() {
                if let Some(v) = arg.strip_prefix("--name=") {
                    name = Some(v.to_string());
                } else if arg == "--name" {
                    name = iter.next().cloned();
                } else if source.is_none() {
                    source = Some(PathBuf::from(arg));
                } else {
                    return Err(format!("unexpected argument {arg:?}"));
                }
            }
            let source = source.ok_or("usage: signetd pack install <plugin-dir | pack.wasm> [--name N]")?;
            let installed = if source.is_dir() {
                packs::install_dir(&source, &dir)
            } else {
                packs::install_wasm(&source, &dir, name.as_deref())
            }
            .map_err(|e| e.to_string())?;

            println!("installed {} {} → {}", installed.name, installed.manifest.version, installed.dir.display());
            println!("namespaces {}", installed.namespaces().join(", "));
            println!();
            println!("It is OFF. Nothing in {} reaches a human until you say so:", installed.namespaces().join(", "));
            println!("  signetd pack enable {}", installed.name);
            if !installed.manifest.policy.is_empty() {
                println!();
                println!("It proposes {} policy rule(s). Read them and add the ones you want to", installed.manifest.policy.len());
                println!("your config yourself — nothing applies them for you:");
                for rule in &installed.manifest.policy {
                    println!("  {rule}");
                }
            }
            Ok(())
        }

        "enable" | "on" | "disable" | "off" => {
            let name = rest.first().ok_or(format!("usage: signetd pack {verb} <name>"))?;
            let on = matches!(verb, "enable" | "on");
            let was = packs::set_enabled(&dir, name, on).map_err(|e| e.to_string())?;
            let installed = packs::list(&dir).map_err(|e| e.to_string())?;
            let ns = installed
                .iter()
                .find(|p| &p.name == name)
                .map(|p| p.namespaces().join(", "))
                .unwrap_or_default();
            match (was, on) {
                (true, true) => println!("{name} was already on"),
                (false, false) => println!("{name} was already off"),
                (false, true) => println!("{name} is on — {ns} may reach a human"),
                (true, false) => println!("{name} is off — {ns} is refused without asking"),
            }
            println!("restart `signetd run` for the daemon to pick this up");
            Ok(())
        }

        "remove" | "rm" | "uninstall" => {
            let name = rest.first().ok_or("usage: signetd pack remove <name>")?;
            packs::remove(&dir, name).map_err(|e| e.to_string())?;
            println!("removed {name}");
            Ok(())
        }

        other => Err(format!("unknown pack command {other:?}; try `signetd pack list`")),
    }
}

fn build_device(
    mode: &str,
    run_dir: &std::path::Path,
    roster: &Arc<Mutex<LocalRoster>>,
) -> Result<Box<dyn Device>, String> {
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

    if mode == "relay" {
        let config = RelayConfig::load(run_dir).map_err(|e| e.to_string())?;
        eprintln!(
            "signetd: approvals for this daemon are asked for at {} — {}",
            config.base_url, config.name
        );
        return Ok(Box::new(
            RelayDevice::new(config)
                .with_roster(Arc::clone(roster))
                .with_counter_file(&run_dir.join("relay-counter")),
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

/// Bind this daemon to whoever minted the pairing code.
///
/// The code is read off the relay's own screen by a signed-in human, which is
/// the whole trust step: it is how a daemon comes to belong to a person. It is
/// single-use and expires in minutes, because a code that stays valid is a
/// standing invitation to bind somebody else's daemon to your account.
fn pair(args: &[String]) -> Result<(), String> {
    let mut base_url = "https://signet.addisdb.com".to_string();
    let mut code: Option<String> = None;
    let mut name = default_signet_name();

    for arg in args {
        if let Some(value) = arg.strip_prefix("--relay=") {
            base_url = value.to_string();
        } else if let Some(value) = arg.strip_prefix("--code=") {
            code = Some(value.to_string());
        } else if let Some(value) = arg.strip_prefix("--name=") {
            name = value.to_string();
        } else if !arg.starts_with("--") && code.is_none() {
            code = Some(arg.clone());
        } else {
            return Err(format!("unexpected argument {arg:?}"));
        }
    }

    let code = code.ok_or_else(|| {
        "no pairing code. Sign in at the relay, open Pair a signet, and pass the code:\n\
         \x20 signetd pair --code ABCD-EFGH"
            .to_string()
    })?;

    let config = RelayDevice::pair(&base_url, &code, &name).map_err(|e| e.to_string())?;
    let run_dir = runtime_dir();
    config.save(&run_dir).map_err(|e| e.to_string())?;

    println!("paired \"{}\" with {}", config.name, config.base_url);
    println!("stored  {}", RelayConfig::path(&run_dir).display());
    println!();
    println!("Start the daemon asking that phone with:");
    println!("  signetd run --device=relay");
    println!();
    println!("Approvals made on the relay's web page are signed with the PUBLISHED TEST");
    println!("KEY, so a default verifier refuses them. That is deliberate. A phone approves");
    println!("with its own enclave key once you have enrolled it: signetd enroll --subject you");
    Ok(())
}

/// A name a human will recognise in a list of their own devices.
fn default_signet_name() -> String {
    std::process::Command::new("scutil")
        .args(["--get", "ComputerName"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "Signet".to_string())
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
