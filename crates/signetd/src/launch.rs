//! Opening Signet when something asks for an approval.
//!
//! Signet is a menu bar app, and until this, a gate whose daemon was not
//! running had nobody to ask. The hook denied the delete, the proxy refused
//! the statement, and the person was told to go and open an app they had no
//! reason to be running — for a request that had already been made, and that
//! they would now have to make again. The approval is the moment Signet exists
//! for, so the approval is what opens it.
//!
//! **Nothing is weakened by this.** Opening an app approves nothing: the
//! daemon still presents the payload, the person still holds the dial, and the
//! signature still comes from a key in that Mac's Secure Enclave. What changes
//! is only which thing they meet — "signetd is not running" becomes the dial
//! they were going to be shown anyway.
//!
//! What it deliberately does not do:
//!
//! - **Open anything but Signet.** "Signet" is a common name. A bundle is
//!   opened only where Signet is installed and only when its identifier is
//!   Countersign's — the same check AddisDB's installer makes before it
//!   touches a copy. Someone else's `Signet.app` is left closed.
//! - **Start a daemon of its own.** `signetd run` with no app attached is a
//!   daemon that aborts every approval it is handed, which trades a clear
//!   refusal for a confusing one. Opening the app is what puts a device on the
//!   socket, so the app is what gets opened.
//! - **Wait indefinitely.** [`STARTUP`] bounds it, and the failure at the end
//!   of it is the failure there would have been at the start. A gate that
//!   blocked until an app appeared would hang whenever nobody is at the Mac.
//! - **Help a client pointed somewhere else.** A GUI app launched through
//!   LaunchServices inherits launchd's environment, not a shell's, so Signet
//!   listens where it listens no matter what `COUNTERSIGN_SOCK` says here.
//!   When the two disagree, opening it would only mean waiting for a socket
//!   that was never going to appear, so nothing is opened.
//!
//! `COUNTERSIGN_AUTOSTART=0` turns it off, and the request then fails while
//! Signet is closed, which is what every client did before this.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::service::{Client, ClientError};

/// Signet's bundle identifier, as `swift/Signet/build-app.sh` writes it.
const BUNDLE_ID: &str = "com.addisdb.signet";
const APP: &str = "Signet.app";

/// How long Signet gets to open, start its daemon and attach as a device.
/// Generous for what it measures: a cold launch and a daemon that prints a
/// banner and listens is about a second.
const STARTUP: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(100);

/// A daemon that can actually present this, opening Signet if that is what it
/// takes.
///
/// The error, when there is one, is the one the caller would have had without
/// any of this — plus what was tried. Every client of this fails closed on it.
pub fn connect_for_approval(path: &Path) -> Result<Client, ClientError> {
    let closed = match ready(path) {
        Ok(client) => return Ok(client),
        Err(e) => e,
    };
    let Some(app) = to_open(path) else {
        return Err(closed);
    };

    // On stderr, where every client's diagnostics go, because an app opening
    // by itself should say who opened it.
    eprintln!("countersign: opening {} to ask", app.display());
    if let Err(e) = open(&app) {
        return Err(refused(path, format!("{} could not be opened: {e}", app.display())));
    }

    let deadline = Instant::now() + STARTUP;
    loop {
        match ready(path) {
            Ok(client) => return Ok(client),
            Err(_) if Instant::now() < deadline => std::thread::sleep(POLL),
            // Whatever the last attempt hit, said plainly: "the socket never
            // appeared" and "it appeared and nothing attached to it" are
            // different enough to be worth telling apart at 3am.
            Err(last) => {
                let why = match &last {
                    ClientError::Connect { message, .. } => message.clone(),
                    other => other.to_string(),
                };
                return Err(refused(
                    path,
                    format!(
                        "{} was opened but {}s later there was still nothing to ask: {why}",
                        app.display(),
                        STARTUP.as_secs()
                    ),
                ));
            }
        }
    }
}

/// A connection to a daemon with a device on it.
///
/// Connecting is not enough. A daemon outliving the app that started it —
/// one that crashed, or was killed — answers every call and aborts every
/// approval, because there is nothing attached to show a payload to. That is
/// the same "Signet is closed" the socket's absence means, and it is fixed the
/// same way.
fn ready(path: &Path) -> Result<Client, ClientError> {
    let mut client = Client::connect(path)?;
    if client.device_status()?.kind == crate::app::NO_APP_ATTACHED {
        return Err(refused(path, "a daemon is listening, but Signet is not attached to it".into()));
    }
    Ok(client)
}

fn refused(path: &Path, message: String) -> ClientError {
    ClientError::Connect {
        path: path.to_path_buf(),
        message,
    }
}

/// Signet's bundle, when opening it is both wanted and any use.
fn to_open(socket: &Path) -> Option<PathBuf> {
    let autostart = std::env::var("COUNTERSIGN_AUTOSTART").ok();
    could_help(socket, autostart.as_deref(), app_socket().as_deref())
        .then(installed)
        .flatten()
}

/// Whether opening Signet could put a daemon on `socket` at all: a Mac, not
/// turned off, and a client pointed where Signet will listen.
fn could_help(socket: &Path, autostart: Option<&str>, app_socket: Option<&Path>) -> bool {
    cfg!(target_os = "macos") && wanted(autostart) && app_socket == Some(socket)
}

/// `COUNTERSIGN_AUTOSTART`. Unset is on; the words that turn things off are
/// off, and anything else is someone's idea of "yes".
fn wanted(value: Option<&str>) -> bool {
    !matches!(
        value.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("0" | "false" | "no" | "off" | "never")
    )
}

/// The socket Signet listens on when it is opened from the Dock, or by us.
///
/// `SignetCore.Paths` computes it from the app's own environment, which for a
/// GUI launch is launchd's: none of `COUNTERSIGN_SOCK`,
/// `COUNTERSIGN_RUNTIME_DIR`, `XDG_RUNTIME_DIR` or `XDG_CONFIG_HOME` is
/// normally set there, so this is that path with none of them set. Deliberately
/// not [`crate::service::socket_path`], which answers a different question —
/// where *this process* was told to look.
fn app_socket() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config/countersign/run/countersign.sock"))
}

/// Where Signet is installed, in the order AddisDB's installer fills.
/// `SIGNET_APP` names a copy somewhere else, for a build that is not installed.
fn installed() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("SIGNET_APP") {
        let app = PathBuf::from(explicit);
        return is_signet(&app).then_some(app);
    }
    let home = PathBuf::from(std::env::var_os("HOME")?);
    [
        PathBuf::from("/Applications").join(APP),
        home.join("Applications").join(APP),
    ]
    .into_iter()
    .find(|app| is_signet(app))
}

/// Whether the bundle at this path is ours, by the only thing that says so.
fn is_signet(app: &Path) -> bool {
    let Ok(plist) = std::fs::read_to_string(app.join("Contents/Info.plist")) else {
        return false;
    };
    plist_string(&plist, "CFBundleIdentifier").as_deref() == Some(BUNDLE_ID)
}

/// The `<string>` after `<key>{key}</key>` in an XML property list. Enough for
/// the one plist this reads, which `build-app.sh` writes. A binary plist reads
/// as nothing, and nothing makes a bundle someone else's.
fn plist_string(plist: &str, key: &str) -> Option<String> {
    let (_, after) = plist.split_once(&format!("<key>{key}</key>"))?;
    let value = after.trim_start().strip_prefix("<string>")?;
    Some(value.split_once("</string>")?.0.trim().to_owned())
}

/// `open -g`: launch it, and leave the front window where it is. Signet raises
/// its own approval window when the request lands, so taking the person off
/// what they were doing any earlier than that would be taking it for nothing.
fn open(app: &Path) -> Result<(), String> {
    let out = Command::new("/usr/bin/open")
        .arg("-g")
        .arg(app)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        return Ok(());
    }
    let said = String::from_utf8_lossy(&out.stderr).trim().to_string();
    Err(if said.is_empty() {
        format!("open exited with {}", out.status)
    } else {
        said
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOCK: &str = "/Users/someone/.config/countersign/run/countersign.sock";

    fn bundle(root: &Path, name: &str, id: &str) -> PathBuf {
        let app = root.join(name);
        std::fs::create_dir_all(app.join("Contents")).unwrap();
        std::fs::write(
            app.join("Contents/Info.plist"),
            format!(
                "<dict>\n  <key>CFBundleIdentifier</key><string>{id}</string>\n  \
                 <key>CFBundleVersion</key><string>7</string>\n</dict>"
            ),
        )
        .unwrap();
        app
    }

    #[test]
    fn a_bundle_is_ours_only_by_its_identifier() {
        let root = std::env::temp_dir().join(format!("cs-launch-{}", std::process::id()));
        assert!(is_signet(&bundle(&root, "ours.app", BUNDLE_ID)));
        assert!(!is_signet(&bundle(&root, "theirs.app", "com.example.signet")));
        assert!(!is_signet(&root.join("absent.app")));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn autostart_is_on_until_it_is_turned_off() {
        for on in [None, Some(""), Some("1"), Some("yes"), Some("please")] {
            assert!(wanted(on), "{on:?} should leave it on");
        }
        for off in ["0", "false", "no", "off", "never", " NO ", "False"] {
            assert!(!wanted(Some(off)), "{off:?} should turn it off");
        }
    }

    #[test]
    fn a_client_pointed_where_signet_listens_is_the_only_one_helped() {
        let sock = PathBuf::from(SOCK);
        // On a Mac, the default socket and nothing turning it off.
        assert_eq!(
            could_help(&sock, None, Some(&sock)),
            cfg!(target_os = "macos")
        );
        // A test's or a developer's own socket: Signet would never listen
        // there, so opening it would only be a wait for nothing.
        assert!(!could_help(
            Path::new("/tmp/cs-test.sock"),
            None,
            Some(&sock)
        ));
        // Turned off.
        assert!(!could_help(&sock, Some("0"), Some(&sock)));
        // No home to compute Signet's socket from.
        assert!(!could_help(&sock, None, None));
    }
}
