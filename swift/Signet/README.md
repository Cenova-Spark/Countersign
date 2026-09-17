# Signet for Mac

A menu bar app that runs `signetd`, is its device, and shows what it has
installed and enrolled. When something needs a person, a window appears with
the payload on it; you read it, acknowledge if the requester changed, hold the
dial, and Touch ID signs with a key that lives in the Secure Enclave. The
daemon verifies the signature against your enrolled key before it believes
it, and a default verifier accepts the result: class `enclave`
([`spec/device-classes-v1.md`](../../spec/device-classes-v1.md)).

```bash
swift/Signet/build-app.sh          # builds signetd, countersign-db, the app, and Signet.app
open swift/Signet/dist/Signet.app
```

`swift test` runs the parts with no window in them: the socket, the JSON-RPC
routing, and the whole approval flow against a fake daemon with the test
signer.

## Layout

```
Sources/SignetCore/    no windows — testable
  UnixSocket           line-delimited client on POSIX sockets
  DaemonConnection     JSON-RPC: calls out, pushes in (device.present / withdraw)
  DaemonController     find signetd, start it or join one, keep its log
  LocalState           roster.json and packs/ off disk; the CLI as the write path
  AppSession           the state: daemon, attachment, the one pending approval
Sources/Signet/        the windows
  SignetApp            MenuBarExtra, the enclave key, the approval window's lifecycle
  ApprovalView         read · acknowledge · hold, and the screen rendered from the bytes
  HoldDial             one affordance: press and hold, three detents to the commit
  MenuView             Devices · Plugins · Audit, and "Enroll this Mac"
build-app.sh           Signet.app with Info.plist (LSUIElement), bundled daemon, ad-hoc signature
```

## First run

1. The app starts `signetd run --device=app` (or joins a daemon already
   listening) and attaches with its Secure Enclave key. The menu says
   **not enrolled**.
2. Devices → *Enroll this Mac* → your email → **Enroll**. (The `?` beside the
   title says why an email.) The approval window shows *Enroll this device as
   an approver for you@example.com*. Read it, hold, Touch ID. The record
   lands in `~/.config/countersign/roster.json`.
3. Ask something to delete a file. With the hook installed
   (`crates/countersign-hook`), Claude Code's `rm` blocks; the window appears
   with the same twelve digest characters the terminal shows; hold; Touch ID;
   the hook proceeds.

Until step 2, the only thing the app will be shown is the ceremony. Approvals
presented to an unenrolled app are refused by the daemon
(`signetd::app::AppDevices::accept`).

## Being opened by a request

Countersign's own clients — the hook, the proxy, `signetd ask`, the MCP bridge
— open the app when they need an approval and nothing is listening
(`signetd::launch`). Nobody has to remember to keep a menu bar app running for
a gate to work, and the request that opened it is the one they answer rather
than one they have to make again.

It is opened only where it is installed (`/Applications`, then
`~/Applications`, or `SIGNET_APP`), only when the bundle's identifier is
`com.addisdb.signet`, and only for a client pointed at the socket the app will
actually listen on — a GUI launch inherits launchd's environment, so a
`COUNTERSIGN_SOCK` set in a shell never reaches it. `COUNTERSIGN_AUTOSTART=0`
turns it off, and every client then fails the way it did before.

Opening the app approves nothing: the daemon still presents, the person still
holds the dial, and the enclave still signs. What changes is which thing they
meet.

## What is deliberately not here

- **An approve action anywhere but the approval window.** Not in the menu,
  not in a notification. A banner with an Approve button is a one-tap
  approval of a payload nobody read (device-class spec §3.2).
- **A software key.** A Mac without a Secure Enclave can display and
  acknowledge; it cannot approve, and the app says so rather than pretending.
- **Passcode fallback.** The key is `biometryCurrentSet` only. On a Mac the
  requester may be running as you, and a passcode can be typed by software;
  a fingerprint cannot. A Mac in clamshell mode with no Touch ID keyboard
  cannot approve. The phone can.

## Development builds and the keychain

A signed, notarized app uses the data-protection keychain. A build run from
`swift run`, with no application identifier, gets `errSecMissingEntitlement`
from it and falls back to the login keychain — `CountersignKit.KeychainItem`.
The ad-hoc signature `build-app.sh` applies is enough for the Secure Enclave
and for the data-protection keychain to accept the process on this machine.
Distribution replaces `--sign -` with a Developer ID identity and adds
notarization; nothing else changes.

The daemon and its pack are bundled in `Contents/Helpers`. With nothing
installed under `~/.config/countersign/packs/`, the daemon falls back to the
`countersign-db` beside it, so SQL is classified on a fresh machine.
