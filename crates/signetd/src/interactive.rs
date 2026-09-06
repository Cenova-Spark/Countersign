//! The interactive mock: a human, a terminal, and no mouse.
//!
//! `signetd run` is a long-lived process the operator starts in their own
//! terminal, so the mock can prompt there directly. That is why this is not a
//! GUI and not a dialog — the wire spec forbids a software approval path that
//! could survive into production, and a terminal prompt in the daemon's own
//! session is about as far from a click-through as an approval affordance gets.
//!
//! It is still a mock. It signs with the published test key, so nothing it
//! produces verifies against a default verifier, and every screen it draws says
//! so.
//!
//! # One affordance
//!
//! The dial approves. That is the only thing it does, and declining is not
//! something the device expresses — it is what happens when you do not turn.
//! So this prompt is not `[y/N]`: approving takes a deliberate word, and every
//! other input, including the easiest one to press, dismisses. See
//! `spec/countersign-v1.md` §5.2.
//!
//! # Acknowledging is a different organ
//!
//! When the requester changes, the device asks for an acknowledgement *first* —
//! and on hardware that is a **button**, never the dial. Same-organ,
//! different-direction would invite exactly the confusion this exists to
//! prevent, in exactly the population it exists for: someone not paying full
//! attention. A different organ cannot be confused for the dial by a hand
//! moving on autopilot. See `spec/countersign-v1.md` §6.3.

use std::io::{BufRead, IsTerminal, Write};
use std::time::Instant;

use countersign_pack::RenderRole;

use crate::device::{Cancel, Device, DeviceInfo, DeviceOutcome, MockDevice, Presentation};

/// A mock that asks the operator on the daemon's own terminal.
pub struct InteractiveDevice {
    inner: MockDevice,
}

impl InteractiveDevice {
    pub fn new(inner: MockDevice) -> Self {
        Self { inner }
    }

    /// Whether the daemon actually has a terminal to prompt on.
    ///
    /// Under systemd, launchd, or a pipe there is nobody to ask, and prompting
    /// into the void would hang every approval until its TTL. Callers should
    /// fall back to a scripted device and say so loudly.
    pub fn has_terminal() -> bool {
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
    }
}

impl Device for InteractiveDevice {
    fn info(&self) -> DeviceInfo {
        self.inner.info()
    }

    fn present(&mut self, presentation: &Presentation, cancel: &Cancel) -> DeviceOutcome {
        // Everything is drawn on stderr: stdout may be a transport, and a
        // prompt written into a JSON-RPC stream corrupts it.
        let mut out = std::io::stderr();
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", "─".repeat(64));

        for line in &presentation.render {
            let rendered = match line.role {
                RenderRole::Label => format!("  ENVIRONMENT  {}", line.text),
                RenderRole::Primary => format!("  {}", line.text),
                RenderRole::Advisory => format!("  · {} (unverified)", line.text),
                RenderRole::Digest => format!("  DIGEST       {}", line.text),
            };
            let _ = writeln!(out, "{rendered}");
        }

        let _ = writeln!(out, "{}", "─".repeat(64));

        // The continuity check, before anything else. A different requester
        // means the rhythm the operator has built is not about the thing in
        // front of them, so the dial does not accept anything until they say
        // they have noticed.
        if presentation.requester_changed {
            let _ = writeln!(out, "  ⚠ THE REQUESTER CHANGED");
            let _ = writeln!(out, "    now asking: {}", presentation.requester);
            let _ = writeln!(
                out,
                "\n    Press the acknowledge button (here: type `ack`) before this can be\n    \
                 approved. Acknowledging is not approving and signs nothing."
            );
            let _ = write!(out, "  > ");
            let _ = out.flush();

            let mut ack = String::new();
            if std::io::stdin().lock().read_line(&mut ack).is_err() || ack.trim() != "ack" {
                let _ = writeln!(out, "  not acknowledged — dismissed, nothing signed\n");
                return DeviceOutcome::Aborted;
            }
            let _ = writeln!(out, "    acknowledged.\n");
        } else {
            let _ = writeln!(out, "  requester     {}", presentation.requester);
        }

        let _ = writeln!(
            out,
            "  Confirm the DIGEST above matches the one your client showed."
        );
        // Deliberately not a [y/N] prompt. The device has one affordance that
        // can approve, and declining is not something it expresses — it is
        // something you do by not turning. A symmetric two-key prompt would
        // teach the wrong model of the hardware, and it would make approving
        // exactly as cheap as declining.
        let _ = writeln!(
            out,
            "  Type `turn` to approve (a real device holds for {} ms), or press Enter to\n  \
             dismiss.",
            presentation.hold_ms()
        );
        let _ = write!(out, "  > ");
        let _ = out.flush();

        let started = Instant::now();
        let mut answer = String::new();
        let read = std::io::stdin().lock().read_line(&mut answer);
        let dwell_ms = started.elapsed().as_millis() as u64;

        // EOF means the terminal went away mid-request. A closed stdin is not
        // consent, so this dismisses.
        if matches!(read, Ok(0)) || read.is_err() {
            let _ = writeln!(out, "\n  input closed — dismissed, nothing signed");
            return DeviceOutcome::Aborted;
        }

        // Only the one word approves. Anything else — including a bare Enter,
        // which is the easiest thing to press — dismisses.
        if answer.trim() != "turn" {
            let _ = writeln!(out, "  dismissed — nothing was signed\n");
            return DeviceOutcome::Aborted;
        }

        // Too fast to have read it. A turn that lands before the payload has
        // been on screen long enough is a reflex, not a decision — and a reflex
        // is exactly what someone would try to borrow by timing a real request
        // to arrive while a hand was already moving.
        let armed_at = presentation.arm_delay_ms();
        if dwell_ms < armed_at {
            let _ = writeln!(
                out,
                "  answered in {dwell_ms} ms, and this payload arms after {armed_at} ms.\n  \
                 dismissed — read it and ask again.\n"
            );
            return DeviceOutcome::Aborted;
        }

        let _ = writeln!(out, "  approved (test key — not a real approval)\n");

        // Delegate the signing itself, so there is exactly one place in this
        // codebase that turns a decision into a signature.
        match self.inner.present(presentation, cancel) {
            DeviceOutcome::Approved {
                device_id,
                counter,
                device_unix_ms,
                signature,
                ..
            } => {
                DeviceOutcome::Approved {
                    device_id,
                    counter,
                    device_unix_ms,
                    signature,
                    // Recorded because it is interesting, and never treated as
                    // evidence of anything — a servo produces any dwell time
                    // you ask it for.
                    dwell_ms: Some(dwell_ms),
                }
            }
            other => other,
        }
    }
}
