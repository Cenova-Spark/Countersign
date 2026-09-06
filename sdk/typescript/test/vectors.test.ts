/**
 * Conformance against `spec/vectors/`.
 *
 * The same files the Rust implementation is checked against. This is the test
 * that makes the spec a spec rather than a description of one codebase: if the
 * two ports ever disagree about a canonical form, a digest, or a signature, one
 * of them fails here.
 *
 * Run with `npm test` (Node 22.6+, no install required).
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

import {
  canonicalizeText,
  digestOfJson,
  hexDecode,
  MemoryCounters,
  NoCounterStore,
  Registry,
  defaultPolicy,
  signingPayload,
  hexEncode,
  verifyBundle,
  verifyForExecution,
  VerifyError,
  b64urlDecode,
  b64urlEncode,
} from "../src/index.ts";
import type { ApprovalEnvelope } from "../src/index.ts";

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), "../../../spec/vectors");

function load(name: string): any {
  return JSON.parse(readFileSync(join(VECTORS, name), "utf8"));
}

function approvalEnvelope(): ApprovalEnvelope {
  return load("approval.json").envelope as ApprovalEnvelope;
}

function testKeyRegistry(): Registry {
  const key = load("test-key.json");
  const registry = new Registry();
  registry.enroll(hexDecode(key.public_key_sec1_uncompressed_hex), {
    is_test_key: true,
    operator: { subject: "alice@example.com" },
  });
  return registry;
}

describe("canonicalization", () => {
  it("matches every accept vector byte for byte", () => {
    const doc = load("canonicalization.json");
    assert.ok(doc.accept.length > 0, "vector file must not be empty");

    for (const testCase of doc.accept) {
      assert.equal(
        canonicalizeText(testCase.input),
        testCase.canonical,
        `${testCase.name}: canonical form differs`,
      );
      assert.equal(
        digestOfJson(testCase.input),
        testCase.digest_sha256,
        `${testCase.name}: digest differs`,
      );
    }
  });

  it("refuses every reject vector for the stated reason", () => {
    // A port that silently accepts these produces digests nobody else can
    // reproduce, which presents as a valid approval failing to verify.
    const doc = load("canonicalization.json");
    assert.ok(doc.reject.length > 0);

    for (const testCase of doc.reject) {
      assert.throws(
        () => canonicalizeText(testCase.input),
        (e: unknown) => {
          assert.ok(e instanceof Error, `${testCase.name}: expected an error`);
          assert.equal((e as { kind: string }).kind, testCase.reason, testCase.name);
          return true;
        },
        `${testCase.name}: should have been rejected`,
      );
    }
  });

  it("sorts astral-plane keys the way UTF-16 does", () => {
    // Free in JavaScript, because its strings are UTF-16. The Rust port has to
    // write this out, and getting it wrong there would show up here.
    const high = "\u{10140}";
    const bmp = "\u{FFFD}";
    const canonical = canonicalizeText(JSON.stringify({ [bmp]: 1, [high]: 2 }));
    assert.equal(canonical, `{"${high}":2,"${bmp}":1}`);
  });
});

describe("the signed approval vector", () => {
  it("verifies with the published test key", () => {
    const envelope = approvalEnvelope();
    const verified = verifyBundle(
      envelope,
      testKeyRegistry(),
      defaultPolicy({ acceptTestKeys: true }),
      new MemoryCounters(),
    );
    assert.equal(verified.requestDigest, envelope.bundle.request_digest);
    assert.equal(verified.signers.length, 1);
    assert.deepEqual(verified.operators, ["alice@example.com"]);
  });

  it("is refused by a default verifier", () => {
    // The safety property that makes a software mock acceptable: it is not
    // "disabled", it is cryptographically incapable of a production approval.
    assert.throws(
      () =>
        verifyBundle(
          approvalEnvelope(),
          testKeyRegistry(),
          defaultPolicy(),
          new MemoryCounters(),
        ),
      (e: unknown) => (e as VerifyError).kind === "test_key_rejected",
    );
  });

  it("binds to its own statement and target", () => {
    const envelope = approvalEnvelope();
    const request = JSON.parse(envelope.request_json);
    const policy = defaultPolicy({ acceptTestKeys: true });

    // The execution it was approved for.
    verifyForExecution(
      envelope,
      {
        statement: request.statement,
        uriFingerprint: request.target.uri_fingerprint,
        action: request.action,
      },
      testKeyRegistry(),
      policy,
      new MemoryCounters(),
    );

    // A different table under the same approval.
    assert.throws(
      () =>
        verifyForExecution(
          envelope,
          {
            statement: "DROP TABLE orders;",
            uriFingerprint: request.target.uri_fingerprint,
          },
          testKeyRegistry(),
          policy,
          new MemoryCounters(),
        ),
      (e: unknown) => (e as VerifyError).kind === "statement_mismatch",
    );
  });

  it("builds the same signing payload the vector pins", () => {
    // Pins the exact preimage — domain separator, digest bytes, big-endian
    // counter and timestamp — so a port compares hex rather than guessing at
    // the concatenation order.
    const doc = load("approval.json");
    const envelope = approvalEnvelope();
    const sig = envelope.bundle.signatures[0];

    assert.equal(
      hexEncode(signingPayload(envelope.bundle.request_digest, sig.counter, sig.device_unix_ms)),
      doc.signing_payload_hex,
    );
  });

  it("fails if one bit of the signature is flipped", () => {
    // Confirms the signature is actually checked, rather than waved through.
    const envelope = approvalEnvelope();
    const raw = b64urlDecode(envelope.bundle.signatures[0].signature);
    raw[10] ^= 0x01;
    envelope.bundle.signatures[0].signature = b64urlEncode(raw);

    assert.throws(
      () =>
        verifyBundle(
          envelope,
          testKeyRegistry(),
          defaultPolicy({ acceptTestKeys: true }),
          new MemoryCounters(),
        ),
      (e: unknown) => ["bad_signature", "high_s"].includes((e as VerifyError).kind),
    );
  });

  it("is refused after being presented once", () => {
    const registry = testKeyRegistry();
    const policy = defaultPolicy({ acceptTestKeys: true });
    const counters = new MemoryCounters();

    verifyBundle(approvalEnvelope(), registry, policy, counters);
    assert.throws(
      () => verifyBundle(approvalEnvelope(), registry, policy, counters),
      (e: unknown) => (e as VerifyError).kind === "counter_regression",
    );
  });

  it("cannot be turned into a signed denial", () => {
    // Only `approved` carries signatures. There is no signed refusal in this
    // protocol and there must never be one — spec §5.2.
    for (const decision of ["aborted", "expired", "refused", "no_device"] as const) {
      const envelope = approvalEnvelope();
      envelope.bundle.decision = decision;
      assert.throws(
        () =>
          verifyBundle(
            envelope,
            testKeyRegistry(),
            defaultPolicy({ acceptTestKeys: true }),
            new NoCounterStore(),
          ),
        (e: unknown) => (e as VerifyError).kind === "not_approved",
        `${decision} must never verify, signature or not`,
      );
    }
  });
});

describe("the enrollment vector", () => {
  it("carries a roster whose records derive their own device ids", () => {
    const doc = load("enrollment.json");
    const roster = JSON.parse(doc.signed_roster.roster_json);

    for (const record of roster.records) {
      const derived = hexEncode(
        new Uint8Array(createHash("sha256").update(hexDecode(record.public_key_hex)).digest()),
      );
      assert.equal(record.device_id, derived, "a record must not name another key's id");
    }
  });
});

describe("the device-class vector", () => {
  // spec/device-classes-v1.md. A phone or laptop approving under a biometric
  // check is class `enclave`: a real approval with a smaller claim. The vector
  // pins both the acceptance and the refusal so a port cannot get one right
  // and the other wrong.
  const doc = () => load("device-classes.json");
  const envelope = () => doc().approval.envelope as ApprovalEnvelope;
  const registry = () => new Registry().enrollRecord(doc().record);

  it("enrolls the record as an enclave device", () => {
    const device = registry().get(doc().enclave_key.device_id);
    assert.ok(device, "the record's id must be the one derived from its key");
    assert.equal(device.class, "enclave");
    assert.equal(device.is_test_key, false);
  });

  it("verifies under a default policy, and says what kind of thing signed", () => {
    const verified = verifyBundle(envelope(), registry(), defaultPolicy(), new MemoryCounters());
    assert.equal(verified.signers.length, 1);
    assert.equal(verified.signers[0].class, "enclave");
    assert.deepEqual(verified.operators, ["bob@example.com"]);
  });

  it("is refused by a hardware-only policy", () => {
    // The one-line way back. Nothing else about the verifier changes.
    assert.throws(
      () =>
        verifyBundle(
          envelope(),
          registry(),
          defaultPolicy({ acceptClasses: ["signet"] }),
          new MemoryCounters(),
        ),
      (e: unknown) => (e as VerifyError).kind === "class_rejected",
    );
  });

  it("takes the class from the record and never from the signature", () => {
    // The same bytes, enrolled as a Signet, pass a hardware-only policy —
    // nothing in a bundle says what kind of device signed it.
    const publicKey = hexDecode(doc().record.public_key_hex);
    verifyBundle(
      envelope(),
      new Registry().enroll(publicKey),
      defaultPolicy({ acceptClasses: ["signet"] }),
      new MemoryCounters(),
    );
    assert.throws(
      () =>
        verifyBundle(
          envelope(),
          new Registry().enroll(publicKey, { is_test_key: true }),
          defaultPolicy(),
          new MemoryCounters(),
        ),
      (e: unknown) => (e as VerifyError).kind === "test_key_rejected",
    );
  });

  it("refuses a record whose class and test flag disagree", () => {
    assert.throws(
      () => new Registry().enrollRecord({ ...doc().record, is_test_key: true }),
      (e: unknown) => (e as VerifyError).kind === "class_mismatch",
    );
  });

  it("refuses an enclave record stripped of its proof", () => {
    const { proof: _proof, ...stripped } = doc().record;
    assert.throws(
      () => new Registry().enrollRecord(stripped),
      (e: unknown) => (e as VerifyError).kind === "enclave_without_proof",
    );
  });

  it("reads a class-less record from before classes existed as before", () => {
    // enrollment.json predates the field. Its record is a test key and must
    // still read as one, with nothing re-issued.
    const roster = JSON.parse(load("enrollment.json").signed_roster.roster_json);
    const record = roster.records[0];
    assert.equal(record.class, undefined, "the legacy vector must stay class-less");
    const device = new Registry().enrollRecord(record).get(record.device_id);
    assert.equal(device?.class, "test");
  });

  it("treats `test` in acceptClasses the same as acceptTestKeys", () => {
    verifyBundle(
      approvalEnvelope(),
      testKeyRegistry(),
      defaultPolicy({ acceptClasses: ["test"] }),
      new MemoryCounters(),
    );
  });

  it("builds the signing payload the vector pins", () => {
    const sig = envelope().bundle.signatures[0];
    assert.equal(
      hexEncode(signingPayload(envelope().bundle.request_digest, sig.counter, sig.device_unix_ms)),
      doc().approval.signing_payload_hex,
    );
    assert.equal(digestOfJson(envelope().request_json), envelope().bundle.request_digest);
  });
});
