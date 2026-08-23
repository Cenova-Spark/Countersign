/**
 * Places where this port could drift from the Rust one without any vector
 * noticing, so they get their own checks.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

import {
  b64urlDecode,
  b64urlEncode,
  EncodingError,
  fingerprintUri,
  hexDecode,
  hexEncode,
  isLowS,
  normalizeUri,
} from "../src/index.ts";

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), "../../../spec/vectors");

describe("target fingerprinting", () => {
  it("agrees with the Rust implementation on the committed vector", () => {
    // The approval vector was fingerprinted by the Rust code from this exact
    // URI. If the two normalizers ever diverge, every approval the proxy asks
    // for lands on a target the daemon labels differently.
    const envelope = JSON.parse(readFileSync(join(VECTORS, "approval.json"), "utf8")).envelope;
    const request = JSON.parse(envelope.request_json);

    assert.equal(
      fingerprintUri("postgres://user:pass@db.example.com/app"),
      request.target.uri_fingerprint,
    );
  });

  it("strips credentials, including a password containing @", () => {
    assert.equal(
      normalizeUri("postgres://alice:hunter2@db.example.com:5432/app"),
      "postgres://db.example.com:5432/app",
    );
    assert.equal(
      normalizeUri("postgres://alice:p@ss@db.example.com/app"),
      "postgres://db.example.com:5432/app",
    );
  });

  it("applies the default port so it cannot be omitted to dodge a policy", () => {
    assert.equal(
      fingerprintUri("postgres://db.example.com/app"),
      fingerprintUri("postgres://DB.Example.com:5432/app"),
    );
  });

  it("ignores query parameters and trailing slashes", () => {
    assert.equal(
      fingerprintUri("postgres://h:5432/app?sslmode=require"),
      fingerprintUri("postgres://h:5432/app/"),
    );
  });

  it("keeps different databases and schemes distinct", () => {
    assert.notEqual(fingerprintUri("postgres://h/app"), fingerprintUri("postgres://h/other"));
    assert.notEqual(fingerprintUri("postgres://h/app"), fingerprintUri("mysql://h/app"));
  });

  it("handles IPv6 hosts with and without a port", () => {
    assert.equal(normalizeUri("postgres://[::1]:5432/app"), "postgres://[::1]:5432/app");
    assert.equal(normalizeUri("postgres://[::1]/app"), "postgres://[::1]:5432/app");
  });

  it("does not guess a port for an unknown scheme", () => {
    // Two different targets must not merge because a made-up default collapsed
    // them.
    assert.equal(normalizeUri("weirddb://h/a"), "weirddb://h:0/a");
    assert.notEqual(fingerprintUri("weirddb://h/a"), fingerprintUri("weirddb://h/b"));
  });
});

describe("encoding is strict where Node is lenient", () => {
  it("round-trips hex and base64url", () => {
    const bytes = new Uint8Array(Array.from({ length: 256 }, (_, i) => i));
    assert.deepEqual(hexDecode(hexEncode(bytes)), bytes);
    assert.deepEqual(b64urlDecode(b64urlEncode(bytes)), bytes);
  });

  it("matches the RFC 4648 url-alphabet vectors", () => {
    assert.equal(b64urlEncode(Buffer.from("f")), "Zg");
    assert.equal(b64urlEncode(Buffer.from("foobar")), "Zm9vYmFy");
    assert.equal(b64urlEncode(new Uint8Array([0xfb, 0xff])), "-_8");
  });

  it("refuses padding and the standard alphabet", () => {
    // Node's Buffer accepts all of these. Accepting two spellings of the same
    // bytes is how a protocol that hashes its own fields gets two digests for
    // one request.
    assert.throws(() => b64urlDecode("Zm8="), EncodingError);
    assert.throws(() => b64urlDecode("+_8"), EncodingError);
    assert.throws(() => b64urlDecode("Z"), EncodingError);
    assert.throws(() => hexDecode("abc"), EncodingError);
    assert.throws(() => hexDecode("zz"), EncodingError);
  });
});

describe("low-S", () => {
  it("accepts the boundary and refuses one above it", () => {
    const atHalf = new Uint8Array(64);
    atHalf[31] = 1; // r = 1
    // n/2 for P-256.
    hexDecode("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8").forEach(
      (b, i) => {
        atHalf[32 + i] = b;
      },
    );
    assert.equal(isLowS(atHalf), true);

    const over = Uint8Array.from(atHalf);
    over[63] += 1;
    assert.equal(isLowS(over), false);
  });

  it("refuses a zero component or a wrong length", () => {
    assert.equal(isLowS(new Uint8Array(64)), false);
    assert.equal(isLowS(new Uint8Array(63)), false);
  });
});
