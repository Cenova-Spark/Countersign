// The browser globals the lib/ modules assume, provided for `node --test`.
// These modules ship to a browser; the test runner is the odd one out.
import { webcrypto } from 'node:crypto'

globalThis.crypto ??= webcrypto
globalThis.btoa ??= (s) => Buffer.from(s, 'binary').toString('base64')
globalThis.atob ??= (s) => Buffer.from(s, 'base64').toString('binary')
