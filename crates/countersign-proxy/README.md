# countersign-proxy

Sit in front of PostgreSQL and refuse statements nobody countersigned.

This is **posture C** — the only posture where the security claim fully holds.
In advisory mode an agent asks and then decides for itself whether to honour the
answer. Here it cannot: the database is on the other side of this process.

**The agent needs no integration and no awareness that Countersign exists.** It
issues a query, this blocks, a human's device lights up, they turn, the query
proceeds.

## Why a proxy instead of more integrations

You cannot enumerate the agents — new ones ship monthly and you will always be
behind. You *can* enumerate the databases. Everything eventually speaks one of
about ten wire protocols to a server, so one proxy covers an editor's assistant,
an unattended cron job, a cloud agent, and every tool that does not exist yet.

Integrations improve the quality of the prompt. The proxy provides the coverage.

## Running it

```bash
countersign-proxy \
  --listen   127.0.0.1:6432 \
  --upstream 127.0.0.1:5432 \
  --target   postgres://app@db.example.com/orders \
  --accept-test-keys
```

Point your client at `127.0.0.1:6432`. Nothing else changes.

`--target` is required and is the operator's statement about what sits behind
this proxy. It is fingerprinted so the daemon can label the environment, and so
the signature is bound to this target and no other — never anything a client
claimed about where it thinks it is.

`--accept-test-keys` is what makes a demo work at all, and is named after the
thing it lets in. Without hardware every signature comes from the published test
key, which a default verifier refuses.

## It verifies rather than trusts

The proxy asks `signetd` for an approval and then **checks the signature
itself**, against the exact statement it is about to forward and the exact
target it is about to forward to.

That is not redundant with the daemon having said "approved". It is what makes
this an enforcement point rather than a relay of someone else's opinion: the
same code path would accept an approval that arrived from anywhere, and would
refuse a forged one from the daemon it is talking to.

## What it inspects

| Message | Handling |
|---|---|
| `Query` (simple protocol) | SQL extracted and authorized |
| `Parse` (extended protocol) | SQL extracted and authorized |
| Everything else | Relayed byte for byte |

`Parse` matters more than it looks. Most real traffic is prepared statements — a
proxy that only watched `Query` would watch a `DROP TABLE` go past because the
driver used the extended protocol.

## Refusing politely

A refusal is an `ErrorResponse` with SQLSTATE `42501` (`insufficient_privilege`)
and a hint naming what would fix it, followed by `ReadyForQuery`.

Dropping the connection instead would read as a network fault and get retried.
An error the client understands stops it, and says why.

In the extended protocol a refusal is followed by discarding messages until
`Sync`, then reporting ready — imitating what the real server does, because a
client that never gets a reply waits forever.

## Failure is closed

No daemon reachable means nothing can be approved, so nothing is forwarded. A
proxy that waved statements through whenever its daemon was down would be
defeated by stopping the daemon, which is not a sophisticated attack.

## Known limitations

- **No TLS between client and proxy.** An `SSLRequest` is answered `N` and the
  client falls back to plaintext. Run it on loopback or inside a tunnel until
  that changes.
- **PostgreSQL only.** MySQL and MongoDB are the same shape and not written yet.
- **In-memory replay state.** Every request carries a fresh nonce so no two
  digests match, which makes replay within a session impossible. A durable
  counter store belongs here once approvals start arriving from somewhere other
  than the local daemon.
- **The registry is the published test key.** A real deployment loads a signed
  roster and trusts one authority key configured out of band — see
  [`spec/enrollment-v1.md`](../../spec/enrollment-v1.md).
