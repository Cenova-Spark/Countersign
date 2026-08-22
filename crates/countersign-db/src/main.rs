//! The `countersign-db` executable: a domain pack speaking the stdio protocol.
//!
//! Run by a host, not by a person. It reads line-delimited JSON-RPC on stdin and
//! writes responses on stdout, so anything printed to stdout that is not a
//! response corrupts the transport — diagnostics go to stderr.

use countersign_db::DbPack;
use countersign_pack::run_stdio;

fn main() -> std::io::Result<()> {
    run_stdio(&DbPack)
}
