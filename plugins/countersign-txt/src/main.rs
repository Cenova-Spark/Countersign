//! The native form: a process speaking line-delimited JSON-RPC on stdio, the
//! way `signetd` runs a pack installed from a plugin directory. Fine on your
//! own machine; a marketplace lists only the WebAssembly build.

fn main() -> std::io::Result<()> {
    countersign_pack::run_stdio(&countersign_txt::TxtPack)
}
