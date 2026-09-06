//! The WebAssembly pack host — the host half of [`crate::wasm`].
//!
//! A marketplace pack is a module with an **empty import section**. This host
//! refuses anything else before instantiating it, so the sandbox is not a
//! capability set the host declined to grant; it is the absence of any way to
//! ask. No network, no filesystem, no clock, no environment — not because
//! they were withheld, but because the module cannot name them.
//!
//! What a hostile module can still do is run forever or allocate without
//! bound, and both are answered here: every call is metered in fuel and the
//! store's memory is capped, so a pack that will not finish degrades to the
//! fail-closed path in pack protocol §4.3 rather than to a hang in front of a
//! human.

use wasmi::{
    Config, Engine, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder, TrapCode,
    TypedFunc,
};

use crate::host::PackFailure;
use crate::wasm::exports;

/// The most linear memory a pack may grow to.
///
/// A classifier holds one statement and one answer. Sixty-four megabytes is
/// two orders of magnitude more than that needs and two orders less than would
/// let a module take the machine down.
pub const MAX_MEMORY_BYTES: usize = 64 << 20;

/// Fuel granted to a single `describe` or `classify` call.
///
/// Fuel counts executed instructions, so this is a deterministic bound where a
/// wall-clock timeout is not: the same statement exhausts it on every machine
/// or on none. Classifying a long SQL batch costs a few million units; this is
/// well above that and well below "the human gave up waiting".
pub const DEFAULT_FUEL_PER_CALL: u64 = 500_000_000;

struct Data {
    limits: StoreLimits,
}

/// One instantiated pack module.
///
/// Not `Send`-agnostic by accident: the store is single-threaded, and a host
/// keeps one of these per pack behind whatever synchronization it already has
/// for the pack's process-backed sibling.
pub struct WasmPack {
    store: Store<Data>,
    memory: Memory,
    alloc: TypedFunc<u32, u32>,
    call: TypedFunc<(u32, u32), u64>,
    free: TypedFunc<(u32, u32), ()>,
    fuel_per_call: u64,
}

impl std::fmt::Debug for WasmPack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmPack")
            .field("memory_bytes", &self.memory.data_size(&self.store))
            .field("fuel_per_call", &self.fuel_per_call)
            .finish()
    }
}

/// The imports a module declares, as `module.name`, without instantiating it.
///
/// A pack must have none, and [`WasmPack::instantiate`] refuses the first one
/// it sees. This is for telling a person *what* a module would reach for,
/// before they decide anything about it.
pub fn imports(bytes: &[u8]) -> Result<Vec<String>, PackFailure> {
    let module = Module::new(&Engine::default(), bytes)
        .map_err(|e| PackFailure::Spawn(format!("not a valid WebAssembly module: {e}")))?;
    Ok(module
        .imports()
        .map(|import| format!("{}.{}", import.module(), import.name()))
        .collect())
}

impl WasmPack {
    /// Validate, instantiate, and bind the exports.
    ///
    /// Fails before anything runs if the module imports so much as one
    /// function. That check is the sandbox; everything after it is a bound on
    /// how much CPU and memory a pure module may spend.
    pub fn instantiate(bytes: &[u8], fuel_per_call: u64) -> Result<Self, PackFailure> {
        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);

        let module = Module::new(&engine, bytes)
            .map_err(|e| PackFailure::Spawn(format!("not a valid WebAssembly module: {e}")))?;

        if let Some(import) = module.imports().next() {
            return Err(PackFailure::Spawn(format!(
                "module imports {}.{}, and a pack must import nothing — that is the sandbox",
                import.module(),
                import.name()
            )));
        }

        let limits = StoreLimitsBuilder::new()
            .memory_size(MAX_MEMORY_BYTES)
            .instances(1)
            .build();
        let mut store = Store::new(&engine, Data { limits });
        store.limiter(|data| &mut data.limits);
        store
            .set_fuel(fuel_per_call)
            .map_err(|e| PackFailure::Spawn(e.to_string()))?;

        let instance = Linker::<Data>::new(&engine)
            .instantiate_and_start(&mut store, &module)
            .map_err(|e| PackFailure::Spawn(format!("module would not start: {e}")))?;

        let missing = |what: &str| {
            PackFailure::Spawn(format!(
                "module does not export {what:?}; build the pack with countersign_pack::export_pack!"
            ))
        };
        let memory = instance
            .get_memory(&store, exports::MEMORY)
            .ok_or_else(|| missing(exports::MEMORY))?;
        let alloc = instance
            .get_typed_func::<u32, u32>(&store, exports::ALLOC)
            .map_err(|_| missing(exports::ALLOC))?;
        let call = instance
            .get_typed_func::<(u32, u32), u64>(&store, exports::CALL)
            .map_err(|_| missing(exports::CALL))?;
        let free = instance
            .get_typed_func::<(u32, u32), ()>(&store, exports::FREE)
            .map_err(|_| missing(exports::FREE))?;

        Ok(Self {
            store,
            memory,
            alloc,
            call,
            free,
            fuel_per_call,
        })
    }

    /// Send one JSON-RPC request line, get one response line back.
    pub fn call_line(&mut self, line: &str) -> Result<String, PackFailure> {
        // Fresh fuel per call: a budget for this question, not a lifetime
        // allowance a chatty host could exhaust on the pack's behalf.
        self.store
            .set_fuel(self.fuel_per_call)
            .map_err(|e| PackFailure::Crashed(e.to_string()))?;

        let len = u32::try_from(line.len())
            .map_err(|_| PackFailure::Malformed("request line exceeds 4 GiB".into()))?;
        let ptr = self
            .alloc
            .call(&mut self.store, len)
            .map_err(|e| self.classify_error(e))?;
        self.memory
            .write(&mut self.store, ptr as usize, line.as_bytes())
            .map_err(|e| PackFailure::Crashed(format!("could not write request: {e}")))?;

        let packed = self
            .call
            .call(&mut self.store, (ptr, len))
            .map_err(|e| self.classify_error(e))?;
        let out_ptr = (packed >> 32) as u32;
        let out_len = (packed & 0xffff_ffff) as u32;

        let mut buffer = vec![0u8; out_len as usize];
        self.memory
            .read(&self.store, out_ptr as usize, &mut buffer)
            .map_err(|e| PackFailure::Malformed(format!("response pointer out of bounds: {e}")))?;
        // Failing to free is the module's leak, not the host's problem; the
        // answer has already been copied out.
        let _ = self.free.call(&mut self.store, (out_ptr, out_len));

        String::from_utf8(buffer).map_err(|_| PackFailure::Malformed("response is not UTF-8".into()))
    }

    fn classify_error(&self, error: wasmi::Error) -> PackFailure {
        if error.as_trap_code() == Some(TrapCode::OutOfFuel) {
            return PackFailure::Exhausted {
                fuel: self.fuel_per_call,
            };
        }
        PackFailure::Crashed(format!("module trapped: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest module there is: a header and nothing else.
    const EMPTY: &[u8] = b"\0asm\x01\0\0\0";

    /// A module whose whole content is one import, `env.f: () -> ()`. Written
    /// by hand so the test does not depend on a toolchain: the type section
    /// declares one empty function type, the import section names it.
    const IMPORTS_ONE: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic, version
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section: one () -> ()
        0x02, 0x09, 0x01, 0x03, b'e', b'n', b'v', 0x01, b'f', 0x00, 0x00, // import env.f
    ];

    #[test]
    fn imports_are_listed_and_are_what_instantiation_refuses() {
        assert_eq!(imports(EMPTY).unwrap(), Vec::<String>::new());
        assert_eq!(imports(IMPORTS_ONE).unwrap(), vec!["env.f".to_string()]);
        assert!(imports(b"not wasm").is_err());

        // The list is for telling a person; the refusal is the sandbox.
        let refused = WasmPack::instantiate(IMPORTS_ONE, DEFAULT_FUEL_PER_CALL).err().unwrap();
        assert!(refused.to_string().contains("imports env.f"), "{refused}");
        // And a module that imports nothing but exports nothing is refused
        // for the other reason: it is not a pack.
        let not_a_pack = WasmPack::instantiate(EMPTY, DEFAULT_FUEL_PER_CALL).err().unwrap();
        assert!(not_a_pack.to_string().contains("does not export"), "{not_a_pack}");
    }
}
