//! The WebAssembly pack ABI — the guest half.
//!
//! A pack the marketplace distributes is a WebAssembly module that **imports
//! nothing**. Not a WASI command with an empty capability set: a module with an
//! empty import section, which cannot name a syscall to ask for. That is the
//! whole sandbox, and it is why a public directory of classifiers that see
//! production SQL is acceptable at all (pack protocol §5).
//!
//! The protocol does not change. A host still sends the line-delimited
//! JSON-RPC messages from `spec/pack-protocol-v1.md`; instead of writing them
//! to a pipe it writes each one into the module's memory and calls one export,
//! and reads the response line back out. [`crate::handle_line`] — the same
//! function the stdio harness runs — answers it.
//!
//! # The exports
//!
//! ```text
//! memory                                  the module's linear memory
//! countersign_alloc(len: u32) -> u32       reserve `len` bytes; returns a pointer
//! countersign_call(ptr: u32, len: u32) -> u64
//!                                          one request line in; `(ptr << 32) | len`
//!                                          of one response line out. Takes
//!                                          ownership of the request buffer.
//! countersign_free(ptr: u32, len: u32)    release a response buffer
//! ```
//!
//! Pack authors do not write any of this. [`export_pack!`] emits it around a
//! [`Pack`](crate::Pack) implementation:
//!
//! ```ignore
//! // lib.rs of a pack crate, built with `--target wasm32-unknown-unknown`
//! #[cfg(target_arch = "wasm32")]
//! countersign_pack::export_pack!(MyPack);
//! ```
//!
//! The `unsafe` the ABI needs — turning pointers back into `Vec`s — expands
//! inside the pack's own crate, so this crate keeps `#![forbid(unsafe_code)]`
//! and a pack author can see every unsafe line they are shipping.

/// Emit the WebAssembly exports for a pack.
///
/// `$pack` is an expression yielding something that implements
/// [`Pack`](crate::Pack) — a unit struct literal is the usual case. It is
/// constructed once per call, which is what a pure classifier wants anyway.
#[macro_export]
macro_rules! export_pack {
    ($pack:expr) => {
        /// Reserve a buffer the host will write a request line into.
        #[no_mangle]
        pub extern "C" fn countersign_alloc(len: u32) -> u32 {
            let mut buffer: ::std::vec::Vec<u8> = ::std::vec::Vec::with_capacity(len as usize);
            let ptr = buffer.as_mut_ptr();
            // The host owns this until it hands it back through
            // `countersign_call`, which reconstructs the Vec and drops it.
            ::std::mem::forget(buffer);
            ptr as u32
        }

        /// Answer one JSON-RPC request line with one response line.
        #[no_mangle]
        pub extern "C" fn countersign_call(ptr: u32, len: u32) -> u64 {
            // SAFETY: `ptr`/`len` came from `countersign_alloc(len)` and the
            // host wrote exactly `len` bytes. Reconstructing the Vec with
            // capacity == len returns ownership so the request buffer is freed
            // when this function returns.
            let request = unsafe {
                ::std::vec::Vec::from_raw_parts(ptr as *mut u8, len as usize, len as usize)
            };
            let line = ::std::string::String::from_utf8_lossy(&request);
            let response = $crate::handle_line(&$pack, &line);
            let mut out: ::std::vec::Vec<u8> = $crate::serde_json::to_vec(&response)
                .unwrap_or_else(|_| b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"could not serialize response\"}}".to_vec());
            out.shrink_to_fit();
            let out_len = out.len() as u32;
            let out_ptr = out.as_mut_ptr() as u32;
            // The host reads it, then returns it through `countersign_free`.
            ::std::mem::forget(out);
            ((out_ptr as u64) << 32) | out_len as u64
        }

        /// Release a response buffer the host has finished reading.
        #[no_mangle]
        pub extern "C" fn countersign_free(ptr: u32, len: u32) {
            // SAFETY: `ptr`/`len` are exactly what `countersign_call` returned
            // after `shrink_to_fit`, so capacity == len and the Vec is whole.
            drop(unsafe {
                ::std::vec::Vec::from_raw_parts(ptr as *mut u8, len as usize, len as usize)
            });
        }
    };
}

/// The export names, shared with the host so the two cannot drift.
pub mod exports {
    pub const MEMORY: &str = "memory";
    pub const ALLOC: &str = "countersign_alloc";
    pub const CALL: &str = "countersign_call";
    pub const FREE: &str = "countersign_free";
}
