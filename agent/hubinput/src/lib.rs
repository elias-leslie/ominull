//! Hub-input parsing and signature verification for the C agent. Everything the
//! hub can put in front of the agent is read here, in safe Rust with no
//! allocation; `ffi` is the only module with unsafe code.
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

mod abi;
mod b64;
mod cert;
mod crypto;
mod ffi;
mod frame;
mod json;
mod offers;
mod payload;
mod scrape;
mod script;
mod tj;
mod trust;

#[cfg(not(test))]
#[allow(unsafe_code)]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    extern "C" {
        fn abort() -> !;
    }
    // SAFETY: libc's abort takes no arguments and never returns.
    unsafe { abort() }
}
