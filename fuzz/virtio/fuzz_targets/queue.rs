#![no_main]

use libfuzzer_sys::fuzz_target;

// Roteiro de push, pop e escritas hostis do dispositivo na fila split.
fuzz_target!(|data: &[u8]| virtio_core::fuzz::queue(data));
