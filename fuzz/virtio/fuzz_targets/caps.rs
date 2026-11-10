#![no_main]

use libfuzzer_sys::fuzz_target;

// O espaço de configuração PCI vem do dispositivo: nunca pode dar pânico.
fuzz_target!(|data: &[u8]| virtio_core::fuzz::caps(data));
