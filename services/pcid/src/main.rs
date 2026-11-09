//! `pcid` (ADR 0043; T-402): processo de usuário que só tem a janela ECAM
//! (`kernel:ecam`). Mapeia um barramento por vez (1 MiB), varre tudo com
//! [`opci::scan`] e escreve cada função no log no formato do `lspci -n`.
//!
//! Não liga bus master (item 4) e não cria objetos de MMIO: os nós vão ao
//! `devmgr` (ADR 0042), que entrega os BARs ao driver casado.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::kabi::Handle;
use ostd::kabi::vm::WRITE;
use ostd::rt::Start;
use ostd::svc::Session;
use ostd::vm::{Mapping, SELF};

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;
/// Onde o barramento atual fica mapeado.
const BUS_VA: u64 = 0x20_0000_0000;
/// Bytes de configuração de um barramento (32 dispositivos × 8 funções ×
/// 4 KiB).
const BUS_BYTES: u64 = 1 << 20;

fn hash(text: &[u8]) -> u32 {
    let h = optcrypt::blake3::hash(text);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// A janela ECAM, com um barramento mapeado de cada vez.
struct Ecam {
    object: Handle,
    /// Barramento mapeado; `(bus, None)` lembra que ele não mapeia.
    current: Option<(u8, Option<Mapping>)>,
}

impl Ecam {
    /// O mapeamento do barramento `bus`, trocando o anterior.
    fn bus(&mut self, bus: u8) -> Option<&mut Mapping> {
        if self.current.as_ref().is_none_or(|(b, _)| *b != bus) {
            self.current = None;
            let offset = u64::from(bus) * BUS_BYTES;
            let map = Mapping::new_at(SELF, self.object, BUS_VA, offset, BUS_BYTES, WRITE).ok();
            self.current = Some((bus, map));
        }
        self.current.as_mut().and_then(|(_, m)| m.as_mut())
    }
}

/// Deslocamento de `offset` da função `bdf` dentro do barramento dela.
fn at(bdf: opci::Bdf, offset: u16) -> usize {
    let within = bdf.ecam_offset() & (BUS_BYTES - 1);
    usize::try_from(within).unwrap_or(usize::MAX) + usize::from(offset & 0xFFC)
}

impl opci::Config for Ecam {
    fn read(&mut self, bdf: opci::Bdf, offset: u16) -> u32 {
        self.bus(bdf.bus)
            .and_then(|m| m.read32(at(bdf, offset)))
            .unwrap_or(u32::MAX)
    }

    fn write(&mut self, bdf: opci::Bdf, offset: u16, value: u32) {
        if let Some(m) = self.bus(bdf.bus) {
            m.write32(at(bdf, offset), value);
        }
    }
}

/// Varre os barramentos que a janela cobre (um barramento fora dela não
/// mapeia e lê como ausente) e devolve quantas funções achou.
fn run(ecam: Handle) -> usize {
    let mut cfg = Ecam {
        object: ecam,
        current: None,
    };
    let mut count = 0;
    opci::scan(&mut cfg, u8::MAX, |f| {
        ostd::debug::print_fmt(format_args!("pcid: {f}"));
        count += 1;
    });
    count
}

fn main(start: Start) -> ! {
    let Ok(mut s) = Session::start(start.args) else {
        ostd::thread::exit()
    };
    let kernel_cap = |name: &[u8]| {
        s.boot
            .caps()
            .iter()
            .find(|c| c.kind == KIND_KERNEL && c.name_hash == hash(name))
            .map(|c| Handle::from_raw(c.handle))
    };
    if let Some(log) = kernel_cap(b"debug") {
        ostd::debug::set_log(log);
    }
    let Some(ecam) = kernel_cap(b"ecam") else {
        ostd::debug::print("pcid: sem kernel:ecam");
        ostd::thread::exit()
    };
    let n = run(ecam);
    ostd::debug::print_fmt(format_args!("pcid: {n} funções"));
    // Até o `devmgr` existir não há a quem publicar: avisa `ready` e sai
    // (`restart = "never"`). Esperar numa notificação da própria tabela
    // prenderia o processo num ciclo thread ↔ `CapSpace` depois do fim.
    let _ = s.ready();
    ostd::thread::exit()
}
