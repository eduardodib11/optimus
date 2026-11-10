//! Portas de E/S do x86 (ADR 0049): a `IoPortRange` que o `devmgr` cria
//! com a cota de dispositivo, ligada à thread que a usa.
//!
//! ```text
//! let faixa = port::create(cota_de_dispositivo, 0x70, 2)?;
//! port::bind(faixa)?;          // só a thread que chama
//! let cmos = Ports::new(0x70, 2);
//! cmos.write8(0, 0x0a);
//! let status_a = cmos.read8(1);
//! ```

use kabi::thread::{CONFIGURE_IO_PORTS, SELF};
use kabi::{Error, Handle, ObjectType, Syscall};

use crate::arch::port;
use crate::cap::{handle, raw};
use crate::sys::syscall;

/// Cria a faixa `base..base + count`. Só com a cota de dispositivo.
///
/// # Errors
///
/// `AccessDenied` com cota comum; `InvalidArgument` para faixa vazia,
/// além de 0xffff ou com portas do kernel.
pub fn create(device_quota: Handle, base: u16, count: u16) -> Result<Handle, Error> {
    let ty = ObjectType::IoPortRange.to_raw();
    let args = [
        raw(device_quota),
        ty,
        u64::from(base),
        u64::from(count),
        0,
        0,
    ];
    let [h, ..] = syscall(Syscall::ObjCreate, args)?;
    handle(h)
}

/// Liga a faixa à thread que chama: daí em diante ela usa `in` e `out`
/// nessas portas.
///
/// # Errors
///
/// `Busy` com 4 faixas já ligadas; `AccessDenied` sem `READ` e `WRITE`.
pub fn bind(range: Handle) -> Result<(), Error> {
    let args = [SELF, 0, 0, 0, raw(range), CONFIGURE_IO_PORTS];
    syscall(Syscall::ThreadConfigure, args).map(|_| ())
}

/// Tira todas as faixas da thread que chama.
///
/// # Errors
///
/// Os do kernel.
pub fn unbind_all() -> Result<(), Error> {
    let args = [SELF, 0, 0, 0, 0, CONFIGURE_IO_PORTS];
    syscall(Syscall::ThreadConfigure, args).map(|_| ())
}

/// Acesso a `count` portas a partir de `base`, já ligadas com [`bind`].
/// Os deslocamentos são conferidos: um fora da faixa entra em pânico em vez
/// de tocar outra porta ligada.
#[derive(Debug, Clone, Copy)]
pub struct Ports {
    base: u16,
    count: u16,
}

impl Ports {
    /// As portas `base..base + count`.
    #[must_use]
    pub const fn new(base: u16, count: u16) -> Self {
        Self { base, count }
    }

    fn port(self, offset: u16, width: u16) -> u16 {
        assert!(
            offset.checked_add(width).is_some_and(|e| e <= self.count),
            "porta fora da faixa"
        );
        self.base + offset
    }

    /// Lê 8 bits em `offset`.
    #[must_use]
    pub fn read8(self, offset: u16) -> u8 {
        port::inb(self.port(offset, 1))
    }

    /// Escreve 8 bits em `offset`.
    pub fn write8(self, offset: u16, v: u8) {
        port::outb(self.port(offset, 1), v);
    }

    /// Lê 16 bits em `offset`.
    #[must_use]
    pub fn read16(self, offset: u16) -> u16 {
        port::inw(self.port(offset, 2))
    }

    /// Escreve 16 bits em `offset`.
    pub fn write16(self, offset: u16, v: u16) {
        port::outw(self.port(offset, 2), v);
    }

    /// Lê 32 bits em `offset`.
    #[must_use]
    pub fn read32(self, offset: u16) -> u32 {
        port::inl(self.port(offset, 4))
    }

    /// Escreve 32 bits em `offset`.
    pub fn write32(self, offset: u16, v: u32) {
        port::outl(self.port(offset, 4), v);
    }
}
