//! Primitivas de driver (ADR 0042, item 4; ADR 0044): MMIO, vetores de
//! MSI/MSI-X e DMA. Quem tem a cota de dispositivo (o `devmgr`) cria os
//! objetos; o driver recebe só o que é do nó dele.

use kabi::{Error, Handle, ObjectType, Syscall};

use crate::cap::{handle, raw};
use crate::sys::syscall;

/// `MemoryObject` de MMIO com `bytes` a partir do físico `base` (T-402),
/// mapeado sem cache. Só com a cota de dispositivo.
///
/// # Errors
///
/// `AccessDenied` com cota comum; `InvalidArgument` para faixa recusada.
pub fn mmio(device_quota: Handle, base: u64, bytes: u64) -> Result<Handle, Error> {
    let ty = ObjectType::MemoryObject.to_raw();
    let args = [raw(device_quota), ty, bytes, kabi::mem::DEVICE, base, 0];
    let [h, ..] = syscall(Syscall::ObjCreate, args)?;
    handle(h)
}

/// Um vetor de MSI ou MSI-X (T-404).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Msi {
    /// O `Interrupt`: ligar com `obj_bind_notify` e confirmar com `irq_ack`.
    pub irq: Handle,
    /// Endereço que o dispositivo escreve (entrada da tabela de MSI-X ou
    /// capability de MSI).
    pub address: u64,
    /// Dado que o dispositivo escreve.
    pub data: u32,
}

/// Aloca um vetor de MSI ou MSI-X para a função `bdf` (`bus << 8 | dev
/// << 3 | fn`), que é a única que consegue dispará-lo quando o kernel
/// remapeia interrupções. Só com a cota de dispositivo.
///
/// # Errors
///
/// `AccessDenied` com cota comum; `Busy` sem vetor livre.
pub fn msi(device_quota: Handle, bdf: u16) -> Result<Msi, Error> {
    let ty = ObjectType::Interrupt.to_raw();
    let source = kabi::irq::SOURCE | u64::from(bdf);
    let args = [raw(device_quota), ty, 0, 0, source, 0];
    let [h, address, data] = syscall(Syscall::ObjCreate, args)?;
    Ok(Msi {
        irq: handle(h)?,
        address,
        data: u32::try_from(data).map_err(|_| Error::InvalidArgument)?,
    })
}

/// `dma_map`: `len` bytes de `object` a partir de `offset` em `iova` no
/// domínio; devolve o endereço que o dispositivo usa (`iova` com IOMMU, o
/// físico sem ela).
///
/// # Errors
///
/// Os do kernel (`InvalidArgument` para faixa inválida ou sobreposta,
/// `NotSupported` para objeto `LAZY`).
pub fn dma_map(
    domain: Handle,
    object: Handle,
    iova: u64,
    offset: u64,
    len: u64,
    write: bool,
) -> Result<u64, Error> {
    let flags = kabi::dma::READ | if write { kabi::dma::WRITE } else { 0 };
    let args = [raw(domain), raw(object), iova, offset, len, flags];
    syscall(Syscall::DmaMap, args).map(|[a, ..]| a)
}

/// `dma_unmap` do mapeamento que começa em `iova` com `len` bytes.
///
/// # Errors
///
/// `InvalidArgument` se não houver mapeamento exatamente ali.
pub fn dma_unmap(domain: Handle, iova: u64, len: u64) -> Result<(), Error> {
    let args = [raw(domain), 0, iova, 0, len, kabi::dma::UNMAP];
    syscall(Syscall::DmaMap, args).map(drop)
}

/// `dma_attach` (`attach`) ou `dma_detach` do dispositivo `bdf` (só o
/// `devmgr`, que tem `BIND`).
///
/// # Errors
///
/// `AccessDenied` sem `BIND`; `Busy` se `bdf` está noutro domínio.
pub fn dma_bind(domain: Handle, bdf: u16, attach: bool) -> Result<(), Error> {
    let flags = if attach {
        kabi::dma::ATTACH
    } else {
        kabi::dma::DETACH
    };
    let args = [raw(domain), 0, u64::from(bdf), 0, 0, flags];
    syscall(Syscall::DmaMap, args).map(drop)
}

/// `irq_ack`: o driver terminou de atender o `Interrupt`, que volta a
/// sinalizar (um disparo guardado sinaliza já).
///
/// # Errors
///
/// `AccessDenied` sem `ACK`.
pub fn irq_ack(irq: Handle) -> Result<(), Error> {
    syscall(Syscall::IrqAck, [raw(irq), 0, 0, 0, 0, 0]).map(drop)
}
