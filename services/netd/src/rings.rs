//! Os anéis de um socket (ADR 0068, item 4) sobre os anéis SPSC do `ostd`:
//! o de transmissão o `netd` cria e consome (memória da cota dele); o de
//! recepção o cliente cria e consome, e o `netd` o abre como produtor.

use onet::sock::{Error, RingError, Rings};
use ostd::kabi::{Handle, ObjectType, Rights};
use ostd::ring::{Consumer, Producer};

/// Bytes de dados de cada anel (o contrato `socket.oidl`).
pub const RING_BYTES: u32 = 8192;
/// `kind` do anel de transmissão (ADR 0036).
const TX_KIND: u16 = 0x0E10;
/// Bit que o `netd` sinaliza na `Notification` do cliente.
const RX_BIT: u64 = 1;
/// Onde os anéis dos sockets ficam mapeados: uma janela de 64 KiB por vaga,
/// o `tx` no início e o `rx` na metade.
const BASE_VA: u64 = 0x30_1000_0000;
const STRIDE: u64 = 0x1_0000;
const RX_OFF: u64 = 0x8000;

/// Os dois anéis e as capabilities que os seguram.
pub struct SockRings {
    tx: Consumer,
    tx_obj: Handle,
    rx: Producer,
    rx_obj: Handle,
    wake: Handle,
}

impl SockRings {
    /// Cria o `tx` (da cota `quota`, acordado por `ntfy`) e abre o `rx` que o
    /// cliente entregou (`rx_obj`, com a `Notification` `wake`) na vaga
    /// `slot`. Em erro nada fica preso, mas as duas capabilities do cliente
    /// continuam com o chamador.
    pub fn create(
        quota: Handle,
        ntfy: Handle,
        slot: usize,
        rx_obj: Handle,
        wake: Handle,
    ) -> Result<Self, Error> {
        let rx_ok = ostd::cap::info(rx_obj).is_ok_and(|i| {
            i.object_type == ObjectType::MemoryObject
                && i.rights
                    .contains(Rights::MAP | Rights::READ | Rights::WRITE)
        });
        let wake_ok = ostd::cap::info(wake).is_ok_and(|i| {
            i.object_type == ObjectType::Notification && i.rights.contains(Rights::SIGNAL)
        });
        if !rx_ok || !wake_ok {
            return Err(Error::BadRequest);
        }
        let va = BASE_VA + STRIDE * slot as u64;
        let tx_obj = ostd::cap::create(
            quota,
            ObjectType::MemoryObject,
            ostd::ring::object_bytes(RING_BYTES),
        )
        .map_err(|_| Error::Quota)?;
        let built = Consumer::create(tx_obj, va, RING_BYTES, TX_KIND, ntfy).and_then(|tx| {
            Producer::open(rx_obj, va + RX_OFF, RING_BYTES, wake, RX_BIT).map(|rx| (tx, rx))
        });
        if let Ok((tx, rx)) = built {
            return Ok(Self {
                tx,
                tx_obj,
                rx,
                rx_obj,
                wake,
            });
        }
        let _ = ostd::cap::delete(tx_obj);
        Err(Error::BadRequest)
    }

    /// O anel de transmissão, para o cliente mapear e escrever.
    pub fn tx_object(&self) -> Handle {
        self.tx_obj
    }
}

impl Drop for SockRings {
    fn drop(&mut self) {
        // Os mapeamentos saem junto com `tx` e `rx` (campos); as capabilities
        // ficam por conta daqui. O objeto do `tx` morre com a última cópia, a
        // do cliente.
        let _ = ostd::cap::delete(self.tx_obj);
        let _ = ostd::cap::delete(self.rx_obj);
        let _ = ostd::cap::delete(self.wake);
    }
}

impl Rings for SockRings {
    fn pop(&mut self, buf: &mut [u8]) -> Result<Option<(u16, usize)>, RingError> {
        self.tx.pop(buf).map_err(|_| RingError)
    }

    fn fits(&mut self, len: usize) -> bool {
        self.rx.fits(len)
    }

    fn push(&mut self, kind: u16, data: &[u8]) -> bool {
        self.rx.push(kind, data).is_ok()
    }
}
