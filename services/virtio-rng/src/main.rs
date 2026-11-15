//! `virtio-rng` (T-414; ADR 0042 e 0046): driver de entropia virtio moderno
//! em processo de usuário. Só tem o que o `devmgr` deu (`cfg`, o BAR das
//! capabilities, `irq0` e `dma`) e com isso negocia o transporte, monta a
//! fila 0 e lê bytes do dispositivo.
//!
//! Os bytes do dispositivo são uma fonte a mais, nunca a única: não
//! substituem a entropia do kernel (`optboot` e `krand`), só se somam a ela.
//! Por isso o driver confere que o dispositivo responde com bytes que variam
//! antes de entregá-los. Depois serve o contrato `EntropySource` gerado do
//! `idl/optimus/entropy.oidl` (T-514; ADR 0054), com o teste de repetição do
//! item 3: um bloco igual ao anterior, ou de bytes todos iguais, reprova o
//! driver, que passa a devolver `Failed` até reiniciar.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

use core::cell::RefCell;

use ostd::ipc::{self, Message};
use ostd::kabi::{Error, Handle, ObjectType};
use ostd::rt::Start;
use ostd::svc::Session;
use ostd::vm::{Mapping, SELF};
use vdrv::{Dma, Irq, Regs};
use virtio_core::{F_ACCESS_PLATFORM, Queue, Seg, Transport};

mod entropy_servidor;

use entropy_servidor::{Contexto, EntropySource, ID_ENTROPYSOURCE, RngError};

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;
/// Onde o `cfg`, o BAR e as páginas de DMA ficam mapeados.
const CFG_VA: u64 = 0x20_0000_0000;
const BAR_VA: u64 = 0x20_0010_0000;
const QUEUE_VA: u64 = 0x20_0020_0000;
const BUF_VA: u64 = 0x20_0030_0000;
/// IOVAs das páginas da fila e do buffer.
const QUEUE_IOVA: u64 = 0x10_0000;
const BUF_IOVA: u64 = 0x10_1000;
/// Descritores da fila 0.
const QUEUE_SIZE: usize = 8;
/// Bytes pedidos a cada leitura.
const CHUNK: usize = 64;
/// Prazo de uma leitura.
const TIMEOUT_NS: u64 = 1_000_000_000;

/// O dispositivo de entropia em uso.
struct Rng<'a> {
    queue: Queue<Dma<'a>, QUEUE_SIZE>,
    notify: Regs<'a>,
    notify_at: usize,
    buf: Mapping,
    buf_iova: u64,
    irq: Irq,
}

impl Rng<'_> {
    /// Lê até [`CHUNK`] bytes do dispositivo em `out`; devolve quantos.
    fn read(&mut self, out: &mut [u8; CHUNK]) -> Result<usize, &'static str> {
        let seg = Seg {
            addr: self.buf_iova,
            len: CHUNK as u32,
            write: true,
        };
        self.queue.push(&[seg]).map_err(|_| "push na fila")?;
        virtio_core::Mmio::write16(&self.notify, self.notify_at, 0);
        self.irq.wait(TIMEOUT_NS)?;
        let chain = match self.queue.pop() {
            Ok(Some(c)) => c,
            Ok(None) => return Err("fila sem cadeia usada"),
            Err(_) => return Err("dispositivo devolveu cadeia inválida"),
        };
        let n = (chain.len as usize).min(CHUNK);
        out[..n].copy_from_slice(&self.buf.bytes()[..n]);
        Ok(n)
    }
}

/// O serviço: o dispositivo, o último bloco (para o teste de repetição) e a
/// saída da leitura atual.
struct Service<'a> {
    rng: Rng<'a>,
    prev: Option<[u8; CHUNK]>,
    out: [u8; CHUNK],
    failed: bool,
}

/// Teste de repetição simplificado (NIST SP 800-90B, 4.4.1): bloco igual ao
/// anterior ou de bytes todos iguais.
fn repeats(block: &[u8; CHUNK], prev: Option<&[u8; CHUNK]>) -> bool {
    block.iter().all(|&b| b == block[0]) || prev == Some(block)
}

impl EntropySource for Service<'_> {
    fn read(&mut self, _ctx: &Contexto, len: u8) -> Result<&[u8], RngError> {
        if self.failed {
            return Err(RngError::Failed);
        }
        let mut block = [0u8; CHUNK];
        let n = self.rng.read(&mut block).map_err(|_| RngError::Failed)?;
        // Só um bloco inteiro entra no teste; o dispositivo devolve menos
        // quando quer, e isso não é falha.
        if n == CHUNK && repeats(&block, self.prev.as_ref()) {
            self.failed = true;
            ostd::debug::print("virtio-rng: teste de saúde falhou");
            return Err(RngError::Failed);
        }
        if n == CHUNK {
            self.prev = Some(block);
        }
        self.out = block;
        Ok(&self.out[..n.min(usize::from(len))])
    }
}

/// Atende o contrato `EntropySource` em `ep` até o endpoint ser revogado.
fn serve(ep: Handle, quota: Handle, buf: &mut ipc::Buffer, svc: &mut Service<'_>) -> Error {
    let reply = match ostd::cap::create(quota, ObjectType::Reply, 0) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let (mut corpo, mut saida) = ([0u8; 16], [0u8; 96]);
    let mut rec = match ipc::recv(ep, reply, 0) {
        Ok(r) => r,
        Err(e) => return e,
    };
    loop {
        let ctx = Contexto { badge: rec.badge };
        let resp = if let Some((rotulo, w)) = entropy_servidor::despacha_entropy_source_palavras(
            svc,
            rec.msg.label,
            &rec.msg.words,
            &ctx,
        ) {
            Ok(Message::new(rotulo, &w))
        } else {
            match ipc::copia(buf, &rec.msg, &mut corpo) {
                Ok(n) => {
                    let entrada = entropy_servidor::Entrada {
                        rotulo: rec.msg.label,
                        badge: rec.badge,
                        corpo: &corpo[..n],
                        caps: &[],
                    };
                    match entropy_servidor::despacha_entropy_source(
                        svc,
                        0,
                        &entrada,
                        &mut saida,
                        &mut [],
                    ) {
                        Some(d) => ipc::monta(buf, d.rotulo, &saida[..d.corpo]),
                        None => Ok(Message::new(osvc::REPLY_BAD_MESSAGE, &[])),
                    }
                }
                Err(_) => Ok(Message::new(osvc::REPLY_BAD_MESSAGE, &[])),
            }
        };
        let Ok(resp) = resp else {
            return Error::InvalidArgument;
        };
        rec = match ipc::reply_recv(ep, reply, &resp, 0) {
            Ok(r) => r,
            Err(e) => return e,
        };
    }
}

/// Duas leituras têm que dar bytes e diferir uma da outra; um dispositivo
/// que devolve zeros ou sempre o mesmo não é fonte de entropia.
fn self_test(rng: &mut Rng<'_>) -> Result<u32, &'static str> {
    let (mut a, mut b) = ([0u8; CHUNK], [0u8; CHUNK]);
    let na = rng.read(&mut a)?;
    let nb = rng.read(&mut b)?;
    if na == 0 || nb == 0 {
        return Err("o dispositivo não devolveu bytes");
    }
    if a[..na].iter().all(|&x| x == 0) || a[..na] == b[..nb] {
        return Err("os bytes do dispositivo não variam");
    }
    let h = optcrypt::blake3::hash(&a[..na]);
    Ok(u32::from_le_bytes([h[0], h[1], h[2], h[3]]))
}

fn run(s: &mut Session, quota: Handle) -> Result<(), &'static str> {
    let (Some(irq), Some(domain)) = (vdrv::resource(s, b"irq0"), vdrv::resource(s, b"dma")) else {
        return Err("faltou irq0 ou dma");
    };
    let caps = vdrv::read_caps(s, CFG_VA)?;
    let bar_map = vdrv::map_bar(s, BAR_VA, &[caps.common, caps.notify, caps.isr])?;
    let queue_obj =
        ostd::cap::create(quota, ObjectType::MemoryObject, 4096).map_err(|_| "página da fila")?;
    let buf_obj =
        ostd::cap::create(quota, ObjectType::MemoryObject, 4096).map_err(|_| "página do buffer")?;
    let queue_map = RefCell::new(
        Mapping::new(SELF, queue_obj, QUEUE_VA, 4096, ostd::kabi::vm::WRITE)
            .map_err(|_| "mapear a fila")?,
    );
    let buf = Mapping::new(SELF, buf_obj, BUF_VA, 4096, ostd::kabi::vm::WRITE)
        .map_err(|_| "mapear o buffer")?;
    let queue_at = ostd::dev::dma_map(domain, queue_obj, QUEUE_IOVA, 0, 4096, true)
        .map_err(|_| "dma_map da fila")?;
    let buf_at = ostd::dev::dma_map(domain, buf_obj, BUF_IOVA, 0, 4096, true)
        .map_err(|_| "dma_map do buffer")?;
    // Com IOMMU o `dma_map` devolve a IOVA; o dispositivo precisa de
    // `ACCESS_PLATFORM` para endereçar por ela.
    let required = if queue_at == QUEUE_IOVA {
        F_ACCESS_PLATFORM
    } else {
        0
    };
    let mut transport = Transport::new(Regs::new(&bar_map, caps.common.offset as usize));
    transport
        .negotiate(F_ACCESS_PLATFORM, required)
        .map_err(|_| "negociar as features")?;
    let (queue, notify_off) = transport
        .setup_queue::<_, QUEUE_SIZE>(0, Dma::new(&queue_map, queue_at), 0)
        .map_err(|_| "montar a fila 0")?;
    let irq = Irq::new(quota, irq)?;
    transport.driver_ok();
    let notify_at =
        caps.notify.offset as usize + usize::from(notify_off) * caps.notify_multiplier as usize;
    let mut rng = Rng {
        queue,
        notify: Regs::new(&bar_map, 0),
        notify_at,
        buf,
        buf_iova: buf_at,
        irq,
    };
    let tag = self_test(&mut rng)?;
    ostd::debug::print_fmt(format_args!(
        "virtio-rng: bytes do dispositivo variam (BLAKE3 {tag:08x})"
    ));
    let ep = s
        .boot
        .provided(ID_ENTROPYSOURCE)
        .map(Handle::from_raw)
        .ok_or("descritor sem o endpoint do EntropySource")?;
    let mut svc = Service {
        rng,
        prev: None,
        out: [0; CHUNK],
        failed: false,
    };
    let e = serve(ep, quota, &mut s.buffer, &mut svc);
    ostd::debug::print_fmt(format_args!("virtio-rng: encerrado ({e:?})"));
    Ok(())
}

fn main(start: Start) -> ! {
    let Ok(mut s) = Session::start(start.args) else {
        ostd::thread::exit()
    };
    if let Some(c) = s
        .boot
        .caps()
        .iter()
        .find(|c| c.kind == KIND_KERNEL && c.name_hash == vdrv::hash(b"debug"))
    {
        ostd::debug::set_log(Handle::from_raw(c.handle));
    }
    let quota = Handle::from_raw(s.boot.quota().unwrap_or(0));
    let _ = s.ready();
    if let Err(e) = run(&mut s, quota) {
        ostd::debug::print_fmt(format_args!("virtio-rng: falhou: {e}"));
    }
    ostd::thread::exit()
}
