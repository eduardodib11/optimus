//! `drvteste` (ADR 0042; T-401): driver de teste do `devmgr`, casado com o
//! dispositivo `edu` do QEMU pelo `[match]` do manifesto. É o aceite de
//! ponta a ponta do M4: o driver só tem o que o `devmgr` deu (`bar0`,
//! `irq0` e `dma`) e com isso
//!
//! 1. lê o registrador de identificação pelo MMIO;
//! 2. faz DMA de ida e volta por uma página própria mapeada no domínio, com
//!    a MSI de fim de DMA acordando a notificação;
//! 3. na primeira partida, pede um DMA para uma IOVA fora do domínio, que a
//!    IOMMU barra (o kernel registra a falta), e fica esperando: o `devmgr`
//!    o contém e o parte de novo (ADR 0051; T-422). A cópia `dma` leva o
//!    `badge` `partida + 1`; na segunda partida o driver só confirma que o
//!    DMA válido funciona e termina bem.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::kabi::vm::WRITE;
use ostd::kabi::{Error, Handle, ObjectType, timer};
use ostd::rt::Start;
use ostd::svc::Session;
use ostd::vm::{Mapping, SELF};

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;
/// `kind` de um recurso de dispositivo.
const KIND_DEV: u8 = 3;
/// Onde o BAR 0 e a página de DMA ficam mapeados.
const BAR_VA: u64 = 0x20_0000_0000;
const DMA_VA: u64 = 0x20_0010_0000;
/// IOVA da página de DMA e uma IOVA fora do domínio.
const IOVA: u64 = 0x10_0000;
const OUTSIDE: u64 = 0x20_0000;
/// Buffer interno do `edu`.
const EDU_BUF: u32 = 0x4_0000;
/// Bytes de cada DMA.
const LEN: usize = 64;
const LEN32: u32 = 64;
/// Bits da notificação: a MSI e o prazo.
const IRQ_BIT: u64 = 1;
const TIMEOUT_BIT: u64 = 2;

fn hash(text: &[u8]) -> u32 {
    let h = optcrypt::blake3::hash(text);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// O `edu` e o que o driver usa para falar com ele.
struct Edu {
    regs: Mapping,
    irq: Handle,
    ntfy: Handle,
    timer: Handle,
}

impl Edu {
    fn write(&mut self, off: usize, value: u32) {
        self.regs.write32(off, value);
    }

    /// Pede o DMA de [`LEN`] bytes entre `iova` e o buffer do `edu`, com
    /// MSI no fim, sem esperar.
    fn start_dma(&mut self, iova: u64, to_ram: bool) -> Result<(), Error> {
        let iova = u32::try_from(iova).map_err(|_| Error::InvalidArgument)?;
        let (src, dst) = if to_ram {
            (EDU_BUF, iova)
        } else {
            (iova, EDU_BUF)
        };
        self.write(0x80, src);
        self.write(0x88, dst);
        self.write(0x90, LEN32);
        self.write(0x98, 1 | if to_ram { 2 } else { 0 } | 4);
        Ok(())
    }

    /// [`start_dma`](Self::start_dma) e espera a MSI. `true` se ela chegou
    /// antes do prazo de 1 s.
    fn dma(&mut self, iova: u64, to_ram: bool) -> Result<bool, Error> {
        self.start_dma(iova, to_ram)?;
        ostd::cap::arm_timer(
            self.timer,
            self.ntfy,
            TIMEOUT_BIT,
            1_000_000_000,
            0,
            timer::RELATIVE,
        )?;
        let bits = ostd::cap::ntfy_wait(self.ntfy)?;
        ostd::cap::disarm_timer(self.timer, self.ntfy)?;
        // Confirma no `edu` (0x100 é o bit do fim de DMA) e no kernel.
        self.write(0x64, 0x100);
        ostd::dev::irq_ack(self.irq)?;
        Ok(bits & IRQ_BIT != 0)
    }
}

fn run(s: &Session, quota: Handle) -> Result<(), &'static str> {
    let dev = |name: &[u8]| {
        s.boot
            .caps()
            .iter()
            .find(|c| c.kind == KIND_DEV && c.name_hash == hash(name))
            .map(|c| Handle::from_raw(c.handle))
    };
    let (Some(bar), Some(irq), Some(domain)) = (dev(b"bar0"), dev(b"irq0"), dev(b"dma")) else {
        return Err("faltou bar0, irq0 ou dma");
    };
    let regs = Mapping::new(SELF, bar, BAR_VA, 4096, WRITE).map_err(|_| "mapear o BAR 0")?;
    if regs.read32(0) != Some(0x0100_00ed) {
        return Err("identificação do edu");
    }
    let ntfy = ostd::cap::create(quota, ObjectType::Notification, 0).map_err(|_| "notificação")?;
    let timer = ostd::cap::create(quota, ObjectType::Timer, 0).map_err(|_| "timer")?;
    ostd::cap::bind_notify(irq, ntfy, 0).map_err(|_| "ligar a MSI")?;
    let mut edu = Edu {
        regs,
        irq,
        ntfy,
        timer,
    };
    let page = ostd::cap::create(quota, ObjectType::MemoryObject, 4096).map_err(|_| "página")?;
    let mut buf = Mapping::new(SELF, page, DMA_VA, 4096, WRITE).map_err(|_| "mapear a página")?;
    // Sem IOMMU, `dma_map` devolve o físico, e é ele que o `edu` usa.
    let at = ostd::dev::dma_map(domain, page, IOVA, 0, 4096, true).map_err(|_| "dma_map")?;
    let bytes = buf.bytes_mut().ok_or("página só de leitura")?;
    for (i, b) in (0u8..).zip(bytes.iter_mut().take(LEN)) {
        *b = i.wrapping_mul(7) ^ 0x5a;
    }
    let ida = edu.dma(IOVA, false).map_err(|_| "DMA de ida")?;
    let volta = edu
        .dma(IOVA + LEN as u64, true)
        .map_err(|_| "DMA de volta")?;
    if !(ida && volta) {
        return Err("a MSI do fim de DMA não chegou");
    }
    let bytes = buf.bytes();
    if bytes[..LEN] != bytes[LEN..2 * LEN] {
        return Err("os bytes não voltaram iguais");
    }
    ostd::debug::print("drvteste: DMA e MSI pelo edu ok");
    // Partida depois de uma falta: sem DMA ruim desta vez (ADR 0051, item 5).
    let generation = ostd::cap::info(domain).map_or(1, |i| i.badge);
    if generation > 1 {
        ostd::debug::print("drvteste: reiniciado pelo devmgr, DMA válido ok");
        return Ok(());
    }
    // Fora do domínio: a IOMMU barra e o kernel registra a falta. Sem
    // IOMMU o DMA escreveria na memória física de verdade, então não vai.
    if at == IOVA {
        // O texto sai antes: o `devmgr` pode parar o driver durante o DMA.
        ostd::debug::print("drvteste: DMA fora do domínio pedido");
        edu.start_dma(OUTSIDE, true)
            .map_err(|_| "pedir o DMA ruim")?;
        // Quem fez DMA fora do domínio é contido: o `devmgr` o para e o
        // parte de novo. Passar de 5 s aqui é falha.
        ostd::cap::arm_timer(timer, ntfy, TIMEOUT_BIT, 5_000_000_000, 0, timer::RELATIVE)
            .map_err(|_| "armar o prazo de contenção")?;
        let bits = ostd::cap::ntfy_wait(ntfy).map_err(|_| "esperar a contenção")?;
        if bits & TIMEOUT_BIT != 0 {
            return Err("não foi contido em 5 s");
        }
    }
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
        .find(|c| c.kind == KIND_KERNEL && c.name_hash == hash(b"debug"))
    {
        ostd::debug::set_log(Handle::from_raw(c.handle));
    }
    let quota = Handle::from_raw(s.boot.quota().unwrap_or(0));
    let _ = s.ready();
    if let Err(e) = run(&s, quota) {
        ostd::debug::print_fmt(format_args!("drvteste: falhou: {e}"));
    }
    ostd::thread::exit()
}
