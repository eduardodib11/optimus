//! Motor do fuzzer estruturado da thread principal: o pool de handles e a
//! tabela de ações que escolhem argumentos aleatórios mas plausíveis para
//! cada syscall.

use ostd::kabi::ipc::{FLAG_NONBLOCK, MsgInfo, recv_target};
use ostd::kabi::sched::{CpuMask, SYS_INFO_CPUS};
use ostd::kabi::vm::{EXEC, PAGE_SIZE, WRITE};
use ostd::kabi::{Error, ObjectType, Rights, Syscall};

use crate::pool::{self, Entry, Pool};
use crate::rng::Rng;

/// Janela de endereços em que o fuzzer pode mexer no próprio espaço sem
/// tocar em código (`0x20_0000`), pilhas nem buffers de IPC.
const SCRATCH_LO: u64 = 0x1000_0000;
const SCRATCH_HI: u64 = 0x4000_0000;

/// Valores "interessantes" para um argumento cru.
const WILD: &[u64] = &[
    0,
    1,
    2,
    7,
    8,
    0xfff,
    PAGE_SIZE,
    PAGE_SIZE + 1,
    0x1000_0000,
    0x20_0000,
    0x7fff_ffff_f000,
    0x8000_0000_0000,
    0xffff_8000_0000_0000,
    0xffff_ffff_ffff_f000,
    u64::MAX,
    0xdead_beef,
    1 << 20,
    64 << 10,
];

/// Um valor cru para fuzzing: às vezes da lista [`WILD`], às vezes aleatório
/// puro, às vezes aleatório com poucos bits.
#[must_use]
pub fn wild(rng: &mut Rng) -> u64 {
    match rng.below(4) {
        0 => rng.pick(WILD),
        1 => rng.next(),
        2 => rng.next() & 0xffff_ffff,
        _ => rng.next() & ((1 << (rng.below(40) + 1)) - 1),
    }
}

/// Tipos de objeto que o fuzzer tenta criar (todos os que `obj_create`
/// aceita, mais alguns que ele recusa, para exercitar a recusa).
const TYPES: &[ObjectType] = &[
    ObjectType::MemoryQuota,
    ObjectType::AddressSpace,
    ObjectType::CapSpace,
    ObjectType::Thread,
    ObjectType::SchedContext,
    ObjectType::MemoryObject,
    ObjectType::Endpoint,
    ObjectType::Reply,
    ObjectType::Notification,
    ObjectType::Interrupt,
    ObjectType::IoPortRange,
    ObjectType::DmaDomain,
];

fn syscall(nr: Syscall, args: [u64; 6]) -> Result<[u64; 3], Error> {
    ostd::sys::syscall(nr, args)
}

/// Número de um tipo de objeto como `u8` (há no máximo 14 tipos).
#[must_use]
const fn ty8(t: ObjectType) -> u8 {
    #[allow(clippy::cast_possible_truncation, reason = "no máximo 14 tipos")]
    let n = t.number() as u8;
    n
}

/// O fuzzer estruturado.
pub struct Fuzzer {
    rng: Rng,
    pool: Pool,
    /// Handle da cota raiz.
    quota: u32,
    /// Handle do próprio `AddressSpace`.
    self_as: u32,
}

impl Fuzzer {
    /// Fuzzer com a semente `seed`, a cota `quota` e o espaço `self_as`.
    #[must_use]
    pub fn new(seed: u64, quota: u64, self_as: u64) -> Self {
        #[allow(clippy::cast_possible_truncation, reason = "handles são u32")]
        let (quota, self_as) = (quota as u32, self_as as u32);
        let mut pool = Pool::new();
        pool.add(Entry {
            raw: quota,
            ty: ty8(ObjectType::MemoryQuota),
            parent: 0,
            flags: pool::PRECIOUS,
        });
        pool.add(Entry {
            raw: self_as,
            ty: ty8(ObjectType::AddressSpace),
            parent: 0,
            flags: pool::PRECIOUS | pool::SELF_AS,
        });
        Self {
            rng: Rng::new(seed),
            pool,
            quota,
            self_as,
        }
    }

    /// Handles conhecidos vivos.
    #[must_use]
    pub fn live(&self) -> usize {
        self.pool.entries().len()
    }

    /// Um handle para passar como argumento: do pool, apagado há pouco ou
    /// lixo.
    fn some_handle(&mut self) -> u64 {
        match self.rng.below(8) {
            0..=4 => u64::from(self.pool.any(&mut self.rng)),
            5 => u64::from(self.pool.stale(&mut self.rng)),
            6 => self.rng.next() & 0xffff_ffff,
            _ => wild(&mut self.rng),
        }
    }

    /// Um endereço na janela de trabalho, alinhado ou não.
    fn scratch_addr(&mut self) -> u64 {
        let span = (SCRATCH_HI - SCRATCH_LO) / PAGE_SIZE;
        let page = SCRATCH_LO + self.rng.below(span) * PAGE_SIZE;
        if self.rng.chance(1, 4) {
            page + self.rng.below(PAGE_SIZE)
        } else {
            page
        }
    }

    /// Um comprimento pequeno, às vezes no limite.
    fn small_len(&mut self) -> u64 {
        match self.rng.below(4) {
            0 => 0,
            1 => PAGE_SIZE,
            2 => PAGE_SIZE * (1 + self.rng.below(16)),
            _ => self.rng.next(),
        }
    }

    /// Flags de `vm_map`/`vm_protect`: válidas (R, RW, RX) ou lixo.
    fn vm_flags(&mut self) -> u64 {
        match self.rng.below(5) {
            0 => 0,
            1 => WRITE,
            2 => EXEC,
            3 => WRITE | EXEC, // recusada (W^X)
            _ => self.rng.next(),
        }
    }

    /// Executa um passo: escolhe uma ação e a emite.
    pub fn step(&mut self) {
        // Com o pool quase cheio, puxa para destruir.
        if self.pool.full() && self.rng.chance(3, 4) {
            self.delete();
            return;
        }
        match self.rng.below(16) {
            0 | 1 => self.create(),
            2 => self.mint(),
            3 => self.delete(),
            4 => self.revoke(),
            5 => self.info(),
            6 => self.vm_map(),
            7 => self.vm_unmap(),
            8 => self.vm_protect(),
            9 => self.sched(),
            10 => self.notify(),
            11 => self.futex(),
            12 | 13 => self.ipc(),
            _ => {
                let _ = syscall(Syscall::ClockGet, [0; 6]);
            }
        }
    }

    fn create(&mut self) {
        let ty = self.rng.pick(TYPES);
        let args = match self.rng.below(4) {
            0 => 0,
            1 => PAGE_SIZE * (1 + self.rng.below(64)), // MemoryObject plausível
            2 => 1 << self.rng.below(40),              // cota filha plausível
            _ => wild(&mut self.rng),
        };
        let quota = if self.rng.chance(7, 8) {
            u64::from(self.quota)
        } else {
            self.some_handle()
        };
        if let Ok([h, ..]) = syscall(Syscall::ObjCreate, [quota, ty.to_raw(), args, 0, 0, 0]) {
            #[allow(clippy::cast_possible_truncation, reason = "handle é u32")]
            let raw = h as u32;
            // Nasce como raiz da árvore de derivação (parent 0).
            self.pool.add(Entry {
                raw,
                ty: ty8(ty),
                parent: 0,
                flags: 0,
            });
        }
    }

    fn mint(&mut self) {
        let src64 = self.some_handle();
        let mask = if self.rng.chance(1, 4) {
            self.rng.next()
        } else {
            u64::from(Rights::ALL.bits()) & self.rng.next()
        };
        let badge = if self.rng.chance(1, 2) {
            self.rng.next()
        } else {
            0
        };
        if let Ok([h, ..]) = syscall(Syscall::CapMint, [src64, mask, badge, 0, 0, 0]) {
            #[allow(clippy::cast_possible_truncation, reason = "handle é u32")]
            let (raw, src) = (h as u32, src64 as u32);
            let ty = self.pool.find(src64).map_or(pool::UNKNOWN, |e| e.ty);
            self.pool.add(Entry {
                raw,
                ty,
                parent: src,
                flags: 0,
            });
        }
    }

    fn delete(&mut self) {
        // Nunca apaga o que é precioso (cota, próprio espaço, nada da
        // auxiliar): isso derrubaria o fuzzer, não o kernel.
        let Some(h) = self.deletable() else {
            return;
        };
        if syscall(Syscall::CapDelete, [u64::from(h), 0, 0, 0, 0, 0]).is_ok() {
            self.pool.remove(h);
        }
    }

    fn revoke(&mut self) {
        let Some(h) = self.deletable() else {
            return;
        };
        if syscall(Syscall::CapRevoke, [u64::from(h), 0, 0, 0, 0, 0]).is_ok() {
            // Oráculo: a revogação apagou todos os descendentes de `h`.
            let mut doomed = [0u32; pool::CAP];
            let mut n = 0;
            for e in self.pool.entries() {
                if e.raw != h && self.pool.descends(e.raw, h) {
                    doomed[n] = e.raw;
                    n += 1;
                }
            }
            for &raw in &doomed[..n] {
                self.pool.remove(raw);
            }
        }
    }

    /// Um handle do pool que pode ser apagado (não precioso).
    fn deletable(&mut self) -> Option<u32> {
        let entries = self.pool.entries();
        let n = entries
            .iter()
            .filter(|e| e.flags & pool::PRECIOUS == 0)
            .count();
        if n == 0 {
            return None;
        }
        let k = usize::try_from(self.rng.below(n as u64)).unwrap_or(0);
        entries
            .iter()
            .filter(|e| e.flags & pool::PRECIOUS == 0)
            .nth(k)
            .map(|e| e.raw)
    }

    fn info(&mut self) {
        let h = self.some_handle();
        let _ = syscall(Syscall::CapInfo, [h, 0, 0, 0, 0, 0]);
    }

    fn vm_map(&mut self) {
        let aspace = self.pick_aspace();
        let object = self
            .pool
            .of_type(&mut self.rng, ty8(ObjectType::MemoryObject))
            .map_or_else(|| self.some_handle(), u64::from);
        let addr = self.map_addr(aspace);
        let offset = if self.rng.chance(3, 4) {
            0
        } else {
            self.small_len()
        };
        let len = self.small_len();
        let flags = self.vm_flags();
        let _ = syscall(Syscall::VmMap, [aspace, object, addr, offset, len, flags]);
    }

    fn vm_unmap(&mut self) {
        let aspace = self.pick_aspace();
        let addr = self.map_addr(aspace);
        let len = self.small_len();
        let _ = syscall(Syscall::VmUnmap, [aspace, addr, len, 0, 0, 0]);
    }

    fn vm_protect(&mut self) {
        let aspace = self.pick_aspace();
        let addr = self.map_addr(aspace);
        let len = self.small_len();
        let flags = self.vm_flags();
        let _ = syscall(Syscall::VmProtect, [aspace, addr, len, flags, 0, 0]);
    }

    /// Um `AddressSpace` alvo: o próprio (a maior parte; pelo handle ou por
    /// `aspace = 0`, ADR 0039) ou outro handle.
    fn pick_aspace(&mut self) -> u64 {
        if self.rng.chance(2, 3) {
            if self.rng.chance(1, 2) {
                ostd::kabi::vm::SELF
            } else {
                u64::from(self.self_as)
            }
        } else {
            self.some_handle()
        }
    }

    /// Endereço para uma operação de VM: na janela de trabalho se o alvo é
    /// o próprio espaço (para não se derrubar), senão qualquer um.
    fn map_addr(&mut self, aspace: u64) -> u64 {
        // No próprio espaço, só a janela de trabalho (não se derrubar);
        // em outro, às vezes a janela, às vezes lixo.
        let safe = aspace == ostd::kabi::vm::SELF || self.pool.flags(aspace) & pool::SELF_AS != 0;
        if safe || self.rng.chance(1, 2) {
            self.scratch_addr()
        } else {
            wild(&mut self.rng)
        }
    }

    fn sched(&mut self) {
        let (a, b) = (self.some_handle(), self.some_handle());
        match self.rng.below(5) {
            0 | 1 => {
                let budget = self.small_len();
                let period = self.small_len();
                let priority = self.rng.below(300);
                // Máscara de afinidade (T-325): às vezes nenhuma, às vezes
                // uma de verdade na pilha, às vezes um endereço qualquer; e
                // às vezes o `r9` reservado ligado.
                let mask = CpuMask([self.rng.next(), self.rng.next(), 0, self.rng.next()]);
                let r8 = match self.rng.below(4) {
                    0 => 0,
                    1 | 2 => core::ptr::from_ref(&mask).addr() as u64,
                    _ if self.rng.chance(1, 2) => self.scratch_addr(),
                    _ => wild(&mut self.rng),
                };
                let r9 = u64::from(self.rng.chance(1, 16));
                let args = [a, budget, period, priority, r8, r9];
                let _ = syscall(Syscall::SchedConfigure, args);
                core::hint::black_box(&mask);
            }
            2 | 3 => {
                let _ = syscall(Syscall::SchedBind, [a, b, 0, 0, 0, 0]);
            }
            _ => {
                let selector = if self.rng.chance(1, 2) {
                    SYS_INFO_CPUS
                } else {
                    wild(&mut self.rng)
                };
                let _ = syscall(Syscall::SysInfo, [selector, 0, 0, 0, 0, 0]);
            }
        }
    }

    fn notify(&mut self) {
        let h = self.some_handle();
        match self.rng.below(4) {
            0 => {
                let _ = syscall(Syscall::NtfySignal, [h, self.rng.next(), 0, 0, 0, 0]);
            }
            1 => {
                let _ = syscall(Syscall::NtfyPoll, [h, 0, 0, 0, 0, 0]);
            }
            2 => {
                // `ntfy_wait` bloqueia: para nunca travar o fuzzer, usa uma
                // notificação nova (direitos cheios, não reduzidos por um
                // `cap_mint`), sinaliza, espera (volta na hora, pois há bit
                // pendente) e a apaga. O kernel não é preemptível e a
                // principal não cede a CPU entre as três chamadas, então
                // nada zera o pendente nessa janela.
                let create = syscall(
                    Syscall::ObjCreate,
                    [
                        u64::from(self.quota),
                        ObjectType::Notification.to_raw(),
                        0,
                        0,
                        0,
                        0,
                    ],
                );
                if let Ok([n, ..]) = create {
                    let _ = syscall(Syscall::NtfySignal, [n, 0xf, 0, 0, 0, 0]);
                    let _ = syscall(Syscall::NtfyWait, [n, 0, 0, 0, 0, 0]);
                    let _ = syscall(Syscall::CapDelete, [n, 0, 0, 0, 0, 0]);
                }
            }
            _ => {
                let b = self.some_handle();
                let _ = syscall(Syscall::ObjBindNotify, [h, b, self.rng.below(80), 0, 0, 0]);
                let _ = syscall(Syscall::IrqAck, [h, 0, 0, 0, 0, 0]);
            }
        }
    }

    fn futex(&mut self) {
        let addr = if self.rng.chance(1, 2) {
            self.scratch_addr()
        } else {
            wild(&mut self.rng)
        };
        if self.rng.chance(1, 2) {
            // `futex_wait` nunca bloqueia de fato: as páginas que o kernel
            // mapeia nascem zeradas e nada aqui as grava, então um esperado
            // não nulo nunca bate (devolve `WouldBlock`); endereço não
            // mapeado dá `InvalidArgument`. Assim o fuzzer não trava a si
            // mesmo numa campanha longa.
            let expected = self.rng.next() | 1;
            let _ = syscall(Syscall::FutexWait, [addr, expected, 0, 0, 0, 0]);
        } else {
            let _ = syscall(Syscall::FutexWake, [addr, self.rng.below(8), 0, 0, 0, 0]);
        }
    }

    fn ipc(&mut self) {
        let ep = self.some_handle();
        let reply = self.some_handle();
        let label = self.rng.next();
        // Sempre sem bloquear: o fuzzer não tem par pronto do outro lado.
        let info = MsgInfo {
            words: u8::try_from(self.rng.below(7)).unwrap_or(0),
            caps: u8::try_from(self.rng.below(5)).unwrap_or(0),
            flags: FLAG_NONBLOCK,
            buffer_words: u16::try_from(self.rng.below(16)).unwrap_or(0),
        }
        .to_raw();
        let regs = [
            ep,
            label,
            info,
            0,
            self.rng.next(),
            self.rng.next(),
            self.rng.next(),
            self.rng.next(),
            self.rng.next(),
            self.rng.next(),
        ];
        let call = self.rng.pick(&[
            Syscall::IpcSend,
            Syscall::IpcCall,
            Syscall::IpcRecv,
            Syscall::IpcReplyRecv,
        ]);
        let target = match call {
            Syscall::IpcRecv | Syscall::IpcReplyRecv =>
            {
                #[allow(clippy::cast_possible_truncation, reason = "handles são u32")]
                recv_target(
                    ostd::kabi::Handle::from_raw(ep as u32),
                    ostd::kabi::Handle::from_raw(reply as u32),
                )
            }
            _ => ep,
        };
        let mut r = regs;
        r[0] = target;
        let _ = ostd::arch::ipc(call.to_raw(), r);
    }
}
