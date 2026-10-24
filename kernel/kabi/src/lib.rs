//! `kabi`: a ABI estável entre o `okernel` e os processos de usuário (SDD v1.0, seção 14).
//!
//! Números de syscall, códigos de erro, direitos, handles, tipos de objeto e o
//! layout das mensagens de IPC. É compartilhada pelo kernel e pelo `ostd`; a
//! ABI só muda em versão maior desta crate (seção 14.6).
//!
//! Todo valor que chega de registradores entra por `TryFrom<u64>`, que recusa
//! valores desconhecidos com [`UnknownValue`] e nunca entra em pânico.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod handle;
mod rights;

pub use handle::{Handle, handle_pair, split_handle_pair};
pub use rights::Rights;

/// Versão da ABI de syscalls (seção 14.2, "ABI v1").
pub const ABI_VERSION: u32 = 1;

/// Máximo de CPUs que o kernel liga (RF-03, ADR 0030); ids lógicos vão de
/// 0 a `MAX_CPUS - 1`.
pub const MAX_CPUS: usize = 256;

/// Valor bruto recusado por uma conversão vinda de registrador.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnknownValue(pub u64);

/// Define um enum da ABI com `ALL`, `number`, `to_raw` e `TryFrom<u64>`.
///
/// `raw(v) => expr` diz como o valor fica num registrador de 64 bits.
macro_rules! abi_enum {
    ($(#[$meta:meta])* pub enum $name:ident: $repr:ty, raw($v:ident) => $raw:expr;
     $($variant:ident = $n:expr => $doc:literal,)+) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[repr($repr)]
        pub enum $name {
            $(#[doc = $doc] $variant = $n,)+
        }

        impl $name {
            /// Todas as variantes, na ordem do SDD.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// Valor numérico estável da variante.
            #[must_use]
            pub const fn number(self) -> $repr {
                self as $repr
            }

            /// Valor como fica num registrador de 64 bits.
            #[must_use]
            pub fn to_raw(self) -> u64 {
                let $v = self.number();
                $raw
            }
        }

        impl TryFrom<u64> for $name {
            type Error = UnknownValue;

            fn try_from(raw: u64) -> Result<Self, UnknownValue> {
                Self::ALL.iter().copied().find(|v| v.to_raw() == raw).ok_or(UnknownValue(raw))
            }
        }
    };
}

pub mod boot;
pub mod fault;
pub mod fuzz;
pub mod ipc;
pub mod sched;

abi_enum! {
/// Números das syscalls da ABI v1 (seção 14.2), passados em `rax`.
pub enum Syscall: u32, raw(n) => u64::from(n);
    DebugWrite = 0 => "`debug_write`: só com capability de debug.",
    CapMint = 1 => "`cap_mint`: cópia com direitos iguais ou menores e badge opcional, na própria tabela ou noutro `CapSpace` (ADR 0029).",
    CapDelete = 2 => "`cap_delete(handle, flags)`; com [`cap_delete::DESTROY`] também destrói o objeto (ADR 0035).",
    CapRevoke = 3 => "`cap_revoke`: apaga todos os descendentes.",
    CapInfo = 4 => "`cap_info`.",
    ObjCreate = 5 => "`obj_create(quota, tipo, args)`.",
    VmMap = 6 => "`vm_map`; `aspace = 0` é o espaço de quem chama (ADR 0039).",
    VmUnmap = 7 => "`vm_unmap`; `aspace = 0` é o espaço de quem chama (ADR 0039).",
    VmProtect = 8 => "`vm_protect`.",
    MemOp = 9 => "`mem_op`: commit, zero, cache.",
    ThreadConfigure = 10 => "`thread_configure`: `CapSpace`, `AddressSpace`, buffer de IPC, endpoint de exceções (ADR 0029) e TLS; `thread = 0` é a própria (ADR 0039).",
    ThreadStart = 11 => "`thread_start`: `rip`, `rsp` e três valores iniciais (ADR 0029).",
    ThreadSuspend = 12 => "`thread_suspend`.",
    ThreadResume = 13 => "`thread_resume`.",
    ThreadReadState = 14 => "`thread_read_state`.",
    ThreadWriteState = 15 => "`thread_write_state`.",
    SchedConfigure = 16 => "`sched_configure`.",
    SchedBind = 17 => "`sched_bind`.",
    IpcSend = 18 => "`ipc_send`.",
    IpcRecv = 19 => "`ipc_recv`.",
    IpcCall = 20 => "`ipc_call`.",
    IpcReplyRecv = 21 => "`ipc_reply_recv`.",
    NtfySignal = 22 => "`ntfy_signal`.",
    NtfyWait = 23 => "`ntfy_wait`; `PeerClosed` se a notificação morre durante a espera.",
    NtfyPoll = 24 => "`ntfy_poll`.",
    ObjBindNotify = 25 => "`obj_bind_notify(obj, ntfy, bits, a3, a4, a5)`: `Interrupt`, e a morte de `Thread` e de `CapSpace` (ADR 0035).",
    IrqAck = 26 => "`irq_ack`.",
    ClockGet = 27 => "`clock_get`.",
    Yield = 28 => "`yield`.",
    FutexWait = 29 => "`futex_wait`.",
    FutexWake = 30 => "`futex_wake`.",
    DmaMap = 31 => "`dma_map` / `dma_unmap`, escolhidos por flag.",
    SysInfo = 32 => "`sys_info(classe, arg)`: CPUs, morte (classe 2, handle em `rsi`) e entropia.",
    ThreadExit = 33 => "`thread_exit(código, flags)`: o código vai ao registro de morte (ADR 0035 e 0039).",
}

/// Quantidade de syscalls da ABI v1 ("34 syscalls estáveis").
pub const SYSCALL_COUNT: usize = Syscall::ALL.len();

/// Syscall de depuração provisória, fora da ABI v1: `debug_print(ptr, len)`
/// manda até [`DEBUG_PRINT_MAX`] bytes UTF-8 ao registro do kernel. Sai
/// quando `debug_write` ganhar a capability de depuração (seção 14.2).
pub const DEBUG_PRINT: u64 = 0x8000_0000;
/// Bytes aceitos por chamada de [`DEBUG_PRINT`].
pub const DEBUG_PRINT_MAX: usize = 64;

/// Status de sucesso devolvido em `rax` (seção 14.1).
pub const STATUS_OK: u64 = 0;

abi_enum! {
/// Erros de syscall (seção 14.2); `number` é o status negativo de `rax`.
///
/// Os números seguem a ordem da lista do SDD, de -1 a -12 (definido aqui, o
/// SDD não fixa). `TryFrom<u64>` recusa `STATUS_OK`.
pub enum Error: i64, raw(n) => n.cast_unsigned();
    InvalidHandle = -1 => "Handle sem slot ou com geração vencida.",
    WrongType = -2 => "O objeto não é do tipo esperado.",
    AccessDenied = -3 => "Faltam direitos na capability.",
    QuotaExceeded = -4 => "A `MemoryQuota` não tem bytes suficientes.",
    InvalidArgument = -5 => "Argumento fora do domínio.",
    WouldBlock = -6 => "A operação bloquearia e o chamador pediu para não bloquear.",
    TimedOut = -7 => "O prazo da operação venceu.",
    PeerClosed = -8 => "O outro lado do canal foi fechado.",
    Cancelled = -9 => "A operação foi cancelada.",
    NotSupported = -10 => "Operação não suportada.",
    Busy = -11 => "Recurso ocupado.",
    Revoked = -12 => "A capability foi revogada.",
}

abi_enum! {
/// Tipos de objeto do kernel, argumento de `obj_create` (seção 6.1).
///
/// A numeração segue a ordem da tabela 6.1, e `Vcpu / Vm` vira dois tipos
/// (definido aqui, o SDD não fixa).
pub enum ObjectType: u32, raw(n) => u64::from(n);
    MemoryQuota = 0 => "Orçamento de bytes para criar objetos.",
    AddressSpace = 1 => "Tabelas de página de um processo.",
    CapSpace = 2 => "Tabela de capabilities de um processo.",
    Thread = 3 => "Contexto de execução.",
    SchedContext = 4 => "Orçamento de CPU e prioridade.",
    MemoryObject = 5 => "Conjunto de páginas físicas.",
    Endpoint = 6 => "Ponto de IPC síncrono.",
    Reply = 7 => "Capability de resposta de uso único.",
    Notification = 8 => "Palavra de 64 bits de sinais assíncronos.",
    Interrupt = 9 => "Linha de IRQ ou vetor MSI.",
    IoPortRange = 10 => "Portas de E/S (só x86).",
    DmaDomain = 11 => "Domínio da IOMMU.",
    Vcpu = 12 => "CPU virtual (M14).",
    Vm = 13 => "Máquina virtual (M14).",
}

/// Badge de 64 bits gravado no slot por `cap_mint` (seção 6.2).
pub type Badge = u64;

/// Slots por nível da tabela radix do `CapSpace` (seção 6.2).
pub const CAPSPACE_SLOTS_PER_LEVEL: usize = 4096;

/// Memória virtual do usuário: faixa e permissões de `vm_map` e `vm_protect`
/// (seção 6.4).
pub mod vm {
    /// Primeiro endereço de usuário mapeável: os primeiros 64 KiB nunca são
    /// mapeados.
    pub const USER_START: u64 = 0x0001_0000;
    /// Fim (exclusivo) da metade baixa canônica de 48 bits.
    pub const USER_END: u64 = 0x0000_8000_0000_0000;
    /// Tamanho da página de `vm_map`.
    pub const PAGE_SIZE: u64 = 4096;
    /// Flag de `vm_map`/`vm_protect`: gravável (leitura é sempre permitida).
    pub const WRITE: u64 = 1;
    /// Flag de `vm_map`/`vm_protect`: executável. Nunca junto com
    /// [`WRITE`] (W^X).
    pub const EXEC: u64 = 1 << 1;
    /// Flags definidas; as demais são recusadas com `InvalidArgument`.
    pub const ALL_FLAGS: u64 = WRITE | EXEC;
    /// `aspace = SELF` (0) em `vm_map` e `vm_unmap`: o espaço da thread
    /// que chama, sem capability (ADR 0039, item 2).
    pub const SELF: u64 = 0;
}

/// Flags de `thread_configure` (ADR 0029 e ADR 0039, item 3): o que muda
/// além do `CapSpace` e do `AddressSpace`.
///
/// `thread = `[`SELF`] (0) é a própria thread, sem capability: vale para o
/// buffer de IPC, o endpoint de exceções e o TLS. Ligar `CapSpace` e
/// `AddressSpace` continua exigindo a capability da thread (com `SELF`, os
/// dois têm de ser 0; senão `InvalidArgument`).
pub mod thread {
    /// `thread_configure(SELF, ...)`: a thread que chama.
    pub const SELF: u64 = 0;
    /// Registra o buffer de IPC (`r10`; 0 tira o buffer).
    pub const CONFIGURE_IPC_BUFFER: u64 = 1;
    /// Registra o endpoint de exceções (`r8`, handle no `CapSpace` da
    /// thread; 0 tira o endpoint).
    pub const CONFIGURE_EXCEPTION: u64 = 1 << 1;
    /// Registra o `FS_BASE` da thread (`r10`, o registrador do buffer de
    /// IPC: as duas flags juntas são `InvalidArgument`). Aceita 0 e
    /// endereços abaixo de `vm::USER_END`, sem exigir alinhamento. Na
    /// própria thread vale ao voltar da syscall; numa thread que roda em
    /// outra CPU, na próxima vez que ela entrar numa CPU.
    pub const CONFIGURE_TLS: u64 = 1 << 2;
    /// Liga a thread alvo (por capability, com `WRITE_STATE`) ao `CapSpace` e
    /// ao `AddressSpace` de **quem chama**, sem exigir as capabilities deles
    /// (T-335): é o que `ostd::thread::spawn` precisa, porque nenhum serviço
    /// guarda capability do próprio `CapSpace` nem do próprio `AddressSpace`
    /// (ADR 0039, itens 2 e 3). Os argumentos `cspace` e `aspace` têm de ser
    /// 0 (senão `InvalidArgument`); a thread alvo só pode estar inativa
    /// (`Busy` depois da partida), e `thread = `[`SELF`] também dá
    /// `InvalidArgument`.
    pub const CONFIGURE_BIND_SELF: u64 = 1 << 3;
    /// Flags definidas; as demais são recusadas com `InvalidArgument`.
    pub const CONFIGURE_ALL: u64 =
        CONFIGURE_IPC_BUFFER | CONFIGURE_EXCEPTION | CONFIGURE_TLS | CONFIGURE_BIND_SELF;
}

/// Flags de `cap_delete(handle, flags)` (`rsi`; ADR 0035, item 4).
pub mod cap_delete {
    /// Além de apagar a capability, destrói o objeto; exige o direito
    /// `Rights::DESTROY` nela. `CapSpace`: encerra o processo (todas as
    /// threads ligadas a ele morrem como `Killed`, inclusive as bloqueadas e
    /// as que rodam noutra CPU) e esvazia a tabela. `Thread`: encerra a
    /// thread. `Endpoint`: fecha o objeto (quem espera e quem chegar depois
    /// recebe `PeerClosed`). Outros tipos: `NotSupported`, sem apagar nada.
    pub const DESTROY: u64 = 1;
    /// Flags definidas; as demais são recusadas com `InvalidArgument`.
    pub const ALL_FLAGS: u64 = DESTROY;
}

/// `thread_exit(código, flags)` (`rdi`, `rsi`; ADR 0035, item 2, e ADR
/// 0039, item 5), as causas do registro de morte e a leitura dele.
///
/// `sys_info(`[`crate::sched::SYS_INFO_EXIT`]`, handle)` devolve `[causa,
/// código, auxiliar]` de uma `Thread` (exige `READ_STATE`) ou do processo de
/// um `CapSpace` (exige `MANAGE`); causa zero é "ainda vivo". O registro do
/// processo é a primeira morte anormal das threads dele ou, se todas foram
/// normais, a da última; `EXIT_GROUP` e `cap_delete(DESTROY)` gravam o dele
/// na chamada (`Exited` com o código e `Killed`) e nada o sobrescreve.
pub mod exit {
    /// Flag de `thread_exit`: encerra o processo inteiro (o `CapSpace` da
    /// thread), como `cap_delete(DESTROY)` sobre ele sem exigir o direito:
    /// as outras threads morrem como `Killed` e a causa do processo é
    /// `Exited` com o código. A thread que chama nunca volta; sem `CapSpace`,
    /// só ela termina.
    pub const GROUP: u64 = 1;
    /// Flags definidas; as demais são recusadas com `InvalidArgument` (a
    /// thread segue).
    pub const ALL_FLAGS: u64 = GROUP;
    /// Código de saída do pânico do `ostd` (`"pani"`).
    pub const PANIC_CODE: u64 = 0x7061_6E69;
    /// Causa: a thread chamou `thread_exit`; o código é o de `rdi`.
    pub const CAUSE_EXITED: u8 = 1;
    /// Causa: falta fatal; o código é o vetor e o auxiliar, o endereço.
    pub const CAUSE_FAULTED: u8 = 2;
    /// Causa: encerrada por outra (`cap_delete` com `DESTROY` ou
    /// `EXIT_GROUP` de outra thread do processo).
    pub const CAUSE_KILLED: u8 = 3;
}

/// Rótulo de 64 bits de uma mensagem de IPC (seção 6.7).
///
/// O significado do rótulo é do protocolo (OIDL); o kernel só o transporta.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MessageLabel(pub u64);

impl From<u64> for MessageLabel {
    fn from(raw: u64) -> Self {
        Self(raw)
    }
}

/// Palavras de mensagem em registradores no caminho rápido (seção 6.7).
pub const MSG_REG_WORDS: usize = 6;
/// Tamanho do buffer de IPC por thread, em bytes (seção 6.7).
pub const IPC_BUFFER_BYTES: usize = 4096;
/// Palavras de 64 bits de mensagem no buffer de IPC: 4 KiB menos os 64
/// bytes do cabeçalho com os handles das capabilities (ADR 0027).
pub const IPC_BUFFER_WORDS: usize = (IPC_BUFFER_BYTES - 64) / 8;
/// Máximo de capabilities transferidas por mensagem (seções 6.2 e 6.7).
pub const MSG_MAX_CAPS: usize = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeros_estaveis() {
        assert_eq!(SYSCALL_COUNT, 34);
        assert_eq!(Error::ALL.len(), 12);
        assert_eq!(ObjectType::ALL.len(), 14);
        for (i, s) in Syscall::ALL.iter().enumerate() {
            assert_eq!(s.number() as usize, i);
        }
        for (i, e) in (1..).zip(Error::ALL) {
            assert_eq!(e.number(), -i);
        }
        for (i, t) in ObjectType::ALL.iter().enumerate() {
            assert_eq!(t.number() as usize, i);
        }
        let syscalls = [
            Syscall::ObjCreate,
            Syscall::IpcCall,
            Syscall::DmaMap,
            Syscall::ThreadExit,
        ];
        assert_eq!(syscalls.map(Syscall::number), [5, 20, 31, 33]);
        assert_eq!(
            (Error::AccessDenied.number(), Error::Revoked.number()),
            (-3, -12)
        );
        assert_eq!(Error::AccessDenied.to_raw(), u64::MAX - 2);
        assert_eq!(
            (ObjectType::Endpoint.number(), ObjectType::Vm.number()),
            (6, 13)
        );
    }

    #[test]
    fn ida_e_volta_e_recusa_desconhecidos() {
        for &s in Syscall::ALL {
            assert_eq!(Syscall::try_from(s.to_raw()), Ok(s));
        }
        for &e in Error::ALL {
            assert_eq!(Error::try_from(e.to_raw()), Ok(e));
        }
        for &t in ObjectType::ALL {
            assert_eq!(ObjectType::try_from(t.to_raw()), Ok(t));
        }
        for raw in [34, 1 << 32, u64::MAX] {
            assert_eq!(Syscall::try_from(raw), Err(UnknownValue(raw)));
        }
        for raw in [STATUS_OK, 1, (-13i64).cast_unsigned(), u64::from(u32::MAX)] {
            assert_eq!(Error::try_from(raw), Err(UnknownValue(raw)));
        }
        assert_eq!(ObjectType::try_from(14), Err(UnknownValue(14)));
    }

    #[test]
    fn flags_de_thread_e_saida() {
        use super::{exit, thread, vm};
        assert_eq!(
            (
                thread::CONFIGURE_IPC_BUFFER,
                thread::CONFIGURE_EXCEPTION,
                thread::CONFIGURE_TLS
            ),
            (1, 2, 4)
        );
        assert_eq!(thread::CONFIGURE_ALL, 0b1111);
        assert_eq!((thread::SELF, vm::SELF), (0, 0));
        assert_eq!(
            (exit::GROUP, exit::ALL_FLAGS, exit::PANIC_CODE),
            (1, 1, 0x7061_6E69)
        );
        assert_eq!(
            (exit::CAUSE_EXITED, exit::CAUSE_FAULTED, exit::CAUSE_KILLED),
            (1, 2, 3)
        );
    }

    #[test]
    fn flags_de_cap_delete() {
        assert_eq!((cap_delete::DESTROY, cap_delete::ALL_FLAGS), (1, 1));
        assert_eq!(sched::SYS_INFO_EXIT, 2);
    }

    #[test]
    fn layout_de_mensagem() {
        assert_eq!((MSG_REG_WORDS, IPC_BUFFER_WORDS, MSG_MAX_CAPS), (6, 504, 4));
        assert_eq!(MessageLabel::from(7), MessageLabel(7));
    }
}
