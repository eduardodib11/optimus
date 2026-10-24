//! Criação de processos a partir de um executável (ADR 0029): o `root`
//! carrega assim os serviços do bootfs.
//!
//! [`load`] cria, numa cota filha, o `CapSpace`, o `AddressSpace`, um
//! `MemoryObject` por segmento do ELF (copiado por um mapeamento
//! temporário no espaço de quem carrega), a pilha, a thread e o
//! `SchedContext`, e liga a thread ao espaço e à tabela novos. Quem
//! carrega põe na tabela do filho o que ele precisa ([`Child::give`]),
//! registra o endpoint de exceções e o inicia ([`Child::start`]).

use kabi::vm::{EXEC, PAGE_SIZE, WRITE};
use kabi::{Badge, Error, Handle, ObjectType, Rights};

use crate::cap::{create, delete, mint};
use crate::thread;
use crate::vm::{Mapping, map};

/// Aborta o processo que chama (ADR 0039, item 5): escreve `reason` no
/// registro de depuração e sai com `EXIT_GROUP` e o código de pânico
/// (`kabi::exit::PANIC_CODE`), o que encerra as outras threads como
/// `Killed`. Não roda destrutores nem devolve o heap: é o caminho do pânico
/// e das falhas do alocador, em que o estado do processo não é confiável.
/// Se o kernel recusar (nunca, com flags válidas), encerra só a thread com
/// o mesmo código.
pub fn abort(reason: &str) -> ! {
    crate::debug::print(reason);
    let _ = thread::exit_group(kabi::exit::PANIC_CODE);
    thread::exit_raw(kabi::exit::PANIC_CODE)
}

/// Topo da pilha da thread inicial (o mesmo do `root`).
pub const STACK_TOP: u64 = 0x0000_7fff_ffff_0000;
/// Tamanho da pilha da thread inicial.
pub const STACK_BYTES: u64 = 64 << 10;

/// Como carregar.
#[derive(Clone, Copy, Debug)]
pub struct Spec<'a> {
    /// O executável (ELF64 de usuário, `ET_EXEC`).
    pub elf: &'a [u8],
    /// Cota de quem carrega, de onde sai a cota do filho.
    pub quota: Handle,
    /// Bytes da cota do filho (objetos dele e o que ele criar).
    pub quota_bytes: u64,
    /// Espaço de quem carrega, para os mapeamentos temporários.
    pub own_aspace: Handle,
    /// Faixa livre do espaço de quem carrega para esses mapeamentos.
    pub scratch_va: u64,
    /// Prioridade da thread (orçamento sem limite).
    pub priority: u8,
}

/// Processo criado e ainda parado. Os handles valem na tabela de quem
/// carregou.
#[derive(Clone, Copy, Debug)]
pub struct Child {
    /// Cota do filho.
    pub quota: Handle,
    /// Tabela de capabilities do filho.
    pub cspace: Handle,
    /// Espaço do filho.
    pub aspace: Handle,
    /// Thread inicial.
    pub thread: Handle,
    /// Ponto de entrada.
    pub entry: u64,
}

/// Período do `SchedContext` da thread inicial.
const PERIOD_NS: u64 = 1_000_000;

impl Child {
    /// Copia para a tabela do filho a capability `h` (de quem carregou),
    /// com os direitos reduzidos a `rights` e `badge`; devolve o handle
    /// dela na tabela do filho.
    ///
    /// # Errors
    ///
    /// Os de `cap_mint`.
    pub fn give(&self, h: Handle, rights: Rights, badge: Badge) -> Result<Handle, Error> {
        mint(h, rights, badge, Some(self.cspace))
    }

    /// Inicia a thread na entrada do ELF, com a pilha em [`STACK_TOP`] e
    /// `args` em `rdi`, `rsi` e `rdx`.
    ///
    /// # Errors
    ///
    /// Os de `thread_start`.
    pub fn start(&self, args: [u64; 3]) -> Result<(), Error> {
        thread::start(self.thread, self.entry, STACK_TOP, args)
    }
}

/// Monta o processo de `spec` sem iniciá-lo.
///
/// # Errors
///
/// `InvalidArgument` para ELF inválido, relocável ou com segmento que
/// não cabe; os das syscalls de cada passo.
pub fn load(spec: &Spec<'_>) -> Result<Child, Error> {
    let elf = oelf::Elf::parse_user(spec.elf).map_err(|_| Error::InvalidArgument)?;
    if elf.is_relocatable() {
        return Err(Error::InvalidArgument);
    }
    let quota = create(spec.quota, ObjectType::MemoryQuota, spec.quota_bytes)?;
    let cspace = create(quota, ObjectType::CapSpace, 0)?;
    let aspace = create(quota, ObjectType::AddressSpace, 0)?;
    for seg in elf.segments() {
        let start = seg.vaddr & !(PAGE_SIZE - 1);
        let end = seg
            .vaddr
            .checked_add(seg.memsz)
            .ok_or(Error::InvalidArgument)?
            .next_multiple_of(PAGE_SIZE);
        let flags = if seg.flags.writable() {
            WRITE
        } else if seg.flags.executable() {
            EXEC
        } else {
            0
        };
        let at = usize::try_from(seg.vaddr - start).map_err(|_| Error::InvalidArgument)?;
        segment(
            spec,
            (quota, aspace),
            (start, end - start, flags),
            at,
            seg.data,
        )?;
    }
    segment(
        spec,
        (quota, aspace),
        (STACK_TOP - STACK_BYTES, STACK_BYTES, WRITE),
        0,
        &[],
    )?;
    let t = create(quota, ObjectType::Thread, 0)?;
    let sc = create(quota, ObjectType::SchedContext, 0)?;
    let bound = thread::sched_configure(sc, PERIOD_NS, PERIOD_NS, spec.priority)
        .and_then(|()| thread::sched_bind(sc, t));
    // A thread guarda o `SchedContext`; a capability não faz mais falta.
    let _ = delete(sc);
    bound?;
    thread::bind(t, cspace, aspace)?;
    Ok(Child {
        quota,
        cspace,
        aspace,
        thread: t,
        entry: elf.entry(),
    })
}

/// Cria o `MemoryObject` de `len` bytes, copia `data` a partir do byte
/// `at` e o mapeia em `va` do filho com `flags`.
fn segment(
    spec: &Spec<'_>,
    (quota, aspace): (Handle, Handle),
    (va, len, flags): (u64, u64, u64),
    at: usize,
    data: &[u8],
) -> Result<(), Error> {
    let object = create(quota, ObjectType::MemoryObject, len)?;
    let result = (|| {
        if !data.is_empty() {
            let mut scratch = Mapping::new(spec.own_aspace, object, spec.scratch_va, len, WRITE)?;
            let bytes = scratch.bytes_mut().ok_or(Error::InvalidArgument)?;
            bytes
                .get_mut(at..at + data.len())
                .ok_or(Error::InvalidArgument)?
                .copy_from_slice(data);
        }
        map(aspace, object, va, 0, len, flags)
    })();
    // A região do filho guarda o objeto.
    let _ = delete(object);
    result
}
