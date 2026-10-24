//! Capabilities e objetos do kernel (SDD v1.0, seções 6.1 e 6.2):
//! `obj_create`, `cap_mint`, `cap_delete` (também com `DESTROY`),
//! `cap_info`, `obj_bind_notify` (também para armar um `Timer`) e o
//! registro de morte de `sys_info` (ADR 0035).

use kabi::{Badge, Error, Handle, ObjectType, Rights, Syscall};

use crate::sys::syscall;

pub(crate) fn raw(h: Handle) -> u64 {
    u64::from(h.raw())
}

fn handle(v: u64) -> Result<Handle, Error> {
    u32::try_from(v)
        .map(Handle::from_raw)
        .map_err(|_| Error::InvalidHandle)
}

/// `obj_create`: objeto novo de `ty` na cota `quota`, com `args` (bytes de
/// um `MemoryObject` ou de uma cota filha; zero para os demais).
///
/// # Errors
///
/// Os do kernel (`QuotaExceeded`, `AccessDenied` sem `CREATE`...).
pub fn create(quota: Handle, ty: ObjectType, args: u64) -> Result<Handle, Error> {
    let [h, ..] = syscall(Syscall::ObjCreate, [raw(quota), ty.to_raw(), args, 0, 0, 0])?;
    handle(h)
}

/// `cap_mint`: cópia de `src` com os direitos reduzidos por `rights` e,
/// se `src` não tiver badge, `badge` (0 mantém). Com `dest`, a cópia vai
/// para aquele `CapSpace` (precisa de `MANAGE`; ADR 0029) e o handle
/// devolvido vale lá.
///
/// # Errors
///
/// Os do kernel.
pub fn mint(
    src: Handle,
    rights: Rights,
    badge: Badge,
    dest: Option<Handle>,
) -> Result<Handle, Error> {
    let dest = dest.map_or(0, raw);
    let args = [raw(src), u64::from(rights.bits()), badge, dest, 0, 0];
    let [h, ..] = syscall(Syscall::CapMint, args)?;
    handle(h)
}

/// `cap_delete`.
///
/// # Errors
///
/// `InvalidHandle` para handle sem capability.
pub fn delete(h: Handle) -> Result<(), Error> {
    syscall(Syscall::CapDelete, [raw(h), 0, 0, 0, 0, 0]).map(drop)
}

/// `cap_delete` com `DESTROY` (ADR 0035, item 4): apaga a capability e
/// destrói o objeto. `CapSpace`: encerra o processo (as threads dele morrem
/// como `Killed` e a tabela é esvaziada); `Thread`: encerra a thread;
/// `Endpoint`: quem espera nele, ou o usar depois, recebe `PeerClosed`.
///
/// # Errors
///
/// `AccessDenied` sem o direito `DESTROY`, `NotSupported` para os outros
/// tipos (nos dois casos nada é apagado) e os de [`delete`].
pub fn destroy(h: Handle) -> Result<(), Error> {
    let args = [raw(h), kabi::cap_delete::DESTROY, 0, 0, 0, 0];
    syscall(Syscall::CapDelete, args).map(drop)
}

/// `obj_bind_notify` (ADR 0035, item 3): o evento de `obj` sinaliza `bits`
/// na notificação `ntfy`. `Thread` e `CapSpace`: o evento é a morte da
/// thread ou do processo; ligar de novo troca a ligação, `bits = 0` desliga
/// e ligar depois da morte sinaliza já. `Interrupt`: `bits` é o número do
/// bit, e a linha só se liga uma vez.
///
/// # Errors
///
/// Os do kernel (`AccessDenied` sem `BIND` em `obj` ou `SIGNAL` em `ntfy`).
pub fn bind_notify(obj: Handle, ntfy: Handle, bits: u64) -> Result<(), Error> {
    let args = [raw(obj), raw(ntfy), bits, 0, 0, 0];
    syscall(Syscall::ObjBindNotify, args).map(drop)
}

/// Arma o `Timer` `timer` (ADR 0035, item 6; `obj_bind_notify` com prazo,
/// período e flags): no prazo `deadline`, em ns do relógio de
/// [`crate::time::now_ns`] (com [`kabi::timer::RELATIVE`] em `flags`, a
/// partir de agora), sinaliza `bits` em `ntfy`. `period = 0` é disparo
/// único; senão repete a cada `period` ns (pelo menos
/// [`kabi::timer::MIN_PERIOD_NS`]), e atrasos de mais de um período dão um
/// sinal só. Prazo vencido sinaliza antes de voltar. Armar de novo troca
/// ligação, prazo e período, e o `Timer` passa para a CPU de quem arma;
/// `bits = 0` ou `deadline = 0` desarma (ver [`disarm_timer`]).
///
/// # Errors
///
/// Os do kernel: `AccessDenied` sem `BIND` no `Timer` ou `SIGNAL` em
/// `ntfy`, `InvalidArgument` para período abaixo do mínimo ou flags
/// desconhecidas, `WrongType`.
pub fn arm_timer(
    timer: Handle,
    ntfy: Handle,
    bits: u64,
    deadline: u64,
    period: u64,
    flags: u64,
) -> Result<(), Error> {
    let args = [raw(timer), raw(ntfy), bits, deadline, period, flags];
    syscall(Syscall::ObjBindNotify, args).map(drop)
}

/// Desarma o `Timer` `timer` (o kernel ainda exige `SIGNAL` em `ntfy`). Um
/// disparo que o kernel já tinha começado a entregar pode chegar a `ntfy`
/// logo depois.
///
/// # Errors
///
/// Os de [`arm_timer`].
pub fn disarm_timer(timer: Handle, ntfy: Handle) -> Result<(), Error> {
    arm_timer(timer, ntfy, 0, 0, 0, 0)
}

/// Registro de morte (ADR 0035, item 2), de [`death`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Death {
    /// `kabi::exit::CAUSE_*`.
    pub cause: u8,
    /// `Exited`: o código de `thread_exit`; `Faulted`: o vetor.
    pub code: u64,
    /// `Faulted`: o endereço que faltou.
    pub aux: u64,
}

/// `sys_info` com `SYS_INFO_EXIT`: o registro de morte da `Thread` (com
/// `READ_STATE`) ou do processo do `CapSpace` (com `MANAGE`) de `h`;
/// `None` enquanto vive.
///
/// # Errors
///
/// Os do kernel (`WrongType` para outros objetos).
pub fn death(h: Handle) -> Result<Option<Death>, Error> {
    let args = [kabi::sched::SYS_INFO_EXIT, raw(h), 0, 0, 0, 0];
    let [cause, code, aux] = syscall(Syscall::SysInfo, args)?;
    Ok((cause != 0).then_some(Death {
        cause: u8::try_from(cause).unwrap_or(u8::MAX),
        code,
        aux,
    }))
}

/// O que `cap_info` diz de uma capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    /// Tipo do objeto.
    pub object_type: ObjectType,
    /// Direitos.
    pub rights: Rights,
    /// Badge.
    pub badge: Badge,
}

/// `cap_info`.
///
/// # Errors
///
/// `InvalidHandle` para handle sem capability.
pub fn info(h: Handle) -> Result<Info, Error> {
    let [ty, rights, badge] = syscall(Syscall::CapInfo, [raw(h), 0, 0, 0, 0, 0])?;
    Ok(Info {
        object_type: ObjectType::try_from(ty).map_err(|_| Error::NotSupported)?,
        rights: Rights::try_from(rights).map_err(|_| Error::NotSupported)?,
        badge,
    })
}
