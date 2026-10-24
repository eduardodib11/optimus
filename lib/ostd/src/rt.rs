//! Entrada do processo.
//!
//! O kernel começa a thread inicial em `_start` ([`crate::arch`]) com até
//! três valores em `rdi`, `rsi` e `rdx` (para o `root`, os handles
//! iniciais). `_start` alinha a pilha e chama [`start`], que acha a
//! função principal registrada por [`entry!`](crate::entry) e a chama com
//! esses valores num [`Start`].
//!
//! Como o binário não pode usar `unsafe` (nem `#[no_mangle]`), a função
//! principal é achada pelo nome do `static` que [`entry!`](crate::entry)
//! cria: o script de ligação `user.ld` desta crate junta numa seção própria
//! (`.ostd_entry`) a seção de dados de todo símbolo chamado `OSTD_ENTRY` e
//! confere que há exatamente um.
//!
//! O alocador global ([`crate::alloc`]) precisa da cota do processo, que o
//! kernel entrega nos valores de entrada em posições que variam de processo
//! para processo (o `root` e o `utest` recebem a cota em `rdi`; o `hello`,
//! junto com o espaço em `rsi`). Por isso a função principal chama [`init`]
//! com esse handle antes da primeira alocação; alocar antes disso aborta o
//! processo. O espaço de endereços não precisa de handle: o alocador mapeia
//! com `aspace = 0`, o espaço de quem chama (ADR 0039, item 2).

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use kabi::Handle;

/// Valores iniciais que o kernel entregou à thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Start {
    /// `rdi`, `rsi` e `rdx` na entrada.
    pub args: [u64; 3],
}

/// Handles que o runtime guarda para si: de onde o alocador tira memória.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Env {
    /// Cota de memória do processo (com o direito `CREATE`).
    pub quota: Handle,
}

static ENV_QUOTA: AtomicU32 = AtomicU32::new(0);
static ENV_READY: AtomicBool = AtomicBool::new(false);

/// Registra os handles do runtime. Chame uma vez, no começo da função
/// principal, antes de alocar.
///
/// # Panics
///
/// Se for chamada de novo com handles diferentes (os segmentos já mapeados
/// seguem a cota antiga).
pub fn init(env: Env) {
    if ENV_READY.load(Ordering::Acquire) {
        assert!(
            self::env() == Some(env),
            "rt::init chamada com outros handles"
        );
        return;
    }
    ENV_QUOTA.store(env.quota.raw(), Ordering::Relaxed);
    ENV_READY.store(true, Ordering::Release);
    // A semente do `HashMap` (T-337): antes do primeiro mapa.
    crate::rand::seed_collections();
}

/// Os handles registrados por [`init`], se já foram.
#[must_use]
pub fn env() -> Option<Env> {
    ENV_READY.load(Ordering::Acquire).then(|| Env {
        quota: Handle::from_raw(ENV_QUOTA.load(Ordering::Relaxed)),
    })
}

/// Função principal de um processo.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Entry(pub fn(Start) -> !);

/// Registra a função principal do processo (`fn(Start) -> !`).
///
/// Use uma vez, na raiz do binário; o script `user.ld` recusa a ligação
/// se faltar ou sobrar.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        /// Função principal lida pelo `_start` do `ostd`.
        #[used]
        static OSTD_ENTRY: $crate::rt::Entry = $crate::rt::Entry($main);
    };
}

/// Chamada por `_start` com os valores de entrada.
pub(crate) extern "sysv64" fn start(a0: u64, a1: u64, a2: u64) -> ! {
    // O bloco da thread principal e o `FS_BASE` antes de qualquer alocação.
    crate::tls::init_main();
    let main = crate::arch::entry();
    (main.0)(Start { args: [a0, a1, a2] })
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    crate::debug::print("ostd: pânico");
    if let Some(at) = info.location() {
        crate::debug::print(at.file());
    }
    // O pânico encerra o processo (ADR 0039, item 5).
    crate::process::abort("ostd: processo abortado por pânico")
}
