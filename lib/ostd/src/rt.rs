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

/// Valores iniciais que o kernel entregou à thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Start {
    /// `rdi`, `rsi` e `rdx` na entrada.
    pub args: [u64; 3],
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
    crate::thread::exit()
}
