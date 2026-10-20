//! Bloco da thread e `thread_local!` (T-335; ADR 0039, item 3).
//!
//! Cada thread do `ostd` tem um [`ThreadBlock`]: uma região gravável que
//! `FS_BASE` aponta, com o ponteiro para si mesmo no início (`fs:[0]`, como o
//! ABI x86-64 espera). Ele guarda o identificador da thread, o heap do
//! `oalloc` dela, a tabela de valores do [`thread_local!`](crate::thread_local),
//! o endpoint de exceções, o buffer de IPC (a última página, para o buffer
//! ficar alinhado) e o que `spawn` e `join` trocam (a função inicial, a
//! flag e o código de saída).
//!
//! A thread principal usa um bloco estático em `.bss`, ligado por
//! [`init_main`] antes da função principal; as outras vivem no mesmo
//! `MemoryObject` da pilha (ver `crate::thread`), logo acima dela.
//!
//! Desvio pequeno do texto da ADR: o índice de cada `thread_local!` sai de um
//! contador global, atribuído no primeiro acesso, em vez da posição de um
//! descritor numa seção do `user.ld`. O efeito é o mesmo (uma tabela de
//! slots no bloco, valor criado no primeiro acesso e destruído na saída da
//! thread) sem script de ligação novo; o preço é o limite de [`MAX_KEYS`]
//! chaves por processo.
//!
//! # Unsafe
//!
//! O teto de usos está em `unsafe-allowlist.toml`. As invariantes:
//!
//! - **O bloco** é sempre acessado por `&ThreadBlock`; tudo que muda tem
//!   mutabilidade interior (atômicos ou `UnsafeCell`) e só a thread dona
//!   toca os `UnsafeCell` (o heap, os slots, a função inicial depois da
//!   partida), com as exceções dos campos que `spawn` escreve **antes** de
//!   iniciar a thread. `unsafe impl Sync` vale por isso.
//! - **`current`:** `FS_BASE` aponta para um bloco que vive enquanto a thread
//!   roda: o estático da principal, ou a região que `JoinHandle` só desmapeia
//!   depois de ver a flag de fim, e a thread não toca nela depois dela
//!   (`arch::exit_signalling`).
//! - **Bloco zerado vale:** todo campo é válido com todos os bytes em zero
//!   (inteiros, atômicos, `Option` de ponteiro, `MaybeUninit`), que é como o
//!   kernel entrega as páginas e como `.bss` começa; `init_block` só
//!   preenche `self_ptr` e `tid`.
//! - **Valores do `thread_local!`** são `Box<T>` guardados como ponteiro
//!   cru e liberados pela função de destruição registrada junto com ele.

#![allow(unsafe_code)]
#![allow(clippy::cast_possible_truncation, reason = "x86-64: 64 bits")]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use alloc_crate::boxed::Box;
use kabi::ipc::IpcBuffer;

use crate::alloc::LocalHeap;
use crate::vm::Mapping;

/// Quantos `thread_local!` o processo pode ter.
pub const MAX_KEYS: usize = 32;

/// Um valor de `thread_local!`: ponteiro para o `Box<T>` e a função que o
/// destrói.
#[derive(Clone, Copy)]
struct Slot {
    ptr: usize,
    dtor: Option<unsafe fn(usize)>,
}

type Main = Box<dyn FnOnce() + Send + 'static>;

/// O bloco da thread. Zero em todos os bytes é um estado válido.
#[repr(C, align(4096))]
pub struct ThreadBlock {
    /// `fs:[0]`: o endereço do próprio bloco.
    self_ptr: *const ThreadBlock,
    tid: AtomicU64,
    /// Flag de fim: a thread a põe em 1 no último ato (ver `join`).
    done: AtomicU32,
    /// Código de saída, gravado antes de `done`.
    exit_code: AtomicU64,
    /// A thread nasceu de `spawn` (e tem quem a junte).
    joinable: AtomicBool,
    /// Handle do endpoint de exceções registrado (0 se nenhum).
    exception: AtomicU32,
    /// 0 sem heap, 1 com heap, 2 devolvido (a thread está saindo).
    heap_state: AtomicU8,
    heap: UnsafeCell<MaybeUninit<LocalHeap>>,
    main: UnsafeCell<Option<Main>>,
    slots: UnsafeCell<[Slot; MAX_KEYS]>,
    /// Buffer de IPC da thread: a última página do bloco.
    ipc: UnsafeCell<IpcBuffer>,
}

// SAFETY: ver `# Unsafe` do módulo: os campos mutáveis são atômicos ou só a
// thread dona (ou o criador, antes da partida) os toca.
unsafe impl Sync for ThreadBlock {}

impl ThreadBlock {
    /// Identificador único da thread (a principal tem 1).
    #[must_use]
    pub fn id(&self) -> u64 {
        self.tid.load(Ordering::Relaxed)
    }

    /// Endereço do bloco (o `FS_BASE` da thread).
    #[must_use]
    pub fn addr(&self) -> u64 {
        core::ptr::from_ref(self).addr() as u64
    }

    /// A flag de fim, para `futex_wait` e `futex_wake`.
    #[must_use]
    pub fn done(&self) -> &AtomicU32 {
        &self.done
    }

    /// Código de saída gravado pela thread.
    #[must_use]
    pub fn exit_code(&self) -> u64 {
        self.exit_code.load(Ordering::Acquire)
    }

    /// Grava o código de saída (antes da flag de fim).
    pub(crate) fn set_exit_code(&self, code: u64) {
        self.exit_code.store(code, Ordering::Release);
    }

    /// A thread tem quem a junte.
    #[must_use]
    pub fn joinable(&self) -> bool {
        self.joinable.load(Ordering::Relaxed)
    }

    /// Endereço do buffer de IPC.
    #[must_use]
    pub fn ipc_va(&self) -> u64 {
        core::ptr::from_ref(&self.ipc).addr() as u64
    }

    /// Endpoint de exceções registrado, se houver.
    #[must_use]
    pub fn exception(&self) -> Option<kabi::Handle> {
        match self.exception.load(Ordering::Relaxed) {
            0 => None,
            h => Some(kabi::Handle::from_raw(h)),
        }
    }

    /// Guarda a função inicial (antes de a thread começar).
    pub(crate) fn set_main(&self, main: Main) {
        // SAFETY: só o criador chama, antes de iniciar a thread; ninguém
        // mais olha `main` até lá.
        unsafe { *self.main.get() = Some(main) };
    }

    /// Tira a função inicial (a própria thread, uma vez; ou o criador, se
    /// a partida falhou).
    pub(crate) fn take_main(&self) -> Option<Main> {
        // SAFETY: um só lado por vez: o criador antes da partida (ou depois
        // de ela falhar), a thread depois.
        unsafe { (*self.main.get()).take() }
    }

    /// Roda `f` com o heap da thread, criando-o na primeira vez. Aborta se
    /// a thread já devolveu o heap.
    pub(crate) fn with_heap<R>(&self, f: impl FnOnce(&mut LocalHeap) -> R) -> R {
        match self.heap_state.load(Ordering::Relaxed) {
            0 => {
                // SAFETY: só a thread dona usa `heap`; o estado 0 diz que o
                // espaço ainda não tem heap.
                unsafe { (*self.heap.get()).write(crate::alloc::new_heap()) };
                self.heap_state.store(1, Ordering::Relaxed);
            }
            1 => {}
            _ => {
                crate::debug::print("ostd: alocação depois de a thread devolver o heap");
                crate::thread::exit_raw(kabi::exit::PANIC_CODE);
            }
        }
        // SAFETY: o estado 1 diz que o heap foi escrito; só a thread dona o
        // usa e `f` não volta a chamar `with_heap` (o alocador não é
        // reentrante).
        f(unsafe { (*self.heap.get()).assume_init_mut() })
    }

    /// Devolve o heap (o `Drop` do `oalloc` abandona os segmentos com
    /// blocos vivos para outro heap adotar). Depois disso, alocar aborta.
    pub(crate) fn retire_heap(&self) {
        if self.heap_state.swap(2, Ordering::Relaxed) == 1 {
            // SAFETY: o estado 1 dizia que o heap existe, e o 2 impede que
            // volte a ser usado ou destruído de novo.
            unsafe { (*self.heap.get()).assume_init_drop() };
        }
    }

    /// Roda os destrutores dos `thread_local!` da thread (e os de valores
    /// criados por eles, em até algumas voltas).
    pub(crate) fn run_destructors(&self) {
        for _ in 0..5 {
            let mut any = false;
            for i in 0..MAX_KEYS {
                // SAFETY: só a thread dona usa `slots`; o destrutor roda
                // depois de o slot ser limpo e sem referência a ele.
                let slot = unsafe { core::mem::replace(&mut (*self.slots.get())[i], Slot::EMPTY) };
                if let (ptr @ 1.., Some(dtor)) = (slot.ptr, slot.dtor) {
                    any = true;
                    // SAFETY: `ptr` e `dtor` vêm do mesmo `LocalKey<T>`
                    // (`Box::into_raw` e `drop_box::<T>`), usados uma vez.
                    unsafe { dtor(ptr) };
                }
            }
            if !any {
                break;
            }
        }
    }
}

impl Slot {
    const EMPTY: Self = Self { ptr: 0, dtor: None };
}

/// O bloco ocupa páginas inteiras (o buffer de IPC é a última).
const _: () = assert!(size_of::<ThreadBlock>().is_multiple_of(4096));

/// Bloco estático da thread principal, em `.bss`.
struct MainBlock(UnsafeCell<MaybeUninit<ThreadBlock>>);

// SAFETY: o bloco é `Sync` e este só é entregue como `&ThreadBlock`.
unsafe impl Sync for MainBlock {}

static MAIN: MainBlock = MainBlock(UnsafeCell::new(MaybeUninit::zeroed()));

static NEXT_TID: AtomicU64 = AtomicU64::new(1);
static NEXT_KEY: AtomicUsize = AtomicUsize::new(0);

/// Liga a thread principal ao bloco estático: grava o ponteiro para si, o
/// `FS_BASE` e o buffer de IPC. Chamada por `rt::start` antes da função
/// principal.
pub(crate) fn init_main() {
    let p = MAIN.0.get().cast::<ThreadBlock>();
    // SAFETY: o bloco é de `.bss` (zerado, válido) e só esta função o
    // escreve, uma vez, antes de qualquer outro acesso; `self_ptr` e `tid`
    // são os únicos campos escritos.
    let block = unsafe {
        core::ptr::addr_of_mut!((*p).self_ptr).write(p);
        core::ptr::addr_of_mut!((*p).tid)
            .write(AtomicU64::new(NEXT_TID.fetch_add(1, Ordering::Relaxed)));
        &*p
    };
    let va = p.addr() as u64;
    let _ = crate::thread::set_tls(crate::thread::SELF, va);
    let _ = crate::thread::set_ipc_buffer(crate::thread::SELF, Some(block.ipc_va()));
}

/// O bloco que começa em `offset` dentro de `map`.
pub(crate) fn block_in(map: &Mapping, offset: usize) -> &ThreadBlock {
    let ptr = core::ptr::with_exposed_provenance::<ThreadBlock>(map.va() as usize + offset);
    // SAFETY: o bloco foi preparado por `init_block` nesta faixa do
    // mapeamento, que o empréstimo mantém vivo.
    unsafe { &*ptr }
}

/// Prepara o bloco que começa em `offset` dentro de `map` (zerado, como o
/// kernel entrega): ponteiro para si, identificador novo, `joinable` e o
/// endpoint de exceções. Devolve o bloco, emprestado do mapeamento.
pub(crate) fn init_block(
    map: &Mapping,
    offset: usize,
    exception: Option<kabi::Handle>,
) -> &ThreadBlock {
    assert!(
        offset.is_multiple_of(4096) && offset + size_of::<ThreadBlock>() <= map.size(),
        "bloco fora do mapeamento"
    );
    let ptr = core::ptr::with_exposed_provenance_mut::<ThreadBlock>(map.va() as usize + offset);
    // SAFETY: a faixa cabe no mapeamento gravável (conferido), está zerada e
    // alinhada a 4096, e nenhuma thread a usa ainda.
    unsafe {
        core::ptr::addr_of_mut!((*ptr).self_ptr).write(ptr);
        core::ptr::addr_of_mut!((*ptr).tid)
            .write(AtomicU64::new(NEXT_TID.fetch_add(1, Ordering::Relaxed)));
        core::ptr::addr_of_mut!((*ptr).joinable).write(AtomicBool::new(true));
        core::ptr::addr_of_mut!((*ptr).exception)
            .write(AtomicU32::new(exception.map_or(0, kabi::Handle::raw)));
    }
    block_in(map, offset)
}

/// O bloco da thread que chama.
///
/// O `FS_BASE` da thread é do `ostd` (`rt::start` e `spawn` o põem): não
/// chame `thread::set_tls` com outro valor na própria thread.
#[must_use]
pub fn current() -> &'static ThreadBlock {
    let va = crate::arch::thread_pointer();
    // SAFETY: ver `# Unsafe`: `fs:[0]` é o endereço de um bloco vivo.
    unsafe { &*core::ptr::with_exposed_provenance::<ThreadBlock>(va as usize) }
}

/// Dá o buffer de IPC da thread (o do bloco) a `f`.
pub fn with_ipc_buffer<R>(f: impl FnOnce(&mut IpcBuffer) -> R) -> R {
    // SAFETY: só a thread dona usa o buffer (o kernel o usa durante as
    // syscalls de IPC, enquanto ela espera), e `f` não volta a chamar isto.
    f(unsafe { &mut *current().ipc.get() })
}

/// Um valor entregue de uma thread para outra uma única vez (o resultado
/// de `spawn`).
pub(crate) struct Handoff<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: `state` ordena a escrita do valor (`set`, Release) antes da
// leitura (`take`, Acquire), e cada lado toca `value` uma vez.
unsafe impl<T: Send> Sync for Handoff<T> {}

impl<T> Handoff<T> {
    pub(crate) const fn new() -> Self {
        Self {
            state: AtomicU8::new(0),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    pub(crate) fn set(&self, v: T) {
        // SAFETY: só `set` escreve, uma vez (estado 0 -> 1).
        unsafe { (*self.value.get()).write(v) };
        self.state.store(1, Ordering::Release);
    }

    pub(crate) fn take(&self) -> Option<T> {
        if self.state.swap(2, Ordering::Acquire) == 1 {
            // SAFETY: o estado 1 diz que o valor foi escrito; o `swap`
            // para 2 garante uma só leitura.
            Some(unsafe { (*self.value.get()).assume_init_read() })
        } else {
            None
        }
    }
}

impl<T> Drop for Handoff<T> {
    fn drop(&mut self) {
        drop(self.take());
    }
}

/// Chave de um `thread_local!`: cada thread tem o seu valor, criado por
/// `init` no primeiro acesso e destruído na saída da thread.
pub struct LocalKey<T: 'static> {
    /// Índice do slot + 1 (0 = ainda sem índice).
    index: AtomicUsize,
    init: fn() -> T,
}

unsafe fn drop_box<T>(ptr: usize) {
    // SAFETY: `ptr` veio de `Box::into_raw` de um `Box<T>` em `with`.
    drop(unsafe { Box::from_raw(core::ptr::with_exposed_provenance_mut::<T>(ptr)) });
}

impl<T: 'static> LocalKey<T> {
    /// Chave com o inicializador `init` (use [`thread_local!`](crate::thread_local)).
    #[must_use]
    pub const fn new(init: fn() -> T) -> Self {
        Self {
            index: AtomicUsize::new(0),
            init,
        }
    }

    fn slot_index(&self) -> usize {
        let cur = self.index.load(Ordering::Acquire);
        if cur != 0 {
            return cur - 1;
        }
        let mine = NEXT_KEY.fetch_add(1, Ordering::Relaxed);
        assert!(mine < MAX_KEYS, "thread_local!: chaves demais");
        match self
            .index
            .compare_exchange(0, mine + 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => mine,
            // Outra thread chegou antes: o índice que gastei se perde.
            Err(other) => other - 1,
        }
    }

    /// Dá o valor da thread atual a `f`.
    ///
    /// # Panics
    ///
    /// Se o processo tem mais de [`MAX_KEYS`] chaves.
    pub fn with<R>(&'static self, f: impl FnOnce(&T) -> R) -> R {
        let block = current();
        let i = self.slot_index();
        // SAFETY: só a thread dona usa `slots`; a leitura é curta.
        let mut ptr = unsafe { (*block.slots.get())[i].ptr };
        if ptr == 0 {
            // O inicializador pode usar outras chaves: sem empréstimo vivo.
            let value = Box::new((self.init)());
            ptr = Box::into_raw(value).addr();
            // SAFETY: como acima.
            unsafe {
                (*block.slots.get())[i] = Slot {
                    ptr,
                    dtor: Some(drop_box::<T>),
                };
            }
        }
        // SAFETY: `ptr` é um `Box<T>` vivo até o destrutor da thread, que só
        // roda na saída dela, depois de todo `with`.
        f(unsafe { &*core::ptr::with_exposed_provenance::<T>(ptr) })
    }
}

/// Declara variáveis locais à thread:
///
/// ```ignore
/// ostd::thread_local! {
///     static CONTADOR: core::cell::Cell<u64> = core::cell::Cell::new(0);
/// }
/// CONTADOR.with(|c| c.set(c.get() + 1));
/// ```
///
/// O valor nasce no primeiro acesso de cada thread e é destruído quando ela
/// sai (`join` volta depois disso). Sem `#[thread_local]`; ver o módulo
/// [`tls`](crate::tls).
#[macro_export]
macro_rules! thread_local {
    () => {};
    ($(#[$meta:meta])* $vis:vis static $name:ident : $ty:ty = $init:expr; $($rest:tt)*) => {
        $(#[$meta])*
        $vis static $name: $crate::tls::LocalKey<$ty> = $crate::tls::LocalKey::new(|| $init);
        $crate::thread_local!($($rest)*);
    };
    ($(#[$meta:meta])* $vis:vis static $name:ident : $ty:ty = $init:expr) => {
        $crate::thread_local!($(#[$meta])* $vis static $name: $ty = $init;);
    };
}
