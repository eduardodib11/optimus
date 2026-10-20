//! Aleatoriedade (ADR 0039, item 4; T-337).
//!
//! - [`secure_fill`]: bytes criptográficos do kernel (`sys_info` de entropia,
//!   classe 5, [`kabi::sched::SYS_INFO_ENTROPY`]), em pedaços de
//!   [`kabi::sched::SYS_INFO_ENTROPY_BYTES`] bytes. Para chaves e nonces;
//!   não é gerador de volume.
//! - [`fast_u64`], [`fast_below`], [`fast_fill`]: xoshiro256++ por thread
//!   ([`ocoll::prng::Xoshiro256pp`]), semeado uma vez por thread com
//!   [`secure_fill`]. **Não** é criptográfico: serve a índices de tabela e
//!   sorteios.
//! - [`is_degraded`]: o kernel recusou a entropia (`NotSupported`: o
//!   `optboot` não achou fonte) e o `ostd` caiu na mistura de reserva
//!   ([`mix_fill`]: relógio, endereço da pilha, id da thread e um
//!   contador). `NotSupported` nunca derruba o programa: o `ostd` avisa uma
//!   vez no registro de depuração e marca a degradação. Serviços que fazem
//!   criptografia devem checar [`is_degraded`] e se recusar a iniciar
//!   (decisão 5 da ADR 0039).
//!
//! A semente do processo ([`process_seed`]) alimenta o `HashMap`
//! ([`crate::collections`]) e o alocador ([`crate::alloc`]); nenhuma das
//! duas chamadas aloca.

use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use kabi::Error;
use kabi::Syscall;
use kabi::sched::{SYS_INFO_ENTROPY, SYS_INFO_ENTROPY_BYTES};
use ocoll::prng::{Xoshiro256pp, mix64};

use crate::sys::syscall;

/// Enche `buf` com bytes aleatórios criptográficos do kernel.
///
/// # Errors
///
/// `NotSupported` se o kernel não tem entropia (o `optboot` não achou
/// fonte); `buf` pode ter sido preenchido em parte. Não marca
/// [`is_degraded`]: quem usa a mistura de reserva por conta própria decide.
pub fn secure_fill(buf: &mut [u8]) -> Result<(), Error> {
    for chunk in buf.chunks_mut(SYS_INFO_ENTROPY_BYTES) {
        let words = syscall(Syscall::SysInfo, [SYS_INFO_ENTROPY, 0, 0, 0, 0, 0])?;
        let mut bytes = [0u8; SYS_INFO_ENTROPY_BYTES];
        for (dst, w) in bytes.chunks_exact_mut(8).zip(words) {
            dst.copy_from_slice(&w.to_le_bytes());
        }
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    Ok(())
}

static DEGRADED: AtomicBool = AtomicBool::new(false);

/// O `ostd` já precisou da mistura de reserva por falta de entropia do
/// kernel (e, portanto, a aleatoriedade deste processo é fraca)?
#[must_use]
pub fn is_degraded() -> bool {
    DEGRADED.load(Ordering::Relaxed)
}

/// Marca a degradação e avisa uma vez no registro de depuração.
fn degrade() {
    if !DEGRADED.swap(true, Ordering::Relaxed) {
        crate::debug::print("ostd: aviso: kernel sem entropia; aleatoriedade degradada");
    }
}

static MIX_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Mistura de reserva: enche `buf` com um embaralhamento do relógio
/// monotônico, do endereço de uma variável da pilha, do id da thread e de
/// um contador global. **Fraca** (um atacante que conhece o horário aproximado
/// do boot a adivinha); só existe para o `ostd` não parar quando o kernel não
/// tem entropia. Não marca [`is_degraded`].
pub fn mix_fill(buf: &mut [u8]) {
    let local = 0u8;
    let n = MIX_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut state = mix64(crate::time::now_ns())
        ^ mix64((&raw const local).addr() as u64)
        ^ mix64(crate::tls::current().id().rotate_left(32))
        ^ mix64(n.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    for chunk in buf.chunks_mut(8) {
        state = mix64(state.wrapping_add(0x9E37_79B9_7F4A_7C15));
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
}

/// Bytes do kernel, ou a mistura de reserva (marcando a degradação) se ele
/// recusar.
fn fill_or_degrade(buf: &mut [u8]) {
    if secure_fill(buf).is_err() {
        degrade();
        mix_fill(buf);
    }
}

// ---- semente do processo ----

const UNSEEDED: u8 = 0;
const SEEDING: u8 = 1;
const SEEDED: u8 = 2;

static SEED_STATE: AtomicU8 = AtomicU8::new(UNSEEDED);
static SEED: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static STREAM: AtomicU64 = AtomicU64::new(0);

/// A semente de 256 bits do processo, tirada do kernel (ou da mistura de
/// reserva) na primeira chamada. Não aloca; é segura de chamar de dentro do
/// alocador.
#[must_use]
pub fn process_seed() -> [u64; 4] {
    loop {
        match SEED_STATE.load(Ordering::Acquire) {
            SEEDED => break,
            UNSEEDED => {
                if SEED_STATE
                    .compare_exchange(UNSEEDED, SEEDING, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    let mut bytes = [0u8; 32];
                    fill_or_degrade(&mut bytes);
                    for (cell, c) in SEED.iter().zip(bytes.chunks_exact(8)) {
                        cell.store(
                            u64::from_le_bytes(c.try_into().unwrap_or([0; 8])),
                            Ordering::Relaxed,
                        );
                    }
                    SEED_STATE.store(SEEDED, Ordering::Release);
                    break;
                }
            }
            // Outra thread está semeando (um punhado de instruções e uma
            // syscall): espera.
            _ => core::hint::spin_loop(),
        }
    }
    [
        SEED[0].load(Ordering::Relaxed),
        SEED[1].load(Ordering::Relaxed),
        SEED[2].load(Ordering::Relaxed),
        SEED[3].load(Ordering::Relaxed),
    ]
}

/// Próxima palavra de um fluxo do processo inteiro: `SplitMix` sobre a semente
/// do processo, com contador atômico (sem trava, sem alocar). Cada chamada
/// dá um valor diferente. **Não** é criptográfico; o alocador o usa para o
/// endereço dos segmentos e as chaves do endurecimento.
pub(crate) fn stream_u64() -> u64 {
    let seed = process_seed();
    let n = STREAM.fetch_add(1, Ordering::Relaxed);
    mix64(seed[1] ^ mix64(seed[0].wrapping_add(n.wrapping_mul(0x9E37_79B9_7F4A_7C15))))
}

/// Semeia o `HashMap` ([`crate::collections`]) com a semente do processo.
/// Chamada por [`crate::rt::init`].
pub(crate) fn seed_collections() {
    let s = process_seed();
    ocoll::seed_random_state([s[2], s[3]]);
}

// ---- xoshiro por thread ----

crate::thread_local! {
    static FAST: RefCell<Xoshiro256pp> = RefCell::new(new_fast());
}

/// Gerador novo da thread: semente de 32 bytes do kernel, ou da mistura de
/// reserva.
fn new_fast() -> Xoshiro256pp {
    let mut seed = [0u8; 32];
    fill_or_degrade(&mut seed);
    Xoshiro256pp::from_bytes(&seed)
}

/// Próxima palavra do xoshiro256++ da thread. **Não criptográfico**: use
/// [`secure_fill`] para chaves e nonces.
#[must_use]
pub fn fast_u64() -> u64 {
    FAST.with(|g| g.borrow_mut().next_u64())
}

/// Valor uniforme em `0..n` (`n = 0` dá 0), do xoshiro da thread.
#[must_use]
pub fn fast_below(n: u64) -> u64 {
    FAST.with(|g| g.borrow_mut().below(n))
}

/// Enche `buf` do xoshiro da thread.
pub fn fast_fill(buf: &mut [u8]) {
    FAST.with(|g| g.borrow_mut().fill(buf));
}
