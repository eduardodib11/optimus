//! `okfuzz`: fuzzer de syscalls do Optimus (T-214; SDD v1.0, seção 18).
//!
//! O kernel inicia este programa no anel 3 com `test=fuzz` (convenção em
//! [`ostd::kabi::fuzz`]), em duas threads que partilham o `CapSpace` do
//! processo:
//!
//! - a principal recebe a cota raiz em `rdi` e o próprio `AddressSpace` em
//!   `rsi`, e roda o [`fuzzer`] estruturado: mantém um pool exato dos
//!   handles que conhece (tipo e pai na árvore de derivação) e chama as
//!   syscalls com argumentos aleatórios mas plausíveis — handles reais e
//!   lixo, endereços válidos e inválidos, tamanhos no limite — criando e
//!   destruindo objetos de todo tipo para exercitar `CapSpace`, revogação,
//!   VM, threads, notificações, futex e IPC. Tudo o que pode bloquear usa
//!   prazo vencido ou [`FLAG_NONBLOCK`], então a thread nunca trava;
//! - a auxiliar não recebe handle nenhum e martela syscalls com
//!   argumentos totalmente aleatórios ([`noise`]), sem nunca criar objeto
//!   (não tem a cota) nem chamar uma syscall que bloqueie. Roda junto com a
//!   principal e exercita o despacho e a validação sob troca de contexto.
//!
//! A semente (reproduzível) e a duração chegam na [`Config`] de `rdx`. O
//! kernel confere, ao fim, que a cota raiz voltou ao que era: nada do que o
//! fuzzer criou pode vazar.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::kabi::Syscall;
use ostd::kabi::fuzz::Config;
use ostd::rt::Start;

#[macro_use]
mod out;
mod fuzzer;
mod pool;
mod rng;

use rng::Rng;

ostd::entry!(main);

/// Syscalls que a thread auxiliar nunca emite ao acaso: as que bloqueiam
/// (sem prazo nem `FLAG_NONBLOCK` acessível aqui) e `thread_exit`.
const NOISE_FORBIDDEN: &[u64] = &[
    Syscall::IpcSend as u64,
    Syscall::IpcRecv as u64,
    Syscall::IpcCall as u64,
    Syscall::IpcReplyRecv as u64,
    Syscall::NtfyWait as u64,
    Syscall::FutexWait as u64,
    Syscall::ThreadExit as u64,
];

fn now_ns() -> u64 {
    ostd::time::now_ns()
}

/// Instante em que a rodada acaba.
fn deadline(config: Config) -> u64 {
    now_ns().saturating_add(u64::from(config.seconds) * 1_000_000_000)
}

/// Thread auxiliar: syscalls com número e argumentos aleatórios, sem criar
/// objeto nem bloquear, até o prazo.
fn noise(mut rng: Rng, until: u64) {
    let mut count: u64 = 0;
    while now_ns() < until {
        for _ in 0..512 {
            let mut nr = rng.next() % 40;
            while NOISE_FORBIDDEN.contains(&nr) {
                nr = rng.next() % 40;
            }
            let args = [
                fuzzer::wild(&mut rng),
                fuzzer::wild(&mut rng),
                fuzzer::wild(&mut rng),
                fuzzer::wild(&mut rng),
                fuzzer::wild(&mut rng),
                fuzzer::wild(&mut rng),
            ];
            // `aspace = 0` é o próprio espaço (ADR 0039): um `vm_unmap` ao
            // acaso nele derrubaria o fuzzer (código e pilha).
            if nr == Syscall::VmUnmap as u64 && args[0] == ostd::kabi::vm::SELF {
                continue;
            }
            let _ = ostd::sys::call(nr, args);
            count += 1;
        }
        ostd::thread::yield_now();
    }
    say!("okfuzz: auxiliar fez {count} chamadas");
}

fn main(start: Start) -> ! {
    let config = Config::from_raw(start.args[2]);
    // A principal tem a cota (rdi) e o próprio espaço (rsi); a auxiliar
    // recebe zero nos dois.
    if start.args[0] == 0 && start.args[1] == 0 {
        noise(Rng::new(config.seed ^ 0xa5a5_a5a5), deadline(config));
        ostd::thread::exit();
    }
    say!(
        "okfuzz: principal, semente {:#x}, {} s",
        config.seed,
        config.seconds
    );
    let mut f = fuzzer::Fuzzer::new(config.seed, start.args[0], start.args[1]);
    let until = deadline(config);
    let mut iters: u64 = 0;
    while now_ns() < until {
        for _ in 0..256 {
            f.step();
            iters += 1;
        }
        ostd::thread::yield_now();
    }
    say!(
        "okfuzz: principal fez {iters} passos, {} handles vivos",
        f.live()
    );
    ostd::thread::exit()
}
