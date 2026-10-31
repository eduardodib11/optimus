//! `utest`: o harness de testes de usuário (T-332).
//!
//! Com `test=user` na linha de comando, o kernel inicia este serviço do
//! bootfs no lugar do `root`, com as mesmas capabilities iniciais: a cota
//! raiz em `rdi` e o próprio espaço em `rsi`. Ele roda cada teste de
//! [`TESTS`] no anel 3 e escreve o relatório na serial, no mesmo estilo do
//! `ktest` do kernel:
//!
//! ```text
//! utest: início, N testes
//! utest: ok nome
//! utest: FALHOU nome: motivo
//! utest: fim: P ok, F falharam
//! ```
//!
//! O `cargo xtask test user` confere esse relatório (e só passa com
//! `0 falharam`). Para provar que uma falha derruba o comando sem deixar
//! um teste quebrado na suíte, o teste [`proposital`] só existe se o
//! `utest` for compilado com `UTEST_FALHA=1` (`cargo xtask test user
//! --falha-proposital`).
//!
//! O `utest` também é o primeiro processo a usar o alocador global do `ostd`
//! (T-334): `Box`, `Vec` e `String` funcionam porque a função principal
//! registra a cota em [`ostd::rt::init`] antes de alocar (o alocador mapeia
//! no próprio espaço com `aspace = 0`, T-333).
//!
//! Para acrescentar um teste, escreva uma `fn(&Ctx) -> Result<(), &'static
//! str>` e a ponha em [`TESTS`].

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use ostd::cap::{create, delete};
use ostd::ipc::{self, Message};
use ostd::kabi::ipc::FLAG_NONBLOCK;
use ostd::kabi::{Error, Handle, ObjectType};
use ostd::rt::{Env, Start};

mod anel;
mod tempo;
mod timer;
mod vida;

ostd::entry!(main);

/// Capabilities iniciais que os testes podem usar.
struct Ctx {
    /// Cota raiz.
    quota: Handle,
    /// `MemoryObject` do bootfs (o `rdx` inicial, parte alta).
    bootfs: Handle,
}

/// Bloco com alinhamento de página.
#[repr(align(4096))]
struct PageAligned([u8; 64]);

/// Resultado de um teste: `Err` com o motivo da falha.
type Outcome = Result<(), &'static str>;

/// Um teste: nome (como aparece na serial) e função.
struct Test {
    name: &'static str,
    run: fn(&Ctx) -> Outcome,
}

/// Os testes, na ordem em que rodam.
const TESTS: &[Test] = &[
    Test {
        name: "cap.criar_e_apagar",
        run: criar_e_apagar,
    },
    Test {
        name: "ipc.sem_par",
        run: ipc_sem_par,
    },
    Test {
        name: "time.monotonico",
        run: monotonico,
    },
    Test {
        name: "alloc.global",
        run: alocador_global,
    },
    Test {
        name: "alloc.sem_memoria",
        run: alocador_sem_memoria,
    },
    Test {
        name: "alloc.janela_reaproveitada",
        run: alocador_reaproveita_janela,
    },
    Test {
        name: "tls.configurar_e_recusar",
        run: tls_configurar,
    },
    Test {
        name: "vm.proprio_espaco_sem_handle",
        run: vm_proprio_espaco,
    },
    Test {
        name: "thread.exit_recusa_flags",
        run: vida::exit_recusa_flags,
    },
    Test {
        name: "thread.cem_sem_vazar_cota",
        run: threads_cem,
    },
    Test {
        name: "thread.tls_de_cada_uma",
        run: threads_tls,
    },
    Test {
        name: "thread.alocacao_concorrente",
        run: threads_alocacao,
    },
    Test {
        name: "thread.alocacao_repetida",
        run: threads_alocacao_repetida,
    },
    Test {
        name: "thread.buffer_de_ipc_proprio",
        run: threads_buffer_ipc,
    },
    Test {
        name: "thread.pilha_com_guarda",
        run: threads_guarda,
    },
    Test {
        name: "thread.join_de_encerradas",
        run: vida::join_de_encerradas,
    },
    Test {
        name: "thread.largada_devolve_regiao",
        run: vida::largada_devolve_regiao,
    },
    Test {
        name: "processo.cem_criados_e_encerrados",
        run: vida::cem_processos,
    },
    Test {
        name: "processo.encerrado_em_ipc_call",
        run: vida::encerrado_em_ipc_call,
    },
    Test {
        name: "processo.limite_e_recusas",
        run: vida::limite_e_recusas,
    },
    Test {
        name: "processo.partida_em_encerrado",
        run: vida::partida_em_processo_encerrado,
    },
    Test {
        name: "timer.disparo_unico",
        run: timer::disparo_unico,
    },
    Test {
        name: "timer.periodico_e_desarme",
        run: timer::periodico_e_desarme,
    },
    Test {
        name: "timer.rearme_noutra_cpu",
        run: timer::rearme_noutra_cpu,
    },
    Test {
        name: "timer.destruido_armado",
        run: timer::destruido_armado,
    },
    Test {
        name: "timer.de_processo_encerrado",
        run: vida::timer_de_processo_encerrado,
    },
    Test {
        name: "timer.mil_de_uma_vez",
        run: timer::mil_timers,
    },
    Test {
        name: "sync.mutex_contador",
        run: sync_mutex,
    },
    Test {
        name: "sync.condvar_produtor_consumidor",
        run: sync_condvar,
    },
    Test {
        name: "sync.once_uma_vez",
        run: sync_once,
    },
    Test {
        name: "sync.rwlock",
        run: sync_rwlock,
    },
    Test {
        name: "time.instant",
        run: tempo::instant,
    },
    Test {
        name: "time.sleep_curto",
        run: tempo::sleep_curto,
    },
    Test {
        name: "time.sleep_longo",
        run: tempo::sleep_longo,
    },
    Test {
        name: "time.sleep_em_threads",
        run: tempo::sleep_em_threads,
    },
    Test {
        name: "sync.condvar_estoura",
        run: tempo::condvar_estoura,
    },
    Test {
        name: "sync.condvar_acordada",
        run: tempo::condvar_acordada,
    },
    Test {
        name: "sync.condvar_sem_perda",
        run: tempo::condvar_sem_perda,
    },
    Test {
        name: "thread.join_com_prazo",
        run: tempo::join_com_prazo,
    },
    Test {
        name: "rand.entropia_do_kernel",
        run: rand_entropia,
    },
    Test {
        name: "rand.fast_e_reserva",
        run: rand_fast,
    },
    Test {
        name: "rand.semente_e_heap_sorteado",
        run: rand_semente,
    },
    Test {
        name: "collections.hashmap_contra_modelo",
        run: colecoes_hashmap,
    },
    Test {
        name: "collections.ring_e_fila",
        run: colecoes_ring,
    },
    Test {
        name: "ring.modelo",
        run: anel::modelo,
    },
    Test {
        name: "ring.par_que_mente",
        run: anel::par_que_mente,
    },
    Test {
        name: "ring.dois_processos",
        run: anel::dois_processos,
    },
    Test {
        name: "utf8.bordas_e_decodificador",
        run: utf8_bordas,
    },
    #[cfg(utest_falha)]
    Test {
        name: "proposital",
        run: proposital,
    },
];

/// Criar um endpoint na cota e apagá-lo; apagar de novo é erro.
fn criar_e_apagar(ctx: &Ctx) -> Outcome {
    let ep = create(ctx.quota, ObjectType::Endpoint, 0).map_err(|_| "create falhou")?;
    delete(ep).map_err(|_| "delete falhou")?;
    match delete(ep) {
        Err(_) => Ok(()),
        Ok(()) => Err("apagar duas vezes devia falhar"),
    }
}

/// Sem ninguém no endpoint, receber com prazo vencido dá `TimedOut` e
/// enviar sem bloquear dá `WouldBlock`.
fn ipc_sem_par(ctx: &Ctx) -> Outcome {
    let ep = create(ctx.quota, ObjectType::Endpoint, 0).map_err(|_| "create(endpoint)")?;
    let reply = create(ctx.quota, ObjectType::Reply, 0).map_err(|_| "create(reply)")?;
    let timed_out = ipc::recv(ep, reply, 1) == Err(Error::TimedOut);
    let mut msg = Message::new(1, &[2, 3]);
    msg.info.flags = FLAG_NONBLOCK;
    let would_block = ipc::send(ep, &msg, 0) == Err(Error::WouldBlock);
    let _ = (delete(ep), delete(reply));
    match (timed_out, would_block) {
        (true, true) => Ok(()),
        (false, _) => Err("recv devia dar TimedOut"),
        (_, false) => Err("send devia dar WouldBlock"),
    }
}

/// O relógio não anda para trás.
fn monotonico(_: &Ctx) -> Outcome {
    let a = ostd::time::now_ns();
    let b = ostd::time::now_ns();
    if a > 0 && b >= a {
        Ok(())
    } else {
        Err("o relógio andou para trás")
    }
}

/// O alocador global: `Box`, `Vec` que cresce por `realloc` (passando de
/// bloco pequeno a grande), um bloco enorme (segmento próprio), `String`,
/// alinhamento de página e, depois de soltar tudo, nenhum bloco a mais vivo.
fn alocador_global(_: &Ctx) -> Outcome {
    let before = ostd::alloc::stats();
    {
        let boxed = Box::new([7u64; 100]);
        if boxed.iter().any(|&w| w != 7) {
            return Err("Box corrompido");
        }
        let mut v: Vec<u32> = Vec::new();
        for i in 0..50_000u32 {
            v.push(i.wrapping_mul(2_654_435_761));
        }
        if v.iter()
            .zip(0..)
            .any(|(&w, i): (&u32, u32)| w != i.wrapping_mul(2_654_435_761))
        {
            return Err("Vec corrompido depois de crescer");
        }
        let mut big: Vec<u8> = Vec::with_capacity(3 << 20);
        big.resize(3 << 20, 0xAB);
        big[0] = 1;
        big[(3 << 20) - 1] = 2;
        if big[0] != 1 || big[1 << 20] != 0xAB || big[(3 << 20) - 1] != 2 {
            return Err("bloco enorme corrompido");
        }
        let mut text = String::new();
        for _ in 0..1000 {
            text.push_str("optimus ");
        }
        if text.len() != 8000 || !text.starts_with("optimus optimus") {
            return Err("String corrompida");
        }
        let aligned = Box::new(PageAligned([9; 64]));
        if !(&raw const *aligned).addr().is_multiple_of(4096) || aligned.0[63] != 9 {
            return Err("alinhamento de página não respeitado");
        }
        let small: Vec<Box<u64>> = (0..5000u64).map(Box::new).collect();
        if small.iter().zip(0..).any(|(b, i)| **b != i) {
            return Err("blocos pequenos corrompidos");
        }
        let during = ostd::alloc::stats();
        if during.live_blocks < before.live_blocks + 5000 {
            return Err("stats não vê os blocos vivos");
        }
    }
    let after = ostd::alloc::stats();
    if after.live_blocks == before.live_blocks && after.live_bytes == before.live_bytes {
        Ok(())
    } else {
        Err("vazou memória ao soltar tudo")
    }
}

/// Memória esgotada: o pedido que a cota não cobre devolve erro (nulo no
/// alocador) e o alocador continua servindo.
fn alocador_sem_memoria(_: &Ctx) -> Outcome {
    let mut v: Vec<u8> = Vec::new();
    // 1 TiB: passa da cota do processo.
    if v.try_reserve_exact(1 << 40).is_ok() {
        return Err("1 TiB devia falhar");
    }
    let mut w: Vec<u64> = Vec::new();
    w.try_reserve_exact(1000)
        .map_err(|_| "alocação pequena falhou depois do erro")?;
    w.push(1);
    Ok(())
}

/// Blocos enormes alocados e liberados em laço reaproveitam a mesma faixa da
/// janela de endereços, em vez de avançar por ela.
fn alocador_reaproveita_janela(_: &Ctx) -> Outcome {
    let mut first = 0;
    for i in 0..50 {
        let mut big: Vec<u8> = Vec::with_capacity(3 << 20);
        big.resize(3 << 20, 1);
        let addr = big.as_ptr().addr();
        if i == 0 {
            first = addr;
        } else if addr != first {
            return Err("a faixa liberada não foi reaproveitada");
        }
    }
    Ok(())
}

/// `thread_configure` com `CONFIGURE_TLS` (T-333): na própria thread
/// (`thread = 0`) e noutra pela capability; recusa endereço não canônico, da
/// metade do kernel, TLS junto com o buffer de IPC, ligação com `thread =
/// 0` e handle inválido.
fn tls_configurar(ctx: &Ctx) -> Outcome {
    // O `FS_BASE` da principal é o bloco da thread (T-335): devolve-o no fim.
    let block = ostd::tls::current().addr();
    let result = tls_configurar_com(ctx);
    ostd::thread::set_tls(ostd::thread::SELF, block).map_err(|_| "restaurar o TLS")?;
    result
}

fn tls_configurar_com(ctx: &Ctx) -> Outcome {
    use ostd::kabi::Syscall;
    use ostd::kabi::thread::{CONFIGURE_IPC_BUFFER, CONFIGURE_TLS};
    use ostd::kabi::vm::USER_END;
    use ostd::thread::{SELF, set_tls};
    let va = 0x7000_0000;
    set_tls(SELF, va).map_err(|_| "TLS da própria thread")?;
    set_tls(SELF, USER_END - 1).map_err(|_| "TLS no fim da metade de usuário")?;
    for bad in [
        USER_END,
        0x0000_8000_0000_1000,
        0xffff_8000_0000_0000,
        u64::MAX,
    ] {
        if set_tls(SELF, bad) != Err(Error::InvalidArgument) {
            return Err("TLS fora da metade de usuário devia ser recusado");
        }
    }
    let raw = |args| ostd::sys::syscall(Syscall::ThreadConfigure, args).map(drop);
    if raw([0, 0, 0, va, 0, CONFIGURE_TLS | CONFIGURE_IPC_BUFFER]) != Err(Error::InvalidArgument) {
        return Err("TLS junto com o buffer de IPC devia ser recusado");
    }
    if raw([0, 1, 1, va, 0, CONFIGURE_TLS]) != Err(Error::InvalidArgument) {
        return Err("thread = 0 não liga CapSpace nem AddressSpace");
    }
    if set_tls(Handle::from_raw(0x00ab_cdef), va) != Err(Error::InvalidHandle) {
        return Err("handle inválido devia dar InvalidHandle");
    }
    let ep = create(ctx.quota, ObjectType::Endpoint, 0).map_err(|_| "create(endpoint)")?;
    let not_thread = set_tls(ep, va).is_err();
    let other = create(ctx.quota, ObjectType::Thread, 0).map_err(|_| "create(thread)")?;
    let on_other = set_tls(other, va);
    let _ = (delete(ep), delete(other));
    set_tls(SELF, 0).map_err(|_| "tirar o TLS")?;
    match (not_thread, on_other) {
        (true, Ok(())) => Ok(()),
        (false, _) => Err("TLS num endpoint devia falhar"),
        (_, Err(_)) => Err("TLS noutra thread pela capability falhou"),
    }
}

/// `vm_map` e `vm_unmap` com `aspace = 0` (T-333): o espaço de quem chama,
/// sem handle.
fn vm_proprio_espaco(ctx: &Ctx) -> Outcome {
    use ostd::kabi::vm::{PAGE_SIZE, WRITE};
    use ostd::vm::{Mapping, SELF};
    let va = 0x7100_0000;
    let object = create(ctx.quota, ObjectType::MemoryObject, PAGE_SIZE).map_err(|_| "create")?;
    let result = (|| {
        let mut m = Mapping::new(SELF, object, va, PAGE_SIZE, WRITE).map_err(|_| "vm_map(0)")?;
        let bytes = m.bytes_mut().ok_or("não gravável")?;
        bytes[0] = 0x5a;
        bytes[4095] = 0xa5;
        if m.bytes()[0] != 0x5a || m.bytes()[4095] != 0xa5 {
            return Err("a página mapeada não guardou os bytes");
        }
        drop(m);
        // O `Drop` desmapeou com `aspace = 0`: mapear de novo funciona.
        let again = Mapping::new(SELF, object, va, PAGE_SIZE, 0).map_err(|_| "vm_map de novo")?;
        drop(again);
        Ok(())
    })();
    let _ = delete(object);
    result
}

/// Quantas páginas a cota `quota` ainda cobre: cria `MemoryObject`s de uma
/// página até a cota negar e os apaga. Serve para comparar a cota antes e
/// depois (a `sys_info` ainda não mostra o uso).
fn quota_pages(quota: Handle) -> Result<usize, &'static str> {
    use ostd::kabi::vm::PAGE_SIZE;
    let mut held = Vec::new();
    loop {
        match create(quota, ObjectType::MemoryObject, PAGE_SIZE) {
            Ok(h) => held.push(h),
            Err(Error::QuotaExceeded) => break,
            Err(_) => return Err("create(page) falhou por outro motivo"),
        }
    }
    let n = held.len();
    for h in held {
        delete(h).map_err(|_| "delete(page)")?;
    }
    Ok(n)
}

/// Cota filha de `bytes` para os testes de thread.
fn child_quota(ctx: &Ctx, bytes: u64) -> Result<Handle, &'static str> {
    create(ctx.quota, ObjectType::MemoryQuota, bytes).map_err(|_| "create(quota)")
}

/// T-335: 100 threads criadas e juntadas, uma depois da outra e em lotes,
/// com o resultado certo e sem vazar cota (pilha, bloco, `Thread`,
/// `SchedContext`) nem segmentos do heap.
fn threads_cem(ctx: &Ctx) -> Outcome {
    use ostd::thread::Builder;
    let q = child_quota(ctx, 4 << 20)?;
    let segments = ostd::alloc::mapped_segments();
    let before = quota_pages(q)?;
    if before < 900 {
        return Err("a cota filha devia cobrir quase 4 MiB");
    }
    let mut sum = 0u64;
    for i in 0..50u64 {
        let h = Builder::new()
            .quota(q)
            .spawn(move || {
                let v: Vec<u64> = (0..100).map(|k| k * i).collect();
                v.iter().sum::<u64>() + ostd::thread::id()
            })
            .map_err(|_| "spawn falhou")?;
        let id = h.thread_id();
        let got = h.join().map_err(|_| "join devolveu Err")?;
        if got != (0..100u64).map(|k| k * i).sum::<u64>() + id {
            return Err("resultado errado");
        }
        sum += got;
    }
    for _ in 0..5 {
        let mut hs = Vec::new();
        for i in 0..10u64 {
            hs.push(
                Builder::new()
                    .quota(q)
                    .spawn(move || {
                        // Cede a vez no meio, para as threads se misturarem.
                        ostd::thread::yield_now();
                        i * 3
                    })
                    .map_err(|_| "spawn em lote falhou")?,
            );
        }
        for (i, h) in (0..10u64).zip(hs) {
            if h.join() != Ok(i * 3) {
                return Err("resultado errado em lote");
            }
        }
    }
    if sum == 0 {
        return Err("soma zerada");
    }
    // O kernel devolve o `Thread` e o `SchedContext` quando a thread acaba
    // de sair; dá um tempo para a última terminar.
    let mut after = 0;
    for _ in 0..10_000 {
        after = quota_pages(q)?;
        if after == before {
            break;
        }
        ostd::thread::yield_now();
    }
    let leaked = after != before;
    let after_segments = ostd::alloc::mapped_segments();
    let _ = delete(q);
    if leaked {
        return Err("a cota não voltou ao que era depois de juntar as threads");
    }
    if after_segments > segments + 1 {
        return Err("segmentos do heap vazaram");
    }
    Ok(())
}

/// Byte de enchimento do bloco `i` da thread `k`.
#[allow(clippy::cast_possible_truncation, reason = "só os 8 bits baixos")]
fn pattern(i: usize, k: u64) -> u8 {
    (i as u8) ^ (k as u8)
}

ostd::thread_local! {
    static TAG: core::cell::Cell<u64> = core::cell::Cell::new(0);
    static NOTE: Noted = Noted(0);
}

/// Valor de `thread_local!` que conta os destrutores.
struct Noted(u64);

static DROPPED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

impl Drop for Noted {
    fn drop(&mut self) {
        DROPPED.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }
}

/// `thread_local!`: cada thread vê o seu valor (também depois de ceder a
/// vez, em CPUs diferentes), a principal não é afetada e os destrutores
/// rodam na saída de cada thread.
fn threads_tls(_: &Ctx) -> Outcome {
    use core::sync::atomic::Ordering::SeqCst;
    TAG.with(|t| t.set(7));
    NOTE.with(|n| assert_eq!(n.0, 0));
    let dropped0 = DROPPED.load(SeqCst);
    let mut hs = Vec::new();
    for k in 0..4u64 {
        hs.push(ostd::thread::spawn(move || {
            if TAG.with(core::cell::Cell::get) != 0 {
                return false;
            }
            TAG.with(|t| t.set(1000 + k));
            NOTE.with(|_| ());
            for _ in 0..200 {
                ostd::thread::yield_now();
                if TAG.with(core::cell::Cell::get) != 1000 + k {
                    return false;
                }
            }
            true
        }));
    }
    for h in hs {
        if h.join() != Ok(true) {
            return Err("uma thread viu o thread_local de outra");
        }
    }
    if TAG.with(core::cell::Cell::get) != 7 {
        return Err("o thread_local da principal mudou");
    }
    if DROPPED.load(SeqCst) != dropped0 + 4 {
        return Err("os destrutores dos thread_local não rodaram uma vez por thread");
    }
    Ok(())
}

/// Alocação em várias threads ao mesmo tempo, com liberação entre threads: a
/// principal solta blocos de threads que já saíram (heap abandonado), e uma
/// thread solta blocos da principal.
fn threads_alocacao(_: &Ctx) -> Outcome {
    let segments = ostd::alloc::mapped_segments();
    let mut hs = Vec::new();
    for k in 0..4u64 {
        hs.push(ostd::thread::spawn(move || {
            let mut keep: Vec<Vec<u8>> = Vec::new();
            let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ k;
            for i in 0..6_000usize {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let size = 1 + (state >> 40) as usize % 3000;
                let mut v = Vec::with_capacity(size);
                v.resize(size, pattern(i, k));
                if i % 8 == 0 {
                    keep.push(v);
                } else if v.iter().any(|&b| b != pattern(i, k)) {
                    return None;
                }
            }
            Some((k, keep))
        }));
    }
    let mut survivors = Vec::new();
    for h in hs {
        match h.join() {
            Ok(Some(s)) => survivors.push(s),
            _ => return Err("uma thread de alocação falhou"),
        }
    }
    // Das threads que já saíram: ler e soltar aqui.
    for (k, keep) in &survivors {
        for (j, v) in keep.iter().enumerate() {
            let want = pattern(j * 8, *k);
            if v.iter().any(|&b| b != want) {
                return Err("bloco de thread que saiu corrompido");
            }
        }
    }
    drop(survivors);
    // Da principal para outra thread soltar.
    let blocks: Vec<Vec<u64>> = (0..2000u64).map(|i| alloc::vec![i; 50]).collect();
    let h = ostd::thread::spawn(move || {
        let ok = blocks
            .iter()
            .zip(0u64..)
            .all(|(b, i)| b.iter().all(|&w| w == i));
        drop(blocks);
        ok
    });
    if h.join() != Ok(true) {
        return Err("a thread viu blocos corrompidos da principal");
    }
    // Tudo solto: a principal ainda pode alocar (e adota o que sobrou).
    let again: Vec<Vec<u8>> = (0..1000).map(|_| alloc::vec![1u8; 4000]).collect();
    drop(again);
    let after = ostd::alloc::mapped_segments();
    // Com as classes até 32 KiB (T-337) o crescimento dos `Vec` de `keep`
    // (8, 16, 32 KiB) passa a deixar uma página por classe em vez de páginas
    // inteiras que voltam logo: um segmento a mais fica retido.
    if after > segments + 3 {
        return Err("segmentos demais depois de soltar tudo");
    }
    Ok(())
}

/// A carga de `thread.alocacao_concorrente` 5 vezes seguidas no mesmo
/// processo: toda rodada tem de dar certo e os segmentos mapeados não podem
/// crescer com as rodadas. Cada rodada já confere `+3` sobre o início dela
/// (os segmentos presos na principal por uma página de classe cada); aqui o
/// teto vale para o total desde o começo, então um vazamento por rodada (antes
/// do T-335 de 2026-10-21: 1 → 4 → 10 segmentos e a cota de 28 MiB esgotada
/// na 2ª rodada) aparece. Cinco rodadas cabem na cota porque nada se acumula.
fn threads_alocacao_repetida(ctx: &Ctx) -> Outcome {
    let base = ostd::alloc::mapped_segments();
    for _ in 0..5 {
        threads_alocacao(ctx)?;
        if ostd::alloc::mapped_segments() > base + 3 {
            return Err("segmentos crescem a cada rodada");
        }
    }
    Ok(())
}

/// T-336: 4 threads incrementam um contador sob `Mutex` 10⁶ vezes no total,
/// sem perda; a principal também disputa a trava.
fn sync_mutex(_: &Ctx) -> Outcome {
    use alloc::sync::Arc;
    use ostd::sync::Mutex;
    const THREADS: u64 = 4;
    const TOTAL: u64 = 1_000_000;
    let counter = Arc::new(Mutex::new(0u64));
    let hs: Vec<_> = (0..THREADS)
        .map(|_| {
            let c = Arc::clone(&counter);
            ostd::thread::spawn(move || {
                for _ in 0..TOTAL / THREADS {
                    *c.lock() += 1;
                }
            })
        })
        .collect();
    for h in hs {
        h.join().map_err(|_| "thread do contador falhou")?;
    }
    if *counter.lock() != TOTAL {
        return Err("incrementos perdidos");
    }
    // `try_lock` com a trava tomada falha; livre, funciona.
    let g = counter.lock();
    if counter.try_lock().is_some() {
        return Err("try_lock com a trava tomada");
    }
    drop(g);
    if counter.try_lock().is_none() {
        return Err("try_lock com a trava livre");
    }
    Ok(())
}

/// T-336: dois produtores e dois consumidores numa fila limitada (capacidade
/// 4) com duas `Condvar`; cada item chega uma só vez.
fn sync_condvar(_: &Ctx) -> Outcome {
    use alloc::collections::VecDeque;
    use alloc::sync::Arc;
    use ostd::sync::{Condvar, Mutex};
    struct Queue {
        items: Mutex<(VecDeque<u32>, bool)>,
        not_empty: Condvar,
        not_full: Condvar,
    }
    const PRODUCERS: u32 = 2;
    const PER: u32 = 20_000;
    let q = Arc::new(Queue {
        items: Mutex::new((VecDeque::new(), false)),
        not_empty: Condvar::new(),
        not_full: Condvar::new(),
    });
    let consumers: Vec<_> = (0..2)
        .map(|_| {
            let q = Arc::clone(&q);
            ostd::thread::spawn(move || {
                let mut got = Vec::new();
                loop {
                    let mut g = q.items.lock();
                    while g.0.is_empty() && !g.1 {
                        g = q.not_empty.wait(g);
                    }
                    let Some(v) = g.0.pop_front() else { break };
                    drop(g);
                    q.not_full.notify_one();
                    got.push(v);
                }
                got
            })
        })
        .collect();
    let producers: Vec<_> = (0..PRODUCERS)
        .map(|p| {
            let q = Arc::clone(&q);
            ostd::thread::spawn(move || {
                for i in 0..PER {
                    let g = q.items.lock();
                    let mut g = q.not_full.wait_while(g, |s| s.0.len() >= 4);
                    g.0.push_back(p * PER + i);
                    drop(g);
                    q.not_empty.notify_one();
                }
            })
        })
        .collect();
    for h in producers {
        h.join().map_err(|_| "produtor falhou")?;
    }
    q.items.lock().1 = true;
    q.not_empty.notify_all();
    let mut seen = alloc::vec![0u8; (PRODUCERS * PER) as usize];
    for h in consumers {
        for v in h.join().map_err(|_| "consumidor falhou")? {
            let slot = seen
                .get_mut(usize::try_from(v).unwrap_or(usize::MAX))
                .ok_or("item fora da faixa")?;
            *slot += 1;
        }
    }
    if seen.iter().any(|&n| n != 1) {
        return Err("item perdido ou repetido");
    }
    Ok(())
}

/// T-336: 4 threads disputam `call_once` e `OnceLock::get_or_init`: a
/// inicialização roda uma vez e todas veem o resultado pronto.
fn sync_once(_: &Ctx) -> Outcome {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};
    use ostd::sync::{Once, OnceLock};
    struct Shared {
        once: Once,
        cell: OnceLock<u64>,
        runs: AtomicU32,
        done: AtomicU32,
    }
    let s = Arc::new(Shared {
        once: Once::new(),
        cell: OnceLock::new(),
        runs: AtomicU32::new(0),
        done: AtomicU32::new(0),
    });
    let hs: Vec<_> = (0..4)
        .map(|_| {
            let s = Arc::clone(&s);
            ostd::thread::spawn(move || {
                s.once.call_once(|| {
                    // Demora, para as outras chegarem e esperarem.
                    for _ in 0..5 {
                        ostd::thread::yield_now();
                    }
                    s.runs.fetch_add(1, Ordering::Relaxed);
                    s.done.store(1, Ordering::Relaxed);
                });
                let seen_done = s.done.load(Ordering::Relaxed);
                let v = *s.cell.get_or_init(|| {
                    s.runs.fetch_add(100, Ordering::Relaxed);
                    7
                });
                seen_done == 1 && v == 7
            })
        })
        .collect();
    for h in hs {
        if h.join() != Ok(true) {
            return Err("thread viu a inicialização incompleta");
        }
    }
    if s.runs.load(Ordering::Relaxed) != 101 || !s.once.is_completed() {
        return Err("a inicialização não rodou exatamente uma vez");
    }
    Ok(())
}

/// T-336: leitores ao mesmo tempo (um espera o outro dentro da seção) e
/// escritor exclusivo (invariante entre duas palavras nunca quebrada).
fn sync_rwlock(_: &Ctx) -> Outcome {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};
    use ostd::sync::RwLock;
    // Leitores simultâneos: 3 leitores só saem quando os 3 estão dentro.
    let lock = Arc::new(RwLock::new(5u64));
    let inside = Arc::new(AtomicU32::new(0));
    let hs: Vec<_> = (0..3)
        .map(|_| {
            let (l, n) = (Arc::clone(&lock), Arc::clone(&inside));
            ostd::thread::spawn(move || {
                let g = l.read();
                n.fetch_add(1, Ordering::SeqCst);
                let mut spins = 0u64;
                while n.load(Ordering::SeqCst) < 3 {
                    spins += 1;
                    if spins > 50_000_000 {
                        return false;
                    }
                    ostd::thread::yield_now();
                }
                *g == 5
            })
        })
        .collect();
    for h in hs {
        if h.join() != Ok(true) {
            return Err("leitores não ficaram juntos na seção");
        }
    }
    // Escritores exclusivos: (a, b) muda sempre junto; leitores veem a == b.
    let pair = Arc::new(RwLock::new((0u64, 0u64)));
    let mut hs = Vec::new();
    for w in 0..2 {
        let p = Arc::clone(&pair);
        hs.push(ostd::thread::spawn(move || {
            for _ in 0..5_000 {
                let mut g = p.write();
                g.0 += 1;
                if w == 0 {
                    ostd::thread::yield_now();
                }
                g.1 += 1;
            }
            true
        }));
    }
    for _ in 0..2 {
        let p = Arc::clone(&pair);
        hs.push(ostd::thread::spawn(move || {
            (0..10_000).all(|_| {
                let g = p.read();
                g.0 == g.1
            })
        }));
    }
    for h in hs {
        if h.join() != Ok(true) {
            return Err("leitor viu a invariante quebrada");
        }
    }
    if *pair.read() != (10_000, 10_000) {
        return Err("escritas perdidas");
    }
    Ok(())
}

/// Cada thread tem o seu buffer de IPC (no bloco dela), em endereços
/// diferentes e que não se misturam.
fn threads_buffer_ipc(_: &Ctx) -> Outcome {
    use ostd::tls::{current, with_ipc_buffer};
    with_ipc_buffer(|b| b.words[0] = 0xAAAA);
    let main_va = current().ipc_va();
    let hs: Vec<_> = (0..4u64)
        .map(|k| {
            ostd::thread::spawn(move || {
                with_ipc_buffer(|b| b.words[0] = k);
                ostd::thread::yield_now();
                let own = with_ipc_buffer(|b| b.words[0]) == k;
                (current().ipc_va(), own)
            })
        })
        .collect();
    let mut seen = Vec::new();
    for h in hs {
        let (va, own) = h.join().map_err(|_| "join")?;
        if !own || va == main_va || va % 4096 != 0 || seen.contains(&va) {
            return Err("buffer de IPC compartilhado ou desalinhado");
        }
        seen.push(va);
    }
    if with_ipc_buffer(|b| b.words[0]) != 0xAAAA {
        return Err("o buffer da principal mudou");
    }
    Ok(())
}

/// Recursão sem fim numa thread de pilha pequena cai na página de guarda: a
/// falta chega ao endpoint de exceções da thread com o endereço dentro da
/// guarda. A resposta encerra a thread, e `join` volta com o registro de
/// morte (`Faulted`, vetor 14, o endereço; T-348).
fn threads_guarda(ctx: &Ctx) -> Outcome {
    /// Vetor da falta de página.
    const PAGE_FAULT_VECTOR: u64 = 14;
    use ostd::kabi::Rights;
    use ostd::kabi::fault::{PAGE_FAULT, WORD_ADDR};
    use ostd::thread::Builder;
    #[inline(never)]
    fn deep(n: u64) -> u64 {
        let pad = [n.to_le_bytes()[0]; 512];
        let r = u64::from(core::hint::black_box(&pad)[3]);
        // `black_box` impede o compilador de ver que a recursão não para.
        if core::hint::black_box(n) == u64::MAX {
            return r;
        }
        core::hint::black_box(r + deep(n + 1))
    }
    let q = child_quota(ctx, 1 << 20)?;
    let ep = create(ctx.quota, ObjectType::Endpoint, 0).map_err(|_| "create(ep)")?;
    let reply = create(ctx.quota, ObjectType::Reply, 0).map_err(|_| "create(reply)")?;
    let exc = ostd::cap::mint(ep, Rights::SEND, 7, None).map_err(|_| "mint")?;
    let h = Builder::new()
        .quota(q)
        .stack_size(16 * 1024)
        .exception_endpoint(exc)
        .spawn(|| deep(0))
        .map_err(|_| "spawn")?;
    let guard = h.guard_page();
    let got = ipc::recv(ep, reply, ostd::time::now_ns() + 5_000_000_000);
    let verdict = match got {
        Ok(m) if m.badge == 7 && m.msg.label == PAGE_FAULT => {
            let addr = m.msg.words[WORD_ADDR];
            if (guard..guard + 4096).contains(&addr) {
                Ok(())
            } else {
                Err("a falta não caiu na página de guarda")
            }
        }
        Ok(_) => Err("mensagem de exceção inesperada"),
        Err(_) => Err("nenhuma exceção chegou"),
    };
    // Qualquer rótulo diferente de RESUME encerra a thread, como `Faulted`.
    let _ = ipc::send(reply, &Message::new(1, &[]), 0);
    // `join` volta pelo evento de morte (T-348) e devolve a região.
    let joined = match h.join_status() {
        Err(d) if d.cause == ostd::kabi::exit::CAUSE_FAULTED && d.code == PAGE_FAULT_VECTOR => {
            if (guard..guard + 4096).contains(&d.aux) {
                Ok(())
            } else {
                Err("o registro de morte devia ter o endereço da guarda")
            }
        }
        Err(_) => Err("join devia dar Faulted com a falta de página"),
        Ok(_) => Err("join de quem faltou devia dar Err"),
    };
    let _ = (delete(exc), delete(ep), delete(reply), delete(q));
    verdict.and(joined)
}

/// T-337: a entropia do kernel (`sys_info` classe 5) muda a cada pedido,
/// enche pedidos de qualquer tamanho e recusa argumento diferente de zero.
/// A amostra vai ao registro para comparar entre boots (a semente do
/// `optboot` muda a cada boot).
fn rand_entropia(_: &Ctx) -> Outcome {
    use ostd::kabi::Syscall;
    use ostd::kabi::sched::SYS_INFO_ENTROPY;
    let mut a = [0u8; 24];
    let mut b = [0u8; 24];
    ostd::rand::secure_fill(&mut a).map_err(|_| "secure_fill falhou")?;
    ostd::rand::secure_fill(&mut b).map_err(|_| "secure_fill falhou")?;
    if a == b || a == [0; 24] {
        return Err("duas leituras de entropia iguais (ou zeradas)");
    }
    let mut big = [0u8; 100];
    ostd::rand::secure_fill(&mut big).map_err(|_| "secure_fill(100) falhou")?;
    if big.chunks(8).any(|c| c.iter().all(|&x| x == 0)) {
        return Err("pedido de 100 bytes não foi preenchido");
    }
    let raw = ostd::sys::syscall(Syscall::SysInfo, [SYS_INFO_ENTROPY, 1, 0, 0, 0, 0]);
    if raw != Err(Error::InvalidArgument) {
        return Err("argumento diferente de zero devia dar InvalidArgument");
    }
    ostd::debug::print_fmt(format_args!(
        "utest: amostra de entropia {:016x}",
        u64::from_le_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]])
    ));
    Ok(())
}

/// T-337: `fast()` (xoshiro por thread) muda a cada chamada, fica dentro do
/// limite pedido, difere entre threads; a mistura de reserva (usada se o
/// kernel recusar a entropia) também muda a cada chamada; e, com o RNG do
/// QEMU, o processo não está degradado.
fn rand_fast(_: &Ctx) -> Outcome {
    use ostd::rand::{fast_below, fast_fill, fast_u64, is_degraded, mix_fill};
    if is_degraded() {
        return Err("o kernel devia ter entropia sob o QEMU (virtio-rng)");
    }
    let (a, b) = (fast_u64(), fast_u64());
    if a == b {
        return Err("duas saídas seguidas de fast() iguais");
    }
    let mut buckets = [0u32; 8];
    for _ in 0..4000 {
        let v = fast_below(8);
        *buckets
            .get_mut(usize::try_from(v).unwrap_or(usize::MAX))
            .ok_or("fast_below fora do limite")? += 1;
    }
    // Esperado 500 por balde (desvio ~21): 6 sigmas.
    if buckets.iter().any(|&c| !(370..630).contains(&c)) {
        return Err("fast_below com distribuição torta");
    }
    if fast_below(0) != 0 || fast_below(1) != 0 {
        return Err("fast_below(0|1) devia dar 0");
    }
    let mut buf = [0u8; 21];
    fast_fill(&mut buf);
    if buf.iter().all(|&x| x == 0) {
        return Err("fast_fill não preencheu");
    }
    // Outra thread semeia o próprio gerador: a primeira saída difere.
    let other = ostd::thread::spawn(fast_u64);
    let other = other.join().map_err(|_| "join")?;
    if other == a || other == b {
        return Err("a thread filha repetiu o gerador da principal");
    }
    // A mistura de reserva muda a cada chamada, mesmo no mesmo instante.
    let (mut m1, mut m2) = ([0u8; 32], [0u8; 32]);
    mix_fill(&mut m1);
    mix_fill(&mut m2);
    if m1 == m2 || m1 == [0; 32] {
        return Err("mix_fill repetiu ou zerou");
    }
    if is_degraded() {
        return Err("mix_fill não deve marcar a degradação por conta própria");
    }
    Ok(())
}

/// T-337: a semente do processo vem do kernel e o heap cai num lugar
/// sorteado da janela (ADR 0039, itens 2 e 4). Escreve a amostra no registro
/// para comparar entre boots: `cargo xtask test user` duas vezes dá valores
/// diferentes.
fn rand_semente(_: &Ctx) -> Outcome {
    use core::hash::BuildHasher;
    use ostd::alloc::heap_range;
    use ostd::collections::RandomState;
    let seed = ostd::rand::process_seed();
    if seed == [0; 4] || seed[0] == seed[1] {
        return Err("semente do processo zerada ou repetida");
    }
    // Cada mapa tem a sua chave; o mesmo dado tem hash diferente.
    let (r1, r2) = (RandomState::new(), RandomState::new());
    if r1.hash_one("amostra") == r2.hash_one("amostra") {
        return Err("dois mapas com a mesma chave");
    }
    let (base, limit) = heap_range();
    let window = 0x0000_1000_0000_0000..0x0000_2000_0000_0000;
    if base % (2 << 20) != 0
        || !window.contains(&base)
        || !window.contains(&(limit - 1))
        || limit - base != 512 << 30
    {
        return Err("faixa do heap fora da janela ou desalinhada");
    }
    let probe = Box::new(7u8);
    let at = (&raw const *probe).addr() as u64;
    if !(base..limit).contains(&at) {
        return Err("alocação fora da faixa do heap");
    }
    let block = Vec::<u8>::with_capacity(3 << 20);
    let at = block.as_ptr().addr() as u64;
    if !(base..limit).contains(&at) {
        return Err("bloco enorme fora da faixa do heap");
    }
    // Uma linha curta por valor (o registro corta linhas longas).
    ostd::debug::print_fmt(format_args!("utest: amostra de semente {:016x}", seed[0]));
    ostd::debug::print_fmt(format_args!("utest: base do heap {base:012x}"));
    ostd::debug::print_fmt(format_args!(
        "utest: hash do mapa {:016x}",
        r1.hash_one("amostra")
    ));
    Ok(())
}

/// T-337: `HashMap` contra um `BTreeMap` de modelo, com operações sorteadas
/// (chaves em faixa pequena para forçar remoções e reinserções), mais
/// `HashSet`.
fn colecoes_hashmap(_: &Ctx) -> Outcome {
    use ostd::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
    use ostd::rand::fast_below;
    let mut map: HashMap<u64, String> = HashMap::new();
    let mut model: BTreeMap<u64, String> = BTreeMap::new();
    for step in 0..3000u64 {
        let key = fast_below(400);
        match fast_below(5) {
            0..=1 => {
                let value = format!("v{step}");
                if map.insert(key, value.clone()) != model.insert(key, value) {
                    return Err("insert divergiu do modelo");
                }
            }
            2 => {
                if map.remove(&key) != model.remove(&key) {
                    return Err("remove divergiu do modelo");
                }
            }
            3 => {
                if map.get(&key) != model.get(&key) {
                    return Err("get divergiu do modelo");
                }
            }
            _ => {
                if map.contains_key(&key) != model.contains_key(&key) {
                    return Err("contains_key divergiu do modelo");
                }
            }
        }
        if map.len() != model.len() {
            return Err("len divergiu do modelo");
        }
    }
    let seen: BTreeMap<u64, String> = map.iter().map(|(k, v)| (*k, v.clone())).collect();
    if seen != model {
        return Err("o conteúdo final divergiu do modelo");
    }
    // Crescimento grande e esvaziamento.
    let mut big: HashMap<u32, u32> = HashMap::new();
    for i in 0..5000 {
        big.insert(i, i * 2);
    }
    if (0..5000).any(|i| big.get(&i) != Some(&(i * 2))) {
        return Err("perdeu entradas ao crescer");
    }
    for i in 0..5000 {
        if big.remove(&i) != Some(i * 2) {
            return Err("remove de entrada presente falhou");
        }
    }
    if !big.is_empty() {
        return Err("devia esvaziar");
    }
    let mut set: HashSet<u16> = HashSet::new();
    let mut set_model = BTreeSet::new();
    for _ in 0..1500 {
        let v = u16::try_from(fast_below(200)).unwrap_or(0);
        if set.insert(v) != set_model.insert(v) {
            return Err("HashSet::insert divergiu do modelo");
        }
    }
    if set.len() != set_model.len() || !set_model.iter().all(|v| set.contains(v)) {
        return Err("HashSet divergiu do modelo");
    }
    Ok(())
}

/// T-337: anel de capacidade fixa e fila contra modelos simples.
fn colecoes_ring(_: &Ctx) -> Outcome {
    use ostd::collections::{Queue, Ring, VecDeque};
    use ostd::rand::fast_below;
    let mut ring: Ring<u32> = Ring::new(5);
    let mut model: VecDeque<u32> = VecDeque::new();
    let mut queue: Queue<u32> = Queue::new();
    let mut plain: Vec<u32> = Vec::new();
    for i in 0..2000u32 {
        match fast_below(4) {
            0 => {
                let ok = ring.push(i).is_ok();
                if ok != (model.len() < 5) {
                    return Err("push no anel divergiu");
                }
                if ok {
                    model.push_back(i);
                }
            }
            1 => {
                if ring.pop() != model.pop_front() {
                    return Err("pop do anel divergiu");
                }
            }
            2 => {
                let dropped = ring.push_overwrite(i);
                let old = if model.len() == 5 {
                    model.pop_front()
                } else {
                    None
                };
                model.push_back(i);
                if dropped != old {
                    return Err("push_overwrite descartou o errado");
                }
            }
            _ => {
                queue.push_back(i);
                plain.push(i);
                if fast_below(2) == 0 {
                    let first = if plain.is_empty() {
                        None
                    } else {
                        Some(plain.remove(0))
                    };
                    if queue.pop_front() != first {
                        return Err("fila divergiu do modelo");
                    }
                }
            }
        }
        if ring.len() != model.len() || !ring.iter().eq(model.iter()) {
            return Err("anel divergiu do modelo");
        }
        if queue.len() != plain.len() {
            return Err("tamanho da fila divergiu");
        }
    }
    Ok(())
}

/// T-337: UTF-8 nas bordas: formas longas demais, substitutos, acima de
/// `U+10FFFF`, sequência cortada, decodificador com caractere partido.
fn utf8_bordas(_: &Ctx) -> Outcome {
    use ostd::utf8::{self, Decoder};
    for ok in ["", "a", "é", "€", "𝄞", "a€𝄞é"] {
        if utf8::validate(ok.as_bytes()) != Ok(ok) {
            return Err("texto válido recusado");
        }
    }
    let bad: [&[u8]; 8] = [
        &[0xC0, 0x80],
        &[0xE0, 0x80, 0x80],
        &[0xED, 0xA0, 0x80],
        &[0xF4, 0x90, 0x80, 0x80],
        &[0xF5, 0x80, 0x80, 0x80],
        &[0x80],
        &[0xE2, 0x82],
        &[0xF0, 0x9F, 0x98],
    ];
    for b in bad {
        if utf8::validate(b).is_ok() {
            return Err("UTF-8 inválido aceito");
        }
    }
    if utf8::validate(&[b'a', 0xE2, 0x82])
        .err()
        .map(|e| (e.valid_up_to, e.error_len))
        != Some((1, None))
    {
        return Err("erro de sequência cortada mal descrito");
    }
    let s = "aé€𝄞z";
    if utf8::truncate(s, 2) != "a" || utf8::truncate(s, 3) != "aé" || utf8::truncate(s, 99) != s {
        return Err("corte fora da fronteira");
    }
    let mut dec = Decoder::new();
    let mut out = String::new();
    for b in "€𝄞".as_bytes() {
        dec.push(&[*b], &mut out);
    }
    dec.push(&[0xE2, 0x82], &mut out);
    dec.finish(&mut out);
    if out != "€𝄞\u{FFFD}" {
        return Err("decodificador incremental errou");
    }
    Ok(())
}

/// Falha de propósito (só com `UTEST_FALHA=1`): prova que o `xtask`
/// derruba o comando quando um teste falha.
#[cfg(utest_falha)]
fn proposital(_: &Ctx) -> Outcome {
    Err("falha proposital (UTEST_FALHA=1)")
}

fn main(start: Start) -> ! {
    let handle = |raw: u64| Handle::from_raw(u32::try_from(raw).unwrap_or(0));
    if start.args[2] & anel::CHILD_FLAG != 0 {
        anel::child(&start);
    }
    let ctx = Ctx {
        quota: handle(start.args[0]),
        bootfs: ostd::kabi::split_handle_pair(start.args[2]).1,
    };
    ostd::rt::init(Env { quota: ctx.quota });
    ostd::debug::print_fmt(format_args!("utest: início, {} testes", TESTS.len()));
    let mut passed = 0usize;
    for test in TESTS {
        match (test.run)(&ctx) {
            Ok(()) => {
                passed += 1;
                ostd::debug::print_fmt(format_args!("utest: ok {}", test.name));
            }
            Err(why) => {
                ostd::debug::print_fmt(format_args!("utest: FALHOU {}: {why}", test.name));
            }
        }
    }
    ostd::debug::print_fmt(format_args!(
        "utest: fim: {passed} ok, {} falharam",
        TESTS.len() - passed
    ));
    ostd::thread::exit()
}
