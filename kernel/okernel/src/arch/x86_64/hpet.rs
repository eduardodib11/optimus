//! HPET: só o contador principal, referência para calibrar o TSC (T-109).

use core::sync::atomic::{AtomicU64, Ordering};

const REG_CAPABILITIES: u64 = 0x00;
const REG_CONFIG: u64 = 0x10;
const REG_COUNTER: u64 = 0xf0;
const CONFIG_ENABLE: u64 = 1;
/// Maior período aceito pela especificação: 100 ns.
const MAX_PERIOD_FS: u64 = 100_000_000;

static BASE: AtomicU64 = AtomicU64::new(0);
static PERIOD_FS: AtomicU64 = AtomicU64::new(0);

fn read(reg: u64) -> u64 {
    // SAFETY: `BASE` é a página de registradores do HPET no mapa direto,
    // conferida por `init`; registradores de 64 bits alinhados.
    unsafe { ((BASE.load(Ordering::Relaxed) + reg) as *const u64).read_volatile() }
}

/// Liga o contador do HPET cujos registradores estão no endereço virtual
/// `base`; devolve o período em femtossegundos, ou `None` se for inválido.
pub fn init(base: u64) -> Option<u64> {
    BASE.store(base, Ordering::Relaxed);
    let period = read(REG_CAPABILITIES) >> 32;
    if period == 0 || period > MAX_PERIOD_FS {
        BASE.store(0, Ordering::Relaxed);
        return None;
    }
    let config = read(REG_CONFIG);
    // SAFETY: ligar ENABLE_CNF só faz o contador andar; os comparadores
    // continuam desligados.
    unsafe { ((base + REG_CONFIG) as *mut u64).write_volatile(config | CONFIG_ENABLE) };
    PERIOD_FS.store(period, Ordering::Relaxed);
    Some(period)
}

/// Período do contador em femtossegundos (zero sem HPET).
pub fn period_fs() -> u64 {
    PERIOD_FS.load(Ordering::Relaxed)
}

/// Contador principal (zero sem HPET).
pub fn counter() -> u64 {
    if period_fs() == 0 {
        0
    } else {
        read(REG_COUNTER)
    }
}
