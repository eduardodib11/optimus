//! Logger do kernel na serial COM1, com níveis (T-104).
//!
//! Use as macros `error!`, `warn!`, `info!`, `debug!` e `trace!`; mensagens
//! acima do nível escolhido (`log=` na linha de comando) são descartadas. Cada
//! mensagem vira uma linha `nível mensagem`, escrita inteira sob um spinlock.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use okernel::log::Level;

use crate::arch::x86_64::serial::Serial;

static MAX_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static LOCK: AtomicBool = AtomicBool::new(false);

/// Programa a serial e define o nível máximo.
pub fn init(level: Level) {
    Serial::init();
    MAX_LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Roda `f` com a trava do `klog` (a última folha, ADR 0031).
pub fn locked<R>(f: impl FnOnce() -> R) -> R {
    while LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let r = f();
    LOCK.store(false, Ordering::Release);
    r
}

/// Mensagem formatada num buffer fixo, cortada na fronteira UTF-8.
struct Line {
    buf: [u8; crate::klogring::MAX_MSG],
    len: usize,
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut n = s.len().min(self.buf.len() - self.len);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// Escreve uma mensagem se `level` estiver habilitado: na serial e no anel
/// do kernel para o `logd` (T-357).
pub fn write(level: Level, args: fmt::Arguments<'_>) {
    if level as u8 > MAX_LEVEL.load(Ordering::Relaxed) {
        return;
    }
    let ts = crate::ktime::now_ns();
    locked(|| {
        let _ = writeln!(Serial::com1(), "{level:5} {args}");
        let mut line = Line {
            buf: [0; crate::klogring::MAX_MSG],
            len: 0,
        };
        let _ = line.write_fmt(args);
        crate::klogring::push(ts, level, &line.buf[..line.len]);
    });
}

/// Escreve ignorando nível e trava: para pânico e faltas, quando quem segurava
/// a trava pode nunca mais soltá-la.
pub fn emergency(args: fmt::Arguments<'_>) {
    let _ = writeln!(Serial::com1(), "{args}");
}

/// Registra uma mensagem no nível dado.
macro_rules! log {
    ($level:expr, $($arg:tt)*) => {
        $crate::klog::write($level, format_args!($($arg)*))
    };
}

/// Registra no nível `error`.
macro_rules! error {
    ($($arg:tt)*) => { log!(okernel::log::Level::Error, $($arg)*) };
}

/// Registra no nível `warn`.
macro_rules! warn {
    ($($arg:tt)*) => { log!(okernel::log::Level::Warn, $($arg)*) };
}

/// Registra no nível `info`.
macro_rules! info {
    ($($arg:tt)*) => { log!(okernel::log::Level::Info, $($arg)*) };
}

/// Registra no nível `debug`.
macro_rules! debug {
    ($($arg:tt)*) => { log!(okernel::log::Level::Debug, $($arg)*) };
}

/// Registra no nível `trace`.
macro_rules! trace {
    ($($arg:tt)*) => { log!(okernel::log::Level::Trace, $($arg)*) };
}
