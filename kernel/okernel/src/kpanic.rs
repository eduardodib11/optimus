//! Pânico do kernel (T-110; SDD v1.0, seção 6.5): congela, registra e
//! reinicia, sem nunca continuar em estado inconsistente.
//!
//! 1. Desliga interrupções, mascara o timer e manda NMI às outras CPUs, que
//!    param ao ver o pânico (com um núcleo só, o NMI não tem destino).
//! 2. Registra mensagem e local na serial (sem a trava do logger) e desenha
//!    a tela de pânico no framebuffer do GOP. Nada aqui aloca nem espera
//!    trava: o pânico pode vir do heap ou de quem segurava uma trava.
//! 3. Fora de teste, espera [`REBOOT_DELAY_S`] s para a tela ser lida e
//!    reinicia. Em teste (`test=` na linha de comando) sai pelo
//!    `isa-debug-exit` com falha; com `test=panic` antes espera o xtask
//!    confirmar pela serial que capturou a tela.
//!
//! O registro persistente do SDD depende de armazenamento que o kernel ainda
//! não tem; por ora o registro é a serial e a tela.

use core::fmt::Write;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use kabi::boot::PixelFormat;
use okernel::console::{FixedBuf, Surface, panic_screen};
use okernel::log::option;
use okernel::time::NS_PER_SEC;

use crate::arch::x86_64::serial::Serial;
use crate::arch::x86_64::{QemuExit, apic, cpu, qemu_exit, reset};
use crate::{bootinfo, klog, ktime};

/// Segundos de tela antes de reiniciar.
pub const REBOOT_DELAY_S: u64 = 5;
/// Quanto `test=panic` espera a confirmação do xtask.
const ACK_TIMEOUT_S: u64 = 10;

static PANICKING: AtomicBool = AtomicBool::new(false);

/// Trata um pânico; nunca volta.
pub fn handle(info: &PanicInfo) -> ! {
    cpu::disable_interrupts();
    if PANICKING.swap(true, Ordering::SeqCst) {
        klog::emergency(format_args!(
            "okernel: pânico durante o pânico: {}",
            info.message()
        ));
        qemu_exit(QemuExit::Failure);
    }
    apic::freeze_others();
    let mut location = FixedBuf::<256>::new();
    let _ = match info.location() {
        Some(l) => write!(location, "em {}:{}:{}", l.file(), l.line(), l.column()),
        None => write!(location, "em local desconhecido"),
    };
    let mut message = FixedBuf::<1024>::new();
    let _ = write!(message, "{}", info.message());
    let (location, message) = (location.as_str(), message.as_str());
    klog::emergency(format_args!("okernel: PÂNICO {location}: {message}"));
    match draw(location, message) {
        Some((w, h)) => {
            klog::emergency(format_args!("okernel: tela de pânico desenhada ({w}x{h})"));
        }
        None => klog::emergency(format_args!(
            "okernel: sem framebuffer para a tela de pânico"
        )),
    }
    let test = bootinfo::get()
        .and_then(|i| i.cmdline())
        .and_then(|c| option(c, "test"));
    match test {
        Some("panic") => {
            klog::emergency(format_args!(
                "okernel: pânico registrado; aguardando confirmação na serial"
            ));
            wait_ack();
            qemu_exit(QemuExit::Failure)
        }
        Some(_) => qemu_exit(QemuExit::Failure),
        None => {
            klog::emergency(format_args!("okernel: reiniciando em {REBOOT_DELAY_S} s"));
            delay_s(REBOOT_DELAY_S);
            reset()
        }
    }
}

/// Desenha a tela de pânico; devolve as dimensões, ou `None` sem framebuffer
/// utilizável.
fn draw(location: &str, message: &str) -> Option<(u32, u32)> {
    let info = bootinfo::get()?;
    let fb = info.framebuffer()?;
    let format = match fb.format {
        0 => PixelFormat::Rgb,
        1 => PixelFormat::Bgr,
        _ => return None,
    };
    let (width, height, stride) = (
        usize::try_from(fb.width).ok()?,
        usize::try_from(fb.height).ok()?,
        usize::try_from(fb.stride).ok()?,
    );
    let pixels = stride.checked_mul(height)?;
    let bytes = u64::try_from(pixels).ok()?.checked_mul(4)?;
    let limit = bootinfo::direct_map_limit(bootinfo::memory_map(info)?);
    if bytes > fb.size || fb.base.checked_add(bytes)? > limit {
        return None;
    }
    // SAFETY: o framebuffer do GOP é memória de vídeo fora da RAM do kernel,
    // inteira no mapa direto (conferido contra o limite) e com `pixels`
    // pixels de 32 bits; só o pânico escreve nele, com tudo mais parado.
    let pixels = unsafe {
        core::slice::from_raw_parts_mut((crate::kmem::direct_base() + fb.base) as *mut u32, pixels)
    };
    let mut surface = Surface::new(pixels, width, height, stride)?;
    panic_screen(&mut surface, format, location, message);
    Some((fb.width, fb.height))
}

/// Espera `seconds` pelo relógio, ou por um laço longo se não houver relógio.
fn delay_s(seconds: u64) {
    let end = ktime::now_ns() + seconds * NS_PER_SEC;
    let mut spins: u64 = seconds * 500_000_000;
    while ktime::now_ns() < end && spins > 0 {
        spins -= 1;
        core::hint::spin_loop();
    }
}

/// Espera um byte na serial por até [`ACK_TIMEOUT_S`] s.
fn wait_ack() {
    let end = ktime::now_ns() + ACK_TIMEOUT_S * NS_PER_SEC;
    let mut serial = Serial::com1();
    while ktime::now_ns() < end {
        if serial.try_read().is_some() {
            klog::emergency(format_args!("okernel: confirmação recebida"));
            return;
        }
        core::hint::spin_loop();
    }
    klog::emergency(format_args!("okernel: sem confirmação"));
}
