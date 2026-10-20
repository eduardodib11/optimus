//! Instalação do trampolim de partida dos APs (`ap.S`; ADR 0030, item 3).
//!
//! O BSP grava, pelo mapa direto, seis páginas abaixo de 1 MiB: o código
//! do trampolim (P), os parâmetros (P + 1), e PML4, PDPT, PD e PT
//! temporários. O PML4 temporário copia a metade alta do PML4 do kernel e
//! tem na entrada 0 a identidade só de P (`R+X`) e de P + 1 (`R`, NX):
//! W^X vale, porque o BSP escreve pelo mapa direto (`RW`, NX) e o AP só
//! executa pela identidade.

#![allow(
    clippy::cast_possible_truncation,
    reason = "o trampolim mora abaixo de 1 MiB: endereços e deslocamentos cabem em 32 bits"
)]

use core::ptr;

use super::cpu;

unsafe extern "C" {
    static ap_trampoline_start: u8;
    static ap_trampoline_end: u8;
    static ap_pm_ptr: u8;
    static ap_lm_ptr: u8;
    static ap_pm: u8;
    static ap_lm: u8;
    fn ap_entry64();
}

const PAGE: u64 = 4096;
/// Entrada de tabela presente e gravável (intermediárias).
const TABLE: u64 = 0b11;
/// Folha presente, só leitura.
const PRESENT: u64 = 1;
/// Folha não executável.
const NX: u64 = 1 << 63;

const CR4_PAE: u64 = 1 << 5;
const CR4_PGE: u64 = 1 << 7;

/// GDT mínima do trampolim: nula, código de 32 bits, dados, código de 64.
/// Os descritores já vêm com o bit de acessado: o salto para o código de 64
/// bits carrega o CS com a paginação ligada, e a CPU gravaria esse bit na
/// página de parâmetros, que a identidade mapeia só para leitura (com
/// CR0.WP, um #PF sem IDT: falta tripla no AP, vista em KVM; o TCG não
/// grava o bit pela paginação).
const GDT: [u64; 4] = [
    0,
    0x00cf_9b00_0000_ffff,
    0x00cf_9300_0000_ffff,
    0x00af_9b00_0000_ffff,
];

// Deslocamentos na página de parâmetros (os de `ap.S`).
const P_GDTR: u64 = 0x20;
const P_CR4: u64 = 0x30;
const P_CR3_TEMP: u64 = 0x34;
const P_CR3: u64 = 0x38;
const P_STACK: u64 = 0x40;
const P_PERCPU: u64 = 0x48;
const P_ENTRY: u64 = 0x50;

/// O trampolim instalado em memória baixa.
pub struct Trampoline {
    /// Endereço físico da página de código (P).
    base: u64,
    /// Endereço virtual de P no mapa direto.
    virt: u64,
}

fn sym(s: &u8) -> u64 {
    ptr::from_ref(s).addr() as u64
}

impl Trampoline {
    /// Monta código, parâmetros fixos e tabelas temporárias nas seis páginas
    /// físicas a partir de `base` (vistas em `direct + base`); `kernel_root`
    /// é o PML4 do kernel e `kernel_pml4` o mesmo PML4 no mapa direto.
    ///
    /// # Safety
    ///
    /// As seis páginas são RAM usável abaixo de 1 MiB que ninguém mais usa,
    /// gravável no mapa direto; `kernel_pml4` aponta o PML4 do kernel.
    pub unsafe fn install(
        base: u64,
        direct: u64,
        kernel_root: u64,
        kernel_pml4: *const u64,
    ) -> Self {
        let virt = direct + base;
        // SAFETY: os símbolos de `ap.S` estão na imagem (só leitura).
        let (start, end, pm_ptr, lm_ptr, pm, lm) = unsafe {
            (
                sym(&ap_trampoline_start),
                sym(&ap_trampoline_end),
                sym(&ap_pm_ptr),
                sym(&ap_lm_ptr),
                sym(&ap_pm),
                sym(&ap_lm),
            )
        };
        let len = end - start;
        assert!(len < PAGE, "trampolim maior que uma página");
        let page = |i: u64| (virt + i * PAGE) as *mut u64;
        // SAFETY: contrato acima; o modelo tem `len` bytes na imagem, e as
        // páginas de destino não o sobrepõem.
        unsafe {
            ptr::write_bytes(page(0).cast::<u8>(), 0, 6 * PAGE as usize);
            ptr::copy_nonoverlapping(start as *const u8, page(0).cast::<u8>(), len as usize);
            {
                let code = page(0).cast::<u8>();
                code.add((pm_ptr - start) as usize)
                    .cast::<u32>()
                    .write_unaligned((base + (pm - start)) as u32);
                code.add((lm_ptr - start) as usize)
                    .cast::<u32>()
                    .write_unaligned((base + (lm - start)) as u32);
                let params = page(1).cast::<u8>();
                page(1).cast::<[u64; 4]>().write(GDT);
                let gdtr = params.add(P_GDTR as usize);
                gdtr.cast::<u16>().write_unaligned(31);
                gdtr.add(2)
                    .cast::<u32>()
                    .write_unaligned((base + PAGE) as u32);
                let cr4 = cpu::read_cr4() & (CR4_PAE | CR4_PGE) | CR4_PAE;
                params
                    .add(P_CR4 as usize)
                    .cast::<u32>()
                    .write_unaligned(cr4 as u32);
                params
                    .add(P_CR3_TEMP as usize)
                    .cast::<u32>()
                    .write_unaligned((base + 2 * PAGE) as u32);
            }
            let params = page(1).cast::<u8>();
            params
                .add(P_CR3 as usize)
                .cast::<u64>()
                .write_unaligned(kernel_root);
            params
                .add(P_ENTRY as usize)
                .cast::<u64>()
                .write_unaligned((ap_entry64 as *const ()).addr() as u64);
            // PML4: identidade em 0 e a metade alta do kernel.
            let pml4 = page(2);
            pml4.write((base + 3 * PAGE) | TABLE);
            for i in 256..512 {
                pml4.add(i).write(kernel_pml4.add(i).read());
            }
            page(3).write((base + 4 * PAGE) | TABLE);
            page(4).write((base + 5 * PAGE) | TABLE);
            let pt = page(5);
            pt.add((base / PAGE) as usize).write(base | PRESENT);
            pt.add((base / PAGE + 1) as usize)
                .write((base + PAGE) | PRESENT | NX);
        }
        Self { base, virt }
    }

    /// Vetor do SIPI: o número da página do código.
    pub fn vector(&self) -> u8 {
        u8::try_from(self.base / PAGE).unwrap_or(0)
    }

    /// Prepara a partida de um AP: topo da pilha de boot e `PerCpu`.
    pub fn set_params(&self, stack_top: u64, percpu: u64) {
        let params = (self.virt + PAGE) as *mut u8;
        // SAFETY: a página de parâmetros é nossa (instalada por `install`);
        // nenhum AP a lê agora (os APs sobem um por vez).
        unsafe {
            params
                .add(P_STACK as usize)
                .cast::<u64>()
                .write_unaligned(stack_top);
            params
                .add(P_PERCPU as usize)
                .cast::<u64>()
                .write_unaligned(percpu);
        }
    }
}
