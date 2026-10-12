/* Trampolim de partida dos APs (ADR 0030, item 3; T-318).
 *
 * O BSP copia o trecho entre `ap_trampoline_start` e `ap_trampoline_end`
 * para uma página abaixo de 1 MiB (a página P do SIPI) e preenche a página
 * seguinte (P + 0x1000) com os parâmetros:
 *
 *   0x00  GDT mínima: nula, código de 32 bits (0x08), dados (0x10),
 *         código de 64 bits (0x18)
 *   0x20  operando do lgdt (limite de 16 bits e base de 32)
 *   0x30  CR4 para ligar a paginação (PAE, e PGE como o BSP)
 *   0x34  CR3 temporário (identidade do trampolim + metade alta do kernel)
 *   0x38  CR3 do kernel
 *   0x40  topo da pilha de boot do AP
 *   0x48  endereço da PerCpu do AP
 *   0x50  `ap_entry64`, na metade alta
 *
 * Os dois saltos distantes têm o destino absoluto gravado pelo BSP na cópia
 * (`ap_pm_ptr` e `ap_lm_ptr`), porque o código não sabe onde vai morar. O
 * modelo fica em dados só de leitura: nunca executa no lugar.
 *
 * Sequência: modo real (CS = P >> 4) → lgdt e CR0.PE → 32 bits: CR4, CR3
 * temporário, EFER.LME | EFER.NXE (sem NXE os bits NX da metade alta dão
 * falta), CR0.PG | CR0.WP → 64 bits na identidade → salto para
 * `ap_entry64`, que troca para o CR3 do kernel (sem identidade) e chama
 * `ap_main(percpu)`. Interrupções desligadas o tempo todo.
 */

.section .rodata.ap_trampoline, "a"
.balign 16
.global ap_trampoline_start
.global ap_trampoline_end
.global ap_pm_ptr
.global ap_lm_ptr
.global ap_pm
.global ap_lm

.code16
ap_trampoline_start:
    cli
    cld
    mov ax, cs
    mov ds, ax
    xor ebx, ebx
    mov bx, ax
    shl ebx, 4                  /* ebx = endereço físico de P */
    lgdt [0x1020]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    /* jmp 0x08:ap_pm (ptr16:32 a partir do modo de 16 bits) */
    .byte 0x66, 0xea
ap_pm_ptr:
    .long 0
    .word 0x08

.code32
ap_pm:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov eax, [ebx + 0x1030]
    mov cr4, eax
    mov eax, [ebx + 0x1034]
    mov cr3, eax
    mov ecx, 0xc0000080         /* IA32_EFER */
    rdmsr
    or eax, 0x900               /* LME | NXE */
    wrmsr
    mov eax, cr0
    or eax, 0x80010001          /* PG | WP | PE */
    mov cr0, eax
    /* jmp 0x18:ap_lm (entra no modo de 64 bits) */
    .byte 0xea
ap_lm_ptr:
    .long 0
    .word 0x18

.code64
ap_lm:
    mov ebx, ebx                /* zera a metade alta */
    mov rsp, [rbx + 0x1040]
    mov rdi, [rbx + 0x1048]
    mov rcx, [rbx + 0x1038]
    mov rax, [rbx + 0x1050]
    jmp rax
ap_trampoline_end:

/* Já na metade alta, com a pilha de boot do AP: troca para o CR3 do
 * kernel e entra em Rust. `ap_main` nunca volta. */
.section .text.ap, "ax"
.global ap_entry64
ap_entry64:
    mov cr3, rcx
    xor ebp, ebp
    call ap_main
2:
    cli
    hlt
    jmp 2b
