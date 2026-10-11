/* Entrada do okernel (T-104), em sintaxe Intel como o resto do asm em Rust.
 *
 * O optboot salta para cá com interrupções desligadas, paginação de 4 níveis
 * ativa, EFER.NXE e CR0.WP ligados, rdi = &BootInfo (no mapa direto) e uma
 * pilha provisória. Aqui o kernel troca para a própria pilha, no BSS, e chama
 * `kernel_main(&BootInfo)`, que nunca volta.
 *
 * O BSS não é zerado aqui: o optboot aloca a imagem em páginas zeradas e só
 * copia `p_filesz` bytes de cada segmento, então o BSS (e esta pilha) já
 * chegam com zero. Zerar de novo apagaria nada e custaria tempo de boot.
 */

.section .text.entry, "ax"
.global kernel_entry
kernel_entry:
    cld
    lea rsp, [rip + boot_stack_top]
    xor ebp, ebp
    /* rdi segue com &BootInfo; rsp alinhado a 16 antes do call, como pede
       o System V. */
    call kernel_main
2:
    cli
    hlt
    jmp 2b

.section .bss.boot_stack, "aw", @nobits
.balign 16
boot_stack_bottom:
    .skip 64 * 1024
boot_stack_top:
