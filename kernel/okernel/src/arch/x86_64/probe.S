/* Sondas de acesso à memória que sobrevivem a faltas (T-107).
 *
 * Cada sonda tenta um único acesso. Se ele faltar, o tratador de exceções
 * acha a instrução em `probe_extable`, registra a falta e retoma no
 * `probe_fault`, que devolve 1; sem falta, a sonda devolve 0. Servem aos
 * testes de kernel (escrever em código precisa dar #PF) e, depois, à cópia
 * de/para memória de usuário. Nenhuma sonda mexe na pilha antes do acesso,
 * então o retorno do `probe_fault` volta direto a quem chamou.
 *
 * probe_exec é diferente: o `call` empilha o retorno, e a falta de busca de
 * instrução acontece já no destino. O tratador reconhece a falta pelo
 * `probe_exec_armed` e desempilha esse retorno antes de ir ao `probe_fault`.
 */

.section .text.probe, "ax"

/* u64 probe_write_byte(u8 *addr, u8 value) */
.global probe_write_byte
probe_write_byte:
probe_write_insn:
    mov byte ptr [rdi], sil
    xor eax, eax
    ret

/* u64 probe_read_byte(const u8 *addr, u8 *out) */
.global probe_read_byte
probe_read_byte:
probe_read_insn:
    movzx eax, byte ptr [rdi]
    mov byte ptr [rsi], al
    xor eax, eax
    ret

/* u64 probe_exec(void (*target)(void)): o destino precisa ser um `ret`. */
.global probe_exec
probe_exec:
    call rdi
    xor eax, eax
    ret

/* u64 copy_user(u8 *dst, const u8 *src, u64 len): cópia de/para memória de
 * usuário (T-206). Com SMAP, só esta janela roda com RFLAGS.AC ligado
 * (STAC/CLAC); uma falta no meio volta por `copy_user_fault`. Quem chama
 * confere antes que a faixa de usuário está na metade baixa. */
.global copy_user
copy_user:
    mov rcx, rdx
    test byte ptr [rip + SMAP_ENABLED], 1
    jz 1f
    stac
1:
copy_user_insn:
    rep movsb
    test byte ptr [rip + SMAP_ENABLED], 1
    jz 2f
    clac
2:
    xor eax, eax
    ret

copy_user_fault:
    test byte ptr [rip + SMAP_ENABLED], 1
    jz 3f
    clac
3:
    mov eax, 1
    ret

.global probe_fault
probe_fault:
    mov eax, 1
    ret

/* Pares (instrução que pode faltar, onde retomar); relocados pelo optboot. */
.section .data.rel.ro.probe_extable, "a"
.balign 8
.global probe_extable
probe_extable:
    .quad probe_write_insn, probe_fault
    .quad probe_read_insn, probe_fault
    .quad copy_user_insn, copy_user_fault
