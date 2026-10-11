/* Entrada de syscall, troca de contexto e primeira entrada de uma thread
 * (T-206).
 *
 * Convenção: no kernel, GS_BASE aponta a área por CPU (`PerCpu` em
 * syscall.rs) e KERNEL_GS_BASE guarda o GS do usuário; no usuário, o
 * contrário. Toda entrada vinda do anel 3 faz SWAPGS antes de tocar em gs:
 * e toda saída para o anel 3 o desfaz por último. As interrupções ficam
 * desligadas no kernel (FMASK limpa IF na SYSCALL; as portas da IDT também),
 * então nada interrompe a janela entre SWAPGS e a troca de pilha, exceto
 * NMI e #MC, que usam IST e não usam gs.
 *
 * Campos da `PerCpu`: gs:[8] = topo da pilha de kernel da thread atual,
 * gs:[16] = rsp do usuário durante a entrada.
 *
 * O quadro montado na pilha de kernel tem o mesmo formato do `TrapFrame`
 * das interrupções (vectors.S), com vetor 0x100 para dizer "syscall". A
 * volta usa SYSRET quando `syscall_handler` devolve 1 (RIP canônico de
 * usuário, seletores de usuário: a SYSRET com RIP não canônico daria #GP
 * no anel 0 com a pilha do usuário nas CPUs Intel); senão volta por
 * `isr_exit`, com IRETQ.
 */

.section .text.syscall, "ax"
.global syscall_entry
syscall_entry:
    swapgs
    mov gs:[16], rsp
    mov rsp, gs:[8]
    push 0x23                 /* SS de usuário */
    push qword ptr gs:[16]    /* RSP de usuário */
    push r11                  /* RFLAGS */
    push 0x2b                 /* CS de usuário */
    push rcx                  /* RIP */
    push 0                    /* código de erro */
    push 0x100                /* vetor: syscall */
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rbp
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rax
    mov rdi, rsp
    call syscall_handler
    test eax, eax
    jz isr_exit
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rbp
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    add rsp, 16               /* vetor e erro */
    mov rcx, [rsp]            /* RIP, já conferido */
    mov r11, [rsp + 16]       /* RFLAGS, já saneado */
    mov rsp, [rsp + 24]       /* RSP de usuário */
    swapgs
    sysretq

/* void switch_context(u64 *save_rsp, u64 next_rsp)
 *
 * Salva os registradores preservados pelo System V na pilha atual, guarda o
 * rsp em *save_rsp, troca para next_rsp e retoma de onde aquela pilha
 * parou (ou em `thread_trampoline`, numa thread nova). */
.global switch_context
switch_context:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    mov rsp, rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* Primeira execução de uma thread: a pilha tem o quadro de usuário montado
 * por `kthread::start`. Termina a troca em Rust e entra no anel 3. */
.global thread_trampoline
thread_trampoline:
    call thread_first_run
    jmp isr_exit
