/* Programa de usuário mínimo dos testes de kernel (T-206, T-207).
 *
 * Não roda no kernel: fica entre os dados só de leitura, e o teste copia os
 * bytes de `user_test_start` a `user_test_end` para um MemoryObject mapeado
 * RX no anel 3. Todo salto é relativo, então o código roda em qualquer
 * endereço. Usa só registradores e a página RW cujo endereço recebe.
 *
 * Syscalls: 0x80000000 = depuração dos testes (kabi::DEBUG_PRINT),
 * 23 = ntfy_wait, 25 = obj_bind_notify, 26 = irq_ack, 27 = clock_get,
 * 28 = yield, 29 = futex_wait, 30 = futex_wake, 33 = thread_exit.
 */

.section .rodata.user_test, "a"
.global user_test_start
user_test_start:

/* user_alternate(rdi = letra, rsi = voltas, rdx = página RW)
 *
 * Em cada volta escreve a letra na página, imprime-a pela syscall de
 * depuração e cede a CPU. A letra também fica em xmm0: se a troca de
 * contexto não preservasse o estado SIMD, a outra thread a sobrescreveria,
 * e a volta seguinte imprimiria '!'. */
.global user_alternate
user_alternate:
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    movq xmm0, r12
1:
    mov byte ptr [r14], r12b
    movq rax, xmm0
    cmp rax, r12
    je 2f
    mov byte ptr [r14], 0x21        /* '!' */
2:
    mov rdi, r14
    mov esi, 1
    mov eax, 0x80000000
    syscall
    mov eax, 28
    syscall
    dec r13
    jnz 1b
    mov eax, 33
    syscall
    ud2

/* user_spin(rdi = prazo em ns do relógio)
 *
 * Gira lendo o relógio (clock_get, que não cede a CPU) até o prazo e
 * termina: só a preempção pelo timer tira a thread da CPU. */
.global user_spin
user_spin:
    mov r12, rdi
1:
    mov eax, 27
    syscall
    cmp rdx, r12
    jb 1b
    mov eax, 33
    syscall
    ud2

/* user_irq_wait(rdi = Interrupt, rsi = Notification, rdx = página RW)
 *
 * Liga a interrupção ao bit 3 da notificação, espera nela e reconhece a
 * interrupção. Grava na página: [0] status do obj_bind_notify, [8] status
 * do ntfy_wait, [16] bits recebidos, [24] status do irq_ack. */
.global user_irq_wait
user_irq_wait:
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov edx, 3
    mov eax, 25
    syscall
    mov qword ptr [r14], rax
    mov rdi, r13
    mov eax, 23
    syscall
    mov qword ptr [r14 + 8], rax
    mov qword ptr [r14 + 16], rdx
    mov rdi, r12
    mov eax, 26
    syscall
    mov qword ptr [r14 + 24], rax
    mov eax, 33
    syscall
    ud2

/* user_mutex(rdi = mutex u32, rsi = contador u64, rdx = voltas)
 *
 * Em cada volta soma 1 ao contador sob um mutex de futex ("Futexes Are
 * Tricky", Drepper, mutex 3: 0 livre, 1 travado, 2 travado com espera). A
 * soma é ler, (às vezes) ceder a CPU e gravar: sem exclusão mútua, somas
 * se perdem. Ceder com o mutex na mão a cada 8 voltas força a disputa e o
 * caminho de futex_wait/futex_wake. */
.global user_mutex
user_mutex:
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    xor r15, r15
1:  /* trava */
    xor eax, eax
    mov ecx, 1
    lock cmpxchg dword ptr [r12], ecx
    jz 4f
    cmp eax, 2
    je 3f
    mov eax, 2
    xchg dword ptr [r12], eax
    test eax, eax
    jz 4f
3:  /* futex_wait(mutex, 2); depois tenta de novo marcando espera */
    mov rdi, r12
    mov esi, 2
    mov eax, 29
    syscall
    mov eax, 2
    xchg dword ptr [r12], eax
    test eax, eax
    jnz 3b
4:  /* seção crítica */
    mov rbx, qword ptr [r13]
    test r15, 7
    jnz 5f
    mov eax, 28
    syscall
5:
    inc rbx
    mov qword ptr [r13], rbx
    /* destrava: de 1 para 0 sem syscall; de 2, zera e acorda um */
    lock dec dword ptr [r12]
    jz 6f
    mov dword ptr [r12], 0
    mov rdi, r12
    mov esi, 1
    mov eax, 30
    syscall
6:
    inc r15
    cmp r15, r14
    jb 1b
    mov eax, 33
    syscall
    ud2

.global user_test_end
user_test_end:
