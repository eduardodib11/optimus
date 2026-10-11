/* Programa de usuário mínimo dos testes de kernel (T-206, T-207).
 *
 * Não roda no kernel: fica entre os dados só de leitura, e o teste copia os
 * bytes de `user_test_start` a `user_test_end` para um MemoryObject mapeado
 * RX no anel 3. Todo salto é relativo, então o código roda em qualquer
 * endereço. Usa só registradores e a página RW cujo endereço recebe.
 *
 * Syscalls: 0x80000000 = depuração dos testes (kthread::DEBUG_PRINT),
 * 27 = clock_get, 28 = yield, 33 = thread_exit.
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

.global user_test_end
user_test_end:
