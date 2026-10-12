/* Programa de usuário mínimo dos testes de kernel (T-206, T-207).
 *
 * Não roda no kernel: fica entre os dados só de leitura, e o teste copia os
 * bytes de `user_test_start` a `user_test_end` para um MemoryObject mapeado
 * RX no anel 3. Todo salto é relativo, então o código roda em qualquer
 * endereço. Usa só registradores e a página RW cujo endereço recebe.
 *
 * Syscalls: 6 = vm_map, 0x80000000 = depuração dos testes (kabi::DEBUG_PRINT),
 * 18 = ipc_send, 19 = ipc_recv, 20 = ipc_call, 21 = ipc_reply_recv,
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

/* user_ipc_server(rdi = endpoint | reply << 32, rsi = voltas, rdx = página)
 *
 * Servidor de ping-pong (T-208): recebe, confere badge ([página + 16]) e
 * palavras (rótulo + 1 a rótulo + 6) e responde com tudo somado de 1, por
 * ipc_reply_recv; a última resposta vai por ipc_send no Reply. Grava em
 * [página] o último status (-100 se a conferência falhar) e conta as voltas
 * em [página + 8]. Registradores de mensagem: rsi, rdx, r8, r9, r12-r15;
 * os do laço ficam em rbx, rbp e na pilha. */
.global user_ipc_server
user_ipc_server:
    mov rbx, rdi
    mov rbp, rsi
    push rdx
    xor edx, edx
    xor r10d, r10d
    mov eax, 19
    syscall
1:
    test rax, rax
    jnz 9f
    mov rcx, [rsp]
    cmp rdi, [rcx + 16]
    jne 8f
    lea rcx, [rsi + 1]
    cmp r8, rcx
    jne 8f
    inc rcx
    cmp r9, rcx
    jne 8f
    inc rcx
    cmp r12, rcx
    jne 8f
    inc rcx
    cmp r13, rcx
    jne 8f
    inc rcx
    cmp r14, rcx
    jne 8f
    inc rcx
    cmp r15, rcx
    jne 8f
    mov rcx, [rsp]
    inc qword ptr [rcx + 8]
    inc rsi
    inc r8
    inc r9
    inc r12
    inc r13
    inc r14
    inc r15
    mov edx, 6
    xor r10d, r10d
    mov rdi, rbx
    dec rbp
    jz 2f
    mov eax, 21
    syscall
    jmp 1b
2:
    shr rdi, 32
    mov eax, 18
    syscall
    jmp 9f
8:
    mov rax, -100
9:
    mov rcx, [rsp]
    mov [rcx], rax
    mov eax, 33
    syscall
    ud2

/* user_ipc_client(rdi = endpoint, rsi = voltas, rdx = página)
 *
 * Cliente de ping-pong: na volta i chama com rótulo 8i e palavras 8i + 1
 * a 8i + 6 e confere a resposta (badge 0, info de 6 palavras, tudo + 1).
 * Grava em [página] o status (0, o erro da syscall ou -100) e conta as
 * voltas em [página + 8]. */
.global user_ipc_client
user_ipc_client:
    mov rbx, rdi
    mov rbp, rsi
    push rdx
    push 0
1:
    mov rsi, [rsp]
    shl rsi, 3
    lea r8, [rsi + 1]
    lea r9, [rsi + 2]
    lea r12, [rsi + 3]
    lea r13, [rsi + 4]
    lea r14, [rsi + 5]
    lea r15, [rsi + 6]
    mov rdi, rbx
    mov edx, 6
    xor r10d, r10d
    mov eax, 20
    syscall
    test rax, rax
    jnz 9f
    test rdi, rdi
    jnz 8f
    cmp rdx, 6
    jne 8f
    mov rcx, [rsp]
    shl rcx, 3
    inc rcx
    cmp rsi, rcx
    jne 8f
    inc rcx
    cmp r8, rcx
    jne 8f
    inc rcx
    cmp r9, rcx
    jne 8f
    inc rcx
    cmp r12, rcx
    jne 8f
    inc rcx
    cmp r13, rcx
    jne 8f
    inc rcx
    cmp r14, rcx
    jne 8f
    inc rcx
    cmp r15, rcx
    jne 8f
    mov rcx, [rsp + 8]
    inc qword ptr [rcx + 8]
    inc qword ptr [rsp]
    cmp qword ptr [rsp], rbp
    jb 1b
    xor eax, eax
    jmp 9f
8:
    mov rax, -100
9:
    mov rcx, [rsp + 8]
    mov [rcx], rax
    mov eax, 33
    syscall
    ud2

/* user_ipc_send_cap(rdi = endpoint, rsi = handle, rdx = buffer de IPC)
 *
 * Põe o handle no cabeçalho do buffer e envia rótulo 0x11 com uma
 * capability; status em [buffer + 16]. Se o envio for recusado, envia
 * rótulo 0x12 sem capability e grava o status em [buffer + 24]. */
.global user_ipc_send_cap
user_ipc_send_cap:
    mov rbx, rdi
    mov rbp, rdx
    mov dword ptr [rbp], esi
    mov rdi, rbx
    mov esi, 0x11
    mov edx, 8
    xor r10d, r10d
    mov eax, 18
    syscall
    mov [rbp + 16], rax
    test rax, rax
    jz 1f
    mov rdi, rbx
    mov esi, 0x12
    xor edx, edx
    xor r10d, r10d
    mov eax, 18
    syscall
    mov [rbp + 24], rax
1:
    mov eax, 33
    syscall
    ud2

/* user_ipc_recv(rdi = endpoint | reply << 32, rsi = prazo relativo em ns
 * ou 0, rdx = buffer de IPC)
 *
 * Recebe uma mensagem (com prazo, se pedido) e grava no buffer: [16]
 * status, [24] badge, [32] rótulo, [40] info e [48] o primeiro handle
 * recebido. */
.global user_ipc_recv
user_ipc_recv:
    mov rbx, rdi
    mov rbp, rdx
    mov r12, rsi
    xor r10d, r10d
    test r12, r12
    jz 1f
    mov eax, 27
    syscall
    lea r10, [rdx + r12]
1:
    mov rdi, rbx
    xor edx, edx
    mov eax, 19
    syscall
    mov [rbp + 16], rax
    mov [rbp + 24], rdi
    mov [rbp + 32], rsi
    mov [rbp + 40], rdx
    mov eax, dword ptr [rbp]
    mov [rbp + 48], rax
    mov eax, 33
    syscall
    ud2

/* user_fault(rdi = vetor, rsi = página RW)
 *
 * Faltas de usuário (T-210): grava 1 em [página] e causa a exceção
 * `vetor` (0 = divisão por zero, 6 = ud2, 13 = hlt no anel 3, 14 = leitura
 * do endereço 0). Se for retomada, grava 2 em [página] e termina. */
.global user_fault
user_fault:
    mov qword ptr [rsi], 1
    cmp rdi, 14
    je 14f
    cmp rdi, 13
    je 13f
    cmp rdi, 6
    je 6f
    xor edx, edx
    xor eax, eax
    xor ecx, ecx
    div rcx
    jmp 1f
6:
    ud2
13:
    hlt
    jmp 1f
14:
    mov rax, qword ptr [0]
1:
    mov qword ptr [rsi], 2
    mov eax, 33
    syscall
    ud2

/* user_fault_read(rdi = endereço, rsi = página RW)
 *
 * Grava 1 em [página], lê a palavra em `endereço` (que falta até o
 * tratador mapeá-la), grava-a em [página + 8], grava 2 em [página] e
 * termina. */
.global user_fault_read
user_fault_read:
    mov qword ptr [rsi], 1
    mov rax, qword ptr [rdi]
    mov qword ptr [rsi + 8], rax
    mov qword ptr [rsi], 2
    mov eax, 33
    syscall
    ud2

/* user_fault_handler(rdi = endpoint | reply << 32, rsi = página RW,
 * rdx = AddressSpace | MemoryObject << 32)
 *
 * Tratador de faltas: recebe uma falta e grava em [página + 16] o status,
 * [+ 24] o badge, [+ 32] o rótulo, [+ 40] o código de erro, [+ 48] o
 * endereço e [+ 56] o rip. Mapeia o MemoryObject (gravável) na página do
 * endereço (vm_map, status em [+ 64]) e responde com rótulo 0 pelo Reply
 * (ipc_send, status em [+ 72]), o que retoma a thread. */
.global user_fault_handler
user_fault_handler:
    mov rbx, rdi
    mov rbp, rsi
    push rdx
    xor edx, edx
    xor r10d, r10d
    mov eax, 19
    syscall
    mov [rbp + 16], rax
    mov [rbp + 24], rdi
    mov [rbp + 32], rsi
    mov [rbp + 40], r8
    mov [rbp + 48], r9
    mov [rbp + 56], r12
    test rax, rax
    jnz 1f
    pop rcx
    mov edi, ecx
    mov rsi, rcx
    shr rsi, 32
    mov rdx, r9
    and rdx, -4096
    xor r10d, r10d
    mov r8d, 4096
    mov r9d, 1
    mov eax, 6
    syscall
    mov [rbp + 64], rax
    mov rdi, rbx
    shr rdi, 32
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    mov eax, 18
    syscall
    mov [rbp + 72], rax
1:
    mov eax, 33
    syscall
    ud2

/* Benchmarks (T-213, `test=bench`). Cada amostra é a diferença do TSC
 * (LFENCE; RDTSC) em volta de uma syscall, gravada em 8 bytes a partir de
 * rdx/rsi; uma falha grava u64::MAX e termina. */

/* user_bench_ipc_client(rdi = endpoint, rsi = voltas, rdx = amostras)
 *
 * ipc_call só com o rótulo (0 palavras), o caminho rápido. */
.global user_bench_ipc_client
user_bench_ipc_client:
    mov rbx, rdi
    mov rbp, rsi
    sub rsp, 16
    mov [rsp], rdx
1:
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rsp + 8], rax
    mov rdi, rbx
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    mov eax, 20
    syscall
    test rax, rax
    jnz 8f
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, [rsp + 8]
    mov rcx, [rsp]
    mov [rcx], rax
    add qword ptr [rsp], 8
    dec rbp
    jnz 1b
    jmp 9f
8:
    mov rcx, [rsp]
    mov qword ptr [rcx], -1
9:
    mov eax, 33
    syscall
    ud2

/* user_bench_ipc_server(rdi = endpoint | reply << 32, rsi = voltas)
 *
 * Recebe, responde as voltas - 1 primeiras com ipc_reply_recv (0
 * palavras) e a última com ipc_send no Reply. */
.global user_bench_ipc_server
user_bench_ipc_server:
    mov rbx, rdi
    mov rbp, rsi
    xor edx, edx
    xor r10d, r10d
    mov eax, 19
    syscall
1:
    test rax, rax
    jnz 9f
    dec rbp
    jz 2f
    mov rdi, rbx
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    mov eax, 21
    syscall
    jmp 1b
2:
    mov rdi, rbx
    shr rdi, 32
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    mov eax, 18
    syscall
9:
    mov eax, 33
    syscall
    ud2

/* user_bench_yield(rdi = voltas, rsi = amostras ou 0)
 *
 * Cede a CPU as voltas pedidas; com rsi, grava o tempo de cada yield (que
 * volta depois de a outra thread rodar e ceder também). */
.global user_bench_yield
user_bench_yield:
    mov rbx, rdi
    mov rbp, rsi
1:
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r12, rax
    mov eax, 28
    syscall
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r12
    test rbp, rbp
    jz 2f
    mov [rbp], rax
    add rbp, 8
2:
    dec rbx
    jnz 1b
    mov eax, 33
    syscall
    ud2

/* user_pingpong(rdi = id | cpu << 8, rsi = voltas, rdx = página compartilhada)
 *
 * Duas threads de processos diferentes, com a mesma página mapeada,
 * alternam a vez pela palavra em [0] (u32, o id de quem joga): esperam a
 * vez em futex_wait, contam a jogada, passam a vez e acordam a outra com
 * futex_wake. Cada jogada lê a CPU por RDTSCP (TSC_AUX = id lógico).
 * Grava em [8 + 8 * id] as jogadas e em [24 + 8 * id] as feitas fora da
 * CPU `cpu`. */
.global user_pingpong
user_pingpong:
    movzx r12d, dil
    mov r13, rdi
    shr r13, 8
    mov r14, rsi
    mov r15, rdx
    mov ebx, r12d
    xor ebx, 1
1:  /* espera a vez */
    mov eax, dword ptr [r15]
    cmp eax, r12d
    je 2f
    mov rdi, r15
    mov esi, ebx
    mov eax, 29
    syscall
    jmp 1b
2:  /* jogada */
    rdtscp
    cmp ecx, r13d
    je 3f
    inc qword ptr [r15 + r12 * 8 + 24]
3:
    inc qword ptr [r15 + r12 * 8 + 8]
    mov dword ptr [r15], ebx
    mov rdi, r15
    mov esi, 1
    mov eax, 30
    syscall
    dec r14
    jnz 1b
    mov eax, 33
    syscall
    ud2

/* user_wait_cpu(rdi = Notification, rsi = página RW)
 *
 * Espera na notificação e grava: [0] status do ntfy_wait, [8] bits
 * recebidos, [16] a CPU em que acordou (RDTSCP, TSC_AUX = id lógico). */
.global user_wait_cpu
user_wait_cpu:
    mov r12, rsi
    mov eax, 23
    syscall
    mov qword ptr [r12], rax
    mov qword ptr [r12 + 8], rdx
    rdtscp
    mov qword ptr [r12 + 16], rcx
    mov eax, 33
    syscall
    ud2

.global user_test_end
user_test_end:
