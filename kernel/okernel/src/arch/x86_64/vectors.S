/* Portas de entrada das exceções 0 a 31 (T-105).
 *
 * Cada porta empilha um código de erro falso (0) quando a CPU não empilha
 * um, e depois o número do vetor, para que `isr_common` sempre veja o mesmo
 * quadro. `isr_common` salva os 15 registradores gerais e chama
 * `exception_handler(&mut TrapFrame)`. O tratador despeja o estado e
 * congela a CPU, ou, se a falta veio de uma sonda (`probe.S`), ajusta o
 * quadro e volta; aí `isr_common` restaura os registradores e faz `iretq`.
 *
 * Pilha ao chamar o tratador (do topo para baixo): SS, RSP, RFLAGS, CS, RIP
 * (da CPU), erro, vetor, r15 ... rax. São 22 palavras = 176 bytes; como a CPU
 * alinha RSP a 16 antes de empilhar, o `call` sai alinhado como pede o
 * System V.
 */

.macro ISR_NOERR n
isr_\n:
    push 0
    push \n
    jmp isr_common
.endm

.macro ISR_ERR n
isr_\n:
    push \n
    jmp isr_common
.endm

.section .text.isr, "ax"
ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERR   8
ISR_NOERR 9
ISR_ERR   10
ISR_ERR   11
ISR_ERR   12
ISR_ERR   13
ISR_ERR   14
ISR_NOERR 15
ISR_NOERR 16
ISR_ERR   17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_ERR   21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_ERR   29
ISR_ERR   30
ISR_NOERR 31

isr_common:
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
    cld
    mov rdi, rsp
    call exception_handler
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
    /* Vetor e código de erro. */
    add rsp, 16
    iretq

/* Endereços das 32 portas, na ordem dos vetores. Cada `.quad` vira uma
   relocação R_X86_64_RELATIVE, ajustada pelo optboot ao KASLR. */
.section .data.rel.ro.isr_table, "a"
.balign 8
.global isr_table
isr_table:
.irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    .quad isr_\n
.endr
