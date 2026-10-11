//! Mensagem de falta de usuário no x86-64 (T-210; SDD v1.0, seção 6.4).
//!
//! O kernel não resolve faltas de usuário: quando uma thread no anel 3
//! causa uma exceção (falta de página, #GP, #UD, divisão por zero...), o
//! kernel faz, em nome dela, um `ipc_call` no endpoint de exceções da
//! thread (um handle no `CapSpace` dela, fixado por `thread_configure`) e
//! a thread fica parada até a resposta. O tratador (o `memd` ou o
//! supervisor) recebe a mensagem com o badge da capability do endpoint,
//! que identifica a thread.
//!
//! Mensagem (definida aqui; o SDD só diz que a falta vira mensagem):
//!
//! | Campo | Conteúdo |
//! |---|---|
//! | rótulo | vetor da exceção (0 a 31) |
//! | palavra 0 | código de erro empilhado pela CPU (0 se não houver) |
//! | palavra 1 | endereço que faltou (CR2 no #PF; 0 nas demais) |
//! | palavra 2 | `rip` da instrução que faltou |
//! | palavra 3 | `rsp` do usuário |
//! | palavra 4 | `rflags` do usuário |
//!
//! Resposta com rótulo [`REPLY_RESUME`] retoma a thread na mesma
//! instrução (o tratador já mapeou a página, por exemplo); qualquer outro
//! rótulo a encerra. Sem endpoint configurado, sem `SEND` nele, ou se a
//! chamada falhar (endpoint destruído, `Reply` apagado sem resposta), a
//! thread é encerrada e o kernel reporta a falta no registro.

/// Palavras da mensagem de falta.
pub const WORDS: u8 = 5;
/// Índice da palavra com o código de erro.
pub const WORD_ERROR: usize = 0;
/// Índice da palavra com o endereço que faltou.
pub const WORD_ADDR: usize = 1;
/// Índice da palavra com o `rip`.
pub const WORD_RIP: usize = 2;
/// Índice da palavra com o `rsp`.
pub const WORD_RSP: usize = 3;
/// Índice da palavra com o `rflags`.
pub const WORD_RFLAGS: usize = 4;

/// Rótulo da resposta que retoma a thread.
pub const REPLY_RESUME: u64 = 0;

/// #DE: divisão por zero.
pub const DIVIDE_ERROR: u64 = 0;
/// #UD: opcode inválido.
pub const INVALID_OPCODE: u64 = 6;
/// #GP: proteção geral.
pub const GENERAL_PROTECTION: u64 = 13;
/// #PF: falta de página.
pub const PAGE_FAULT: u64 = 14;

/// Exceções que nunca são atribuídas a uma thread de usuário: NMI (2),
/// falta dupla (8) e verificação de máquina (18) congelam o kernel.
#[must_use]
pub const fn user_vector(vector: u64) -> bool {
    vector < 32 && !matches!(vector, 2 | 8 | 18)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vetores_de_usuario() {
        for v in [DIVIDE_ERROR, INVALID_OPCODE, GENERAL_PROTECTION, PAGE_FAULT] {
            assert!(user_vector(v));
        }
        for v in [2, 8, 18, 32, 255] {
            assert!(!user_vector(v));
        }
        assert_eq!(WORD_RFLAGS + 1, usize::from(WORDS));
    }
}
