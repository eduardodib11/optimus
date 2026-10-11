//! `root`: o primeiro processo de usuário (SDD v1.0, seção 7.2).
//!
//! O kernel o carrega do bootfs (T-211) e lhe entrega as capabilities
//! iniciais (por ora, só a cota raiz, cujo handle chega no primeiro valor
//! de [`Start`]). Nesta versão ele só se anuncia e termina; dividir a
//! memória em cotas e iniciar o `svcmgr` vêm nas próximas tarefas.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::rt::Start;

ostd::entry!(main);

fn main(_start: Start) -> ! {
    ostd::debug::print("root: iniciado");
    ostd::thread::exit()
}
