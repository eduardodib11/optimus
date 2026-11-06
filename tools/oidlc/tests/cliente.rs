//! Cliente gerado (T-345): golden do `hello.oidl` e formas esperadas.

use oidlc::parser::parse;
use oidlc::servidor::{formata, gera_cliente};

const HELLO: &str = include_str!("../../../idl/optimus/hello.oidl");
const GOLDEN: &str = include_str!("golden/gen/hello_cliente.rs");

fn gerado() -> String {
    let file = parse(HELLO).expect("hello.oidl analisa");
    assert!(
        oidlc::analyze(&file).is_empty(),
        "hello.oidl passa na semântica"
    );
    formata(&gera_cliente(&file).expect("gera o cliente"))
}

#[test]
fn hello_gera_o_golden() {
    assert_eq!(gerado(), GOLDEN);
}

#[test]
fn cada_metodo_tem_um_envio_com_rotulo_do_ordinal() {
    let g = gerado();
    // Ordinal 0, 1 e 2 em rótulos de pedido: a parte baixa do rótulo é o ordinal.
    for (nome, ordinal) in [("saudacao", 0), ("ping", 1), ("bye", 2)] {
        assert!(g.contains(&format!("pub fn {nome}(")), "falta {nome}");
        assert!(
            g.contains(&format!("0x0C5F05E3{ordinal:08X}")),
            "rótulo do ordinal {ordinal}"
        );
    }
}

#[test]
fn resposta_separa_ok_de_erro_pelo_tipo_do_rotulo() {
    let g = gerado();
    assert!(g.contains("if rotulo >> 62 == 0"));
    // `ping` cabe em registradores: o erro é a palavra 0 (u8).
    assert!(g.contains("Ok(Err(u8::try_from(w[0]).unwrap_or(u8::MAX)))"));
}

#[test]
fn metodo_que_cabe_em_registradores_nao_passa_por_bytes() {
    let g = gerado();
    // `ping` (seis u64 e resposta Seis) vai por `call_palavras`.
    let ping = g.split("pub fn ping(").nth(1).expect("ping existe");
    let ping = &ping[..ping.find("pub fn bye(").unwrap_or(ping.len())];
    assert!(ping.contains("ostd::ipc::call_palavras("), "{ping}");
    assert!(!ping.contains("codifica_hello_1"), "{ping}");
    // `saudacao` tem string: continua pelo caminho de bytes.
    let saud = g.split("pub fn saudacao(").nth(1).expect("saudacao existe");
    assert!(saud.contains("ostd::ipc::call_corpo("), "{saud}");
}

#[test]
fn handle_na_resposta_e_recusado_com_erro() {
    let src = "package optimus.t @1.0;\ninterface I {\n    m() -> result<handle<I>, u8>;\n}\n";
    let file = parse(src).expect("analisa");
    let erros = gera_cliente(&file).expect_err("handle não tem cliente");
    assert!(erros.iter().any(|e| e.msg.contains("handle")), "{erros:?}");
}
