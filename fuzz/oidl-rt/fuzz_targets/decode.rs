#![no_main]

use libfuzzer_sys::fuzz_target;
use oidl_rt::Reader;

// Layout da entrada: byte 0 é o tamanho da cabeça; os bytes 1 a 16 são as
// operações (cada um escolhe uma leitura); o resto é o corpo. O alvo só
// confere que nenhuma leitura entra em pânico: erros são resultados válidos.
fuzz_target!(|data: &[u8]| {
    if data.len() < 17 {
        return;
    }
    let head_len = usize::from(data[0]);
    let (ops, body) = data[1..17].split_at(16);

    let Ok(mut r) = Reader::new(body, head_len) else {
        return;
    };
    for &op in ops {
        let max = usize::from(op);
        let _ = match op % 9 {
            0 => r.u8().map(drop),
            1 => r.u16().map(drop),
            2 => r.u32().map(drop),
            3 => r.u64().map(drop),
            4 => r.i64().map(drop),
            5 => r.bool().map(drop),
            6 => r.string(max).map(drop),
            7 => r.vec(max, usize::from(op / 9) + 1).map(|e| {
                // Lê os elementos como `u64`, para cobrir a região inteira.
                r.seek(e.off());
                for _ in 0..e.count() {
                    let _ = r.u64();
                }
            }),
            _ => {
                r.seek(max);
                Ok(())
            }
        };
    }
    let _ = r.finish();
});
