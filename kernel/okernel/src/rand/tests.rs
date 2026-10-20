use optcrypt::blake3::{Hasher, KEY_LEN};

use super::{Drbg, MAX_STEP, SEED_LABEL};

fn seed(byte: u8) -> [u8; 64] {
    let mut s = [0u8; 64];
    for (i, b) in (0u8..).zip(s.iter_mut()) {
        *b = byte ^ i;
    }
    s
}

fn bytes<const N: usize>(d: &mut Drbg, extra: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    d.fill(extra, &mut out);
    out
}

/// A construção da ADR 0039: chave inicial `BLAKE3(semente ‖ rótulo)` e cada
/// saída o XOF chaveado, com os 32 primeiros bytes como chave nova.
#[test]
fn segue_a_construcao_da_adr() {
    let s = seed(7);
    let key0 = Hasher::new().update(&s).update(SEED_LABEL).finalize();
    let xof = |key: &[u8; KEY_LEN], len: usize, extra: &[u8]| {
        let mut buf = [0u8; KEY_LEN + MAX_STEP];
        Hasher::new_keyed(key)
            .update(&[0])
            .update(&(len as u64).to_le_bytes())
            .update(extra)
            .finalize_xof(&mut buf[..KEY_LEN + len]);
        buf
    };
    let mut d = Drbg::from_seed(&s).unwrap();
    let first: [u8; 24] = bytes(&mut d, b"x");
    let want = xof(&key0, 24, b"x");
    assert_eq!(first, want[KEY_LEN..KEY_LEN + 24]);
    let key1: [u8; KEY_LEN] = want[..KEY_LEN].try_into().unwrap();
    let second: [u8; 24] = bytes(&mut d, b"y");
    assert_eq!(second, xof(&key1, 24, b"y")[KEY_LEN..KEY_LEN + 24]);
    // A chave andou: a antiga não aparece mais no estado.
    let key2 = d.into_key();
    assert_ne!(key2, key0);
    assert_ne!(key2, key1);
}

#[test]
fn deterministico_pela_semente() {
    let mut one = Drbg::from_seed(&seed(1)).unwrap();
    let mut same = Drbg::from_seed(&seed(1)).unwrap();
    let mut other = Drbg::from_seed(&seed(2)).unwrap();
    for _ in 0..10 {
        let out: [u8; 24] = bytes(&mut one, b"");
        assert_eq!(out, bytes::<24>(&mut same, b""));
        assert_ne!(out, bytes::<24>(&mut other, b""));
    }
}

#[test]
fn semente_zero_nao_semeia() {
    assert!(Drbg::from_seed(&[0; 64]).is_none());
    let mut one = [0u8; 64];
    one[63] = 1;
    assert!(Drbg::from_seed(&one).is_some());
}

#[test]
fn saidas_seguidas_diferem() {
    let mut d = Drbg::from_seed(&seed(3)).unwrap();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..1000 {
        let out: [u8; 24] = bytes(&mut d, b"");
        assert!(seen.insert(out));
    }
}

/// A mistura (`extra`) muda a saída e o estado seguinte.
#[test]
fn mistura_muda_a_saida() {
    let mut a = Drbg::from_seed(&seed(4)).unwrap();
    let mut b = Drbg::from_seed(&seed(4)).unwrap();
    let (x, y): ([u8; 24], [u8; 24]) = (bytes(&mut a, b"tsc=1"), bytes(&mut b, b"tsc=2"));
    assert_ne!(x, y);
    let (x, y): ([u8; 24], [u8; 24]) = (bytes(&mut a, b""), bytes(&mut b, b""));
    assert_ne!(x, y);
}

/// Um DRBG por CPU: fluxos diferentes entre si e do principal, o
/// principal troca de chave a cada filho e o mesmo id em outro instante dá
/// outro filho.
#[test]
fn filhos_por_cpu_diferem() {
    let mut main = Drbg::from_seed(&seed(5)).unwrap();
    let mut kids: Vec<Drbg> = (0..8).map(|cpu| main.fork(cpu, b"")).collect();
    let mut outs: Vec<[u8; 32]> = kids.iter_mut().map(|k| bytes(k, b"")).collect();
    outs.push(bytes(&mut main, b""));
    let mut again = main.fork(0, b"");
    outs.push(bytes(&mut again, b""));
    let n = outs.len();
    outs.sort_unstable();
    outs.dedup();
    assert_eq!(outs.len(), n);
    // Fork e saída comum são domínios separados.
    let mut p = Drbg::from_seed(&seed(6)).unwrap();
    let mut q = Drbg::from_seed(&seed(6)).unwrap();
    let kid = p.fork(0, b"").into_key();
    let out: [u8; 32] = bytes(&mut q, b"");
    assert_ne!(kid, out);
}

/// Tamanhos: vazio não muda o estado; acima de `MAX_STEP` sai em passos
/// de `MAX_STEP`, cada um com troca de chave.
#[test]
fn tamanhos() {
    let mut a = Drbg::from_seed(&seed(8)).unwrap();
    let mut b = Drbg::from_seed(&seed(8)).unwrap();
    a.fill(b"", &mut []);
    assert_eq!(bytes::<24>(&mut a, b""), bytes::<24>(&mut b, b""));
    let mut big = [0u8; 2 * MAX_STEP + 5];
    a.fill(b"m", &mut big);
    let p1: [u8; MAX_STEP] = bytes(&mut b, b"m");
    let p2: [u8; MAX_STEP] = bytes(&mut b, b"m");
    let p3: [u8; 5] = bytes(&mut b, b"m");
    assert_eq!(&big[..MAX_STEP], &p1);
    assert_eq!(&big[MAX_STEP..2 * MAX_STEP], &p2);
    assert_eq!(&big[2 * MAX_STEP..], &p3);
    // O tamanho entra no passo: um prefixo menor não é prefixo do maior.
    let mut c = Drbg::from_seed(&seed(9)).unwrap();
    let mut d = Drbg::from_seed(&seed(9)).unwrap();
    let short: [u8; 8] = bytes(&mut c, b"");
    let long: [u8; 24] = bytes(&mut d, b"");
    assert_ne!(short, long[..8]);
}

#[test]
fn chave_guardada_continua_o_fluxo() {
    let mut a = Drbg::from_seed(&seed(10)).unwrap();
    let mut b = Drbg::from_seed(&seed(10)).unwrap();
    let _: [u8; 3] = bytes(&mut a, b"");
    let _: [u8; 3] = bytes(&mut b, b"");
    let mut a = Drbg::from_key(a.into_key());
    assert_eq!(bytes::<24>(&mut a, b"z"), bytes::<24>(&mut b, b"z"));
}
