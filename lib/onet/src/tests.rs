use crate::eth::{self, Header, Mac};

const A: Mac = Mac([2, 0, 0, 0, 0, 1]);
const B: Mac = Mac([2, 0, 0, 0, 0, 2]);

#[test]
fn quadro_ida_e_volta() {
    let h = Header {
        dst: B,
        src: A,
        ethertype: eth::ETHERTYPE_IPV4,
    };
    let mut out = [0u8; 64];
    let n = eth::build(&h, b"abc", &mut out).unwrap();
    assert_eq!(n, 17);
    let (h2, payload) = eth::parse(&out[..n]).unwrap();
    assert_eq!(h2, h);
    assert_eq!(payload, b"abc");
}

#[test]
fn quadro_curto_ou_longo_e_recusado() {
    assert!(eth::parse(&[0u8; 13]).is_none());
    assert!(eth::parse(&[0u8; 14]).is_some());
    assert!(eth::parse(&[0u8; eth::MAX_FRAME]).is_some());
    assert!(eth::parse(&[0u8; eth::MAX_FRAME + 1]).is_none());
}

#[test]
fn montagem_respeita_limites() {
    let h = Header {
        dst: B,
        src: A,
        ethertype: eth::ETHERTYPE_ARP,
    };
    let mut pequeno = [0u8; 16];
    assert!(eth::build(&h, &[0; 3], &mut pequeno).is_none());
    let mut grande = [0u8; 2048];
    assert!(eth::build(&h, &[0; eth::MTU], &mut grande).is_some());
    assert!(eth::build(&h, &[0; eth::MTU + 1], &mut grande).is_none());
}

#[test]
fn mac_do_netinfo_e_destino() {
    let m = Mac::from_u64(0x0605_0403_0200);
    assert_eq!(m.0, [0, 2, 3, 4, 5, 6]);
    assert!(!m.is_group());
    assert!(Mac::BROADCAST.is_group());
    let h = |dst| Header {
        dst,
        src: A,
        ethertype: 0,
    };
    assert!(eth::for_us(&h(m), m));
    assert!(eth::for_us(&h(Mac::BROADCAST), m));
    assert!(!eth::for_us(&h(B), m));
}

#[test]
fn nenhum_comprimento_entra_em_panico() {
    let mut buf = [0u8; eth::MAX_FRAME + 4];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = u8::try_from(i * 7 % 256).unwrap_or(0);
    }
    for n in 0..buf.len() {
        let _ = eth::parse(&buf[..n]);
    }
}
