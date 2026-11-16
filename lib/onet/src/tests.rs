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

mod arp {
    use crate::arp::{Cache, Local, MAX_TRIES, NEGATIVE_NS, Op, Packet, RETRY_NS, Resolve, TTL_NS};
    use crate::eth::Mac;

    const US: Local = Local {
        mac: Mac([2, 0, 0, 0, 0, 1]),
        ip: [10, 0, 2, 15],
    };
    const GW: [u8; 4] = [10, 0, 2, 2];
    const GW_MAC: Mac = Mac([2, 0, 0, 0, 0, 2]);

    fn reply(spa: [u8; 4], sha: Mac) -> Packet {
        Packet {
            op: Op::Reply,
            sha,
            spa,
            tha: US.mac,
            tpa: US.ip,
        }
    }

    #[test]
    fn pacote_ida_e_volta() {
        let p = US.request(GW);
        let b = p.build();
        assert_eq!(Packet::parse(&b), Some(p));
        // O preenchimento do quadro Ethernet sobra no fim.
        let mut longo = [0u8; 46];
        longo[..28].copy_from_slice(&b);
        assert_eq!(Packet::parse(&longo), Some(p));
    }

    #[test]
    fn pacote_estranho_e_recusado() {
        let b = US.request(GW).build();
        assert!(Packet::parse(&b[..27]).is_none());
        for i in 0..8 {
            let mut x = b;
            x[i] ^= 0x80;
            assert!(Packet::parse(&x).is_none(), "byte {i}");
        }
        let mut x = b;
        x[7] = 3;
        assert!(Packet::parse(&x).is_none());
    }

    #[test]
    fn responde_pedido_para_o_nosso_ip_e_aprende_o_remetente() {
        let mut c = Cache::new();
        let req = Packet {
            op: Op::Request,
            sha: GW_MAC,
            spa: GW,
            tha: Mac([0; 6]),
            tpa: US.ip,
        };
        let r = c.input(&US, &req, 5).unwrap();
        assert_eq!(r.op, Op::Reply);
        assert_eq!((r.sha, r.spa, r.tha, r.tpa), (US.mac, US.ip, GW_MAC, GW));
        assert_eq!(c.lookup(GW, 6), Some(GW_MAC));
    }

    #[test]
    fn nao_responde_para_outro_ip_nem_sem_ip_nem_a_si_mesmo() {
        let mut c = Cache::new();
        let req = |tpa, sha| Packet {
            op: Op::Request,
            sha,
            spa: GW,
            tha: Mac([0; 6]),
            tpa,
        };
        assert!(c.input(&US, &req([10, 0, 2, 99], GW_MAC), 0).is_none());
        assert!(c.input(&US, &req(US.ip, US.mac), 0).is_none());
        let sem_ip = Local { ip: [0; 4], ..US };
        assert!(c.input(&sem_ip, &req([0; 4], GW_MAC), 0).is_none());
        assert_eq!(c.lookup(GW, 1), None);
    }

    #[test]
    fn resposta_que_ninguem_pediu_nao_cria_entrada() {
        let mut c = Cache::new();
        assert!(c.input(&US, &reply(GW, GW_MAC), 0).is_none());
        assert_eq!(c.lookup(GW, 1), None);
        assert_eq!(c.resolve(GW, 2), Resolve::Ask);
        assert!(c.input(&US, &reply(GW, GW_MAC), 3).is_none());
        assert_eq!(c.lookup(GW, 4), Some(GW_MAC));
    }

    #[test]
    fn resposta_de_grupo_ou_ip_zero_e_ignorada() {
        let mut c = Cache::new();
        assert_eq!(c.resolve(GW, 0), Resolve::Ask);
        assert!(c.input(&US, &reply(GW, Mac::BROADCAST), 1).is_none());
        assert_eq!(c.lookup(GW, 2), None);
    }

    #[test]
    fn resolucao_pergunta_espera_repete_e_desiste() {
        let mut c = Cache::new();
        let mut t = 0;
        for _ in 0..MAX_TRIES {
            assert_eq!(c.resolve(GW, t), Resolve::Ask);
            assert_eq!(c.resolve(GW, t + 1), Resolve::Wait);
            t += RETRY_NS;
        }
        assert_eq!(c.resolve(GW, t), Resolve::Failed);
        assert_eq!(c.resolve(GW, t + 1), Resolve::Failed);
        // Passada a memória negativa, tenta de novo.
        assert_eq!(c.resolve(GW, t + NEGATIVE_NS + 1), Resolve::Ask);
    }

    #[test]
    fn entrada_expira_e_e_perguntada_de_novo() {
        let mut c = Cache::new();
        assert_eq!(c.resolve(GW, 0), Resolve::Ask);
        c.input(&US, &reply(GW, GW_MAC), 1);
        assert_eq!(c.resolve(GW, 2), Resolve::Hit(GW_MAC));
        assert_eq!(c.lookup(GW, 1 + TTL_NS), None);
        assert_eq!(c.resolve(GW, 1 + TTL_NS), Resolve::Ask);
    }

    #[test]
    fn cache_cheio_despeja_a_entrada_menos_recente() {
        let mut c = Cache::new();
        for i in 0..u8::try_from(crate::arp::CAP).unwrap() {
            let ip = [10, 0, 1, i];
            assert_eq!(c.resolve(ip, u64::from(i)), Resolve::Ask);
        }
        assert_eq!(c.resolve([10, 0, 9, 9], 100), Resolve::Ask);
        // A mais antiga (10.0.1.0) saiu: pergunta de novo, sem esperar.
        assert_eq!(c.resolve([10, 0, 1, 0], 101), Resolve::Ask);
    }

    #[test]
    fn anuncio_gratuito_e_pedido_do_proprio_ip() {
        let g = US.gratuitous();
        assert_eq!((g.spa, g.tpa), (US.ip, US.ip));
        assert_eq!(g.op, Op::Request);
    }
}

mod stack {
    use crate::arp::{Op, Packet};
    use crate::eth::{self, Header, Mac};
    use crate::stack::{Link, Stack};

    const US: Mac = Mac([2, 0, 0, 0, 0, 1]);
    const GW: Mac = Mac([2, 0, 0, 0, 0, 2]);
    const GW_IP: [u8; 4] = [10, 0, 2, 2];
    const IP: [u8; 4] = [10, 0, 2, 15];

    #[derive(Default)]
    struct Wire(Vec<Vec<u8>>);

    impl Link for Wire {
        fn send(&mut self, frame: &[u8]) -> bool {
            self.0.push(frame.to_vec());
            true
        }
    }

    fn arp_frame(dst: Mac, src: Mac, p: &Packet) -> Vec<u8> {
        let mut out = vec![0u8; 60];
        let h = Header {
            dst,
            src,
            ethertype: eth::ETHERTYPE_ARP,
        };
        eth::build(&h, &p.build(), &mut out).unwrap();
        out
    }

    fn sent_arp(frame: &[u8]) -> (Header, Packet) {
        let (h, p) = eth::parse(frame).unwrap();
        assert_eq!(h.ethertype, eth::ETHERTYPE_ARP);
        (h, Packet::parse(p).unwrap())
    }

    #[test]
    fn set_ip_anuncia() {
        let mut s = Stack::new(US);
        let mut w = Wire::default();
        s.set_ip(&mut w, IP);
        assert_eq!(w.0.len(), 1);
        let (h, p) = sent_arp(&w.0[0]);
        assert_eq!(h.dst, Mac::BROADCAST);
        assert_eq!((p.spa, p.tpa), (IP, IP));
        // Sem IP não há o que anunciar.
        let mut w = Wire::default();
        s.set_ip(&mut w, [0; 4]);
        assert!(w.0.is_empty());
    }

    #[test]
    fn resolve_o_roteador_pela_resposta() {
        let mut s = Stack::new(US);
        let mut w = Wire::default();
        s.set_ip(&mut w, IP);
        w.0.clear();
        assert_eq!(s.neighbor(&mut w, GW_IP, 0), None);
        assert_eq!(w.0.len(), 1);
        let (h, p) = sent_arp(&w.0[0]);
        assert_eq!((h.dst, p.op, p.tpa), (Mac::BROADCAST, Op::Request, GW_IP));
        // Pergunta repetida dentro do intervalo não manda de novo.
        assert_eq!(s.neighbor(&mut w, GW_IP, 1), None);
        assert_eq!(w.0.len(), 1);
        let reply = Packet {
            op: Op::Reply,
            sha: GW,
            spa: GW_IP,
            tha: US,
            tpa: IP,
        };
        s.input(&mut w, &arp_frame(US, GW, &reply), 2);
        assert_eq!(s.neighbor(&mut w, GW_IP, 3), Some(GW));
    }

    #[test]
    fn responde_ao_arp_do_roteador() {
        let mut s = Stack::new(US);
        let mut w = Wire::default();
        s.set_ip(&mut w, IP);
        w.0.clear();
        let req = Packet {
            op: Op::Request,
            sha: GW,
            spa: GW_IP,
            tha: Mac([0; 6]),
            tpa: IP,
        };
        s.input(&mut w, &arp_frame(Mac::BROADCAST, GW, &req), 0);
        assert_eq!(w.0.len(), 1);
        let (h, p) = sent_arp(&w.0[0]);
        assert_eq!((h.dst, h.src), (GW, US));
        assert_eq!(
            (p.op, p.sha, p.spa, p.tha, p.tpa),
            (Op::Reply, US, IP, GW, GW_IP)
        );
        assert_eq!(s.neighbor(&mut w, GW_IP, 1), Some(GW));
    }

    #[test]
    fn descarta_quadro_de_outro_destino_ou_lixo() {
        let mut s = Stack::new(US);
        let mut w = Wire::default();
        s.set_ip(&mut w, IP);
        w.0.clear();
        let req = Packet {
            op: Op::Request,
            sha: GW,
            spa: GW_IP,
            tha: Mac([0; 6]),
            tpa: IP,
        };
        // Destino é outro MAC.
        s.input(&mut w, &arp_frame(Mac([2, 0, 0, 0, 0, 9]), GW, &req), 0);
        // Eco do que nós mesmos mandamos.
        s.input(&mut w, &arp_frame(Mac::BROADCAST, US, &req), 0);
        // Curto e com EtherType desconhecido.
        s.input(&mut w, &[0u8; 5], 0);
        s.input(&mut w, &[0xffu8; 60], 0);
        assert!(w.0.is_empty());
    }
}
