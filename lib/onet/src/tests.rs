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
    use crate::icmp;
    use crate::ip4::{self, Config};
    use crate::stack::{Event, Link, NoUpper, SendError, Stack, Upper};
    use crate::udp;

    fn cfg() -> Config {
        Config {
            ip: IP,
            mask: [255, 255, 255, 0],
            gateway: GW_IP,
        }
    }

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
        s.set_config(&mut w, cfg());
        assert_eq!(w.0.len(), 1);
        let (h, p) = sent_arp(&w.0[0]);
        assert_eq!(h.dst, Mac::BROADCAST);
        assert_eq!((p.spa, p.tpa), (IP, IP));
        // Sem IP não há o que anunciar.
        let mut w = Wire::default();
        s.set_config(&mut w, Config::default());
        assert!(w.0.is_empty());
    }

    #[test]
    fn resolve_o_roteador_pela_resposta() {
        let mut s = Stack::new(US);
        let mut w = Wire::default();
        s.set_config(&mut w, cfg());
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
        s.input(&mut w, &mut NoUpper, &arp_frame(US, GW, &reply), 2);
        assert_eq!(s.neighbor(&mut w, GW_IP, 3), Some(GW));
    }

    #[test]
    fn responde_ao_arp_do_roteador() {
        let mut s = Stack::new(US);
        let mut w = Wire::default();
        s.set_config(&mut w, cfg());
        w.0.clear();
        let req = Packet {
            op: Op::Request,
            sha: GW,
            spa: GW_IP,
            tha: Mac([0; 6]),
            tpa: IP,
        };
        s.input(
            &mut w,
            &mut NoUpper,
            &arp_frame(Mac::BROADCAST, GW, &req),
            0,
        );
        assert_eq!(w.0.len(), 1);
        let (h, p) = sent_arp(&w.0[0]);
        assert_eq!((h.dst, h.src), (GW, US));
        assert_eq!(
            (p.op, p.sha, p.spa, p.tha, p.tpa),
            (Op::Reply, US, IP, GW, GW_IP)
        );
        assert_eq!(s.neighbor(&mut w, GW_IP, 1), Some(GW));
    }

    fn ip_frame(dst: Mac, src: Mac, h: &ip4::Header, payload: &[u8]) -> Vec<u8> {
        let mut pkt = [0u8; 1500];
        let n = ip4::build(h, payload, &mut pkt).unwrap();
        let mut out = vec![0u8; 14 + n];
        let eh = Header {
            dst,
            src,
            ethertype: eth::ETHERTYPE_IPV4,
        };
        eth::build(&eh, &pkt[..n], &mut out).unwrap();
        out
    }

    fn iph(src: [u8; 4], dst: [u8; 4]) -> ip4::Header {
        ip4::Header {
            id: 1,
            dont_fragment: false,
            more_fragments: false,
            frag_offset: 0,
            ttl: 64,
            proto: ip4::PROTO_ICMP,
            src,
            dst,
        }
    }

    fn echo(kind: u8, data: &[u8]) -> Vec<u8> {
        let mut m = vec![0u8; 8 + data.len()];
        let e = icmp::Echo {
            kind,
            id: 0xabcd,
            seq: 3,
            data,
        };
        icmp::build_echo(&e, &mut m).unwrap();
        m
    }

    /// Pilha configurada, com o roteador já no cache ARP.
    fn ready() -> (Stack, Wire) {
        let mut s = Stack::new(US);
        let mut w = Wire::default();
        s.set_config(&mut w, cfg());
        let req = Packet {
            op: Op::Request,
            sha: GW,
            spa: GW_IP,
            tha: Mac([0; 6]),
            tpa: IP,
        };
        s.input(
            &mut w,
            &mut NoUpper,
            &arp_frame(Mac::BROADCAST, GW, &req),
            0,
        );
        w.0.clear();
        (s, w)
    }

    #[test]
    fn ping_ao_roteador_e_resposta() {
        let mut s = Stack::new(US);
        let mut w = Wire::default();
        s.set_config(&mut w, cfg());
        w.0.clear();
        // Sem o MAC do roteador: a pergunta ARP sai e o ping fica pendente.
        assert_eq!(
            s.ping(&mut w, GW_IP, 0xabcd, 3, b"ping", 0),
            Err(SendError::Pending)
        );
        assert_eq!(w.0.len(), 1);
        let reply = Packet {
            op: Op::Reply,
            sha: GW,
            spa: GW_IP,
            tha: US,
            tpa: IP,
        };
        s.input(&mut w, &mut NoUpper, &arp_frame(US, GW, &reply), 1);
        w.0.clear();
        s.ping(&mut w, GW_IP, 0xabcd, 3, b"ping", 2).unwrap();
        let (h, p) = eth::parse(&w.0[0]).unwrap();
        assert_eq!((h.dst, h.ethertype), (GW, eth::ETHERTYPE_IPV4));
        let (ih, payload) = ip4::parse(p).unwrap();
        assert_eq!((ih.src, ih.dst, ih.proto, ih.ttl), (IP, GW_IP, 1, 64));
        let e = icmp::parse_echo(payload).unwrap();
        assert_eq!(
            (e.kind, e.id, e.seq, e.data),
            (icmp::ECHO_REQUEST, 0xabcd, 3, &b"ping"[..])
        );
        // A resposta do roteador vira evento.
        let r = ip_frame(US, GW, &iph(GW_IP, IP), &echo(icmp::ECHO_REPLY, b"ping"));
        assert_eq!(
            s.input(&mut w, &mut NoUpper, &r, 3),
            Some(Event::EchoReply {
                src: GW_IP,
                id: 0xabcd,
                seq: 3,
                len: 4
            })
        );
    }

    #[test]
    fn responde_ao_eco_dirigido_a_nos() {
        let (mut s, mut w) = ready();
        let f = ip_frame(US, GW, &iph(GW_IP, IP), &echo(icmp::ECHO_REQUEST, b"oi"));
        assert_eq!(s.input(&mut w, &mut NoUpper, &f, 1), None);
        assert_eq!(w.0.len(), 1);
        let (h, p) = eth::parse(&w.0[0]).unwrap();
        assert_eq!(h.dst, GW);
        let (ih, payload) = ip4::parse(p).unwrap();
        assert_eq!((ih.src, ih.dst), (IP, GW_IP));
        let e = icmp::parse_echo(payload).unwrap();
        assert_eq!(
            (e.kind, e.id, e.seq, e.data),
            (icmp::ECHO_REPLY, 0xabcd, 3, &b"oi"[..])
        );
    }

    #[test]
    fn nao_responde_a_eco_em_difusao_nem_de_origem_invalida() {
        let (mut s, mut w) = ready();
        let msg = echo(icmp::ECHO_REQUEST, b"oi");
        for (dst, src) in [
            ([10, 0, 2, 255], GW_IP),
            ([255; 4], GW_IP),
            (IP, [224, 0, 0, 1]),
            (IP, [255; 4]),
            (IP, [10, 0, 2, 255]),
            (IP, [0; 4]),
        ] {
            s.input(
                &mut w,
                &mut NoUpper,
                &ip_frame(US, GW, &iph(src, dst), &msg),
                1,
            );
        }
        assert!(w.0.is_empty());
    }

    #[test]
    fn descarta_ip_de_outro_destino_ttl_zero_e_checksum_ruim() {
        let (mut s, mut w) = ready();
        let msg = echo(icmp::ECHO_REQUEST, b"oi");
        s.input(
            &mut w,
            &mut NoUpper,
            &ip_frame(US, GW, &iph(GW_IP, [10, 0, 2, 99]), &msg),
            1,
        );
        let mut h = iph(GW_IP, IP);
        h.ttl = 0;
        s.input(&mut w, &mut NoUpper, &ip_frame(US, GW, &h, &msg), 1);
        let mut f = ip_frame(US, GW, &iph(GW_IP, IP), &msg);
        f[14 + 10] ^= 1;
        s.input(&mut w, &mut NoUpper, &f, 1);
        let mut f = ip_frame(US, GW, &iph(GW_IP, IP), &msg);
        let n = f.len();
        f[n - 1] ^= 1;
        s.input(&mut w, &mut NoUpper, &f, 1);
        assert!(w.0.is_empty());
    }

    #[test]
    fn eco_fragmentado_e_remontado() {
        let (mut s, mut w) = ready();
        let msg = echo(icmp::ECHO_REQUEST, &[7u8; 24]);
        let (a, b) = msg.split_at(16);
        let mut h = iph(GW_IP, IP);
        h.more_fragments = true;
        s.input(&mut w, &mut NoUpper, &ip_frame(US, GW, &h, a), 1);
        assert!(w.0.is_empty());
        h.more_fragments = false;
        h.frag_offset = 16;
        s.input(&mut w, &mut NoUpper, &ip_frame(US, GW, &h, b), 2);
        assert_eq!(w.0.len(), 1);
        let (_, p) = eth::parse(&w.0[0]).unwrap();
        let e = icmp::parse_echo(ip4::parse(p).unwrap().1).unwrap();
        assert_eq!((e.kind, e.data.len()), (icmp::ECHO_REPLY, 24));
    }

    /// Um `Upper` que guarda o que recebeu e escuta só uma porta.
    struct Listener {
        port: u16,
        got: Vec<(u16, Vec<u8>)>,
    }

    impl Upper for Listener {
        fn udp(&mut self, _: [u8; 4], sport: u16, dport: u16, data: &[u8]) -> bool {
            if dport == self.port {
                self.got.push((sport, data.to_vec()));
                true
            } else {
                false
            }
        }
    }

    fn udp_frame(dst: [u8; 4], sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
        let mut seg = [0u8; 600];
        let n = udp::build(GW_IP, dst, sport, dport, data, &mut seg).unwrap();
        let mut h = iph(GW_IP, dst);
        h.proto = ip4::PROTO_UDP;
        ip_frame(US, GW, &h, &seg[..n])
    }

    #[test]
    fn udp_entregue_e_enviado_com_checksum() {
        let (mut s, mut w) = ready();
        let mut up = Listener {
            port: 5000,
            got: vec![],
        };
        s.input(&mut w, &mut up, &udp_frame(IP, 777, 5000, b"eco"), 1);
        assert_eq!(up.got, vec![(777, b"eco".to_vec())]);
        assert!(w.0.is_empty());
        s.send_udp(&mut w, 5000, GW_IP, 777, b"eco", 2).unwrap();
        let (_, p) = eth::parse(&w.0[0]).unwrap();
        let (ih, payload) = ip4::parse(p).unwrap();
        assert_eq!(ih.proto, ip4::PROTO_UDP);
        let d = udp::parse(IP, GW_IP, payload).unwrap();
        assert_eq!((d.sport, d.dport, d.data), (5000, 777, &b"eco"[..]));
    }

    #[test]
    fn udp_para_porta_fechada_gera_icmp_com_limite_de_taxa() {
        let (mut s, mut w) = ready();
        let mut up = Listener {
            port: 5000,
            got: vec![],
        };
        s.input(&mut w, &mut up, &udp_frame(IP, 777, 9, b"x"), 1);
        assert_eq!(w.0.len(), 1);
        let (_, p) = eth::parse(&w.0[0]).unwrap();
        let (ih, icmp_msg) = ip4::parse(p).unwrap();
        assert_eq!((ih.proto, ih.dst), (ip4::PROTO_ICMP, GW_IP));
        assert_eq!(icmp_msg[..2], [3, 3]);
        assert_eq!(ip4::checksum(icmp_msg), 0);
        // Cita o cabeçalho IP original (20) mais 8 bytes.
        assert_eq!(icmp_msg.len(), 8 + 20 + 8);
        assert_eq!(icmp_msg[8 + 9], ip4::PROTO_UDP);
        // Dentro de 100 ms não sai outro.
        s.input(&mut w, &mut up, &udp_frame(IP, 777, 9, b"x"), 2);
        assert_eq!(w.0.len(), 1);
        s.input(&mut w, &mut up, &udp_frame(IP, 777, 9, b"x"), 100_000_001);
        assert_eq!(w.0.len(), 2);
        // Difusão para porta fechada não gera erro.
        s.input(
            &mut w,
            &mut up,
            &udp_frame([255; 4], 777, 9, b"x"),
            200_000_002,
        );
        assert_eq!(w.0.len(), 2);
    }

    #[test]
    fn udp_com_checksum_ruim_ou_tamanho_incoerente_e_descartado() {
        let (mut s, mut w) = ready();
        let mut up = Listener {
            port: 5000,
            got: vec![],
        };
        let mut f = udp_frame(IP, 777, 5000, b"eco");
        let n = f.len();
        f[n - 1] ^= 1;
        s.input(&mut w, &mut up, &f, 1);
        assert!(up.got.is_empty() && w.0.is_empty());
        // Campo de tamanho maior que o recebido.
        let mut seg = [0u8; 16];
        let n = udp::build(GW_IP, IP, 1, 5000, b"abcdefgh", &mut seg).unwrap();
        seg[4..6].copy_from_slice(&200u16.to_be_bytes());
        let mut h = iph(GW_IP, IP);
        h.proto = ip4::PROTO_UDP;
        s.input(&mut w, &mut up, &ip_frame(US, GW, &h, &seg[..n]), 1);
        assert!(up.got.is_empty() && w.0.is_empty());
    }

    #[test]
    fn envio_sem_rota_grande_demais_e_difusao() {
        let mut s = Stack::new(US);
        let mut w = Wire::default();
        assert_eq!(
            s.send_ip(&mut w, GW_IP, 17, b"x", 0),
            Err(SendError::NoRoute)
        );
        s.set_config(&mut w, cfg());
        w.0.clear();
        let grande = [0u8; 1481];
        assert_eq!(
            s.send_ip(&mut w, GW_IP, 17, &grande, 0),
            Err(SendError::TooBig)
        );
        // Difusão sai sem ARP.
        s.send_ip(&mut w, [255; 4], 17, b"x", 0).unwrap();
        let (h, _) = eth::parse(&w.0[0]).unwrap();
        assert_eq!(h.dst, Mac::BROADCAST);
        // Sem endereço, só a difusão limitada sai (DHCP).
        let mut s = Stack::new(US);
        let mut w = Wire::default();
        s.send_ip(&mut w, [255; 4], 17, b"x", 0).unwrap();
        let (_, p) = eth::parse(&w.0[0]).unwrap();
        assert_eq!(ip4::parse(p).unwrap().0.src, [0; 4]);
        assert_eq!(
            s.send_ip(&mut w, GW_IP, 17, b"x", 0),
            Err(SendError::NoRoute)
        );
    }

    #[test]
    fn descarta_quadro_de_outro_destino_ou_lixo() {
        let mut s = Stack::new(US);
        let mut w = Wire::default();
        s.set_config(&mut w, cfg());
        w.0.clear();
        let req = Packet {
            op: Op::Request,
            sha: GW,
            spa: GW_IP,
            tha: Mac([0; 6]),
            tpa: IP,
        };
        // Destino é outro MAC.
        s.input(
            &mut w,
            &mut NoUpper,
            &arp_frame(Mac([2, 0, 0, 0, 0, 9]), GW, &req),
            0,
        );
        // Eco do que nós mesmos mandamos.
        s.input(
            &mut w,
            &mut NoUpper,
            &arp_frame(Mac::BROADCAST, US, &req),
            0,
        );
        // Curto e com EtherType desconhecido.
        s.input(&mut w, &mut NoUpper, &[0u8; 5], 0);
        s.input(&mut w, &mut NoUpper, &[0xffu8; 60], 0);
        assert!(w.0.is_empty());
    }
}

mod ip {
    use crate::arp::Ip4;
    use crate::icmp::{self, Echo};
    use crate::ip4::{self, Config, Header};

    fn hdr(src: Ip4, dst: Ip4) -> Header {
        Header {
            id: 7,
            dont_fragment: true,
            more_fragments: false,
            frag_offset: 0,
            ttl: 64,
            proto: ip4::PROTO_ICMP,
            src,
            dst,
        }
    }

    #[test]
    fn checksum_da_rfc_1071() {
        // Exemplo da RFC 1071, seção 3: 00 01 f2 03 f4 f5 f6 f7 soma ddf2.
        let d = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(ip4::fold(ip4::sum(&d, 0)), !0xddf2);
        // Tamanho ímpar completa com zero à direita.
        assert_eq!(ip4::checksum(&[0xff]), !0xff00);
        assert_eq!(ip4::checksum(&[]), 0xffff);
    }

    #[test]
    fn cabecalho_ida_e_volta_com_checksum() {
        let h = hdr([10, 0, 2, 15], [10, 0, 2, 2]);
        let mut out = [0u8; 64];
        let n = ip4::build(&h, b"hello", &mut out).unwrap();
        assert_eq!(n, 25);
        assert_eq!(ip4::checksum(&out[..20]), 0);
        let (h2, p) = ip4::parse(&out[..n]).unwrap();
        assert_eq!(h2, h);
        assert_eq!(p, b"hello");
        // O preenchimento do quadro depois de `total_length` é cortado.
        out[n..n + 10].fill(0xaa);
        assert_eq!(ip4::parse(&out[..n + 10]).unwrap().1, b"hello");
    }

    #[test]
    fn cabecalho_invalido_e_recusado() {
        let h = hdr([10, 0, 2, 15], [10, 0, 2, 2]);
        let mut out = [0u8; 64];
        let n = ip4::build(&h, b"hello", &mut out).unwrap();
        assert!(ip4::parse(&out[..19]).is_none());
        // Truncado: total_length maior que o recebido.
        assert!(ip4::parse(&out[..n - 1]).is_none());
        for i in 0..20 {
            let mut x = out;
            x[i] ^= 0x01;
            assert!(ip4::parse(&x[..n]).is_none(), "byte {i}");
        }
        // Versão 6 e IHL menor que 5, com checksum refeito.
        for first in [0x65u8, 0x44] {
            let mut x = out;
            x[0] = first;
            x[10..12].fill(0);
            let c = ip4::checksum(&x[..20]);
            x[10..12].copy_from_slice(&c.to_be_bytes());
            assert!(ip4::parse(&x[..n]).is_none());
        }
        let mut pequeno = [0u8; 24];
        assert!(ip4::build(&h, b"hello", &mut pequeno).is_none());
    }

    #[test]
    fn fragmentos_marcados() {
        let mut h = hdr([1, 1, 1, 1], [2, 2, 2, 2]);
        assert!(!h.is_fragment());
        h.more_fragments = true;
        assert!(h.is_fragment());
        h.more_fragments = false;
        h.frag_offset = 16;
        assert!(h.is_fragment());
        let mut out = [0u8; 40];
        let n = ip4::build(&h, b"x", &mut out).unwrap();
        assert_eq!(ip4::parse(&out[..n]).unwrap().0.frag_offset, 16);
    }

    #[test]
    fn rotas_e_destinos_locais() {
        let c = Config {
            ip: [10, 0, 2, 15],
            mask: [255, 255, 255, 0],
            gateway: [10, 0, 2, 2],
        };
        assert_eq!(c.next_hop([10, 0, 2, 99]), Some([10, 0, 2, 99]));
        assert_eq!(c.next_hop([8, 8, 8, 8]), Some([10, 0, 2, 2]));
        let sem_gw = Config {
            gateway: [0; 4],
            ..c
        };
        assert_eq!(sem_gw.next_hop([8, 8, 8, 8]), None);
        assert_eq!(Config::default().next_hop([10, 0, 2, 2]), None);
        assert!(c.is_local([10, 0, 2, 15]));
        assert!(c.is_local([10, 0, 2, 255]));
        assert!(c.is_local([255; 4]));
        assert!(!c.is_local([10, 0, 2, 16]));
        assert!(!Config::default().is_local([0; 4]));
        assert!(Config::default().is_local([255; 4]));
    }

    #[test]
    fn eco_ida_e_volta_e_checksum() {
        let e = Echo {
            kind: icmp::ECHO_REQUEST,
            id: 0x1234,
            seq: 9,
            data: b"abcdefg",
        };
        let mut out = [0u8; 32];
        let n = icmp::build_echo(&e, &mut out).unwrap();
        assert_eq!(icmp::parse_echo(&out[..n]), Some(e));
        out[n - 1] ^= 1;
        assert!(icmp::parse_echo(&out[..n]).is_none());
        assert!(icmp::parse_echo(&out[..7]).is_none());
        let mut pequeno = [0u8; 10];
        assert!(icmp::build_echo(&e, &mut pequeno).is_none());
        // Tipo que não é eco.
        let mut x = [3u8, 1, 0, 0, 0, 0, 0, 0];
        let c = ip4::checksum(&x);
        x[2..4].copy_from_slice(&c.to_be_bytes());
        assert!(icmp::parse_echo(&x).is_none());
    }
}

mod frag {
    use crate::frag::{MAX_DATAGRAM, MAX_FRAGS, Reassembler, SLOTS, TIMEOUT_NS};
    use crate::ip4::{self, Header};

    fn frag(id: u16, off: u16, more: bool) -> Header {
        Header {
            id,
            dont_fragment: false,
            more_fragments: more,
            frag_offset: off,
            ttl: 64,
            proto: ip4::PROTO_UDP,
            src: [1, 1, 1, 1],
            dst: [2, 2, 2, 2],
        }
    }

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    #[test]
    fn remonta_em_ordem_e_fora_de_ordem() {
        let d = data(40);
        let mut out = [0u8; MAX_DATAGRAM];
        let mut r = Reassembler::new();
        assert!(r.add(&frag(1, 0, true), &d[..16], 0, &mut out).is_none());
        assert!(r.add(&frag(1, 16, true), &d[16..32], 0, &mut out).is_none());
        let (h, n) = r.add(&frag(1, 32, false), &d[32..], 0, &mut out).unwrap();
        assert_eq!(&out[..n], &d[..]);
        assert!(!h.is_fragment());
        assert_eq!(r.pending(), 0);
        // Fora de ordem, o último primeiro.
        assert!(r.add(&frag(2, 32, false), &d[32..], 0, &mut out).is_none());
        assert!(r.add(&frag(2, 16, true), &d[16..32], 0, &mut out).is_none());
        let (_, n) = r.add(&frag(2, 0, true), &d[..16], 0, &mut out).unwrap();
        assert_eq!(&out[..n], &d[..]);
    }

    #[test]
    fn sobreposicao_derruba_o_datagrama() {
        let d = data(40);
        let mut out = [0u8; MAX_DATAGRAM];
        let mut r = Reassembler::new();
        r.add(&frag(1, 0, true), &d[..16], 0, &mut out);
        assert!(r.add(&frag(1, 8, true), &d[8..24], 0, &mut out).is_none());
        assert_eq!(r.pending(), 0);
        // Repetição exata também conta como sobreposição.
        r.add(&frag(3, 0, true), &d[..16], 0, &mut out);
        assert!(r.add(&frag(3, 0, true), &d[..16], 0, &mut out).is_none());
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn limites_de_tamanho_e_de_fragmentos() {
        let d = data(MAX_DATAGRAM + 8);
        let mut out = [0u8; MAX_DATAGRAM];
        let mut r = Reassembler::new();
        // Passa do máximo.
        assert!(
            r.add(&frag(1, 8, false), &d[..MAX_DATAGRAM], 0, &mut out)
                .is_none()
        );
        // Fragmento do meio que não é múltiplo de 8.
        assert!(r.add(&frag(1, 0, true), &d[..10], 0, &mut out).is_none());
        // Vazio.
        assert!(r.add(&frag(1, 0, true), &[], 0, &mut out).is_none());
        // Fragmentos demais.
        for i in 0..MAX_FRAGS {
            let off = u16::try_from(i * 8).unwrap();
            r.add(&frag(9, off, true), &d[..8], 0, &mut out);
        }
        assert_eq!(r.pending(), 1);
        let off = u16::try_from(MAX_FRAGS * 8).unwrap();
        assert!(r.add(&frag(9, off, true), &d[..8], 0, &mut out).is_none());
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn ultimo_fragmento_incoerente() {
        let d = data(64);
        let mut out = [0u8; MAX_DATAGRAM];
        let mut r = Reassembler::new();
        r.add(&frag(1, 32, true), &d[..8], 0, &mut out);
        // O "último" termina antes de um fragmento já recebido.
        assert!(r.add(&frag(1, 0, false), &d[..16], 0, &mut out).is_none());
        assert_eq!(r.pending(), 0);
        // Dois últimos.
        r.add(&frag(2, 8, false), &d[..8], 0, &mut out);
        assert!(r.add(&frag(2, 24, false), &d[..8], 0, &mut out).is_none());
        // Fragmento "com mais" além do fim já declarado.
        r.add(&frag(3, 8, false), &d[..8], 0, &mut out);
        assert!(r.add(&frag(3, 16, true), &d[..8], 0, &mut out).is_none());
    }

    #[test]
    fn prazo_e_vagas() {
        let d = data(16);
        let mut out = [0u8; MAX_DATAGRAM];
        let mut r = Reassembler::new();
        for id in 0..u16::try_from(SLOTS).unwrap() {
            r.add(&frag(id, 0, true), &d[..8], 0, &mut out);
        }
        assert_eq!(r.pending(), SLOTS);
        // Sem vaga: o novo é recusado e os antigos ficam.
        assert!(r.add(&frag(99, 0, true), &d[..8], 1, &mut out).is_none());
        assert_eq!(r.pending(), SLOTS);
        assert!(r.add(&frag(0, 8, false), &d[8..16], 2, &mut out).is_some());
        assert_eq!(r.pending(), SLOTS - 1);
        // Passado o prazo, tudo sai.
        r.expire(TIMEOUT_NS);
        assert_eq!(r.pending(), 0);
    }
}

mod udp_e_portas {
    use crate::ip4;
    use crate::ports::{COUNT, Ephemeral, FIRST};
    use crate::udp;

    const A: [u8; 4] = [10, 0, 2, 15];
    const B: [u8; 4] = [10, 0, 2, 2];

    #[test]
    fn datagrama_ida_e_volta() {
        let mut out = [0u8; 64];
        let n = udp::build(A, B, 1234, 53, b"dados", &mut out).unwrap();
        assert_eq!(n, 13);
        let d = udp::parse(A, B, &out[..n]).unwrap();
        assert_eq!((d.sport, d.dport, d.data), (1234, 53, &b"dados"[..]));
        // Endereço trocado muda o pseudo-cabeçalho e invalida o checksum.
        assert!(udp::parse(B, A, &out[..n]).is_some());
        assert!(udp::parse(A, [1, 1, 1, 1], &out[..n]).is_none());
        // Checksum zero é aceito (sem checksum).
        out[6..8].fill(0);
        assert!(udp::parse(A, [1, 1, 1, 1], &out[..n]).is_some());
        // Preenchimento depois do tamanho é cortado.
        let mut cheio = [0u8; 64];
        let n = udp::build(A, B, 1, 2, b"ab", &mut cheio).unwrap();
        cheio[n..n + 5].fill(9);
        assert_eq!(udp::parse(A, B, &cheio[..n + 5]).unwrap().data, b"ab");
    }

    #[test]
    fn datagrama_malformado() {
        let mut out = [0u8; 64];
        let n = udp::build(A, B, 1, 2, b"ab", &mut out).unwrap();
        assert!(udp::parse(A, B, &out[..7]).is_none());
        assert!(udp::parse(A, B, &out[..n - 1]).is_none());
        let mut x = out;
        x[4..6].copy_from_slice(&7u16.to_be_bytes());
        assert!(udp::parse(A, B, &x[..n]).is_none());
        let mut pequeno = [0u8; 9];
        assert!(udp::build(A, B, 1, 2, b"ab", &mut pequeno).is_none());
    }

    #[test]
    fn checksum_nunca_sai_zero() {
        // Procura dados cujo checksum calculado seria 0 e confere o 0xffff.
        let mut out = [0u8; 16];
        for x in 0..=u16::MAX {
            let n = udp::build(A, B, 1, 2, &x.to_be_bytes(), &mut out).unwrap();
            assert_ne!(out[6..8], [0, 0]);
            assert!(udp::parse(A, B, &out[..n]).is_some());
        }
        assert_eq!(ip4::PROTO_UDP, 17);
    }

    #[test]
    fn portas_efemeras() {
        let mut p = Ephemeral::new();
        let a = p.alloc(7).unwrap();
        assert!(a >= FIRST && p.in_use(a));
        // Porta ocupada: anda para a seguinte.
        let b = p.alloc(7).unwrap();
        assert_ne!(a, b);
        p.release(a);
        assert!(!p.in_use(a));
        assert_eq!(p.alloc(7), Some(a));
        // A aleatoriedade espalha: outra semente, outra porta.
        assert_ne!(p.alloc(1000), p.alloc(1000));
        assert!(!p.reserve(a));
        assert!(!p.reserve(80));
        assert!(!p.in_use(80));
        p.release(80);
    }

    #[test]
    fn portas_esgotadas_e_volta() {
        let mut p = Ephemeral::new();
        for _ in 0..COUNT {
            assert!(p.alloc(0).is_some());
        }
        assert_eq!(p.alloc(5), None);
        p.release(65535);
        assert_eq!(p.alloc(12345), Some(65535));
        assert!(!p.reserve(FIRST));
    }
}

mod dhcp {
    use crate::dhcp::{Client, Lease, Outcome, Packet, State};
    use crate::eth::{self, Header, Mac};
    use crate::ip4::{self, Config};
    use crate::stack::{Event, Link, NoUpper, Stack};
    use crate::udp;

    const US: Mac = Mac([2, 0, 0, 0, 0, 1]);
    const SRV: [u8; 4] = [10, 0, 2, 2];
    const IP: [u8; 4] = [10, 0, 2, 15];
    const SEC: u64 = 1_000_000_000;

    #[derive(Default)]
    struct Wire(Vec<Vec<u8>>);

    impl Link for Wire {
        fn send(&mut self, frame: &[u8]) -> bool {
            self.0.push(frame.to_vec());
            true
        }
    }

    /// Opções que o servidor de teste põe na resposta.
    struct Opts {
        lease: Option<u32>,
        t1: Option<u32>,
        t2: Option<u32>,
        mask: Option<[u8; 4]>,
        router: Option<[u8; 4]>,
        server: Option<[u8; 4]>,
    }

    impl Default for Opts {
        fn default() -> Self {
            Self {
                lease: Some(3600),
                t1: None,
                t2: None,
                mask: Some([255, 255, 255, 0]),
                router: Some(SRV),
                server: Some(SRV),
            }
        }
    }

    fn reply(req: &[u8], kind: u8, ip: [u8; 4], o: &Opts) -> Vec<u8> {
        let mut m = vec![0u8; 240];
        m[0] = 2;
        m[1] = 1;
        m[2] = 6;
        m[4..8].copy_from_slice(&req[4..8]);
        m[16..20].copy_from_slice(&ip);
        m[28..34].copy_from_slice(&req[28..34]);
        m[236..240].copy_from_slice(&[99, 130, 83, 99]);
        m.extend_from_slice(&[53, 1, kind]);
        if let Some(s) = o.server {
            m.extend_from_slice(&[54, 4]);
            m.extend_from_slice(&s);
        }
        if let Some(x) = o.mask {
            m.extend_from_slice(&[1, 4]);
            m.extend_from_slice(&x);
        }
        if let Some(r) = o.router {
            m.extend_from_slice(&[3, 4]);
            m.extend_from_slice(&r);
        }
        m.extend_from_slice(&[6, 8, 10, 0, 2, 3, 8, 8, 8, 8]);
        for (code, v) in [(51, o.lease), (58, o.t1), (59, o.t2)] {
            if let Some(v) = v {
                m.extend_from_slice(&[code, 4]);
                m.extend_from_slice(&v.to_be_bytes());
            }
        }
        m.push(255);
        m
    }

    fn drive(c: &mut Client, now: u64) -> Option<Packet> {
        c.poll(now, 0xdead_beef)
    }

    /// Procura a opção `code` numa mensagem do cliente.
    fn opt(msg: &[u8], code: u8) -> Option<Vec<u8>> {
        let mut o = &msg[240..];
        while let Some(&c) = o.first() {
            if c == 255 {
                return None;
            }
            if c == 0 {
                o = &o[1..];
                continue;
            }
            let l = usize::from(o[1]);
            if c == code {
                return Some(o[2..2 + l].to_vec());
            }
            o = &o[2 + l..];
        }
        None
    }

    /// Leva o cliente até `Bound` às 0 s e devolve o `REQUEST` que ele mandou.
    fn bind(c: &mut Client, o: &Opts) -> Lease {
        let d = drive(c, 0).unwrap();
        assert_eq!(opt(d.bytes(), 53), Some(vec![1]));
        assert_eq!(d.dst, [255; 4]);
        assert_eq!(c.input(&reply(d.bytes(), 2, IP, o), 0), Outcome::Offered);
        let r = drive(c, 0).unwrap();
        assert_eq!(opt(r.bytes(), 53), Some(vec![3]));
        assert_eq!(opt(r.bytes(), 50), Some(IP.to_vec()));
        assert_eq!(opt(r.bytes(), 54), Some(SRV.to_vec()));
        let Outcome::Bound(l) = c.input(&reply(r.bytes(), 5, IP, o), 0) else {
            panic!("sem concessão");
        };
        l
    }

    #[test]
    fn descoberta_oferta_pedido_e_ack() {
        let mut c = Client::new(US);
        let l = bind(&mut c, &Opts::default());
        assert_eq!(c.state(), State::Bound);
        assert_eq!(
            l.config,
            Config {
                ip: IP,
                mask: [255, 255, 255, 0],
                gateway: SRV
            }
        );
        assert_eq!(l.dns[..l.dns_count], [[10, 0, 2, 3], [8, 8, 8, 8]]);
        assert_eq!(l.lease_secs, 3600);
        assert!(c.lease().is_some());
    }

    #[test]
    fn renova_em_t1_reassocia_em_t2_e_vence() {
        let mut c = Client::new(US);
        bind(&mut c, &Opts::default());
        assert!(drive(&mut c, 1_799 * SEC).is_none());
        // T1 = metade: pedido unicast ao servidor, com `ciaddr` e sem opção 50.
        let r = drive(&mut c, 1_800 * SEC).unwrap();
        assert_eq!(c.state(), State::Renewing);
        assert_eq!(r.dst, SRV);
        assert_eq!(&r.bytes()[12..16], &IP);
        assert_eq!(opt(r.bytes(), 50), None);
        // Resposta de renovação reinicia o prazo.
        let Outcome::Bound(_) = c.input(&reply(r.bytes(), 5, IP, &Opts::default()), 1_801 * SEC)
        else {
            panic!("renovação não aceita");
        };
        assert_eq!(c.state(), State::Bound);
        assert!(drive(&mut c, 3_500 * SEC).is_none());
        // Sem resposta até T2 (7/8): difusão.
        let r = drive(&mut c, 1_801 * SEC + 3_150 * SEC).unwrap();
        assert_eq!(c.state(), State::Rebinding);
        assert_eq!(r.dst, [255; 4]);
        // E no fim da concessão a pilha perde o endereço.
        assert!(drive(&mut c, 1_801 * SEC + 3_600 * SEC).is_none());
        assert!(c.take_expired());
        assert!(!c.take_expired());
        assert_eq!(c.state(), State::Init);
        assert!(c.lease().is_none());
        // Recomeça pelo `DISCOVER` depois da pausa.
        assert!(drive(&mut c, 1_801 * SEC + 3_600 * SEC + SEC / 2).is_none());
        assert!(drive(&mut c, 1_801 * SEC + 3_601 * SEC).is_some());
    }

    #[test]
    fn t1_e_t2_do_servidor_valem_e_os_incoerentes_nao() {
        let mut c = Client::new(US);
        bind(
            &mut c,
            &Opts {
                t1: Some(100),
                t2: Some(200),
                ..Opts::default()
            },
        );
        assert!(drive(&mut c, 99 * SEC).is_none());
        assert!(drive(&mut c, 100 * SEC).is_some());
        let mut c = Client::new(US);
        bind(
            &mut c,
            &Opts {
                t1: Some(5000),
                t2: Some(10),
                ..Opts::default()
            },
        );
        assert!(drive(&mut c, 1_799 * SEC).is_none());
        assert!(drive(&mut c, 1_800 * SEC).is_some());
    }

    #[test]
    fn discover_repete_com_espera_crescente() {
        let mut c = Client::new(US);
        assert!(drive(&mut c, 0).is_some());
        assert!(drive(&mut c, SEC).is_none());
        assert!(drive(&mut c, 2 * SEC).is_some());
        assert!(drive(&mut c, 5 * SEC).is_none());
        assert!(drive(&mut c, 6 * SEC).is_some());
        assert!(drive(&mut c, 13 * SEC).is_none());
        assert!(drive(&mut c, 14 * SEC).is_some());
    }

    #[test]
    fn request_sem_ack_recomeca_e_nak_derruba() {
        let mut c = Client::new(US);
        let d = drive(&mut c, 0).unwrap();
        c.input(&reply(d.bytes(), 2, IP, &Opts::default()), 0);
        let r = drive(&mut c, 0).unwrap();
        assert_eq!(c.state(), State::Requesting);
        // Quatro tentativas no total, depois volta ao início.
        let mut n = 1;
        let mut t = 0;
        while c.state() == State::Requesting {
            t += 70 * SEC;
            if drive(&mut c, t).is_some() {
                n += 1;
            }
        }
        assert_eq!(n, 4);
        assert_eq!(c.state(), State::Init);
        // `NAK` no pedido.
        let mut c = Client::new(US);
        let d = drive(&mut c, 0).unwrap();
        c.input(&reply(d.bytes(), 2, IP, &Opts::default()), 0);
        let r2 = drive(&mut c, 0).unwrap();
        assert_eq!(
            c.input(&reply(r2.bytes(), 6, [0; 4], &Opts::default()), 0),
            Outcome::Nak
        );
        assert_eq!(c.state(), State::Init);
        let _ = r;
    }

    #[test]
    fn resposta_hostil_e_ignorada() {
        let mut c = Client::new(US);
        let d = drive(&mut c, 0).unwrap();
        let ok = reply(d.bytes(), 2, IP, &Opts::default());
        let mut trocar = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut m = ok.clone();
            f(&mut m);
            assert_eq!(c.input(&m, 0), Outcome::None, "aceitou resposta adulterada");
        };
        trocar(&|m| m[4] ^= 1); // xid
        trocar(&|m| m[28] ^= 1); // chaddr
        trocar(&|m| m[0] = 1); // op
        trocar(&|m| m[236] = 0); // cookie
        trocar(&|m| m[1] = 6); // htype
        trocar(&|m| m.truncate(200));
        trocar(&|m| m[16..20].copy_from_slice(&[0; 4])); // yiaddr zero
        trocar(&|m| m[16..20].copy_from_slice(&[224, 0, 0, 1]));
        trocar(&|m| m[16..20].copy_from_slice(&[127, 0, 0, 1]));
        // Máscara não contígua, grande demais ou sem servidor.
        for o in [
            Opts {
                mask: Some([255, 0, 255, 0]),
                ..Opts::default()
            },
            Opts {
                mask: Some([255, 255, 255, 255]),
                ..Opts::default()
            },
            Opts {
                mask: Some([0; 4]),
                ..Opts::default()
            },
            Opts {
                mask: None,
                ..Opts::default()
            },
            Opts {
                server: None,
                ..Opts::default()
            },
        ] {
            assert_eq!(c.input(&reply(d.bytes(), 2, IP, &o), 0), Outcome::None);
        }
        // Tipo certo no estado errado: `ACK` sem pedido.
        assert_eq!(
            c.input(&reply(d.bytes(), 5, IP, &Opts::default()), 0),
            Outcome::None
        );
        // Opção que passa do fim da mensagem.
        let mut m = ok.clone();
        m.truncate(m.len() - 3);
        let n = m.len();
        m[n - 1] = 200;
        assert_eq!(c.input(&m, 0), Outcome::None);
    }

    #[test]
    fn roteador_fora_da_rede_e_ack_sem_prazo() {
        let mut c = Client::new(US);
        let o = Opts {
            router: Some([192, 168, 0, 1]),
            ..Opts::default()
        };
        let l = bind(&mut c, &o);
        assert_eq!(l.config.gateway, [0; 4]);
        // `ACK` sem prazo ou com prazo zero não vale.
        let mut c = Client::new(US);
        let d = drive(&mut c, 0).unwrap();
        c.input(&reply(d.bytes(), 2, IP, &Opts::default()), 0);
        let r = drive(&mut c, 0).unwrap();
        for lease in [None, Some(0)] {
            let o = Opts {
                lease,
                ..Opts::default()
            };
            assert_eq!(c.input(&reply(r.bytes(), 5, IP, &o), 0), Outcome::None);
        }
    }

    #[test]
    fn concessao_eterna_nao_renova() {
        let mut c = Client::new(US);
        bind(
            &mut c,
            &Opts {
                lease: Some(u32::MAX),
                ..Opts::default()
            },
        );
        assert!(drive(&mut c, 1_000_000 * SEC).is_none());
        assert_eq!(c.state(), State::Bound);
    }

    #[test]
    fn nenhuma_mensagem_entra_em_panico() {
        let mut c = Client::new(US);
        let d = drive(&mut c, 0).unwrap();
        let ok = reply(d.bytes(), 2, IP, &Opts::default());
        for len in 0..=ok.len() {
            c.input(&ok[..len], 0);
        }
        for i in 0..ok.len() {
            let mut m = ok.clone();
            m[i] = m[i].wrapping_add(0x55);
            c.input(&m, 0);
        }
    }

    fn udp_frame(dst: Mac, msg: &[u8]) -> Vec<u8> {
        let mut seg = vec![0u8; msg.len() + 8];
        let n = udp::build(SRV, [255; 4], 67, 68, msg, &mut seg).unwrap();
        let h = ip4::Header {
            id: 1,
            dont_fragment: false,
            more_fragments: false,
            frag_offset: 0,
            ttl: 64,
            proto: ip4::PROTO_UDP,
            src: SRV,
            dst: [255; 4],
        };
        let mut pkt = vec![0u8; 1500];
        let pn = ip4::build(&h, &seg[..n], &mut pkt).unwrap();
        let mut out = vec![0u8; 1514];
        let eh = Header {
            dst,
            src: Mac([2, 0, 0, 0, 0, 2]),
            ethertype: eth::ETHERTYPE_IPV4,
        };
        let len = eth::build(&eh, &pkt[..pn], &mut out).unwrap();
        out.truncate(len);
        out
    }

    /// A pilha, ligada ao DHCP, sai sem endereço e entra na rede com o que
    /// o servidor concede.
    #[test]
    fn pilha_obtem_o_endereco_pelo_dhcp() {
        let mut s = Stack::new(US);
        let mut w = Wire::default();
        // Sem `start_dhcp`, `tick` não manda nada.
        s.tick(&mut w, 0);
        assert!(w.0.is_empty());
        s.start_dhcp();
        s.tick(&mut w, 0);
        assert_eq!(w.0.len(), 1);
        let (h, p) = eth::parse(&w.0[0]).unwrap();
        assert_eq!(h.dst, Mac::BROADCAST);
        let (ih, body) = ip4::parse(p).unwrap();
        assert_eq!((ih.src, ih.dst), ([0; 4], [255; 4]));
        let u = udp::parse(ih.src, ih.dst, body).unwrap();
        assert_eq!((u.sport, u.dport), (68, 67));
        let discover = u.data.to_vec();
        w.0.clear();
        // A oferta chega: o `REQUEST` sai na hora.
        let offer = reply(&discover, 2, IP, &Opts::default());
        assert_eq!(
            s.input(&mut w, &mut NoUpper, &udp_frame(Mac::BROADCAST, &offer), 1),
            None
        );
        assert_eq!(w.0.len(), 1);
        let (_, p) = eth::parse(&w.0[0]).unwrap();
        let (ih, body) = ip4::parse(p).unwrap();
        let request = udp::parse(ih.src, ih.dst, body).unwrap().data.to_vec();
        assert_eq!(opt(&request, 53), Some(vec![3]));
        w.0.clear();
        let ack = reply(&request, 5, IP, &Opts::default());
        let ev = s.input(&mut w, &mut NoUpper, &udp_frame(Mac::BROADCAST, &ack), 2);
        assert!(matches!(ev, Some(Event::Lease(l)) if l.config.ip == IP));
        assert_eq!(s.ip(), IP);
        assert_eq!(s.config().gateway, SRV);
        // O endereço é anunciado por ARP gratuito.
        assert_eq!(w.0.len(), 1);
        assert_eq!(eth::parse(&w.0[0]).unwrap().0.ethertype, eth::ETHERTYPE_ARP);
        // Resposta repetida não reconfigura nem anuncia de novo.
        w.0.clear();
        s.input(&mut w, &mut NoUpper, &udp_frame(Mac::BROADCAST, &ack), 3);
        assert!(w.0.is_empty());
        // DHCP de outro servidor/porta é ignorado pela entrada normal.
        assert_eq!(s.dhcp().state(), State::Bound);
    }
}

mod ipv6 {
    use crate::eth::{self, Header, Mac};
    use crate::frag::{MAX_DATAGRAM, Reassembler};
    use crate::icmp6::{self, Msg, Prefix};
    use crate::ip6::{self, Ip6};
    use crate::slaac::{Kind, Slaac, Tx};
    use crate::stack::{Event, Link, NoUpper, Stack};

    const US: Mac = Mac([2, 0, 0, 0, 0, 1]);
    const GW: Mac = Mac([2, 0, 0, 0, 0, 2]);
    const S: u64 = 1_000_000_000;
    const GW_LL: Ip6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const PREFIX: Ip6 = [0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    #[derive(Default)]
    struct Wire(Vec<Vec<u8>>);

    impl Link for Wire {
        fn send(&mut self, frame: &[u8]) -> bool {
            self.0.push(frame.to_vec());
            true
        }
    }

    /// Mensagem ICMPv6 de um quadro enviado: (cabeçalho Ethernet, IP, mensagem).
    fn sent(frame: &[u8]) -> (Header, ip6::Header, Vec<u8>) {
        let (eh, p) = eth::parse(frame).unwrap();
        assert_eq!(eh.ethertype, eth::ETHERTYPE_IPV6);
        let (h, body) = ip6::parse(p).unwrap();
        assert_eq!(h.next, ip6::PROTO_ICMP6);
        (eh, h, body.to_vec())
    }

    fn frame(src_mac: Mac, dst_mac: Mac, h: &ip6::Header, body: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; 1500];
        let n = ip6::build(h, body, &mut pkt).unwrap();
        let mut out = vec![0u8; 1514];
        let eh = Header {
            dst: dst_mac,
            src: src_mac,
            ethertype: eth::ETHERTYPE_IPV6,
        };
        let len = eth::build(&eh, &pkt[..n], &mut out).unwrap();
        out.truncate(len);
        out
    }

    fn hdr(src: Ip6, dst: Ip6, hop: u8) -> ip6::Header {
        ip6::Header {
            traffic_class: 0,
            flow_label: 0,
            next: ip6::PROTO_ICMP6,
            hop_limit: hop,
            src,
            dst,
            frag: None,
        }
    }

    /// Anúncio de roteador com um prefixo de SLAAC.
    fn ra(hop: u8, lifetime: u16, preferred: u32, valid: u32) -> Vec<u8> {
        let mut m = vec![0u8; 16 + 8 + 32];
        m[0] = 134;
        m[6..8].copy_from_slice(&lifetime.to_be_bytes());
        m[16] = 1;
        m[17] = 1;
        m[18..24].copy_from_slice(&GW.0);
        m[24] = 3;
        m[25] = 4;
        m[26] = 64;
        m[27] = 0xc0;
        m[28..32].copy_from_slice(&valid.to_be_bytes());
        m[32..36].copy_from_slice(&preferred.to_be_bytes());
        m[40..56].copy_from_slice(&PREFIX);
        let dst = ip6::ALL_NODES;
        m[2..4].fill(0);
        let c = crate::ip4::fold(crate::ip4::sum(
            &m,
            ip6::pseudo_sum(&GW_LL, &dst, 58, m.len()),
        ));
        m[2..4].copy_from_slice(&c.to_be_bytes());
        frame(GW, ip6::multicast_mac(&dst), &hdr(GW_LL, dst, hop), &m)
    }

    fn stack() -> Stack {
        let mut s = Stack::new(US);
        s.seed([7; 16]);
        s.start_ipv6();
        s
    }

    /// Leva a pilha até o endereço local do enlace pronto e o RA recebido.
    fn configured(s: &mut Stack, w: &mut Wire) -> u64 {
        s.tick(w, 0);
        s.tick(w, S + 1);
        s.tick(w, 2 * S + 2);
        let f = ra(255, 1800, 3600, 7200);
        s.input(w, &mut NoUpper, &f, 2 * S + 3);
        s.tick(w, 2 * S + 4);
        s.tick(w, 4 * S);
        assert!(s.slaac().global(4 * S).is_some());
        4 * S
    }

    #[test]
    fn dad_e_solicitacao_de_roteador() {
        let mut s = stack();
        let mut w = Wire::default();
        s.tick(&mut w, 0);
        assert_eq!(w.0.len(), 1);
        let (eh, h, m) = sent(&w.0[0]);
        let ll = s.slaac().addrs().next().unwrap().ip;
        assert_eq!(h.src, ip6::UNSPECIFIED);
        assert_eq!(h.dst, ip6::solicited_node(&ll));
        assert_eq!(h.hop_limit, 255);
        assert_eq!(eh.dst, ip6::multicast_mac(&h.dst));
        assert!(
            matches!(icmp6::parse(&h, &m), Some(Msg::NeighborSolicit { target, slla: None }) if target == ll)
        );
        // Em DAD o endereço ainda não vale como origem.
        assert!(s.slaac().link_local(S / 2).is_none());
        w.0.clear();
        s.tick(&mut w, S + 1);
        assert!(s.slaac().link_local(S + 1).is_some());
        // A solicitação de roteador sai dentro de 1 s depois da DAD.
        s.tick(&mut w, 2 * S + 2);
        assert_eq!(w.0.len(), 1);
        let (_, h, m) = sent(&w.0[0]);
        assert_eq!((h.dst, h.src), (ip6::ALL_ROUTERS, ll));
        assert!(matches!(icmp6::parse(&h, &m), Some(Msg::RouterSolicit)));
        // Repete a cada 4 s até 3 vezes.
        w.0.clear();
        s.tick(&mut w, 6 * S + 3);
        s.tick(&mut w, 10 * S + 4);
        s.tick(&mut w, 20 * S);
        assert_eq!(w.0.len(), 2);
    }

    #[test]
    fn anuncio_de_roteador_gera_estavel_e_temporario() {
        let mut s = stack();
        let mut w = Wire::default();
        let t = configured(&mut s, &mut w);
        let kinds: Vec<_> = s.slaac().addrs().map(|a| a.kind).collect();
        assert!(kinds.contains(&Kind::LinkLocal));
        assert!(kinds.contains(&Kind::Stable));
        assert!(kinds.contains(&Kind::Temporary));
        let g = s.slaac().global(t).unwrap();
        assert_eq!(g[..8], PREFIX[..8]);
        // O temporário é o preferido e difere do estável.
        let stable = s
            .slaac()
            .addrs()
            .find(|a| a.kind == Kind::Stable)
            .unwrap()
            .ip;
        assert_ne!(g, stable);
        assert_eq!(s.slaac().router(t), Some(GW_LL));
        // Origem para fora do enlace: global; para o roteador: local do enlace.
        let far: Ip6 = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        assert_eq!(s.slaac().source_for(&far, t), Some(g));
        assert_eq!(s.slaac().source_for(&GW_LL, t), s.slaac().link_local(t));
        assert_eq!(s.slaac().next_hop(&far, t), Some(GW_LL));
        let mut near = PREFIX;
        near[15] = 5;
        assert_eq!(s.slaac().next_hop(&near, t), Some(near));
    }

    #[test]
    fn ra_com_limite_de_saltos_errado_ou_origem_global_e_ignorado() {
        let mut s = stack();
        let mut w = Wire::default();
        s.tick(&mut w, 0);
        s.tick(&mut w, S + 1);
        s.input(&mut w, &mut NoUpper, &ra(64, 1800, 3600, 7200), S + 2);
        s.tick(&mut w, 2 * S);
        assert!(s.slaac().router(2 * S).is_none());
        assert!(s.slaac().global(2 * S).is_none());
    }

    #[test]
    fn ping_ao_roteador_e_resposta() {
        let mut s = stack();
        let mut w = Wire::default();
        let t = configured(&mut s, &mut w);
        w.0.clear();
        // O MAC do roteador veio no anúncio: o eco sai direto.
        s.ping6(&mut w, GW_LL, 0x6e64, 1, b"optimus", t).unwrap();
        assert_eq!(w.0.len(), 1);
        let (eh, h, m) = sent(&w.0[0]);
        assert_eq!((eh.dst, h.dst), (GW, GW_LL));
        let Some(Msg::Echo {
            kind,
            id,
            seq,
            data,
        }) = icmp6::parse(&h, &m)
        else {
            panic!("não é eco");
        };
        assert_eq!(
            (kind, id, seq, data),
            (icmp6::ECHO_REQUEST, 0x6e64, 1, &b"optimus"[..])
        );
        // A resposta vira evento.
        let mut r = vec![0u8; 15];
        icmp6::build_echo(&GW_LL, &h.src, icmp6::ECHO_REPLY, id, seq, data, &mut r).unwrap();
        let f = frame(GW, US, &hdr(GW_LL, h.src, 64), &r);
        assert_eq!(
            s.input(&mut w, &mut NoUpper, &f, t + 1),
            Some(Event::EchoReply6 {
                src: GW_LL,
                id,
                seq,
                len: 7
            })
        );
    }

    #[test]
    fn eco_de_vizinho_resolve_por_solicitacao() {
        let mut s = stack();
        let mut w = Wire::default();
        let t = configured(&mut s, &mut w);
        w.0.clear();
        let mut peer = PREFIX;
        peer[15] = 5;
        // Desconhecido: sai a solicitação ao nó solicitado, com a nossa opção.
        assert_eq!(
            s.ping6(&mut w, peer, 1, 1, b"x", t),
            Err(crate::stack::SendError::Pending)
        );
        let (eh, h, m) = sent(&w.0[0]);
        assert_eq!(h.dst, ip6::solicited_node(&peer));
        assert_eq!(eh.dst, ip6::multicast_mac(&h.dst));
        assert!(
            matches!(icmp6::parse(&h, &m), Some(Msg::NeighborSolicit { target, slla: Some(US) }) if target == peer)
        );
        // O anúncio resolve e o eco passa.
        let mac = Mac([2, 0, 0, 0, 0, 9]);
        let mut na = vec![0u8; 32];
        let n = icmp6::build_na(
            &peer,
            &h.src,
            icmp6::NA_SOLICITED | icmp6::NA_OVERRIDE,
            &peer,
            mac,
            &mut na,
        )
        .unwrap();
        let f = frame(mac, US, &hdr(peer, h.src, 255), &na[..n]);
        s.input(&mut w, &mut NoUpper, &f, t + 1);
        w.0.clear();
        s.ping6(&mut w, peer, 1, 2, b"x", t + 2).unwrap();
        assert_eq!(sent(&w.0[0]).0.dst, mac);
    }

    #[test]
    fn responde_solicitacao_de_vizinho_e_eco() {
        let mut s = stack();
        let mut w = Wire::default();
        let t = configured(&mut s, &mut w);
        let ours = s.slaac().global(t).unwrap();
        let peer: Ip6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
        let pmac = Mac([2, 0, 0, 0, 0, 7]);
        // NS para o nosso endereço.
        let mut ns = vec![0u8; 32];
        let n = icmp6::build_ns(
            &peer,
            &ip6::solicited_node(&ours),
            &ours,
            Some(pmac),
            &mut ns,
        )
        .unwrap();
        let f = frame(
            pmac,
            ip6::multicast_mac(&ip6::solicited_node(&ours)),
            &hdr(peer, ip6::solicited_node(&ours), 255),
            &ns[..n],
        );
        w.0.clear();
        s.input(&mut w, &mut NoUpper, &f, t + 1);
        assert_eq!(w.0.len(), 1);
        let (eh, h, m) = sent(&w.0[0]);
        assert_eq!((eh.dst, h.src, h.dst), (pmac, ours, peer));
        assert!(matches!(
            icmp6::parse(&h, &m),
            Some(Msg::NeighborAdvert { flags, target, tlla: Some(US) })
                if target == ours && flags == icmp6::NA_SOLICITED | icmp6::NA_OVERRIDE
        ));
        // NS com limite de saltos 254 é ignorada.
        w.0.clear();
        let f = frame(
            pmac,
            ip6::multicast_mac(&ip6::solicited_node(&ours)),
            &hdr(peer, ip6::solicited_node(&ours), 254),
            &ns[..n],
        );
        s.input(&mut w, &mut NoUpper, &f, t + 2);
        assert!(w.0.is_empty());
        // NS para outro alvo: sem resposta.
        let mut other = ours;
        other[15] ^= 1;
        let n = icmp6::build_ns(
            &peer,
            &ip6::solicited_node(&other),
            &other,
            Some(pmac),
            &mut ns,
        )
        .unwrap();
        let f = frame(
            pmac,
            ip6::multicast_mac(&ip6::solicited_node(&other)),
            &hdr(peer, ip6::solicited_node(&other), 255),
            &ns[..n],
        );
        s.input(&mut w, &mut NoUpper, &f, t + 3);
        assert!(w.0.is_empty());
        // Eco para nós.
        let mut e = vec![0u8; 12];
        icmp6::build_echo(&peer, &ours, icmp6::ECHO_REQUEST, 9, 3, b"ola!", &mut e).unwrap();
        s.input(
            &mut w,
            &mut NoUpper,
            &frame(pmac, US, &hdr(peer, ours, 64), &e),
            t + 4,
        );
        assert_eq!(w.0.len(), 1);
        let (eh, h, m) = sent(&w.0[0]);
        assert_eq!((eh.dst, h.src, h.dst), (pmac, ours, peer));
        assert!(matches!(
            icmp6::parse(&h, &m),
            Some(Msg::Echo {
                kind: icmp6::ECHO_REPLY,
                id: 9,
                seq: 3,
                ..
            })
        ));
        // Checksum errado: descartado.
        w.0.clear();
        e[10] ^= 1;
        s.input(
            &mut w,
            &mut NoUpper,
            &frame(pmac, US, &hdr(peer, ours, 64), &e),
            t + 5,
        );
        assert!(w.0.is_empty());
    }

    #[test]
    fn dad_com_conflito_remove_o_endereco() {
        let mut s = stack();
        let mut w = Wire::default();
        s.tick(&mut w, 0);
        let ll = s.slaac().addrs().next().unwrap().ip;
        // Outro nó faz DAD do mesmo endereço (origem ::): conflito.
        let mut ns = vec![0u8; 24];
        let n = icmp6::build_ns(
            &ip6::UNSPECIFIED,
            &ip6::solicited_node(&ll),
            &ll,
            None,
            &mut ns,
        )
        .unwrap();
        let other = Mac([2, 0, 0, 0, 0, 8]);
        let f = frame(
            other,
            ip6::multicast_mac(&ip6::solicited_node(&ll)),
            &hdr(ip6::UNSPECIFIED, ip6::solicited_node(&ll), 255),
            &ns[..n],
        );
        s.input(&mut w, &mut NoUpper, &f, S / 2);
        let again = s.slaac().addrs().next().unwrap().ip;
        // Refeito com outro identificador (RFC 7217, DAD_Counter).
        assert_ne!(again, ll);
        assert_eq!(s.slaac().addrs().count(), 1);
    }

    #[test]
    fn temporario_vence_e_e_trocado_no_proximo_anuncio() {
        let mut s = stack();
        let mut w = Wire::default();
        s.tick(&mut w, 0);
        s.tick(&mut w, S + 1);
        s.tick(&mut w, 2 * S + 2);
        let long = ra(255, 1800, 200_000, 400_000);
        s.input(&mut w, &mut NoUpper, &long, 2 * S + 3);
        s.tick(&mut w, 2 * S + 4);
        s.tick(&mut w, 4 * S);
        let t = 4 * S;
        let stable = s
            .slaac()
            .addrs()
            .find(|a| a.kind == Kind::Stable)
            .unwrap()
            .ip;
        let first = s
            .slaac()
            .addrs()
            .find(|a| a.kind == Kind::Temporary)
            .unwrap()
            .ip;
        assert_eq!(s.slaac().global(t), Some(first));
        // Passada a vida preferida máxima do temporário (24 h), a origem é o estável.
        let later = t + 86_401 * S;
        assert_eq!(s.slaac().global(later), Some(stable));
        // O próximo anúncio cria outro temporário, com identificador novo.
        s.input(&mut w, &mut NoUpper, &long, later);
        s.tick(&mut w, later + 1);
        s.tick(&mut w, later + 2 * S);
        let second = s.slaac().global(later + 2 * S).unwrap();
        assert_ne!(second, first);
        assert_ne!(second, stable);
        assert_eq!(
            s.slaac()
                .addrs()
                .filter(|a| a.kind == Kind::Temporary)
                .count(),
            2
        );
    }

    #[test]
    fn ip6_parse_e_extensoes() {
        let h = hdr([1; 16], [2; 16], 7);
        let mut pkt = [0u8; 200];
        let n = ip6::build(&h, b"abcd", &mut pkt).unwrap();
        let (g, body) = ip6::parse(&pkt[..n]).unwrap();
        assert_eq!((g, body), (h, &b"abcd"[..]));
        // Cabeçalho de opções de destino (8 bytes) é pulado.
        let mut ext = vec![58u8, 0, 1, 4, 0, 0, 0, 0];
        ext.extend_from_slice(b"abcd");
        let mut hh = h;
        hh.next = 60;
        let n = ip6::build(&hh, &ext, &mut pkt).unwrap();
        let (g, body) = ip6::parse(&pkt[..n]).unwrap();
        assert_eq!((g.next, body), (58, &b"abcd"[..]));
        // Truncado, versão errada e roteamento ativo caem.
        assert!(ip6::parse(&pkt[..n - 1]).is_none());
        pkt[0] = 0x40;
        assert!(ip6::parse(&pkt[..n]).is_none());
        let mut rt = vec![58u8, 0, 2, 1, 0, 0, 0, 0];
        rt.extend_from_slice(b"abcd");
        hh.next = 43;
        let n = ip6::build(&hh, &rt, &mut pkt).unwrap();
        assert!(ip6::parse(&pkt[..n]).is_none());
        // Pilha de extensões sem fim.
        let mut many = Vec::new();
        for _ in 0..8 {
            many.extend_from_slice(&[60, 0, 1, 4, 0, 0, 0, 0]);
        }
        hh.next = 60;
        let n = ip6::build(&hh, &many, &mut pkt).unwrap();
        assert!(ip6::parse(&pkt[..n]).is_none());
    }

    #[test]
    fn fragmentos_ipv6_remontam() {
        let data: Vec<u8> = (0..40u8).collect();
        let frag = |off: u16, more: bool, part: &[u8]| {
            let mut ext = vec![17u8, 0];
            ext.extend_from_slice(&(off | u16::from(more)).to_be_bytes());
            ext.extend_from_slice(&0xabcd_0001u32.to_be_bytes());
            ext.extend_from_slice(part);
            let mut h = hdr([1; 16], [2; 16], 64);
            h.next = 44;
            let mut pkt = vec![0u8; 100];
            let n = ip6::build(&h, &ext, &mut pkt).unwrap();
            pkt.truncate(n);
            pkt
        };
        let (f2, f1) = (frag(16, false, &data[16..]), frag(0, true, &data[..16]));
        let mut r = Reassembler::new();
        let mut out = [0u8; MAX_DATAGRAM];
        let mut done = None;
        for pkt in [&f2, &f1] {
            let (h, body) = ip6::parse(pkt).unwrap();
            let f = h.frag.unwrap();
            assert_eq!(h.next, 17);
            let key = crate::frag::Key {
                src: h.src,
                dst: h.dst,
                id: f.id,
                proto: h.next,
                v6: true,
            };
            let piece = crate::frag::Piece {
                offset: usize::from(f.offset),
                more: f.more,
            };
            done = r.add_piece(&key, piece, body, 0, &mut out);
        }
        assert_eq!(&out[..done.unwrap()], &data[..]);
        // Fragmento atômico é o pacote inteiro; extensão dentro do fragmento cai.
        let atomic = frag(0, false, &data);
        assert!(ip6::parse(&atomic).unwrap().0.frag.is_none());
        let mut bad = frag(0, true, &data[..8]);
        bad[40] = 60;
        assert!(ip6::parse(&bad).is_none());
    }

    #[test]
    fn enderecos_especiais() {
        let a: Ip6 = [
            0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x12,
        ];
        assert_eq!(ip6::solicited_node(&a)[11..], [1, 0xff, 0xcd, 0xef, 0x12]);
        assert_eq!(
            ip6::multicast_mac(&ip6::ALL_NODES).0,
            [0x33, 0x33, 0, 0, 0, 1]
        );
        assert!(ip6::is_link_local(&GW_LL) && !ip6::is_link_local(&a));
        assert!(ip6::is_multicast(&ip6::ALL_ROUTERS));
        let h = |dst| Header {
            dst,
            src: GW,
            ethertype: 0,
        };
        assert!(eth::for_us(&h(ip6::multicast_mac(&ip6::ALL_NODES)), US));
        // O prefixo "mesmo enlace" respeita bits que não são múltiplos de 8.
        let mut s = Slaac::new(US);
        s.seed([1; 16]);
        s.start();
        assert_eq!(s.poll(0, 0), Some(Tx::Dad(s.addrs().next().unwrap().ip)));
        let p = Prefix {
            prefix: PREFIX,
            len: 60,
            onlink: true,
            autonomous: false,
            valid: 100,
            preferred: 50,
        };
        assert!(s.input_ra(&GW_LL, 100, &[Some(p)], 0, 1));
        let mut inside = PREFIX;
        inside[7] = 0x0f;
        let mut outside = PREFIX;
        outside[7] = 0x10;
        assert!(s.on_link(&inside, 1) && !s.on_link(&outside, 1));
        assert!(!s.on_link(&inside, 101 * S));
    }

    #[test]
    fn nenhum_comprimento_entra_em_panico_no_icmp6() {
        let h = hdr(GW_LL, ip6::ALL_NODES, 255);
        let full = ra(255, 1800, 3600, 7200);
        let body = &full[eth::HEADER_LEN + ip6::HEADER_LEN..];
        for n in 0..body.len() {
            let _ = icmp6::parse(&h, &body[..n]);
        }
        // Opção de tamanho zero: recusada.
        let mut bad = body.to_vec();
        bad[17] = 0;
        let _ = icmp6::parse(&h, &bad);
        for n in 0..70 {
            let mut p = vec![0xffu8; n];
            if n > 0 {
                p[0] = 133 + u8::try_from(n % 4).unwrap();
            }
            let _ = icmp6::parse(&h, &p);
            let _ = ip6::parse(&p);
        }
    }
}
