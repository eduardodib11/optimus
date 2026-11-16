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
        assert!(p.reserve(FIRST) == false);
    }
}
