# ADR 0069: Pilha IP do `netd`: escopo e faseamento do M6

- Status: aceita (modo autônomo de Eduardo, 2026-11-16), aguardando a revisão dele
- Data: 2026-11-16
- Origem: backlog do M6, T-603 (SDD v1.0, seções 8.2, 10.1, 10.2 e 19)
- Relaciona-se com: ADR 0017 (pilha própria), 0046 e 0064 (virtio-net, `NetDevice`), 0068 (contrato do `netd`)

## Contexto

A seção 10.1 do SDD lista mais do que cabe num marco: Ethernet, ARP, VLAN, Wi-Fi, IPv4, IPv6, ICMP, DHCPv4, DHCPv6, SLAAC, TCP com CUBIC e BBR, UDP, QUIC, DNS com DoH, DoT e DNSSEC. A tabela 8.2 põe os drivers de rede reais (Intel e1000e/i219, Realtek, Wi-Fi) no M12 e o QUIC no M14. No M6 só existe o `virtio-net` (M4) e o QEMU com rede de usuário (*slirp*), que serve DHCP, DNS e roteador.

## Decisão

O M6 entrega o que se testa de ponta a ponta no QEMU, na ordem abaixo. O que sai do M6 fica registrado com o marco que o recebe.

1. **Entra no M6.** Ethernet, ARP; IPv4 e ICMP; DHCPv4; UDP; TCP completo (máquina de estados, retransmissão por RTO e RACK simplificado, janela escalável, SACK, timestamps, CUBIC como padrão); IPv6 com ND, ICMPv6 e SLAAC com endereços temporários de privacidade; DNS próprio (UDP, retorno por TCP, cache com TTL e cache negativo); firewall (ADR 0068); DoT pelo `tlsd` (ADR 0070).
2. **Entra no M6, depois dos itens acima, se o tempo permitir.** DoH, por um cliente HTTP/1.1 mínimo, e DNSSEC (reutiliza as verificações de assinatura da ADR 0071). Podem escorregar para o M8, onde o `ai-exec` já precisa de HTTP.
3. **Fora do M6.** Wi-Fi e `wland` (M12, com o driver Intel; o QEMU não emula Wi-Fi); drivers e1000e, i219 e RTL8125 (M12); QUIC (M14); VLAN, BBR, multi-fila com RSS e DHCPv6 com prefixo delegado (perfil Server, M16). SLAAC cobre o IPv6 no cliente.
4. **Sem fragmentação de saída.** O TCP usa MSS e descoberta de MTU de caminho; UDP maior que o MTU é recusado. Na entrada, a remontagem IPv4 e IPv6 é limitada (cota, tempo, poucos fragmentos) e sob fuzzing.
5. **Um `netd` por máquina, um laço por interface.** Uma thread de protocolo (relógio de TCP por temporizador do `timed`, ADR 0035) e uma por interface no M6; multi-fila fica para o Server.
6. **Entradas externas são hostis.** Todo parser (quadro, IPv4/6, TCP, ICMP, DHCP, DNS, ND) tem alvo de fuzzing (SDD 8.3) e é escrito em Rust seguro; sem `unsafe` no `netd` fora de `ostd`.
7. **Aleatoriedade.** Números de sequência iniciais, portas efêmeras e IDs de DNS vêm do `keyd` (ADR 0054), nunca do relógio.
   Nota (T-634, 2026-11-16): o `keyd` não serve bytes aleatórios (ADR 0054 rejeitou um serviço que distribua entropia a todos; só guarda chaves), então o `netd` sorteia direto do DRBG do kernel por `ostd::rand::secure_fill` (ADR 0039), a mesma fonte que semeia o `keyd`. O requisito se mantém: nada de relógio.
8. **Medição.** `cargo xtask bench-net` mede latência de ida e volta e vazão TCP no QEMU com gate de 5 % sobre contagens determinísticas (pacotes, retransmissões, cópias), como o `bench-io` (T-532). Vazão em Mbit/s é só informativa no QEMU.

## Alternativas consideradas

- Pilha de terceiros portada (smoltcp e similares): proibida na imagem pela ADR 0003.
- Fazer IPv6 só no Server: o SDD pede IPv6 no cliente, e o slirp o suporta; rejeitada.
- Esperar o driver real para testar o TCP: sem como medir; o QEMU basta para correção e a medição de desempenho real vem no M12.

## Consequências

- O aceite do M6 é de correção e de isolamento, não de desempenho em hardware real.
- O que foi adiado volta nos backlogs de M8, M12, M14 e M16.
- Qualquer mudança no que está acima exige ADR nova.
