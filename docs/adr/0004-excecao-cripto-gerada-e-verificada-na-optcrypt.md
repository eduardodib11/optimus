# ADR 0004: Exceção: cripto gerada e formalmente verificada na optcrypt

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 13.3, 16.1 e 18
- Relaciona-se com: ADR 0003, ADR 0017, ADR 0018

## Contexto

A ADR 0003 proíbe código não escrito à mão na imagem. Primitivas criptográficas,
porém, são a maior fonte de falhas sutis: aritmética de corpo finito errada em
casos raros, vazamento por tempo de execução, redução modular incompleta. Essas
falhas passam em testes comuns. O sistema depende de Ed25519, ML-DSA-65, X25519,
ML-KEM-768, AES-256-GCM, ChaCha20-Poly1305, SHA-2 e BLAKE3 (seção 13.3).

## Decisão

As primitivas criptográficas vêm de código gerado e formalmente verificado, no
estilo fiat-crypto (aritmética de corpo gerada com prova em Coq) e HACL*
(implementações provadas em F*), adaptado para a crate `lib/optcrypt`.

A adaptação se limita a integrar o código ao estilo do projeto (tipos, erros,
`no_std`), sem alterar a lógica provada. Protocolos, composição e APIs acima das
primitivas são escritos à mão. Toda implementação passa nos vetores Wycheproof e
NIST e em testes de tempo constante (dudect) no CI, com cobertura ≥ 80%.

## Alternativas

- **Escrever as primitivas à mão:** cumpriria a ADR 0003 ao pé da letra, mas
  repetiria erros históricos conhecidos de bibliotecas caseiras.
- **Usar crates prontas** (RustCrypto, `ring`, `aws-lc-rs`): bem testadas, mas
  sem prova formal na maior parte e com dependências e código C/assembly que
  violariam a ADR 0003 sem ganho de garantia.
- **Vincular a uma biblioteca C** (OpenSSL, BoringSSL, libsodium): traz libc e
  código C para a imagem, contra as ADRs 0002 e 0003.

## Consequências

- Correção funcional e tempo constante das primitivas sustentados por prova, não
  só por teste.
- É a única porta para código não escrito à mão na imagem; qualquer outra
  exceção exige ADR nova.
- Mudanças na `optcrypt` exigem revisão dedicada do responsável de segurança.
- Atualizar uma primitiva significa regerar e readaptar o código verificado.
- Provisório: até chegar o código verificado, a `optcrypt` usa o BLAKE3 de
  referência escrito à mão (M3). A substituição é obrigatória antes da
  primeira imagem distribuída.

## Revisão de 2026-10-20

Mudanças em relação ao texto anterior:

- Registrado que a `optcrypt` usa hoje um BLAKE3 de referência escrito à mão,
-   como solução provisória, a ser substituída por código verificado.
