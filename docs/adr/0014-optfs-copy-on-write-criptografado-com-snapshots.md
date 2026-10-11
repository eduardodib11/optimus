# ADR 0014: OptFS copy-on-write, com criptografia autenticada e snapshots

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 5.4, 9 e 13.3
- Relaciona-se com: ADR 0004 (cripto verificada), ADR 0011, ADR 0015

## Contexto

O volume de dados guarda arquivos do usuário, apps, modelos e memória da IA.
Ele precisa sobreviver a corte de energia, detectar adulteração de blocos,
proteger os dados se o disco for roubado e permitir desfazer mudanças da IA e
atualizações. A ADR 0003 exige código próprio, sem portar sistemas existentes.

## Decisão

- Copy-on-write com árvore B+ de extents: nada é sobrescrito no lugar.
- Integridade: cada ponteiro de bloco guarda o tag de autenticação do filho,
  formando uma árvore autenticada até o superbloco.
- Criptografia por bloco com AES-256-GCM, ou ChaCha20-Poly1305 em CPUs sem
  AES-NI; nonce de 96 bits no ponteiro. Chaves: mestra do volume (via `keyd`),
  por usuário e por app, derivadas por HKDF-SHA-256.
- Snapshots instantâneos antes de mudanças da IA e de atualizações.
- Compressão LZ4 por padrão e zstd nível 3 para arquivos frios; cotas por realm.
- Dois superblocos rotativos com contador de transação; `optfs-check` no resgate.
- Um processo `optfs` por volume. A imagem de sistema usa o mesmo formato em
  modo somente leitura, com árvore de Merkle (ADR 0015).

## Alternativas

- **ext4 com fscrypt e dm-integrity:** maduro, mas journaling não dá snapshots
  baratos e a integridade fica em camada separada.
- **btrfs ou ZFS:** têm CoW, checksums e snapshots, mas são grandes, ligados aos
  seus kernels, e o checksum não é autenticado com chave; ZFS tem licença CDDL.
- **FAT ou sistema simples com criptografia de disco inteiro (estilo LUKS):**
  pequeno, mas sem integridade por bloco, sem snapshots e com uma chave só.

## Consequências

- Corte de energia não corrompe o volume, e bloco adulterado vira erro, não dado.
- Chaves por usuário e por app limitam o que um processo tomado consegue ler.
- Escrever um FS CoW autenticado é um marco grande (M5) e exige fuzzing e testes
  de queda de energia.
- Fragmentação e amplificação de escrita do CoW precisam de medição e limpeza.
