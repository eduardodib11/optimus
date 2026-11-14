# ADR 0053: Criptografia de volume e chaves

- Status: proposta (aguarda a revisão do Eduardo; nenhum código de criptografia antes do aceite; T-503)
- Data: 2026-11-14
- Origem: SDD v1.0, seções 5.3, 5.4, 9.3, 13.2, 13.3 e 13.5; backlog do M5, T-503
- Relaciona-se com: ADR 0004 (`optcrypt`), 0014 (OptFS), 0038 (`memd`), 0039 (aleatoriedade), 0052 (layout), 0054 (entropia)

## Contexto

O SDD fixa o essencial:

- AES-256-GCM por bloco, ou ChaCha20-Poly1305 em CPUs sem AES-NI, com nonce de 96 bits no ponteiro.
- Chave-mestra do volume via `keyd`, e chaves por usuário e por app derivadas por HKDF-SHA-256.
- Com TPM, a chave é selada aos PCRs 0, 7, 8 e 9. Sem TPM, ela deriva de senha por Argon2id (Lite: 64 MiB e 3 iterações).
- O `keyd` está no bootfs e na TCB (seções 5.3 e 13).

Ficam em aberto cinco pontos:

1. Como garantir que um nonce nunca se repete. Com AEAD de nonce de 96 bits, a repetição sob a mesma chave quebra tudo: revela o XOR dos textos e permite forjar tags.
2. O formato do cabeçalho.
3. Quem guarda cada chave.
4. Como desbloquear no M5, já que o TPM só chega no M10 e o trusted path do `displayd` no M7.
5. O que acontece quando a chave se perde, e o que a `optcrypt` precisa provar.

## Decisão

### 1. Algoritmos

- **AEAD por volume**, escolhido na criação e gravado no cabeçalho: AES-256-GCM se a CPU tem AES-NI e PCLMULQDQ, senão ChaCha20-Poly1305 (SDD 9.3). Nunca AES em software, que não tem tempo constante sem bitslicing. O volume fica com o algoritmo para sempre, e trocar exige recifrar tudo, o que está fora do M5.
- Derivação por HKDF-SHA-256. MAC do cabeçalho e do superbloco por HMAC-SHA-256. Senha por Argon2id (RFC 9106). Tudo conforme o SDD 13.3.
- **Ordem no M5:** ChaCha20-Poly1305 primeiro, porque roda em qualquer CPU, inclusive no Lite e no QEMU TCG. AES-256-GCM vem numa tarefa própria (T-534, item 8). Até a T-534, o `keyd` cria volumes com ChaCha20-Poly1305 mesmo com AES-NI, e o cabeçalho registra isso.

### 2. Hierarquia de chaves

- **K_mestra:** 256 bits aleatórios do gerador do `keyd` (ADR 0054), criados com o volume. Nunca sai do `keyd`, nunca vai ao disco em claro e nunca aparece no log.
- **PRK** = HKDF-Extract(sal = UUID do volume, IKM = K_mestra). Dela saem, por HKDF-Expand com rótulos `optimus/optfs/v1/…`:
  - **K_cab**: HMAC do cabeçalho e dos superblocos.
  - **K_meta**: nós das árvores.
  - **K_nome**: hash dos nomes de diretório (ADR 0052, item 3).
  - **K_ds(id)**: dados de cada dataset. A chave por usuário e por app do SDD é a K_ds do dataset do usuário ou do app. O M5 tem um dataset só.
- O `keyd` entrega ao `optfs` só K_cab, K_meta, K_nome e as K_ds dos datasets que ele pode abrir. A K_mestra fica no `keyd`. É isso que deixa trancar um usuário depois, sem mudar o formato.
- **Época.** A cada montagem, o `optfs` cria uma época `e` (o número seguinte, `u32`) com um sal `s` de 32 bytes de `ostd::rand::secure_fill`. A chave de bloco é `K_x,e = HKDF-Expand(K_x, "época" ‖ e ‖ s)`. A época entra na árvore de épocas (ADR 0052) no primeiro txg que a usa.
- **Nonce** (96 bits no ponteiro) = `e` (`u32`) ‖ `c` (`u64`), em que `c` é um contador em memória da época, que cresce a cada bloco cifrado.
- **Por que o nonce não se repete:**
  - Dentro de uma época, `c` não volta.
  - Entre épocas, a chave muda porque `s` é aleatório.
  - Uma queda antes de gravar a época pode reusar o número `e`, mas com outro `s`, e portanto outra chave.
  - O mesmo vale se alguém restaura uma cópia antiga do disco.
  - A unicidade não depende de gravar um contador nem de o disco ser honesto.
- **AAD de cada bloco** = UUID ‖ endereço ‖ nascimento ‖ id do dataset (0 nos metadados) ‖ tipo. Mover um bloco para outro endereço, ou reaproveitar um bloco antigo, falha na tag.

### 3. Cabeçalho do volume e keyslots

O cabeçalho fica no bloco 0 e no último bloco (ADR 0052). Ele tem `magic` `OPTFSVH1`, versão, UUID aleatório de 128 bits, algoritmo AEAD, modo de integridade, até 8 keyslots e um HMAC-SHA-256 com K_cab sobre tudo. O HMAC é conferido logo depois do desbloqueio, e se falhar o volume não monta.

Cada keyslot tem tipo, parâmetros, sal de 32 bytes, nonce de 12 bytes e a K_mestra embrulhada (32 bytes e tag de 16) pelo AEAD do volume com a KEK do slot. O AAD é UUID ‖ índice ‖ tipo ‖ parâmetros, então alterar os parâmetros invalida o slot.

| Tipo | KEK | Observação |
|---|---|---|
| 1 senha | Argon2id(senha, sal, m, t, p = 1) | Lite: m = 64 MiB, t = 3 (SDD 5.4); demais perfis: m = 256 MiB, t = 3 |
| 2 recuperação | HKDF(chave de recuperação, sal, `recuperação`) | chave de 256 bits aleatória, mostrada uma vez na criação em base32 (52 caracteres em grupos de 4) |
| 3 TPM | selada aos PCRs 0, 7, 8 e 9 | reservado. Chega no M10, com ADR própria se o SDD não bastar |

- O `keyd` recusa slot com `m` acima de 1 GiB ou `t` acima de 10. Assim um cabeçalho adulterado não esgota a memória nem trava o `keyd`.
- Um disco criado num perfil maior e levado ao Lite pode pedir uma nova senha, com outro embrulho.
- Trocar a senha é gravar um slot novo e apagar o antigo, sem recifrar dados.

### 4. Desbloqueio no boot (M5)

1. O `optfs` lê o cabeçalho e chama `keyd.unlock(cabeçalho)`.
2. O `keyd` confere os limites, pede a senha no console e tenta os slots de senha. Se o usuário pedir, aceita a chave de recuperação. No M5 o console é a entrada do `virtio-console`, por isso a T-527 depende da T-514.
3. Senha errada dobra a espera a partir de 1 s, até 60 s. Isso vale contra quem está no teclado. Contra a força bruta offline, quem protege é o Argon2id.
4. Com a senha certa, o `keyd` confere o HMAC do cabeçalho, deriva as chaves e as entrega ao `optfs`, que monta.
5. **No CI** o `xtask` digita a senha de teste no `chardev` do console. A imagem não tem chave de teste nem atalho.

Se o desbloqueio falha, o `optfs` não monta, o `svcmgr` segue com o volume trancado e o modo de resgate continua disponível (SDD, princípio 7).

O pedido de senha passa ao trusted path do `displayd` no M7 (SDD 11), com ADR própria. Com o TPM (M10), o slot 3 desbloqueia sem senha quando os PCRs conferem.

### 5. Perda de chave

Não há nuvem, custódia, chave escondida nem recuperação pelo projeto. Quem perde a senha **e** a chave de recuperação (e o TPM, a partir do M10) perde os dados para sempre.

Na criação, o `keyd` diz isso em linguagem clara e pede que o usuário digite de volta um grupo da chave de recuperação. Isso é uma propriedade, não uma falha: é a mesma garantia que protege o disco roubado (SDD 13.2).

### 6. Higiene de segredos

- Chaves só ficam em memória de objetos que não são `LAZY` (ADR 0038). O `memd` nunca comprime nem despeja essa memória.
- Os tipos de segredo da `optcrypt` não implementam `Debug`, `Display` nem `Clone`, e são zerados no `Drop`. O zeramento escreve zeros e chama `compiler_fence` e `black_box`, sem `unsafe`. Se a revisão da T-526 mostrar que o compilador elimina essas escritas, a `optcrypt` entra na `unsafe-allowlist.toml` para um único `write_volatile`, pela regra da ADR 0039.
- Chaves só viajam por IPC do `keyd` ao `optfs`, e o buffer de IPC é zerado depois. Nenhuma chave vai ao log.
- O `keyd` e o `optfs` se recusam a iniciar se `ostd::rand::is_degraded()` (ADR 0039).

### 7. Propriedades verificáveis da `optcrypt` (aceite da T-503)

| # | Propriedade | Verificação |
|---|---|---|
| P1 | ChaCha20-Poly1305 correto | vetores da RFC 8439 e Wycheproof |
| P2 | AES-256-GCM correto | vetores GCM do NIST CAVP e Wycheproof |
| P3 | SHA-256, HMAC-SHA-256 e HKDF corretos | NIST CAVP (curtas, longas e Monte Carlo), RFC 4231, RFC 5869 |
| P4 | Argon2id e BLAKE2b corretos | RFC 9106 e RFC 7693 |
| P5 | Tempo constante | dudect no CI para selar e abrir AEAD, comparar tags, conferir HMAC e para a passada independente de dados do Argon2id |
| P6 | Sem texto claro com tag inválida | teste que inverte cada byte da tag: a abertura falha e a saída fica zerada |
| P7 | Nonce não vem do chamador | a API de bloco recebe a chave de época e gera o contador. Um teste de propriedade mostra que dois selos da mesma época nunca usam o mesmo contador |
| P8 | Segredo não vaza por formatação | teste de compilação que falha ao pedir `Debug` de um segredo |
| P9 | Origem verificada | ChaCha20, Poly1305, SHA-256, HMAC, HKDF, BLAKE2b e AES-GCM adaptados de código verificado (estilo HACL* e libcrux), conforme a ADR 0004. O Argon2id é composição escrita à mão sobre o BLAKE2b verificado, o que a ADR 0004 permite |
| P10 | Cobertura | ≥ 80% (ADR 0004) |

### 8. Mudanças no backlog

A T-526 não cabe em um PR de 400 linhas. Ela se divide em:

| Tarefa | Conteúdo | Propriedades | Modelo |
|---|---|---|---|
| T-526 | SHA-256, HMAC e HKDF | P3, P5, P8 a P10 | Opus/high |
| T-535 | ChaCha20-Poly1305 e a API de bloco com época | P1, P5 a P7 | Opus/high |
| T-536 | BLAKE2b e Argon2id | P4, P5 | Sonnet/high |
| T-534 | AES-256-GCM com AES-NI e PCLMULQDQ, por intrinsics de `core::arch` em `lib/optcrypt/src/arch/x86_64/`, com entrada e orçamento na `unsafe-allowlist.toml` | P2, P5 | Opus/high |

As dependências mudam assim: a T-527 passa a depender de T-514 (entrada do console), T-526 e T-536; a T-528 depende de T-535.

## Alternativas consideradas

- **Nonce aleatório de 96 bits por bloco:** o limite de aniversário dá cerca de 2³² blocos por chave (NIST SP 800-38D), e um volume grava isso ao longo da vida. Rejeitada.
- **Só um contador gravado, sem sal:** uma queda ou um disco restaurado repete o nonce com outro texto, e a quebra é total. Rejeitada.
- **XChaCha20-Poly1305 ou AES-GCM-SIV:** resolvem com nonce aleatório, mas não estão no SDD 13.3 e pediriam nonce de 24 bytes no ponteiro. Exigiria mudar o SDD.
- **Disco inteiro sem autenticação (XTS, estilo LUKS):** não tem integridade por bloco. A ADR 0014 já rejeitou.
- **Recuperação por nuvem ou conta:** contraria o local por padrão e cria uma chave escondida.
- **Senha como chave-mestra direta:** trocar a senha obrigaria a recifrar tudo, e não haveria vários protetores.

## Consequências

- Cada montagem grava uma época de 36 bytes.
- A K_mestra nunca sai do `keyd`, e trancar por usuário fica possível depois, sem mudar o formato.
- Segredo perdido é dado perdido, de propósito. A interface (M7) precisa deixar isso claro.
- O M5 ganha três tarefas (T-534 a T-536) com a divisão da T-526.
- **Risco aceito até o M10:** quem restaura o disco inteiro a uma cópia antiga (rollback do volume todo) não é detectado. Isso exige o contador monotônico do TPM. Fica registrado como os riscos do SDD 13.5.
- Sem a chave dá para ler o cabeçalho e o superbloco (txg, tamanhos, contagens). Conteúdo, nomes e estrutura das árvores não.
- Qualquer mudança no que está acima exige ADR nova.
