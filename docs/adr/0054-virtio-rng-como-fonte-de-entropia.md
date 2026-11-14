# ADR 0054: virtio-rng como fonte de entropia

- Status: proposta (aguarda a revisão do Eduardo; T-504)
- Data: 2026-11-14
- Origem: SDD v1.0, seções 5.1 (passo 5), 13.3 e 13.5; pendência do M4 (`docs/aceite/m4.md`); backlog do M5, T-504
- Relaciona-se com: ADR 0039 (item 4, aleatoriedade), 0042, 0046 (virtio), 0053 (chaves)

## Contexto

Hoje a entropia chega assim:

- O SDD 13.3 diz que o CSPRNG do kernel é semeado por RDSEED, TPM e jitter.
- A ADR 0039 implementou o DRBG do kernel (`krand`) a partir de `BootInfo.rng_seed`, que vem de EFI_RNG mais RDSEED ou RDRAND.
- O kernel entrega 24 bytes por `sys_info(5)` a qualquer processo.
- Não há syscall para somar entropia ao kernel, e a ABI v1 está congelada em 34.

A T-414 trouxe o driver `virtio-rng`. Ele lê e confere os bytes, mas não os entrega a ninguém.

O M5 passa a criar chaves de longo prazo (ADR 0053), que valem por anos. Uma segunda fonte reduz o risco de uma semente fraca na hora em que mais importa.

Numa VM, o EFI_RNG do OVMF muitas vezes já vem do próprio virtio-rng (driver `VirtioRngDxe`). Nesse caso o dispositivo já alimenta a semente do kernel no boot, mas não depois dele.

## Decisão

1. **O kernel continua a fonte primária e obrigatória.** Esta ADR não muda o `krand` nem a ABI. Sem entropia do kernel (`sys_info(5)` devolve `NotSupported`), o `keyd` não cria chaves nem volumes, mesmo com virtio-rng. Uma fonte controlada pelo hipervisor não basta sozinha. Desbloquear um volume existente não precisa de aleatoriedade e continua possível.
2. **O virtio-rng é fonte secundária só do `keyd`.** O driver expõe a interface OIDL `EntropySource` em `optimus.dev`:

   ```
   enum RngError : u8 { Failed, Busy }
   interface EntropySource {
       read(len: u8) -> result<vec<u8, 64>, RngError>;
   }
   ```

   O `svcmgr` entrega a capability só ao `keyd`, pelo manifesto.
3. **Teste de saúde no driver.** Além da conferência que já faz na partida, o driver aplica um teste de repetição simplificado (NIST SP 800-90B, 4.4.1). Se um bloco de 64 bytes for igual ao anterior, ou tiver todos os bytes iguais, o driver devolve `Failed` dali em diante, até reiniciar, e registra `virtio-rng: teste de saúde falhou`.
4. **Gerador do `keyd`** (é a "semente do sistema" do backlog):
   - O gerador é ChaCha20 com apagamento rápido de chave: a cada saída, os primeiros 32 bytes viram a chave seguinte. É o CSPRNG que o SDD 13.3 cita.
   - Na partida, e antes de cada segredo de longo prazo (K_mestra, chave de recuperação, sais de keyslot), o `keyd` mistura `semente = HKDF-Extract(sal = "optimus/keyd/semente/v1", IKM = kernel ‖ virtio ‖ chave atual)`.
   - `kernel` são 72 bytes de três chamadas a `sys_info(5)`.
   - `virtio` são 64 bytes do `EntropySource`, se ele responder em até 100 ms. Senão o campo fica vazio.
5. **Sem o dispositivo**, ou com ele em `Failed`, o `keyd` segue só com o kernel e registra uma vez `keyd: sem virtio-rng; semente só do kernel`, em nível `info`, porque não é erro.
6. **Nada de segredo no log.** Só a imagem de teste (`xtask test`, recurso `teste`) registra impressões digitais de 64 bits (BLAKE3 truncado) da contribuição virtio e da semente: `keyd: contribuição virtio=…` e `keyd: semente=…`. A imagem normal não registra nada disso.
7. **Aceite da T-518.** Este texto substitui o do backlog.
   - Com o QEMU usando `-object rng-random,filename=<arquivo fixo>`, dois boots mostram a mesma contribuição virtio e sementes diferentes. Isso prova que o dispositivo soma e não substitui.
   - Sem o dispositivo, o `keyd` parte e registra a ausência.
   - Com um arquivo de zeros, o driver marca `Failed` e o `keyd` segue só com o kernel.

   O texto antigo ("dois boots com a mesma semente do QEMU geram a mesma sequência") só seria verdade se o virtio substituísse o kernel. Isso contraria o item 1 e o próprio backlog ("sem trocar a fonte do kernel").

## Alternativas consideradas

- **Syscall ou objeto para injetar entropia no DRBG do kernel:** muda a ABI v1 e dá a quem tiver a capability influência sobre o DRBG do kernel. Rejeitada.
- **Usar o virtio-rng como semente única quando o kernel não tem fonte:** o hipervisor controlaria as chaves. Rejeitada.
- **Um serviço `entropyd` que distribui a todos:** seria mais um processo na TCB. Os usos que não são chaves já têm o kernel pelo `ostd::rand` (ADR 0039). Rejeitada para o M5.
- **Só o caminho do firmware (EFI_RNG pelo `VirtioRngDxe`):** já acontece no boot quando o OVMF tem o driver, mas não ajuda depois do boot nem com firmware sem ele. É complementar, não substituto.

## Consequências

- O kernel não muda. O `virtio-rng` ganha a interface `EntropySource`, que entra no lote da T-514.
- A T-518 passa a depender também de T-526 (HKDF) e T-535 (ChaCha20), além de T-504 e T-414.
- Toda chave de volume nasce com duas fontes quando há virtio-rng, e com uma (a do kernel) quando não há.
- Qualquer mudança no que está acima exige ADR nova.
