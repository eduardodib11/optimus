# ADR 0005: Bootloader próprio optboot como aplicação UEFI, sem BIOS

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 5 e 16.2
- Relaciona-se com: ADR 0003, ADR 0015, ADR 0018

## Contexto

A cadeia de confiança exige que nenhum código não assinado execute entre o
firmware e o primeiro processo (RF-01). O kernel precisa receber mapa de memória,
framebuffer, tabelas ACPI ou DTB e entropia num formato estável. As plataformas
da v1.0 são x86-64 e AArch64, ambas com UEFI.

## Decisão

O `optboot` é uma aplicação UEFI em Rust (alvo `x86_64-unknown-uefi`). Ele:

- é validado pelo Secure Boot do firmware (chave do projeto no `db`);
- escolhe o slot A/B e verifica as assinaturas híbridas do kernel e do bootfs;
- mede kernel, bootfs e linha de comando nos PCRs 8 e 9 do TPM 2.0;
- coleta mapa de memória, GOP, RSDP ou DTB e 64 bytes de entropia;
- aplica KASLR, monta as tabelas de página, chama `ExitBootServices` e salta
  para `kernel_entry(&BootInfo)` com a `BootInfo` v1 versionada.

Não há suporte a BIOS legado nem a Multiboot.

## Alternativas

- **GRUB 2:** maduro e com Secure Boot via shim, mas é código C grande, fala
  Multiboot, não conhece a `BootInfo` nem as assinaturas híbridas.
- **Limine:** simples e moderno, mas é dependência externa no caminho de boot,
  contra a ADR 0003, e traz seu próprio protocolo de entrega.
- **systemd-boot ou EFI stub:** pensados para Linux; o kernel teria de virar
  imagem PE e repetir no próprio kernel a verificação e a medição.
- **Suportar BIOS legado:** dobra o código de boot e não tem Secure Boot, GOP
  nem mapa de memória padronizado.

## Consequências

- Uma única cadeia de verificação e medição, sob controle do projeto.
- Kernel livre de código de firmware: recebe tudo pronto na `BootInfo`.
- Máquinas anteriores a ~2012, sem UEFI, não são suportadas.
- Falhas repetidas trocam de slot ou iniciam o `rescue` (seção 5.5).
