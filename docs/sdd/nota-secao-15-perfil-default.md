# Nota para a próxima revisão do SDD: seção 15 (perfil Default)

O PDF do SDD v1.0 não se edita; esta nota pede a correção na próxima
revisão do documento.

**Seção 15 (perfis de hardware e metas).** O perfil que se chamava
`JARVIS` passa a se chamar `Default`, por decisão do Eduardo (2026-11-04).
Os parâmetros do perfil (8+ núcleos, 32 GiB, GPU 16 GiB ou NPU 40+ TOPS,
metas de latência e de quadro) não mudam, só o nome.

Referências atualizadas no repositório: `--profile` do `cargo xtask`
(`xtask/src/main.rs`), PRD (seção 8 e RNF-05), ADR 0021 e ADR 0041. As
menções a JARVIS como referência de estilo visual e de marca (ADR 0040, ADR
0041 item 5 e relatório do HUD) continuam: são o filme, não o perfil.
