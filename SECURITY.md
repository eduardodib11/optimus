# Política de segurança

## Como reportar

Não abra issue pública para falhas de segurança. Use o
[reporte privado de vulnerabilidades do GitHub](https://github.com/eduardodib11/optimus/security/advisories/new)
deste repositório.

Inclua a versão ou commit afetado, os passos para reproduzir e o impacto esperado.

## Compromissos

- Confirmação do recebimento em até 3 dias úteis.
- Correção de falhas críticas em até 30 dias.
- Aviso público e CVE quando a correção for publicada.

## Escopo

A base de confiança (TCB) é `optboot`, `okernel`, `root`, `svcmgr`, `keyd`,
`policyd`, `displayd` (trusted path) e `updated`. Falhas nesses componentes, na
cadeia de atualização, em cripto ou que permitam à IA executar ação R3 sem
confirmação física ou qualquer ação R4 têm prioridade máxima.
