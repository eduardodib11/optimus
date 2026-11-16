# Âncoras de confiança do `tlsd`

`roots.der` é o conjunto de raízes que o `tlsd` aceita para servidores TLS
(ADR 0071, item 5): certificados DER concatenados, na ordem do arquivo de
origem. `roots.der.sha256` guarda o hash; o `cargo xtask check` confere os
dois e lê todas as raízes com o `ox509`.

## Origem

- Arquivo: `lib/ckfw/builtins/certdata.txt` do NSS, do projeto Mozilla,
  licença MPL-2.0.
- Revisão: `a9939a63e83529fe434c995cb7fd0afb4ab8b4f8` do repositório
  <https://hg.mozilla.org/projects/nss> (2026-11-13, "Bug 2092662").
- SHA-256 do `certdata.txt`:
  `6d177e33ab54b338edfee24dc3868585833636716a320a725137ab4a15927292`.
- Extraído em 2026-11-16 com `tools/mkroots`.

## Critério

Entram os certificados com `CKA_TRUST_SERVER_AUTH` igual a
`CKT_NSS_TRUSTED_DELEGATOR`: **109 raízes**, 114 533 bytes.

Ficam de fora as raízes com `CKA_NSS_SERVER_DISTRUST_AFTER` (a Mozilla deixa
de confiar nelas para certificados emitidos depois de uma data). O `ox509`
não guarda essa data, então falha fechado e não confia nelas:

- Entrust.net Premium 2048 Secure Server CA
- Izenpe.com
- DigiCert Trusted Root G4
- Entrust Root Certification Authority - G2
- Entrust Root Certification Authority - EC1
- emSign Root CA - G1
- Autoridad de Certificacion Firmaprofesional CIF A62634068

As raízes P-384 entram no conjunto, mas a ADR 0071 ainda não aceita essa
curva: o `ox509` as lê como `Unsupported` e nenhum caminho fecha nelas.

## Para atualizar

```sh
curl -sSfL -o certdata.txt \
  https://hg.mozilla.org/projects/nss/raw-file/<revisão>/lib/ckfw/builtins/certdata.txt
cargo run -p mkroots -- certdata.txt data/trust/roots.der
(cd data/trust && sha256sum roots.der > roots.der.sha256)
```

e atualize a revisão, o hash e a lista acima. A troca das raízes muda dois
arquivos versionados e passa pela revisão do PR. O usuário não adiciona
raízes por conta própria no M6.
