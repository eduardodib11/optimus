# OIDL: gramática (EBNF)

Fonte normativa da gramática do OIDL. A ADR 0033 (seção 1) traz o resumo;
este arquivo é a versão completa que o `oidlc` implementa (T-341). A
semântica (nomes, limites, semver, `@tool` obrigatório) fica para a T-342.

## Léxico

- Espaços e quebras de linha separam tokens. Comentário é `//` até o fim da
  linha.
- `id` = letra ou `_`, seguida de letras, dígitos ou `_` (ASCII).
- `inteiro` = dígitos decimais sem sinal, cabendo em `u64`. Não há
  hexadecimal nem sinal no texto do arquivo.
- `texto` = aspas duplas com escapes `\n`, `\t`, `\"` e `\\`; sem quebra de
  linha dentro. Usado só em `desc`.
- Pontuação: `{ } ( ) < > , ; : = @ .` e a seta `->`.
- Palavras-chave (`package`, `type`, `open`, `enum`, `flags`, `struct`,
  `interface`, `oneway`, `result`, `tool`, `risk`, `desc`) são identificadores
  reconhecidos pela posição. Não podem ser nomes de tipo nem de método:
  `oneway`, `result`, `string`, `vec`, `handle`, `bool`, `u8`…`i64` são
  reservadas em todo nome.

## Sintaxe

```
arquivo     = cabecalho { decl } ;
cabecalho   = "package" caminho "@" inteiro "." inteiro ";" ;
caminho     = id { "." id } ;

decl        = "type" id "=" tipo ";"
            | [ "open" ] "enum" id ":" base "{" variante { "," variante } "}"
            | "flags" id ":" base "{" bit { "," bit } "}"
            | "struct" id "{" campo { "," campo } "}"
            | "interface" id "{" { metodo } "}" ;

base        = "u8" | "u16" | "u32" ;
variante    = id [ "=" inteiro ] ;
bit         = id "=" inteiro ;          (* valor obrigatório *)
campo       = id ":" tipo ;

metodo      = { anotacao } [ "oneway" ] id "(" [ campo { "," campo } ] ")"
              [ "->" "result" "<" tipo_ok "," tipo ">" ] ";" ;
anotacao    = "@" "tool" "(" "risk" "=" risco "," "desc" "=" texto ")" ;
risco       = "R0" | "R1" | "R2" | "R3" | "R4" ;
tipo_ok     = tipo | "(" ")" ;          (* "()" só aqui *)

tipo        = primitivo
            | "string" "<" inteiro ">"
            | "vec" "<" tipo "," inteiro ">"
            | "handle" "<" caminho ">"
            | caminho ;
primitivo   = "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" | "bool" ;
```

## Regras que o parser aplica

- O tipo-base de `enum` e `flags` é `u8`, `u16` ou `u32`.
- Todo bit de `flags` tem valor explícito.
- `()` só vale como sucesso de `result`.
- `oneway` não leva `->`.
- Uma anotação `@` que não seja `@tool` é erro.
- Os números de versão cabem em `u32`.

## Regras que ficam para a análise semântica (T-342)

- Método fora de `oneway` sem `->` (a ADR exige `-> result<T, E>`).
- Nomes não resolvidos, duplicados ou de pacote não importado.
- `string<N>` e `vec<T, N>` com N zero ou maior que o limite do transporte.
- `@tool` obrigatório em método exposto à IA e risco R0 a R4.
- Compatibilidade semver entre duas versões do mesmo pacote.

## Erros

Todo erro sai como `linha:coluna: erro: mensagem`, com linha e coluna a
partir de 1. A coluna conta caracteres Unicode. Os casos dourados estão em
`tools/oidlc/tests/golden/`.
