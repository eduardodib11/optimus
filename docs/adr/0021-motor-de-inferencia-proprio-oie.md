# ADR 0021: Motor de inferência próprio oie, GGUF e gramática

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 9, 12.12, 12.13 e 14.5
- Relaciona-se com: ADR 0003 (tudo do zero), ADR 0019 (separação da IA),
  ADR 0020 (OPS), ADR 0022 (licença dos modelos)

## Contexto

A IA roda localmente, do perfil Lite (512 MiB) ao Premium. A ADR 0003 proíbe
dependências externas na imagem, e o motor de inferência é um processo isolado
que lê arquivos de modelo vindos de fora. Ele precisa de memória previsível,
carga sem cópia e saída sempre válida para OPS e JSON.

## Decisão

- O `oie` é um motor próprio em Rust, em espaço de usuário, sem capability de
  rede nem de ação.
- Formato GGUF, empacotado em `.omdl` assinado; quantização Q4_K, Q5_K, Q8_0,
  F16 e BF16, com Q4 como padrão dos perfis.
- Pesos mapeados do disco sem cópia via `MemoryObject`; cache KV paginado e
  quantizado em 8 bits; cache de prefixo para o prompt do sistema.
- Kernels SIMD de SSE2 a AMX, NEON e SVE; backend GPU Intel Xe no M12.
- Decodificação restrita por gramática (OPS, JSON Schema) nas chamadas de
  ferramenta, garantindo saída sintaticamente válida.

## Alternativas

- **llama.cpp como dependência:** maduro e rápido, mas é C/C++ grande, fora do
  Rust e da auditoria, e quebra a ADR 0003. Serve de referência de desempenho.
- **ONNX Runtime ou similar:** pesado, com muitas dependências e pouco controle
  sobre memória e quantização.
- **Formato próprio de pesos:** mais controle, mas isola o projeto dos modelos
  já publicados; GGUF é aberto e amplamente usado.
- **Só nuvem:** sem custo local, mas tira a privacidade e o uso offline.

## Consequências

- O `oie` vira parte grande do código; o parser GGUF exige fuzzing.
- Sem GPU até o M12, perfis JARVIS e Premium ficam mais lentos.
- A gramática elimina saída inválida, mas não erro de conteúdo do plano.
