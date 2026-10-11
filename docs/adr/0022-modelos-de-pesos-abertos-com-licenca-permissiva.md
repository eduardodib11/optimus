# ADR 0022: Modelos só de pesos abertos com licença Apache-2.0 ou MIT

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 12.13 e 14.5
- Relaciona-se com: ADR 0021 (oie), ADR 0024 (licença do projeto),
  ADR 0018 (assinaturas)

## Contexto

O sistema distribui modelos de IA junto com a imagem e pelo canal de
atualização. Muitos modelos de "pesos abertos" vêm com licenças próprias que
restringem uso, escala, campo de aplicação ou exigem nome e aceite de política.
Redistribuir esses pesos num sistema operacional cria risco jurídico para o
projeto e para quem o empacota. Modelos fechados não podem ser auditados nem
rodar offline.

## Decisão

- Só entram na imagem modelos com pesos publicados sob Apache-2.0 ou MIT.
- A escolha de cada modelo (roteador, planejador, leitor, voz) acontece no
  release, por benchmark próprio de qualidade, latência e memória por perfil.
- Cada `.omdl` traz licença, hash, arquitetura, quantização, avaliações e RAM
  mínima, e é assinado (ADR 0018).
- A lista de modelos aprovados é revisada a cada release.

## Alternativas

- **Llama Community License e similares:** modelos fortes, mas com limite de
  usuários ativos, política de uso aceitável e exigências de marca; não são
  licenças abertas e não combinam com a Apache-2.0 do projeto.
- **Licenças não comerciais (CC-BY-NC e afins):** impedem uso comercial do
  sistema por terceiros.
- **Fixar um modelo no SDD:** simples, mas fica obsoleto antes da v1.0.
- **Depender de API de nuvem:** sem pesos para auditar, sem uso offline e com
  envio de dados para fora; fica só como opção desligada por padrão (12.14).

## Consequências

- Alguns dos melhores modelos ficam de fora; a qualidade depende do que
  existe sob licença permissiva na época do release.
- O usuário pode instalar outros modelos por conta própria, fora da imagem.
- Cada release precisa de rodada de avaliação e revisão de licenças.
