# ADR 0024: Licença Apache-2.0 com DCO

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 17.2 e 20 (T-001)
- Relaciona-se com: ADR 0003 (tudo do zero), ADR 0022 (licença dos modelos)

## Contexto

O Optimus OS é escrito do zero e quer ser usado por fabricantes, empresas e
outros projetos. Um sistema operacional toca muitas áreas cobertas por
patentes (cripto, compressão, gráficos, IA). Sem concessão explícita, quem
adota o código fica exposto. O projeto também precisa registrar que cada
contribuição foi feita por quem tem direito de licenciá-la.

## Decisão

- Todo o código do projeto é licenciado sob Apache-2.0.
- Contribuições exigem DCO: cada commit leva `Signed-off-by`, no padrão
  Conventional Commits (seção 17.2).
- O monorepo traz `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md` com a regra de DCO
  e `CODEOWNERS` desde o M0.

## Alternativas

- **GPL-2.0 ou GPL-3.0:** garante que derivados sigam abertos, mas afasta
  fabricantes e integradores e complica a convivência com apps e modelos
  de terceiros.
- **MIT ou BSD:** simples e permissiva, mas sem concessão explícita de patentes
  nem cláusula de retaliação contra quem processa por patente.
- **CLA em vez de DCO:** dá ao projeto direitos amplos, mas exige assinatura
  prévia, gestão jurídica e afasta contribuições pequenas.

## Consequências

- Usuários e fabricantes recebem concessão de patentes dos contribuidores.
- Derivados podem ser fechados; o projeto aceita isso em troca de adoção ampla.
- O CI ainda não confere `Signed-off-by`; a verificação fica para quando houver
  contribuições externas. Pendência de Eduardo.
- Código de terceiros nas ferramentas de build precisa ser compatível com
  Apache-2.0; modelos seguem a ADR 0022.

## Revisão de 2026-10-20

Mudanças em relação ao texto anterior:

- O texto do CI deixa de afirmar uma checagem de DCO que ainda não existe;
-   fica como pendência de Eduardo.
