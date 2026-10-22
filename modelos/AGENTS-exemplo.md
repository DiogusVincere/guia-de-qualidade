# Modelo de AGENTS.md para um projeto que usa o guia

Copie para a raiz do projeto como `AGENTS.md` e ajuste as partes entre colchetes. Crie também um `CLAUDE.md` com
uma linha, `@AGENTS.md`, para o Claude Code ler o mesmo arquivo.

---

```markdown
# [Nome do projeto]

Antes de qualquer alteração, leia e siga `docs/guia-de-qualidade/AGENTS.md` (ou
https://github.com/DiogusVincere/guia-de-qualidade). As regras deste arquivo valem sobre as do guia quando forem
mais restritivas.

## O que este projeto é

[Site + API em Nuxt no Cloudflare Workers, com painel administrativo e pedidos de clientes.]
Listas obrigatórias do guia: 00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 10.

## Como rodar

- Instalar: `[npm install]`
- Testes: `[npm test]` (todos precisam passar antes de qualquer commit)
- Local: `[npm run dev]` em http://localhost:[3000]
- Build de produção: `[npm run build]`

## Regras próprias

- [Produção é https://exemplo.test. Nunca POST/PUT/PATCH/DELETE lá: cria dado real.]
- [Segredos só em `.env` (ignorado) e nas variáveis do serviço de hospedagem. `.env.example` lista as chaves sem valor.]
- [Pasta `clientes/` é somente leitura.]
- [Textos de garantia e troca precisam de aprovação da dona antes de ir para o ar.]
- [Conferir no celular (375 px) antes do desktop: é por onde entra a maioria dos acessos.]

## O que a pessoa faz, não o agente

- [Login no serviço de hospedagem e no gerenciador de domínio.]
- [Trocar segredos.]
- [Publicar mudanças de texto comercial.]

## Onde as pontas ficam registradas

- `docs/TAREFAS.md`, seção "Pendências". Toda entrega aponta para lá.
```
