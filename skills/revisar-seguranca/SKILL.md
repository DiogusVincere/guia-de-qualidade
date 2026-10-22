---
name: revisar-seguranca
description: Revisa um projeto inteiro ou o diff atual contra as listas de segurança do guia de qualidade (segredos, segurança web, APIs, autenticação e sessão, dados pessoais) e devolve achados com como-verificar e como-corrigir. Use para /revisar-seguranca, "revisa a segurança", "vê vulnerabilidades", "auditoria de segurança", "está seguro?", antes de publicar um site ou API, ou quando o diff toca login, sessão, upload, cabeçalhos, banco ou configuração.
---

# /revisar-seguranca

Revisão de segurança guiada pelas listas em `${CLAUDE_PLUGIN_ROOT}/checklists/`. O resultado é uma lista de
achados verificáveis, não um parecer genérico.

## Escopo

- Sem argumento: o projeto inteiro no diretório atual.
- Com um caminho, um branch ou "diff": só aquilo. Para diff, use `git diff` da base para o HEAD mais a árvore de
  trabalho.

## Passos

1. **Identificar o tipo do projeto** (site, API, desktop, Flutter, automação) lendo `AGENTS.md`/`CLAUDE.md`,
   `package.json`, `pyproject.toml`/`requirements.txt`, `pubspec.yaml` e a árvore. Abrir as listas que se aplicam:
   - sempre: `01-segredos-e-configuracao.md`
   - site ou aplicação web: `02-seguranca-web.md`, `04-autenticacao-e-sessao.md`
   - API ou rotas chamadas por programa: `03-apis.md`, `04-autenticacao-e-sessao.md`
   - guarda dado de pessoa: `05-dados-pessoais.md`
   - desktop em Python: `11-desktop-python.md` (itens DESK-01, 04, 05, 07)
   - Flutter: `12-apps-flutter.md` (itens FLU-01, 02, 04, 07)
   - certificado digital ou web service: `13-automacoes-certificado-webservices.md`
2. **Percorrer item a item.** Para cada item, executar o "Como verificar" de verdade (grep, curl no ambiente local,
   leitura do código, teste) e registrar: **passa**, **falha** (com a evidência: arquivo e linha, saída do comando) ou
   **não se aplica** (com o motivo em uma linha). Não marcar "passa" sem ter verificado.
3. **Produção só leitura.** Se o projeto está no ar, as verificações em produção são apenas GET/HEAD (`curl -sI`).
   Nunca POST, PUT, PATCH ou DELETE em sistema real; escrita se testa em ambiente local.
4. **Classificar os achados** em: bloqueia publicar (vazamento, escrita sem origem, injeção, segredo no repositório),
   corrige antes do próximo deploy, melhoria. Dentro de cada grupo, do mais fácil de explorar para o mais difícil.
5. **Entregar** no formato abaixo. Cada achado cita o id do item (por exemplo `WEB-03`), a evidência, e o "Como
   corrigir" adaptado ao projeto. Se a pessoa pediu correção, corrigir começando pelo grupo "bloqueia", com teste que
   reproduz o problema antes da correção (QA-01), e repetir a verificação depois.
6. **Pontas registradas.** O que não pôde ser verificado (sem acesso, sem ambiente) e o que ficou de fora entram na
   tabela de pontas com motivo, risco e onde foi anotado no projeto. Nada fica só na mensagem.

## Formato da entrega

```
## Revisão de segurança — <projeto> — <data>

Listas percorridas: 01, 02, 04 (completas); 05 (não se aplica: não guarda dado de pessoa)
Verificado em: ambiente local (http://localhost:3000) e produção só leitura (https://...)

### Bloqueia publicar
- WEB-03 · Escrita sem checagem de origem — `server/api/pedidos.post.ts:12`. Evidência: `curl -X POST ... -H "Origin: https://outro.test"` devolveu 200. Correção: middleware que compara o host do Origin; teste em `tests/origem.test.ts`.

### Corrige antes do próximo deploy
- ...

### Melhorias
- ...

### Passou
- SEG-01, SEG-02, WEB-01 (cabeçalhos presentes nas três rotas), ...

### Não verificado
- OPS-05 backup: sem acesso ao painel do provedor. A pessoa confere em <onde>.

### Pontas registradas
| Ponta | Por que ficou | Risco | Onde está anotado |
```

## Regras

- Achado sem evidência não é achado. Diga o que rodou e o que viu.
- Não invente severidade para parecer completo: "passou" é resultado válido e desejado.
- Segredo encontrado: não cole o valor na mensagem. Diga o arquivo, a linha e que precisa ser trocado, não só apagado.
- Siga `${CLAUDE_PLUGIN_ROOT}/AGENTS.md` em tudo o que esta skill não cobre.
