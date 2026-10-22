# 14 · Reconhecimento e inventário

O que o site entrega sobre si antes de qualquer ataque, e o que você sabe que tem no ar. Baseado no OWASP WSTG
(Information Gathering) e na API9 do OWASP API Top 10 (inventário impróprio). O atacante faz isto primeiro; faça
antes dele.

### REC-01 · Você tem a lista de tudo que está exposto
- **Conferir:** domínios, subdomínios, rotas de API (inclusive versões antigas e de teste), ambientes (produção, homologação, preview) e o que cada um serve.
- **Por quê:** não se protege o que não se sabe que existe; API fantasma e ambiente de teste esquecido são porta dos fundos.
- **Como verificar:** rode o crawler do scanner (`--sondas rastreio`), liste subdomínios, confira o `sitemap.xml` e as rotas que aparecem no JavaScript.
- **Como corrigir:** desative o que não é usado; proteja homologação/preview com senha; documente a lista em `docs/OPERACAO.md`.

### REC-02 · Rotas de versão antiga da API foram desativadas
- **Conferir:** `/api/v1` quando já existe `/v2`, endpoints descontinuados, `beta`, `old`, `legacy`.
- **Por quê:** a versão antiga costuma não ter as correções da nova.
- **Como verificar:** peça `/api/v1/...`, `/api/old/...` e veja se respondem; compare com a versão atual.
- **Como corrigir:** desligue de verdade (não só esconda do front) ou aplique as mesmas proteções da versão nova.

### REC-03 · O servidor não anuncia versão nem tecnologia detalhada
- **Conferir:** cabeçalhos `Server`, `X-Powered-By`, `X-AspNet-Version`, comentários no HTML, nomes de arquivo que revelam o framework.
- **Por quê:** a versão exata leva direto ao exploit pronto.
- **Como verificar:** `curl -sI` e leia os cabeçalhos; veja o HTML atrás de `<!-- -->` e de caminhos como `/_next/`, `/_nuxt/`.
- **Como corrigir:** remova ou neutralize os cabeçalhos de versão; o framework você não esconde, mas a versão sim.

### REC-04 · `robots.txt` e `sitemap.xml` não entregam o que é secreto
- **Conferir:** `Disallow` apontando para `/admin`, `/api/interno`, backups; sitemap listando rota privada.
- **Por quê:** é a primeira coisa que um robô lê, e "proibir no robots" só avisa onde está o tesouro.
- **Como verificar:** abra os dois arquivos e leia cada caminho.
- **Como corrigir:** proteja a rota de verdade (autenticação), não pelo robots; tire o caminho sensível do sitemap.

### REC-05 · Páginas de erro não vazam pilha, caminho nem tecnologia
- **Conferir:** 404, 500 e erro de validação em produção.
- **Por quê:** cada detalhe no erro economiza trabalho de quem ataca e pode revelar estrutura de arquivos ou SQL.
- **Como verificar:** force um 500 e um 404 (com `Accept: text/html` e `application/json`); leia o corpo.
- **Como corrigir:** tratador global que registra o detalhe no log e devolve mensagem curta com um identificador.

### REC-06 · Metadados e arquivos de build não foram publicados
- **Conferir:** `/.git`, `/.svn`, `/.map` (source maps), `/node_modules`, `/.well-known` além do necessário, `/__nuxt`, artefatos de CI.
- **Por quê:** source map reconstrói o código; `.git` entrega o histórico inteiro.
- **Como verificar:** rode a sonda de exposição do scanner; peça `/.git/config`, `/app.js.map`.
- **Como corrigir:** não publique esses arquivos; bloqueie no CDN; desligue source map em produção.

### REC-07 · Buscadores não indexaram o que é privado
- **Conferir:** painel, API, documentos de cliente achados por busca (`site:seudominio.com admin`).
- **Por quê:** o que o Google indexou, qualquer um acha sem esforço.
- **Como verificar:** faça a busca `site:` do seu domínio; procure rota administrativa e arquivo que não devia estar lá.
- **Como corrigir:** `noindex` e autenticação na área privada; peça remoção no console do buscador se já indexou.
