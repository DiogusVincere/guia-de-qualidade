# 15 · SSRF e requisições que o servidor faz

Quando o seu servidor busca uma URL (imagem, webhook, importação, pré-visualização), quem controla essa URL
controla para onde ele vai. É a API7 do OWASP API Top 10 (SSRF) e um dos caminhos mais sérios para roubo de
credencial interna. Vale para qualquer backend que faz requisição de saída.

### SRV-01 · O servidor nunca busca uma URL que o cliente escolhe
- **Conferir:** campos de URL (avatar por link, webhook, "importar de", pré-visualização de link, callback de pagamento).
- **Por quê:** o atacante aponta a URL para dentro da sua rede ou para o endereço de metadados da nuvem e lê segredo.
- **Como verificar:** rode a sonda de SSRF do scanner; mande `http://169.254.169.254/` e `http://localhost/` no campo e veja se o servidor busca.
- **Como corrigir:** não busque URL do cliente; se precisar, use lista de permissão de domínios e bloqueie IP interno, localhost e metadados.

### SRV-02 · Endereço de metadados da nuvem está bloqueado
- **Conferir:** `169.254.169.254` (AWS/GCP/Azure), `metadata.google.internal`, `100.100.100.200` (Alibaba).
- **Por quê:** é de lá que sai a credencial temporária da máquina; SSRF até ele é comprometimento total.
- **Como verificar:** de dentro de uma função que faz fetch, tente alcançar o endereço; deve falhar.
- **Como corrigir:** bloqueie a faixa `169.254.0.0/16` e `127.0.0.0/8` na saída; use IMDSv2 (exige token) na AWS.

### SRV-03 · Redirecionamento aberto não existe
- **Conferir:** parâmetros `redirect`, `next`, `return`, `url`, `voltar`, `callback`.
- **Por quê:** redirecionamento aberto usa o seu domínio como isca de phishing e burla validação de URL.
- **Como verificar:** `/?next=https://site-invasor.exemplo/` deve terminar no seu site, nunca no externo; `//invasor` também.
- **Como corrigir:** aceite só caminho relativo começando com `/` e não `//`; ou mapeie nomes para rotas conhecidas.

### SRV-04 · O cabeçalho Host não é usado para montar links ou cache
- **Conferir:** redefinição de senha, e-mails, links absolutos e chave de cache que usam `Host` da requisição.
- **Por quê:** host header injection envenena o link de redefinição de senha e a cache (serve conteúdo do atacante).
- **Como verificar:** mande `Host: site-invasor.exemplo` e veja se volta refletido num `Location` ou no corpo.
- **Como corrigir:** use um host fixo da configuração; rejeite Host desconhecido no servidor/CDN.

### SRV-05 · Timeout, tamanho e destino limitados em toda requisição de saída
- **Conferir:** `fetch`/`requests`/`axios` do backend têm `timeout`, limite de tamanho de resposta e destino validado.
- **Por quê:** sem timeout, um destino lento trava o servidor; sem limite, uma resposta enorme o derruba.
- **Como verificar:** `grep` por `fetch(`/`requests.get(`/`axios` e confira timeout em cada um.
- **Como corrigir:** timeout obrigatório; limite de bytes; nunca seguir redirecionamento para IP interno.

### SRV-06 · Webhook que você envia não vaza segredo nem bate em alvo do cliente
- **Conferir:** URL de webhook configurável pelo usuário, com segredo seu no cabeçalho.
- **Por quê:** o usuário aponta o webhook para um servidor dele e captura o seu segredo, ou usa você para atacar terceiros.
- **Como verificar:** confira se o segredo vai no corpo/URL; se o destino é validado; se há limite de tentativas.
- **Como corrigir:** assine o webhook (HMAC) em vez de mandar segredo; valide o destino; não siga para IP interno.
