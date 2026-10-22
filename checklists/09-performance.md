# 09 · Performance

Para sites e APIs. O objetivo é o básico que faz diferença para quem acessa pelo celular em rede média: página que
abre rápido, imagem no tamanho certo, consulta que não cresce com a tabela.

### PERF-01 · Imagens no tamanho e formato que a tela precisa
- **Conferir:** fotos servidas redimensionadas (CDN de imagem ou variantes geradas), formato moderno (WebP/AVIF) com fallback, `width`/`height` declarados, `loading="lazy"` fora da primeira dobra e carregamento imediato na primeira.
- **Por quê:** a foto de 4 MB é o motivo mais comum de site lento em loja e portfólio.
- **Como verificar:** aba de rede no modo celular: nenhuma imagem acima de ~200 KB na página inicial; dimensões da imagem baixada próximas das exibidas; sem salto de layout ao carregar.
- **Como corrigir:** parâmetros de transformação da CDN (largura, qualidade, formato automático); atributos de dimensão; `srcset` quando servir local.

### PERF-02 · Primeira dobra renderiza no servidor e sem bloqueio
- **Conferir:** HTML inicial já traz o conteúdo visível; CSS crítico pequeno; fontes com `font-display: swap` e pré-carregadas; scripts de terceiros adiados.
- **Por quê:** tela branca de três segundos no celular é abandono.
- **Como verificar:** Lighthouse no modo celular: LCP abaixo de 2,5 s em rede simulada; `curl` da página mostra o conteúdo no HTML.
- **Como corrigir:** SSR/SSG para páginas públicas; `preload` da fonte principal; `defer` em scripts; menos fontes.

### PERF-03 · Consultas ao banco não crescem com o tamanho da tabela
- **Conferir:** índices nas colunas de filtro e ordenação; listagens paginadas; sem N+1 (uma consulta por linha); capas de produto buscadas em lote.
- **Por quê:** funciona com 50 registros e cai com 5 000.
- **Como verificar:** `EXPLAIN` (ou o plano do ORM) nas consultas principais: usa índice; log de consultas por requisição mostra número constante, não proporcional aos itens.
- **Como corrigir:** `inArray`/`IN` para buscar relacionados em lote; índice composto para filtro + ordem.

### PERF-04 · Cache onde o conteúdo é estável, nunca onde é pessoal
- **Conferir:** `Cache-Control` longo com hash no nome para assets; curto ou `no-store` para páginas com sessão e para API autenticada; CDN não guarda resposta com cookie.
- **Por quê:** cache errado serve o pedido de uma pessoa para outra; cache ausente faz o servidor repetir trabalho.
- **Como verificar:** `curl -sI` em um asset (`max-age` grande, `immutable`) e em `/api/...` autenticada (`no-store` ou `private`).
- **Como corrigir:** regras por rota no servidor/plataforma; `Vary: Cookie` quando a resposta depende de sessão.

### PERF-05 · JavaScript enviado é o que a página usa
- **Conferir:** tamanho do bundle inicial; divisão por rota; bibliotecas grandes carregadas sob demanda; nada de biblioteca inteira para uma função.
- **Por quê:** cada 100 KB de JS é tempo de análise no celular.
- **Como verificar:** relatório de build (tamanho por chunk); aba de rede: JS inicial comprimido abaixo de algumas centenas de KB; análise do bundle sem dependência inesperada.
- **Como corrigir:** import dinâmico por rota; troque a biblioteca pela função; remova o que não é usado.

### PERF-06 · Trabalho pesado fora da requisição
- **Conferir:** geração de PDF, envio de e-mail, chamada a web service lento, processamento de arquivo rodam em fila, tarefa agendada ou pelo menos depois de responder.
- **Por quê:** a requisição espera, o usuário espera, o servidor bloqueia.
- **Como verificar:** tempo de resposta das rotas de escrita abaixo de ~500 ms em condição normal; o trabalho pesado tem log próprio.
- **Como corrigir:** responda "recebido" e processe depois; registre o estado para consulta.

### PERF-07 · Tempo de resposta medido, não estimado
- **Conferir:** logs ou painel com tempo por rota; alerta quando sobe; teste de carga simples antes de um lançamento.
- **Por quê:** "parece rápido" na máquina de desenvolvimento não é dado.
- **Como verificar:** percentil 95 das rotas principais em produção (painel da plataforma) ou um teste local com dezenas de requisições simultâneas.
- **Como corrigir:** registre o tempo no log de acesso; investigue as rotas acima do esperado.

### PERF-08 · Limites do ambiente conhecidos e respeitados
- **Conferir:** limite de CPU por requisição, de tamanho de resposta, de conexões ao banco, de subrequisições (ambientes sem servidor têm todos).
- **Por quê:** a função que passa do limite morre no meio, sem erro claro.
- **Como verificar:** documentação do provedor lida e os limites anotados em `docs/OPERACAO.md`; a rota mais pesada medida contra eles.
- **Como corrigir:** divida o trabalho; pagine; mova para tarefa agendada.
