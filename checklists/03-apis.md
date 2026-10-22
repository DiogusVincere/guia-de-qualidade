# 03 · APIs

Para qualquer interface HTTP consumida por programa: API REST, rota de um site que o front chama, webhook,
servidor local que uma interface usa. Complementa a [02 Segurança web](02-seguranca-web.md); os itens de lá sobre
cabeçalhos, validação, limite de tentativas e erros valem aqui também.

### API-01 · Toda rota declara quem pode chamar, e a regra é testada
- **Conferir:** cada rota tem autenticação explícita (ou é explicitamente pública) e a autorização checa o **recurso**, não só o papel: o usuário 7 não lê nem altera o pedido do usuário 8 trocando o id na URL.
- **Por quê:** acesso quebrado por objeto (BOLA) é a falha número um de APIs e não aparece em teste de "está logado?".
- **Como verificar:** teste automatizado que autentica como A, cria um recurso, autentica como B e tenta GET/PUT/DELETE nele: 403 ou 404 em todos. Rota sem decorador/middleware de autenticação está numa lista de públicas conhecida.
- **Como corrigir:** filtre a consulta pelo dono (`where id = ? and dono = ?`) em vez de buscar e depois comparar; centralize a regra em um helper.

### API-02 · Métodos e códigos de status fazem o que dizem
- **Conferir:** GET não altera nada; POST cria; PUT/PATCH alteram; DELETE apaga. 200/201/204 no sucesso, 400 entrada inválida, 401 sem autenticação, 403 sem permissão, 404 não existe, 409 conflito, 413 grande demais, 429 limite, 5xx só para falha do servidor.
- **Por quê:** cliente, proxy, cache e monitoramento confiam nisso. GET que altera é cacheado e repetido.
- **Como verificar:** tabela de rotas × métodos × códigos nos testes; `grep` por `GET` em handlers que escrevem.
- **Como corrigir:** mova a escrita para POST/PUT; ajuste o código de status onde estiver genérico.

### API-03 · Paginação e limites em toda listagem
- **Conferir:** rota que lista aceita página/tamanho com teto (por exemplo 50) e devolve de forma previsível (ordem estável, indicação de que há mais).
- **Por quê:** listagem sem limite cai quando a tabela cresce e vira ataque de negação de serviço gratuito.
- **Como verificar:** `?tamanho=100000` devolve no máximo o teto; ordenação tem desempate por id; teste com mais registros que o teto.
- **Como corrigir:** limite no servidor, não no cliente; `ORDER BY` com coluna única + id.

### API-04 · Escrita que não pode acontecer duas vezes é idempotente
- **Conferir:** criação de pedido, pagamento, envio de e-mail, baixa de estoque. Repetir a mesma requisição (reenvio do navegador, retry do cliente) não duplica o efeito.
- **Por quê:** rede falha depois de o servidor processar e antes de o cliente receber a resposta. O cliente reenvia.
- **Como verificar:** envie o mesmo POST duas vezes com a mesma chave de idempotência (ou mesmo conteúdo em janela curta): um registro só. Botão do front desabilita enquanto envia e ignora clique duplo.
- **Como corrigir:** chave de idempotência (cabeçalho ou campo) guardada com a resposta; no front, guarda `enviando` antes de disparar.

### API-05 · Operação em vários registros é atômica ou tem compensação registrada
- **Conferir:** baixar estoque de três itens, criar pedido e itens, transferir saldo.
- **Por quê:** falha no meio deixa o banco pela metade e ninguém percebe até a contagem física.
- **Como verificar:** teste que força erro no segundo item e confere que o primeiro não mudou (transação) ou que a compensação rodou e ficou registrada.
- **Como corrigir:** transação do banco quando o ambiente permite (`db.batch`, `transaction.atomic`); quando não permite, registre o que foi feito (`reservado`) para devolver exatamente aquilo.

### API-06 · Entrada e saída têm contrato escrito e versionado
- **Conferir:** esquema de cada rota (OpenAPI, esquema Zod/Pydantic exportado ou ao menos tipos compartilhados entre front e back); mudança incompatível muda a versão ou mantém o campo antigo por um período.
- **Por quê:** o front quebra em silêncio quando um campo muda de nome.
- **Como verificar:** tipos do front são gerados ou importados do back (`shared/`), não copiados à mão; teste de contrato ou de integração que chama a rota real.
- **Como corrigir:** mova o esquema para um módulo compartilhado; documente a rota; marque campos descontinuados antes de remover.

### API-07 · Erro não vaza detalhe e não some
- **Conferir:** resposta de erro tem um código estável e uma mensagem curta; o detalhe (stack, SQL) vai para o log com um identificador que aparece na resposta.
- **Por quê:** "erro interno" sem identificador é impossível de investigar; stack na resposta é presente para quem ataca.
- **Como verificar:** force uma exceção: resposta `{ "erro": "falha interna", "id": "..." }` e o log tem o mesmo id com a stack.
- **Como corrigir:** tratador global de erro.

### API-08 · CORS fechado por padrão
- **Conferir:** `Access-Control-Allow-Origin` só para os domínios do front; nunca `*` com credenciais; métodos e cabeçalhos listados.
- **Por quê:** CORS aberto com cookie é a mesma coisa que não ter autenticação para quem tem um site.
- **Como verificar:** `curl -sI -H "Origin: https://outro.test" https://api/...` não devolve `Access-Control-Allow-Origin: https://outro.test` nem `*` em rota autenticada.
- **Como corrigir:** lista explícita de origens por ambiente; preflight respondido só para elas.

### API-09 · Webhook recebido é autenticado e repetível
- **Conferir:** assinatura HMAC ou segredo verificado antes de processar; evento duplicado é reconhecido pelo id; processamento rápido com trabalho pesado fora da requisição.
- **Por quê:** webhook sem assinatura é uma rota pública que muda estado; provedores reenviam.
- **Como verificar:** requisição sem assinatura ou com assinatura errada: 401. Mesmo evento duas vezes: um efeito.
- **Como corrigir:** verifique a assinatura com comparação em tempo constante; guarde ids processados.

### API-10 · Rota de saúde diz só o necessário para quem não está autenticado
- **Conferir:** `/api/saude` (health) público responde `ok` e um próximo passo em linguagem simples; versão, migrações aplicadas, contagens e nomes de tabela só para quem está autenticado como admin.
- **Por quê:** é a primeira rota que um scanner lê.
- **Como verificar:** `curl .../api/saude` sem sessão devolve o mínimo; com sessão de admin devolve o detalhe.
- **Como corrigir:** ramifique pela sessão dentro do handler.

### API-11 · Tempo e tamanho de requisição têm teto
- **Conferir:** timeout de chamadas a terceiros, limite de corpo, limite de itens por pedido, limite de quantidade por item.
- **Por quê:** sem teto, um cliente lento ou malicioso ocupa o servidor; sem limite de quantidade, alguém "compra" 999999 unidades.
- **Como verificar:** pedido com 11 unidades quando o teto é 10 (também somando linhas repetidas do mesmo item): 400. Chamada externa com `timeout` explícito em todo `fetch`/`requests`.
- **Como corrigir:** validação após somar; `timeout=` obrigatório; corpo limitado antes de ler.

### API-12 · Rotas de teste e depuração não existem em produção
- **Conferir:** `/debug`, `/api/semear`, `/graphiql`, `/swagger` aberto, `?dump=1`.
- **Por quê:** ficam esquecidas e dão acesso total.
- **Como verificar:** `grep -rn "debug\|semear\|seed\|/docs" server/api server/routes` e confira que cada uma só registra fora de produção ou exige admin. Em produção, `curl` nelas devolve 404.
- **Como corrigir:** registre condicionalmente por ambiente; semente de produção só roda com guarda (catálogo vazio, marcador que impede rodar duas vezes) e nunca apaga.
