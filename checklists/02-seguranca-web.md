# 02 · Segurança web

Para qualquer site ou aplicação servida por HTTP: páginas, painel administrativo, loja, formulário. APIs têm lista
própria ([03](03-apis.md)); login e sessão também ([04](04-autenticacao-e-sessao.md)). Baseado no OWASP ASVS e
no Top 10, traduzido em verificações que cabem num `curl`.

### WEB-01 · Cabeçalhos de segurança presentes em TODAS as respostas de produção
- **Conferir:** `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, `X-Frame-Options` (ou `frame-ancestors` na CSP). Nenhum `Server`/`X-Powered-By` detalhado.
- **Por quê:** são a camada que segura XSS, clickjacking e downgrade quando o resto falha. E somem fácil: um `_headers` que o framework ignora, um hook que só roda em uma rota.
- **Como verificar:** `curl -sI https://seu-site/ ` e também numa rota de API e numa página 404. Os cabeçalhos aparecem nas três. Ferramenta externa de nota (securityheaders.com) como conferência final.
- **Como corrigir:** defina os cabeçalhos no lugar que cobre todas as respostas (middleware ou hook de renderização do servidor), não em arquivo estático de uma plataforma só. Teste automatizado que pede três rotas e confere os cabeçalhos.

### WEB-02 · CSP sem `unsafe-inline` em `script-src`
- **Conferir:** a política de scripts usa nonce por requisição ou hash; `style-src 'unsafe-inline'` é tolerável quando o framework exige, `script-src` não.
- **Por quê:** com `unsafe-inline` a CSP não impede XSS, que é o motivo de ela existir.
- **Como verificar:** no cabeçalho, `script-src` contém `'nonce-...'` diferente a cada carregamento e não contém `'unsafe-inline'`. No HTML, toda tag `<script>` inline leva o mesmo nonce. Console do navegador sem erro de CSP ao navegar pelas páginas principais.
- **Como corrigir:** gere o nonce no servidor por requisição e injete nas tags; scripts de terceiros entram por domínio explícito. Scripts inline que não podem receber nonce (por exemplo gravação em `sessionStorage` no `<head>`) viram arquivo externo.

### WEB-03 · Escrita só com origem confiável
- **Conferir:** POST, PUT, PATCH e DELETE verificam `Origin` (ou `Sec-Fetch-Site`) ou token anti-CSRF; cookies de sessão com `SameSite=Lax` ou `Strict`.
- **Por quê:** sem isso, um site qualquer faz o navegador da pessoa logada enviar um pedido, trocar uma senha ou apagar um registro.
- **Como verificar:** `curl -X POST https://seu-site/api/alguma-escrita -H "Origin: https://outro.test" -H "Content-Type: application/json" -d '{}'` responde 403. Sem `Origin` e sem `Sec-Fetch-Site` (cliente antigo) responde 403 também. O fluxo normal pelo navegador continua funcionando.
- **Como corrigir:** middleware que compara o host do `Origin` com o host da requisição e aceita `Sec-Fetch-Site: same-origin`; em formulários clássicos, token sincronizado.

### WEB-04 · Toda entrada é validada com esquema, e o que falha dá 400 claro
- **Conferir:** corpo, query e parâmetros de rota passam por um esquema (Zod, Pydantic, serializer) antes de qualquer uso; tamanho máximo do corpo definido.
- **Por quê:** entrada sem esquema vira erro 500 (vaza stack e derruba o worker) ou dado inválido no banco.
- **Como verificar:** envie JSON com tipo errado, campo a mais, string de 1 MB e número negativo: todas voltam 400 com mensagem que não ecoa o valor. Corpo acima do limite (por exemplo 64 KB) volta 413.
- **Como corrigir:** `safeParse` e resposta 400; limite de `Content-Length` antes de ler o corpo; nunca `JSON.parse` solto.

### WEB-05 · Saída escapada: nada do usuário vira HTML sem escape
- **Conferir:** `v-html`, `innerHTML`, `dangerouslySetInnerHTML`, `|safe`, `mark_safe`, templates com autoescape desligado, geração de e-mail HTML.
- **Por quê:** é o XSS clássico, e aparece em lugar inesperado: nome do produto no título da página, observação do pedido no painel.
- **Como verificar:** `grep -rn "v-html\|innerHTML\|dangerouslySetInnerHTML\|mark_safe\|| *safe" app src templates`. Para cada ocorrência, a origem do conteúdo é fixa (texto do próprio projeto) ou passa por sanitizador. Teste: cadastre `<img src=x onerror=alert(1)>` num campo e veja a renderização em todas as telas que mostram o campo.
- **Como corrigir:** interpolação normal do framework; conteúdo rico só com sanitizador com lista de permissão.

### WEB-06 · Consultas ao banco sem concatenação
- **Conferir:** ORM com parâmetros; nenhum `f"SELECT ... {valor}"`, nenhum `sql.raw` com string montada.
- **Por quê:** injeção de SQL continua no topo das causas de vazamento total.
- **Como verificar:** `grep -rn "execute(f\|execute(\"\|\.raw(\|sql\`" server src` e leia cada ocorrência. Parâmetro vem por placeholder, não por formatação.
- **Como corrigir:** use a API parametrizada do ORM ou driver; para ordenação dinâmica, mapeie o nome recebido para uma lista fixa de colunas.

### WEB-07 · Upload com tipo, tamanho e destino controlados
- **Conferir:** extensão e tipo real (não só o `Content-Type` declarado), tamanho máximo, nome gerado pelo servidor, armazenamento fora da raiz pública ou em serviço de objetos com assinatura.
- **Por quê:** upload é o atalho para executar código no servidor ou servir malware pelo seu domínio.
- **Como verificar:** envie um `.html` renomeado para `.jpg`: recusado. Envie 50 MB: recusado antes de ler tudo. O arquivo salvo não tem o nome original e não fica acessível por caminho previsível.
- **Como corrigir:** valide os primeiros bytes (assinatura do formato), limite tamanho no proxy e na aplicação, gere nome aleatório, sirva por URL assinada ou com `Content-Disposition: attachment`.

### WEB-08 · Mensagens de erro não vazam internos
- **Conferir:** respostas 4xx/5xx em produção não trazem stack, caminho de arquivo, versão do framework, SQL ou nome de tabela.
- **Por quê:** cada detalhe economiza tempo de quem ataca.
- **Como verificar:** force um 500 (rota que lança exceção em ambiente de teste) e um 404 com `Accept: text/html` e com `Accept: application/json`. Ambos genéricos. A página 404 tem título e layout do site (não a página padrão do framework).
- **Como corrigir:** tratador global de erro que registra o detalhe no log e devolve mensagem curta; `DEBUG=False` garantido por padrão.

### WEB-09 · Limite de tentativas em tudo que custa ou que se adivinha
- **Conferir:** login, troca de senha, recuperação de senha, criação de pedido, envio de formulário, busca pesada. Limite por IP (faixa /64 em IPv6) e por conta; limite global de proteção.
- **Por quê:** sem isso, força bruta é só questão de tempo e um script cria mil pedidos em um minuto.
- **Como verificar:** 11 tentativas de login erradas em sequência: a 11ª volta 429 com `Retry-After`. O limite é reservado antes de processar (não dá para passar com requisições simultâneas). Teste automatizado cobre a janela.
- **Como corrigir:** contador com janela deslizante no armazenamento que o ambiente oferece (KV, Redis, tabela); reserve a tentativa antes de verificar a credencial; devolva a tentativa só em erro 5xx.

### WEB-10 · Redirecionamentos só para dentro
- **Conferir:** parâmetros `next`, `redirect`, `url`, `voltar`.
- **Por quê:** redirecionamento aberto é a isca de phishing que usa o seu domínio.
- **Como verificar:** `/login?next=https://outro.test` termina no próprio site, não em `outro.test`. `//outro.test` também.
- **Como corrigir:** aceite só caminho relativo que começa com `/` e não com `//`; ou mapeie nomes para rotas conhecidas.

### WEB-11 · Dependências do front sem fonte externa não controlada
- **Conferir:** scripts e estilos vêm do próprio domínio ou de CDN fixada por versão e, se possível, por integridade (`integrity=`). Ícones e fontes idem.
- **Por quê:** CDN comprometida executa no seu site com a sua CSP liberando.
- **Como verificar:** `grep -rn "https://.*\.js\"\|cdn\." app public` e confira versão fixa e `integrity`. A CSP lista exatamente esses domínios, não `*`.
- **Como corrigir:** sirva localmente quando couber; quando não, versão exata + SRI + domínio na CSP.

### WEB-12 · Área administrativa não está só atrás do login da aplicação
- **Conferir:** `/admin` ou equivalente tem segunda barreira: acesso por identidade do provedor (Cloudflare Access, VPN, lista de IPs) ou, no mínimo, autenticação forte e limite agressivo.
- **Por quê:** o painel é o alvo de maior valor e o login da aplicação é uma linha de defesa só.
- **Como verificar:** sem estar autenticado no provedor, `/admin` nem carrega a tela de login da aplicação. Robôs não indexam (`robots.txt` e `X-Robots-Tag: noindex` na área).
- **Como corrigir:** ative a camada do provedor de hospedagem para o caminho; registre no relatório se depende de ação da pessoa (geralmente depende).

### WEB-13 · Cookies com os atributos certos
- **Conferir:** `Secure`, `HttpOnly`, `SameSite=Lax` (ou `Strict`), `Path` restrito, prazo definido.
- **Por quê:** cookie sem `HttpOnly` é lido por XSS; sem `Secure` vai em texto puro; sem `SameSite` participa de CSRF.
- **Como verificar:** `curl -sI -X POST .../login` (ou ferramentas do navegador, aba Application) e leia o `Set-Cookie`.
- **Como corrigir:** configure na biblioteca de sessão; não monte `Set-Cookie` à mão.

### WEB-14 · Recursos sensíveis não aparecem para quem não deve
- **Conferir:** quantidade em estoque, custo, margem, e-mail de outros clientes, códigos internos não vazam em respostas públicas de API nem no HTML renderizado.
- **Por quê:** o front filtra o que mostra, mas a resposta JSON inteira está a um F12 de distância.
- **Como verificar:** abra a rota pública de listagem e leia o JSON campo a campo. O que o cliente não precisa ver não está lá (estoque vira "esgotado"/"últimas unidades", não número).
- **Como corrigir:** selecione as colunas na consulta ou serialize com lista de campos permitidos por perfil.
