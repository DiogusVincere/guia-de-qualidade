# 19 · Cliente e DOM

O que roda no navegador: JavaScript, DOM, scripts de terceiro. Capítulo V3 do OWASP ASVS (Web Frontend) e a
categoria Client-Side do OWASP WSTG. O servidor pode estar certo e o ataque acontecer inteiro no navegador da
vítima.

### CLI-01 · Nada do usuário vira HTML ou código no DOM sem escape (DOM XSS)
- **Conferir:** `innerHTML`, `v-html`, `dangerouslySetInnerHTML`, `document.write`, `eval`, `setTimeout(string)` com dado que veio da URL, do `postMessage` ou da API.
- **Por quê:** XSS baseado em DOM não passa pelo servidor e escapa de muita proteção; executa na vítima.
- **Como verificar:** `grep` por esses sumidouros e rastreie a origem do dado; teste com `#<img src=x onerror=...>` na URL.
- **Como corrigir:** use a interpolação normal do framework; conteúdo rico só com sanitizador de lista de permissão.

### CLI-02 · Script de terceiro vem fixado e com integridade
- **Conferir:** `<script src>` externo com `integrity=` (SRI) e versão exata; CSP listando os domínios, não `*`.
- **Por quê:** se a CDN do script for comprometida, ela executa no seu site com a sua permissão.
- **Como verificar:** rode a sonda `cliente` do scanner; veja as tags de script externas e se têm `integrity`.
- **Como corrigir:** adicione `integrity` e `crossorigin`, ou sirva o script do seu domínio; fixe a versão.

### CLI-03 · Links para fora não dão controle da sua aba (tabnabbing)
- **Conferir:** `<a target="_blank">` com `rel="noopener noreferrer"`.
- **Por quê:** sem `noopener`, a página aberta pode trocar a sua aba original por uma falsa de login.
- **Como verificar:** a sonda `cliente` aponta; ou `grep` por `target="_blank"` sem `noopener`.
- **Como corrigir:** adicione `rel="noopener noreferrer"` a todo link que abre em nova aba.

### CLI-04 · Nada de conteúdo misto numa página HTTPS
- **Conferir:** imagem, script, iframe ou fetch por `http://` numa página `https://`.
- **Por quê:** o recurso por http pode ser interceptado e trocado, e quebra o cadeado.
- **Como verificar:** a sonda `cliente` aponta; console do navegador mostra "mixed content".
- **Como corrigir:** sirva todo recurso por https; use `upgrade-insecure-requests` na CSP como rede de segurança.

### CLI-05 · `postMessage` valida a origem e a mensagem
- **Conferir:** todo `window.addEventListener('message', ...)` checa `event.origin` e não confia no conteúdo cegamente.
- **Por quê:** sem checar a origem, qualquer site manda mensagem e o seu código a executa.
- **Como verificar:** `grep` por `addEventListener('message'` e veja se há `event.origin ===` antes de usar o dado.
- **Como corrigir:** valide `event.origin` contra uma lista; trate `event.data` como entrada hostil.

### CLI-06 · Nada sensível guardado no navegador do jeito errado
- **Conferir:** token de sessão em `localStorage` (lido por XSS), dado pessoal em cache sem prazo, segredo em `window`.
- **Por quê:** `localStorage` é lido por qualquer script; cookie `HttpOnly` não.
- **Como verificar:** abra a aba Application do navegador; veja o que está em localStorage/sessionStorage.
- **Como corrigir:** sessão em cookie `HttpOnly`+`Secure`+`SameSite`; no `localStorage` só preferência não sensível.

### CLI-07 · Dependências do front sem vulnerabilidade conhecida
- **Conferir:** bibliotecas JavaScript do bundle (versões) contra avisos conhecidos.
- **Por quê:** uma lib vulnerável no front é XSS ou pior, sem erro seu.
- **Como verificar:** `npm audit`; o `nuclei` e scanners de tecnologia também apontam libs antigas servidas.
- **Como corrigir:** atualize; remova a lib que não usa; ver [07 dependências](07-dependencias-e-ci.md).
