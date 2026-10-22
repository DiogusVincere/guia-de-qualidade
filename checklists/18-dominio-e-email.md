# 18 · Domínio e e-mail

Para quem tem domínio próprio (não só um subdomínio de plataforma). Protege contra falsificação do seu e-mail
(phishing que parece vir de você) e contra sequestro de subdomínio. A maior parte se resolve com três registros
de DNS. O scanner cobre isto na sonda `dominio` (via DNS sobre HTTPS, sem precisar de ferramenta).

### DOM-01 · SPF publicado e fechado
- **Conferir:** um TXT `v=spf1 ...` no domínio raiz, listando quem pode enviar e-mail, terminando em `-all`.
- **Por quê:** sem SPF, qualquer servidor manda e-mail como `voce@seudominio` e cai na caixa de entrada do cliente.
- **Como verificar:** `dig TXT seudominio` (ou a sonda `dominio` do scanner); confira o `-all` no fim, não `+all`.
- **Como corrigir:** publique o SPF com os remetentes legítimos (seu provedor de e-mail, serviços de envio) e `-all`.

### DOM-02 · DMARC publicado e em modo de bloqueio
- **Conferir:** um TXT `v=DMARC1; p=quarantine` (ou `p=reject`) em `_dmarc.seudominio`, com `rua=` para receber relatórios.
- **Por quê:** o DMARC diz ao recebedor o que fazer com e-mail que falha SPF/DKIM; `p=none` só observa, não protege.
- **Como verificar:** `dig TXT _dmarc.seudominio`; confira o `p=`.
- **Como corrigir:** comece em `p=none` com `rua=`, leia os relatórios por algumas semanas, depois suba para `quarantine` e `reject`.

### DOM-03 · DKIM assinando os e-mails
- **Conferir:** o provedor de e-mail assina com DKIM e a chave pública está no DNS.
- **Por quê:** DKIM prova que o e-mail não foi adulterado e veio de quem diz; é a outra perna do DMARC.
- **Como verificar:** veja o cabeçalho `DKIM-Signature` num e-mail enviado; confira o seletor no DNS.
- **Como corrigir:** ative DKIM no painel do provedor de e-mail e publique o registro que ele indicar.

### DOM-04 · Nenhum subdomínio aponta para serviço que não existe mais (takeover)
- **Conferir:** CNAMEs de subdomínios apontando para GitHub Pages, Heroku, S3, Vercel, Netlify etc. que foram removidos.
- **Por quê:** se o recurso de destino não existe, o atacante recria no serviço e assume o subdomínio (com HTTPS válido).
- **Como verificar:** rode a sonda `dominio` do scanner; para cada subdomínio, veja o CNAME e se o destino responde "não existe".
- **Como corrigir:** remova o CNAME órfão ou recrie o recurso no serviço de destino.

### DOM-05 · Domínio em nome do dono do negócio e com renovação automática
- **Conferir:** titular correto no `whois`, renovação automática ligada, aviso de vencimento para alguém que lê.
- **Por quê:** domínio vencido derruba tudo e é difícil recuperar; em nome errado é risco jurídico.
- **Como verificar:** `whois seudominio`; confira a data de expiração e o titular.
- **Como corrigir:** transfira a titularidade para a dona do negócio; ligue a renovação automática.

### DOM-06 · Registros DNS conferidos e sem sobra
- **Conferir:** registros antigos (A/CNAME/TXT de serviços que você não usa mais), wildcard amplo, zona transferível.
- **Por quê:** registro esquecido vira superfície de ataque; wildcard `*` facilita takeover e phishing.
- **Como verificar:** liste a zona no painel do provedor; questione cada registro que você não reconhece.
- **Como corrigir:** remova o que não usa; evite wildcard; restrinja quem edita o DNS.
