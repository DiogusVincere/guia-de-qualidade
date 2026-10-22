# 16 · Upload e manuseio de arquivos

Para qualquer lugar onde o usuário envia arquivo (foto de produto, comprovante, importação de planilha, anexo) ou
onde o sistema lê caminho de arquivo. É o capítulo V5 do OWASP ASVS. Upload é um dos caminhos mais diretos para
executar código no servidor ou servir malware pelo seu domínio.

### UPL-01 · O tipo é validado pelo conteúdo, não pela extensão nem pelo Content-Type
- **Conferir:** os primeiros bytes (assinatura) do arquivo batem com o que diz ser; `.jpg` que é HTML é recusado.
- **Por quê:** extensão e `Content-Type` são do cliente; um `.html` renomeado para `.jpg` vira XSS no seu domínio.
- **Como verificar:** envie um `.html` renomeado para `.jpg` e um `.php`/`.svg` com script; devem ser recusados.
- **Como corrigir:** valide os bytes mágicos; lista de permissão de tipos; para imagem, reprocesse (reencode) antes de guardar.

### UPL-02 · Tamanho limitado antes de ler o arquivo inteiro
- **Conferir:** limite no proxy/CDN e na aplicação; o limite vale antes de carregar tudo na memória.
- **Por quê:** upload gigante derruba o servidor (negação de serviço) e enche o armazenamento.
- **Como verificar:** envie 100 MB; deve ser recusado cedo (413), não processado.
- **Como corrigir:** limite de tamanho no servidor e no CDN; leia em streaming com teto.

### UPL-03 · O nome do arquivo é gerado pelo servidor
- **Conferir:** o arquivo salvo não usa o nome que o usuário mandou; nome aleatório, sem a extensão original executável.
- **Por quê:** nome do cliente permite path traversal (`../../`) e sobrescrever arquivo do sistema.
- **Como verificar:** envie um arquivo chamado `../../index.html`; o destino não pode sair da pasta de uploads.
- **Como corrigir:** gere nome aleatório; guarde o nome original só como metadado; nunca use o nome na montagem do caminho.

### UPL-04 · Arquivo enviado não fica em pasta executável nem pública por caminho adivinhável
- **Conferir:** uploads fora da raiz do site, ou em armazenamento de objetos com URL assinada; nada de `/uploads/` listável.
- **Por quê:** arquivo numa pasta que o servidor executa vira execução de código; URL previsível vaza documento de cliente.
- **Como verificar:** veja onde o arquivo é servido; tente adivinhar a URL de um upload de outro usuário.
- **Como corrigir:** armazene fora da raiz pública ou em bucket privado; sirva por URL assinada e com `Content-Disposition: attachment`.

### UPL-05 · Importação de arquivo trata caminho interno (zip-slip) e fórmula (CSV)
- **Conferir:** ao descompactar zip, nenhuma entrada escreve fora da pasta (`../`); ao exportar CSV, células que começam com `= + - @` são neutralizadas.
- **Por quê:** zip-slip sobrescreve arquivo do sistema; fórmula em CSV executa quando alguém abre no Excel (muito relevante em ferramentas fiscais).
- **Como verificar:** importe um zip com entrada `../x`; exporte um dado começando com `=cmd`; confira a neutralização.
- **Como corrigir:** valide cada caminho do zip antes de escrever; prefixe célula perigosa com `'` na exportação.

### UPL-06 · Path traversal não existe onde o sistema lê arquivo por nome
- **Conferir:** download por `?arquivo=`, servir imagem por `?path=`, template por nome.
- **Por quê:** `?arquivo=../../etc/passwd` lê arquivo do sistema.
- **Como verificar:** rode a sonda de traversal do scanner; peça `../../../../etc/passwd` no parâmetro.
- **Como corrigir:** nunca use entrada como caminho; sirva por id mapeado para um caminho fixo; valide contra lista.
