# 10 · Deploy e operação

Para qualquer sistema que fica no ar: site, API, servidor local da equipe, tarefa agendada.

### OPS-01 · Produção se confere depois do deploy, com comandos
- **Conferir:** depois de publicar, a rota principal responde 200, a rota de saúde diz "ok", os cabeçalhos de segurança estão lá, uma página inexistente dá 404 com layout.
- **Por quê:** build que passa no CI pode subir com variável faltando ou cabeçalho perdido.
- **Como verificar:** `curl -sI https://site/`, `curl -s https://site/api/saude`, `curl -sI https://site/nao-existe` (com `Accept: text/html`). Registre o resultado no relatório.
- **Como corrigir:** se falhou, reverta primeiro (deploy anterior), investigue depois.

### OPS-02 · Reverter é um comando conhecido
- **Conferir:** como voltar para a versão anterior está escrito e foi testado uma vez (deploy anterior na plataforma, tag no git, pacote anterior guardado).
- **Por quê:** o deploy quebrado às 18h não pode depender de descobrir como reverter.
- **Como verificar:** `docs/OPERACAO.md` tem a seção "Reverter" com o comando ou o clique exato.
- **Como corrigir:** escreva e teste em horário calmo.

### OPS-03 · Migração de banco é reversível ou tem cópia antes
- **Conferir:** migração que apaga ou altera coluna tem passo de volta ou backup imediatamente antes; migração roda antes do código novo que depende dela e é compatível com o código velho durante a troca.
- **Por quê:** migração sem volta mais deploy quebrado é perda de dados.
- **Como verificar:** histórico de migrações aplicado em cópia do banco de produção antes de aplicar no real; a migração destrutiva está em commit separado do código.
- **Como corrigir:** expanda-migre-contraia: adicione a coluna nova, migre dados, só depois remova a antiga.

### OPS-04 · Semente e scripts de dados não destroem produção
- **Conferir:** script de semente de produção só insere, só com catálogo vazio, e deixa um marcador que impede rodar duas vezes; a semente de desenvolvimento (com `DELETE`) não roda contra o banco de produção por engano (nome diferente, confirmação).
- **Por quê:** já aconteceu: semente de desenvolvimento apontada para produção apagou tudo.
- **Como verificar:** leia o script de produção: nenhum `DELETE`/`DROP`/`TRUNCATE`; rodá-lo duas vezes não duplica nada (teste automatizado).
- **Como corrigir:** dois arquivos distintos (`semente.sql` e `semente-producao.sql`), guarda por marcador, comando de produção separado no `package.json`.

### OPS-05 · Cópia de segurança existe, é automática e já foi restaurada uma vez
- **Conferir:** backup do banco e dos arquivos enviados, periódico, fora do mesmo servidor, com prazo de retenção; restauração testada.
- **Por quê:** backup nunca restaurado é hipótese.
- **Como verificar:** data do último backup no painel; um teste de restauração registrado com data em `docs/OPERACAO.md`.
- **Como corrigir:** ative o backup do provedor (ou exportação agendada); restaure numa cópia e anote.

### OPS-06 · Logs suficientes para investigar, sem dado sensível
- **Conferir:** cada requisição com método, rota, status, tempo e um identificador; erros com stack no log (não na resposta); nada de senha, token, CPF, e-mail completo.
- **Por quê:** sem log não há investigação; com dado sensível o log vira o vazamento.
- **Como verificar:** leia 50 linhas do log de produção: dá para seguir uma requisição com problema? aparece algum dado pessoal?
- **Como corrigir:** logger estruturado com mascaramento; identificador de requisição propagado.

### OPS-07 · Alguém fica sabendo quando cai
- **Conferir:** monitor externo que chama a rota de saúde a cada poucos minutos e avisa (e-mail, mensagem); alerta de erro 5xx acima de um limiar.
- **Por quê:** descobrir pelo cliente é o pior jeito.
- **Como verificar:** desligue o serviço em homologação (ou mude a rota) e veja o aviso chegar.
- **Como corrigir:** serviço de monitoramento gratuito ou da própria plataforma apontando para `/api/saude`.

### OPS-08 · Domínio, certificado e DNS documentados e com renovação automática
- **Conferir:** onde o domínio está registrado, em nome de quem, quando vence, quem recebe o aviso; TLS renovado pela plataforma; registros DNS listados.
- **Por quê:** domínio vencido derruba tudo e é difícil de recuperar; em nome da pessoa errada é risco jurídico.
- **Como verificar:** `docs/OPERACAO.md` tem a tabela; o certificado mostra renovação automática no painel; `whois` confirma o titular.
- **Como corrigir:** escreva; transfira a titularidade para a dona do negócio quando for o caso.

### OPS-09 · Ambiente de produção e de desenvolvimento não se confundem
- **Conferir:** nomes de banco, URLs e credenciais claramente diferentes; cor ou aviso no painel de desenvolvimento; comando de produção exige confirmação ou flag explícita.
- **Por quê:** o erro de rodar o comando no lugar errado é humano e previsível.
- **Como verificar:** rode o comando de migração sem a flag de produção: ele age no local. A tela de desenvolvimento mostra "DESENVOLVIMENTO".
- **Como corrigir:** sufixo `:prod` nos scripts; faixa visível por ambiente.

### OPS-10 · Tarefas agendadas têm registro de execução e de falha
- **Conferir:** cada rotina automática (limpeza, cobrança, envio) escreve quando rodou, o que fez e se falhou; falha gera aviso; execução duplicada é inofensiva.
- **Por quê:** rotina silenciosa que parou há três meses só aparece na auditoria.
- **Como verificar:** tabela ou log com a última execução de cada rotina; force uma falha e veja o aviso.
- **Como corrigir:** envolva a rotina em registro de início/fim/erro; torne-a idempotente.

### OPS-11 · O passo a passo de operação existe e cabe numa página
- **Conferir:** `docs/OPERACAO.md` com: como publicar, como reverter, onde estão os segredos e como trocar, como migrar e semear, como restaurar backup, limites do ambiente, contatos (sem dado pessoal em repositório público), o que fazer num incidente.
- **Por quê:** é o documento que a próxima pessoa (ou o próximo agente) abre quando algo dá errado.
- **Como verificar:** cada seção acima existe; alguém que não participou consegue seguir.
- **Como corrigir:** escreva o que falta hoje, mesmo que curto.
