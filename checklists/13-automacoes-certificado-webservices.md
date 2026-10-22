# 13 · Automações com certificado digital e web services

Para robôs que consultam ou enviam dados a serviços públicos ou de terceiros com certificado A1 (mTLS, XML
assinado), que percorrem portais, que rodam em lote para várias empresas. Os itens de [01 Segredos](01-segredos-e-configuracao.md)
e [06 QA](06-qa-e-testes.md) são pré-requisito.

### CERT-01 · Certificado e senha nunca saem da máquina autorizada
- **Conferir:** o `.pfx` não é enviado a servidor próprio nem a serviço de terceiro; interface local escuta só em 127.0.0.1; a senha fica em memória durante a execução e é descartada; a chave privada em PEM só existe em pasta temporária apagada no `finally`.
- **Por quê:** certificado de cliente é identidade jurídica; quem tem o arquivo e a senha assina por ele.
- **Como verificar:** depois de uma execução, `find` por `.pem`/`.key`/`.pfx` novos na pasta temporária e na do projeto: nada; nenhum log contém a senha; a opção "hospedada" não existe, por decisão.
- **Como corrigir:** `tempfile.mkdtemp` + `shutil.rmtree` em `finally`; `SenhaProvider` em memória com `esquecer()`.

### CERT-02 · O CNPJ vem de dentro do certificado, não do nome do arquivo
- **Conferir:** leitura do CN ou do `otherName` ICP-Brasil; validade conferida antes de usar; o certificado mais recente válido é escolhido por CNPJ.
- **Por quê:** nome de arquivo mente; certificado vencido é recusado pelo serviço com erro genérico.
- **Como verificar:** teste com dois `.pfx` do mesmo CNPJ (um vencido) e nome de arquivo errado: escolhe o válido pelo conteúdo.
- **Como corrigir:** `cryptography` lê o certificado; `validade > agora` antes de usar.

### CERT-03 · Só certificado que a pessoa está autorizada a usar
- **Conferir:** a ferramenta e a documentação deixam claro que o certificado é da empresa dona dos dados; demonstração e gravação de prova usam certificado próprio ou dado simulado, nunca o de um cliente.
- **Por quê:** usar certificado de cliente para portfólio ou teste é uso indevido de identidade.
- **Como verificar:** README e tela dizem isso; o modo simulado existe para quem não tem certificado à mão.
- **Como corrigir:** acrescente o aviso; crie o modo simulado.

### CERT-04 · Toda chamada tem timeout, pausa e backoff, e respeita `Retry-After`
- **Conferir:** `timeout=` em cada requisição; pausa fixa entre chamadas e entre empresas; backoff crescente em 429/5xx e em queda de rede; limite de tentativas; nunca laço infinito.
- **Por quê:** serviço público tem limite de uso; quem abusa é bloqueado por CNPJ, e o bloqueio é do cliente.
- **Como verificar:** teste com servidor falso que devolve 429 com `Retry-After: 30`: o robô espera pelo menos 30 s; após N falhas, desiste com mensagem e guarda o que já veio.
- **Como corrigir:** constantes `PAUSA`, `BACKOFF`, `REPETE`; `max(backoff, retry_after)`.

### CERT-05 · Incremental e idempotente: rodar de novo não repete nem perde
- **Conferir:** o cursor (NSU, página, data) é guardado por empresa só depois de salvar o que veio; o que é de outra competência ou de outro papel vai para um arquivo, não para o lixo; rodar duas vezes gera o mesmo resultado.
- **Por quê:** a primeira execução pode cair no meio; a segunda não pode começar do zero nem pular o que faltou.
- **Como verificar:** teste que interrompe após o primeiro lote: o cursor não avançou além do salvo; segunda execução completa sem duplicar arquivo.
- **Como corrigir:** gravação atômica do estado (arquivo temporário + `replace`); `guardar_cursor` após `salvar`.

### CERT-06 · O que o XML diz é lido, nunca deduzido
- **Conferir:** valores (retenções, totais, situação) vêm dos campos; quando o leiaute só traz a soma, a soma é registrada como soma; total informado é conferido com a soma lida e a diferença vira aviso "conferir", não ajuste silencioso.
- **Por quê:** campo que mudou de significado numa nota técnica (por exemplo, soma de contribuições num campo que antes era um tributo só) gera número errado por meses se o robô "calcula".
- **Como verificar:** testes com XML sintético para cada versão do leiaute (antes e depois da mudança) e para o total divergente: a nota sai marcada.
- **Como corrigir:** tabela de códigos com data de vigência; `divergencia()` no modelo; comentário no leitor citando a nota técnica.

### CERT-07 · Travas antes de gravar em portal de terceiro
- **Conferir:** antes de confirmar um formulário em portal (escrituração, declaração), o robô lê de volta o que o portal mostra e compara com a origem (número do documento, valor, imposto recalculado); diverge, descarta e vira pendência; consulta anti-duplicidade antes de incluir.
- **Por quê:** o portal aplica padrão próprio (alíquota, tipo) e gravar errado é retificação com multa.
- **Como verificar:** teste com portal simulado que calcula errado 1 em 7: a nota errada aparece como pendência e nunca é gravada; rodar duas vezes gera "já escriturada".
- **Como corrigir:** `Previa` + `conferir_antes_de_gravar` + ledger local do que já foi gravado.

### CERT-08 · Falha numa empresa não para o lote
- **Conferir:** exceção vira linha de pendência no relatório daquela empresa e o laço segue; o relatório final lista todas as pendências com motivo; nada é "concluído" se tudo falhou.
- **Por quê:** lote de 200 empresas não pode morrer na 37ª.
- **Como verificar:** teste com extrator que lança erro numa empresa: as demais são processadas e o relatório mostra a pendência.
- **Como corrigir:** `try/except` por empresa com `log.exception` e `res.erros.append`.

### CERT-09 · Competência e papel definidos por regra escrita, não por palpite
- **Conferir:** competência = mês da emissão (ou a regra que o projeto fixou), aplicada igual nas duas fontes; papel (tomada/prestada) decidido pelo CNPJ nos campos certos, considerando quem emitiu; pasta de destino reaproveita a que a equipe criou à mão em qualquer grafia.
- **Por quê:** regra implícita gera nota na pasta errada e duas pastas para o mesmo mês.
- **Como verificar:** testes com `dhProc` em outro mês que `dhEmi`, com pastas `09-2026`/`09.2026`/`092026` existentes, com nota em que o emitente não é o prestador.
- **Como corrigir:** função única `competencia_de()` e `papel_de()` com testes de tabela.

### CERT-10 · Sem navegador quando há web service; com navegador, sem credencial no código
- **Conferir:** integração por API/SOAP documentada sempre que exista; automação por navegador só onde não há alternativa, com a sessão aberta pela pessoa e nunca com senha digitada pelo robô.
- **Por quê:** navegador é frágil e lento; senha no robô é vazamento e viola a regra de nunca fazer login por alguém.
- **Como verificar:** nenhum `send_keys(senha)`/`fill(password)` no código; o passo de login está documentado como ação da pessoa.
- **Como corrigir:** troque por web service; onde não há, reaproveite a sessão aberta e documente.

### CERT-11 · Dado de terceiro no XML não vira identificação da empresa
- **Conferir:** CNPJ de tomador, intermediário ou remetente de um documento não é usado para "descobrir" de quem é o lote; a identidade vem do certificado ou do cadastro.
- **Por quê:** ficha de nota pronta numa mensagem traz o CNPJ do cliente do cliente; usar isso arquiva no lugar errado.
- **Como verificar:** teste com documento cujo tomador é outra empresa cadastrada: o arquivo vai para a empresa do certificado.
- **Como corrigir:** origem da identidade explícita no código; o resto é dado da nota.

### CERT-12 · Log e relatório sem dado sensível, mas com o suficiente para investigar
- **Conferir:** chave da nota, número, CNPJ da empresa (que é pública) podem aparecer; senha, token, conteúdo de certificado e dado pessoal de pessoa física não; cada pendência diz o que fazer.
- **Por quê:** o relatório circula por e-mail; o log fica meses.
- **Como verificar:** leia um relatório e um log de execução completos.
- **Como corrigir:** mascare; reescreva a mensagem da pendência com o próximo passo.
