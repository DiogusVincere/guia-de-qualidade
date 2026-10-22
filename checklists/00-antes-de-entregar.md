# 00 · Antes de entregar

A definição de pronto. Vale para qualquer projeto e qualquer tamanho de tarefa, de um ajuste de texto a um sistema
novo. Percorra em ordem; o que não se aplica se declara "não se aplica" com o motivo. O resultado vai para o
[relatório de entrega](../modelos/RELATORIO-DE-ENTREGA.md).

### ENT-01 · O pedido foi atendido inteiro, não só a parte fácil
- **Conferir:** cada frase do pedido original tem uma linha correspondente em "O que foi feito" ou em "Pontas registradas".
- **Por quê:** o erro mais comum de entrega é fazer 80% e descrever como 100%. A pessoa só descobre depois.
- **Como verificar:** releia o pedido como foi escrito e marque, item a item, feito / adiado / impossível. Se "adiado" ou "impossível", precisa de motivo e registro.
- **Como corrigir:** termine o que falta ou mova para "Pontas registradas" com os quatro campos. Nunca omita.

### ENT-02 · Os testes rodaram agora, não "da última vez"
- **Conferir:** a suíte completa foi executada depois da última alteração e passou.
- **Por quê:** a última mudança é a que quebra. Teste rodado antes dela não prova nada.
- **Como verificar:** rode o comando de teste do projeto e cole o resumo (quantidade, falhas, tempo) no relatório. Em CI, espere o workflow ficar verde no commit final.
- **Como corrigir:** falhou, corrige antes de entregar. Teste "instável" é bug até prova em contrário.

### ENT-03 · O que foi verificado está escrito como foi verificado
- **Conferir:** toda afirmação de funcionamento tem o comando, o teste ou a observação ao lado.
- **Por quê:** "deve funcionar" e "testei" sem evidência não ajudam quem recebe nem quem revisa depois.
- **Como verificar:** no relatório, a tabela "Como foi verificado" não tem linha sem a coluna "Como".
- **Como corrigir:** rode a verificação que falta ou mova a afirmação para "O que NÃO foi verificado".

### ENT-04 · Nada de segredo, dado real ou caminho interno saiu junto
- **Conferir:** diff, mensagens de commit, capturas de tela, relatório e exemplos.
- **Por quê:** o vazamento mais comum não está no código, está no exemplo "só para ilustrar" ou no print.
- **Como verificar:** `git diff --cached | grep -inE "senha|password|secret|token|api[_-]?key|BEGIN (RSA|PRIVATE)|@gmail|cnpj|\\\\\\\\[a-z0-9]+\\\\"` (ajuste os termos ao projeto) e olhe cada captura de tela. Rode também a busca por nomes de clientes que o projeto proíbe.
- **Como corrigir:** retire antes do commit. Se já foi para um remoto público, troque o segredo e reescreva o histórico; apagar só o arquivo não resolve.

### ENT-05 · Documentação mudou junto com o comportamento
- **Conferir:** README, AGENTS do projeto, `.env.example`, lista de tarefas e textos de ajuda refletem o que o código faz agora.
- **Por quê:** o próximo agente lê a documentação, não o diff. Documentação velha produz erro novo.
- **Como verificar:** para cada variável, comando, rota, pasta ou regra que mudou, encontre a menção na documentação e confira.
- **Como corrigir:** atualize no mesmo commit. Se a documentação não existe, crie o mínimo: como rodar, como testar, o que precisa de configuração.

### ENT-06 · A pessoa sabe o que só ela pode fazer
- **Conferir:** a seção "O que a pessoa precisa fazer" lista login, troca de segredo, aprovação de texto, compra de domínio, publicação.
- **Por quê:** o agente não faz login nem publica por ninguém. Se não disser o que falta, o trabalho fica parado sem ninguém saber.
- **Como verificar:** releia o fluxo até produção e marque cada passo que exige credencial ou decisão humana.
- **Como corrigir:** escreva o passo com o comando ou o caminho exato e o que esperar como resultado.

### ENT-07 · Ponta solta tem nome, motivo, risco e lugar
- **Conferir:** tudo o que ficou de fora está na tabela "Pontas registradas" e anotado no lugar que o projeto usa (lista de tarefas, issue, documento de revisão).
- **Por quê:** a ponta que fica só na cabeça do agente some quando a sessão acaba.
- **Como verificar:** compare a tabela do relatório com o arquivo de tarefas do projeto. Cada linha de um existe no outro.
- **Como corrigir:** registre agora. Se não há lugar definido, crie `docs/TAREFAS.md` com a seção "Pendências" e avise.

### ENT-08 · Rodou no ambiente parecido com o de verdade
- **Conferir:** além dos testes, a aplicação subiu (build de produção, servidor local, executável) e o caminho principal foi exercitado.
- **Por quê:** teste unitário passa com módulo quebrado em produção: variável de ambiente que falta, arquivo que não entrou no pacote, cabeçalho que o servidor remove.
- **Como verificar:** build de produção sem erro; a página ou o comando principal respondem; em site, `curl -sI` na URL local de produção mostra os cabeçalhos esperados.
- **Como corrigir:** o que só aparece no build vira teste de fumaça (um teste que sobe o pacote e pede a rota principal).

### ENT-09 · Nada mudou fora do pedido sem aviso
- **Conferir:** o diff contém só o que a tarefa exigia. Refatoração oportunista, formatação em massa e "já aproveitei e..." foram combinados antes.
- **Por quê:** mudança fora do escopo esconde a mudança pedida e dificulta reverter.
- **Como verificar:** `git diff --stat` e leia a lista de arquivos. Arquivo que a pessoa não espera ver precisa de uma frase no relatório.
- **Como corrigir:** separe em outro commit ou reverta. Se valeu a pena, diga por quê.

### ENT-10 · A mensagem final se sustenta sozinha
- **Conferir:** quem lê só a última mensagem entende o resultado, o que importa e o que falta, sem abrir o histórico.
- **Por quê:** a pessoa muitas vezes não viu nada do processo.
- **Como verificar:** releia a mensagem como se fosse a primeira. Resultado na primeira frase; números em tabela ou linha própria; nome de arquivo só quando a pessoa precisa ir lá.
- **Como corrigir:** reescreva. Corte o que descreve o processo e mantenha o que descreve o estado.
