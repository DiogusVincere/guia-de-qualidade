# 05 · Dados pessoais

Para qualquer projeto que guarde ou processe dado de pessoa física: nome, e-mail, telefone, CPF, endereço,
pedido, foto, localização, dado de funcionário ou de cliente de um escritório. A referência é a LGPD (Lei
13.709/2018); a lista traduz os princípios em verificações. Não substitui orientação jurídica para casos sensíveis
(saúde, menores, biometria).

### DAD-01 · Cada dado pessoal guardado tem motivo escrito
- **Conferir:** inventário simples (uma tabela) com o campo, para que serve, onde fica, por quanto tempo e quem vê.
- **Por quê:** a LGPD exige finalidade e necessidade; na prática, o inventário é o que impede o campo "só por via das dúvidas".
- **Como verificar:** `docs/DADOS.md` (ou seção no README) existe e cobre todos os campos pessoais do esquema do banco e dos formulários.
- **Como corrigir:** escreva a tabela; o campo sem motivo sai do formulário.

### DAD-02 · Coleta o mínimo
- **Conferir:** formulários pedem só o que a finalidade exige. Loja sem cadastro não pede CPF; pedido por WhatsApp pede nome e telefone, não endereço completo se não entrega.
- **Por quê:** o que não se coleta não vaza.
- **Como verificar:** compare cada campo do formulário com o inventário. Campo opcional que ninguém usa é candidato a sair.
- **Como corrigir:** remova o campo e a coluna; migração de banco que apaga o que já foi coletado sem motivo.

### DAD-03 · A pessoa sabe o que acontece com o dado antes de enviar
- **Conferir:** aviso curto perto do botão (quem recebe, para quê, canal de contato), política de privacidade acessível, sem caixa pré-marcada.
- **Por quê:** transparência é exigência e é confiança.
- **Como verificar:** abra o formulário em celular: o aviso está visível sem rolar para fora do contexto; a política abre e está em português claro.
- **Como corrigir:** uma frase ao lado do botão basta no começo; política em página própria.

### DAD-04 · Dado pessoal não aparece em log, URL, mensagem de erro nem repositório
- **Conferir:** logs de requisição mascaram e-mail e telefone; nenhum dado pessoal em query string; seeds e fixtures usam dados fictícios declarados; capturas de tela anonimizadas.
- **Por quê:** log vai para terceiro, URL fica em histórico, repositório é clonado.
- **Como verificar:** `grep -rniE "@gmail|@hotmail|\b[0-9]{3}\.[0-9]{3}\.[0-9]{3}-[0-9]{2}\b|\(1[0-9]\) 9" . --include=*.py --include=*.ts --include=*.sql --include=*.json --include=*.md` vazio ou só com exemplos fictícios óbvios. Leia um log de produção de 5 minutos.
- **Como corrigir:** mascare no logger; gere dados fictícios com semente; troque exemplos reais por `Cliente Exemplo Ltda`.

### DAD-05 · Acesso restrito a quem precisa, e registrado
- **Conferir:** dado pessoal só em rota autenticada com o perfil certo; o painel mostra o necessário para a tarefa; existe registro de quem exportou ou apagou.
- **Por quê:** o vazamento mais comum é interno e por conveniência.
- **Como verificar:** rota pública de listagem não devolve e-mail/telefone de ninguém; exportação de clientes exige admin e deixa linha de auditoria.
- **Como corrigir:** serialize por perfil; tabela de auditoria para exportar/apagar.

### DAD-06 · Dado tem prazo e existe rotina para apagar
- **Conferir:** pedidos concluídos, contatos antigos, logs e cópias de segurança têm prazo definido no inventário e um mecanismo que apaga ou anonimiza.
- **Por quê:** guardar para sempre é o padrão quando ninguém decide, e é o que dá mais trabalho num incidente.
- **Como verificar:** rode a rotina de limpeza em ambiente de teste com dados vencidos: eles somem ou viram anônimos; a cópia de segurança respeita o mesmo prazo.
- **Como corrigir:** comando ou tarefa agendada de limpeza; anonimização quando o registro precisa continuar existindo (pedido para contabilidade, por exemplo).

### DAD-07 · A pessoa consegue pedir acesso, correção e exclusão, e o pedido é atendido
- **Conferir:** canal publicado (e-mail ou formulário), procedimento interno escrito, prazo de resposta (a lei fala em 15 dias para a confirmação detalhada).
- **Por quê:** é direito do titular e é o que a fiscalização pergunta primeiro.
- **Como verificar:** a política diz o canal; `docs/OPERACAO.md` diz como achar e apagar todos os registros de uma pessoa (consulta pronta).
- **Como corrigir:** escreva a consulta de busca por e-mail/CPF em todas as tabelas e o passo a passo.

### DAD-08 · Terceiros que recebem dado estão listados e têm contrato ou termo
- **Conferir:** hospedagem, CDN, provedor de e-mail, armazenamento de imagens, analytics, WhatsApp/Meta, planilhas na nuvem.
- **Por quê:** operador em outro país ou sem termo é responsabilidade de quem coletou.
- **Como verificar:** o inventário tem a coluna "quem mais recebe"; cada serviço tem termos de tratamento de dados aceitos pela pessoa dona do projeto (não pelo agente).
- **Como corrigir:** liste; troque o serviço que não oferece termo; registre no relatório que o aceite é da pessoa.

### DAD-09 · Em trânsito e em repouso, protegido
- **Conferir:** HTTPS em tudo (HSTS), banco e cópias de segurança criptografados pelo provedor ou pela aplicação, arquivos com dado pessoal fora da raiz pública.
- **Por quê:** o mínimo técnico que a lei chama de "medidas de segurança".
- **Como verificar:** `curl -sI http://seu-site/` redireciona para HTTPS; painel do provedor confirma criptografia do armazenamento; nenhum arquivo pessoal acessível por URL direta.
- **Como corrigir:** force HTTPS no servidor; ative criptografia do provedor; mova arquivos para armazenamento privado com URL assinada.

### DAD-10 · Existe um plano para quando vazar
- **Conferir:** quem é avisado, como se descobre a extensão (logs, auditoria), como se comunica aos titulares e à autoridade, como se troca segredo.
- **Por quê:** o prazo de comunicação é curto e ninguém pensa com calma durante o incidente.
- **Como verificar:** `docs/OPERACAO.md` tem a seção "Incidente" com os passos e os contatos (sem dados pessoais do time no repositório público).
- **Como corrigir:** escreva meia página. Melhor incompleta do que inexistente.
