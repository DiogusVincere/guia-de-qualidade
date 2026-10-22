# Guia de qualidade para agentes

Este arquivo é o contrato. Qualquer agente (Claude, Codex, Gemini, Cursor, Copilot ou pessoa) que for mexer num
projeto que aponta para este guia lê esta página inteira antes da primeira alteração e segue o que está aqui. As
listas detalhadas ficam em [`checklists/`](checklists/); este arquivo diz o que é inegociável e como o trabalho
termina.

## As regras que não se negociam

1. **Segredo nunca entra no repositório.** Senha, token, chave de API, certificado (`.pfx`, `.pem`, `.key`),
   string de conexão, cookie de sessão. Nem em código, nem em teste, nem em commit antigo, nem em captura de tela.
   Vai para `.env` (ignorado pelo git), para o cofre do serviço de hospedagem ou para o gerenciador de credenciais
   do sistema. Se um segredo vazou, ele é trocado, não só apagado.
2. **Nada vai para produção sem os testes passando.** Teste vermelho não se "pula", não se comenta, não se marca como
   esperado para passar. Corrige-se o código ou o teste, e se diz qual dos dois estava errado.
3. **Toda escrita vinda de fora é hostil até prova em contrário.** Corpo de requisição, parâmetro, cabeçalho, arquivo
   enviado, planilha do cliente, XML de terceiro, texto colado. Valida-se formato, tamanho e faixa antes de usar,
   e o que não passa recebe uma resposta clara (400, aviso na tela), nunca um erro genérico nem um comportamento
   silencioso.
4. **O agente não faz login por ninguém.** Não digita senha, não roda fluxo de autenticação, não aceita termos, não
   troca visibilidade de repositório, não apaga dado de produção, não envia e-mail ou mensagem, não paga nada. Esses
   passos são da pessoa; o agente prepara, explica e espera.
5. **Produção é só leitura, salvo pedido explícito.** Nada de POST, PUT, PATCH ou DELETE em sistema no ar para
   "testar". Teste se faz em ambiente local ou de homologação, com dado fictício.
6. **Dado de cliente e de empresa não sai do lugar.** Pasta de cliente é somente leitura quando o projeto diz isso.
   Repositório público não recebe nome, CNPJ, e-mail, telefone, código interno, caminho de rede nem exemplo
   "parecido com o real". Exemplo é fictício e se declara fictício.
7. **Corrigir bug começa pelo teste que reproduz o bug.** Primeiro o teste falha, depois a correção, depois o teste
   passa. Sem isso, a correção é um palpite.
8. **Mudança de comportamento muda a documentação no mesmo commit.** README, AGENTS do projeto, lista de tarefas,
   variáveis de ambiente de exemplo. Documentação que fica para depois não fica.
9. **O que o agente não consegue verificar, ele diz que não verificou.** "Testado" significa que rodou e viu o
   resultado. "Deve funcionar" não existe no relatório de entrega.
10. **Nenhuma ponta solta sem registro.** Tudo o que ficou fora do escopo, foi adiado, está incerto ou depende de
    outra pessoa aparece no relatório de entrega com nome, motivo, risco e onde ficou anotado. "Fica para depois"
    sem anotação é falha de entrega, não economia de tempo.

## Como o trabalho acontece

**Antes de começar**

- Ler o `AGENTS.md` ou `CLAUDE.md` do projeto. Regras do projeto valem sobre as deste guia quando forem mais
  restritivas; nunca o contrário.
- Identificar o tipo do projeto e abrir as listas que se aplicam (tabela abaixo). Sites e APIs usam pelo menos
  cinco listas; um script de linha de comando usa duas. Na dúvida, abre-se a lista e se descarta item a item.
- Confirmar como se roda o projeto e os testes localmente. Se não dá para rodar, isso é a primeira pendência.

**Durante**

- Alteração pequena e verificável, uma de cada vez. Rodar o teste que cobre o trecho antes de seguir.
- Toda decisão de regra de negócio ambígua vira pergunta para a pessoa, com opção recomendada e exemplo real.
  Decisão técnica ou cosmética o agente toma e avisa.
- Commit só do que o agente mexeu. Com outras pessoas no mesmo repositório, não se usa `git add -A` sem olhar.

**Antes de entregar**

- Percorrer [`checklists/00-antes-de-entregar.md`](checklists/00-antes-de-entregar.md) item a item.
- Preencher o [relatório de entrega](modelos/RELATORIO-DE-ENTREGA.md): o que foi feito, como foi verificado (com o
  comando ou o teste), o que ficou de fora e por quê, o que a pessoa precisa fazer.
- A última mensagem para a pessoa se sustenta sozinha: resultado primeiro, depois o que importa, depois o que
  falta. Sem "acho que", sem "deve estar".

## Qual lista abrir

| Tipo de projeto | Listas obrigatórias |
|---|---|
| Qualquer um | [00 Antes de entregar](checklists/00-antes-de-entregar.md), [01 Segredos e configuração](checklists/01-segredos-e-configuracao.md), [06 QA e testes](checklists/06-qa-e-testes.md), [07 Dependências e CI](checklists/07-dependencias-e-ci.md) |
| Site ou aplicação web | + [02 Segurança web](checklists/02-seguranca-web.md), [04 Autenticação e sessão](checklists/04-autenticacao-e-sessao.md), [08 Acessibilidade e celular](checklists/08-acessibilidade-e-celular.md), [09 Performance](checklists/09-performance.md), [10 Deploy e operação](checklists/10-deploy-e-operacao.md) |
| API | + [03 APIs](checklists/03-apis.md), [04 Autenticação e sessão](checklists/04-autenticacao-e-sessao.md), [10 Deploy e operação](checklists/10-deploy-e-operacao.md) |
| Guarda dado de pessoa (nome, e-mail, CPF, endereço, pedido) | + [05 Dados pessoais](checklists/05-dados-pessoais.md) |
| Aplicativo desktop em Python | + [11 Desktop em Python](checklists/11-desktop-python.md) |
| Aplicativo Flutter | + [12 Apps Flutter](checklists/12-apps-flutter.md) |
| Automação com certificado digital ou web service | + [13 Automações com certificado e web services](checklists/13-automacoes-certificado-webservices.md) |

## Como conectar este guia a um projeto

- **Claude Code, em todos os projetos da máquina:** `/plugin marketplace add DiogusVincere/guia-de-qualidade` e
  depois `/plugin install guia-de-qualidade@guia-de-qualidade`. As skills `/revisar-seguranca` (lê o código),
  `/testar-seguranca` (roda o scanner contra um site seu), `/qa-antes-de-entregar` e `/checklist-de-entrega`
  passam a existir.
- **Num repositório, para qualquer agente:** copiar este guia para `docs/guia-de-qualidade/` (ou adicionar como
  submódulo) e pôr no `AGENTS.md` do projeto a linha
  `Antes de qualquer alteração, leia e siga docs/guia-de-qualidade/AGENTS.md.` O `CLAUDE.md` do projeto pode
  importar direto: `@docs/guia-de-qualidade/AGENTS.md`. Modelo em [`modelos/AGENTS-exemplo.md`](modelos/AGENTS-exemplo.md).
- **Num chat, sem repositório:** colar o link do arquivo bruto (`raw.githubusercontent.com/...`) deste `AGENTS.md`
  e da lista que interessa. Cada lista funciona sozinha.

## Teste ativo: o scanner

Além das listas (que se leem), o guia tem um scanner que **roda de verdade** contra um site, em
[`testes-ativos/`](testes-ativos/). Ele testa TLS, cabeçalhos, cookies, arquivos e rotas expostos, XSS/SQL/
traversal/template refletidos, autenticação e CORS, e carga. É não destrutivo: as cargas de injeção detectam a
falha, não alteram dado. Travas que não se desligam por opção: sem declaração de autorização não roda; escrita
nunca acontece em produção; o estresse é limitado em produção. Use pela skill `/testar-seguranca` ou direto:
`python testes-ativos/scanner.py --alvo https://SEU-SITE --autorizo "é meu"`. Só contra um site seu ou que você
tem permissão para testar — nunca de terceiro.

## O que este guia não é

Não é norma nem auditoria formal. É o conjunto de verificações que evitam os erros que já aconteceram: cabeçalho
de segurança que sumiu no deploy, limite de tentativas que não existia, semente de banco que apagava produção,
planilha de cliente com coluna trocada que gerou número absurdo sem aviso, senha no nome do arquivo do
certificado. Cada item das listas tem o que conferir, por que, como verificar e como corrigir. Quando um erro novo
aparecer, ele vira item.
