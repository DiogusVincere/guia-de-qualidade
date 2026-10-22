---
name: qa-antes-de-entregar
description: Percorre a lista de QA e testes e a lista "antes de entregar" do guia de qualidade sobre o trabalho feito na sessão ou num diff: testes rodados agora, bug com teste que reproduz, caminho principal exercitado em 375 px, estados de erro vistos, entrada maliciosa tentada, documentação atualizada, nada fora do escopo. Use para /qa-antes-de-entregar, "faz o QA", "confere antes de entregar", "pode entregar?", "testa tudo", ou sempre que uma tarefa de código estiver prestes a ser dada como pronta.
---

# /qa-antes-de-entregar

Garantia de qualidade antes de dizer "pronto". Usa `${CLAUDE_PLUGIN_ROOT}/checklists/06-qa-e-testes.md` e
`${CLAUDE_PLUGIN_ROOT}/checklists/00-antes-de-entregar.md`, mais as listas de interface quando houver tela
(`08-acessibilidade-e-celular.md`, `09-performance.md`).

## Passos

1. **Delimitar o que foi feito.** `git diff --stat` da base até a árvore de trabalho, mais a lista do que a pessoa
   pediu. Guardar a lista do pedido para o item ENT-01.
2. **Rodar a suíte inteira agora** e guardar o resumo (quantidade, falhas, tempo). Falhou: parar e corrigir antes de
   continuar; não existe "falha conhecida".
3. **Para cada bug corrigido no diff**, localizar o teste que o reproduz (QA-01). Se não existe, escrever, ver
   falhar sem a correção (stash) e passar com ela.
4. **Para cada regra de negócio tocada**, confirmar teste de tabela com casos de borda (QA-02, QA-07): zero,
   negativo, máximo, vírgula e ponto, vazio, acento, duplicado, limite após somar.
5. **Se há interface:** subir o projeto (preferir a configuração de preview do próprio projeto) e exercitar o caminho
   principal como usuário em 375 px e no desktop (QA-05), olhar console e rede, forçar estado vazio, erro de rede e
   sessão expirada (QA-06), tentar entrada maliciosa nos formulários (QA-07). Capturar tela de cada passo.
   Conferir ACE-01, ACE-02, ACE-03, ACE-06 e PERF-01 nas telas tocadas.
6. **Se há build de produção ou pacote:** gerá-lo e exercitar a rota ou o comando principal nele (ENT-08).
7. **Conferir a documentação** (ENT-05): README, AGENTS do projeto, `.env.example`, lista de tarefas. Atualizar no
   mesmo commit.
8. **Conferir o diff** contra o escopo (ENT-09) e contra segredos e dados reais (ENT-04).
9. **Percorrer `00-antes-de-entregar.md` inteira**, marcando cada item.
10. **Produzir o relatório** com `${CLAUDE_PLUGIN_ROOT}/modelos/RELATORIO-DE-ENTREGA.md`. O que não foi verificado
    vai na seção própria com o roteiro para a pessoa testar. O que ficou de fora vai em "Pontas registradas" e no
    arquivo de pendências do projeto.

## Formato da entrega

O relatório de entrega preenchido, sem seção vazia: se "Pontas registradas" não tem linha, escreva "nenhuma";
se "O que NÃO foi verificado" não tem linha, escreva "tudo o que está em 'Como foi verificado' foi executado nesta
sessão".

## Regras

- "Testado" significa executado e observado nesta sessão. Qualquer outra coisa é "não verificado".
- Teste que só passa com `sleep` ou com ordem fixa é bug (QA-03).
- Erro engolido (`except: pass`, `catch {}`) no diff precisa de motivo e de registro (QA-11).
- Produção é só leitura. Nada de escrita em sistema real para "ver se funciona".
- Siga `${CLAUDE_PLUGIN_ROOT}/AGENTS.md` em tudo o que esta skill não cobre.
