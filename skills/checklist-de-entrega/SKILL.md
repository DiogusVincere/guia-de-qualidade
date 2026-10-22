---
name: checklist-de-entrega
description: Gera o relatório de entrega do guia de qualidade para o trabalho da sessão: o que foi pedido, o que foi feito, como foi verificado (com comando ou teste), o que não foi verificado, pontas registradas com motivo e risco, e o que a pessoa precisa fazer. Use para /checklist-de-entrega, "monta o relatório de entrega", "resume o que foi feito", "o que ficou pendente", ao fechar uma tarefa, ao escrever a descrição de um pull request ou a mensagem final para a pessoa.
---

# /checklist-de-entrega

Preenche `${CLAUDE_PLUGIN_ROOT}/modelos/RELATORIO-DE-ENTREGA.md` com o que aconteceu na sessão (ou no diff
indicado) e confere `${CLAUDE_PLUGIN_ROOT}/checklists/00-antes-de-entregar.md` item a item. É a última coisa
que o agente faz antes de entregar; serve de corpo de pull request e de mensagem final.

## Passos

1. **Recuperar o pedido** nas palavras da pessoa (primeira mensagem da tarefa e os acréscimos no meio).
2. **Listar o que foi feito** a partir de `git diff --stat` e `git log` da sessão, no passado, sem adjetivo. Uma
   linha por mudança de comportamento; mudanças só de formatação viram uma linha só.
3. **Montar a tabela "Como foi verificado"** com as verificações que realmente rodaram na sessão: comando e
   resultado. Se a suíte não rodou depois da última alteração, rodar agora e usar esse resultado.
4. **Separar o não verificado.** Tudo o que depende de credencial, ambiente, hardware ou de outra pessoa, com o
   roteiro para a pessoa testar (passos, entrada, resultado esperado).
5. **Comparar pedido × feito** (ENT-01). Cada frase do pedido vira "feito", ou uma linha em "Pontas registradas"
   com: ponta, por que ficou, risco se ficar, onde está anotado. Se não está anotado em lugar nenhum do projeto,
   anotar agora (lista de tarefas, documento de revisão ou issue) e só então preencher a coluna.
6. **Listar o que a pessoa precisa fazer**: login, trocar segredo, aprovar texto, comprar domínio, publicar,
   instalar. Com o comando ou o caminho exato.
7. **Percorrer `00-antes-de-entregar.md`** e registrar, no fim do relatório, quais listas do guia foram percorridas
   na tarefa, quais ficaram completas e quais itens ficaram pendentes (com id).
8. **Reler a mensagem como se fosse a primeira** (ENT-10): resultado na primeira frase; o que importa; o que falta.
   Cortar o que descreve o processo.

## Regras

- Nenhuma seção vazia: escreva "nenhuma" ou "tudo verificado nesta sessão" quando for o caso.
- Sem "deve funcionar", "acredito que", "provavelmente". O que não foi visto é "não verificado".
- Nome de arquivo ou função só quando a pessoa precisa ir lá; no máximo um por frase.
- Número vai em tabela ou em linha própria, não no meio do parágrafo.
- Siga `${CLAUDE_PLUGIN_ROOT}/AGENTS.md` em tudo o que esta skill não cobre.
