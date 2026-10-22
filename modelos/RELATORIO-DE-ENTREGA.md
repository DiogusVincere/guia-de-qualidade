# Relatório de entrega

Preenchido pelo agente ao terminar uma tarefa. É a última mensagem para a pessoa, ou o corpo do pull request.
Cada linha de "verificado" leva o comando, o teste ou a observação que prova. O que não foi verificado se diz
como não verificado. O que ficou de fora entra em "Pontas registradas" com os quatro campos; sem isso a entrega
não está pronta.

---

## O que foi pedido

Uma ou duas frases, nas palavras da pessoa.

## O que foi feito

- Item por item, no passado, sem adjetivo. Arquivo ou função só quando a pessoa precisa ir lá.

## Como foi verificado

| O quê | Como | Resultado |
|---|---|---|
| Testes automatizados | `python -m unittest discover -s tests` | 112 testes, 0 falhas |
| Cabeçalhos de segurança em produção | `curl -sI https://exemplo.test/` | CSP, HSTS, X-Content-Type-Options, Referrer-Policy presentes |
| Escrita sem Origin | `curl -X POST .../api/pedidos -H 'Origin: https://outro.test'` | 403 |
| Celular 375 px | captura da tela / leitura da página | sem rolagem horizontal, botões ≥ 44 px |

## O que NÃO foi verificado

- Diga o que não rodou e por quê (sem acesso, sem certificado, sem ambiente). Não escreva "deve funcionar".

## Pontas registradas

| Ponta | Por que ficou | Risco se ficar | Onde está anotado |
|---|---|---|---|
| Baixa de estoque de vários itens não é atômica | fora do escopo pedido | pedido simultâneo pode vender além do estoque | `docs/TAREFAS.md`, item 14 |

## O que a pessoa precisa fazer

- Passos que só ela pode dar: login, trocar segredo, comprar domínio, aprovar texto, publicar.

## Listas percorridas

- 00 Antes de entregar: completa
- 02 Segurança web: completa, 2 itens não se aplicam (sem upload, sem iframe)
- 05 Dados pessoais: itens DAD-04 e DAD-07 pendentes, registrados acima
