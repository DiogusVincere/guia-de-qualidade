# Guia de qualidade para agentes

[![conferir](https://github.com/DiogusVincere/guia-de-qualidade/actions/workflows/conferir.yml/badge.svg)](https://github.com/DiogusVincere/guia-de-qualidade/actions/workflows/conferir.yml)

Um conjunto de regras e listas de verificação, em português, que qualquer agente de código (Claude Code, Codex,
Gemini CLI, Cursor, Copilot) ou pessoa lê antes de mexer num projeto: segurança, QA, dados pessoais, dependências,
deploy, acessibilidade, desktop, mobile e automações com certificado digital. A regra que amarra tudo: **nenhuma
ponta solta sem registro**. O que não foi feito aparece no relatório de entrega com motivo, risco e onde ficou
anotado.

Cada item de cada lista tem quatro campos: o que conferir, por que, **como verificar** (um comando, um teste ou uma
observação concreta) e como corrigir. Nada de "siga boas práticas".

## Estrutura

```
AGENTS.md                      o contrato de uma página: regras inegociáveis, fluxo de trabalho, qual lista abrir
CLAUDE.md                      aponta para o AGENTS.md (o Claude Code lê este nome)
checklists/
  00-antes-de-entregar.md      a definição de pronto, para qualquer projeto
  01-segredos-e-configuracao.md
  02-seguranca-web.md
  03-apis.md
  04-autenticacao-e-sessao.md
  05-dados-pessoais.md
  06-qa-e-testes.md
  07-dependencias-e-ci.md
  08-acessibilidade-e-celular.md
  09-performance.md
  10-deploy-e-operacao.md
  11-desktop-python.md
  12-apps-flutter.md
  13-automacoes-certificado-webservices.md
skills/                        as listas em formato Agent Skills, para o agente carregar sob demanda
  revisar-seguranca/
  qa-antes-de-entregar/
  checklist-de-entrega/
modelos/
  RELATORIO-DE-ENTREGA.md      o que o agente preenche ao terminar
  AGENTS-exemplo.md            como um projeto importa este guia
ferramentas/conferir.py        valida o próprio guia (ids únicos, quatro campos por item, links existentes)
.claude-plugin/                manifesto de plugin e de marketplace do Claude Code
```

## Como usar

**No Claude Code, para todos os projetos da máquina**

```
/plugin marketplace add DiogusVincere/guia-de-qualidade
/plugin install guia-de-qualidade@guia-de-qualidade
```

Ficam disponíveis `/revisar-seguranca` (revisa o projeto ou o diff contra as listas de segurança),
`/qa-antes-de-entregar` (percorre a lista de QA e a de pronto) e `/checklist-de-entrega` (gera o relatório de
entrega preenchido). O agente também passa a usar as skills sozinho quando reconhece a situação.

**Num repositório, para qualquer agente**

Copie a pasta (ou adicione como submódulo) em `docs/guia-de-qualidade/` e escreva no `AGENTS.md` do projeto:

```
Antes de qualquer alteração, leia e siga docs/guia-de-qualidade/AGENTS.md.
Este projeto é: site web + API + guarda dado de pessoa. Listas obrigatórias: 00, 01, 02, 03, 04, 05, 06, 07, 09, 10.
```

No `CLAUDE.md` do projeto, uma linha basta: `@docs/guia-de-qualidade/AGENTS.md`. Modelo completo em
[`modelos/AGENTS-exemplo.md`](modelos/AGENTS-exemplo.md).

**Num chat, sem repositório**

Cole o link do arquivo bruto do `AGENTS.md` e da lista que interessa, por exemplo
`https://raw.githubusercontent.com/DiogusVincere/guia-de-qualidade/main/checklists/02-seguranca-web.md`.
Cada lista funciona sozinha.

## De onde vêm os itens

De projetos reais: uma loja em Nuxt no Cloudflare Workers revisada por segurança, correção e QA; robôs que consultam
web services públicos com certificado A1; ferramentas desktop que leem planilhas de clientes em layouts que mudam
sem aviso; integrações com Outlook. Os erros que aconteceram viraram itens. As referências externas são o OWASP
Application Security Verification Standard, o OWASP Top 10 e a LGPD; o guia traduz o que elas pedem para verificações
que cabem numa tarde.

## Conferir o guia

```
python ferramentas/conferir.py
```

Falha se algum item estiver sem um dos quatro campos, se houver id repetido, se um link interno apontar para arquivo
inexistente, se um manifesto de plugin estiver inválido ou se aparecer e-mail pessoal, CNPJ ou CPF formatado. O
workflow de CI roda isso a cada push. A lista de termos do escritório e dos clientes (nomes, códigos, caminhos de
rede) não entra no código: vai no segredo `TERMOS_PROIBIDOS` do repositório, separada por vírgula, e o validador a
usa sem imprimir os termos no log.

## Contribuir

Erro novo que aconteceu de verdade vira item, com os quatro campos e um exemplo neutro. Item que nunca pegou nada em
seis meses pode sair. Nenhum exemplo pode citar empresa, cliente ou pessoa real.

## Licença

[MIT](LICENSE).
