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
  14-reconhecimento-e-inventario.md
  15-ssrf-e-requisicoes-do-servidor.md
  16-upload-e-arquivos.md
  17-criptografia.md
  18-dominio-e-email.md
  19-cliente-e-dom.md
testes-ativos/                 o scanner que roda de verdade contra um site (não destrutivo, com travas)
  scanner.py                   linha de comando: --alvo, --autorizo, --ambiente, --intensidade, --escrever, --config
  nucleo.py                    o alvo e as travas (autorização, produção só leitura, teto de estresse)
  configuracao.py              estrutura do site para as sondas autenticadas (sem segredo; creds vêm do ambiente)
  sondas.py                    tls, cabecalhos, exposicao, injecao, autenticacao, carga, login
  rastreio.py                  crawler + segredos e source map no front
  autenticado.py               login, IDOR, mass assignment, JWT (homologação)
  logica.py                    adulteração de preço/quantidade e condição de corrida (homologação)
  sondas_rede.py               domínio/e-mail (SPF/DMARC/takeover), SSRF, open redirect, host header, métodos, GraphQL, cliente/DOM
  sondas_app.py                OAuth/SSO, WebSocket (CSWSH) e XSS no DOM (com Playwright opcional)
  nuclei_ponte.py              varredura ampla pelo nuclei, se instalado
  cenarios.py                  "como um atacante usaria isto": encadeia os achados
  relatorio.py                 relatório em Markdown por gravidade, com os cenários
  teste_scanner.py             prova o scanner contra um site de mentira vulnerável, offline
interface/                     página no navegador (127.0.0.1) para rodar o scanner sem linha de comando
  servidor.py                  python interface/servidor.py → http://127.0.0.1:8771/
  web/                         index.html, app.js, estilo.css
  teste_interface.py           prova a interface offline
skills/                        as listas e o scanner em formato Agent Skills, carregados sob demanda
  revisar-seguranca/           revisa o código contra as listas
  testar-seguranca/            roda o scanner contra um site seu
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
`/testar-seguranca` (roda o scanner de verdade contra um site seu), `/qa-antes-de-entregar` (percorre a lista de
QA e a de pronto) e `/checklist-de-entrega` (gera o relatório de entrega preenchido). O agente também passa a usar
as skills sozinho quando reconhece a situação.

## Teste ativo contra um site (o scanner)

As listas se leem; o scanner **roda**. Ele faz requisições de verdade contra uma URL e relata o que o site
respondeu, como um pentest não destrutivo.

```
pip install -r testes-ativos/requirements.txt
python testes-ativos/scanner.py --alvo https://SEU-SITE --autorizo "é meu" --saida relatorio.md
```

Cobre: crawler que descobre rotas (inclusive as escondidas no JavaScript), TLS e HTTPS, cabeçalhos e cookies,
segredos e source map no front, arquivos e rotas expostos (só quando o corpo é mesmo do arquivo, sem confundir com
a página de um SPA), XSS/SQL/traversal/template refletidos, autenticação e CORS, limite e carga por nível. Em
homologação com `--config` e credenciais, também faz varredura autenticada (IDOR, mass assignment, JWT) e testes de
lógica (preço/quantidade adulterados, condição de corrida). Se o `nuclei` estiver instalado, roda a varredura ampla
dele por baixo. O relatório sai por gravidade, com a requisição que reproduz e como corrigir, e termina com **"como
um atacante usaria isto"**, encadeando os achados em cenários.

Cada achado é **suspeita**: o scanner confirma por conteúdo (um `.env` tem de ter linhas `CHAVE=valor`, não a
página do app) e ainda assim o resultado se confere no código antes de concluir. Num site SPA no Cloudflare, por
exemplo, `/admin` responder 200 costuma ser só o shell protegido pela API, não exposição.

**Travas que não se desligam por opção** (em `nucleo.py`, cobertas por teste):

- sem `--autorizo` não roda, e a frase vai no relatório;
- escrita (POST/PUT/PATCH/DELETE) **nunca** em produção, mesmo com `--escrever`;
- o estresse é limitado em produção (teto de nível 2), por mais alto que você peça;
- as cargas de injeção são marcadores que **detectam** a falha, nunca alteram nem apagam dado.

Escrita, teste de bloqueio de login e estresse alto (até nível 5) só com `--ambiente homologacao` ou `local` e
`--escrever`. **Use só contra um site seu ou que você tem permissão para testar.** Achado é suspeita: confirme no
código antes de concluir.

### Interface no navegador

Para rodar sem linha de comando:

```
python interface/servidor.py
```

Abre `http://127.0.0.1:8771/` (só nesta máquina, com token por execução): você digita a URL, declara a
autorização, escolhe o ambiente e o nível, e vê o andamento sonda a sonda e o relatório por gravidade, com os
cenários de ataque e o download do `.md`. As mesmas travas do scanner valem na interface.

### Sondas

São 20, em ordem: `rastreio`, `tls`, `cabecalhos`, `segredos`, `exposicao`, `metodos`, `injecao`,
`redirecionamento` (open redirect, host header, SSRF), `cliente` (SRI, tabnabbing, conteúdo misto), `dom` (XSS no
DOM, com Playwright opcional), `graphql`, `oauth`, `websocket`, `autenticacao`, `autenticado` (IDOR, mass
assignment, JWT), `logica` (adulteração, condição de corrida), `dominio` (SPF/DMARC/takeover), `carga`, `login`,
`nuclei`. As rotas de saúde, login, admin e escrita são candidatos genéricos em português e inglês, ajustáveis por
`--config`, então o scanner funciona em qualquer site seu.

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
