---
name: testar-seguranca
description: Roda o scanner de testes-ativos de verdade contra um site QUE O USUÁRIO CONFIRMA SER DELE ou autorizado — TLS e HTTPS, cabeçalhos, cookies, arquivos e rotas expostos, XSS/SQL/traversal/template refletidos, autenticação e CORS, limite de requisições e carga — e devolve um relatório com gravidade, a requisição que reproduz e como corrigir. Use para /testar-seguranca, "testa a segurança do site de verdade", "tenta hackear meu site", "roda um pentest", "vê se dá para derrubar", "testa todas as variáveis", "procura vulnerabilidade real". NÃO é para site de terceiro.
---

# /testar-seguranca

Teste de segurança ativo e não destrutivo contra um site do usuário, com o scanner em
`${CLAUDE_PLUGIN_ROOT}/testes-ativos/scanner.py`. Diferente de `/revisar-seguranca` (que lê o código), este
**roda requisições de verdade** contra a URL e relata o que o site respondeu.

## Antes de rodar: autorização e alvo

1. **Confirmar com o usuário que o alvo é dele ou que ele tem autorização para testá-lo.** Se a URL não é
   claramente de um projeto do usuário, perguntar. Nunca rodar contra site de terceiro, mesmo a pedido.
2. **Escolher o ambiente.** Produção → só leitura (padrão). Para testar escrita, limite de login e estresse alto,
   pedir um alvo de homologação ou local; esses testes são bloqueados em produção pelo próprio scanner.
3. **Instalar a dependência** uma vez: `pip install -r ${CLAUDE_PLUGIN_ROOT}/testes-ativos/requirements.txt`
   (só `requests`).

## Como rodar

```
# produção, só leitura (o padrão):
python ${CLAUDE_PLUGIN_ROOT}/testes-ativos/scanner.py --alvo https://SITE --autorizo "é meu" --saida relatorio.md

# homologação ou local: libera escrita, teste de login e estresse até o nível 5:
python ${CLAUDE_PLUGIN_ROOT}/testes-ativos/scanner.py --alvo http://localhost:3000 --ambiente local \
    --escrever --intensidade 5 --saida relatorio.md

# só algumas sondas:
python ${CLAUDE_PLUGIN_ROOT}/testes-ativos/scanner.py --alvo https://SITE --autorizo "é meu" --sondas tls,cabecalhos,exposicao
```

Opções: `--ambiente producao|homologacao|local`, `--intensidade 1..5` (produção limitada a 2), `--escrever`
(ignorado em produção), `--pausa SEGUNDOS` (gentileza entre requisições), `--sondas` (lista), `--saida`
(arquivo .md). O scanner sai com código 1 quando há achado crítico ou alto.

## O que o scanner cobre

| Sonda | O que faz |
|---|---|
| rastreio | segue links, sitemap e robots, e vasculha o JS atrás de rotas de API escondidas; alimenta a injeção |
| tls | protocolo negociado, TLS 1.0/1.1 aceitos, HSTS (em todas as respostas), certificado |
| cabecalhos | CSP (e unsafe-inline em script-src), nosniff, Referrer-Policy, clickjacking, cookies, versão vazando |
| segredos | chave de API, token, credencial e source map (.js.map) expostos no front |
| exposicao | `/.git`, `/.env`, `/wrangler.*`, backups, dumps, rotas de debug/semeadura — só quando o CORPO é mesmo do arquivo |
| metodos | métodos HTTP perigosos habilitados (PUT, DELETE, TRACE, CONNECT) |
| injecao | XSS refletido, erro de SQL, traversal, template e entrada longa que derruba, em cada parâmetro descoberto |
| redirecionamento | open redirect, host header injection e indício de SSRF (metadado de nuvem) |
| cliente | script externo sem SRI, tabnabbing (target=_blank sem noopener), conteúdo misto http em página https |
| graphql | introspection ligado (esquema inteiro visível) |
| autenticacao | API de admin sem sessão (crítico), página /admin sem barreira (confirme), saúde vazando, CORS de outra origem — rotas genéricas PT e EN |
| autenticado | login e então IDOR, mass assignment e análise de JWT — só homologação com `--escrever`, `--config` e credenciais |
| logica | preço/quantidade adulterados e condição de corrida (vender além do estoque) — só homologação com `--escrever` |
| dominio | SPF, DMARC e subdomínio sequestrável, via DNS sobre HTTPS (domínio próprio) |
| carga | p50/p95 sob carga do nível escolhido e se aparece 429 (sinal de limite) |
| login | bloqueio por tentativa repetida — só em homologação com `--escrever` |
| nuclei | varredura ampla com o nuclei, se instalado (milhares de testes); sem ele, avisa como instalar |

O relatório termina com **"Como um atacante usaria isto"**: encadeia os achados em cenários (roubo de sessão, painel
exposto, fraude de compra) com gravidade estilo CVSS. Para a varredura autenticada e os testes de lógica, passe
`--config` (estrutura do site, sem segredo — ver `exemplos/alvo.exemplo.json`) e as credenciais por
`SCANNER_USUARIO`/`SCANNER_SENHA` ou `--usuario`/`--senha`.

## Passos da skill

1. Confirmar alvo e autorização (acima).
2. Rodar o scanner com `--saida` num arquivo temporário; para produção, sem `--escrever` e com `--intensidade`
   baixa primeiro.
3. **Ler o relatório e confirmar os achados no código** antes de afirmar. O scanner levanta suspeitas pela
   resposta; um achado de "possível XSS" vira confirmado ao ver o ponto no código, e vira falso positivo (a
   descartar, não a ignorar) quando o código escapa. Cruze cada achado com a lista do guia citada no colchete.
4. Para o que só se testa em homologação (escrita, login, estresse alto), avisar o usuário e, se ele tiver o
   ambiente, rodar lá com `--ambiente homologacao --escrever --intensidade N`.
5. Entregar: o resumo por gravidade, os achados críticos e altos primeiro com o `curl` que reproduz, e o caminho
   de correção. O que não pôde ser testado vira ponta registrada (ver `${CLAUDE_PLUGIN_ROOT}/modelos/RELATORIO-DE-ENTREGA.md`).

## Regras

- Sem autorização do usuário para aquele alvo, não roda. A frase de autorização vai no relatório.
- Produção é só leitura, sempre. Escrita e estresse pesado exigem homologação ou local, por decisão do scanner,
  não por opção que se desligue.
- Achado é suspeita até ser confirmado no código. Não anuncie "o site é vulnerável" sem a confirmação.
- Siga `${CLAUDE_PLUGIN_ROOT}/AGENTS.md` no resto.
