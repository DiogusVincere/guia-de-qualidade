# 20 · Camadas e ferramentas

Segurança não é uma ferramenta, são camadas. Nenhuma pega tudo; cada uma cobre o que a outra não vê. Esta lista é o
mapa do que um programa de segurança usa e como o guia se encaixa, para você ligar cada camada sem comprar nada —
tudo com ferramenta livre. O scanner (`testes-ativos/`) é a camada DAST e integra as outras por baixo quando
instaladas.

### REF-01 · DAST — testar o site rodando
- **Conferir:** você roda um teste dinâmico contra o site no ar (cabeçalhos, injeção, autenticação, exposição).
- **Por quê:** é o ponto de vista do atacante; pega o que só aparece com o sistema em execução.
- **Como verificar:** rode o scanner do guia (`python testes-ativos/scanner.py --alvo ...`) ou o OWASP ZAP; para a varredura ampla, o `nuclei`.
- **Como corrigir:** trate os achados por gravidade; confirme no código antes de concluir.

### REF-02 · SAST — analisar o código parado
- **Conferir:** o código-fonte é analisado por uma ferramenta que acha injeção, XSS e padrão inseguro sem rodar o app.
- **Por quê:** acha a falha na origem, antes do deploy, inclusive em caminho que o DAST não alcança.
- **Como verificar:** `semgrep --config auto .` (o scanner liga o semgrep com `--codigo <pasta>`); ou a ferramenta do ecossistema (Bandit para Python, ESLint security para JS).
- **Como corrigir:** corrija a regra apontada; ligue o SAST no CI.

### REF-03 · SCA — vulnerabilidade nas dependências
- **Conferir:** as bibliotecas de terceiro são checadas contra CVE conhecido.
- **Por quê:** a maior parte do código que você entrega é de terceiros; a falha deles vira sua.
- **Como verificar:** `osv-scanner -r .` ou `trivy fs .` (o scanner os liga com `--codigo`); `npm audit`, `pip-audit`.
- **Como corrigir:** atualize a dependência; ver [07 dependências](07-dependencias-e-ci.md).

### REF-04 · Segredo no histórico do git
- **Conferir:** o histórico do repositório é varrido por segredo commitado (mesmo já apagado do código atual).
- **Por quê:** segredo fica no histórico para sempre; é um dos vazamentos mais comuns.
- **Como verificar:** `gitleaks detect --source .` (o scanner o liga com `--codigo`); ou trufflehog.
- **Como corrigir:** troque o segredo; remova do histórico com git filter-repo; ver [01 SEG-01](01-segredos-e-configuracao.md).

### REF-05 · IaC e container — configuração de infraestrutura
- **Conferir:** Dockerfile, Terraform, Kubernetes e afins são checados por erro de configuração.
- **Por quê:** o erro de infra (porta aberta, permissão ampla, imagem vulnerável) derruba o resto.
- **Como verificar:** `trivy config .` ou `checkov -d .`.
- **Como corrigir:** siga a recomendação da ferramenta; ver [10 deploy](10-deploy-e-operacao.md).

### REF-06 · Reconhecimento — mapear a superfície
- **Conferir:** você sabe todos os subdomínios, rotas e URLs antigas expostas.
- **Por quê:** não se protege o que não se sabe que existe.
- **Como verificar:** o scanner faz recon passivo (crt.sh, Wayback) e crawler; ferramentas: subfinder, amass, httpx, ffuf.
- **Como corrigir:** desative o que não usa; proteja o de teste; ver [14 reconhecimento](14-reconhecimento-e-inventario.md).

### REF-07 · Processo — o que ferramenta nenhuma faz
- **Conferir:** modelagem de ameaça do que é crítico, logs e alerta, plano de resposta a incidente, revisão humana.
- **Por quê:** falha de lógica e de projeto não aparece em scanner; é onde o estrago grande mora.
- **Como verificar:** há um documento de ameaças, um de operação ([10](10-deploy-e-operacao.md)) e um de incidente ([05 DAD-10](05-dados-pessoais.md)); revisão de código humana nas partes sensíveis.
- **Como corrigir:** escreva o mínimo de cada; nenhuma automação substitui pensar onde dói.

### REF-08 · Nenhuma camada sozinha é "completo"
- **Conferir:** você não trata uma ferramenta verde como "está seguro".
- **Por quê:** DAST verde não garante código limpo; SAST verde não garante dependência sã; nenhuma vê falha de lógica.
- **Como verificar:** confira que pelo menos DAST + SAST + SCA + segredo rodam, e que há revisão humana do que é crítico.
- **Como corrigir:** ligue as camadas que faltam; o scanner integra DAST + recon e, por baixo, nuclei, semgrep, gitleaks, osv e trivy.
