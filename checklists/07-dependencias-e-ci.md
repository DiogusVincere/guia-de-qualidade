# 07 · Dependências e CI

Para qualquer projeto com gerenciador de pacotes (npm, pip, pub, cargo) e repositório no GitHub ou equivalente.

### DEP-01 · Versões travadas e arquivo de lock versionado
- **Conferir:** `package-lock.json`, `requirements.txt` com versões (ou `uv.lock`/`poetry.lock`), `pubspec.lock` no git; instalação reprodutível (`npm ci`, `pip install -r`).
- **Por quê:** sem lock, o build de hoje é diferente do de ontem e o bug "só acontece em produção".
- **Como verificar:** `git ls-files | grep -E "lock"` mostra o arquivo; CI instala com o comando que respeita o lock.
- **Como corrigir:** gere e versione o lock; troque `npm install` por `npm ci` no CI.

### DEP-02 · Atualização de dependência passa pelos testes antes de entrar
- **Conferir:** Dependabot ou Renovate configurado; todo PR de atualização roda a suíte; o que quebra a CI é investigado, não aceito.
- **Por quê:** atualização cega é a forma mais comum de quebrar produção numa segunda-feira.
- **Como verificar:** `.github/dependabot.yml` existe com agrupamento de menores/correções; o último PR de atualização tem o check de testes verde antes do merge.
- **Como corrigir:** configure; regra de proteção de branch que exige o check.

### DEP-03 · Versão maior que quebra tem motivo registrado para ficar para trás
- **Conferir:** quando uma atualização é ignorada (exige Node mais novo, muda API), o `ignore` do Dependabot tem comentário com o motivo e a condição para remover.
- **Por quê:** "ignorar" sem motivo vira dívida invisível.
- **Como verificar:** cada `ignore` no `dependabot.yml` tem comentário na linha acima com data e condição.
- **Como corrigir:** escreva o comentário ou remova o ignore.

### DEP-04 · Vulnerabilidades conhecidas conferidas a cada mudança de dependência
- **Conferir:** `npm audit --omit=dev`, `pip-audit`, `dart pub outdated`/advisories; alertas do GitHub habilitados.
- **Por quê:** a dependência vulnerável é a brecha que não precisa de erro seu.
- **Como verificar:** rode o comando e leia: crítico e alto em dependência de produção não ficam sem decisão escrita (atualiza, substitui ou aceita com motivo).
- **Como corrigir:** atualize; se não dá, registre a ponta com risco e prazo.

### DEP-05 · Dependência nova justificada e de fonte confiável
- **Conferir:** antes de adicionar, perguntar se a biblioteca padrão resolve; checar mantenedor, última atualização, downloads, licença compatível, tamanho.
- **Por quê:** cada dependência é uma superfície de ataque e um futuro trabalho de atualização.
- **Como verificar:** no PR, uma frase por dependência nova: para quê, por que não a padrão, licença.
- **Como corrigir:** remova a que não se justifica; substitua por código próprio quando forem 20 linhas.

### DEP-06 · CI roda testes, lint e build de produção em todo push e PR
- **Conferir:** workflow com os três passos; cache de dependências; falha bloqueia merge; roda nas versões de runtime que produção usa.
- **Por quê:** o que não roda no CI é "funciona na minha máquina".
- **Como verificar:** abra o último run: três passos verdes; versão do Node/Python igual à de produção; tempo total razoável.
- **Como corrigir:** acrescente o passo que falta; fixe a versão do runtime com `setup-node`/`setup-python`.

### DEP-07 · Ações e imagens do CI fixadas em versão
- **Conferir:** `uses: actions/checkout@v7` (ou SHA), nunca `@main`/`@latest`; imagens Docker com tag específica.
- **Por quê:** a ação muda embaixo de você e pode ser comprometida.
- **Como verificar:** `grep -n "uses:" .github/workflows/*.yml` sem `@main`, `@master` ou `@latest`.
- **Como corrigir:** fixe; deixe o Dependabot de `github-actions` atualizar.

### DEP-08 · Segredos do CI com escopo mínimo e sem eco
- **Conferir:** tokens de deploy com permissão só do que precisam; `secrets.*` nunca impressos; logs de debug desligados; PR de fork não recebe segredo.
- **Por quê:** log do CI é público em repositório público.
- **Como verificar:** leia o workflow: nenhum `echo ${{ secrets...}}`; `permissions:` declaradas no topo com o mínimo (`contents: read`).
- **Como corrigir:** acrescente `permissions`; mascare; separe o workflow de deploy do de testes.

### DEP-09 · Build reproduzível sem passo manual
- **Conferir:** clone limpo + comando documentado = artefato pronto; nada depende de arquivo que só existe na máquina de alguém.
- **Por quê:** o dia em que a máquina morre.
- **Como verificar:** o CI é esse clone limpo; rode também o empacotamento (PyInstaller, Flutter build) no CI quando existir.
- **Como corrigir:** mova o passo manual para script versionado.

### DEP-10 · Licenças compatíveis com a forma de distribuição
- **Conferir:** dependências com licença copyleft forte (GPL) em projeto fechado ou em executável distribuído; atribuição exigida (MIT, BSD) incluída.
- **Por quê:** licença é obrigação legal, não detalhe.
- **Como verificar:** `npx license-checker --summary`, `pip-licenses` ou leitura dos `LICENSE` das dependências diretas.
- **Como corrigir:** substitua a dependência ou inclua o aviso de licença no pacote.
