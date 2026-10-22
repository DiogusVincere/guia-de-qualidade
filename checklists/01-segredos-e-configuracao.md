# 01 · Segredos e configuração

Vale para qualquer projeto. Segredo é tudo o que, vazado, dá acesso ou prejuízo: senha, token, chave de API,
certificado e sua senha, string de conexão, cookie de sessão, chave de assinatura, webhook com segredo na URL.

### SEG-01 · Nenhum segredo no repositório, nem no histórico
- **Conferir:** código, testes, fixtures, documentação, capturas de tela, mensagens de commit e commits antigos.
- **Por quê:** repositório público é indexado em minutos; privado vira público um dia, ou é clonado numa máquina perdida.
- **Como verificar:** `git log -p --all | grep -inE "password|senha|secret|token|api[_-]?key|BEGIN (RSA |EC |)PRIVATE|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}" | head`. Ferramenta dedicada quando houver (gitleaks, trufflehog).
- **Como corrigir:** troque o segredo primeiro (o vazado continua válido até ser revogado), depois remova do histórico com `git filter-repo` e force a atualização dos remotos. Apagar o arquivo em um commit novo não remove nada.

### SEG-02 · Segredo vive em um lugar só, e esse lugar está fora do git
- **Conferir:** `.env` local (no `.gitignore`), variáveis do serviço de hospedagem (Cloudflare, Render, Vercel, Azure) ou gerenciador de credenciais do sistema. Nunca em `config.json` versionado, nunca em constante no código.
- **Por quê:** dois lugares significam um esquecido.
- **Como verificar:** `git check-ignore -v .env` responde com a regra. `grep -rn "os.environ\|process.env\|useRuntimeConfig" --include=*.py --include=*.ts --include=*.js .` mostra que o código lê do ambiente, não de literal.
- **Como corrigir:** mova para o ambiente e deixe um `.env.example` com as chaves e valores vazios ou de exemplo.

### SEG-03 · `.env.example` lista tudo o que o projeto precisa, sem nenhum valor real
- **Conferir:** cada variável lida pelo código aparece no exemplo com uma linha de comentário dizendo para que serve e onde obter.
- **Por quê:** é a única forma de outra pessoa (ou outro agente) subir o projeto sem adivinhar.
- **Como verificar:** compare `grep -o "environ.get(['\"][A-Z_]*\|process.env.[A-Z_]*" -r . ` com as chaves do exemplo. Diferença é item faltando.
- **Como corrigir:** acrescente a variável com valor vazio ou fictício óbvio (`troque-me`), nunca um valor que funcione.

### SEG-04 · Senha de certificado não está no nome do arquivo nem ao lado dele
- **Conferir:** pastas de certificados `.pfx`/`.p12`, scripts que os abrem, arquivos `senha.txt`.
- **Por quê:** já aconteceu: arquivo `empresa_senha123.pfx` numa pasta compartilhada. Quem tem o arquivo tem a chave privada.
- **Como verificar:** `find . -iname "*.pfx" -o -iname "*.p12" -o -iname "*.pem" -o -iname "*.key"` e olhe os nomes e o que há na mesma pasta. Nenhum desses deve estar versionado (`git ls-files | grep -iE "\.(pfx|p12|pem|key)$"` vazio).
- **Como corrigir:** senha no gerenciador de credenciais ou em variável por CNPJ (`NFSE_PFX_SENHA_<CNPJ>`); o CNPJ é lido de dentro do certificado, não do nome do arquivo.

### SEG-05 · Segredo de desenvolvimento não é o de produção
- **Conferir:** chave de sessão, senha do admin inicial, chaves de API de teste.
- **Por quê:** a chave que está no `.env.example` ou no `docker-compose` de todo mundo não protege nada.
- **Como verificar:** produção tem valor diferente do local (comparar o tamanho ou os primeiros caracteres, nunca copiar o valor para o chat). Senha inicial do primeiro admin é removida do ambiente depois do primeiro login.
- **Como corrigir:** gere valores novos para produção (`python -c "import secrets; print(secrets.token_urlsafe(32))"`) e apague a variável de senha inicial depois de usada.

### SEG-06 · Segredo não aparece em log, erro, URL nem relatório
- **Conferir:** mensagens de exceção, logs de requisição, query strings, arquivos de saída, mensagens para a pessoa.
- **Por quê:** log vai para serviço de terceiro, URL fica no histórico do navegador e no proxy, relatório é encaminhado por e-mail.
- **Como verificar:** force um erro de autenticação e leia o log: o token não pode aparecer. `grep -rn "logging\.\(info\|debug\|error\)" .` nos pontos que lidam com credencial.
- **Como corrigir:** mascare (`****` + 4 últimos caracteres) ou não registre. Token vai no cabeçalho `Authorization`, nunca na URL.

### SEG-07 · Chave privada só existe em memória ou em arquivo temporário que é apagado
- **Conferir:** código que converte `.pfx` em PEM para mTLS, que assina XML, que descriptografa.
- **Por quê:** PEM esquecido em `/tmp` ou na pasta do projeto é a chave privada em texto puro.
- **Como verificar:** depois de rodar o fluxo, `ls` na pasta temporária e na pasta do projeto: nenhum `.pem`/`.key` novo. O código usa `try/finally` ou gerenciador de contexto para apagar.
- **Como corrigir:** `tempfile.mkdtemp()` + `shutil.rmtree` no `finally`; ou passe a chave em memória quando a biblioteca permitir.

### SEG-08 · Configuração tem valores padrão seguros
- **Conferir:** `DEBUG`, CORS, hosts permitidos, cookies `Secure`/`HttpOnly`/`SameSite`, nível de log, pasta de upload.
- **Por quê:** o padrão é o que fica quando alguém esquece de configurar.
- **Como verificar:** rode sem `.env` nenhum e observe: deve falhar de forma clara (falta variável X) ou subir no modo mais restrito, nunca com debug ligado e CORS aberto.
- **Como corrigir:** padrão restritivo no código; o relaxamento (debug, CORS amplo) exige variável explícita e só funciona fora de produção.

### SEG-09 · Dependência de terceiro recebe só o segredo dela
- **Conferir:** SDKs, bibliotecas de upload, ferramentas de CI.
- **Por quê:** uma chave com permissão total compartilhada entre serviços vira um vazamento total quando um deles cai.
- **Como verificar:** liste os segredos e, para cada um, a permissão mínima que o serviço aceita (escopo, bucket, pasta). Token de CI com escopo de leitura quando só precisa ler.
- **Como corrigir:** crie chaves separadas por uso e escopo; revogue a chave "mestra".

### SEG-10 · Existe um jeito de trocar o segredo sem parar tudo
- **Conferir:** documentação de operação diz onde cada segredo está e como rotacionar.
- **Por quê:** no dia do vazamento ninguém lembra.
- **Como verificar:** `docs/OPERACAO.md` (ou equivalente) tem uma linha por segredo: nome, onde fica, como gerar outro, o que reiniciar.
- **Como corrigir:** escreva. Uma tabela basta.
