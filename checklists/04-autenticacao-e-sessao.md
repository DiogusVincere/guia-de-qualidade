# 04 · Autenticação e sessão

Para qualquer sistema com login: painel, área do cliente, API com token, interface local com senha.

### AUT-01 · Senha guardada com algoritmo lento e sal, nunca reversível
- **Conferir:** bcrypt, scrypt ou Argon2 com parâmetro de custo definido de propósito; nunca MD5/SHA puro, nunca texto claro, nunca criptografia simétrica.
- **Por quê:** o banco vaza; o que define o dano é quanto tempo leva para abrir cada senha.
- **Como verificar:** leia a configuração de hash (por exemplo `scrypt cost` ou `argon2 time_cost`) e um registro do banco: começa com o prefixo do algoritmo. Teste de login leva dezenas de milissegundos, não microssegundos.
- **Como corrigir:** use a biblioteca de autenticação do framework; ao mudar o custo, faça o re-hash no próximo login válido.

### AUT-02 · Login tem limite por IP e por conta, e o limite é reservado antes de verificar
- **Conferir:** janela e teto definidos (por exemplo 10 tentativas em 15 minutos por IP e 20 por e-mail); IPv6 contado por /64; sucesso zera os dois.
- **Por quê:** força bruta distribuída passa pelo limite por IP; limite por conta protege o alvo.
- **Como verificar:** teste automatizado que falha 10 vezes e recebe 429 na 11ª, com `Retry-After`; requisições simultâneas não passam além do teto.
- **Como corrigir:** `consumirTentativa` (grava, depois confere) em vez de "confere, depois grava".

### AUT-03 · A resposta de login não diz se o usuário existe
- **Conferir:** mesma mensagem e tempo parecido para "usuário não existe" e "senha errada"; recuperação de senha responde "se o e-mail existir, enviamos".
- **Por quê:** enumeração de contas é o primeiro passo de qualquer ataque dirigido.
- **Como verificar:** compare as duas respostas (corpo, status, tempo em dezenas de tentativas).
- **Como corrigir:** faça o hash mesmo quando o usuário não existe (hash de uma senha falsa) para igualar o tempo.

### AUT-04 · Sessão expira, pode ser encerrada e muda de id ao autenticar
- **Conferir:** prazo definido (por exemplo 7 dias para painel, menos para operações sensíveis); logout invalida no servidor; login gera sessão nova (não reaproveita a anônima).
- **Por quê:** sessão eterna é senha eterna; fixação de sessão usa o id anterior.
- **Como verificar:** cookie tem `Max-Age`/`Expires`; depois de logout, o cookie antigo não funciona; o valor do cookie antes e depois do login é diferente.
- **Como corrigir:** `maxAge` na configuração de sessão; `clearUserSession` no logout; `replaceUserSession` ou equivalente no login.

### AUT-05 · Troca de senha exige a senha atual e encerra as outras sessões
- **Conferir:** rota de troca pede a atual; limite de tentativas próprio; depois da troca, sessões em outros dispositivos caem.
- **Por quê:** sessão roubada não pode virar senha nova sem a antiga; e a troca é o momento de expulsar o invasor.
- **Como verificar:** teste com senha atual errada: 400/403 e conta no limite. Depois da troca, uma segunda sessão aberta antes recebe 401.
- **Como corrigir:** guarde uma versão da credencial na sessão e compare; incremente na troca.

### AUT-06 · Senha inicial de administrador não sobrevive ao primeiro acesso
- **Conferir:** a senha semeada vem de variável de ambiente, obriga a troca no primeiro login e a variável é removida depois.
- **Por quê:** senha inicial em README ou em semente é a primeira que se tenta.
- **Como verificar:** depois do primeiro login, a variável não existe mais no ambiente de produção e o login com a senha inicial falha.
- **Como corrigir:** sinalize `precisa_trocar_senha` no registro; documente a remoção da variável no passo a passo de operação.

### AUT-07 · Token de API não vai em URL, tem escopo e prazo
- **Conferir:** `Authorization: Bearer`; tokens com validade e revogação; escopo mínimo (leitura quando só lê).
- **Por quê:** URL fica em log, histórico e proxy; token sem prazo é permanente.
- **Como verificar:** `grep -rn "token=" .` em código e documentação: nada em query string. Lista de tokens com data de expiração no banco.
- **Como corrigir:** mova para cabeçalho; crie tabela de tokens com escopo, prazo e revogação.

### AUT-08 · Recuperação de senha usa link único, curto e de uso único
- **Conferir:** token aleatório (≥ 32 bytes), expira em minutos, invalida ao usar, não revela se o e-mail existe, limite de envios.
- **Por quê:** é a porta de trás de todo login.
- **Como verificar:** usar o link duas vezes falha na segunda; link de 1 hora atrás falha; pedir 10 recuperações em um minuto bloqueia.
- **Como corrigir:** `secrets.token_urlsafe(32)`, hash do token no banco, `usado_em` e `expira_em`.

### AUT-09 · Autorização por papel é verificada no servidor, em toda rota
- **Conferir:** menu escondido no front não é controle de acesso; cada rota administrativa checa o papel; teste cobre usuário comum chamando rota de admin.
- **Por quê:** a URL é digitável.
- **Como verificar:** com sessão de usuário comum, `curl` em cada rota de admin: 403. Lista de rotas de admin bate com a lista protegida pelo middleware.
- **Como corrigir:** middleware por prefixo (`/api/admin/**`) mais checagem explícita nas rotas fora do prefixo.

### AUT-10 · Interface local (localhost) também tem porta trancada
- **Conferir:** servidor que roda na máquina da pessoa escuta só em 127.0.0.1, exige token gerado por execução embutido na página, e a página não aceita chamadas de outra origem.
- **Por quê:** um site aberto em outra aba consegue chamar `http://127.0.0.1:8747/api/...` se não houver token; e `0.0.0.0` expõe para a rede.
- **Como verificar:** `netstat -an | findstr 8747` mostra 127.0.0.1; `curl` na API sem o token responde 403; página de outra origem não consegue ler o token.
- **Como corrigir:** `bind` em 127.0.0.1; token aleatório por processo; cabeçalho `X-Token` conferido com comparação em tempo constante.
