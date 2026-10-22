# 17 · Criptografia

Além do TLS (que está na [02](02-seguranca-web.md)) e do hash de senha (na [04](04-autenticacao-e-sessao.md)): onde o
sistema gera aleatório, assina, criptografa e guarda token. Capítulo V11 do OWASP ASVS. Criptografia feita à mão
quase sempre está errada; o objetivo aqui é usar o certo e não enfraquecer o que a biblioteca já faz.

### CRI-01 · Aleatório de segurança vem de gerador criptográfico
- **Conferir:** token de sessão, de recuperação de senha, de API, nonce e id imprevisível usam `secrets`/`crypto.randomBytes`, não `random`/`Math.random`.
- **Por quê:** `random` é previsível; um token adivinhável é uma conta invadida.
- **Como verificar:** `grep` por `Math.random`, `random.randint`, `uuid1` em código que gera token; devem usar o gerador seguro.
- **Como corrigir:** `secrets.token_urlsafe(32)` / `crypto.randomBytes`; UUID v4 para id, nunca v1.

### CRI-02 · Token opaco e com validade
- **Conferir:** token de sessão/recuperação é longo (≥ 32 bytes), não carrega dado em claro, tem expiração e é de uso único quando cabe.
- **Por quê:** token curto se adivinha; token sem prazo vale para sempre depois de vazar.
- **Como verificar:** olhe o comprimento e o conteúdo de um token real; confira `exp`/`expira_em` no banco.
- **Como corrigir:** gere token aleatório, guarde o hash dele, com `expira_em` e `usado_em`.

### CRI-03 · JWT, quando usado, é verificado direito
- **Conferir:** algoritmo fixado (rejeita `none` e troca HS/RS), segredo longo e aleatório, `exp` validado, assinatura conferida sempre.
- **Por quê:** `alg: none` e segredo fraco permitem forjar token e virar admin.
- **Como verificar:** rode a sonda de JWT do scanner (homologação); decodifique um token e cheque o cabeçalho e o `exp`.
- **Como corrigir:** biblioteca madura com algoritmo fixo; segredo de 32+ bytes fora do código; nunca confie no `alg` do token.

### CRI-04 · Segredo de assinatura e de criptografia fora do código e rotacionável
- **Conferir:** chave de sessão, de JWT, de assinatura de cookie e de criptografia de dado vêm do ambiente/cofre.
- **Por quê:** chave no código vaza no repositório e não se troca sem redeploy.
- **Como verificar:** `grep` por chaves literais; confira que vêm de variável de ambiente.
- **Como corrigir:** mova para o cofre; documente como rotacionar (ver [01 SEG-10](01-segredos-e-configuracao.md)).

### CRI-05 · Dado sensível em repouso é criptografado e o algoritmo é atual
- **Conferir:** o que é sensível (documento, dado pessoal forte) é criptografado pelo provedor ou pela aplicação com AES-GCM ou equivalente; nada de DES, RC4, ECB, MD5, SHA1 para fim de segurança.
- **Por quê:** algoritmo quebrado é o mesmo que texto puro; ECB vaza padrão.
- **Como verificar:** `grep` por `DES`, `RC4`, `ECB`, `md5`, `sha1` em contexto de segurança; confira a criptografia do banco no painel.
- **Como corrigir:** AES-256-GCM para dado; SHA-256+ para integridade; criptografia do provedor ligada.

### CRI-06 · Comparação de segredo é em tempo constante
- **Conferir:** comparação de token, assinatura de webhook e senha de API usa comparação em tempo constante.
- **Por quê:** comparação comum vaza, pelo tempo, quantos caracteres batem (timing attack).
- **Como verificar:** `grep` por `==` comparando token/assinatura; deve ser `secrets.compare_digest`/`crypto.timingSafeEqual`.
- **Como corrigir:** troque pela comparação em tempo constante da linguagem.
