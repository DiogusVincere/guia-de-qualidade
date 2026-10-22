# 21 · Injeção avançada e protocolo

As técnicas que vão além do XSS e do SQL básico (que estão na [02](02-seguranca-web.md)). Aparecem em pentest
profissional e em bug bounty. Nem toda se testa com segurança de forma automática; onde o teste é arriscado, o guia
diz para confirmar à mão em homologação.

### ADV-01 · XXE — entidade externa em XML
- **Conferir:** endpoints que recebem XML (SOAP, upload de XML, importação, SAML) desligam entidade externa no parser.
- **Por quê:** XXE lê arquivo do servidor, faz SSRF e às vezes executa código.
- **Como verificar:** em homologação, mande um XML com `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>` e veja se o arquivo volta; ou confira no código se o parser tem `resolve_entities=False`.
- **Como corrigir:** desligue DTD e entidade externa no parser (defusedxml no Python; `FEATURE_SECURE_PROCESSING` no Java).

### ADV-02 · SSTI — injeção de template no servidor
- **Conferir:** entrada do usuário que chega a um motor de template (e-mail, PDF, página renderizada com dado do cliente).
- **Por quê:** template injection vira execução de código no servidor.
- **Como verificar:** o scanner testa `{{7*7}}`/`${7*7}`; confirme no código onde o dado do cliente entra no template.
- **Como corrigir:** nunca passe entrada do usuário como template; trate como dado a ser exibido, com escape.

### ADV-03 · Prototype pollution (JavaScript)
- **Conferir:** mesclagem de objeto com entrada do cliente (query, JSON) sem filtrar `__proto__`, `constructor`, `prototype`.
- **Por quê:** poluir o protótipo vira negação de serviço, bypass de validação ou execução de código.
- **Como verificar:** o scanner tenta `?__proto__[x]=y`; no código, procure merge/extend/clone recursivo de entrada.
- **Como corrigir:** rejeite essas chaves; use `Object.create(null)` para mapas; bibliotecas de merge seguras.

### ADV-04 · CSRF — requisição forjada de outro site
- **Conferir:** toda escrita exige cookie `SameSite=Lax/Strict` ou token anti-CSRF; API por token no cabeçalho é imune.
- **Por quê:** sem isso, outro site faz o navegador da vítima logada enviar uma ação.
- **Como verificar:** o scanner confere forms sem token e checa SameSite; teste um POST a partir de outra origem (ver [02 WEB-03](02-seguranca-web.md)).
- **Como corrigir:** `SameSite=Lax` nos cookies de sessão e/ou token sincronizado; checagem de Origin nas escritas.

### ADV-05 · HTTP request smuggling (desync)
- **Conferir:** divergência entre o proxy/CDN e o servidor na interpretação de `Content-Length` × `Transfer-Encoding`.
- **Por quê:** smuggling injeta requisição na conexão de outra pessoa: sequestro de sessão, envenenamento de resposta.
- **Como verificar:** **não automatize cegamente** (pode afetar outros usuários): teste com cuidado, em homologação, com ferramenta dedicada (Burp, smuggler); ou confirme que proxy e servidor concordam no parsing.
- **Como corrigir:** use HTTP/2 fim a fim quando possível; rejeite requisição com os dois cabeçalhos; mantenha proxy e servidor atualizados.

### ADV-06 · Web cache poisoning e deception
- **Conferir:** a chave de cache não inclui cabeçalho não-confiável (X-Forwarded-Host, X-Forwarded-Scheme); página com dado pessoal não é cacheável.
- **Por quê:** poluir a cache serve o payload do atacante (ou o dado de uma pessoa) para todo mundo.
- **Como verificar:** em homologação, mande um cabeçalho não-keyed refletido e veja se a resposta cacheada muda; confira `Cache-Control` das páginas pessoais.
- **Como corrigir:** não reflita cabeçalho não-confiável; `Cache-Control: private/no-store` no que é pessoal; chave de cache só com o que é seguro.

### ADV-07 · Desserialização insegura
- **Conferir:** dado do cliente (cookie, campo, upload) é desserializado em objeto (pickle, Java serial, `unserialize` PHP, YAML inseguro).
- **Por quê:** desserializar dado hostil executa código.
- **Como verificar:** difícil por fora; confira no código se há `pickle.loads`, `yaml.load` sem SafeLoader, `unserialize` sobre entrada do cliente.
- **Como corrigir:** nunca desserialize dado do cliente em objeto; use JSON; se precisar, assine e valide antes.

### ADV-08 · GraphQL a fundo
- **Conferir:** introspection desligado em produção, limite de profundidade e de lote das consultas, sem sugestão de campo.
- **Por quê:** introspection entrega o esquema; consulta profunda/em lote é negação de serviço; sugestão de campo vaza nomes.
- **Como verificar:** o scanner testa introspection; confira limites de profundidade e rate limit nas mutations.
- **Como corrigir:** desligue introspection; limite profundidade/complexidade; rate limit por operação; desligue sugestão de campo.
