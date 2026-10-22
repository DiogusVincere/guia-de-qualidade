# 12 · Aplicativos Flutter

Para apps mobile e web em Flutter que consomem uma API. Os itens de [03 APIs](03-apis.md) e
[08 Acessibilidade](08-acessibilidade-e-celular.md) valem para o lado do servidor e da interface.

### FLU-01 · Nenhum segredo no app
- **Conferir:** chave de API de terceiro, senha de serviço, token fixo. O que está no APK é público.
- **Por quê:** APK se descompila em um minuto; a chave de clima ou de mapas no código vira conta de outra pessoa.
- **Como verificar:** `grep -rn "api[_-]\?key\|secret\|token" lib/` e `--dart-define` no build; nada com valor literal. O segredo de terceiro fica no backend e o app chama o backend.
- **Como corrigir:** proxy no servidor para a API de terceiro; chaves públicas restritas por domínio/pacote quando o provedor permite.

### FLU-02 · Token de sessão guardado em armazenamento seguro, com expiração
- **Conferir:** `flutter_secure_storage` (ou equivalente) para o token; `SharedPreferences` só para preferências; renovação e logout limpam tudo.
- **Por quê:** preferências são texto puro no aparelho e no backup.
- **Como verificar:** leia o código de login e logout; depois do logout, nenhuma chave sensível fica no armazenamento.
- **Como corrigir:** mova para o armazenamento seguro; apague no logout e ao receber 401.

### FLU-03 · Toda chamada de rede tem timeout, tratamento de erro e estado na tela
- **Conferir:** `timeout` nas requisições; 401 leva ao login; sem rede mostra mensagem e botão de tentar de novo; carregando tem indicador; lista vazia tem texto.
- **Por quê:** app que "fica pensando" para sempre é desinstalado.
- **Como verificar:** modo avião no meio do fluxo; servidor desligado; resposta 500 forçada: cada caso mostra estado coerente.
- **Como corrigir:** camada de cliente HTTP única com os tratamentos; widgets de estado reutilizáveis.

### FLU-04 · HTTPS obrigatório e certificado validado
- **Conferir:** URL base com `https`; nenhuma desativação de validação de certificado (`badCertificateCallback` que retorna true); `usesCleartextTraffic` desligado no Android.
- **Por quê:** rede pública intercepta HTTP e certificado ignorado.
- **Como verificar:** `grep -rn "http://\|badCertificate\|cleartext" lib/ android/app/src/main/AndroidManifest.xml`.
- **Como corrigir:** remova as exceções; em desenvolvimento use um domínio de homologação com certificado válido.

### FLU-05 · Permissões mínimas e pedidas no contexto
- **Conferir:** `AndroidManifest.xml` e `Info.plist` só com as permissões usadas; cada uma pedida no momento do uso com explicação; funciona (degradado) se negada.
- **Por quê:** permissão a mais é rejeição na loja e desconfiança do usuário.
- **Como verificar:** liste as permissões declaradas e aponte a tela que usa cada uma; negue cada uma e veja o app continuar.
- **Como corrigir:** remova as não usadas; trate a negativa.

### FLU-06 · Entrada validada no app E no servidor
- **Conferir:** formulários com validação local (formato, obrigatório) e o servidor validando de novo; mensagens de erro do servidor exibidas perto do campo.
- **Por quê:** validação só no app é contornada; só no servidor é lenta para o usuário.
- **Como verificar:** envie valor inválido direto na API (fora do app): 400. No app, o erro aparece sem tela branca.
- **Como corrigir:** `validator` nos campos; mapeamento dos erros do servidor para os campos.

### FLU-07 · Build de release assinado, ofuscado e versionado
- **Conferir:** chave de assinatura fora do repositório (`key.properties` ignorado); `--obfuscate --split-debug-info`; `version` no `pubspec.yaml` incrementado a cada release; o APK ou AAB publicado corresponde a uma tag no git.
- **Por quê:** APK de debug não entra na loja; chave no repositório é a identidade do app para sempre.
- **Como verificar:** `git ls-files | grep -iE "key.properties|\.jks|\.keystore"` vazio; o workflow de build gera o artefato com a versão da tag.
- **Como corrigir:** gere a chave fora, guarde no cofre, injete no CI por segredo.

### FLU-08 · Funciona em tela pequena, com fonte grande e em modo escuro
- **Conferir:** 360 × 640 sem overflow (nenhuma faixa amarela e preta); `textScaleFactor` 1,3 sem corte; tema escuro legível se o app o suporta.
- **Por quê:** é o aparelho de entrada e a configuração de acessibilidade mais comum.
- **Como verificar:** emulador pequeno + fonte grande do sistema; `flutter test` com `golden` ou pelo menos captura de cada tela principal.
- **Como corrigir:** `Expanded`/`Flexible`, `SingleChildScrollView` onde cabe, `FittedBox` em números grandes.

### FLU-09 · Estado offline previsível
- **Conferir:** o que o app guarda localmente (cache de lista, rascunho de formulário) tem prazo e é descartado ao trocar de usuário; ação feita offline é enfileirada ou recusada com aviso, nunca perdida em silêncio.
- **Por quê:** dado antigo mostrado como atual gera decisão errada.
- **Como verificar:** faça uma ação sem rede e volte a rede: ela foi enviada ou o usuário foi avisado de que não foi.
- **Como corrigir:** indicador de "dados de HH:MM"; fila local simples com reenvio.

### FLU-10 · Testes de widget para o fluxo principal e teste de integração contra a API falsa
- **Conferir:** `flutter test` cobre login, listagem e a ação principal com cliente HTTP falso; CI roda `flutter analyze` e `flutter test` em cada push; versão do Flutter fixada no workflow.
- **Por quê:** sem CI, o app quebra numa atualização de dependência e só se descobre na loja.
- **Como verificar:** workflow verde com as três etapas; versão do Flutter declarada (`flutter-version`).
- **Como corrigir:** `mockito`/`http` falso; `subosito/flutter-action` com versão fixa.
