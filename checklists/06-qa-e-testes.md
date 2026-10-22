# 06 · QA e testes

Para qualquer projeto. O objetivo não é cobertura alta; é que o que importa esteja protegido por um teste que falha
quando aquilo quebra, e que a verificação manual seja feita como um usuário faria.

### QA-01 · Bug corrigido tem o teste que o reproduz, escrito antes da correção
- **Conferir:** o commit de correção traz um teste que falhava antes e passa depois.
- **Por quê:** sem o teste, não se sabe se a correção corrigiu o bug ou um sintoma; e o bug volta na próxima refatoração.
- **Como verificar:** `git stash` da correção (ou checkout do commit anterior) e rode o teste novo: falha. Volte: passa.
- **Como corrigir:** escreva o teste primeiro, veja falhar, corrija.

### QA-02 · As regras de negócio têm teste próprio, separado da interface
- **Conferir:** cálculo de preço, desconto, retenção, competência, arredondamento, limites, validação de entrada estão em funções puras com testes de tabela (entrada → saída esperada), incluindo os casos que já deram errado.
- **Por quê:** é onde o erro custa dinheiro e onde a interface esconde o problema.
- **Como verificar:** para cada regra listada no AGENTS do projeto, existe um teste com nome que a descreve. Casos de borda presentes: zero, negativo, máximo, vírgula e ponto, acento, vazio, duplicado.
- **Como corrigir:** extraia a regra para `shared/` ou `nucleo/` e teste ali.

### QA-03 · Teste não depende de rede, de relógio nem de ordem
- **Conferir:** serviços externos substituídos por dublês; data fixada quando o resultado depende dela; cada teste limpa o que cria; a suíte passa em ordem aleatória e em paralelo.
- **Por quê:** teste que depende do mundo falha no dia errado e ensina a equipe a ignorar vermelho.
- **Como verificar:** rode a suíte com a rede desligada e duas vezes seguidas na mesma pasta temporária. Procure `date.today()`/`Date.now()` em código testado sem injeção.
- **Como corrigir:** injete a data e os clientes externos como parâmetro; use pastas temporárias por teste.

### QA-04 · Teste de regressão para o que já quebrou em produção
- **Conferir:** cada incidente (500 em todas as páginas por objeto indefinido no bundle, cabeçalho que sumiu, semente que apagou dado) tem um teste que o pegaria.
- **Por quê:** o que aconteceu uma vez acontece de novo em outra forma.
- **Como verificar:** leia o documento de revisão ou o histórico de bugs do projeto; para cada um, aponte o teste.
- **Como corrigir:** escreva o teste de fumaça (sobe o build de produção e pede três rotas) e o teste específico.

### QA-05 · O caminho principal foi exercitado como usuário, no dispositivo principal
- **Conferir:** o fluxo que gera valor (abrir, escolher, enviar, confirmar; importar, conferir, gerar) foi feito de ponta a ponta na interface, no tamanho de tela mais usado (celular, quando é site para o público), com dados realistas fictícios.
- **Por quê:** teste automatizado não vê botão fora da tela nem texto cortado.
- **Como verificar:** captura de tela de cada passo em 375 px e no desktop; console sem erro; nenhuma rolagem horizontal; formulário com erro mostra a mensagem perto do campo.
- **Como corrigir:** ajuste e repita; o que for recorrente vira teste de interface.

### QA-06 · Estados vazios, de erro e de carregamento existem e foram vistos
- **Conferir:** lista sem itens, busca sem resultado, falha de rede, sessão expirada, arquivo inválido, permissão negada.
- **Por quê:** o usuário encontra esses estados mais do que o caminho feliz, e eles costumam ser tela branca.
- **Como verificar:** force cada um (desligue o servidor, envie arquivo errado, expire a sessão) e veja a tela. Mensagem em português, com próximo passo.
- **Como corrigir:** componente de estado vazio/erro com texto e ação.

### QA-07 · Entrada maliciosa ou absurda foi tentada
- **Conferir:** texto com HTML, SQL, emoji, 10 mil caracteres; número negativo, zero, enorme, com vírgula; arquivo de 0 bytes e de 100 MB; datas inválidas; o mesmo item 11 vezes.
- **Por quê:** é o que o mundo manda.
- **Como verificar:** uma rodada por formulário e por rota de escrita; cada caso devolve 400 ou mensagem de validação, nunca 500 nem dado gravado errado.
- **Como corrigir:** validação por esquema com limites; teste de tabela com os casos.

### QA-08 · O teste diz o que quebrou sem precisar abrir o código
- **Conferir:** nome do teste descreve o comportamento ("limite de 10 por peça vale depois de somar as linhas"); asserções com mensagem; dados do teste nomeados.
- **Por quê:** teste é documentação executável; vermelho sem contexto vira "deve ser instável".
- **Como verificar:** leia a saída de uma falha provocada: dá para entender o que se esperava e o que veio.
- **Como corrigir:** renomeie e acrescente mensagens.

### QA-09 · Suíte roda rápido o bastante para ser rodada sempre
- **Conferir:** suíte completa em poucos minutos no máximo; testes lentos (integração real, navegador) separados e rodados no CI.
- **Por quê:** suíte lenta não é rodada antes do commit.
- **Como verificar:** tempo total impresso ao final; teste individual acima de alguns segundos tem motivo.
- **Como corrigir:** substitua esperas fixas por espera por condição; use banco em memória ou pasta temporária.

### QA-10 · Dados de teste e de demonstração são fictícios e se declaram fictícios
- **Conferir:** nomes como "Empresa Exemplo Ltda", CNPJs gerados com dígito verificador válido mas inexistentes, e-mails em `.test`/`.example`, telefones de faixa reservada.
- **Por quê:** teste com dado real vaza e confunde; demonstração com dado real é incidente.
- **Como verificar:** `grep` por domínios reais e nomes conhecidos nas pastas de teste e semente; o README diz que os dados são fictícios.
- **Como corrigir:** gerador com semente fixa; substitua.

### QA-11 · Falha é isolada e relatada, não engolida
- **Conferir:** `except Exception: pass`, `catch (e) {}` e `contextlib.suppress` amplos só existem onde o comentário explica por quê e o erro vai para o relatório ou log.
- **Por quê:** erro engolido vira dado faltando em silêncio (a nota que não entrou, o cliente que não foi arquivado).
- **Como verificar:** `grep -rn "except Exception\|except:\|catch (e) {}\|suppress(Exception)" .` e leia cada um: há log ou pendência? Há comentário?
- **Como corrigir:** capture o específico, registre, conte no relatório ("3 arquivos ignorados: ...").

### QA-12 · O que o agente não conseguiu testar está escrito
- **Conferir:** envio real de e-mail, certificado real, portal de terceiro, impressão, hardware.
- **Por quê:** a pessoa precisa saber o que testar à mão.
- **Como verificar:** seção "O que NÃO foi verificado" do relatório preenchida com o motivo e com o roteiro para a pessoa testar.
- **Como corrigir:** escreva o roteiro (passos, dado de entrada, resultado esperado).
