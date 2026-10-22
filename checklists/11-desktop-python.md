# 11 · Aplicativos desktop em Python

Para ferramentas de mesa (Tkinter ou similar) que leem planilhas, PDFs, XML e pastas de rede, integram com Outlook
ou outro programa por COM, e são distribuídas como script ou executável. Os itens de [01 Segredos](01-segredos-e-configuracao.md)
e [06 QA](06-qa-e-testes.md) valem aqui também.

### DESK-01 · Pasta de origem é somente leitura quando o projeto diz isso
- **Conferir:** nenhum `open(..., 'w')`, `shutil.move`, `os.remove`, `Path.write_*` apontando para a pasta de clientes ou de dados de terceiros; saídas vão para a pasta de saída configurada.
- **Por quê:** a ferramenta que "só lê" e grava um `~$` ou um log na pasta do cliente já alterou o que não devia.
- **Como verificar:** `grep -rn "write_text\|write_bytes\|open(.*['\"]w\|shutil.move\|os.remove\|unlink" .` e confira cada destino; depois de um teste, liste a pasta de origem e compare com antes.
- **Como corrigir:** toda escrita passa por uma função que recebe a pasta de saída; abra Excel por COM com `ReadOnly=True`.

### DESK-02 · Planilha de cliente é tratada como hostil: colunas trocam, títulos somem, tipos mudam
- **Conferir:** o leitor reconhece a coluna pelo conteúdo ou confere título E conteúdo; avisa quando a coluna "não parece" o que o título diz; linha com texto onde era número vira aviso, não valor zero nem linha sumida.
- **Por quê:** já aconteceu: cliente reordenou colunas mantendo o título e a ferramenta gerou R$ 19 trilhões sem avisar.
- **Como verificar:** teste com planilha sintética com colunas trocadas, título repetido a cada página, linha de total no fim, célula de data onde era número: a saída traz avisos nomeados ou recusa, nunca número absurdo em silêncio.
- **Como corrigir:** função de conferência de layout (faixa esperada por coluna, tipo majoritário) que coloca avisos no topo do resultado.

### DESK-03 · Nada roda no lugar errado: dois tempos para qualquer ação que altera arquivos
- **Conferir:** "Conferir" mostra o que vai acontecer (quantos arquivos, para onde); "Executar" só depois; o plano é descartado se qualquer campo muda.
- **Por quê:** mover 300 XMLs para a pasta errada é uma tarde perdida.
- **Como verificar:** mude a pasta de destino depois de conferir: o botão de executar volta a exigir conferência.
- **Como corrigir:** guarde o plano com os parâmetros que o geraram e compare antes de executar.

### DESK-04 · Nunca sobrescreve sem permissão; nunca apaga sem ter arquivado
- **Conferir:** arquivo de mesmo nome no destino ganha sufixo ou é comparado byte a byte ("já estava"); origem só é apagada depois de confirmar que o destino existe e confere; nada é apagado quando nada foi arquivado.
- **Por quê:** o ZIP apagado com erro no meio é dado perdido.
- **Como verificar:** teste com destino já contendo arquivo igual e arquivo diferente de mesmo nome; teste com falha simulada no meio: a origem continua lá.
- **Como corrigir:** compare conteúdo; renomeie com data; apague só ao final e só com sucesso total.

### DESK-05 · Código de cliente repetido ou ambíguo é erro, não escolha silenciosa
- **Conferir:** quando dois registros casam com o mesmo código ou nome, a ferramenta para e pergunta ou lista, em vez de pegar o primeiro.
- **Por quê:** arquivar no cliente errado é pior do que não arquivar.
- **Como verificar:** teste com duas pastas `223 - A` e `223 - B`: a ferramenta recusa ou pede escolha.
- **Como corrigir:** resolva por código exato; em empate, pendência nomeada.

### DESK-06 · A interface não trava e o erro aparece na tela
- **Conferir:** trabalho longo roda em thread com fila para a interface; variáveis da interface (`StringVar`) são lidas antes de entrar na thread; exceções viram mensagem na tela e linha no `erros.log`, não morte silenciosa do `pythonw`.
- **Por quê:** `pythonw` engole o erro e a pessoa vê a tela sumir; ler `StringVar` na thread derruba o programa.
- **Como verificar:** force uma exceção dentro da thread: a tela mostra o erro; o log tem a stack. Force um arquivo grande: a janela responde durante o processamento.
- **Como corrigir:** `threading.Thread` + `queue.Queue` + `after()`; `try/except` com `logging.exception` no topo da thread; `sys.excepthook` para a interface.

### DESK-07 · Integração por COM é testável sem o programa
- **Conferir:** a lógica (classificar e-mail, decidir pasta, montar mensagem) está em funções puras sobre objetos simples; o COM fica numa camada fina; existe um dublê (Outlook simulado) para testes e demonstração.
- **Por quê:** sem isso o teste exige Outlook aberto e nunca roda no CI; e mandar e-mail de verdade por engano em teste é incidente.
- **Como verificar:** a suíte roda numa máquina sem Outlook; `so_testar=True` monta e descarta sem enviar; nenhum teste chama `.Send()`.
- **Como corrigir:** separe `ler_item(ItemLido)` de `ler_do_outlook()`; crie `falso.py` com dados fictícios.

### DESK-08 · Dados da ferramenta ficam na pasta do usuário, não na pasta do programa
- **Conferir:** configuração, cache e aprendizado em `%LOCALAPPDATA%\<Ferramenta>` (ou pasta de dados por usuário); a pasta do programa só tem código.
- **Por quê:** pasta do programa pode ser somente leitura, compartilhada ou substituída na atualização.
- **Como verificar:** rode de uma pasta somente leitura: funciona; a atualização do programa não apaga a configuração.
- **Como corrigir:** função única `pasta_de_dados()`; migre o que estava ao lado do código.

### DESK-09 · Caminhos de rede, acentos e Excel aberto por alguém não derrubam a ferramenta
- **Conferir:** caminhos UNC e letras mapeadas; nomes com acento e espaço; arquivo `.xlsx` aberto por outra pessoa (lock) tratado com mensagem; `Path.resolve()` que troca a letra pelo UNC não quebra comparações.
- **Por quê:** é o ambiente real de um escritório.
- **Como verificar:** teste com pasta `N:\Clientes\123 - Nome Ção\08-2026` e com um arquivo aberto no Excel: mensagem clara, sem traceback.
- **Como corrigir:** `os.path.abspath` em vez de `resolve()` quando a letra importa; `try/except PermissionError` com texto para a pessoa.

### DESK-10 · Executável distribuído é reproduzível e diz a versão
- **Conferir:** receita de empacotamento versionada (`build/empacotar.py` + spec), versão visível na tela e no arquivo, `LEIA-ME.txt` no pacote, nada de dado ou configuração pessoal dentro do zip.
- **Por quê:** "qual versão você está usando?" precisa ter resposta.
- **Como verificar:** liste o conteúdo do zip: só o programa; a tela mostra a versão; o CI (ou um script) monta o pacote a partir de um clone limpo.
- **Como corrigir:** constante `VERSAO` única; script de empacotamento; `.gitignore` para `dist/`.

### DESK-11 · Entrada de usuário em campo livre entende português, não lista fechada
- **Conferir:** quantidades, intervalos e prazos que a pessoa define aceitam texto ("20 min", "1:30h", "a cada 2 horas", "dia 15") e devolvem erro claro fora da faixa.
- **Por quê:** lista fixa nunca tem o valor que a pessoa quer; é decisão de produto registrada em projetos reais.
- **Como verificar:** teste de tabela com as formas aceitas e as recusadas.
- **Como corrigir:** função `ler_intervalo()`/`ler_prazo()` com testes; mensagem que mostra exemplos válidos.
