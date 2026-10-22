# 08 · Acessibilidade e celular

Para qualquer interface que uma pessoa use: site, painel, aplicativo desktop ou mobile. Em site aberto ao público,
a maior parte dos acessos vem do celular: confira primeiro em 375 px, depois no desktop.

### ACE-01 · Funciona em 375 px sem rolagem horizontal
- **Conferir:** todas as páginas e o fluxo principal numa janela de 375 px de largura (ou no aparelho).
- **Por quê:** é a tela da maioria; tabela larga, imagem fixa e texto longo sem quebra quebram o layout.
- **Como verificar:** `document.documentElement.scrollWidth <= window.innerWidth` em cada página no modo celular do navegador; captura de tela de cada passo.
- **Como corrigir:** `max-width: 100%` em mídia, `overflow-x: auto` só em contêiner de tabela, quebras de linha em texto longo, grade que vira coluna.

### ACE-02 · Alvos de toque com pelo menos 44 px e espaçados
- **Conferir:** botões, links de menu, ícones de ação, caixas de seleção.
- **Por quê:** dedo não é cursor; alvo pequeno e colado gera clique errado em ação destrutiva.
- **Como verificar:** no inspetor, altura e largura de cada alvo ≥ 44 px (ou área de toque equivalente); 8 px entre alvos adjacentes.
- **Como corrigir:** `min-height: 44px`, padding em vez de reduzir fonte, espaçamento entre itens.

### ACE-03 · Teclado alcança tudo e o foco é visível
- **Conferir:** Tab percorre menu, formulário, diálogos e botões em ordem lógica; Enter/Espaço ativam; Esc fecha; o foco tem anel visível com contraste.
- **Por quê:** leitores de tela e quem não usa mouse dependem disso; foco invisível é padrão de muitos temas.
- **Como verificar:** navegue a página inteira só com o teclado; abra e feche um diálogo; o foco volta para onde estava.
- **Como corrigir:** `:focus-visible` com `outline` de 2 px e cor de contraste sobre o fundo; `tabindex` só quando necessário; diálogo com foco preso e retorno.

### ACE-04 · Contraste de texto e de ícones de ação
- **Conferir:** texto normal ≥ 4,5:1, texto grande e ícones ≥ 3:1, inclusive texto sobre imagem, sobre cor de destaque e estado desabilitado que ainda precisa ser lido.
- **Por quê:** cor de marca clara (dourado, sálvia) sobre fundo claro reprova e some sob luz do sol.
- **Como verificar:** verificador de contraste nas combinações usadas (texto/fundo, preço com desconto, selo); ferramenta de auditoria do navegador (Lighthouse/axe) sem erro de contraste.
- **Como corrigir:** use a cor de destaque como fundo e a tinta escura como texto, ou escureça a cor; nunca cor clara como texto em fundo claro.

### ACE-05 · Imagens com texto alternativo, decoração sem
- **Conferir:** `alt` descritivo em foto de produto e ilustração com significado; `alt=""` em decoração; ícone de botão com rótulo acessível.
- **Por quê:** leitor de tela lê "imagem" sem o alt e lê o nome do arquivo com alt errado.
- **Como verificar:** `grep -rn "<img" app | grep -v "alt="` vazio; botões só com ícone têm `aria-label`.
- **Como corrigir:** escreva o alt com o que a imagem mostra; ícone decorativo com `aria-hidden="true"`.

### ACE-06 · Formulário acessível: rótulo, erro perto do campo, obrigatório marcado
- **Conferir:** todo campo tem `<label>` ligado; mensagem de erro aparece junto do campo e é anunciada; grupo de opções tem `fieldset`/`legend`; `required` e `autocomplete` corretos.
- **Por quê:** placeholder não é rótulo; erro só no topo da página perde quem rolou.
- **Como verificar:** clique no rótulo: o campo recebe foco; envie vazio: a mensagem fica ao lado do campo e o foco vai para o primeiro erro.
- **Como corrigir:** `label for`, `aria-describedby` para o erro, `aria-invalid`.

### ACE-07 · Estrutura semântica: títulos em ordem, marcos de página, uma `h1`
- **Conferir:** `h1` única, `h2`/`h3` sem pular níveis, `nav`, `main`, `footer`, listas como `ul/ol`, tabela como `table` com cabeçalho.
- **Por quê:** é como quem usa leitor de tela navega; também é o que o buscador lê.
- **Como verificar:** árvore de acessibilidade do navegador ou extensão de títulos; auditoria sem aviso de ordem.
- **Como corrigir:** ajuste as tags; título visualmente oculto (`sr-only`) quando a seção precisa de nome mas o desenho não o mostra.

### ACE-08 · Movimento e mídia respeitam preferências
- **Conferir:** animações desligam com `prefers-reduced-motion`; vídeo não toca sozinho com som; carrossel tem pausa.
- **Por quê:** movimento causa enjoo e distração; é ajuste de uma regra de CSS.
- **Como verificar:** ative "reduzir movimento" no sistema e recarregue: transições decorativas somem.
- **Como corrigir:** `@media (prefers-reduced-motion: reduce) { * { animation: none; transition: none } }` (ou por componente).

### ACE-09 · Texto cresce 200 % sem quebrar
- **Conferir:** zoom do navegador em 200 % e tamanho de fonte do sistema aumentado: nada sobreposto, nada cortado, nada fora da tela.
- **Por quê:** é como muita gente lê.
- **Como verificar:** Ctrl + "+" até 200 % em cada página principal; no celular, fonte grande do sistema.
- **Como corrigir:** unidades relativas (`rem`), alturas mínimas em vez de fixas, quebra de linha permitida.

### ACE-10 · Conteúdo essencial sem JavaScript ou com ele falhando
- **Conferir:** página de produto, informações, contato e a confirmação de pedido mostram o essencial no HTML do servidor; mensagem de `noscript` onde a ação exige script.
- **Por quê:** script falha (CSP, rede lenta, extensão) e o usuário fica na tela branca.
- **Como verificar:** desative JavaScript e abra as páginas principais: conteúdo legível e aviso claro onde não dá para prosseguir.
- **Como corrigir:** renderização no servidor para conteúdo; `<noscript>` com instrução; links reais em vez de `onclick`.

### ACE-11 · Idioma e textos em português claro
- **Conferir:** `lang="pt-BR"` no HTML; textos de botão dizem a ação ("Enviar pedido", não "OK"); erros dizem o que fazer; sem jargão técnico para o público.
- **Por quê:** leitor de tela escolhe a voz pelo `lang`; texto vago gera abandono.
- **Como verificar:** leia cada mensagem de erro e cada botão em voz alta: faz sentido sem contexto?
- **Como corrigir:** reescreva; mantenha os textos num lugar só para revisão.
