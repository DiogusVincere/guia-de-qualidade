# 22 · Logs, monitoramento e resposta

A camada que decide se um ataque é descoberto em minutos ou em meses. É o capítulo V16 do OWASP ASVS. Ferramenta
nenhuma substitui: é registro, alerta e um plano escrito. Vale para qualquer sistema no ar.

### LOG-01 · O que importa é registrado, com contexto
- **Conferir:** login (sucesso e falha), troca de senha, acesso de admin, erro 5xx, ação sensível — cada um com quem, quando, de onde e um identificador.
- **Por quê:** sem registro não há investigação; depois do incidente é tarde para começar a logar.
- **Como verificar:** force cada evento e veja a linha no log; confira que dá para seguir uma requisição ponta a ponta.
- **Como corrigir:** logger estruturado nos pontos sensíveis; propague um id de requisição.

### LOG-02 · O log não vira o vazamento
- **Conferir:** senha, token, cartão, CPF e e-mail completo não entram no log; nada de corpo de requisição com segredo.
- **Por quê:** o log vai para serviço de terceiro e é lido por muita gente; dado sensível ali é incidente.
- **Como verificar:** leia 50 linhas do log de produção procurando dado sensível; `grep` por campos de senha/token nos pontos de log.
- **Como corrigir:** mascare (4 últimos dígitos); não logue corpo inteiro; filtre campos sensíveis no logger.

### LOG-03 · Alguém é avisado quando algo foge do normal
- **Conferir:** alerta para pico de 5xx, pico de 401/403 (força bruta), pico de 429, erro novo, queda do site.
- **Por quê:** log que ninguém lê não protege; o ataque precisa gerar um aviso.
- **Como verificar:** provoque um pico em homologação e veja o alerta chegar (e-mail, mensagem).
- **Como corrigir:** regra de alerta no painel do provedor ou num monitor externo apontando para a rota de saúde.

### LOG-04 · Há um WAF ou camada que barra o básico
- **Conferir:** proteção contra bot, regras contra injeção e contra abuso (Cloudflare, provedor), rate limit no limite da borda.
- **Por quê:** barra o ruído automatizado antes de chegar na aplicação e dá tempo de reagir.
- **Como verificar:** confira as regras ativas no painel; teste que um padrão óbvio de ataque é barrado.
- **Como corrigir:** ative o WAF/regras do provedor; não dependa só dele (é uma camada, não a única).

### LOG-05 · Existe um plano de resposta a incidente, escrito
- **Conferir:** quem é avisado, como se estima a extensão, como se troca segredo, como se comunica a titulares e à autoridade (prazo da LGPD), como se restaura.
- **Por quê:** no meio do incidente ninguém pensa com calma; o plano é o que salva.
- **Como verificar:** `docs/OPERACAO.md` tem a seção "Incidente" com passos e contatos; alguém que não participou consegue seguir.
- **Como corrigir:** escreva meia página; melhor incompleto que inexistente. Ver [05 DAD-10](05-dados-pessoais.md).

### LOG-06 · O log é guardado tempo suficiente e protegido
- **Conferir:** retenção que cubra a descoberta tardia (semanas a meses), log fora do servidor que ele descreve, acesso restrito, sem alteração.
- **Por quê:** o atacante apaga o log local; investigação precisa do histórico íntegro.
- **Como verificar:** confira a retenção e onde o log fica; veja quem tem acesso.
- **Como corrigir:** envie o log para fora (serviço de log); restrinja acesso; defina a retenção no inventário.

### LOG-07 · Monitor externo confirma que o site está de pé
- **Conferir:** um serviço de fora chama a rota de saúde a cada poucos minutos e avisa na queda.
- **Por quê:** descobrir que caiu pelo cliente é o pior jeito.
- **Como verificar:** desligue o serviço em homologação e veja o aviso; ver [10 OPS-07](10-deploy-e-operacao.md).
- **Como corrigir:** monitor gratuito apontando para `/api/saude` (ou equivalente).
