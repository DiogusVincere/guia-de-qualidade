# -*- coding: utf-8 -*-
"""Sonda fora-de-banda: usa o colaborador OAST para achar as falhas CEGAS.

SSRF cego, webhook/url que sai para onde eu apontar, e envenenamento por cabeçalho Host. Em todos, a resposta do
alvo não muda — a prova é o servidor dele tocar num endereço meu. Só roda se o colaborador estiver ligado
(scanner --oast / caixa na interface); senão vira um aviso 'info' dizendo como ligar. Tudo por requisições de
leitura (GET), então é seguro em produção.
"""
from __future__ import annotations

from nucleo import Achado, Alvo
from sondas_rede import PARAMS_SSRF

# cabeçalhos que um backend às vezes usa para montar URL (reset de senha, links de e-mail, SSRF por cabeçalho)
CABECALHOS_HOST = ['Host', 'X-Forwarded-Host', 'X-Forwarded-Server', 'X-Host', 'Forwarded']


def _rotas_alvo(alvo: Alvo, teto: int) -> list[str]:
    rotas = ['/'] + [r for r in sorted(alvo.descobertas.get('rotas') or set())
                     if r.startswith(('/api', '/admin', '/auth', '/proxy', '/fetch'))]
    vistas, saida = set(), []
    for r in rotas:
        if r not in vistas:
            vistas.add(r)
            saida.append(r)
    return saida[:teto]


def fora_de_banda(alvo: Alvo) -> list[Achado]:
    oast = getattr(alvo, 'oast', None)
    if oast is None:
        return [Achado('oast', 'API-07', 'Teste fora-de-banda desligado (SSRF cego não verificado)', 'info',
                       alvo.base_url,
                       'sem um colaborador OAST, não dá para confirmar SSRF cego, webhook e envenenamento de Host.',
                       'essas falhas não mudam a resposta do site; só se veem quando o servidor do alvo toca num '
                       'endereço externo que eu controlo.',
                       'rode com --oast (ou marque na interface) para ligar o colaborador interactsh; '
                       'opcional porque fala com um servidor de terceiro.')]
    if not oast.pronto and not oast.registrar():
        return [Achado('oast', 'API-07', 'Colaborador OAST não registrou (fora-de-banda pulado)', 'info',
                       alvo.base_url, f'não consegui falar com o servidor OAST: {oast.erro}.',
                       'sem o colaborador, o teste de falhas cegas não roda.',
                       'confira a rede/saída para o servidor interactsh, ou aponte um próprio com --oast-servidor.')]

    # orçamento de injeção pelo nível (produção vem limitada pelo núcleo)
    teto_rotas = {1: 2, 2: 4, 3: 8, 4: 16, 5: 30}.get(alvo.intensidade, 4)
    teto_params = {1: 4, 2: 6, 3: 10, 4: 14, 5: 20}.get(alvo.intensidade, 6)
    params = PARAMS_SSRF[:teto_params]

    disparos = 0
    for rota in _rotas_alvo(alvo, teto_rotas):
        for par in params:
            rotulo = f'ssrf {rota}?{par}'
            alvo.get(rota, params={par: oast.url(rotulo)}, seguir=False)
            disparos += 1
    # envenenamento por cabeçalho (Host e parentes): o backend monta uma URL com o cabeçalho e sai para ela
    for cab in CABECALHOS_HOST:
        rotulo = f'cabecalho {cab}'
        alvo.requisitar('GET', '/', headers={cab: oast.dominio(rotulo)}, seguir=False)
        disparos += 1
    # Referer/callback como URL completa
    for par, valor in (('Referer', oast.url('cabecalho Referer')),):
        alvo.requisitar('GET', '/', headers={par: valor}, seguir=False)
        disparos += 1

    espera = {1: 3.0, 2: 4.0, 3: 6.0, 4: 8.0, 5: 10.0}.get(alvo.intensidade, 4.0)
    interacoes = oast.coletar(espera=espera)

    achados: list[Achado] = []
    for it in interacoes:
        rotulo = it.get('rotulo') or 'ponto não identificado'
        if rotulo.startswith('cabecalho'):
            achados.append(Achado('oast', 'WEB-10', f'Envenenamento por {rotulo} confirmado (fora-de-banda)',
                                  'alto', alvo.base_url,
                                  f'o servidor tocou meu colaborador via {it["protocolo"]} ({it["remetente"]}) '
                                  f'ao receber o {rotulo}.',
                                  'o backend monta uma URL com o cabeçalho da requisição e sai para ela: '
                                  'envenena reset de senha, links de e-mail e cache, e pode virar SSRF.',
                                  'use um host fixo configurado; valide/ignore o cabeçalho Host de entrada.'))
        else:
            achados.append(Achado('oast', 'API-07', f'SSRF cego confirmado em {rotulo} (fora-de-banda)', 'critico',
                                  alvo.base_url,
                                  f'o servidor buscou meu endereço ({it["protocolo"]} de {it["remetente"]}) a partir '
                                  f'de {rotulo} — a resposta não mudava, mas o servidor saiu para onde eu apontei.',
                                  'SSRF cego: o servidor faz requisições para onde o cliente mandar; dá para alcançar '
                                  'metadados de nuvem, serviços internos e portas da rede privada.',
                                  'nunca busque URL vinda do cliente; use lista de permissão de destinos; '
                                  'bloqueie IP interno e de metadado; resolva e fixe o destino.'))
    if not achados:
        achados.append(Achado('oast', 'API-07', 'Nenhuma interação fora-de-banda', 'info', alvo.base_url,
                              f'injetei meu endereço em {disparos} ponto(s) e o servidor não tocou o colaborador '
                              f'em {espera:.0f}s.',
                              'bom sinal para SSRF cego, webhook e Host nos pontos testados.',
                              'o teste tem janela curta; um SSRF que demora mais pode não aparecer aqui.'))
    return achados
