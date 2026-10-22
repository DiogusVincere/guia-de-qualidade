# -*- coding: utf-8 -*-
"""Lógica da loja e condição de corrida. Específico do seu site; o nuclei e os scanners genéricos não acham isto.

Tudo é escrita, então só roda em homologação ou local com --escrever e com --config descrevendo o pedido. Em
produção, emite um aviso dizendo o que falta. Cobre:
- adulteração: preço negativo, quantidade negativa/gigante/decimal, para ver se o servidor aceita;
- condição de corrida: vários pedidos simultâneos do mesmo item para ver se vende além do estoque.
Use SEMPRE com dado fictício, num ambiente que você pode sujar.
"""
from __future__ import annotations

import concurrent.futures

from autenticado import _caminho_para
from nucleo import Achado, Alvo, Bloqueado


def _aviso_homologacao(alvo: Alvo, motivo: str) -> Achado:
    return Achado('logica', 'API-05', f'Teste de lógica não feito: {motivo}', 'info', alvo.base_url,
                  motivo, 'adulteração e condição de corrida são escrita; não se testam em produção.',
                  'rode contra homologação com --escrever e --config (pedido_caminho, pedido_corpo).')


def _aceitou(r) -> bool:
    return r.ok and r.status in (200, 201)


def testes_de_logica(alvo: Alvo) -> list[Achado]:
    cfg = alvo.config
    if alvo.ambiente == 'producao' or not alvo.permitir_escrita:
        return [_aviso_homologacao(alvo, 'produção ou escrita desligada')]
    if not cfg or not cfg.pedido_caminho or not cfg.pedido_corpo:
        return [_aviso_homologacao(alvo, 'faltam pedido_caminho e pedido_corpo no --config')]

    achados: list[Achado] = []
    achados += _adulteracao(alvo, cfg)
    achados += _corrida(alvo, cfg)
    return achados


def _adulteracao(alvo: Alvo, cfg) -> list[Achado]:
    achados: list[Achado] = []
    casos = []
    if cfg.pedido_campo_quantidade:
        casos += [('quantidade negativa', cfg.pedido_campo_quantidade, -1, 'WEB-04'),
                  ('quantidade gigante', cfg.pedido_campo_quantidade, 999999999, 'API-11'),
                  ('quantidade decimal', cfg.pedido_campo_quantidade, 1.5, 'WEB-04'),
                  ('quantidade zero', cfg.pedido_campo_quantidade, 0, 'WEB-04')]
    if cfg.pedido_campo_preco:
        casos += [('preço negativo', cfg.pedido_campo_preco, -100, 'WEB-14'),
                  ('preço um centavo', cfg.pedido_campo_preco, 0.01, 'WEB-14')]
    for nome, campo, valor, item in casos:
        try:
            corpo = _caminho_para(cfg.pedido_corpo, campo, valor)
        except (KeyError, IndexError, ValueError):
            continue
        try:
            r = alvo.requisitar('POST', cfg.pedido_caminho, json=corpo, seguir=False)
        except Bloqueado as e:
            return [_aviso_homologacao(alvo, str(e))]
        if _aceitou(r):
            achados.append(Achado('logica', item, f'Pedido com {nome} foi aceito', 'alto',
                                  alvo.url_de(cfg.pedido_caminho),
                                  f'o servidor aceitou {nome} ({valor}) e respondeu {r.status}.',
                                  'valor que não devia passar foi aceito: fraude de preço ou de estoque.',
                                  'valide no servidor (tipo, faixa, mínimo 1, preço sempre do catálogo, nunca do cliente).'))
    return achados


def _corrida(alvo: Alvo, cfg) -> list[Achado]:
    corrida = getattr(cfg, 'corrida', None) or {}
    # usa o próprio pedido_corpo se não houver um específico; só roda se o config disser o estoque esperado
    corpo = corrida.get('corpo', cfg.pedido_corpo)
    estoque = corrida.get('estoque')
    tentativas = int(corrida.get('tentativas', 20))
    if not corpo or estoque is None:
        return [Achado('logica', 'API-05', 'Condição de corrida não testada: falta "corrida" no config', 'info',
                       alvo.url_de(cfg.pedido_caminho),
                       'informe corrida.estoque (quantas unidades existem) e, se quiser, corrida.corpo e tentativas.',
                       'sem saber o estoque, não dá para dizer se vendeu além dele.',
                       'reponha o estoque do item de teste e informe-o no config antes de rodar.')]

    def um(_):
        try:
            r = alvo.requisitar('POST', cfg.pedido_caminho, json=corpo, seguir=False)
            return _aceitou(r)
        except Bloqueado:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(tentativas, 50)) as ex:
        sucessos = sum(1 for ok in ex.map(um, range(tentativas)) if ok)

    achados = [Achado('logica', 'API-04', 'Medição de corrida', 'info', alvo.url_de(cfg.pedido_caminho),
                      f'{tentativas} pedidos simultâneos do mesmo item; {sucessos} aceitos para um estoque de {estoque}.',
                      'número de referência; sucessos acima do estoque indicam baixa não atômica.',
                      'confirme o estoque depois do teste.')]
    if sucessos > int(estoque):
        achados.append(Achado('logica', 'API-05', 'Condição de corrida: vendeu além do estoque', 'alto',
                              alvo.url_de(cfg.pedido_caminho),
                              f'{sucessos} pedidos aceitos para {estoque} em estoque.',
                              'dois pedidos simultâneos passam pela mesma checagem antes de qualquer baixa: '
                              'vende-se o que não existe.',
                              'baixe o estoque de forma atômica (transação, UPDATE condicional) e rejeite quando acabar.'))
    return achados
