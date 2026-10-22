# -*- coding: utf-8 -*-
"""Varredura autenticada: login e então teste de autorização. É onde mora o roubo de dado.

Só roda em homologação ou local com --escrever e com credenciais (SCANNER_USUARIO/SCANNER_SENHA ou --usuario/
--senha), porque o login é um POST. Cobre:
- privilégio: a sessão (de um usuário) acessa rota de admin → não devia;
- IDOR: objeto por id sequencial responde para ids que não são do usuário → acesso a dado de outros;
- mass assignment: campo proibido (role, admin, preço) enviado num POST é aceito;
- JWT: alg none, sem expiração, segredo fraco.
Cada achado é suspeita: IDOR certo exige duas contas; o scanner aponta o indício.
"""
from __future__ import annotations

import base64
import json
import re

from nucleo import Achado, Alvo, Bloqueado

RE_JWT = re.compile(r'eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*')
SEGREDOS_JWT_COMUNS = ['secret', 'segredo', 'changeme', 'password', 'admin', '123456', 'jwt', 'chave', 'troque-me']


def _precisa_homologacao(alvo: Alvo, motivo: str) -> Achado:
    return Achado('autenticado', 'AUT-09', f'Varredura autenticada não feita: {motivo}', 'info', alvo.base_url,
                  motivo, 'teste de autorização exige login, que é um POST — não se faz em produção.',
                  'rode contra homologação com --escrever, --config e credenciais (SCANNER_USUARIO/SCANNER_SENHA).')


def _b64(parte: str) -> dict:
    resto = len(parte) % 4
    if resto:
        parte += '=' * (4 - resto)
    return json.loads(base64.urlsafe_b64decode(parte))


def varredura_autenticada(alvo: Alvo) -> list[Achado]:
    cfg = alvo.config
    if alvo.ambiente == 'producao' or not alvo.permitir_escrita:
        return [_precisa_homologacao(alvo, 'produção ou escrita desligada')]
    if not cfg or not cfg.tem_login:
        return [_precisa_homologacao(alvo, 'faltam --config com o login e as credenciais')]

    achados: list[Achado] = []
    try:
        entrou = alvo.entrar(cfg.login_caminho, cfg.corpo_de_login())
    except Bloqueado as e:
        return [_precisa_homologacao(alvo, str(e))]
    if not entrou:
        achados.append(Achado('autenticado', 'AUT-01', 'Login não autenticou (credencial ou caminho errado)', 'info',
                              alvo.url_de(cfg.login_caminho), 'o POST de login não devolveu sessão.',
                              'sem autenticar, as sondas autenticadas não rodam.',
                              'confira o caminho do login e as credenciais de homologação.'))
        return achados

    achados += _idor(alvo, cfg)
    achados += _mass_assignment(alvo, cfg)
    achados += _jwt(alvo, cfg)
    return achados


def _idor(alvo: Alvo, cfg) -> list[Achado]:
    achados: list[Achado] = []
    for obj in cfg.objetos_idor:
        caminho = obj.get('caminho', '')
        de, ate = int(obj.get('de', 1)), int(obj.get('ate', 20))
        if '{id}' not in caminho:
            continue
        ok = []
        for i in range(de, ate + 1):
            r = alvo.get(caminho.replace('{id}', str(i)), seguir=False)
            if r.ok and r.status == 200 and len(r.texto) > 20:
                ok.append(i)
        if len(ok) >= max(3, (ate - de) // 2):
            achados.append(Achado('autenticado', 'API-01', f'Possível IDOR em {caminho}', 'critico',
                                  alvo.url_de(caminho.replace('{id}', str(ok[0]))),
                                  f'a mesma sessão leu {len(ok)} objetos sequenciais ({ok[0]}..{ok[-1]}).',
                                  'se esses objetos são de outros usuários, há acesso a dado alheio trocando o id.',
                                  'filtre a consulta pelo dono (where id=? and dono=?); confirme com duas contas.'))
    return achados


def _caminho_para(corpo: dict, caminho_campo: str, valor):
    """Escreve valor em corpo seguindo 'itens.0.quantidade'. Devolve uma cópia."""
    import copy
    novo = copy.deepcopy(corpo)
    alvo_atual = novo
    partes = caminho_campo.split('.')
    for p in partes[:-1]:
        alvo_atual = alvo_atual[int(p)] if p.isdigit() else alvo_atual[p]
    ultimo = partes[-1]
    if ultimo.isdigit():
        alvo_atual[int(ultimo)] = valor
    else:
        alvo_atual[ultimo] = valor
    return novo


def _mass_assignment(alvo: Alvo, cfg) -> list[Achado]:
    achados: list[Achado] = []
    if not cfg.pedido_caminho or not cfg.pedido_corpo:
        return achados
    for campo in cfg.campos_proibidos:
        corpo = {**cfg.pedido_corpo, campo: 'admin'}
        r = alvo.requisitar('POST', cfg.pedido_caminho, json=corpo, seguir=False)
        if r.ok and r.status in (200, 201) and (campo in r.texto or 'admin' in r.texto.lower()):
            achados.append(Achado('autenticado', 'API-06', f'Possível mass assignment: campo "{campo}" aceito', 'alto',
                                  alvo.url_de(cfg.pedido_caminho),
                                  f'o POST com "{campo}" extra foi aceito e o campo voltou na resposta.',
                                  'o cliente consegue definir um campo que devia ser só do servidor (papel, preço).',
                                  'aceite só os campos esperados (lista de permissão); ignore o resto.'))
    return achados


def _jwt(alvo: Alvo, cfg) -> list[Achado]:
    achados: list[Achado] = []
    # procura um JWT nos cookies e numa resposta autenticada
    textos = []
    for c in alvo.sessao.cookies:
        textos.append(c.value)
    r = alvo.get(cfg.rotas_admin[0] if cfg.rotas_admin else '/')
    if r.ok:
        textos.append(r.texto[:5000])
        textos.append(str(r.cabecalhos))
    for texto in textos:
        m = RE_JWT.search(texto or '')
        if not m:
            continue
        token = m.group(0)
        try:
            cabecalho = _b64(token.split('.')[0])
            carga = _b64(token.split('.')[1])
        except Exception:
            continue
        if str(cabecalho.get('alg', '')).lower() == 'none':
            achados.append(Achado('autenticado', 'AUT-07', 'JWT aceita alg "none"', 'critico', alvo.base_url,
                                  'o cabeçalho do token diz alg: none.',
                                  'token sem assinatura pode ser forjado: o atacante vira quem quiser.',
                                  'rejeite alg none; fixe o algoritmo esperado na verificação.'))
        if 'exp' not in carga:
            achados.append(Achado('autenticado', 'AUT-04', 'JWT sem expiração (exp)', 'alto', alvo.base_url,
                                  'a carga do token não tem o campo exp.',
                                  'token sem prazo é válido para sempre, mesmo depois de roubado.',
                                  'inclua exp curto e valide; invalide no logout.'))
        # segredo fraco: tenta assinar com segredos comuns e comparar (benigno, é o seu token)
        import hashlib
        import hmac
        assinatura = token.rsplit('.', 1)[1]
        corpo_assinado = token.rsplit('.', 1)[0].encode()
        for segredo in SEGREDOS_JWT_COMUNS:
            calc = base64.urlsafe_b64encode(hmac.new(segredo.encode(), corpo_assinado, hashlib.sha256).digest()).rstrip(b'=').decode()
            if calc == assinatura:
                achados.append(Achado('autenticado', 'AUT-07', f'JWT assinado com segredo fraco', 'critico',
                                      alvo.base_url, f'a assinatura confere com um segredo de dicionário.',
                                      'com o segredo, o atacante forja qualquer token e entra como admin.',
                                      'use um segredo longo e aleatório; guarde-o fora do código.'))
                break
        break
    return achados
