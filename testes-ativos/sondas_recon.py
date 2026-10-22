# -*- coding: utf-8 -*-
"""Reconhecimento passivo e técnicas que faltavam, nativas e seguras:

- recon_passivo: subdomínios pelo crt.sh (certificados públicos) e URLs antigas pelo Wayback Machine; as URLs
  antigas entregam parâmetros esquecidos que a injeção passa a testar. Tudo leitura, de fontes públicas.
- csrf: formulário que muda estado sem token anti-CSRF e com cookie sem SameSite.
- prototype_pollution: parâmetros __proto__/constructor que poluem o objeto (indício; confirme).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from nucleo import Achado, Alvo, curl

RE_STAGING = re.compile(r'(staging|homolog|dev|teste|test|qa|sandbox|preview|interno|admin|api|old|beta)', re.I)


def _raiz(host: str) -> str:
    partes = host.split('.')
    return '.'.join(partes[-2:]) if len(partes) >= 2 else host


def _e_local(host: str) -> bool:
    return (host in ('localhost', '127.0.0.1', '::1') or host.startswith(('127.', '192.168.', '10.'))
            or host.endswith(('.local', '.localhost', '.test')) or re.fullmatch(r'[\d.:]+', host or '') is not None)


def recon_passivo(alvo: Alvo) -> list[Achado]:
    import requests
    achados: list[Achado] = []
    host = urlparse(alvo.base_url).hostname or ''
    if _e_local(host):
        return [Achado('recon', 'REC-01', 'Recon passivo não se aplica a localhost/IP', 'info', alvo.base_url,
                       f'{host} é local; crt.sh e Wayback valem para domínio público.',
                       'o reconhecimento externo é sobre o que está exposto na internet.',
                       'rode o recon quando o alvo for um domínio público seu.')]
    raiz = _raiz(host)
    plataforma = raiz.endswith(('.workers.dev', '.pages.dev', '.vercel.app', '.netlify.app', '.github.io'))

    # subdomínios pelo crt.sh (não vale para domínio de plataforma)
    subdominios = set()
    if raiz and not plataforma:
        try:
            r = requests.get('https://crt.sh/', params={'q': '%.' + raiz, 'output': 'json'}, timeout=20)
            for item in r.json():
                for nome in str(item.get('name_value', '')).splitlines():
                    nome = nome.strip().lstrip('*.').lower()
                    if nome.endswith(raiz) and nome != raiz:
                        subdominios.add(nome)
        except Exception:
            pass
    if subdominios:
        sensiveis = sorted(s for s in subdominios if RE_STAGING.search(s.replace(raiz, '')))
        achados.append(Achado('recon', 'REC-01', f'{len(subdominios)} subdomínio(s) públicos (crt.sh)',
                              'medio' if sensiveis else 'info', raiz,
                              f'exemplos: {sorted(subdominios)[:12]}' + (f'; parecem de teste/interno: {sensiveis[:8]}' if sensiveis else ''),
                              'cada subdomínio é superfície de ataque; os de teste/dev costumam ser esquecidos sem proteção.',
                              'confira o que cada subdomínio serve; proteja ou desligue os de teste/homologação expostos.'))

    # URLs antigas pelo Wayback Machine; os parâmetros entram para a injeção testar
    try:
        r = requests.get('http://web.archive.org/cdx/search/cdx',
                         params={'url': host + '/*', 'output': 'json', 'fl': 'original',
                                 'collapse': 'urlkey', 'limit': '800'}, timeout=25)
        linhas = r.json()[1:] if r.ok else []
    except Exception:
        linhas = []
    novas_rotas, novos_params = set(), set()
    for linha in linhas:
        u = urlparse(linha[0] if linha else '')
        if u.netloc and host not in u.netloc:
            continue
        if u.path:
            novas_rotas.add(u.path)
        for par in u.query.split('&'):
            nome = par.split('=')[0]
            if nome and u.path:
                novos_params.add((u.path, nome))
    if novas_rotas:
        alvo.descobertas['rotas'] |= novas_rotas
        alvo.descobertas['parametros'] |= novos_params
        achados.append(Achado('recon', 'REC-02', f'{len(novas_rotas)} URL(s) antigas no Wayback Machine', 'info', host,
                              f'{len(novos_params)} parâmetro(s) histórico(s) entraram para a injeção testar. '
                              f'Ex.: {sorted(novas_rotas)[:10]}',
                              'URL antiga pode apontar para rota/parâmetro descontinuado que ainda responde.',
                              'confira se alguma rota antiga ainda está no ar sem proteção.'))
    if not achados:
        achados.append(Achado('recon', 'REC-01', 'Recon passivo sem novidade', 'info', alvo.base_url,
                              'crt.sh e Wayback não trouxeram subdomínio nem URL nova (ou é domínio de plataforma).',
                              'inventário da superfície externa.', 'nada a fazer.'))
    return achados


def csrf(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    formularios = alvo.descobertas.get('formularios') or []
    # cookies com SameSite protegem contra CSRF; se há, não é achado
    r = alvo.get('/')
    tem_samesite = False
    for k, v in (r.cabecalhos.items() if r.ok else []):
        if k.lower() == 'set-cookie' and 'samesite' in v.lower():
            tem_samesite = True
    for caminho, campos in formularios:
        tem_token = any(re.search(r'csrf|token|authenticity|_token|xsrf', c, re.I) for c in campos)
        sensivel = any(re.search(r'senha|password|email|conta|valor|pedido|endereco', c, re.I) for c in campos)
        if sensivel and not tem_token and not tem_samesite:
            achados.append(Achado('csrf', 'WEB-03', f'Formulário sem proteção anti-CSRF ({caminho})', 'medio',
                                  alvo.url_de(caminho), f'o formulário em {caminho} não tem campo de token nem cookie SameSite.',
                                  'outro site pode fazer o navegador da vítima enviar esse formulário (CSRF).',
                                  'use cookie SameSite=Lax e/ou token anti-CSRF sincronizado no formulário.'))
            break
    return achados


def prototype_pollution(alvo: Alvo) -> list[Achado]:
    import secrets
    achados: list[Achado] = []
    marca = 'pp' + secrets.token_hex(3)
    rotas = ['/'] + [r for r in sorted(alvo.descobertas.get('rotas') or set()) if r.startswith('/api')][:5]
    for caminho in rotas:
        for par in (f'__proto__[{marca}]', f'constructor[prototype][{marca}]'):
            r = alvo.get(caminho, params={par: 'poluido'}, seguir=False)
            if r.ok and (r.status >= 500 or (marca in r.texto and 'poluido' in r.texto)):
                achados.append(Achado('prototype', 'WEB-04', f'Indício de prototype pollution em {caminho}', 'medio',
                                      alvo.url_de(caminho), f'o parâmetro {par} causou {r.status}/reflexo.',
                                      'poluir o protótipo do objeto pode virar negação de serviço ou execução de código.',
                                      'não mescle entrada do cliente em objeto sem filtrar chaves (__proto__, constructor, prototype).',
                                      curl('GET', alvo.url_de(caminho) + f'?{par}=poluido')))
                return achados
    return achados
