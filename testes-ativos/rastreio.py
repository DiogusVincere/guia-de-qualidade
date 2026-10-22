# -*- coding: utf-8 -*-
"""Crawler e segredos no cliente. Tudo leitura, seguro em produção.

- rastrear(): segue links do mesmo host, lê sitemap.xml e robots.txt, e vasculha o JavaScript servido atrás de
  rotas de API escondidas (fetch/axios/URLs). Preenche alvo.descobertas, que a injeção usa para saber onde testar.
- segredos_no_cliente(): procura chave de API, token, credencial e source maps (.js.map) expostos no front — o que
  um atacante lê abrindo o F12 ou baixando o bundle.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from nucleo import Achado, Alvo

MAX_PAGINAS = 80
MAX_JS = 40
# links que não se segue (evita logout, ações destrutivas, âncoras e protocolos não http)
EVITAR = re.compile(r'(logout|sair|delete|apagar|remover|excluir|signout)', re.I)

RE_HREF = re.compile(r'(?:href|src)=["\']([^"\']+)["\']', re.I)
RE_FORM = re.compile(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', re.I | re.S)
RE_INPUT = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.I)
RE_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
# rotas de API dentro do JS: fetch('/api/..'), axios.get("/..."), url: "/api/..", "/api/x"
RE_ROTA_JS = re.compile(r'["\'`](/(?:api|admin|auth|v\d)/[A-Za-z0-9_\-/{}.:]+)["\'`]')

# padrões de segredo que não deviam estar no front
SEGREDOS = [
    (re.compile(r'AKIA[0-9A-Z]{16}'), 'chave de acesso AWS', 'critico'),
    (re.compile(r'AIza[0-9A-Za-z_\-]{35}'), 'chave de API Google', 'alto'),
    (re.compile(r'sk_live_[0-9A-Za-z]{10,}'), 'chave secreta Stripe (live)', 'critico'),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), 'token do GitHub', 'critico'),
    (re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}'), 'token do Slack', 'critico'),
    (re.compile(r'-----BEGIN (?:RSA |EC |)PRIVATE KEY-----'), 'chave privada', 'critico'),
    (re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'), 'token JWT', 'medio'),
    (re.compile(r'(?i)(api[_-]?key|secret|token|senha|password|authorization)["\']?\s*[:=]\s*["\'][^"\']{12,}["\']'),
     'credencial embutida no código', 'alto'),
    (re.compile(r'(?i)cloudinary://[^"\'\s]+'), 'URL do Cloudinary com segredo', 'critico'),
]
# telltale de que o valor é de exemplo, para não gritar à toa
FALSOS = re.compile(r'(?i)(troque-me|exemplo|example|your[_-]?key|xxxx|<[^>]+>|placeholder|dummy|changeme)')


def rastrear(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    vistas: set[str] = set()
    fila = [alvo.base_url]
    rotas, parametros, js, formularios = set(), set(), [], []

    # sitemap e robots como sementes
    for semente in ('/robots.txt', '/sitemap.xml'):
        r = alvo.get(semente)
        if r.ok and r.status == 200:
            for cam in re.findall(r'(?:Allow|Disallow|Sitemap):\s*(\S+)', r.texto) + re.findall(r'<loc>([^<]+)</loc>', r.texto):
                u = urljoin(alvo.base_url, cam)
                if alvo.mesmo_host(u):
                    fila.append(u)

    while fila and len(vistas) < MAX_PAGINAS:
        url = fila.pop(0)
        if url in vistas or not alvo.mesmo_host(url):
            continue
        vistas.add(url)
        caminho = urlparse(url).path or '/'
        rotas.add(caminho)
        r = alvo.get(url)
        if not r.ok or 'html' not in r.cabecalhos.get('Content-Type', r.cabecalhos.get('content-type', '')).lower():
            continue
        # links
        for alvo_link in RE_HREF.findall(r.texto):
            if alvo_link.startswith(('mailto:', 'tel:', 'javascript:', '#', 'data:')):
                continue
            u = urljoin(url, alvo_link)
            if not alvo.mesmo_host(u) or EVITAR.search(u):
                continue
            p = urlparse(u)
            rotas.add(p.path or '/')
            if p.query:
                for par in p.query.split('&'):
                    nome = par.split('=')[0]
                    if nome:
                        parametros.add((p.path or '/', nome))
            if u not in vistas and u.split('#')[0] not in vistas:
                fila.append(u.split('#')[0])
        # formulários e seus campos
        for action, miolo in RE_FORM.findall(r.texto):
            cam = urlparse(urljoin(url, action)).path or caminho
            campos = RE_INPUT.findall(miolo)
            formularios.append((cam, campos))
            for c in campos:
                parametros.add((cam, c))
        # arquivos JS
        for src in RE_SCRIPT_SRC.findall(r.texto):
            u = urljoin(url, src)
            if alvo.mesmo_host(u) and u not in js and len(js) < MAX_JS:
                js.append(u)

    # rotas escondidas no JS
    for u in js:
        r = alvo.get(u)
        if not r.ok:
            continue
        for rota in RE_ROTA_JS.findall(r.texto):
            rotas.add(rota)
            # parâmetros de API comuns também entram para a injeção
            parametros.add((rota, 'id'))
            parametros.add((rota, 'q'))

    alvo.descobertas['rotas'] = rotas
    alvo.descobertas['parametros'] = parametros
    alvo.descobertas['js'] = js
    alvo.descobertas['formularios'] = formularios
    achados.append(Achado('rastreio', 'API-06', 'Mapa do site', 'info', alvo.base_url,
                          f'{len(vistas)} página(s), {len(rotas)} rota(s), {len(parametros)} parâmetro(s), '
                          f'{len(js)} arquivo(s) JS. Rotas de API descobertas no JS: '
                          f'{sorted(r for r in rotas if r.startswith(("/api", "/admin", "/auth")))[:20]}',
                          'é a superfície que o scanner conseguiu enxergar; o que não aparece aqui não foi testado.',
                          'confira se há rota sensível no JS que não devia ser pública.'))
    return achados


def segredos_no_cliente(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    # junta o HTML da home e todo o JS descoberto
    alvos_texto = [('/', alvo.get('/'))]
    for u in alvo.descobertas.get('js', []):
        alvos_texto.append((u, alvo.get(u)))

    vistos: set[tuple] = set()
    for onde, r in alvos_texto:
        if not r.ok:
            continue
        for padrao, descricao, grav in SEGREDOS:
            for m in padrao.finditer(r.texto):
                trecho = m.group(0)
                if FALSOS.search(trecho):
                    continue
                chave = (descricao, trecho[:16])
                if chave in vistos:
                    continue
                vistos.add(chave)
                achados.append(Achado('segredos', 'SEG-01', f'{descricao} no código do front', grav,
                                      alvo.url_de(onde) if onde.startswith('/') else onde,
                                      f'encontrado no conteúdo servido: "{trecho[:12]}…" (mascarado).',
                                      'qualquer um lê o JavaScript do site; chave ali é chave pública.',
                                      'tire o segredo do front; o que precisa de chave privada vai para o backend; '
                                      'troque a chave que já vazou.'))
        # source map expondo o código-fonte
        if onde.endswith('.js'):
            mapa = alvo.get(onde + '.map')
            if mapa.ok and mapa.status == 200 and '"version"' in mapa.texto[:200] and 'sources' in mapa.texto[:500]:
                achados.append(Achado('segredos', 'WEB-08', 'Source map expõe o código-fonte', 'medio',
                                      onde + '.map', f'{onde}.map responde 200 com o mapa do código.',
                                      'o source map reconstrói o código-fonte original, com rotas e lógica internas.',
                                      'não publique .map em produção (desligue no build ou bloqueie no CDN).'))
    return achados
