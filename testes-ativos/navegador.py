# -*- coding: utf-8 -*-
"""Rastreio por navegador de verdade (Playwright), para enxergar o que o crawler de texto não vê.

Um site que monta a tela no cliente (React/Vue/SPA) quase não tem link no HTML cru: tudo aparece depois que o
JavaScript roda e faz as chamadas de API. Esta sonda abre um navegador sem tela, carrega a home e algumas rotas,
espera a rede sossegar e recolhe: os links e formulários do DOM já montado, e TODAS as requisições que a página
disparou (fetch/XHR) — é daí que saem as rotas de API reais. Tudo isso entra em alvo.descobertas, que a injeção,
o fora-de-banda e a descoberta usam. Só leitura: navega e lê, não envia formulário.

Sem o Playwright instalado, vira um aviso 'info' dizendo como instalar (igual ao DOM XSS e ao nuclei).
"""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

from nucleo import Achado, Alvo

MAX_PAGINAS = 25


def _playwright_ok() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except Exception:
        return False


def rastreio_navegador(alvo: Alvo) -> list[Achado]:
    if not _playwright_ok():
        return [Achado('navegador', 'API-06', 'Rastreio por navegador não feito (Playwright não instalado)', 'info',
                       alvo.base_url,
                       'um site que renderiza no cliente (SPA) quase não expõe rota no HTML cru; sem navegador, a '
                       'superfície real fica escondida.',
                       'as rotas de API aparecem só quando o JavaScript roda e chama o backend.',
                       'instale: pip install playwright && playwright install chromium; e rode de novo.')]
    from playwright.sync_api import sync_playwright

    rotas = set(alvo.descobertas.get('rotas') or set())
    parametros = set(alvo.descobertas.get('parametros') or set())
    js = list(alvo.descobertas.get('js') or [])
    formularios = list(alvo.descobertas.get('formularios') or [])
    pedidos_api: set[str] = set()      # URLs que a página chamou (fetch/XHR) no mesmo host

    # sementes: home + rotas de página já conhecidas (não as de API)
    sementes = [alvo.base_url] + [alvo.url_de(r) for r in sorted(rotas) if not r.startswith('/api')]
    vistas: set[str] = set()
    fila = []
    for s in sementes:
        if s not in fila:
            fila.append(s)

    try:
        with sync_playwright() as pw:
            nav = pw.chromium.launch(headless=True)
            ctx = nav.new_context(ignore_https_errors=True)
            pag = ctx.new_page()

            def ao_pedir(req):
                u = req.url
                if alvo.mesmo_host(u):
                    p = urlparse(u)
                    cam = p.path or '/'
                    rotas.add(cam)
                    if cam.startswith(('/api', '/v1', '/v2', '/graphql', '/auth')):
                        pedidos_api.add(f'{req.method} {cam}')
                    if p.query:
                        for q in p.query.split('&'):
                            nome = q.split('=')[0]
                            if nome:
                                parametros.add((cam, nome))

            pag.on('request', ao_pedir)

            while fila and len(vistas) < MAX_PAGINAS:
                url = fila.pop(0)
                if url in vistas or not alvo.mesmo_host(url):
                    continue
                vistas.add(url)
                try:
                    pag.goto(url, timeout=int(alvo.timeout * 1000), wait_until='networkidle')
                except Exception:
                    continue
                # links do DOM já montado
                try:
                    hrefs = pag.eval_on_selector_all(
                        'a[href]', 'els => els.map(e => e.getAttribute("href"))') or []
                except Exception:
                    hrefs = []
                for href in hrefs:
                    if not href or href.startswith(('mailto:', 'tel:', 'javascript:', '#', 'data:')):
                        continue
                    u = urljoin(url, href).split('#')[0]
                    if not alvo.mesmo_host(u):
                        continue
                    p = urlparse(u)
                    rotas.add(p.path or '/')
                    if p.query:
                        for q in p.query.split('&'):
                            nome = q.split('=')[0]
                            if nome:
                                parametros.add((p.path or '/', nome))
                    if u not in vistas and u not in fila and not p.path.startswith('/api'):
                        fila.append(u)
                # formulários e campos do DOM
                try:
                    forms = pag.eval_on_selector_all(
                        'form', 'els => els.map(f => ({a: f.getAttribute("action") || "", '
                        'c: Array.from(f.querySelectorAll("[name]")).map(i => i.getAttribute("name"))}))') or []
                except Exception:
                    forms = []
                for f in forms:
                    cam = urlparse(urljoin(url, f.get('a') or url)).path or '/'
                    campos = [c for c in (f.get('c') or []) if c]
                    formularios.append((cam, campos))
                    for c in campos:
                        parametros.add((cam, c))
            nav.close()
    except Exception as e:  # noqa: BLE001
        return [Achado('navegador', 'OPS-06', 'Rastreio por navegador falhou', 'info', alvo.base_url,
                       f'{type(e).__name__}: {e}', 'o navegador sem tela não rodou.',
                       'confira a instalação do Playwright (playwright install chromium).')]

    alvo.descobertas['rotas'] = rotas
    alvo.descobertas['parametros'] = parametros
    alvo.descobertas['js'] = js
    alvo.descobertas['formularios'] = formularios

    rotas_api = sorted(r for r in rotas if r.startswith(('/api', '/v1', '/v2', '/graphql', '/auth')))
    return [Achado('navegador', 'API-06', 'Mapa do site pelo navegador', 'info', alvo.base_url,
                   f'{len(vistas)} página(s) abertas no navegador; {len(pedidos_api)} chamada(s) de API observadas; '
                   f'total agora: {len(rotas)} rota(s), {len(parametros)} parâmetro(s). '
                   f'Rotas de API: {rotas_api[:20]}',
                   'é a superfície que só aparece com o JavaScript rodando — o que a leitura do HTML cru não via.',
                   'confira se alguma dessas chamadas de API devia exigir autenticação ou não devia ser pública.')]
