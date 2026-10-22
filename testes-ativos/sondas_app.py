# -*- coding: utf-8 -*-
"""Sondas de aplicação que faltavam: OAuth/SSO, WebSocket e XSS no DOM (com navegador opcional).

Todas globais. OAuth e WebSocket usam só a biblioteca padrão. O DOM XSS usa o Playwright SE estiver instalado;
senão, avisa como instalar, como o nuclei. Baseado no OWASP ASVS (V9 tokens, V10 OAuth, V3 front) e no WSTG.
"""
from __future__ import annotations

import base64
import os
import re
import socket
import ssl
from urllib.parse import urljoin, urlparse

from nucleo import Achado, Alvo, curl

WELLKNOWN = ['/.well-known/openid-configuration', '/.well-known/oauth-authorization-server']
RE_WS = re.compile(r'(wss?://[A-Za-z0-9_.:/\-]+)')
RE_NEW_WS = re.compile(r'new\s+WebSocket\(\s*["\'`]([^"\'`]+)["\'`]')
INVASOR = 'https://site-invasor.exemplo/'


# =====================================================================================================================
# OAuth / SSO
# =====================================================================================================================
def oauth_sso(alvo: Alvo) -> list[Achado]:
    import json
    import requests
    achados: list[Achado] = []
    descoberta = None
    for caminho in WELLKNOWN:
        r = alvo.get(caminho, seguir=False)
        if r.ok and r.status == 200 and r.texto.lstrip()[:1] == '{':
            try:
                descoberta = json.loads(r.texto)
                break
            except Exception:
                pass
    if descoberta:
        auth = descoberta.get('authorization_endpoint', '')
        token = descoberta.get('token_endpoint', '')
        pkce = descoberta.get('code_challenge_methods_supported') or []
        if auth and not auth.startswith('https://'):
            achados.append(Achado('oauth', 'DAD-09', 'Endpoint de autorização OAuth sem HTTPS', 'alto', auth,
                                  f'authorization_endpoint = {auth}', 'o fluxo OAuth por http vaza código e token.',
                                  'sirva todos os endpoints OAuth por https.'))
        if 'S256' not in pkce:
            achados.append(Achado('oauth', 'AUT-07', 'OAuth sem PKCE (S256)', 'medio', alvo.url_de(WELLKNOWN[0]),
                                  f'code_challenge_methods_supported = {pkce or "ausente"}.',
                                  'sem PKCE, o código de autorização interceptado é trocado por token por quem o roubar.',
                                  'exija PKCE com S256 no provedor e no cliente.'))
        achados.append(Achado('oauth', 'REC-01', 'OAuth/OIDC descoberto', 'info', alvo.url_de(WELLKNOWN[0]),
                              f'authorization_endpoint={auth or "?"}, token_endpoint={token or "?"}.',
                              'inventário do provedor de identidade.', 'confira que só os fluxos necessários estão ligados.'))

    # link de login OAuth na home: fluxo implícito e falta de state
    r = alvo.get('/')
    if r.ok:
        for m in re.finditer(r'href=["\']([^"\']*(?:oauth|authorize|connect/authorize|auth/)[^"\']*)["\']', r.texto, re.I):
            link = m.group(1)
            if 'response_type=token' in link:
                achados.append(Achado('oauth', 'AUT-07', 'OAuth em fluxo implícito (response_type=token)', 'medio',
                                      urljoin(alvo.base_url, link), 'o link de login pede token direto na URL.',
                                      'o fluxo implícito expõe o token no histórico e no referer; foi descontinuado.',
                                      'use o fluxo de código de autorização com PKCE.'))
            if 'client_id=' in link and 'state=' not in link:
                achados.append(Achado('oauth', 'WEB-03', 'Login OAuth sem parâmetro state', 'medio',
                                      urljoin(alvo.base_url, link), 'o link de autorização não leva state.',
                                      'sem state, o login fica aberto a CSRF (login forçado na conta do atacante).',
                                      'inclua um state aleatório e valide-o no retorno.'))
            # redirect_uri aberto: troca o destino por um host externo e vê se o provedor aceita
            if 'redirect_uri=' in link and 'client_id=' in link:
                adulterado = re.sub(r'redirect_uri=[^&]*', 'redirect_uri=' + INVASOR.replace(':', '%3A').replace('/', '%2F'), link)
                rr = alvo.get(adulterado, seguir=False)
                destino = next((v for k, v in rr.cabecalhos.items() if k.lower() == 'location'), '')
                if rr.ok and rr.status in (301, 302, 303, 307, 308) and 'site-invasor.exemplo' in destino:
                    achados.append(Achado('oauth', 'AUT-07', 'OAuth aceita redirect_uri de outro site (takeover)',
                                          'critico', urljoin(alvo.base_url, link),
                                          f'o authorize redirecionou para {destino} com redirect_uri externo.',
                                          'o atacante recebe o código de autorização da vítima e assume a conta.',
                                          'valide redirect_uri contra uma lista exata registrada; nunca aceite host arbitrário.'))
            break
    return achados


# =====================================================================================================================
# WebSocket
# =====================================================================================================================
def _handshake_ws(host: str, porta: int, caminho: str, tls: bool, origem: str, timeout: float) -> str:
    chave = base64.b64encode(os.urandom(16)).decode()
    pedido = (f'GET {caminho or "/"} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
              f'Sec-WebSocket-Key: {chave}\r\nSec-WebSocket-Version: 13\r\nOrigin: {origem}\r\n\r\n')
    s = socket.create_connection((host, porta), timeout=timeout)
    try:
        if tls:
            s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
        s.sendall(pedido.encode())
        return s.recv(4096).decode('latin-1', 'ignore').split('\r\n')[0]
    finally:
        s.close()


def websocket(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    urls = set()
    for u in alvo.descobertas.get('js', []):
        r = alvo.get(u)
        if r.ok:
            urls |= set(RE_WS.findall(r.texto)) | set(RE_NEW_WS.findall(r.texto))
    home = alvo.get('/')
    if home.ok:
        urls |= set(RE_WS.findall(home.texto))
    urls = {u for u in urls if '://' in u}
    if not urls:
        return [Achado('websocket', 'REC-01', 'Nenhum WebSocket encontrado', 'info', alvo.base_url,
                       'não achei endereço ws:// ou wss:// no front.',
                       'se o site usa WebSocket por outro caminho, informe-o.',
                       'nada a fazer se o site não usa WebSocket.')]

    for u in list(urls)[:5]:
        p = urlparse(u)
        tls = p.scheme == 'wss'
        host = p.hostname or ''
        porta = p.port or (443 if tls else 80)
        if not tls and urlparse(alvo.base_url).scheme == 'https':
            achados.append(Achado('websocket', 'DAD-09', f'WebSocket sem criptografia (ws://) em {host}', 'medio', u,
                                  f'{u} usa ws:// numa aplicação https.',
                                  'o tráfego do WebSocket vai em texto puro e pode ser interceptado.',
                                  'use wss:// (TLS) para todo WebSocket.'))
        try:
            mesma = _handshake_ws(host, porta, p.path, tls, alvo.base_url.rstrip('/'), alvo.timeout)
            estranha = _handshake_ws(host, porta, p.path, tls, 'https://site-invasor.exemplo', alvo.timeout)
        except Exception:
            continue
        if '101' in estranha:
            achados.append(Achado('websocket', 'API-08', f'WebSocket aceita origem de outro site (CSWSH) em {host}',
                                  'alto', u, 'o handshake com Origin de outro site foi aceito (101).',
                                  'outro site abre o WebSocket com a sessão da vítima e lê/escreve dados (hijacking).',
                                  'valide o cabeçalho Origin no handshake e exija autenticação na conexão.'))
    return achados


# =====================================================================================================================
# XSS no DOM (precisa do Playwright; sem ele, avisa)
# =====================================================================================================================
def _playwright_ok():
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except Exception:
        return False


def dom_xss(alvo: Alvo) -> list[Achado]:
    if not _playwright_ok():
        return [Achado('dom', 'WEB-05', 'XSS no DOM não testado (Playwright não instalado)', 'info', alvo.base_url,
                       'o teste de XSS no DOM precisa de um navegador sem tela.',
                       'XSS que só acontece no navegador (via fragmento #, postMessage, render do SPA) não aparece '
                       'nas sondas de texto.',
                       'instale: pip install playwright && playwright install chromium; e rode de novo.')]
    from playwright.sync_api import sync_playwright
    achados: list[Achado] = []
    marca = 'qgx' + os.urandom(3).hex()
    # rotas a testar: home + algumas descobertas, no fragmento e em parâmetros comuns
    caminhos = ['/'] + [r for r in sorted(alvo.descobertas.get('rotas') or set()) if not r.startswith('/api')][:8]
    cargas = [f'#<img src=x onerror=window.__{marca}=1>', f'?q=<img src=x onerror=window.__{marca}=1>',
              f'#"><script>window.__{marca}=1</script>']
    try:
        with sync_playwright() as pw:
            nav = pw.chromium.launch(headless=True)
            pag = nav.new_context(ignore_https_errors=True).new_page()
            for caminho in caminhos:
                for carga in cargas:
                    url = alvo.url_de(caminho) + carga
                    try:
                        pag.goto(url, timeout=int(alvo.timeout * 1000), wait_until='networkidle')
                        executou = pag.evaluate(f'window.__{marca} === 1')
                    except Exception:
                        executou = False
                    pag.evaluate(f'window.__{marca} = 0')
                    if executou:
                        achados.append(Achado('dom', 'WEB-05', f'XSS no DOM em {caminho}', 'critico', url,
                                              f'a carga no fragmento/parâmetro executou script no navegador.',
                                              'XSS baseado em DOM: executa na vítima sem passar pela proteção do servidor.',
                                              'não use dado da URL/postMessage em innerHTML/eval; sanitize no cliente.',
                                              curl('GET', url)))
                        break
            nav.close()
    except Exception as e:  # noqa: BLE001
        return [Achado('dom', 'OPS-06', 'Teste de DOM XSS falhou', 'info', alvo.base_url,
                       f'{type(e).__name__}: {e}', 'o navegador sem tela não rodou.',
                       'confira a instalação do Playwright (playwright install chromium).')]
    if not achados:
        achados.append(Achado('dom', 'WEB-05', 'Sem XSS no DOM detectado', 'info', alvo.base_url,
                              f'{len(caminhos)} rota(s) testadas no navegador, nada executou.',
                              'bom sinal para as cargas testadas.',
                              'o teste de DOM não é exaustivo; revise os sumidouros no código (CLI-01).'))
    return achados
