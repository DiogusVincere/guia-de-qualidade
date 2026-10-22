# -*- coding: utf-8 -*-
"""Sondas de rede e de aplicação que faltavam, todas globais e não destrutivas:

- dominio_email: SPF, DMARC e subdomínio sequestrável, via DNS sobre HTTPS (não precisa de biblioteca de DNS);
- requisicoes_servidor: open redirect, host header injection e indício de SSRF (metadado de nuvem);
- metodos_http: métodos perigosos habilitados (PUT/DELETE/TRACE) lidos pelo OPTIONS;
- graphql: introspection ligado;
- cliente_web: SRI faltando, tabnabbing e conteúdo misto.

Baseado no OWASP WSTG (config, input, client-side) e no OWASP API Top 10 2023 (SSRF, misconfiguration).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from nucleo import Achado, Alvo, curl

DOH = 'https://cloudflare-dns.com/dns-query'
# serviços onde um CNAME apontando para um recurso que não existe mais permite sequestro de subdomínio
TAKEOVER = {
    'github.io': "There isn't a GitHub Pages site here",
    'herokuapp.com': 'No such app',
    's3.amazonaws.com': 'NoSuchBucket',
    'amazonaws.com': 'NoSuchBucket',
    'azurewebsites.net': 'Error 404 - Web app not found',
    'cloudfront.net': 'Bad request',
    'ghost.io': 'Domain error',
    'fastly.net': 'Fastly error: unknown domain',
    'pages.dev': 'Nothing is here yet',
    'vercel.app': 'DEPLOYMENT_NOT_FOUND',
    'netlify.app': 'Not Found',
}
PARAMS_REDIR = ['redirect', 'redir', 'next', 'return', 'returnurl', 'voltar', 'url', 'u', 'dest', 'destination',
                'continue', 'go', 'link', 'callback']
PARAMS_SSRF = ['url', 'uri', 'link', 'src', 'img', 'image', 'fetch', 'load', 'proxy', 'dest', 'webhook', 'callback',
               'feed', 'host', 'site', 'open', 'file']
METADADO = re.compile(r'ami-id|instance-id|iam/security-credentials|computeMetadata|meta-data', re.I)
INVASOR = 'site-invasor.exemplo'


def _txt(dominio: str) -> list[str]:
    import requests
    try:
        r = requests.get(DOH, params={'name': dominio, 'type': 'TXT'}, headers={'Accept': 'application/dns-json'},
                         timeout=10)
        return [a.get('data', '').strip('"') for a in r.json().get('Answer', [])]
    except Exception:
        return []


def _cname(dominio: str) -> list[str]:
    import requests
    try:
        r = requests.get(DOH, params={'name': dominio, 'type': 'CNAME'}, headers={'Accept': 'application/dns-json'},
                         timeout=10)
        return [a.get('data', '').rstrip('.') for a in r.json().get('Answer', []) if a.get('type') == 5]
    except Exception:
        return []


def _raiz(host: str) -> str:
    partes = host.split('.')
    return '.'.join(partes[-2:]) if len(partes) >= 2 else host


def dominio_email(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    host = urlparse(alvo.base_url).hostname or ''
    raiz = _raiz(host)
    if not raiz or raiz.endswith(('.workers.dev', '.pages.dev', '.vercel.app', '.netlify.app', '.github.io')):
        # domínio de plataforma: SPF/DMARC e e-mail não são do usuário
        return [Achado('dominio', 'OPS-08', 'Domínio de plataforma: e-mail e DNS não são seus', 'info', alvo.base_url,
                       f'o host {host} é de uma plataforma, não um domínio próprio.',
                       'SPF/DMARC e sequestro de subdomínio valem quando você tem domínio próprio.',
                       'ao usar um domínio seu (ex.: sualoja.com.br), rode esta sonda de novo.')]

    spf = [t for t in _txt(raiz) if t.lower().startswith('v=spf1')]
    if not spf:
        achados.append(Achado('dominio', 'DAD-08', 'Domínio sem registro SPF', 'medio', raiz,
                              f'nenhum TXT v=spf1 em {raiz}.',
                              'sem SPF, qualquer um pode enviar e-mail fingindo ser do seu domínio (phishing).',
                              'publique um TXT SPF listando quem pode enviar; termine com -all.'))
    elif 'all' in spf[0] and '+all' in spf[0].replace(' ', ''):
        achados.append(Achado('dominio', 'DAD-08', 'SPF permissivo (+all)', 'medio', raiz, spf[0],
                              '+all deixa qualquer servidor enviar como você.', 'troque +all por -all.'))

    dmarc = [t for t in _txt('_dmarc.' + raiz) if t.lower().startswith('v=dmarc1')]
    if not dmarc:
        achados.append(Achado('dominio', 'DAD-08', 'Domínio sem registro DMARC', 'medio', '_dmarc.' + raiz,
                              f'nenhum TXT v=dmarc1 em _dmarc.{raiz}.',
                              'sem DMARC, o recebedor não sabe o que fazer com e-mail falsificado do seu domínio.',
                              'publique _dmarc com p=quarantine ou p=reject e um rua= para receber relatórios.'))
    elif re.search(r'p=none', dmarc[0], re.I):
        achados.append(Achado('dominio', 'DAD-08', 'DMARC com p=none (só observa)', 'baixo', '_dmarc.' + raiz, dmarc[0],
                              'p=none não bloqueia falsificação, só reporta.',
                              'depois de conferir os relatórios, suba para p=quarantine e p=reject.'))

    # subdomínio sequestrável
    import requests
    for sub in __import__('configuracao').SUBDOMINIOS_COMUNS:
        fqdn = f'{sub}.{raiz}'
        for destino in _cname(fqdn):
            servico = next((s for s in TAKEOVER if destino.endswith(s)), None)
            if not servico:
                continue
            try:
                corpo = requests.get(f'https://{fqdn}', timeout=8).text[:3000]
            except Exception:
                corpo = ''
            if TAKEOVER[servico].lower() in corpo.lower():
                achados.append(Achado('dominio', 'OPS-08', f'Subdomínio sequestrável: {fqdn}', 'alto', fqdn,
                                      f'{fqdn} aponta (CNAME) para {destino} ({servico}), que responde "não existe".',
                                      'o recurso de destino foi removido; um atacante recria no serviço e assume o subdomínio.',
                                      f'remova o CNAME de {fqdn} ou recrie o recurso no {servico}.'))
    return achados


def requisicoes_servidor(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    marca = 'qg' + INVASOR
    # open redirect: parâmetros de redirecionamento que mandam para um host externo
    for par in PARAMS_REDIR:
        r = alvo.get('/', params={par: f'https://{INVASOR}/'}, seguir=False)
        local = next((v for k, v in r.cabecalhos.items() if k.lower() == 'location'), '')
        if r.ok and r.status in (301, 302, 303, 307, 308) and INVASOR in local:
            achados.append(Achado('redirecionamento', 'WEB-10', f'Open redirect no parâmetro {par}', 'medio',
                                  alvo.url_de('/'), f'/?{par}=https://{INVASOR}/ redirecionou para {local}.',
                                  'redirecionamento aberto é isca de phishing que usa o seu domínio.',
                                  'aceite só caminho relativo (começando com / e não //); ou mapeie nomes para rotas.',
                                  curl('GET', alvo.url_de('/') + f'?{par}=https://{INVASOR}/')))
            break
    # host header injection: o servidor reflete o Host que eu mandar
    r = alvo.requisitar('GET', '/', headers={'Host': INVASOR}, seguir=False)
    local = next((v for k, v in r.cabecalhos.items() if k.lower() == 'location'), '')
    if r.ok and (INVASOR in local or (r.texto and INVASOR in r.texto[:3000])):
        achados.append(Achado('redirecionamento', 'WEB-10', 'Host header injection', 'medio', alvo.base_url,
                              f'o cabeçalho Host "{INVASOR}" voltou refletido na resposta.',
                              'o Host refletido envenena links, redefinição de senha e cache.',
                              'use um host fixo configurado, não o cabeçalho Host da requisição.'))
    # SSRF: parâmetro que busca uma URL — tenta o endereço de metadado da nuvem (benigno)
    for par in PARAMS_SSRF:
        for destino in ('http://169.254.169.254/latest/meta-data/', 'http://metadata.google.internal/computeMetadata/v1/'):
            r = alvo.get('/', params={par: destino}, seguir=False)
            if r.ok and r.status == 200 and METADADO.search(r.texto[:3000]):
                achados.append(Achado('ssrf', 'API-07', f'Possível SSRF no parâmetro {par}', 'critico', alvo.url_de('/'),
                                      f'/?{par}={destino} devolveu conteúdo de metadado de nuvem.',
                                      'o servidor busca a URL que o cliente manda: dá para ler metadados e credenciais internas.',
                                      'nunca busque URL vinda do cliente; use lista de permissão de destinos; bloqueie IPs internos.',
                                      curl('GET', alvo.url_de('/') + f'?{par}={destino}')))
                return achados
    return achados


def metodos_http(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    r = alvo.requisitar('OPTIONS', '/', seguir=False)
    permitidos = next((v for k, v in r.cabecalhos.items() if k.lower() == 'allow'), '') if r.ok else ''
    perigosos = [m for m in ('PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH') if m in permitidos.upper()]
    if perigosos:
        achados.append(Achado('metodos', 'API-02', f'Métodos perigosos habilitados: {", ".join(perigosos)}', 'medio',
                              alvo.base_url, f'OPTIONS / respondeu Allow: {permitidos}.',
                              'TRACE ajuda XST; PUT/DELETE sem controle alteram ou apagam; CONNECT abre túnel.',
                              'deixe só os métodos que a rota usa; desligue TRACE e CONNECT no servidor/CDN.'))
    return achados


def graphql(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    consulta = '{__schema{queryType{name}types{name}}}'
    for caminho in __import__('configuracao').ROTAS_GRAPHQL:
        r = alvo.get(caminho, params={'query': consulta}, seguir=False)   # introspection via GET (leitura)
        corpo = r.texto.lstrip()[:1] if r.ok else ''
        # precisa ser JSON de verdade com o esquema, não a página do SPA que só refletiu o texto da consulta
        if r.ok and r.status == 200 and corpo == '{' and '"__schema"' in r.texto and '"types"' in r.texto:
            achados.append(Achado('graphql', 'API-09', f'GraphQL com introspection ligado ({caminho})', 'medio',
                                  alvo.url_de(caminho), 'a consulta de introspection devolveu o esquema.',
                                  'o esquema inteiro (tipos, campos, mutations) fica visível para quem ataca.',
                                  'desligue a introspection em produção; limite profundidade e lote das consultas.',
                                  curl('GET', alvo.url_de(caminho) + '?query=' + consulta)))
            break
    return achados


def cliente_web(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    paginas = [('/', alvo.get('/'))]
    r = paginas[0][1]
    if not r.ok:
        return achados
    html = r.texto
    # script externo sem integrity (SRI)
    for m in re.finditer(r'<script[^>]+src=["\'](https?://[^"\']+)["\'][^>]*>', html, re.I):
        tag = m.group(0)
        host_script = urlparse(m.group(1)).hostname or ''
        if host_script and host_script != (urlparse(alvo.base_url).hostname or '') and 'integrity=' not in tag.lower():
            achados.append(Achado('cliente', 'WEB-11', 'Script externo sem Subresource Integrity (SRI)', 'baixo',
                                  m.group(1), f'{m.group(1)} carregado sem integrity.',
                                  'se a CDN desse script for comprometida, ela executa no seu site.',
                                  'adicione integrity= e crossorigin= à tag, ou sirva o script do seu domínio.'))
            break
    # tabnabbing: target=_blank sem rel=noopener
    for m in re.finditer(r'<a\b[^>]*target=["\']_blank["\'][^>]*>', html, re.I):
        if 'noopener' not in m.group(0).lower() and 'href="http' in m.group(0).lower():
            achados.append(Achado('cliente', 'WEB-11', 'Link target=_blank sem rel=noopener (tabnabbing)', 'baixo',
                                  alvo.base_url, 'há link que abre em nova aba sem rel="noopener".',
                                  'a página aberta pode trocar a sua aba original por uma falsa (tabnabbing).',
                                  'adicione rel="noopener noreferrer" aos links target="_blank".'))
            break
    # conteúdo misto: recurso http:// numa página https
    if urlparse(alvo.base_url).scheme == 'https':
        for m in re.finditer(r'(?:src|href)=["\'](http://[^"\']+)["\']', html, re.I):
            achados.append(Achado('cliente', 'DAD-09', 'Conteúdo misto (recurso http numa página https)', 'medio',
                                  m.group(1), f'a página carrega {m.group(1)} por http.',
                                  'recurso por http numa página https pode ser interceptado e quebra o cadeado.',
                                  'sirva todo recurso por https.'))
            break
    return achados
