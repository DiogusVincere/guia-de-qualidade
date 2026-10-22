# -*- coding: utf-8 -*-
"""As sondas: cada uma recebe o Alvo e devolve uma lista de Achado. Todas são não destrutivas.

Em produção só saem requisições de leitura e as cargas de nível vêm limitadas pelo núcleo. As cargas de injeção
usam marcadores que DETECTAM a falha (reflexão, erro de SQL, assinatura de arquivo do sistema), nunca cargas que
alteram ou apagam dado. O que uma sonda não consegue testar no ambiente atual vira um achado 'info' dizendo o que
falta, em vez de silêncio.
"""
from __future__ import annotations

import concurrent.futures
import contextlib
import re
import secrets
import statistics
from urllib.parse import urlparse, quote

from nucleo import Achado, Alvo, Bloqueado, curl

# caminhos que não deviam ser servidos; cada um só é achado se o CORPO for mesmo daquele arquivo (a assinatura),
# nunca a página do app que o Cloudflare devolve para qualquer caminho desconhecido.
CAMINHOS_EXPOSTOS = [
    ('/.git/config', 'repositório git exposto', 'critico', re.compile(r'\[core\]|repositoryformatversion', re.I)),
    ('/.git/HEAD', 'repositório git exposto', 'critico', re.compile(r'ref:\s*refs/')),
    ('/.env', 'arquivo de ambiente com segredos', 'critico', re.compile(r'(?m)^[A-Z0-9_]{2,}=')),
    ('/.env.local', 'arquivo de ambiente com segredos', 'critico', re.compile(r'(?m)^[A-Z0-9_]{2,}=')),
    ('/.env.production', 'arquivo de ambiente com segredos', 'critico', re.compile(r'(?m)^[A-Z0-9_]{2,}=')),
    ('/.dev.vars', 'variáveis de desenvolvimento com segredos', 'critico', re.compile(r'(?m)^[A-Z0-9_]{2,}=')),
    ('/wrangler.toml', 'configuração do Worker exposta', 'alto', re.compile(r'compatibility_date|^name\s*=', re.I | re.M)),
    ('/wrangler.jsonc', 'configuração do Worker exposta', 'alto', re.compile(r'"compatibility_date"|"main"')),
    ('/.htpasswd', 'credenciais expostas', 'critico', re.compile(r':\$(apr1|2[aby]|1)\$|:\{SHA\}')),
    ('/backup.sql', 'dump de banco acessível', 'critico', re.compile(r'INSERT INTO|CREATE TABLE|-- .*dump', re.I)),
    ('/dump.sql', 'dump de banco acessível', 'critico', re.compile(r'INSERT INTO|CREATE TABLE|-- .*dump', re.I)),
    ('/backup.zip', 'backup acessível', 'alto', None),          # verificado pelos bytes mágicos PK
    ('/docker-compose.yml', 'infraestrutura exposta', 'medio', re.compile(r'(?m)^services:|image:\s')),
    ('/phpinfo.php', 'phpinfo exposto', 'alto', re.compile(r'phpinfo\(\)|PHP Version')),
    ('/server-status', 'status do servidor exposto', 'medio', re.compile(r'Apache Server Status|Scoreboard')),
    ('/package.json', 'dependências expostas', 'baixo', re.compile(r'"dependencies"|"devDependencies"')),
]

# rotas de depuração/semeadura que, se respondem com DADO (não a página do app), são achado
CAMINHOS_ADMIN = [
    ('/api/debug', 'alto'), ('/api/semear', 'alto'), ('/api/seed', 'alto'), ('/api/admin', 'alto'),
    ('/debug', 'medio'), ('/graphql', 'medio'), ('/graphiql', 'medio'), ('/server-status', 'medio'),
]
RE_SHELL = re.compile(r'<!doctype html|<html', re.I)
RE_ERRO_GENERICO = re.compile(r'error code: \d|cloudflare|not found|nao encontrad', re.I)

# assinaturas de erro de banco de dados numa resposta
ERROS_SQL = [
    'sql syntax', 'sqlite_error', 'sqlite3.', 'd1_error', 'unrecognized token', 'near "', 'syntax error at or near',
    'ora-0', 'mysql_fetch', 'you have an error in your sql', 'pg::', 'psycopg', 'sqlstate', 'unterminated quoted string',
]
# assinaturas de leitura de arquivo do sistema (traversal)
ERROS_ARQUIVO = ['root:x:0:0:', 'root:.:0:0:', '[extensions]', '[fonts]', 'daemon:x:']


def _sem_rede(sonda: str, resp) -> list[Achado]:
    return [Achado(sonda, 'OPS-01', 'Alvo não respondeu', 'info', resp.url,
                   f'a requisição não completou: {resp.erro}',
                   'confirme que a URL está certa e o site está no ar antes de concluir qualquer coisa.',
                   'o alvo pode estar fora do ar, bloqueando o IP do teste, ou a URL está errada.')]


# =====================================================================================================================
# 1. TLS e HTTPS
# =====================================================================================================================
def tls(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    if urlparse(alvo.base_url).scheme != 'https':
        achados.append(Achado('tls', 'DAD-09', 'Site servido sem HTTPS', 'critico', alvo.base_url,
                              'a URL base não é https.', 'tudo trafega em texto puro: senha, sessão, dado pessoal.',
                              'sirva por HTTPS e redirecione o HTTP; ative HSTS.'))
        return achados

    info = alvo.info_tls()
    if info and info.get('erro'):
        achados.append(Achado('tls', 'DAD-09', 'Falha no handshake TLS', 'alto', alvo.base_url,
                              info['erro'], 'não foi possível validar o certificado ou negociar a conexão.',
                              'confira o certificado e a cadeia no painel do provedor.'))
    elif info:
        proto = info.get('protocolo') or ''
        if proto and proto < 'TLSv1.2':
            achados.append(Achado('tls', 'DAD-09', f'Conexão negociou {proto}', 'alto', alvo.base_url,
                                  f'protocolo negociado: {proto}', 'TLS abaixo de 1.2 tem ataques conhecidos.',
                                  'exija TLS 1.2 ou superior no servidor/CDN.'))

    aceitos = alvo.protocolos_aceitos()
    for versao, estado in aceitos.items():
        if estado.startswith('ACEITO'):
            achados.append(Achado('tls', 'DAD-09', f'Servidor aceita {versao} (obsoleto)', 'alto', alvo.base_url,
                                  f'{versao}: {estado}', f'{versao} é obsoleto e vulnerável.',
                                  'desative TLS 1.0 e 1.1 no provedor; deixe só 1.2 e 1.3.'))

    # HSTS: checa a home E uma rota de API, porque às vezes só vem em algumas respostas
    r = alvo.get('/')
    if not r.ok:
        return achados + _sem_rede('tls', r)
    saude = (alvo.config.candidatos_saude() if alvo.config else __import__('configuracao').ROTAS_SAUDE)[0]
    outra = alvo.get(saude, seguir=False)
    pega = lambda resp: next((v for k, v in resp.cabecalhos.items() if k.lower() == 'strict-transport-security'), None)  # noqa: E731
    hsts = pega(r)
    hsts_outra = pega(outra) if outra.ok else None
    if not hsts and not hsts_outra:
        achados.append(Achado('tls', 'WEB-01', 'Sem Strict-Transport-Security (HSTS)', 'medio', alvo.base_url,
                              'cabeçalho Strict-Transport-Security ausente nas respostas testadas.',
                              'sem HSTS, o primeiro acesso pode ser rebaixado para HTTP.',
                              "adicione 'Strict-Transport-Security: max-age=31536000; includeSubDomains' em todas as respostas.",
                              curl('HEAD', alvo.base_url)))
    elif not hsts:
        achados.append(Achado('tls', 'WEB-01', 'HSTS não está em todas as respostas (falta na home)', 'baixo',
                              alvo.base_url, f'HSTS presente em {saude} mas ausente em /.',
                              'o navegador só grava o HSTS quando o vê; faltando na home, o primeiro acesso não é protegido.',
                              'aplique o HSTS no middleware que cobre todas as respostas, não só em algumas rotas.'))
    elif 'max-age=0' in hsts.replace(' ', ''):
        achados.append(Achado('tls', 'WEB-01', 'HSTS com max-age=0', 'medio', alvo.base_url,
                              f'Strict-Transport-Security: {hsts}', 'max-age=0 desliga o HSTS.',
                              'use um max-age longo (por exemplo 31536000).'))
    return achados


# =====================================================================================================================
# 2. Cabeçalhos de segurança e cookies
# =====================================================================================================================
def _rotas_para_cabecalhos(alvo: Alvo) -> list[str]:
    # uma página, uma rota de API comum e uma 404, para pegar cabeçalho que só aparece em algumas respostas
    return ['/', '/api/saude', '/' + secrets.token_hex(6)]


def cabecalhos(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    exigidos = {
        'content-security-policy': ('WEB-02', 'alto', 'Content-Security-Policy ausente',
                                    'sem CSP, um XSS executa sem barreira.',
                                    'defina a CSP no middleware que cobre todas as respostas; script-src com nonce.'),
        'x-content-type-options': ('WEB-01', 'medio', 'X-Content-Type-Options ausente',
                                   'o navegador pode adivinhar o tipo e executar conteúdo como script.',
                                   "adicione 'X-Content-Type-Options: nosniff'."),
        'referrer-policy': ('WEB-01', 'baixo', 'Referrer-Policy ausente',
                            'a URL atual pode vazar para terceiros no cabeçalho Referer.',
                            "use 'Referrer-Policy: strict-origin-when-cross-origin'."),
    }
    enquadramento = False
    visto_em: dict[str, list[str]] = {}
    for caminho in _rotas_para_cabecalhos(alvo):
        r = alvo.get(caminho, seguir=True)
        if not r.ok:
            continue
        baixos = {k.lower(): v for k, v in r.cabecalhos.items()}
        for nome in exigidos:
            if nome in baixos:
                visto_em.setdefault(nome, []).append(caminho)
        if 'x-frame-options' in baixos or ('content-security-policy' in baixos
                                           and 'frame-ancestors' in baixos['content-security-policy'].lower()):
            enquadramento = True
        # servidor/versão vazando
        for k in ('server', 'x-powered-by'):
            if k in baixos and any(c.isdigit() for c in baixos[k]):
                achados.append(Achado('cabecalhos', 'WEB-08', f'Cabeçalho {k} revela versão', 'baixo',
                                      alvo.url_de(caminho), f'{k}: {baixos[k]}',
                                      'a versão facilita achar exploit pronto.',
                                      f'remova ou neutralize o cabeçalho {k}.'))
        # CSP com unsafe-inline em script-src
        csp = baixos.get('content-security-policy', '')
        if csp:
            script = re.search(r'script-src[^;]*', csp, re.I)
            if script and 'unsafe-inline' in script.group(0).lower() and 'nonce-' not in script.group(0).lower():
                achados.append(Achado('cabecalhos', 'WEB-02', "CSP com 'unsafe-inline' em script-src", 'alto',
                                      alvo.url_de(caminho), script.group(0),
                                      "com unsafe-inline a CSP não barra XSS, que é o motivo dela existir.",
                                      'troque por nonce por requisição ou hash; remova o unsafe-inline.'))
        # cookies
        for valor in r.cabecalhos.items():
            if valor[0].lower() == 'set-cookie':
                _confere_cookie(achados, alvo, caminho, valor[1])

    for nome, (item, grav, titulo, porque, corrige) in exigidos.items():
        if nome not in visto_em:
            achados.append(Achado('cabecalhos', item, titulo, grav, alvo.base_url,
                                  f'{nome} não apareceu em nenhuma das rotas testadas.', porque, corrige,
                                  curl('HEAD', alvo.base_url)))
    if not enquadramento:
        achados.append(Achado('cabecalhos', 'WEB-01', 'Sem proteção contra enquadramento (clickjacking)', 'medio',
                              alvo.base_url, 'nem X-Frame-Options nem frame-ancestors na CSP.',
                              'a página pode ser embutida num iframe de outro site para clickjacking.',
                              "adicione frame-ancestors 'none' na CSP ou X-Frame-Options: DENY."))
    return achados


def _confere_cookie(achados, alvo, caminho, set_cookie: str):
    nome = set_cookie.split('=', 1)[0].strip()
    baixo = set_cookie.lower()
    faltando = [attr for attr, chave in (('Secure', 'secure'), ('HttpOnly', 'httponly')) if chave not in baixo]
    if 'samesite' not in baixo:
        faltando.append('SameSite')
    if faltando:
        achados.append(Achado('cabecalhos', 'WEB-13', f'Cookie "{nome}" sem {", ".join(faltando)}',
                              'alto' if 'HttpOnly' in faltando else 'medio', alvo.url_de(caminho),
                              f'Set-Cookie: {set_cookie[:120]}',
                              'cookie sem HttpOnly é lido por XSS; sem Secure vai em texto puro; sem SameSite entra em CSRF.',
                              'defina Secure, HttpOnly e SameSite=Lax na biblioteca de sessão.'))


# =====================================================================================================================
# 3. Arquivos e rotas que não deviam estar expostos
# =====================================================================================================================
def _e_pagina_ou_erro(r) -> bool:
    """True quando a resposta é a página do app (SPA) ou um erro genérico — ou seja, NÃO é o arquivo procurado."""
    cabeca = (r.texto or '')[:600]
    return bool(RE_SHELL.search(cabeca) or RE_ERRO_GENERICO.search(cabeca)) or not (r.texto or '').strip()


def exposicao(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    for caminho, descricao, grav, assinatura in CAMINHOS_EXPOSTOS:
        r = alvo.get(caminho, seguir=False)
        if not r.ok or r.status != 200 or _e_pagina_ou_erro(r):
            continue                               # 404, redirecionamento ou a página do app: não é exposição
        bate = False
        if caminho.endswith('.zip'):
            bate = r.texto[:2].encode('utf-8', 'ignore')[:2] == b'PK'
        elif assinatura is not None:
            bate = bool(assinatura.search(r.texto[:5000]))
        if bate:
            achados.append(Achado('exposicao', 'API-12', f'{descricao} ({caminho})', grav, alvo.url_de(caminho),
                                  f'GET {caminho} devolveu 200 com o conteúdo do arquivo (assinatura confere).',
                                  'arquivo que não devia ser servido está público, com segredo ou código interno.',
                                  'bloqueie o caminho no servidor/CDN; tire o arquivo da raiz pública; troque o que vazou.',
                                  curl('GET', alvo.url_de(caminho))))

    for caminho, grav in CAMINHOS_ADMIN:
        r = alvo.get(caminho, seguir=False)
        if not r.ok or r.status != 200 or _e_pagina_ou_erro(r):
            continue                               # só é achado se responder com DADO (não a página, não 404)
        tipo = r.cabecalhos.get('Content-Type', r.cabecalhos.get('content-type', '')).lower()
        if 'json' in tipo or r.texto.strip()[:1] in ('{', '['):
            achados.append(Achado('exposicao', 'API-12', f'Rota sensível responde com dado sem autenticação ({caminho})',
                                  grav, alvo.url_de(caminho), f'GET {caminho} devolveu {r.status} com corpo de dados.',
                                  'rota de depuração, semeadura ou admin acessível sem login.',
                                  'remova rotas de depuração e semeadura de produção; proteja /api/admin com sessão.',
                                  curl('GET', alvo.url_de(caminho))))

    # listagem de diretório

    # listagem de diretório
    for pasta in ('/assets/', '/img/', '/uploads/', '/public/'):
        r = alvo.get(pasta, seguir=False)
        if r.ok and r.status == 200 and re.search(r'index of|<title>Directory listing', r.texto, re.I):
            achados.append(Achado('exposicao', 'WEB-07', f'Listagem de diretório em {pasta}', 'medio',
                                  alvo.url_de(pasta), 'a pasta lista os arquivos.',
                                  'listar a pasta entrega nomes de arquivos que não deviam ser descobertos.',
                                  'desative a listagem de diretório no servidor/CDN.'))
    return achados


# =====================================================================================================================
# 4. Injeção (reflexão de XSS, erro de SQL, traversal) — só detecção, cargas benignas
# =====================================================================================================================
def _parametros_descobertos(alvo: Alvo) -> list[tuple[str, str]]:
    """(caminho, parâmetro) para injetar: o que o crawler achou, mais a home e parâmetros comuns."""
    achados = set(alvo.descobertas.get('parametros') or set())
    r = alvo.get('/')
    if r.ok:
        for href in re.findall(r'href=["\']([^"\']+\?[^"\']+)["\']', r.texto):
            parsed = urlparse(href)
            for par in parsed.query.split('&'):
                nome = par.split('=')[0]
                if nome:
                    achados.add((parsed.path or '/', nome))
        for nome in re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', r.texto):
            achados.add(('/', nome))
    for comum in ('q', 'busca', 'search', 'categoria', 'pagina', 'page', 'id', 'slug', 'next', 'redirect', 'url'):
        achados.add(('/', comum))
        achados.add(('/api/produtos', comum))
    # rotas de API que o crawler achou também ganham os parâmetros comuns
    for rota in sorted(alvo.descobertas.get('rotas') or set()):
        if rota.startswith(('/api', '/admin', '/auth')):
            for comum in ('id', 'q', 'busca', 'pagina'):
                achados.add((rota, comum))
    return sorted(achados)[:200]          # teto para não estourar em site grande


def _redireciona(alvo: Alvo, caminho: str) -> bool:
    """Rota que só redireciona (ex.: página de admin que manda para o login) não vale a pena injetar: a injeção
    seguiria para outra página e geraria alarme falso."""
    base = alvo.get(caminho, seguir=False)
    return base.ok and base.status in (301, 302, 303, 307, 308)


def injecao(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    marca = 'qg' + secrets.token_hex(4)
    redirecionam: dict[str, bool] = {}
    quedas_500: list[str] = []          # entrada longa que gera 500; quedas_503 separa a sobrecarga de plataforma
    quedas_503: list[str] = []
    for caminho, par in _parametros_descobertos(alvo):
        if redirecionam.setdefault(caminho, _redireciona(alvo, caminho)):
            continue                               # rota que redireciona: não injeta (evita falso positivo do SPA)
        # XSS refletido: marcador com < > " ' que deve voltar escapado — sem seguir redirecionamento
        carga_xss = f'{marca}"\'><svg/onload=x>'
        r = alvo.get(caminho, params={par: carga_xss}, seguir=False)
        tipo = r.cabecalhos.get('Content-Type', r.cabecalhos.get('content-type', '')).lower()
        if r.ok and r.status == 200 and f'{marca}"\'><svg/onload=x>' in r.texto and 'text/html' in tipo:
            achados.append(Achado('injecao', 'WEB-05', f'Possível XSS refletido em {caminho}?{par}', 'critico',
                                  alvo.url_de(caminho), f'o parâmetro {par} voltou sem escape no HTML.',
                                  'entrada do usuário virou HTML sem escape: a base de XSS.',
                                  'escape a saída (interpolação normal do framework); nunca v-html/innerHTML com dado externo.',
                                  curl('GET', alvo.url_de(caminho) + f'?{par}=' + quote(carga_xss))))
        # erro de SQL: aspa simples
        r = alvo.get(caminho, params={par: marca + "'"}, seguir=False)
        if r.ok and r.status < 300 and any(sig in r.texto.lower() for sig in ERROS_SQL):
            achados.append(Achado('injecao', 'WEB-06', f'Possível injeção de SQL em {caminho}?{par}', 'critico',
                                  alvo.url_de(caminho), f'o parâmetro {par} provocou mensagem de erro de SQL.',
                                  'a consulta monta SQL com a entrada; pode permitir ler ou alterar o banco.',
                                  'use consulta parametrizada do ORM/driver; nunca concatene valor em SQL.',
                                  curl('GET', alvo.url_de(caminho) + f'?{par}=' + quote(marca + "'"))))
        # traversal
        r = alvo.get(caminho, params={par: '../../../../etc/passwd'}, seguir=False)
        if r.ok and r.status < 300 and any(sig in r.texto for sig in ERROS_ARQUIVO):
            achados.append(Achado('injecao', 'WEB-07', f'Possível leitura de arquivo (traversal) em {caminho}?{par}',
                                  'critico', alvo.url_de(caminho), f'o parâmetro {par} devolveu conteúdo de arquivo do sistema.',
                                  'o parâmetro vira caminho de arquivo sem validação.',
                                  'nunca use entrada como caminho; valide contra lista fixa; sirva por id, não por nome.'))
        # injeção de template
        carga_tpl = marca + '{{7*7}}' + marca
        r = alvo.get(caminho, params={par: carga_tpl}, seguir=False)
        if r.ok and r.status < 300 and f'{marca}49{marca}' in r.texto:
            achados.append(Achado('injecao', 'WEB-05', f'Possível injeção de template em {caminho}?{par}', 'alto',
                                  alvo.url_de(caminho), f'{marca}{{{{7*7}}}}{marca} foi avaliado para {marca}49{marca}.',
                                  'a entrada é interpretada como template no servidor; caminho para execução de código.',
                                  'nunca passe entrada do usuário para o motor de template; trate como dado.'))
        # entrada longa provocando 5xx (direto, sem seguir redirecionamento): acumula para um achado só
        r = alvo.get(caminho, params={par: 'A' * 4000}, seguir=False)
        if r.ok and r.status == 503:
            quedas_503.append(f'{caminho}?{par}')
        elif r.ok and 500 <= r.status < 600:
            quedas_500.append(f'{caminho}?{par}')

    # um achado por causa, não um por rota: entrada longa sem limite de tamanho
    if quedas_500:
        achados.append(Achado('injecao', 'WEB-04', 'Entrada longa derruba o servidor (500)', 'medio', alvo.base_url,
                              f'parâmetro de 4000 caracteres gerou 500 em {len(quedas_500)} ponto(s), ex.: {quedas_500[:5]}.',
                              'entrada sem limite de tamanho chega a um ponto que lança exceção não tratada.',
                              'limite o tamanho do parâmetro e valide com esquema; devolva 400, não deixe a exceção subir.',
                              curl('GET', alvo.url_de(quedas_500[0].split("?")[0]) + '?' + quedas_500[0].split("?")[1] + '=' + 'A' * 4000)))
    if quedas_503:
        achados.append(Achado('injecao', 'API-11', 'Entrada longa faz o servidor devolver 503', 'baixo', alvo.base_url,
                              f'parâmetro de 4000 caracteres gerou 503 em {len(quedas_503)} ponto(s), ex.: {quedas_503[:5]}.',
                              'parâmetro sem limite de tamanho estoura o recurso da plataforma (SSR/CPU) e vira 503; '
                              'baixo impacto, mas é entrada não validada.',
                              'limite o tamanho do parâmetro na entrada e devolva 400 para o que passar do razoável.',
                              curl('GET', alvo.url_de(quedas_503[0].split("?")[0]) + '?' + quedas_503[0].split("?")[1] + '=' + 'A' * 4000)))
    return achados


# =====================================================================================================================
# 5. Autenticação, autorização e origem
# =====================================================================================================================
def _parece_barreira_de_login(texto: str) -> bool:
    baixo = texto.lower()
    return ('entrar' in baixo and ('senha' in baixo or 'password' in baixo or 'login' in baixo)) \
        or 'http-equiv="refresh"' in baixo and ('entrar' in baixo or 'login' in baixo)


def _rotas_admin_para_testar(alvo: Alvo) -> list[str]:
    """Candidatos genéricos (PT e EN) do config, mais o que o crawler achou com 'admin'/'interno'/'private' no nome."""
    candidatos = list(alvo.config.candidatos_admin_api()) if alvo.config else list(
        __import__('configuracao').ROTAS_ADMIN_API)
    for rota in sorted(alvo.descobertas.get('rotas') or set()):
        if rota.startswith('/api') and any(p in rota for p in ('admin', 'interno', 'internal', 'private', 'usuario', 'user')):
            candidatos.append(rota)
    return list(dict.fromkeys(candidatos))


def autenticacao(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    # ROTAS DE API de admin: se devolvem 200 com DADO sem sessão, é exposição de verdade (crítico). Genérico.
    for caminho in _rotas_admin_para_testar(alvo):
        r = alvo.get(caminho, seguir=False)
        if r.ok and r.status == 200 and r.texto.strip()[:1] in ('{', '['):
            achados.append(Achado('autenticacao', 'AUT-09', f'API de admin aberta: {caminho} responde 200 sem sessão',
                                  'critico', alvo.url_de(caminho), f'GET {caminho} sem sessão devolveu 200 com dados.',
                                  'rota de API protegida entregando dado sem login.',
                                  'exija sessão no servidor para toda rota de admin; teste com usuário comum.',
                                  curl('GET', alvo.url_de(caminho))))
    # PÁGINA de admin (HTML): num SPA, 200 costuma ser só o shell que redireciona no cliente. Só é achado se vier
    # 200 sem nenhuma barreira de login à vista — e aí como MÉDIO "confirme", não crítico.
    r = alvo.get('/admin', seguir=False)
    if r.ok and r.status == 200 and not _parece_barreira_de_login(r.texto):
        achados.append(Achado('autenticacao', 'WEB-12', 'Página /admin carrega sem barreira visível (confirme)', 'medio',
                              alvo.url_de('/admin'), 'GET /admin devolveu 200 e o HTML não mostra tela de login.',
                              'pode ser só o shell do SPA (protegido pela API) ou pode estar exposto; confirme. '
                              'O ideal é /admin atrás de uma camada do provedor (Cloudflare Access), não só do login.',
                              'ponha /admin atrás do Access/VPN; confira que a API de admin recusa sem sessão.',
                              curl('GET', alvo.url_de('/admin'))))

    # rota de saúde/status não deve vazar detalhe sem sessão (testa os nomes comuns, PT e EN)
    candidatos_saude = alvo.config.candidatos_saude() if alvo.config else __import__('configuracao').ROTAS_SAUDE
    for caminho in candidatos_saude:
        r = alvo.get(caminho, seguir=False)
        if not (r.ok and r.status == 200 and r.texto.strip()[:1] in ('{', '[')):
            continue
        baixo = r.texto.lower()
        for termo, o_que in (('migr', 'estado de migração'), ('tabela', 'nomes de tabela'), ('table', 'nomes de tabela'),
                             ('version', 'versão'), ('select ', 'consulta'), ('senha', 'senha'), ('password', 'senha'),
                             ('token', 'token'), ('secret', 'segredo'), ('database', 'banco'), ('hostname', 'host interno')):
            if termo in baixo:
                achados.append(Achado('autenticacao', 'API-10', f'{caminho} vaza {o_que} sem sessão', 'medio',
                                      alvo.url_de(caminho), f'a resposta pública contém "{termo.strip()}".',
                                      'rota de saúde/status entrega detalhe interno a quem não está autenticado.',
                                      'devolva só ok e próximo passo para quem não é admin.'))
                break
        break                                   # achou uma rota de saúde que responde; não precisa testar as outras

    # escrita com Origin de outro site deve ser recusada (OPTIONS, não grava)
    escrita = (alvo.config.candidatos_escrita() if alvo.config else __import__('configuracao').ROTAS_ESCRITA)
    testadas = 0
    for caminho in escrita + candidatos_saude[:1]:
        if testadas >= 6:
            break
        r = alvo.requisitar('OPTIONS', caminho, headers={'Origin': 'https://site-invasor.exemplo',
                                                         'Access-Control-Request-Method': 'POST'}, seguir=False)
        if not r.ok:
            continue
        testadas += 1
        permitido = next((v for k, v in r.cabecalhos.items() if k.lower() == 'access-control-allow-origin'), None)
        credenciais = next((v for k, v in r.cabecalhos.items() if k.lower() == 'access-control-allow-credentials'), '')
        if permitido and ('site-invasor.exemplo' in permitido or
                          (permitido.strip() == '*' and credenciais.lower() == 'true')):
            achados.append(Achado('autenticacao', 'API-08', f'CORS aceita origem de outro site em {caminho}', 'alto',
                                  alvo.url_de(caminho), f'Access-Control-Allow-Origin: {permitido}',
                                  'outro site pode chamar a API com o cookie da pessoa logada.',
                                  'permita só os domínios do seu front; nunca refletir a origem; nunca * com credenciais.'))
    return achados


# =====================================================================================================================
# 6. Limite de tentativas e carga
# =====================================================================================================================
def carga(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    total, simultaneas = alvo.plano_de_carga()
    alvo_caminho = '/'
    tempos: list[float] = []
    status_contagem: dict[int, int] = {}
    erros = 0

    def uma(_):
        r = alvo.get(alvo_caminho)
        return r

    with concurrent.futures.ThreadPoolExecutor(max_workers=simultaneas) as executor:
        for r in executor.map(uma, range(total)):
            if not r.ok:
                erros += 1
                continue
            tempos.append(r.ms)
            status_contagem[r.status] = status_contagem.get(r.status, 0) + 1

    if not tempos:
        return _sem_rede('carga', alvo.get(alvo_caminho))

    tempos.sort()
    p50 = statistics.median(tempos)
    p95 = tempos[min(len(tempos) - 1, int(len(tempos) * 0.95))]
    tem_429 = 429 in status_contagem
    nota = f'{total} requisições, {simultaneas} simultâneas (nível {alvo.intensidade})'
    if alvo.intensidade_limitada:
        nota += f'; pedido nível {alvo.intensidade_pedida}, limitado em produção'

    achados.append(Achado('carga', 'PERF-07', 'Medição de carga', 'info', alvo.base_url,
                          f'{nota}. p50={p50:.0f} ms, p95={p95:.0f} ms, erros={erros}, '
                          f'status={status_contagem}.',
                          'número de referência de como o site responde sob esta carga.',
                          'compare o p95 com o limite aceitável; investigue as rotas acima disso.'))

    # sem nenhum 429 numa carga que já aperta sugere ausência de limite global
    if not tem_429 and total >= 60:
        achados.append(Achado('carga', 'WEB-09', 'Nenhum 429 sob carga: limite de requisições pode não existir', 'medio',
                              alvo.base_url, f'{total} requisições e nenhuma resposta 429.',
                              'sem limite global, um script sobrecarrega o site ou faz força bruta sem freio.',
                              'adicione limite por IP e global; confirme com um nível mais alto em homologação.'))
    if p95 > 3000:
        achados.append(Achado('carga', 'PERF-02', 'Resposta lenta sob carga (p95 acima de 3 s)', 'medio',
                              alvo.base_url, f'p95 de {p95:.0f} ms com {simultaneas} simultâneas.',
                              'sob carga o site fica lento o bastante para o usuário desistir.',
                              'veja cache, consultas sem índice e trabalho pesado na requisição.'))
    return achados


def limite_de_login(alvo: Alvo) -> list[Achado]:
    """Confere o 429 no login por tentativa repetida. Em produção, só se não houver escrita — usa OPTIONS/HEAD para
    não submeter credencial; a verificação real de bloqueio fica para homologação."""
    achados: list[Achado] = []
    if alvo.ambiente == 'producao' or not alvo.permitir_escrita:
        achados.append(Achado('login', 'WEB-09', 'Limite de login não exercitado (precisa de homologação)', 'info',
                              alvo.url_de('/api/admin/sessao'),
                              'tentar logins de verdade exige ambiente de homologação com --escrever.',
                              'força bruta de login só se testa submetendo tentativas, o que não se faz em produção.',
                              'rode o scanner contra homologação com --escrever para medir o bloqueio.'))
        return achados
    # homologação: submete tentativas erradas no caminho de login do config e espera 429
    caminho = alvo.config.login_caminho if (alvo.config and alvo.config.login_caminho) else alvo.config.candidatos_login()[0]
    campo_u = alvo.config.login_campo_usuario if alvo.config else 'email'
    campo_s = alvo.config.login_campo_senha if alvo.config else 'senha'
    visto_429 = False
    for i in range(15):
        r = alvo.requisitar('POST', caminho, json={campo_u: f'nao-existe-{i}@teste.exemplo',
                                                   campo_s: 'errada-de-proposito'}, seguir=False)
        if not r.ok:
            break
        if r.status == 429:
            visto_429 = True
            break
    if not visto_429:
        achados.append(Achado('login', 'AUT-02', 'Login sem limite de tentativas', 'alto',
                              alvo.url_de(caminho), '15 tentativas erradas sem receber 429.',
                              'sem limite, força bruta de senha é só questão de tempo.',
                              'conte tentativas por IP e por e-mail; reserve antes de verificar; devolva 429 com Retry-After.'))
    return achados


from rastreio import rastrear, segredos_no_cliente       # noqa: E402
from autenticado import varredura_autenticada            # noqa: E402
from logica import testes_de_logica                      # noqa: E402
from nuclei_ponte import rodar_nuclei                    # noqa: E402
from sondas_rede import (cliente_web, dominio_email, graphql, metodos_http,  # noqa: E402
                         requisicoes_servidor)
from sondas_app import dom_xss, oauth_sso, websocket     # noqa: E402

# a ordem define a execução e o relatório. O crawler (rastreio) vem antes da injeção porque a alimenta.
SONDAS = [
    ('rastreio', rastrear),
    ('tls', tls),
    ('cabecalhos', cabecalhos),
    ('segredos', segredos_no_cliente),
    ('exposicao', exposicao),
    ('metodos', metodos_http),
    ('injecao', injecao),
    ('redirecionamento', requisicoes_servidor),
    ('cliente', cliente_web),
    ('dom', dom_xss),
    ('graphql', graphql),
    ('oauth', oauth_sso),
    ('websocket', websocket),
    ('autenticacao', autenticacao),
    ('autenticado', varredura_autenticada),
    ('logica', testes_de_logica),
    ('dominio', dominio_email),
    ('carga', carga),
    ('login', limite_de_login),
    ('nuclei', rodar_nuclei),
]


def rodar_tudo(alvo: Alvo, apenas: list[str] | None = None, callback=None) -> list[Achado]:
    """Roda as sondas na ordem. `callback(nome, indice, total, achados_da_sonda)` é chamado ao fim de cada uma,
    para a interface mostrar o andamento ao vivo."""
    todos: list[Achado] = []
    lista = [(n, f) for n, f in SONDAS if not apenas or n in apenas]
    for i, (nome, func) in enumerate(lista, 1):
        try:
            novos = func(alvo)
        except Bloqueado as e:
            novos = [Achado(nome, 'OPS-09', f'Sonda {nome} bloqueada pela trava', 'info', alvo.base_url,
                            str(e), 'a trava de ambiente impediu esta sonda (esperado em produção).',
                            'rode contra homologação ou local para esta parte.')]
        except Exception as e:  # noqa: BLE001 — uma sonda não pode derrubar o scanner
            novos = [Achado(nome, 'OPS-06', f'Sonda {nome} falhou', 'info', alvo.base_url,
                            f'{type(e).__name__}: {e}', 'erro inesperado na sonda.',
                            'veja o traceback; a sonda precisa de ajuste.')]
        todos += novos
        if callback:
            with contextlib.suppress(Exception):
                callback(nome, i, len(lista), novos)
    return todos
