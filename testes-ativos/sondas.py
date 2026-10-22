# -*- coding: utf-8 -*-
"""As sondas: cada uma recebe o Alvo e devolve uma lista de Achado. Todas são não destrutivas.

Em produção só saem requisições de leitura e as cargas de nível vêm limitadas pelo núcleo. As cargas de injeção
usam marcadores que DETECTAM a falha (reflexão, erro de SQL, assinatura de arquivo do sistema), nunca cargas que
alteram ou apagam dado. O que uma sonda não consegue testar no ambiente atual vira um achado 'info' dizendo o que
falta, em vez de silêncio.
"""
from __future__ import annotations

import concurrent.futures
import re
import secrets
import statistics
from urllib.parse import urlparse, quote

from nucleo import Achado, Alvo, Bloqueado, curl

# caminhos que não deviam existir ou não deviam responder num site de produção
CAMINHOS_EXPOSTOS = [
    ('/.git/config', 'repositório git exposto', 'critico'),
    ('/.git/HEAD', 'repositório git exposto', 'critico'),
    ('/.env', 'arquivo de ambiente com segredos', 'critico'),
    ('/.env.local', 'arquivo de ambiente com segredos', 'critico'),
    ('/wrangler.toml', 'configuração do Worker exposta', 'alto'),
    ('/wrangler.jsonc', 'configuração do Worker exposta', 'alto'),
    ('/.dev.vars', 'variáveis de desenvolvimento com segredos', 'critico'),
    ('/config.json', 'configuração exposta', 'medio'),
    ('/docker-compose.yml', 'infraestrutura exposta', 'medio'),
    ('/.htpasswd', 'credenciais expostas', 'critico'),
    ('/backup.zip', 'backup acessível', 'alto'),
    ('/backup.sql', 'dump de banco acessível', 'critico'),
    ('/dump.sql', 'dump de banco acessível', 'critico'),
    ('/phpinfo.php', 'phpinfo exposto', 'alto'),
    ('/server-status', 'status do servidor exposto', 'medio'),
    ('/.vscode/settings.json', 'arquivos do editor expostos', 'baixo'),
    ('/package.json', 'dependências expostas', 'baixo'),
]

# rotas de depuração ou administração que, se respondem sem autenticação, são achado
CAMINHOS_ADMIN = ['/admin', '/admin/', '/api/admin', '/debug', '/api/debug', '/api/semear', '/api/seed',
                  '/graphql', '/graphiql', '/.well-known/security.txt']

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

    # HSTS e redirecionamento de http -> https
    r = alvo.get('/')
    if not r.ok:
        return achados + _sem_rede('tls', r)
    hsts = next((v for k, v in r.cabecalhos.items() if k.lower() == 'strict-transport-security'), None)
    if not hsts:
        achados.append(Achado('tls', 'WEB-01', 'Sem Strict-Transport-Security (HSTS)', 'medio', alvo.base_url,
                              'cabeçalho Strict-Transport-Security ausente.',
                              'sem HSTS, o primeiro acesso pode ser rebaixado para HTTP.',
                              "adicione 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                              curl('HEAD', alvo.base_url)))
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
def exposicao(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    base_404 = alvo.get('/' + secrets.token_hex(8))
    corpo_404 = base_404.texto[:2000] if base_404.ok else ''

    for caminho, descricao, grav in CAMINHOS_EXPOSTOS:
        r = alvo.get(caminho, seguir=False)
        if not r.ok:
            continue
        if r.status == 200 and r.texto and r.texto[:2000] != corpo_404:
            achados.append(Achado('exposicao', 'API-12', f'{descricao} ({caminho})', grav, alvo.url_de(caminho),
                                  f'GET {caminho} devolveu 200 com conteúdo.',
                                  'arquivo ou pasta que não devia ser servido está público.',
                                  'bloqueie o caminho no servidor/CDN; tire o arquivo da raiz pública.',
                                  curl('GET', alvo.url_de(caminho))))

    for caminho in CAMINHOS_ADMIN:
        r = alvo.get(caminho, seguir=False)
        if not r.ok:
            continue
        if r.status in (200, 500):
            grav = 'alto' if ('admin' in caminho or 'debug' in caminho or 'semear' in caminho or 'seed' in caminho) else 'medio'
            achados.append(Achado('exposicao', 'API-12', f'Rota sensível responde sem autenticação ({caminho})', grav,
                                  alvo.url_de(caminho), f'GET {caminho} devolveu {r.status}.',
                                  'rota administrativa, de depuração ou de semeadura acessível sem login.',
                                  'exija autenticação forte e uma camada do provedor (Access/VPN) em /admin; '
                                  'remova rotas de depuração e semeadura de produção.',
                                  curl('GET', alvo.url_de(caminho))))

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
    """Acha (caminho, parâmetro) em links e formulários da página inicial, para saber onde injetar."""
    r = alvo.get('/')
    achados = set()
    if r.ok:
        for href in re.findall(r'href=["\']([^"\']+\?[^"\']+)["\']', r.texto):
            parsed = urlparse(href)
            for par in parsed.query.split('&'):
                nome = par.split('=')[0]
                if nome:
                    achados.add((parsed.path or '/', nome))
        for nome in re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', r.texto):
            achados.add(('/', nome))
    # parâmetros comuns de busca e paginação, sempre testados
    for comum in ('q', 'busca', 'search', 'categoria', 'pagina', 'page', 'id', 'slug', 'next', 'redirect', 'url'):
        achados.add(('/', comum))
        achados.add(('/api/produtos', comum))
    return sorted(achados)


def injecao(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    marca = 'qg' + secrets.token_hex(4)
    for caminho, par in _parametros_descobertos(alvo):
        # XSS refletido: marcador com < > " ' que deve voltar escapado
        carga_xss = f'{marca}"\'><svg/onload=x>'
        r = alvo.get(caminho, params={par: carga_xss})
        if r.ok and r.status == 200 and f'{marca}"\'><svg/onload=x>' in r.texto and 'text/html' in \
                r.cabecalhos.get('Content-Type', r.cabecalhos.get('content-type', '')).lower():
            achados.append(Achado('injecao', 'WEB-05', f'Possível XSS refletido em {caminho}?{par}', 'critico',
                                  alvo.url_de(caminho), f'o parâmetro {par} voltou sem escape no HTML.',
                                  'entrada do usuário virou HTML sem escape: a base de XSS.',
                                  'escape a saída (interpolação normal do framework); nunca v-html/innerHTML com dado externo.',
                                  curl('GET', alvo.url_de(caminho) + f'?{par}=' + quote(carga_xss))))
        # erro de SQL: aspa simples
        r = alvo.get(caminho, params={par: marca + "'"})
        if r.ok and any(sig in r.texto.lower() for sig in ERROS_SQL):
            achados.append(Achado('injecao', 'WEB-06', f'Possível injeção de SQL em {caminho}?{par}', 'critico',
                                  alvo.url_de(caminho), f'o parâmetro {par} provocou mensagem de erro de SQL.',
                                  'a consulta monta SQL com a entrada; pode permitir ler ou alterar o banco.',
                                  'use consulta parametrizada do ORM/driver; nunca concatene valor em SQL.',
                                  curl('GET', alvo.url_de(caminho) + f'?{par}=' + quote(marca + "'"))))
        # traversal
        r = alvo.get(caminho, params={par: '../../../../etc/passwd'})
        if r.ok and any(sig in r.texto for sig in ERROS_ARQUIVO):
            achados.append(Achado('injecao', 'WEB-07', f'Possível leitura de arquivo (traversal) em {caminho}?{par}',
                                  'critico', alvo.url_de(caminho), f'o parâmetro {par} devolveu conteúdo de arquivo do sistema.',
                                  'o parâmetro vira caminho de arquivo sem validação.',
                                  'nunca use entrada como caminho; valide contra lista fixa; sirva por id, não por nome.'))
        # injeção de template
        carga_tpl = marca + '{{7*7}}' + marca
        r = alvo.get(caminho, params={par: carga_tpl})
        if r.ok and f'{marca}49{marca}' in r.texto:
            achados.append(Achado('injecao', 'WEB-05', f'Possível injeção de template em {caminho}?{par}', 'alto',
                                  alvo.url_de(caminho), f'{marca}{{{{7*7}}}}{marca} foi avaliado para {marca}49{marca}.',
                                  'a entrada é interpretada como template no servidor; caminho para execução de código.',
                                  'nunca passe entrada do usuário para o motor de template; trate como dado.'))
        # 500 provocado por entrada
        r = alvo.get(caminho, params={par: marca + '%00' + marca})
        if r.ok and r.status >= 500:
            achados.append(Achado('injecao', 'WEB-04', f'Entrada inesperada derruba {caminho}?{par} (500)', 'medio',
                                  alvo.url_de(caminho), f'o parâmetro {par} com byte nulo gerou {r.status}.',
                                  'entrada sem validação chega a um ponto que lança exceção não tratada.',
                                  'valide com esquema e devolva 400; nunca deixe a exceção subir.'))
    return achados


# =====================================================================================================================
# 5. Autenticação, autorização e origem
# =====================================================================================================================
def autenticacao(alvo: Alvo) -> list[Achado]:
    achados: list[Achado] = []
    # rotas de admin sem sessão devem recusar (401/403/redirecionar ao login), não entregar 200
    for caminho in ('/admin', '/api/admin/pedidos', '/api/admin/produtos'):
        r = alvo.get(caminho, seguir=False)
        if r.ok and r.status == 200:
            achados.append(Achado('autenticacao', 'AUT-09', f'{caminho} responde 200 sem autenticação', 'critico',
                                  alvo.url_de(caminho), f'GET {caminho} sem sessão devolveu 200.',
                                  'rota protegida acessível sem login: dado ou painel exposto.',
                                  'exija sessão no servidor para toda rota administrativa; teste com usuário comum.',
                                  curl('GET', alvo.url_de(caminho))))

    # /api/saude não deve vazar detalhe sem sessão
    r = alvo.get('/api/saude')
    if r.ok and r.status == 200:
        baixo = r.texto.lower()
        for termo, o_que in (('migr', 'estado de migração'), ('tabela', 'nomes de tabela'),
                             ('version', 'versão'), ('select', 'consulta'), ('senha', 'senha'),
                             ('token', 'token'), ('secret', 'segredo')):
            if termo in baixo:
                achados.append(Achado('autenticacao', 'API-10', f'/api/saude vaza {o_que} sem sessão', 'medio',
                                      alvo.url_de('/api/saude'), f'a resposta pública contém "{termo}".',
                                      'rota de saúde entrega detalhe interno a quem não está autenticado.',
                                      'devolva só ok e próximo passo para quem não é admin.'))
                break

    # escrita com Origin de outro site deve ser recusada (checa, não grava — HEAD/OPTIONS)
    for caminho in ('/api/pedidos', '/api/admin/sessao'):
        r = alvo.requisitar('OPTIONS', caminho, headers={'Origin': 'https://site-invasor.exemplo',
                                                         'Access-Control-Request-Method': 'POST'}, seguir=False)
        if not r.ok:
            continue
        permitido = next((v for k, v in r.cabecalhos.items() if k.lower() == 'access-control-allow-origin'), None)
        if permitido and ('site-invasor.exemplo' in permitido or permitido.strip() == '*'):
            achados.append(Achado('autenticacao', 'API-08', f'CORS aceita origem de outro site em {caminho}', 'alto',
                                  alvo.url_de(caminho), f'Access-Control-Allow-Origin: {permitido}',
                                  'outro site pode chamar a API com o cookie da pessoa logada.',
                                  'permita só os domínios do seu front; nunca * com credenciais.'))
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
    # homologação: submete tentativas erradas e espera 429
    visto_429 = False
    for i in range(15):
        r = alvo.requisitar('POST', '/api/admin/sessao', json={'email': f'nao-existe-{i}@teste.exemplo',
                                                               'senha': 'errada-de-proposito'}, seguir=False)
        if not r.ok:
            break
        if r.status == 429:
            visto_429 = True
            break
    if not visto_429:
        achados.append(Achado('login', 'AUT-02', 'Login sem limite de tentativas', 'alto',
                              alvo.url_de('/api/admin/sessao'), '15 tentativas erradas sem receber 429.',
                              'sem limite, força bruta de senha é só questão de tempo.',
                              'conte tentativas por IP e por e-mail; reserve antes de verificar; devolva 429 com Retry-After.'))
    return achados


# a ordem define a execução e o relatório
SONDAS = [
    ('tls', tls),
    ('cabecalhos', cabecalhos),
    ('exposicao', exposicao),
    ('injecao', injecao),
    ('autenticacao', autenticacao),
    ('carga', carga),
    ('login', limite_de_login),
]


def rodar_tudo(alvo: Alvo, apenas: list[str] | None = None) -> list[Achado]:
    todos: list[Achado] = []
    for nome, func in SONDAS:
        if apenas and nome not in apenas:
            continue
        try:
            todos += func(alvo)
        except Bloqueado as e:
            todos.append(Achado(nome, 'OPS-09', f'Sonda {nome} bloqueada pela trava', 'info', alvo.base_url,
                                str(e), 'a trava de ambiente impediu esta sonda (esperado em produção).',
                                'rode contra homologação ou local para esta parte.'))
        except Exception as e:  # noqa: BLE001 — uma sonda não pode derrubar o scanner
            todos.append(Achado(nome, 'OPS-06', f'Sonda {nome} falhou', 'info', alvo.base_url,
                                f'{type(e).__name__}: {e}', 'erro inesperado na sonda.',
                                'veja o traceback; a sonda precisa de ajuste.'))
    return todos
