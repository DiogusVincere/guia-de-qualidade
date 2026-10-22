# -*- coding: utf-8 -*-
"""Descoberta ativa de conteúdo: procura rotas e painéis que não aparecem em link nenhum.

É o 'dirbusting' do pentester, mas enxuto e em Python puro (sem ffuf/feroxbuster): testa uma lista curada de
caminhos sensíveis e vê quais existem. O truque para não cair na armadilha do SPA — onde todo caminho responde 200
com a mesma página — é tirar uma LINHA DE BASE de um caminho que com certeza não existe e só marcar o que responde
diferente dela (outro status, outro tipo de conteúdo, ou tamanho bem diferente). O que achar entra em
alvo.descobertas, então a injeção e o fora-de-banda passam a testar essas rotas também. Tudo leitura (GET).
"""
from __future__ import annotations

import concurrent.futures
import secrets

from nucleo import Achado, Alvo

# caminhos que valem procurar. Genéricos, PT e EN. Não repetem os arquivos de assinatura da sonda 'exposicao'
# (.git/.env/backups); aqui são ROTAS e PAINÉIS. Os sensíveis de verdade vêm marcados em SENSIVEIS.
LISTA = [
    '/admin', '/administrador', '/administrator', '/painel', '/dashboard', '/manage', '/gerenciar',
    '/api', '/api/v1', '/api/v2', '/v1', '/v2', '/rest', '/graphql', '/graphiql', '/api/graphql',
    '/swagger', '/swagger-ui', '/swagger-ui.html', '/swagger.json', '/openapi.json', '/api-docs',
    '/api/docs', '/docs', '/redoc', '/api/swagger.json', '/.well-known/security.txt',
    '/actuator', '/actuator/health', '/actuator/env', '/actuator/mappings', '/metrics', '/debug',
    '/server-status', '/status', '/health', '/healthz', '/up', '/version', '/info',
    '/login', '/signin', '/entrar', '/auth', '/logout', '/register', '/cadastro', '/signup',
    '/config', '/configuracao', '/settings', '/setup', '/install', '/phpmyadmin', '/adminer',
    '/backup', '/backups', '/old', '/new', '/test', '/teste', '/dev', '/staging', '/homolog',
    '/uploads', '/files', '/arquivos', '/download', '/tmp', '/temp', '/logs', '/log',
    '/user', '/users', '/usuarios', '/account', '/conta', '/perfil', '/me', '/api/me', '/api/user',
    '/api/users', '/api/usuarios', '/api/admin', '/api/config', '/api/internal', '/api/interno',
    '/api/pedidos', '/api/orders', '/api/produtos', '/api/products', '/api/clientes', '/api/customers',
    '/wp-admin', '/wp-login.php', '/wp-json', '/.git', '/robots.txt', '/sitemap.xml',
    '/console', '/_next/static', '/__debug__', '/telescope', '/horizon', '/rails/info/routes',
]

# o que, se existir, já é um achado por si só (documentação de API aberta, console de métricas, debug)
SENSIVEIS = {
    '/swagger': 'medio', '/swagger-ui': 'medio', '/swagger-ui.html': 'medio', '/swagger.json': 'medio',
    '/openapi.json': 'medio', '/api-docs': 'medio', '/api/docs': 'medio', '/redoc': 'medio',
    '/api/swagger.json': 'medio', '/graphiql': 'medio',
    '/actuator': 'alto', '/actuator/env': 'alto', '/actuator/mappings': 'medio', '/actuator/health': 'baixo',
    '/metrics': 'medio', '/debug': 'medio', '/__debug__': 'alto', '/server-status': 'medio',
    '/telescope': 'alto', '/horizon': 'medio', '/rails/info/routes': 'alto', '/adminer': 'alto',
    '/phpmyadmin': 'alto', '/wp-admin': 'baixo', '/console': 'alto', '/setup': 'medio', '/install': 'medio',
}


def _fatia(intensidade: int) -> list[str]:
    quanto = {1: 34, 2: 64, 3: 110, 4: 170, 5: len(LISTA)}.get(intensidade, 64)
    return LISTA[:quanto]


def _linha_de_base(alvo: Alvo) -> tuple:
    """(status, tamanho, tipo) de um caminho que não existe — a resposta 'de nada encontrado' deste site."""
    r = alvo.get('/qg-nao-existe-' + secrets.token_hex(6), seguir=False)
    tipo = r.cabecalhos.get('Content-Type', r.cabecalhos.get('content-type', '')).split(';')[0].strip().lower()
    return (r.status if r.ok else 0, len(r.texto or ''), tipo)


def _tipo_de(r) -> str:
    return r.cabecalhos.get('Content-Type', r.cabecalhos.get('content-type', '')).split(';')[0].strip().lower()


def descoberta_ativa(alvo: Alvo) -> list[Achado]:
    base_status, base_tam, base_tipo = _linha_de_base(alvo)
    caminhos = _fatia(alvo.intensidade)
    _, simultaneas = alvo.plano_de_carga()
    achados: list[Achado] = []
    encontrados: list[tuple] = []     # (caminho, status, tipo, tamanho)

    def sondar(caminho):
        r = alvo.get(caminho, seguir=False)
        if not r.ok:
            return None
        return (caminho, r.status, _tipo_de(r), len(r.texto or ''))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(2, min(simultaneas, 20))) as ex:
        for res in ex.map(sondar, caminhos):
            if res is None:
                continue
            caminho, status, tipo, tam = res
            if not _interessante(status, tipo, tam, base_status, base_tam, base_tipo):
                continue
            encontrados.append(res)
            alvo.descobertas.setdefault('rotas', set()).add(caminho)

    for caminho, status, tipo, tam in encontrados:
        grav = SENSIVEIS.get(caminho)
        if grav:
            achados.append(Achado('descoberta', 'API-06', f'Rota sensível exposta: {caminho}', grav,
                                  alvo.url_de(caminho),
                                  f'{caminho} respondeu {status} ({tipo or "sem tipo"}, {tam} bytes), '
                                  f'diferente da linha de base ({base_status}/{base_tam}).',
                                  'documentação de API, console de métricas/debug ou painel aberto dá ao atacante o '
                                  'mapa do sistema e, às vezes, dados e ações.',
                                  'tire de produção ou proteja com autenticação/rede interna; '
                                  'confirme no código o que essa rota entrega.'))
        else:
            grav2 = 'baixo' if status in (200, 201, 401, 403) else 'info'
            achados.append(Achado('descoberta', 'API-06', f'Rota encontrada: {caminho} ({status})', grav2,
                                  alvo.url_de(caminho),
                                  f'{caminho} respondeu {status} ({tipo or "sem tipo"}, {tam} bytes), '
                                  f'fora do padrão de "não encontrado" ({base_status}/{base_tam}).',
                                  'rota que não está em link nenhum, mas existe: aumenta a superfície e entra para os '
                                  'outros testes.',
                                  'confirme se devia ser pública; um 401/403 aqui mostra que a rota existe e é protegida.'))

    achados.append(Achado('descoberta', 'API-06', 'Descoberta ativa concluída', 'info', alvo.base_url,
                          f'testei {len(caminhos)} caminho(s); {len(encontrados)} fora do padrão de "não encontrado". '
                          f'Linha de base: status {base_status}, {base_tam} bytes, tipo "{base_tipo or "?"}".',
                          'é a busca por rotas sem link; o que não está na lista não foi procurado.',
                          'para ir além, rode o nuclei ou um ffuf com uma lista maior.'))
    return achados


def _interessante(status, tipo, tam, base_status, base_tam, base_tipo) -> bool:
    if status in (0, 404):
        return False
    if base_status == 200:
        # SPA que devolve 200 para tudo: só interessa status diferente, tipo diferente, ou tamanho bem diferente
        if status != 200:
            return True
        if tipo and base_tipo and tipo != base_tipo:
            return True
        if base_tam and abs(tam - base_tam) > max(400, base_tam * 0.3):
            return True
        return False
    # site que devolve 404 para o que não existe: qualquer 2xx/3xx/401/403/405 é rota que existe
    return status in (200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500)
