# -*- coding: utf-8 -*-
"""Prova o scanner contra um site DE MENTIRA, propositalmente vulnerável, servido em 127.0.0.1.

Sem rede externa: sobe um servidor local com XSS refletido, erro de SQL, /.env exposto, /admin aberto, segredo e
rota escondida no JavaScript, source map, IDOR, mass assignment e baixa de estoque não atômica, e confere que cada
sonda acha o que tem de achar. Também confere as travas (escrita e estresse bloqueados em produção) e os cenários
de ataque encadeados.
"""
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(os.path.abspath(__file__)).parent))

import cenarios  # noqa: E402
import sondas  # noqa: E402
from configuracao import Config  # noqa: E402
from nucleo import Achado, Alvo, Bloqueado  # noqa: E402

JS_COM_SEGREDO = (
    'const API_KEY = "AKIAZ3XK7PQ2MNBVCX9Q";\n'                  # cara de chave AWS (sem a palavra "example")
    'fetch("/api/interno/clientes").then(r=>r.json());\n'
    'axios.get("/api/admin/relatorio");\n'
    '//# sourceMappingURL=/app.js.map\n'
)
JS_MAP = json.dumps({'version': 3, 'sources': ['src/app.js'], 'mappings': 'AAAA'})

ESTOQUE = {'n': 1}
TRAVA = threading.Lock()


class SiteVulneravel(BaseHTTPRequestHandler):
    """Vulnerável de propósito. NÃO é exemplo de como fazer; é alvo de teste do scanner."""

    def log_message(self, *a):
        pass

    def _responder(self, status, corpo, tipo='text/html; charset=utf-8', extra=None):
        dados = corpo.encode('utf-8') if isinstance(corpo, str) else corpo
        self.send_response(status)
        self.send_header('Content-Type', tipo)
        self.send_header('Content-Length', str(len(dados)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(dados)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == '/.env':
            return self._responder(200, 'SECRET_KEY=abc123\nDATABASE_URL=postgres://x', 'text/plain')
        if u.path == '/api/debug':                        # rota de debug devolvendo dado (exposta)
            return self._responder(200, '{"env":"prod","tabelas":["pedidos"]}', 'application/json')
        if u.path == '/admin':
            return self._responder(200, '<h1>Painel</h1>')
        if u.path == '/api/admin/pedidos/' or u.path.startswith('/api/admin/pedidos/'):
            return self._responder(200, '{"id":1,"cliente":"Fulano","total":100}', 'application/json')
        if u.path in ('/api/admin/produtos', '/api/admin/pedidos'):   # API de admin ABERTA (crítico)
            return self._responder(200, '[{"id":1,"nome":"Produto"}]', 'application/json')
        if u.path == '/api/saude':
            return self._responder(200, '{"ok":true,"migracoes":"aplicadas","tabela":"pedidos"}', 'application/json')
        if u.path == '/app.js':
            return self._responder(200, JS_COM_SEGREDO, 'application/javascript')
        if u.path == '/app.js.map':
            return self._responder(200, JS_MAP, 'application/json')
        if u.path == '/robots.txt':
            return self._responder(200, 'User-agent: *\nDisallow: /api/interno/', 'text/plain')
        if u.path in ('/', '/api/produtos', '/api/interno/clientes', '/api/admin/relatorio'):
            valor = (q.get('q') or q.get('busca') or q.get('id') or [''])[0]
            if "'" in valor:
                return self._responder(200, f'Error: SQL syntax near "{valor}"')
            corpo = (f'<html><body>Busca: {valor} '
                     f'<a href="/catalogo?categoria=aneis">cat</a><script src="/app.js"></script></body></html>')
            return self._responder(200, corpo)
        if u.path == '/catalogo':
            return self._responder(200, '<html><body>catálogo</body></html>')
        return self._responder(404, 'nao encontrado')

    def do_POST(self):
        u = urlparse(self.path)
        tam = int(self.headers.get('Content-Length') or 0)
        corpo = {}
        if tam:
            try:
                corpo = json.loads(self.rfile.read(tam).decode('utf-8') or '{}')
            except Exception:
                corpo = {}
        if u.path == '/api/admin/sessao':                 # login: devolve cookie
            return self._responder(200, '{"ok":true}', 'application/json',
                                   {'Set-Cookie': 'sessao=abc; Path=/'})
        if u.path == '/api/pedidos':
            # aceita qualquer quantidade (vulnerável) e campo a mais (mass assignment)
            if 'role' in corpo or 'admin' in corpo:
                return self._responder(201, json.dumps({'ok': True, 'role': corpo.get('role', 'admin')}),
                                       'application/json')
            # baixa de estoque NÃO atômica: confere, dorme, baixa
            with TRAVA if False else _nulo():
                pass
            if ESTOQUE['n'] > 0:
                time.sleep(0.02)                          # janela da corrida
                ESTOQUE['n'] -= 1
                return self._responder(201, '{"ok":true}', 'application/json')
            return self._responder(409, '{"erro":"sem estoque"}', 'application/json')
        return self._responder(200, 'ok')


class _nulo:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class BaseServidor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servidor = ThreadingHTTPServer(('127.0.0.1', 0), SiteVulneravel)
        cls.porta = cls.servidor.server_address[1]
        threading.Thread(target=cls.servidor.serve_forever, daemon=True).start()
        cls.url = f'http://127.0.0.1:{cls.porta}'

    @classmethod
    def tearDownClass(cls):
        cls.servidor.shutdown()
        cls.servidor.server_close()

    def setUp(self):
        ESTOQUE['n'] = 1

    def alvo(self, **kw):
        kw.setdefault('ambiente', 'local')
        kw.setdefault('intensidade', 2)
        return Alvo(self.url, autorizado=True, **kw)

    def itens(self, achados):
        return {a.item for a in achados}


class TestSondasBasicas(BaseServidor):
    def test_cabecalhos_ausentes(self):
        itens = self.itens(sondas.cabecalhos(self.alvo()))
        self.assertIn('WEB-02', itens)
        self.assertIn('WEB-01', itens)

    def test_exposicao_por_conteudo(self):
        achados = sondas.exposicao(self.alvo())
        textos = ' '.join(a.titulo for a in achados)
        self.assertIn('.env', textos)                      # corpo com CHAVE=valor, não a página do app
        self.assertIn('/api/debug', textos)                # rota de debug devolvendo JSON

    def test_exposicao_nao_marca_pagina_do_app(self):
        # servidor que devolve a página do app (200 HTML) para qualquer caminho não pode gerar exposição
        class SoApp(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                corpo = '<!DOCTYPE html><html><head><title>Loja</title></head><body>app</body></html>'
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(corpo)))
                self.end_headers()
                self.wfile.write(corpo.encode())
        srv = ThreadingHTTPServer(('127.0.0.1', 0), SoApp)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            alvo = Alvo(f'http://127.0.0.1:{srv.server_address[1]}', ambiente='producao', intensidade=1, autorizado=True)
            self.assertEqual(sondas.exposicao(alvo), [])    # nada, apesar de tudo responder 200
        finally:
            srv.shutdown()
            srv.server_close()

    def test_autenticacao_api_admin_aberta_e_saude_vaza(self):
        itens = self.itens(sondas.autenticacao(self.alvo()))
        self.assertIn('AUT-09', itens)                     # /api/admin/produtos devolve 200 com dados
        self.assertIn('WEB-12', itens)                     # /admin (HTML) carrega sem barreira: confirme
        self.assertIn('API-10', itens)                     # /api/saude vaza

    def test_pagina_admin_que_redireciona_nao_vira_critico(self):
        # servidor que manda /admin para o login não deve gerar WEB-12 nem AUT-09
        class Redireciona(SiteVulneravel):
            def do_GET(self):
                if urlparse(self.path).path == '/admin':
                    return self._responder(302, '', extra={'Location': '/admin/entrar'})
                if urlparse(self.path).path.startswith('/api/admin'):
                    return self._responder(401, '{"erro":"sem sessao"}', 'application/json')
                return super().do_GET()
        srv = ThreadingHTTPServer(('127.0.0.1', 0), Redireciona)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            alvo = Alvo(f'http://127.0.0.1:{srv.server_address[1]}', ambiente='producao', intensidade=1, autorizado=True)
            itens = self.itens(sondas.autenticacao(alvo))
            self.assertNotIn('AUT-09', itens)
            self.assertNotIn('WEB-12', itens)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_carga_mede_e_aponta_falta_de_limite(self):
        itens = self.itens(sondas.carga(self.alvo(intensidade=2)))
        self.assertIn('PERF-07', itens)
        self.assertIn('WEB-09', itens)


class TestRastreioESegredos(BaseServidor):
    def test_crawler_descobre_rota_de_api_no_js(self):
        alvo = self.alvo()
        sondas.rastrear(alvo)
        rotas = alvo.descobertas['rotas']
        self.assertIn('/api/interno/clientes', rotas)      # estava escondida no app.js
        self.assertIn('/api/admin/relatorio', rotas)
        self.assertIn('/catalogo', rotas)                  # seguiu o link

    def test_segredo_e_sourcemap_no_front(self):
        alvo = self.alvo()
        sondas.rastrear(alvo)                               # popula os JS
        itens = self.itens(sondas.segredos_no_cliente(alvo))
        self.assertIn('SEG-01', itens)                     # chave no app.js
        self.assertIn('WEB-08', itens)                     # source map

    def test_injecao_usa_rota_descoberta(self):
        alvo = self.alvo()
        sondas.rastrear(alvo)
        achados = sondas.injecao(alvo)
        # a rota interna descoberta reflete e dá erro de SQL
        urls = ' '.join(a.url for a in achados)
        self.assertTrue(any('WEB-05' == a.item or 'WEB-06' == a.item for a in achados))


class TestAutenticadoELogica(BaseServidor):
    def config(self):
        return Config.de_arquivo(None).__class__(
            login_caminho='/api/admin/sessao', login_campo_usuario='email', login_campo_senha='senha',
            objetos_idor=[{'caminho': '/api/admin/pedidos/{id}', 'de': 1, 'ate': 10}],
            pedido_caminho='/api/pedidos', pedido_corpo={'itens': [{'slug': 'x', 'quantidade': 1}]},
            pedido_campo_quantidade='itens.0.quantidade',
            usuario='admin@teste.exemplo', senha='qualquer')

    def test_idor_e_mass_assignment(self):
        alvo = self.alvo(ambiente='local', permitir_escrita=True, config=self.config())
        itens = self.itens(sondas.varredura_autenticada(alvo))
        self.assertIn('API-01', itens)                     # IDOR: vários ids respondem
        self.assertIn('API-06', itens)                     # mass assignment: role aceito

    def test_logica_aceita_quantidade_ruim(self):
        alvo = self.alvo(ambiente='local', permitir_escrita=True, config=self.config())
        itens = self.itens(sondas.testes_de_logica(alvo))
        self.assertTrue({'WEB-04', 'API-11'} & itens)      # quantidade negativa/gigante aceita

    def test_corrida_vende_alem_do_estoque(self):
        cfg = self.config()
        cfg.corrida = {'corpo': {'itens': [{'slug': 'x', 'quantidade': 1}]}, 'estoque': 1, 'tentativas': 15}
        ESTOQUE['n'] = 5                                    # 5 em estoque, 15 pedidos simultâneos
        alvo = self.alvo(ambiente='local', permitir_escrita=True, config=cfg)
        achados = sondas.testes_de_logica(alvo)
        self.assertIn('API-04', self.itens(achados))       # medição sempre sai

    def test_autenticado_em_producao_so_avisa(self):
        alvo = self.alvo(ambiente='producao', config=self.config())
        achados = sondas.varredura_autenticada(alvo)
        self.assertTrue(all(a.gravidade == 'info' for a in achados))


class TestReconEFerramentas(BaseServidor):
    def test_recon_nao_chama_rede_em_localhost(self):
        import sondas_recon
        achados = sondas_recon.recon_passivo(self.alvo())      # alvo é 127.0.0.1: não toca a internet
        self.assertEqual(len(achados), 1)
        self.assertEqual(achados[0].gravidade, 'info')
        self.assertIn('localhost', achados[0].titulo.lower() + achados[0].evidencia.lower())

    def test_csrf_formulario_sem_token(self):
        import sondas_recon
        alvo = self.alvo()
        alvo.descobertas['formularios'] = [('/entrar', ['email', 'senha'])]   # sem token, servidor sem SameSite
        itens = self.itens(sondas_recon.csrf(alvo))
        self.assertIn('WEB-03', itens)

    def test_ferramentas_externas_avisam_sem_codigo_e_sem_binario(self):
        import ferramentas_externas as fe
        alvo = self.alvo()
        for sonda in (fe.semgrep, fe.gitleaks, fe.osv, fe.trivy):
            a = sonda(alvo)[0]
            self.assertEqual(a.gravidade, 'info')
            self.assertIn('código', a.titulo.lower())        # precisa de --codigo
        import shutil
        alvo.codigo = '.'
        for sonda, binario in ((fe.gitleaks, 'gitleaks'), (fe.osv, 'osv-scanner'), (fe.trivy, 'trivy')):
            if shutil.which(binario):
                continue                                       # instalado nesta máquina: não dá para prever info
            a = sonda(alvo)[0]
            self.assertEqual(a.gravidade, 'info')             # binário ausente: info, nunca derruba


class TestCenarios(BaseServidor):
    def test_cenarios_encadeiam(self):
        achados = [Achado('x', 'WEB-05', 'xss', 'critico', 'u', 'e', 'p', 'c'),
                   Achado('x', 'WEB-13', 'cookie', 'alto', 'u', 'e', 'p', 'c'),
                   Achado('x', 'AUT-09', 'admin', 'critico', 'u', 'e', 'p', 'c'),
                   Achado('x', 'WEB-06', 'sql', 'critico', 'u', 'e', 'p', 'c')]
        cs = cenarios.montar_cenarios(achados)
        titulos = [c.titulo for c in cs]
        self.assertIn('Roubo de sessão por XSS', titulos)
        self.assertIn('Painel administrativo acessível sem login', titulos)
        self.assertIn('Leitura do banco por injeção de SQL', titulos)
        self.assertEqual(cs[0].gravidade, 'critico')       # ordenado por gravidade

    def test_sem_achados_sem_cenario(self):
        self.assertEqual(cenarios.montar_cenarios([]), [])


class TestTravas(BaseServidor):
    def test_sem_autorizacao_nao_cria_alvo(self):
        with self.assertRaises(Bloqueado):
            Alvo(self.url, ambiente='local', intensidade=2, autorizado=False)

    def test_escrita_bloqueada_em_producao(self):
        alvo = Alvo(self.url, ambiente='producao', intensidade=5, autorizado=True, permitir_escrita=True)
        self.assertFalse(alvo.permitir_escrita)
        with self.assertRaises(Bloqueado):
            alvo.requisitar('POST', '/api/pedidos', json={})

    def test_estresse_limitado_em_producao(self):
        self.assertEqual(Alvo(self.url, ambiente='producao', intensidade=5, autorizado=True).intensidade, 2)
        self.assertEqual(Alvo(self.url, ambiente='homologacao', intensidade=5, autorizado=True).intensidade, 5)

    def test_logica_em_producao_so_avisa(self):
        achados = sondas.testes_de_logica(Alvo(self.url, ambiente='producao', intensidade=1, autorizado=True))
        self.assertTrue(all(a.gravidade == 'info' for a in achados))


class TestConfig(unittest.TestCase):
    def test_credencial_no_arquivo_e_recusada(self):
        import tempfile
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as f:
            f.write('{"login_caminho":"/x","senha":"nao-pode"}')
            caminho = f.name
        with self.assertRaises(ValueError):
            Config.de_arquivo(Path(caminho))
        os.unlink(caminho)

    def test_credencial_vem_do_ambiente(self):
        from unittest import mock
        with mock.patch.dict(os.environ, {'SCANNER_USUARIO': 'u@teste.exemplo', 'SCANNER_SENHA': 's'}):
            cfg = Config.de_arquivo(None)
        self.assertEqual(cfg.usuario, 'u@teste.exemplo')
        self.assertEqual(cfg.senha, 's')


class TestUrlInvalida(unittest.TestCase):
    def test_url_sem_esquema(self):
        with self.assertRaises(ValueError):
            Alvo('nao-e-url', ambiente='local', intensidade=1, autorizado=True)


if __name__ == '__main__':
    unittest.main()
