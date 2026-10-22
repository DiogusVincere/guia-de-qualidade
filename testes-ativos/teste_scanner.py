# -*- coding: utf-8 -*-
"""Prova o scanner contra um site DE MENTIRA, propositalmente vulnerável, servido em 127.0.0.1.

Sem rede externa: sobe um servidor local com XSS refletido, erro de SQL, /.env exposto, /admin aberto, sem
cabeçalhos de segurança e sem limite, e confere que cada sonda acha o que tem de achar. Também confere as travas:
escrita e estresse bloqueados em produção.
"""
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(os.path.abspath(__file__)).parent))

import sondas  # noqa: E402
from nucleo import Alvo, Bloqueado  # noqa: E402


class SiteVulneravel(BaseHTTPRequestHandler):
    """Vulnerável de propósito. NÃO é exemplo de como fazer; é alvo de teste do scanner."""

    def log_message(self, *a):
        pass

    def _responder(self, status, corpo, tipo='text/html; charset=utf-8', extra=None):
        dados = corpo.encode('utf-8')
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
        if u.path == '/.env':                              # segredo exposto
            return self._responder(200, 'SECRET_KEY=abc123\nDATABASE_URL=...', 'text/plain')
        if u.path == '/admin':                             # admin aberto
            return self._responder(200, '<h1>Painel</h1>')
        if u.path == '/api/saude':                         # vaza detalhe
            return self._responder(200, '{"ok":true,"migracoes":"aplicadas","tabela":"pedidos"}',
                                   'application/json')
        if u.path in ('/', '/api/produtos'):
            valor = (q.get('q') or q.get('busca') or [''])[0]
            if "'" in valor:                               # "erro de SQL"
                return self._responder(200, f'Error: SQL syntax near "{valor}"')
            # reflexão sem escape (XSS)
            corpo = f'<html><body>Busca: {valor} <a href="/?q=x">link</a></body></html>'
            return self._responder(200, corpo)             # sem nenhum cabeçalho de segurança
        return self._responder(404, 'nao encontrado')

    def do_POST(self):
        self._responder(200, 'ok')                         # login sem limite


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

    def alvo(self, **kw):
        kw.setdefault('ambiente', 'local')
        kw.setdefault('intensidade', 2)
        return Alvo(self.url, autorizado=True, **kw)


class TestSondas(BaseServidor):
    def itens(self, achados):
        return {a.item for a in achados}

    def test_cabecalhos_ausentes(self):
        achados = sondas.cabecalhos(self.alvo())
        self.assertIn('WEB-02', self.itens(achados))       # CSP ausente
        self.assertIn('WEB-01', self.itens(achados))       # nosniff ausente

    def test_exposicao_env_e_admin(self):
        achados = sondas.exposicao(self.alvo())
        textos = ' '.join(a.titulo for a in achados)
        self.assertIn('.env', textos)
        self.assertIn('/admin', textos)

    def test_injecao_xss_e_sql(self):
        achados = sondas.injecao(self.alvo())
        itens = self.itens(achados)
        self.assertIn('WEB-05', itens)                     # XSS refletido
        self.assertIn('WEB-06', itens)                     # erro de SQL

    def test_autenticacao_admin_aberto_e_saude_vaza(self):
        achados = sondas.autenticacao(self.alvo())
        itens = self.itens(achados)
        self.assertIn('AUT-09', itens)                     # /admin 200
        self.assertIn('API-10', itens)                     # /api/saude vaza

    def test_carga_mede_e_aponta_falta_de_limite(self):
        achados = sondas.carga(self.alvo(intensidade=2))
        itens = self.itens(achados)
        self.assertIn('PERF-07', itens)                    # medição sempre
        self.assertIn('WEB-09', itens)                     # sem 429

    def test_rodar_tudo_nao_quebra(self):
        achados = sondas.rodar_tudo(self.alvo())
        self.assertTrue(achados)
        self.assertTrue(all(a.gravidade in ('critico', 'alto', 'medio', 'baixo', 'info') for a in achados))


class TestTravas(BaseServidor):
    def test_sem_autorizacao_nao_cria_alvo(self):
        with self.assertRaises(Bloqueado):
            Alvo(self.url, ambiente='local', intensidade=2, autorizado=False)

    def test_escrita_bloqueada_em_producao(self):
        alvo = Alvo(self.url, ambiente='producao', intensidade=5, autorizado=True, permitir_escrita=True)
        self.assertFalse(alvo.permitir_escrita)            # produção ignora --escrever
        self.assertTrue(alvo.escrita_pedida_em_producao)
        with self.assertRaises(Bloqueado):
            alvo.requisitar('POST', '/api/pedidos', json={})

    def test_estresse_limitado_em_producao(self):
        alvo = Alvo(self.url, ambiente='producao', intensidade=5, autorizado=True)
        self.assertEqual(alvo.intensidade, 2)              # teto de produção
        self.assertTrue(alvo.intensidade_limitada)
        # fora de produção o nível pedido vale
        livre = Alvo(self.url, ambiente='homologacao', intensidade=5, autorizado=True)
        self.assertEqual(livre.intensidade, 5)

    def test_leitura_sempre_permitida(self):
        alvo = Alvo(self.url, ambiente='producao', intensidade=1, autorizado=True)
        r = alvo.get('/')
        self.assertTrue(r.ok)
        self.assertEqual(r.status, 200)

    def test_login_nao_submete_em_producao(self):
        achados = sondas.limite_de_login(Alvo(self.url, ambiente='producao', intensidade=1, autorizado=True))
        self.assertTrue(any(a.gravidade == 'info' for a in achados))   # não testa, só avisa


class TestUrlInvalida(unittest.TestCase):
    def test_url_sem_esquema(self):
        with self.assertRaises(ValueError):
            Alvo('nao-e-url', ambiente='local', intensidade=1, autorizado=True)


if __name__ == '__main__':
    unittest.main()
