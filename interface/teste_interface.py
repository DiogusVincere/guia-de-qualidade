# -*- coding: utf-8 -*-
"""Interface local (interface/servidor.py): página e token, trava de autorização, teste contra um site de mentira
vulnerável servido em 127.0.0.1, download do relatório e encerramento. Sem rede externa."""
import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

RAIZ = Path(os.path.abspath(__file__)).parent.parent
sys.path.insert(0, str(RAIZ / 'testes-ativos'))
sys.path.insert(0, str(RAIZ))

from interface import servidor as iface  # noqa: E402


class SiteVulneravel(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path).path
        if u == '/.env':
            c = b'SECRET_KEY=abc123\nDATABASE_URL=x'
            self.send_response(200); self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(c))); self.end_headers(); self.wfile.write(c)
            return
        c = b'<html><body>loja</body></html>'
        self.send_response(200); self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(c))); self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(c)

    def do_HEAD(self):
        self.do_GET()


class TestInterface(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln = ThreadingHTTPServer(('127.0.0.1', 0), SiteVulneravel)
        threading.Thread(target=cls.vuln.serve_forever, daemon=True).start()
        cls.alvo = f'http://127.0.0.1:{cls.vuln.server_address[1]}'
        cls.srv = iface.iniciar_em_thread(porta=0)
        cls.url = cls.srv.url.rstrip('/')
        cls.token = cls.srv.token

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close(); cls.vuln.shutdown(); cls.vuln.server_close()

    def pedir(self, metodo, rota, corpo=None, token=True, bruto=False):
        dados = json.dumps(corpo).encode() if corpo is not None else None
        req = urllib.request.Request(self.url + rota, data=dados, method=metodo)
        if token:
            req.add_header('X-Token', self.token)
        if dados is not None:
            req.add_header('Content-Type', 'application/json')
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                b = r.read()
                return r.status, (b if bruto else json.loads(b or b'{}'))
        except urllib.error.HTTPError as e:
            b = e.read()
            return e.code, (b if bruto else json.loads(b or b'{}'))

    def esperar(self, limite=120):
        fim = time.time() + limite
        while time.time() < fim:
            _, est = self.pedir('GET', '/api/estado')
            if est['trabalho'] and est['trabalho']['concluido']:
                return est['trabalho']
            time.sleep(0.3)
        self.fail('não terminou')

    def test_01_pagina_e_token(self):
        s, html = self.pedir('GET', '/', token=False, bruto=True)
        self.assertEqual(s, 200)
        self.assertIn(self.token, html.decode())
        self.assertEqual(self.pedir('GET', '/api/estado', token=False)[0], 403)   # sem token
        self.assertEqual(self.pedir('GET', '/estilo.css', token=False, bruto=True)[0], 200)

    def test_02_sem_autorizacao_falha(self):
        s, resp = self.pedir('POST', '/api/testar', {'alvo': self.alvo, 'autorizo': '', 'ambiente': 'local'})
        self.assertEqual(s, 202)                    # começa, mas o trabalho termina com erro
        t = self.esperar()
        self.assertIsNotNone(t['erro'])
        self.assertIn('autoriz', t['erro'].lower())

    def test_03_teste_completo_e_download(self):
        s, resp = self.pedir('POST', '/api/testar',
                             {'alvo': self.alvo, 'autorizo': 'é meu', 'ambiente': 'producao', 'intensidade': 1})
        self.assertEqual(s, 202, resp)
        t = self.esperar()
        self.assertIsNone(t['erro'], t['mensagens'][-3:])
        res = t['resultado']
        self.assertEqual(res['ambiente'], 'producao')
        self.assertIn('contagem', res)
        self.assertTrue(any(a['item'] == 'API-12' for a in res['achados']))   # /.env exposto
        self.assertTrue(any('[' in m['texto'] and '/' in m['texto'] for m in t['mensagens']))  # andamento por sonda
        # download do markdown
        s, corpo = self.pedir('GET', '/api/baixar', bruto=True)
        self.assertEqual(s, 200)
        self.assertIn('Relatório de teste de segurança', corpo.decode('utf-8'))

    def test_04_encerrar(self):
        outro = iface.iniciar_em_thread(porta=0)
        self.assertEqual(self.pedir_em(outro, 'POST', '/api/encerrar', {})[0], 200)
        time.sleep(0.4)
        with self.assertRaises((urllib.error.URLError, OSError)):
            urllib.request.urlopen(outro.url, timeout=2)

    def pedir_em(self, srv, metodo, rota, corpo):
        req = urllib.request.Request(srv.url.rstrip('/') + rota, data=json.dumps(corpo).encode(), method=metodo)
        req.add_header('X-Token', srv.token); req.add_header('Content-Type', 'application/json')
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read() or b'{}')
        except urllib.error.HTTPError as e:
            return e.code, {}


if __name__ == '__main__':
    unittest.main()
