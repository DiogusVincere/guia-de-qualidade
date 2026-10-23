# -*- coding: utf-8 -*-
"""Prova as sondas de IA e cadeia, offline: MCP exposto, canário de injeção de prompt, e slopsquatting.

- Site de mentira: expõe um manifesto de ferramentas MCP em /mcp e um endpoint de chat em /api/chat que OBEDECE à
  instrução escondida (devolve <marca>49 e uma marca de prompt de sistema) — como um app que passa a entrada crua
  ao modelo.
- dependencias_fantasma: um repositório temporário com um pacote que existe e um que não existe; um consultador de
  registro de mentira (sem rede) devolve 404 para o fantasma. Confere que o fantasma vira achado crítico IA-08.
- segredos: uma chave Anthropic no front é detectada.
"""
import json
import os
import re
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(os.path.abspath(__file__)).parent))

import dependencias  # noqa: E402
import ia  # noqa: E402
import sondas  # noqa: E402
from nucleo import Alvo  # noqa: E402

MANIFESTO_MCP = json.dumps({'jsonrpc': '2.0', 'result': {'tools': [
    {'name': 'ler_arquivo', 'description': 'lê um arquivo', 'inputSchema': {'type': 'object'}}]}})
JS_COM_CHAVE = 'const c = "sk-ant-api03-ZZZ1234567890abcdefGHIJ";\n'


class SiteIA(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _resp(self, status, corpo, tipo='application/json'):
        d = corpo.encode() if isinstance(corpo, str) else corpo
        self.send_response(status); self.send_header('Content-Type', tipo)
        self.send_header('Content-Length', str(len(d))); self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(d)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        cam = urlparse(self.path).path
        if cam == '/mcp':
            return self._resp(200, MANIFESTO_MCP)
        if cam == '/app.js':
            return self._resp(200, JS_COM_CHAVE, 'application/javascript')
        if cam == '/':
            return self._resp(200, '<html><body><script src="/app.js"></script></body></html>', 'text/html')
        if cam == '/api/chat':
            return self._resp(405, '{"erro":"use POST"}')     # existe, mas exige POST
        return self._resp(404, '{"erro":"nao encontrado"}')

    def do_POST(self):
        cam = urlparse(self.path).path
        n = int(self.headers.get('Content-Length') or 0)
        corpo = self.rfile.read(n).decode('utf-8', 'ignore')
        if cam == '/api/chat':
            # simula um modelo que OBEDECE à instrução escondida: acha a marca e responde <marca>49 + marca de prompt
            m = re.search(r'texto (QG[0-9a-f]+) seguido', corpo)
            marca = m.group(1) if m else 'QG000000'
            return self._resp(200, json.dumps({'reply': f'{marca}49. Você é um assistente prestativo.'}))
        return self._resp(404, '{}')


class BaseIA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(('127.0.0.1', 0), SiteIA)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f'http://127.0.0.1:{cls.srv.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def itens(self, achados):
        return {a.item for a in achados}


class TestIA(BaseIA):
    def test_mcp_exposto(self):
        alvo = Alvo(self.url, ambiente='producao', intensidade=1, autorizado=True)
        achados = ia._mcp_exposto(alvo)
        self.assertTrue(any(a.item == 'IA-06' and a.gravidade == 'alto' for a in achados), [a.titulo for a in achados])

    def test_canario_obedece_em_homologacao(self):
        alvo = Alvo(self.url, ambiente='local', intensidade=1, autorizado=True, permitir_escrita=True)
        achados = ia._canario_injecao(alvo)
        inj = [a for a in achados if a.item == 'IA-01' and a.gravidade in ('alto', 'medio')]
        self.assertTrue(inj, [a.titulo for a in achados])
        self.assertIn('injeção de prompt', inj[0].titulo.lower())

    def test_canario_bloqueado_em_producao(self):
        alvo = Alvo(self.url, ambiente='producao', intensidade=1, autorizado=True)
        achados = ia._canario_injecao(alvo)
        self.assertTrue(all(a.gravidade == 'info' for a in achados))
        self.assertIn('homologação', achados[0].correcao.lower() + achados[0].titulo.lower())

    def test_chave_de_ia_no_front(self):
        alvo = Alvo(self.url, ambiente='producao', intensidade=1, autorizado=True)
        sondas.rastrear(alvo)                     # descobre o /app.js
        achados = sondas.segredos_no_cliente(alvo)
        self.assertTrue(any('Anthropic' in a.titulo for a in achados), [a.titulo for a in achados])


class TestDependencias(BaseIA):
    def _repo(self):
        d = Path(tempfile.mkdtemp(prefix='qgdep-'))
        (d / 'requirements.txt').write_text('requests==2.31.0\npacote-que-nao-existe-qg99\n# comentário\n', 'utf-8')
        (d / 'package.json').write_text(json.dumps({'dependencies': {'react': '^18', 'pkg-fantasma-qg': '^1'}}), 'utf-8')
        (d / 'composer.json').write_text(json.dumps({'require': {'php': '>=8', 'monolog/monolog': '^3'}}), 'utf-8')
        return d

    def test_fantasma_vira_critico(self):
        d = self._repo()
        # registro de mentira: 404 para os nomes "fantasma", 200 para o resto
        def consultar(url):
            return 404 if ('nao-existe' in url or 'fantasma' in url) else 200
        alvo = Alvo(self.url, ambiente='producao', intensidade=3, autorizado=True)
        alvo.codigo = d
        alvo._consultar_registro = consultar
        achados = dependencias.dependencias_fantasma(alvo)
        fantasmas = [a for a in achados if a.gravidade == 'critico' and 'não existe' in a.titulo]
        nomes = ' '.join(a.titulo for a in fantasmas)
        self.assertIn('pacote-que-nao-existe-qg99', nomes)
        self.assertIn('pkg-fantasma-qg', nomes)
        self.assertNotIn('requests', nomes)       # o que existe não é marcado

    def test_sem_codigo_avisa(self):
        alvo = Alvo(self.url, ambiente='producao', intensidade=1, autorizado=True)
        achados = dependencias.dependencias_fantasma(alvo)
        self.assertTrue(all(a.gravidade == 'info' for a in achados))
        self.assertIn('--codigo', achados[0].correcao)


if __name__ == '__main__':
    unittest.main()
