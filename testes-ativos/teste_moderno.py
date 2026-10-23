# -*- coding: utf-8 -*-
"""Prova as três camadas novas, offline: fora-de-banda (OAST), descoberta ativa e rastreio por navegador.

- OAST protocolo: sobe um servidor interactsh DE MENTIRA em 127.0.0.1 e confere o ciclo real do cliente
  (registrar a chave pública, injetar endereço, buscar e DECIFRAR a interação com RSA-OAEP + AES-CFB) e o
  mapeamento de volta para o ponto que disparou. Pula se faltar cryptography/requests (como no CI).
- OAST sonda: com um colaborador de mentira (sem rede), confere que a sonda injeta e que uma interação vira
  SSRF cego crítico; e que, sem colaborador, vira só um aviso.
- Descoberta: site que devolve 404 para o que não existe; a sonda acha /api/users e marca /swagger.json.
- Navegador: contra um site simples; pula se o Playwright não estiver instalado (como no CI).
"""
import base64
import json
import os
import secrets
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from pathlib import Path

sys.path.insert(0, str(Path(os.path.abspath(__file__)).parent))

import descoberta  # noqa: E402
import navegador  # noqa: E402
import sondas_oast  # noqa: E402
from nucleo import Alvo  # noqa: E402
from oast import Colaborador, cripto_ok  # noqa: E402

try:
    import requests  # noqa: F401
    REQUESTS = True
except Exception:
    REQUESTS = False


# =====================================================================================================================
# Servidor interactsh de mentira
# =====================================================================================================================
class OastFalso(BaseHTTPRequestHandler):
    chaves: dict = {}          # correlation-id -> PEM da chave pública (bytes)
    fila: dict = {}            # correlation-id -> [json de interação (str)]

    def log_message(self, *a):
        pass

    def _json(self, status, obj):
        corpo = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def do_POST(self):
        if urlparse(self.path).path != '/register':
            return self._json(404, {})
        n = int(self.headers.get('Content-Length') or 0)
        dados = json.loads(self.rfile.read(n) or b'{}')
        OastFalso.chaves[dados['correlation-id']] = base64.b64decode(dados['public-key'])
        self._json(200, {'message': 'registration successful'})

    def do_GET(self):
        u = urlparse(self.path)
        if u.path != '/poll':
            return self._json(404, {})
        q = parse_qs(u.query)
        cid = (q.get('id') or [''])[0]
        pem = OastFalso.chaves.get(cid)
        interacoes = OastFalso.fila.pop(cid, [])
        if not pem or not interacoes:
            return self._json(200, {'data': [], 'aes_key': ''})
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        try:
            from cryptography.hazmat.decrepit.ciphers.modes import CFB
        except Exception:
            CFB = modes.CFB
        pub = serialization.load_pem_public_key(pem)
        aes = secrets.token_bytes(32)
        aes_cifrada = pub.encrypt(aes, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
                                                    label=None))
        itens = []
        for bruto in interacoes:
            iv = secrets.token_bytes(16)
            c = Cipher(algorithms.AES(aes), CFB(iv)).encryptor()
            ct = c.update(bruto.encode()) + c.finalize()
            itens.append(base64.b64encode(iv + ct).decode())
        self._json(200, {'data': itens, 'aes_key': base64.b64encode(aes_cifrada).decode()})


@unittest.skipUnless(cripto_ok() and REQUESTS, 'precisa de cryptography e requests')
class TestOastProtocolo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OastFalso.chaves, OastFalso.fila = {}, {}
        cls.srv = ThreadingHTTPServer(('127.0.0.1', 0), OastFalso)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.host = f'127.0.0.1:{cls.srv.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def test_registra_injeta_e_decifra(self):
        col = Colaborador(servidores=[self.host], esquema='http', timeout=5)
        self.assertTrue(col.registrar())
        host_injetado = col.dominio('ssrf /api/busca?url')      # token embutido no host
        # o servidor do alvo "tocou" nesse host: enfileira a interação correspondente
        OastFalso.fila[col.correlation_id] = [json.dumps({
            'protocol': 'http', 'full-id': host_injetado, 'remote-address': '203.0.113.9',
            'timestamp': '2026-10-22T10:00:00Z'})]
        interacoes = col.coletar()
        self.assertEqual(len(interacoes), 1)
        self.assertEqual(interacoes[0]['protocolo'], 'http')
        self.assertEqual(interacoes[0]['rotulo'], 'ssrf /api/busca?url')   # mapeou de volta pelo token


# =====================================================================================================================
# Sonda fora-de-banda com colaborador de mentira (sem rede)
# =====================================================================================================================
class ColaboradorStub:
    """Imita o Colaborador sem falar com servidor nenhum: guarda os rótulos injetados e devolve uma interação."""
    pronto = True
    erro = None

    def __init__(self):
        self.rotulos = []

    def registrar(self):
        return True

    def dominio(self, rotulo):
        self.rotulos.append(rotulo)
        return f'x{len(self.rotulos)}.exemplo.oast'

    def url(self, rotulo):
        return 'http://' + self.dominio(rotulo)

    def coletar(self, espera=0.0):
        alvo_rotulo = next((r for r in self.rotulos if r.startswith('ssrf')), self.rotulos[0] if self.rotulos else '')
        return [{'protocolo': 'dns', 'remetente': '198.51.100.7', 'quando': '', 'host': 'x.exemplo.oast',
                 'rotulo': alvo_rotulo}]


class SiteSimples(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200); self.send_header('Content-Type', 'text/html')
        corpo = b'<html><body><a href="/sobre">sobre</a></body></html>'
        self.send_header('Content-Length', str(len(corpo))); self.end_headers(); self.wfile.write(corpo)

    do_HEAD = do_GET


class TestOastSonda(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(('127.0.0.1', 0), SiteSimples)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f'http://127.0.0.1:{cls.srv.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def test_desligado_vira_aviso(self):
        alvo = Alvo(self.url, ambiente='producao', intensidade=1, autorizado=True)
        achados = sondas_oast.fora_de_banda(alvo)
        self.assertTrue(all(a.gravidade == 'info' for a in achados))
        self.assertIn('desligado', achados[0].titulo.lower())

    def test_interacao_vira_ssrf_critico(self):
        alvo = Alvo(self.url, ambiente='producao', intensidade=1, autorizado=True)
        alvo.oast = ColaboradorStub()
        achados = sondas_oast.fora_de_banda(alvo)
        criticos = [a for a in achados if a.gravidade == 'critico' and a.item == 'API-07']
        self.assertTrue(criticos, [a.titulo for a in achados])
        self.assertIn('ssrf cego', criticos[0].titulo.lower())


# =====================================================================================================================
# Descoberta ativa
# =====================================================================================================================
class SiteComRotas(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        cam = urlparse(self.path).path
        if cam == '/api/users':
            corpo, tipo, status = b'[{"id":1}]', 'application/json', 200
        elif cam == '/swagger.json':
            corpo, tipo, status = b'{"swagger":"2.0"}', 'application/json', 200
        elif cam == '/admin':
            corpo, tipo, status = b'forbidden', 'text/plain', 403
        else:
            corpo, tipo, status = b'<html>nao encontrado</html>', 'text/html', 404
        self.send_response(status); self.send_header('Content-Type', tipo)
        self.send_header('Content-Length', str(len(corpo))); self.end_headers(); self.wfile.write(corpo)

    do_HEAD = do_GET


class TestDescoberta(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(('127.0.0.1', 0), SiteComRotas)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f'http://127.0.0.1:{cls.srv.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def test_acha_rotas_e_marca_sensivel(self):
        alvo = Alvo(self.url, ambiente='local', intensidade=3, autorizado=True)
        achados = descoberta.descoberta_ativa(alvo)
        urls = ' '.join(a.url + ' ' + a.titulo for a in achados)
        self.assertIn('/api/users', urls)
        swagger = [a for a in achados if a.url.endswith('/swagger.json')]
        self.assertTrue(swagger)
        self.assertEqual(swagger[0].gravidade, 'medio')
        self.assertIn('/api/users', alvo.descobertas['rotas'])    # alimenta as outras sondas

    def test_interessante_ignora_catchall_de_spa(self):
        # baseline 200 html 500 bytes: outro 200 html de tamanho parecido não interessa; json interessa
        self.assertFalse(descoberta._interessante(200, 'text/html', 520, 200, 500, 'text/html'))
        self.assertTrue(descoberta._interessante(200, 'application/json', 520, 200, 500, 'text/html'))
        self.assertTrue(descoberta._interessante(401, 'text/html', 30, 200, 500, 'text/html'))


# =====================================================================================================================
# Rastreio por navegador (pula sem Playwright, como no CI)
# =====================================================================================================================
def _playwright_ok():
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except Exception:
        return False


class TestNavegador(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(('127.0.0.1', 0), SiteSimples)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f'http://127.0.0.1:{cls.srv.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def test_sem_playwright_avisa(self):
        # força o caminho "sem Playwright" (roda em qualquer máquina, com ou sem o navegador instalado)
        orig = navegador._playwright_ok
        navegador._playwright_ok = lambda: False
        try:
            alvo = Alvo(self.url, ambiente='local', intensidade=1, autorizado=True)
            achados = navegador.rastreio_navegador(alvo)
        finally:
            navegador._playwright_ok = orig
        texto = ' '.join(a.titulo + ' ' + a.correcao for a in achados).lower()
        self.assertIn('playwright', texto)

    @unittest.skipUnless(_playwright_ok(), 'precisa do Playwright')
    def test_com_playwright_mapeia(self):
        alvo = Alvo(self.url, ambiente='local', intensidade=1, autorizado=True)
        achados = navegador.rastreio_navegador(alvo)
        self.assertTrue(any(a.item == 'API-06' and 'navegador' in a.titulo.lower() for a in achados))
        self.assertIn('/sobre', alvo.descobertas['rotas'])


if __name__ == '__main__':
    unittest.main()
