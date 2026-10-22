# -*- coding: utf-8 -*-
"""Interface local do scanner: página no navegador + API JSON, tudo em 127.0.0.1, servido por este processo.

A pessoa digita a URL do site dela, declara a autorização, escolhe o ambiente e o nível, e clica em Testar. O
servidor roda as sondas numa thread, mostra o andamento ao vivo e devolve o relatório por gravidade, com os
cenários de ataque e o download do .md.

As travas são as mesmas do scanner (núcleo): sem autorização não roda; escrita e estresse só fora de produção.
Só escuta em 127.0.0.1 e a API exige um token aleatório por execução, embutido na página.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import functools
import json
import logging
import os
import secrets
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

RAIZ = Path(os.path.abspath(__file__)).parent.parent
TA = RAIZ / 'testes-ativos'
for p in (str(TA), str(RAIZ)):
    if p not in sys.path:
        sys.path.insert(0, p)

import relatorio as rel          # noqa: E402
import sondas                    # noqa: E402
from cenarios import montar_cenarios  # noqa: E402
from configuracao import Config  # noqa: E402
from nucleo import GRAVIDADES, Alvo, Bloqueado  # noqa: E402

log = logging.getLogger('scanner.interface')

VERSAO = '1.1.0'
PORTA_PADRAO = 8771
PASTA_WEB = Path(os.path.abspath(__file__)).parent / 'web'
TIPOS = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
         '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8'}
LIMITE_CORPO = 2 * 1024 * 1024
OCIOSO_SEGUNDOS = 15 * 60


class Trabalho:
    def __init__(self):
        self.id = secrets.token_hex(4)
        self.inicio = time.time()
        self.fim: Optional[float] = None
        self.fase = 'preparando'
        self.mensagens: list[dict] = []
        self.erro: Optional[str] = None
        self.concluido = False
        self.resultado: Optional[dict] = None
        self.markdown = ''
        self._lock = threading.Lock()

    def anotar(self, texto: str, nivel: str = 'info'):
        with self._lock:
            self.mensagens.append({'hora': dt.datetime.now().strftime('%H:%M:%S'), 'texto': str(texto), 'nivel': nivel})

    def estado(self, desde: int = 0) -> dict:
        with self._lock:
            msgs = self.mensagens[desde:]
            total = len(self.mensagens)
        return {'id': self.id, 'fase': self.fase, 'concluido': self.concluido, 'erro': self.erro,
                'segundos': round((self.fim or time.time()) - self.inicio),
                'mensagens': msgs, 'total_mensagens': total,
                'resultado': self.resultado if self.concluido else None, 'tem_md': bool(self.markdown)}

    def terminar(self, erro: Optional[str] = None):
        self.erro = erro
        self.fase = 'erro' if erro else 'concluido'
        self.concluido = True
        self.fim = time.time()


@functools.lru_cache(maxsize=1)
def capacidades() -> dict:
    """Quais ferramentas opcionais estão instaladas nesta máquina, para a página mostrar o que está ligado.

    Em cache: o /api/estado é consultado a cada segundo durante um teste, e a página só lê isto no
    carregamento; sem o cache cada poll refazia 6 varreduras de PATH e um find_spec à toa."""
    import importlib.util
    import shutil
    bin_ok = lambda *nomes: any(shutil.which(n) for n in nomes)  # noqa: E731
    return {
        'nuclei': bin_ok('nuclei'),
        'semgrep': bin_ok('semgrep'),
        'gitleaks': bin_ok('gitleaks'),
        'osv-scanner': bin_ok('osv-scanner'),
        'trivy': bin_ok('trivy'),
        'testssl.sh': bin_ok('testssl.sh', 'testssl'),
        'playwright (DOM)': importlib.util.find_spec('playwright') is not None,
    }


def _achado_json(a) -> dict:
    return {'sonda': a.sonda, 'item': a.item, 'titulo': a.titulo, 'gravidade': a.gravidade, 'url': a.url,
            'evidencia': a.evidencia, 'explicacao': a.explicacao, 'correcao': a.correcao, 'reproduzir': a.reproduzir}


def _resultado(alvo, achados, declaracao) -> dict:
    contagem = {g: sum(1 for a in achados if a.gravidade == g) for g in GRAVIDADES}
    cenarios = [{'titulo': c.titulo, 'gravidade': c.gravidade, 'cvss': c.cvss, 'o_que_entrega': c.o_que_entrega,
                 'passos': c.passos, 'base': c.base} for c in montar_cenarios(achados)]
    return {'host': alvo.host, 'ambiente': alvo.ambiente, 'declaracao': declaracao,
            'intensidade': alvo.intensidade, 'intensidade_limitada': alvo.intensidade_limitada,
            'escrita': alvo.permitir_escrita, 'contagem': contagem, 'cenarios': cenarios,
            'achados': [_achado_json(a) for a in achados], 'ordem': list(GRAVIDADES)}


def rodar(trabalho: Trabalho, dados: dict):
    try:
        autorizo = (dados.get('autorizo') or '').strip()
        if not autorizo:
            raise ValueError('declare que o alvo é seu ou que você tem autorização para testá-lo')
        ambiente = dados.get('ambiente') or 'producao'
        escrever = bool(dados.get('escrever'))
        intensidade = int(dados.get('intensidade') or 2)
        config = Config(**{}) if not dados.get('config') else Config(**{
            k: v for k, v in (json.loads(dados['config']) if isinstance(dados['config'], str) else dados['config']).items()
            if k in {f for f in Config.__dataclass_fields__}})
        config.usuario = dados.get('usuario') or os.environ.get('SCANNER_USUARIO', '')
        config.senha = dados.get('senha') or os.environ.get('SCANNER_SENHA', '')
        trabalho.fase = 'preparando'
        alvo = Alvo(dados.get('alvo') or '', ambiente, intensidade, autorizado=True,
                    permitir_escrita=escrever, pausa=float(dados.get('pausa') or 0.02), config=config)
        if dados.get('codigo'):
            caminho = Path(dados['codigo'])
            if not caminho.is_dir():
                raise ValueError(f'código-fonte: a pasta "{dados["codigo"]}" não existe ou não é um diretório')
            alvo.codigo = caminho
        trabalho.anotar(f'Testando {alvo.base_url} ({ambiente}). Autorização: "{autorizo}".')
        if ambiente == 'producao':
            trabalho.anotar('Produção: só leitura; escrita e estresse alto ficam para homologação.', 'aviso')
        if alvo.intensidade_limitada:
            trabalho.anotar(f'Nível {intensidade} limitado a {alvo.intensidade} em produção.', 'aviso')
        trabalho.fase = 'testando'

        def ao_terminar(nome, i, total, novos):
            graves = sum(1 for a in novos if a.gravidade in ('critico', 'alto'))
            nivel = 'erro' if graves else 'info'
            trabalho.anotar(f'[{i}/{total}] {nome}: {len(novos)} achado(s)'
                            + (f', {graves} grave(s)' if graves else ''), nivel)

        apenas = dados.get('sondas') or None
        achados = sondas.rodar_tudo(alvo, apenas=apenas, callback=ao_terminar)
        trabalho.fase = 'montando'
        trabalho.resultado = _resultado(alvo, achados, autorizo)
        trabalho.markdown = rel.montar(alvo, achados, autorizo)
        c = trabalho.resultado['contagem']
        trabalho.anotar(f"Pronto: {c['critico']} crítico, {c['alto']} alto, {c['medio']} médio, "
                        f"{c['baixo']} baixo, {c['info']} info.")
        trabalho.terminar()
    except (ValueError, Bloqueado) as e:
        trabalho.anotar(str(e), 'erro')
        trabalho.terminar(str(e))
    except Exception as e:  # noqa: BLE001
        trabalho.anotar(f'{type(e).__name__}: {e}', 'erro')
        trabalho.terminar(str(e) or type(e).__name__)


class Servidor(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = os.name != 'nt'

    def __init__(self, endereco, encerrar_ocioso=False):
        super().__init__(endereco, Tratador)
        self.token = secrets.token_urlsafe(24)
        self.trabalho: Optional[Trabalho] = None
        self.encerrar_ocioso = encerrar_ocioso
        self.ultimo_contato = time.time()
        self._lock = threading.Lock()

    @property
    def url(self):
        return f'http://127.0.0.1:{self.server_address[1]}/'

    def ocupado(self):
        return bool(self.trabalho and not self.trabalho.concluido)

    def iniciar(self, dados) -> Trabalho:
        with self._lock:
            if self.ocupado():
                raise RuntimeError('já existe um teste em andamento')
            self.trabalho = Trabalho()
            threading.Thread(target=rodar, args=(self.trabalho, dados), daemon=True, name='scan').start()
            return self.trabalho

    def encerrar(self):
        threading.Thread(target=self.shutdown, daemon=True).start()

    def vigiar(self):
        while True:
            time.sleep(30)
            if self.encerrar_ocioso and not self.ocupado() and time.time() - self.ultimo_contato > OCIOSO_SEGUNDOS:
                self.encerrar()
                return


class Tratador(BaseHTTPRequestHandler):
    server_version = f'Scanner/{VERSAO}'
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        log.debug('%s', a)

    def _resp(self, codigo, corpo: bytes, tipo, extra=None):
        self.send_response(codigo)
        self.send_header('Content-Type', tipo)
        self.send_header('Content-Length', str(len(corpo)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(corpo)

    def _json(self, codigo, dados):
        self._resp(codigo, json.dumps(dados, ensure_ascii=False).encode('utf-8'), TIPOS['.json'])

    def _autorizado(self):
        return secrets.compare_digest(self.headers.get('X-Token') or '', self.server.token)

    def _corpo(self):
        tam = int(self.headers.get('Content-Length') or 0)
        if tam > LIMITE_CORPO:
            raise ValueError('corpo grande demais')
        return json.loads((self.rfile.read(tam) if tam else b'{}').decode('utf-8') or '{}')

    def do_GET(self):
        caminho = urlparse(self.path).path
        if caminho == '/':
            html = (PASTA_WEB / 'index.html').read_text('utf-8').replace('__TOKEN__', self.server.token).replace('__VERSAO__', VERSAO)
            return self._resp(200, html.encode('utf-8'), TIPOS['.html'])
        if not caminho.startswith('/api/'):
            nome = caminho.lstrip('/')
            arq = PASTA_WEB / nome
            if not nome or '..' in nome or not arq.is_file() or arq.suffix not in TIPOS:
                return self._json(404, {'erro': 'não encontrado'})
            return self._resp(200, arq.read_bytes(), TIPOS[arq.suffix])
        if not self._autorizado():
            return self._json(403, {'erro': 'token inválido'})
        self.server.ultimo_contato = time.time()
        if caminho == '/api/estado':
            desde = 0
            with contextlib.suppress(Exception):
                desde = int(dict(p.split('=', 1) for p in urlparse(self.path).query.split('&') if '=' in p).get('desde', 0))
            t = self.server.trabalho
            return self._json(200, {'versao': VERSAO, 'ocupado': self.server.ocupado(),
                                    'sondas': [n for n, _ in sondas.SONDAS], 'capacidades': capacidades(),
                                    'trabalho': t.estado(desde) if t else None})
        if caminho == '/api/baixar':
            t = self.server.trabalho
            if not (t and t.markdown):
                return self._json(404, {'erro': 'sem relatório'})
            nome = f'seguranca-{t.resultado["host"] if t.resultado else "scan"}.md'.encode('ascii', 'ignore').decode()
            return self._resp(200, t.markdown.encode('utf-8'), 'text/markdown; charset=utf-8',
                              {'Content-Disposition': f'attachment; filename="{nome or "relatorio.md"}"'})
        return self._json(404, {'erro': 'rota não encontrada'})

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        caminho = urlparse(self.path).path
        if not self._autorizado():
            return self._json(403, {'erro': 'token inválido'})
        self.server.ultimo_contato = time.time()
        try:
            dados = self._corpo()
        except Exception as e:  # noqa: BLE001
            return self._json(400, {'erro': f'pedido inválido: {e}'})
        if caminho == '/api/testar':
            try:
                t = self.server.iniciar(dados)
            except RuntimeError as e:
                return self._json(409, {'erro': str(e)})
            return self._json(202, {'id': t.id})
        if caminho == '/api/encerrar':
            self._json(200, {'ok': True})
            self.server.encerrar()
            return None
        return self._json(404, {'erro': 'rota não encontrada'})


def criar(porta=PORTA_PADRAO, encerrar_ocioso=False) -> Servidor:
    ultimo = None
    for p in ([porta] if porta == 0 else range(porta, porta + 20)):
        try:
            return Servidor(('127.0.0.1', p), encerrar_ocioso=encerrar_ocioso)
        except OSError as e:
            ultimo = e
    raise RuntimeError(f'não consegui abrir uma porta a partir de {porta}: {ultimo}')


def iniciar_em_thread(porta=0, **kw) -> Servidor:
    s = criar(porta, **kw)
    threading.Thread(target=s.serve_forever, daemon=True, name='interface-scanner').start()
    if s.encerrar_ocioso:
        threading.Thread(target=s.vigiar, daemon=True).start()
    return s


def iniciar(porta=PORTA_PADRAO, abrir_navegador=True, encerrar_ocioso=True):
    s = criar(porta, encerrar_ocioso=encerrar_ocioso)
    if encerrar_ocioso:
        threading.Thread(target=s.vigiar, daemon=True).start()
    print(f'\n  Interface do scanner: {s.url}\n  O alvo e a autorização ficam só nesta máquina.\n', flush=True)
    if abrir_navegador:
        threading.Timer(0.6, lambda: webbrowser.open(s.url)).start()
    try:
        s.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        s.server_close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%H:%M:%S')
    iniciar()
