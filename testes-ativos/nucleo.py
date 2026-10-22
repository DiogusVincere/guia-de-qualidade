# -*- coding: utf-8 -*-
"""Núcleo do scanner: o alvo (com as travas de autorização e ambiente), o modelo de achado e utilitários.

Este arquivo não conhece nenhuma sonda. Ele garante três coisas:
- nada roda sem o alvo ter sido declarado como seu ou autorizado (Alvo.autorizado);
- em produção só saem requisições de LEITURA (GET/HEAD/OPTIONS); escrita exige ambiente de homologação ou local;
- o estresse tem teto por ambiente: produção não é inundada, mesmo que o nível peça.
"""
from __future__ import annotations

import dataclasses
import socket
import ssl
import time
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

# Gravidades, da maior para a menor. A ordem define o relatório.
GRAVIDADES = ('critico', 'alto', 'medio', 'baixo', 'info')

LEITURA = ('GET', 'HEAD', 'OPTIONS')

# nível de estresse → (total de requisições, requisições simultâneas). O usuário escolhe o nível; produção é limitada.
NIVEIS_CARGA = {
    1: (20, 2),
    2: (60, 6),
    3: (200, 20),
    4: (600, 50),
    5: (2000, 100),
}
TETO_CARGA_PRODUCAO = 2          # em produção, não passa daqui, por mais alto que o nível peça

AMBIENTES = ('producao', 'homologacao', 'local')


class Bloqueado(Exception):
    """Uma sonda pediu algo que a trava não permite neste alvo (escrita em produção, estresse acima do teto)."""


@dataclasses.dataclass
class Achado:
    sonda: str                  # nome da sonda que achou
    item: str                   # id do item do guia, ex.: 'WEB-01'
    titulo: str
    gravidade: str              # uma de GRAVIDADES
    url: str
    evidencia: str              # a observação ou a requisição que reproduz
    explicacao: str
    correcao: str
    reproduzir: str = ''        # um comando curl que reproduz, quando faz sentido

    def __post_init__(self):
        if self.gravidade not in GRAVIDADES:
            raise ValueError(f'gravidade inválida: {self.gravidade}')


@dataclasses.dataclass
class Resposta:
    """O que uma sonda precisa saber de uma resposta, sem carregar o objeto inteiro do requests para todo lado."""
    status: int
    cabecalhos: dict
    texto: str
    url_final: str
    ms: float                   # tempo até receber, em milissegundos
    erro: Optional[str] = None  # quando a requisição nem completou (rede, timeout)

    @property
    def ok(self) -> bool:
        return self.erro is None


class Alvo:
    """O site sob teste e as regras do que pode ser feito nele."""

    def __init__(self, base_url: str, ambiente: str, intensidade: int, autorizado: bool,
                 permitir_escrita: bool = False, timeout: float = 15.0, pausa: float = 0.0,
                 user_agent: str = 'guia-de-qualidade/scanner (teste autorizado)'):
        if not autorizado:
            raise Bloqueado('o scanner só roda contra um alvo declarado como seu ou autorizado (--autorizo)')
        if ambiente not in AMBIENTES:
            raise ValueError(f'ambiente inválido: {ambiente} (use {", ".join(AMBIENTES)})')
        parsed = urlparse(base_url)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc:
            raise ValueError(f'alvo inválido: {base_url!r} (informe a URL completa, com http:// ou https://)')
        self.base_url = base_url.rstrip('/') + '/'
        self.host = parsed.netloc
        self.ambiente = ambiente
        self.autorizado = autorizado
        self.timeout = timeout
        self.pausa = pausa
        # escrita (POST/PUT/PATCH/DELETE) nunca em produção, mesmo pedida
        self.permitir_escrita = bool(permitir_escrita) and ambiente != 'producao'
        self.escrita_pedida_em_producao = bool(permitir_escrita) and ambiente == 'producao'
        # teto de estresse por ambiente
        teto = TETO_CARGA_PRODUCAO if ambiente == 'producao' else max(NIVEIS_CARGA)
        self.intensidade = max(1, min(int(intensidade), teto))
        self.intensidade_pedida = int(intensidade)
        self.intensidade_limitada = self.intensidade < self.intensidade_pedida
        self.sessao = requests.Session()
        self.sessao.headers['User-Agent'] = user_agent
        self.sessao.max_redirects = 5

    # -- requisições --------------------------------------------------------------------------------------------
    def url_de(self, caminho: str) -> str:
        return urljoin(self.base_url, caminho.lstrip('/'))

    def requisitar(self, metodo: str, caminho: str, seguir: bool = True, **kw) -> Resposta:
        metodo = metodo.upper()
        if metodo not in LEITURA and not self.permitir_escrita:
            motivo = ('escrita não é feita em produção' if self.ambiente == 'producao'
                      else 'escrita desligada; use --escrever em homologação ou local')
            raise Bloqueado(f'{metodo} {caminho}: {motivo}')
        url = self.url_de(caminho)
        kw.setdefault('timeout', self.timeout)
        kw.setdefault('allow_redirects', seguir)
        inicio = time.perf_counter()
        try:
            r = self.sessao.request(metodo, url, **kw)
        except requests.RequestException as e:
            return Resposta(0, {}, '', url, (time.perf_counter() - inicio) * 1000, erro=str(e))
        finally:
            if self.pausa:
                time.sleep(self.pausa)
        corpo = ''
        try:
            corpo = r.text[:200_000]
        except Exception:
            corpo = ''
        return Resposta(r.status_code, {k: v for k, v in r.headers.items()}, corpo,
                        str(r.url), (time.perf_counter() - inicio) * 1000)

    def get(self, caminho: str, **kw) -> Resposta:
        return self.requisitar('GET', caminho, **kw)

    def cabecalhos_de(self, caminho: str = '/') -> Resposta:
        return self.requisitar('HEAD', caminho, seguir=False)

    # -- carga --------------------------------------------------------------------------------------------------
    def plano_de_carga(self) -> tuple[int, int]:
        """(total, simultâneas) para o nível efetivo deste alvo."""
        return NIVEIS_CARGA[self.intensidade]

    # -- TLS (sem HTTP) ---------------------------------------------------------------------------------------
    def info_tls(self) -> Optional[dict]:
        """Conecta na porta 443 e devolve protocolo, cifra e o certificado. None se o alvo não é https."""
        if urlparse(self.base_url).scheme != 'https':
            return None
        host = urlparse(self.base_url).hostname
        porta = urlparse(self.base_url).port or 443
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, porta), timeout=self.timeout) as cru:
                with ctx.wrap_socket(cru, server_hostname=host) as tls:
                    return {
                        'protocolo': tls.version(),
                        'cifra': tls.cipher(),
                        'certificado': tls.getpeercert(),
                    }
        except Exception as e:
            return {'erro': str(e)}

    def protocolos_aceitos(self) -> dict:
        """Tenta forçar TLS 1.0 e 1.1 (obsoletos) e diz se o servidor aceitou cada um."""
        host = urlparse(self.base_url).hostname
        porta = urlparse(self.base_url).port or 443
        resultado = {}
        for nome, maximo in (('TLSv1', ssl.TLSVersion.TLSv1), ('TLSv1.1', ssl.TLSVersion.TLSv1_1)):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = maximo
            except ValueError:
                resultado[nome] = 'indisponível nesta máquina'
                continue
            try:
                with socket.create_connection((host, porta), timeout=self.timeout) as cru:
                    with ctx.wrap_socket(cru, server_hostname=host) as tls:
                        resultado[nome] = f'ACEITO ({tls.version()})'
            except Exception:
                resultado[nome] = 'recusado'
        return resultado


def curl(metodo: str, url: str, cabecalhos: Optional[dict] = None, dados: Optional[str] = None) -> str:
    partes = ['curl', '-s', '-i']
    if metodo != 'GET':
        partes += ['-X', metodo]
    for k, v in (cabecalhos or {}).items():
        partes += ['-H', f"'{k}: {v}'"]
    if dados:
        partes += ['--data', f"'{dados}'"]
    partes.append(f"'{url}'")
    return ' '.join(partes)
