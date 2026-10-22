# -*- coding: utf-8 -*-
"""Colaborador fora-de-banda (OAST): um cliente do protocolo interactsh, em Python puro.

Para que serve: achar as falhas CEGAS, que as sondas de texto não enxergam porque a resposta não muda — SSRF cego
(o servidor busca uma URL que eu mando e eu não vejo o corpo), envenenamento por cabeçalho Host, webhook que sai
para onde eu apontar. A ideia é injetar um endereço MEU em cada ponto e esperar o servidor do alvo tocar nesse
endereço (DNS ou HTTP). Se tocou, a falha é real — não é palpite.

Como funciona o interactsh (resumido): registro uma chave pública num servidor colaborador, ele me dá um domínio
único; qualquer consulta a `<qualquer-coisa>.<meu-id>.<servidor>` fica gravada; eu busco as interações e o servidor
me devolve cifrado com a minha chave. Os servidores públicos são da ProjectDiscovery (oast.pro, oast.live, ...).

ATENÇÃO, por isso é OPCIONAL e desligado por padrão: usar um servidor público manda para um TERCEIRO o fato de que
o seu servidor tocou no colaborador (o IP do alvo e o subdomínio sorteado). É prática normal de pentest no seu
próprio site, mas é a sua escolha. Dá para apontar um servidor interactsh próprio com `servidores=[...]`.

Sem a biblioteca `cryptography`, o colaborador se declara indisponível e a sonda vira um aviso dizendo o que falta.
"""
from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Optional

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

# servidores colaboradores públicos da ProjectDiscovery; o primeiro que registrar vence
SERVIDORES_PADRAO = ['oast.pro', 'oast.live', 'oast.site', 'oast.online', 'oast.fun', 'oast.me']

_ALFABETO = 'abcdefghijklmnopqrstuvwxyz0123456789'


def _id(n: int) -> str:
    return ''.join(secrets.choice(_ALFABETO) for _ in range(n))


def cripto_ok() -> bool:
    try:
        import cryptography  # noqa: F401
        return True
    except Exception:
        return False


class Colaborador:
    """Um cliente interactsh. Registra uma vez, dá endereços por sonda e coleta as interações decifradas."""

    def __init__(self, servidores: Optional[list] = None, timeout: float = 10.0, esquema: str = 'https'):
        self.servidores = list(servidores or SERVIDORES_PADRAO)
        self.timeout = timeout
        self.esquema = esquema                     # https nos servidores públicos; http só para um interactsh de teste
        self.servidor: Optional[str] = None
        self.correlation_id = _id(20)
        self.secret = _id(32)
        self.base: Optional[str] = None            # <correlation_id><13 aleatórios>.<servidor>
        self._priv = None
        self._tokens: dict[str, str] = {}          # token da sonda -> rótulo (que ponto gerou)
        self._erro: Optional[str] = None

    # -- registro ----------------------------------------------------------------------------------------------
    def registrar(self) -> bool:
        if requests is None or not cripto_ok():
            self._erro = 'faltam as bibliotecas requests/cryptography'
            return False
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        self._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = self._priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        corpo = {
            'public-key': base64.b64encode(pub_pem).decode(),
            'secret-key': self.secret,
            'correlation-id': self.correlation_id,
        }
        for srv in self.servidores:
            try:
                r = requests.post(f'{self.esquema}://{srv}/register', json=corpo, timeout=self.timeout,
                                  headers={'Content-Type': 'application/json'})
                if r.status_code == 200:
                    self.servidor = srv
                    self.base = f'{self.correlation_id}{_id(13)}.{srv}'
                    return True
            except Exception as e:  # noqa: BLE001
                self._erro = f'{type(e).__name__}: {e}'
                continue
        self._erro = self._erro or 'nenhum servidor OAST respondeu'
        return False

    @property
    def pronto(self) -> bool:
        return self.servidor is not None and self.base is not None

    @property
    def erro(self) -> Optional[str]:
        return self._erro

    # -- endereços por sonda ----------------------------------------------------------------------------------
    def dominio(self, rotulo: str) -> str:
        """Um host único para este ponto de injeção. O rótulo diz qual ponto foi, para a gente mapear de volta."""
        token = _id(10)
        self._tokens[token] = rotulo
        return f'{token}.{self.base}'

    def url(self, rotulo: str) -> str:
        return f'http://{self.dominio(rotulo)}/'

    # -- coleta ------------------------------------------------------------------------------------------------
    def coletar(self, espera: float = 0.0) -> list[dict]:
        """Busca as interações e decifra. Cada item traz protocolo, remetente e o rótulo do ponto que disparou."""
        if not self.pronto:
            return []
        if espera:
            time.sleep(espera)
        try:
            r = requests.get(f'{self.esquema}://{self.servidor}/poll',
                             params={'id': self.correlation_id, 'secret': self.secret}, timeout=self.timeout)
            if r.status_code != 200:
                return []
            dados = r.json()
        except Exception as e:  # noqa: BLE001
            self._erro = f'{type(e).__name__}: {e}'
            return []
        chave_aes = self._decifrar_chave(dados.get('aes_key', ''))
        if not chave_aes:
            return []
        interacoes = []
        for item in dados.get('data', []) or []:
            bruto = self._decifrar_dado(chave_aes, item)
            if not bruto:
                continue
            try:
                registro = json.loads(bruto)
            except Exception:
                continue
            rotulo = self._rotulo_de(bruto)
            interacoes.append({
                'protocolo': registro.get('protocol', '?'),
                'remetente': registro.get('remote-address', '?'),
                'quando': registro.get('timestamp', ''),
                'host': registro.get('full-id', registro.get('unique-id', '')),
                'rotulo': rotulo,
            })
        return interacoes

    def _rotulo_de(self, bruto: str) -> Optional[str]:
        for token, rotulo in self._tokens.items():
            if token in bruto:
                return rotulo
        return None

    # -- cripto ------------------------------------------------------------------------------------------------
    def _decifrar_chave(self, aes_b64: str):
        if not aes_b64:
            return None
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        try:
            return self._priv.decrypt(
                base64.b64decode(aes_b64),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        except Exception:
            return None

    @staticmethod
    def _decifrar_dado(chave_aes: bytes, dado_b64: str) -> Optional[str]:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        try:                                            # CFB mudou de lugar no cryptography novo
            from cryptography.hazmat.decrepit.ciphers.modes import CFB
        except Exception:
            CFB = modes.CFB
        try:
            cru = base64.b64decode(dado_b64)
            iv, cifra = cru[:16], cru[16:]
            c = Cipher(algorithms.AES(chave_aes), CFB(iv))
            d = c.decryptor()
            return (d.update(cifra) + d.finalize()).decode('utf-8', 'ignore')
        except Exception:
            return None
