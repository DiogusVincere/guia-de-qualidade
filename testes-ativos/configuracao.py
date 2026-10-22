# -*- coding: utf-8 -*-
"""Configuração do alvo: a ESTRUTURA do site que as sondas autenticadas e de lógica precisam conhecer.

Nenhum segredo entra aqui. Usuário e senha vêm da linha de comando ou do ambiente (SCANNER_USUARIO,
SCANNER_SENHA), nunca do arquivo versionado — é a regra SEG-02/SEG-06 do próprio guia. O arquivo só diz onde é o
login, quais são as rotas de admin, quais endereços servem objeto por id (para IDOR) e como é o corpo de um pedido
(para adulteração e condição de corrida). Ver exemplos/alvo.exemplo.json.
"""
from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
from typing import Optional


@dataclasses.dataclass
class Config:
    login_caminho: str = ''                     # ex.: /api/admin/sessao
    login_campo_usuario: str = 'email'
    login_campo_senha: str = 'senha'
    login_campos_fixos: dict = dataclasses.field(default_factory=dict)
    rotas_admin: list = dataclasses.field(default_factory=list)      # ['/api/admin/pedidos', ...]
    objetos_idor: list = dataclasses.field(default_factory=list)     # [{'caminho': '/api/admin/pedidos/{id}', 'de': 1, 'ate': 20}]
    pedido_caminho: str = ''                    # ex.: /api/pedidos
    pedido_corpo: dict = dataclasses.field(default_factory=dict)     # um corpo válido de pedido, com campos fictícios
    pedido_campo_quantidade: str = ''           # caminho do campo de quantidade dentro do corpo (ex.: 'itens.0.quantidade')
    pedido_campo_preco: str = ''                # idem para preço, se o cliente manda preço (não devia)
    campos_proibidos: list = dataclasses.field(default_factory=lambda: ['role', 'papel', 'admin', 'is_admin', 'perfil'])
    usuario: str = ''                           # preenchido do ambiente/CLI, não do arquivo
    senha: str = ''                             # idem; nunca impresso

    @classmethod
    def de_arquivo(cls, caminho: Optional[Path]) -> 'Config':
        dados = {}
        if caminho:
            dados = json.loads(Path(caminho).read_text('utf-8'))
            if 'usuario' in dados or 'senha' in dados:
                raise ValueError('usuário e senha não ficam no arquivo de configuração; use --usuario/--senha ou '
                                 'as variáveis SCANNER_USUARIO e SCANNER_SENHA')
        campos = {f.name for f in dataclasses.fields(cls)}
        cfg = cls(**{k: v for k, v in dados.items() if k in campos})
        cfg.usuario = os.environ.get('SCANNER_USUARIO', cfg.usuario)
        cfg.senha = os.environ.get('SCANNER_SENHA', cfg.senha)
        return cfg

    def com_credenciais(self, usuario: str, senha: str) -> 'Config':
        if usuario:
            self.usuario = usuario
        if senha:
            self.senha = senha
        return self

    @property
    def tem_login(self) -> bool:
        return bool(self.login_caminho and self.usuario and self.senha)

    def corpo_de_login(self) -> dict:
        return {**self.login_campos_fixos,
                self.login_campo_usuario: self.usuario,
                self.login_campo_senha: self.senha}
