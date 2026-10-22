# -*- coding: utf-8 -*-
"""Cenários de ataque: pega os achados e conta COMO um atacante os encadearia para chegar a um estrago real.

Uma lista de itens não assusta ninguém; "eis como você seria invadido" assusta. Cada regra olha o conjunto de
achados e, quando o encadeamento existe, descreve o passo a passo, a gravidade no estilo CVSS e o que isso entrega
ao atacante. É o que você pediu: o ponto de vista de quem ataca.
"""
from __future__ import annotations

import dataclasses

from nucleo import Achado


@dataclasses.dataclass
class Cenario:
    titulo: str
    gravidade: str          # critico/alto/medio
    cvss: str               # nota aproximada, 0-10
    o_que_entrega: str      # o que o atacante consegue
    passos: list            # o encadeamento, em ordem
    base: list              # ids dos achados que sustentam o cenário


def _tem(achados, *itens) -> bool:
    presentes = {a.item for a in achados}
    return all(i in presentes for i in itens)


def _algum(achados, *itens) -> bool:
    presentes = {a.item for a in achados}
    return any(i in presentes for i in itens)


# cada regra recebe os achados e devolve um Cenario ou None
def _roubo_de_sessao(achados):
    if _tem(achados, 'WEB-05', 'WEB-13'):
        return Cenario(
            'Roubo de sessão por XSS', 'critico', '8.8',
            'entrar no site como a vítima (inclusive admin) e fazer tudo o que ela faz.',
            ['o atacante põe um XSS num campo que volta sem escape (WEB-05);',
             'a vítima logada abre a página; o script roda no navegador dela;',
             'como o cookie de sessão não tem HttpOnly (WEB-13), o script lê o cookie e manda para o atacante;',
             'o atacante cola o cookie e passa a navegar como a vítima.'],
            ['WEB-05', 'WEB-13'])
    return None


def _painel_exposto(achados):
    if _algum(achados, 'AUT-09'):
        extra = ' e, com CORS aberto (API-08), até de outro site' if _tem(achados, 'API-08') else ''
        return Cenario(
            'Painel administrativo acessível sem login', 'critico', '9.1',
            'ler e alterar pedidos, produtos e clientes sem nenhuma credencial.',
            ['uma rota de admin responde 200 sem sessão (AUT-09);',
             f'o atacante acessa direto pela URL{extra};',
             'a partir daí vê dado de cliente e muda o que quiser.'],
            ['AUT-09'] + (['API-08'] if _tem(achados, 'API-08') else []))
    return None


def _vazamento_de_codigo(achados):
    if _algum(achados, 'WEB-08', 'SEG-01'):
        base = [a.item for a in achados if a.item in ('WEB-08', 'SEG-01')]
        entrega = []
        if any(a.item == 'SEG-01' for a in achados):
            entrega.append('usar uma chave ou credencial que estava no front')
        if any(a.item == 'WEB-08' for a in achados):
            entrega.append('ler o código-fonte e descobrir rotas internas e lógica')
        return Cenario(
            'Reconhecimento pelo próprio front', 'alto', '7.5',
            ' e '.join(entrega) + '.',
            ['o atacante baixa o JavaScript do site (é público);',
             'acha segredo embutido (SEG-01) e/ou o source map com o código-fonte (WEB-08);',
             'com isso mapeia as rotas de API e tenta cada uma com o que aprendeu.'],
            base)
    return None


def _banco_exposto(achados):
    if _algum(achados, 'WEB-06'):
        return Cenario(
            'Leitura do banco por injeção de SQL', 'critico', '9.8',
            'ler (e talvez alterar) todo o banco: clientes, pedidos, senhas.',
            ['um parâmetro monta SQL com a entrada (WEB-06);',
             'o atacante injeta uma consulta que devolve outras tabelas;',
             'extrai e-mails, dados de pedido e o que mais houver.'],
            ['WEB-06'])
    return None


def _dado_de_outros(achados):
    if _algum(achados, 'API-01'):
        return Cenario(
            'Acesso a dados de outros usuários (IDOR)', 'alto', '7.7',
            'ler pedidos e dados pessoais de qualquer cliente trocando o número na URL.',
            ['um endereço serve objeto por id sem checar o dono (API-01);',
             'o atacante, autenticado como um usuário qualquer, percorre os ids;',
             'coleta o dado de todos os outros.'],
            ['API-01'])
    return None


def _fraude_de_compra(achados):
    if _algum(achados, 'WEB-14', 'API-05', 'API-11'):
        base = [a.item for a in achados if a.item in ('WEB-14', 'API-05', 'API-11')]
        return Cenario(
            'Fraude no fluxo de compra', 'alto', '7.4',
            'comprar por preço errado, levar mais do que há em estoque ou travar o estoque.',
            ['o servidor aceita preço ou quantidade que não devia, ou baixa o estoque sem ser atômico;',
             'o atacante manda pedidos adulterados ou simultâneos;',
             'leva produto por centavos ou esgota o estoque de propósito.'],
            base)
    return None


def _forca_bruta(achados):
    if _algum(achados, 'AUT-02', 'WEB-09'):
        return Cenario(
            'Força bruta de senha ou sobrecarga', 'medio', '6.5',
            'tentar milhares de senhas no admin, ou sobrecarregar o site, sem freio.',
            ['não há limite de tentativas no login (AUT-02) ou limite global (WEB-09);',
             'o atacante roda um script de senhas ou de carga;',
             'eventualmente acerta a senha ou deixa o site lento para todos.'],
            [a.item for a in achados if a.item in ('AUT-02', 'WEB-09')])
    return None


REGRAS = [_banco_exposto, _painel_exposto, _roubo_de_sessao, _dado_de_outros, _fraude_de_compra,
          _vazamento_de_codigo, _forca_bruta]


def montar_cenarios(achados: list[Achado]) -> list[Cenario]:
    # cenário só se encadeia a partir de achado REAL (crítico/alto/médio), nunca de um aviso informativo
    reais = [a for a in achados if a.gravidade in ('critico', 'alto', 'medio')]
    vistos = set()
    cenarios = []
    for regra in REGRAS:
        c = regra(reais)
        if c and c.titulo not in vistos:
            vistos.add(c.titulo)
            cenarios.append(c)
    ordem = {'critico': 0, 'alto': 1, 'medio': 2}
    cenarios.sort(key=lambda c: ordem.get(c.gravidade, 3))
    return cenarios
