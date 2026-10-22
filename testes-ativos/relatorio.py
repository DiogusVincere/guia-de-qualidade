# -*- coding: utf-8 -*-
"""Monta o relatório em Markdown a partir dos achados, agrupado por gravidade."""
from __future__ import annotations

import datetime as dt

from cenarios import montar_cenarios
from nucleo import GRAVIDADES, Achado, Alvo

TITULO_GRAVIDADE = {
    'critico': 'Crítico — corrija antes de qualquer coisa',
    'alto': 'Alto — corrija antes do próximo deploy',
    'medio': 'Médio',
    'baixo': 'Baixo',
    'info': 'Informação e medições',
}


def resumo_contagem(achados: list[Achado]) -> dict[str, int]:
    contagem = {g: 0 for g in GRAVIDADES}
    for a in achados:
        contagem[a.gravidade] += 1
    return contagem


def montar(alvo: Alvo, achados: list[Achado], declaracao: str) -> str:
    agora = dt.datetime.now().strftime('%d/%m/%Y %H:%M')
    contagem = resumo_contagem(achados)
    linhas = []
    linhas.append(f'# Relatório de teste de segurança — {alvo.host}')
    linhas.append('')
    linhas.append(f'- **Alvo:** {alvo.base_url}')
    linhas.append(f'- **Ambiente:** {alvo.ambiente}')
    linhas.append(f'- **Quando:** {agora}')
    escrita = 'sim' if alvo.permitir_escrita else ('pedida mas bloqueada em produção' if alvo.escrita_pedida_em_producao else 'não')
    linhas.append(f'- **Escrita permitida:** {escrita}')
    nivel = f'{alvo.intensidade}' + (f' (pedido {alvo.intensidade_pedida}, limitado em produção)' if alvo.intensidade_limitada else '')
    linhas.append(f'- **Nível de carga:** {nivel}')
    linhas.append(f'- **Autorização declarada:** {declaracao}')
    linhas.append('')
    linhas.append('| Gravidade | Achados |')
    linhas.append('|---|---|')
    for g in GRAVIDADES:
        linhas.append(f'| {g} | {contagem[g]} |')
    linhas.append('')
    if alvo.ambiente == 'producao':
        linhas.append('> Rodado em produção: só verificações de leitura. Escrita, estresse alto, varredura '
                      'autenticada, teste de lógica e bloqueio de login não foram feitos aqui; rode contra '
                      'homologação com `--escrever`, `--config` e credenciais para cobrir essa parte.')
        linhas.append('')

    cenarios = montar_cenarios(achados)
    if cenarios:
        linhas.append('## Como um atacante usaria isto')
        linhas.append('')
        linhas.append('Encadeamentos possíveis a partir dos achados acima. Cada um é uma hipótese a confirmar, '
                      'não uma invasão feita.')
        linhas.append('')
        for c in cenarios:
            linhas.append(f'### {c.titulo} — {c.gravidade} (CVSS ~{c.cvss})')
            linhas.append(f'- **O que entrega ao atacante:** {c.o_que_entrega}')
            linhas.append('- **Como:**')
            for passo in c.passos:
                linhas.append(f'  1. {passo}')
            linhas.append(f'- **Sustentado pelos achados:** {", ".join(c.base)}')
            linhas.append('')

    for g in GRAVIDADES:
        do_grupo = [a for a in achados if a.gravidade == g]
        if not do_grupo:
            continue
        linhas.append(f'## {TITULO_GRAVIDADE[g]}')
        linhas.append('')
        for a in do_grupo:
            linhas.append(f'### [{a.item}] {a.titulo}')
            linhas.append(f'- **Onde:** {a.url}')
            linhas.append(f'- **Evidência:** {a.evidencia}')
            linhas.append(f'- **Por que importa:** {a.explicacao}')
            linhas.append(f'- **Como corrigir:** {a.correcao}')
            if a.reproduzir:
                linhas.append('- **Reproduzir:**')
                linhas.append('')
                linhas.append('  ```bash')
                linhas.append(f'  {a.reproduzir}')
                linhas.append('  ```')
            linhas.append('')

    linhas.append('---')
    linhas.append('Gerado pelo scanner de `guia-de-qualidade/testes-ativos`. Cada achado é uma suspeita baseada no '
                  'que o site respondeu: confirme no código antes de concluir, e trate falso positivo como achado a '
                  'descartar, não a ignorar. Itens entre colchetes remetem às listas em `checklists/`.')
    return '\n'.join(linhas)


def resumo_terminal(alvo: Alvo, achados: list[Achado]) -> str:
    c = resumo_contagem(achados)
    graves = [a for a in achados if a.gravidade in ('critico', 'alto')]
    linhas = [f'{alvo.host} ({alvo.ambiente}): '
              f'{c["critico"]} crítico, {c["alto"]} alto, {c["medio"]} médio, {c["baixo"]} baixo, {c["info"]} info']
    for a in graves:
        linhas.append(f'  [{a.gravidade}] {a.item} {a.titulo} — {a.url}')
    return '\n'.join(linhas)
