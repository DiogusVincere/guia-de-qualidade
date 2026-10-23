# -*- coding: utf-8 -*-
"""Envenenamento do assistente de IA: procura instrução escondida nos arquivos de configuração de agente.

Em outubro/2026 a campanha TrapDoor plantou arquivos `.cursorrules` e `CLAUDE.md` com ordens escondidas que as
ferramentas de IA leem e obedecem — baixar segredo, instalar pacote, rodar comando — sem o humano ver. Esta sonda
lê esses arquivos no repositório (`--codigo`) e marca o que um olho humano não pega: caractere invisível (largura
zero, sobrescrita bidirecional, bloco de tag), instrução dentro de comentário HTML, comando de rede que baixa e
executa, exfiltração de segredo, e bloco grande em base64. Tudo local, sem rede. Ver IA-13.
"""
from __future__ import annotations

import re
from pathlib import Path

from nucleo import Achado, Alvo

# arquivos que uma ferramenta de IA lê como instrução (nome exato ou glob), em qualquer pasta do repositório
NOMES = ['CLAUDE.md', 'AGENTS.md', 'GEMINI.md', 'COPILOT.md', '.cursorrules', '.windsurfrules', '.clinerules',
         '.aider.conf.yml', '.roorules', '.github/copilot-instructions.md', '.mcp.json', 'mcp.json']
GLOBS = ['.cursor/rules/*', '.continue/*', '.roo/*', '.claude/**/*.md', '.github/chatmodes/*']
IGNORAR_PASTAS = {'node_modules', '.venv', 'venv', 'vendor', '.git', 'dist', 'build'}

# caracteres invisíveis/perigosos: largura zero, sobrescrita bidirecional, separadores, bloco de tag Unicode
INVISIVEL = re.compile('[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]')
# comentário HTML com ordem escondida
COMENTARIO = re.compile(r'<!--(?:(?!-->).)*?\b(ignore|disregard|exec|execute|curl|wget|secret|token|password|senha|'
                        r'exfil|chave|n[ãa]o (avise|conte|mencione)|do not (tell|inform))\b.*?-->', re.I | re.S)
# comando de rede que baixa e executa, ou exfiltra segredo
EXEC_REDE = re.compile(r'(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)'
                       r'|(iwr|invoke-webrequest)[^\n]*\|\s*iex'
                       r'|(pip|npm|pnpm|yarn|uv)\s+(install|add)\s+https?://'
                       r'|base64\s+-{1,2}d', re.I)
EXFIL = re.compile(r'(process\.env|os\.environ|GITHUB_TOKEN|AWS_SECRET|AWS_ACCESS|~/\.ssh|~/\.aws|\.npmrc|id_rsa)', re.I)
# ordem imperativa de sobrescrever/silenciar, no começo de linha ou item
ORDEM = re.compile(r'(?im)^\s*(?:[-*>]\s*)?(ignore (all )?previous|disregard (the )?(above|previous|prior)|'
                   r'ignore (as |todas as )?instru|desconsidere|forget (your|all) (previous|prior)|'
                   r'do not (tell|inform|mention) (the )?user|n[ãa]o (avise|informe|mencione|conte) (o|ao|para o) usu)')
# bloco grande em base64 (esconde carga); evita hash curto
BASE64 = re.compile(r'[A-Za-z0-9+/]{160,}={0,2}')


def _mascara(trecho: str) -> str:
    t = ' '.join(trecho.split())
    return (t[:80] + '…') if len(t) > 80 else t


def _coletar(raiz: Path) -> list[Path]:
    achados: list[Path] = []
    for nome in NOMES:
        for p in raiz.rglob(nome):
            if not any(parte in IGNORAR_PASTAS for parte in p.parts):
                achados.append(p)
    for glob in GLOBS:
        for p in raiz.glob(glob):
            if p.is_file() and not any(parte in IGNORAR_PASTAS for parte in p.parts):
                achados.append(p)
    # sem duplicar
    vistos, saida = set(), []
    for p in achados:
        if p not in vistos:
            vistos.add(p)
            saida.append(p)
    return saida


def config_de_agente(alvo: Alvo) -> list[Achado]:
    if not alvo.codigo:
        return [Achado('agente', 'IA-13', 'Config de agente não verificada (sem --codigo)', 'info', alvo.base_url,
                       'a checagem de arquivo de instrução de IA (CLAUDE.md, .cursorrules, MCP) lê o repositório.',
                       'a campanha TrapDoor (10/2026) plantou ordens escondidas nesses arquivos para a IA obedecer.',
                       'rode com --codigo <pasta do repositório> para conferir os arquivos de agente.')]
    raiz = Path(alvo.codigo)
    arquivos = _coletar(raiz)
    if not arquivos:
        return [Achado('agente', 'IA-13', 'Nenhum arquivo de config de agente encontrado', 'info', alvo.base_url,
                       'não achei CLAUDE.md, AGENTS.md, .cursorrules, config de MCP etc.',
                       'sem arquivo de instrução de IA, não há o que envenenar por aqui.',
                       'se o projeto usa outra ferramenta de IA, aponte os arquivos dela.')]

    achados: list[Achado] = []
    for p in arquivos:
        try:
            texto = p.read_text('utf-8', 'ignore')
        except Exception:
            continue
        onde = str(p.relative_to(raiz))
        m = INVISIVEL.search(texto)
        if m:
            achados.append(Achado('agente', 'IA-13', f'Caractere invisível em {onde}', 'critico', alvo.base_url,
                                  f'o arquivo tem caractere Unicode invisível (código U+{ord(m.group()):04X}) '
                                  'que esconde texto do humano mas o modelo lê.',
                                  'é a assinatura do envenenamento de assistente (TrapDoor): a ordem escondida '
                                  'entra no contexto da IA sem ninguém ver no editor.',
                                  f'abra {onde} com um visualizador que mostre caracteres de controle; apague o '
                                  'invisível; só aceite esse arquivo de fonte confiável.'))
        mc = COMENTARIO.search(texto)
        if mc:
            achados.append(Achado('agente', 'IA-13', f'Instrução escondida em comentário HTML em {onde}', 'alto',
                                  alvo.base_url, f'comentário oculto: "{_mascara(mc.group())}".',
                                  'o comentário não aparece renderizado, mas a IA lê o arquivo cru e obedece.',
                                  'remova o comentário; trate todo arquivo de instrução de IA como código a revisar.'))
        me = EXEC_REDE.search(texto)
        if me:
            achados.append(Achado('agente', 'IA-13', f'Comando de rede que baixa e executa em {onde}', 'critico',
                                  alvo.base_url,
                                  f'o arquivo manda rodar: "{_mascara(me.group())}".',
                                  'instrução de IA que baixa e executa (curl|sh, install de URL, base64 -d) é '
                                  'execução de código na sua máquina pela mão do agente.',
                                  'nunca deixe o agente baixar e rodar; tire a linha; confira a origem do arquivo.'))
        if EXFIL.search(texto) and re.search(r'https?://', texto):
            achados.append(Achado('agente', 'IA-13', f'Possível exfiltração de segredo em {onde}', 'alto',
                                  alvo.base_url,
                                  'o arquivo cita segredo (variável de ambiente, token, chave SSH, .npmrc) perto de uma URL.',
                                  'a ordem escondida pode mandar o agente ler o segredo e enviar para fora.',
                                  'remova; segredo nunca entra em arquivo de instrução; revise o que o agente pode ler.'))
        mo = ORDEM.search(texto)
        if mo and not mc:
            achados.append(Achado('agente', 'IA-13', f'Ordem de sobrescrever/silenciar em {onde}', 'medio',
                                  alvo.base_url, f'linha imperativa: "{_mascara(mo.group())}".',
                                  'frase que manda ignorar instruções anteriores ou esconder algo do usuário é a '
                                  'marca de prompt plantado; pode ser legítimo, confirme.',
                                  'confira quem escreveu essa linha e por quê; na dúvida, remova.'))
        if BASE64.search(texto):
            achados.append(Achado('agente', 'IA-13', f'Bloco grande em base64 em {onde}', 'medio', alvo.base_url,
                                  'há um bloco longo em base64 que pode esconder carga ou instrução.',
                                  'base64 em arquivo de instrução de IA foge do olho humano e pode virar comando.',
                                  'decodifique e confira o que é; se não precisa estar ali, remova.'))

    achados.append(Achado('agente', 'IA-13', 'Checagem de config de agente concluída',
                          'critico' if any(a.gravidade == 'critico' for a in achados) else 'info', alvo.base_url,
                          f'{len(arquivos)} arquivo(s) de instrução de IA conferido(s): '
                          f'{", ".join(str(p.relative_to(raiz)) for p in arquivos[:8])}.',
                          'é a defesa contra o envenenamento de assistente (TrapDoor): todo arquivo que a IA lê como '
                          'instrução é código, e passa pela mesma revisão.',
                          'trate CLAUDE.md/.cursorrules/MCP como código versionado e revisado; nunca os aceite de '
                          'fonte não confiável.'))
    return achados
