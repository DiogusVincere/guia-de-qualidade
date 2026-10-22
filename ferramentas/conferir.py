# -*- coding: utf-8 -*-
"""Confere o próprio guia. Falha (código 1) se:

- algum item de checklist (### ID · Título) não tiver os quatro campos Conferir / Por quê / Como verificar / Como corrigir;
- houver id repetido em qualquer lista;
- um link interno em Markdown apontar para arquivo que não existe;
- um manifesto em .claude-plugin/ não for JSON válido ou apontar para pasta de skills inexistente;
- uma skill não tiver o frontmatter com `name` e `description`, ou citar um arquivo do guia que não existe;
- o AGENTS.md ou o README não listarem todas as checklists.

Uso: python ferramentas/conferir.py   (na raiz do repositório ou de qualquer lugar)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
CAMPOS = ('Conferir', 'Por quê', 'Como verificar', 'Como corrigir')
RE_ITEM = re.compile(r'^### ([A-Z]+-\d{2}) · (.+)$', re.M)
RE_LINK = re.compile(r'\[[^\]]*\]\(([^)#\s]+)(?:#[^)]*)?\)')
RE_CAMINHO_SKILL = re.compile(r'`\$\{CLAUDE_PLUGIN_ROOT\}/([^`]+)`')

erros: list[str] = []
avisos: list[str] = []


def erro(msg: str) -> None:
    erros.append(msg)


def conferir_checklists() -> dict[str, Path]:
    ids: dict[str, Path] = {}
    pasta = RAIZ / 'checklists'
    arquivos = sorted(pasta.glob('*.md'))
    if not arquivos:
        erro('nenhuma checklist em checklists/')
    for arq in arquivos:
        texto = arq.read_text('utf-8')
        itens = list(RE_ITEM.finditer(texto))
        if not itens:
            erro(f'{arq.name}: nenhum item no formato "### ID-00 · Título"')
        for i, m in enumerate(itens):
            ident = m.group(1)
            if ident in ids:
                erro(f'{arq.name}: id {ident} repetido (também em {ids[ident].name})')
            ids[ident] = arq
            fim = itens[i + 1].start() if i + 1 < len(itens) else len(texto)
            corpo = texto[m.end():fim]
            for campo in CAMPOS:
                padrao = rf'^- \*\*{re.escape(campo)}:\*\* \S'
                if not re.search(padrao, corpo, re.M):
                    erro(f'{arq.name} {ident}: falta o campo "{campo}"')
            if len(corpo.strip().splitlines()) > 4 + 2:
                avisos.append(f'{arq.name} {ident}: item com mais de quatro linhas de campo (conferir se há texto solto)')
        prefixos = {m.group(1).split('-')[0] for m in itens}
        if len(prefixos) > 1:
            erro(f'{arq.name}: mais de um prefixo de id no mesmo arquivo: {sorted(prefixos)}')
    return ids


def conferir_links() -> None:
    for arq in RAIZ.rglob('*.md'):
        if '.git' in arq.parts:
            continue
        for m in RE_LINK.finditer(arq.read_text('utf-8')):
            alvo = m.group(1)
            if alvo.startswith(('http://', 'https://', 'mailto:')):
                continue
            destino = (arq.parent / alvo).resolve()
            if not destino.exists():
                erro(f'{arq.relative_to(RAIZ)}: link para arquivo inexistente: {alvo}')


def conferir_manifestos() -> None:
    pasta = RAIZ / '.claude-plugin'
    for nome in ('plugin.json', 'marketplace.json'):
        caminho = pasta / nome
        if not caminho.exists():
            erro(f'falta .claude-plugin/{nome}')
            continue
        try:
            dados = json.loads(caminho.read_text('utf-8'))
        except json.JSONDecodeError as e:
            erro(f'{nome}: JSON inválido ({e})')
            continue
        if nome == 'plugin.json':
            for chave in ('name', 'description', 'version', 'skills'):
                if chave not in dados:
                    erro(f'plugin.json: falta "{chave}"')
            for skills in dados.get('skills', []):
                if not (RAIZ / skills).is_dir():
                    erro(f'plugin.json: pasta de skills inexistente: {skills}')
        else:
            if not dados.get('plugins'):
                erro('marketplace.json: lista "plugins" vazia')
            for p in dados.get('plugins', []):
                if p.get('source') not in ('./', '.'):
                    avisos.append(f'marketplace.json: plugin {p.get("name")} com source {p.get("source")!r}')


def conferir_skills() -> None:
    pasta = RAIZ / 'skills'
    skills = sorted(pasta.glob('*/SKILL.md'))
    if not skills:
        erro('nenhuma skill em skills/*/SKILL.md')
    for arq in skills:
        texto = arq.read_text('utf-8')
        m = re.match(r'^---\n(.*?)\n---\n', texto, re.S)
        if not m:
            erro(f'{arq.parent.name}: SKILL.md sem frontmatter')
            continue
        frente = m.group(1)
        for chave in ('name', 'description'):
            if not re.search(rf'^{chave}: \S', frente, re.M):
                erro(f'{arq.parent.name}: frontmatter sem "{chave}"')
        nome = re.search(r'^name: (.+)$', frente, re.M)
        if nome and nome.group(1).strip() != arq.parent.name:
            erro(f'{arq.parent.name}: name "{nome.group(1).strip()}" diferente do nome da pasta')
        for caminho in RE_CAMINHO_SKILL.findall(texto):
            if not (RAIZ / caminho).exists():
                erro(f'{arq.parent.name}: cita arquivo inexistente do guia: {caminho}')
        for nome_arq in re.findall(r'`(\d{2}-[a-z0-9-]+\.md)`', texto):
            if not (RAIZ / 'checklists' / nome_arq).exists():
                erro(f'{arq.parent.name}: cita checklist inexistente: {nome_arq}')


def conferir_indices() -> None:
    nomes = sorted(p.name for p in (RAIZ / 'checklists').glob('*.md'))
    for doc in ('AGENTS.md', 'README.md'):
        texto = (RAIZ / doc).read_text('utf-8')
        for nome in nomes:
            if nome not in texto:
                erro(f'{doc}: não cita a checklist {nome}')


# Termos que nunca podem aparecer: o guia é público e neutro. Aqui ficam só os genéricos (domínios de e-mail
# pessoal e os formatos de CNPJ e CPF). A lista do escritório, dos clientes e das pessoas NÃO entra no código:
# vem de TERMOS_PROIBIDOS no ambiente (separados por vírgula), que no CI é um segredo do repositório. Quando um
# termo é achado, a mensagem diz a posição na lista, não o termo, para o log do CI não vazá-lo.
TERMOS_FIXOS = ('@' + 'gmail.com', '@' + 'hotmail.com', '@' + 'outlook.com')
RE_CNPJ = re.compile(r'\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b')
RE_CPF = re.compile(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b')


def conferir_termos() -> None:
    import os
    do_ambiente = [t.strip() for t in os.environ.get('TERMOS_PROIBIDOS', '').split(',') if t.strip()]
    termos = list(TERMOS_FIXOS) + do_ambiente
    proprio = Path(__file__).resolve()
    for arq in RAIZ.rglob('*'):
        if '.git' in arq.parts or arq.suffix not in ('.md', '.py', '.json', '.yml', '.txt') or arq.resolve() == proprio:
            continue
        texto = arq.read_text('utf-8', errors='replace')
        baixo = texto.lower()
        for i, termo in enumerate(termos):
            if termo.lower() in baixo:
                mostrar = termo if termo in TERMOS_FIXOS else f'nº {i - len(TERMOS_FIXOS) + 1} de TERMOS_PROIBIDOS'
                erro(f'{arq.relative_to(RAIZ)}: termo proibido ({mostrar})')
        for padrao, nome in ((RE_CNPJ, 'CNPJ formatado'), (RE_CPF, 'CPF formatado')):
            if padrao.search(texto):
                erro(f'{arq.relative_to(RAIZ)}: {nome} encontrado')


def main() -> int:
    if '--termos' in sys.argv:
        conferir_termos()
        for e in erros:
            print('ERRO:', e)
        print(f'termos proibidos: {len(erros)} ocorrência(s)')
        return 1 if erros else 0
    ids = conferir_checklists()
    conferir_links()
    conferir_manifestos()
    conferir_skills()
    conferir_indices()
    conferir_termos()
    for a in avisos:
        print('aviso:', a)
    for e in erros:
        print('ERRO:', e)
    print(f'{len(ids)} itens em {len(list((RAIZ / "checklists").glob("*.md")))} checklists, '
          f'{len(list((RAIZ / "skills").glob("*/SKILL.md")))} skills, {len(erros)} erro(s), {len(avisos)} aviso(s)')
    return 1 if erros else 0


if __name__ == '__main__':
    sys.exit(main())
