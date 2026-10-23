# -*- coding: utf-8 -*-
"""Slopsquatting e pacote fantasma: confere se cada dependência existe mesmo no registro público.

A IA inventa nome de pacote (cerca de 20% das sugestões apontam para nomes que não existem) e os nomes se repetem;
o atacante registra o nome fantasma com código malicioso e espera alguém rodar o install. Não é só Python/JS/PHP:
a campanha TrapDoor de 10/2026 atingiu npm, PyPI e crates.io juntos. Esta sonda lê os manifestos do repositório —
requirements/pyproject (Python), package.json (JS), composer.json (PHP), Cargo.toml (Rust), Gemfile (Ruby),
pom.xml/build.gradle (Java) — e pergunta a cada registro (PyPI, npm, Packagist, crates.io, RubyGems, Maven) se o
pacote existe. Nome que não existe no público é alvo de slopsquatting (ou erro de digitação que vira porta). Roda só
com `--codigo <pasta>`. Fala com os registros públicos (nomes de pacote já são públicos). Ver IA-08/IA-09.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from nucleo import Achado, Alvo

TETO = {1: 40, 2: 80, 3: 160, 4: 320, 5: 1000}     # quantos pacotes conferir, pelo nível

# pacotes que não são de registro: linguagem, extensão, meta
PHP_IGNORAR = re.compile(r'^(php(-64bit)?|ext-|lib-|composer-|composer/|hhvm)', re.I)


def _nome_py(linha: str) -> str:
    linha = linha.split('#', 1)[0].strip()
    if not linha or linha.startswith('-') or '://' in linha or linha.startswith(('.', '/')):
        return ''
    # tira marcador de ambiente, extras e especificador de versão
    linha = linha.split(';', 1)[0].split('[', 1)[0]
    nome = re.split(r'[<>=!~ )(]', linha, maxsplit=1)[0].strip()
    return nome if re.match(r'^[A-Za-z0-9._-]+$', nome) else ''


def _deps_requirements(texto: str) -> set[str]:
    return {n for n in (_nome_py(l) for l in texto.splitlines()) if n}


def _deps_pyproject(texto: str) -> set[str]:
    try:
        import tomllib
    except Exception:
        return set()
    try:
        dados = tomllib.loads(texto)
    except Exception:
        return set()
    nomes: set[str] = set()
    proj = dados.get('project', {})
    for item in proj.get('dependencies', []) or []:
        n = _nome_py(item)
        if n:
            nomes.add(n)
    for grupo in (proj.get('optional-dependencies', {}) or {}).values():
        for item in grupo or []:
            n = _nome_py(item)
            if n:
                nomes.add(n)
    poetry = dados.get('tool', {}).get('poetry', {})
    for chave in ('dependencies', 'dev-dependencies'):
        for nome in (poetry.get(chave, {}) or {}):
            if nome.lower() != 'python':
                nomes.add(nome)
    return nomes


def _deps_package_json(texto: str) -> set[str]:
    try:
        dados = json.loads(texto)
    except Exception:
        return set()
    nomes: set[str] = set()
    for chave in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
        for nome, versao in (dados.get(chave, {}) or {}).items():
            v = str(versao)
            if v.startswith(('file:', 'link:', 'workspace:', 'git+', 'http')) or '/' in v and v.startswith('github'):
                continue
            nomes.add(nome)
    return nomes


def _deps_composer(texto: str) -> set[str]:
    try:
        dados = json.loads(texto)
    except Exception:
        return set()
    nomes: set[str] = set()
    for chave in ('require', 'require-dev'):
        for nome in (dados.get(chave, {}) or {}):
            if '/' in nome and not PHP_IGNORAR.match(nome):
                nomes.add(nome)
    return nomes


def _deps_cargo(texto: str) -> set[str]:            # Rust
    try:
        import tomllib
    except Exception:
        return set()
    try:
        dados = tomllib.loads(texto)
    except Exception:
        return set()
    nomes: set[str] = set()
    for chave in ('dependencies', 'dev-dependencies', 'build-dependencies'):
        for nome, spec in (dados.get(chave, {}) or {}).items():
            # dependência local (path) ou de git não é do crates.io
            if isinstance(spec, dict) and (spec.get('path') or spec.get('git')):
                continue
            nomes.add(spec.get('package', nome) if isinstance(spec, dict) else nome)
    return nomes


def _deps_gemfile(texto: str) -> set[str]:          # Ruby
    nomes: set[str] = set()
    for m in re.finditer(r'^\s*gem\s+["\']([A-Za-z0-9._\-]+)["\']', texto, re.M):
        nomes.add(m.group(1))
    return nomes


def _deps_pom(texto: str) -> set[str]:              # Java/Maven
    nomes: set[str] = set()
    for m in re.finditer(r'<dependency>(.*?)</dependency>', texto, re.S):
        bloco = m.group(1)
        g = re.search(r'<groupId>\s*([^<$]+?)\s*</groupId>', bloco)
        a = re.search(r'<artifactId>\s*([^<$]+?)\s*</artifactId>', bloco)
        if g and a and '${' not in g.group(1) and '${' not in a.group(1):
            nomes.add(f'{g.group(1)}:{a.group(1)}')
    return nomes


def _deps_gradle(texto: str) -> set[str]:           # Java/Kotlin (Gradle)
    nomes: set[str] = set()
    for m in re.finditer(r'["\']([A-Za-z0-9._\-]+:[A-Za-z0-9._\-]+):[^"\']+["\']', texto):
        nomes.add(m.group(1))
    return nomes


# (ecossistema, arquivo, função, montador de URL de existência)
def _url_pypi(n):      return f'https://pypi.org/pypi/{n}/json'
def _url_npm(n):       return 'https://registry.npmjs.org/' + n.replace('/', '%2f')
def _url_packagist(n): return f'https://repo.packagist.org/p2/{n}.json'
def _url_crates(n):    return f'https://crates.io/api/v1/crates/{n}'
def _url_rubygems(n):  return f'https://rubygems.org/api/v1/gems/{n}.json'
def _url_maven(n):
    grupo, art = n.split(':', 1)
    return f'https://repo1.maven.org/maven2/{grupo.replace(".", "/")}/{art}/maven-metadata.xml'

FONTES = [
    ('PyPI', 'requirements.txt', _deps_requirements, _url_pypi),
    ('PyPI', 'pyproject.toml', _deps_pyproject, _url_pypi),
    ('npm', 'package.json', _deps_package_json, _url_npm),
    ('Packagist', 'composer.json', _deps_composer, _url_packagist),
    ('crates.io', 'Cargo.toml', _deps_cargo, _url_crates),
    ('RubyGems', 'Gemfile', _deps_gemfile, _url_rubygems),
    ('Maven', 'pom.xml', _deps_pom, _url_maven),
    ('Maven', 'build.gradle', _deps_gradle, _url_maven),
]


def _consultador_padrao(alvo: Alvo):
    import requests
    sessao = requests.Session()
    sessao.headers['User-Agent'] = 'guia-de-qualidade/scanner'

    def consultar(url: str) -> int:
        try:
            r = sessao.get(url, timeout=min(alvo.timeout, 10), stream=True)
            cod = r.status_code
            r.close()
            return cod
        except Exception:
            return 0
    return consultar


def dependencias_fantasma(alvo: Alvo) -> list[Achado]:
    if not alvo.codigo:
        return [Achado('dependencias', 'IA-08', 'Slopsquatting não verificado (sem --codigo)', 'info', alvo.base_url,
                       'a checagem de pacote fantasma lê os manifestos do repositório.',
                       'nome de pacote que a IA inventa e não existe no registro é alvo de slopsquatting.',
                       'rode com --codigo <pasta do repositório> para conferir requirements/package.json/composer.json.')]
    raiz = Path(alvo.codigo)
    consultar = getattr(alvo, '_consultar_registro', None) or _consultador_padrao(alvo)

    # junta as dependências por ecossistema, varrendo o repositório (sem node_modules/venv)
    por_eco: dict[str, tuple] = {}     # (ecossistema, nome) -> url
    arquivos_lidos: list[str] = []
    for eco, arquivo, extrair, monta_url in FONTES:
        for caminho in raiz.rglob(arquivo):
            if any(p in ('node_modules', '.venv', 'venv', 'vendor', '.git', 'dist', 'build')
                   for p in caminho.parts):
                continue
            try:
                texto = caminho.read_text('utf-8', 'ignore')
            except Exception:
                continue
            arquivos_lidos.append(str(caminho.relative_to(raiz)))
            for nome in extrair(texto):
                por_eco.setdefault((eco, nome), monta_url(nome))

    if not por_eco:
        return [Achado('dependencias', 'IA-08', 'Nenhum manifesto de dependência encontrado', 'info', alvo.base_url,
                       'não achei requirements.txt, pyproject.toml, package.json nem composer.json.',
                       'sem manifesto, não há o que conferir contra o registro.',
                       'se as dependências ficam em outro arquivo, aponte a pasta certa com --codigo.')]

    teto = TETO.get(alvo.intensidade, 80)
    itens = sorted(por_eco.items())[:teto]
    fantasmas: list[tuple] = []        # (ecossistema, nome)
    conferidos = 0
    indefinidos = 0
    for (eco, nome), url in itens:
        cod = consultar(url)
        if alvo.pausa:
            import time
            time.sleep(alvo.pausa)
        if cod == 404:
            fantasmas.append((eco, nome))
        elif cod == 200:
            conferidos += 1
        else:
            indefinidos += 1

    achados: list[Achado] = []
    for eco, nome in fantasmas:
        achados.append(Achado('dependencias', 'IA-08', f'Dependência que não existe no {eco}: {nome}', 'critico',
                              alvo.base_url,
                              f'o manifesto pede "{nome}", mas o pacote não existe no {eco} (resposta 404).',
                              'pacote que não existe no registro público é alvo de slopsquatting: o atacante registra '
                              'o nome com código malicioso e você o instala no próximo "install". Pode ser nome '
                              'inventado por IA ou erro de digitação.',
                              'confirme o nome certo do pacote e a procedência antes de instalar; se o nome está certo '
                              'e o pacote some, trave a origem no registro privado (confusão de dependência, IA-09).'))
    nota = (f'{len(itens)} dependência(s) conferida(s) em {len(arquivos_lidos)} manifesto(s): '
            f'{conferidos} existem, {len(fantasmas)} fantasma(s), {indefinidos} sem resposta do registro.')
    achados.append(Achado('dependencias', 'IA-08', 'Checagem de pacote fantasma concluída',
                          'critico' if fantasmas else 'info', alvo.base_url, nota,
                          'é a defesa contra slopsquatting: todo nome sugerido por IA tratado como não confiável até '
                          'provar que existe e de onde veio.',
                          'rode SCA no CI e use allowlist de dependências em produção; ver a checklist 07.'))
    return achados
