# -*- coding: utf-8 -*-
"""Pontes para as ferramentas de mercado — o que um profissional de segurança usa, cada uma a melhor na sua camada.

A filosofia é a do nuclei: se a ferramenta está instalada, o scanner a roda e traz os achados para o mesmo
relatório; se não está, avisa como instalar e segue com o resto. Assim o núcleo continua leve (só requests) e você
liga as camadas que quiser.

- Semgrep: SAST — analisa o CÓDIGO-FONTE parado (precisa de --codigo).
- gitleaks: segredo no histórico do git (precisa de --codigo).
- osv-scanner: SCA — CVE conhecido nas dependências (precisa de --codigo).
- trivy: SCA, IaC e container (precisa de --codigo).
- testssl.sh: TLS a fundo (roda contra o host do alvo).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from urllib.parse import urlparse

from nucleo import Achado, Alvo

GRAV = {'critical': 'critico', 'high': 'alto', 'error': 'alto', 'medium': 'medio', 'warning': 'medio',
        'moderate': 'medio', 'low': 'baixo', 'info': 'info', 'note': 'info', 'unknown': 'info'}


def _falta(nome: str, como: str, alvo: Alvo, item='DEP-04') -> Achado:
    return Achado(nome, item, f'{nome} não instalado (camada pulada)', 'info', alvo.base_url,
                  f'o {nome} não foi encontrado.', f'o {nome} cobre uma camada que as sondas próprias não fazem.',
                  f'instale e rode de novo: {como}. Sem ele, o scanner segue com as outras sondas.')


def _precisa_codigo(nome: str, alvo: Alvo) -> Achado:
    return Achado(nome, 'REC-01', f'{nome} precisa do código-fonte (--codigo)', 'info', alvo.base_url,
                  f'o {nome} analisa o código, não a URL.',
                  'SAST, segredo no git e SCA se fazem sobre o repositório.',
                  f'rode com --codigo <pasta do repositório> para ligar o {nome}.')


def _rodar(comando: list, timeout: int = 1200):
    return subprocess.run(comando, capture_output=True, text=True, timeout=timeout)


# =====================================================================================================================
# Semgrep — SAST
# =====================================================================================================================
def semgrep(alvo: Alvo) -> list[Achado]:
    if not alvo.codigo:
        return [_precisa_codigo('semgrep', alvo)]
    if not shutil.which('semgrep'):
        return [_falta('semgrep', 'pip install semgrep (ou pipx install semgrep)', alvo)]
    try:
        proc = _rodar(['semgrep', '--config', 'auto', '--json', '--quiet', str(alvo.codigo)])
        dados = json.loads(proc.stdout or '{}')
    except Exception as e:  # noqa: BLE001
        return [Achado('semgrep', 'OPS-06', 'semgrep falhou', 'info', alvo.base_url, f'{type(e).__name__}: {e}',
                       'não foi possível rodar o semgrep.', 'confira a instalação do semgrep.')]
    achados = []
    for r in dados.get('results', [])[:60]:
        sev = (r.get('extra', {}).get('severity') or 'info').lower()
        msg = r.get('extra', {}).get('message', r.get('check_id', ''))
        onde = f"{r.get('path', '?')}:{r.get('start', {}).get('line', '?')}"
        achados.append(Achado('semgrep', 'QA-01', f'[semgrep] {r.get("check_id", "regra")}', GRAV.get(sev, 'medio'),
                              onde, (msg or '')[:240], 'análise estática do código-fonte (SAST).',
                              'corrija no código conforme a regra; veja a referência do semgrep.'))
    if not achados:
        achados.append(Achado('semgrep', 'QA-01', 'semgrep rodou sem achados', 'info', str(alvo.codigo),
                              f'{len(dados.get("results", []))} resultado(s).', 'SAST sem apontamentos de gravidade.',
                              'bom sinal; mantenha as regras atualizadas.'))
    return achados


# =====================================================================================================================
# gitleaks — segredo no histórico do git
# =====================================================================================================================
def gitleaks(alvo: Alvo) -> list[Achado]:
    if not alvo.codigo:
        return [_precisa_codigo('gitleaks', alvo)]
    if not shutil.which('gitleaks'):
        return [_falta('gitleaks', 'veja github.com/gitleaks/gitleaks/releases', alvo, 'SEG-01')]
    try:
        proc = _rodar(['gitleaks', 'detect', '--source', str(alvo.codigo), '--report-format', 'json',
                       '--report-path', '-', '--no-banner', '--exit-code', '0'])
        dados = json.loads(proc.stdout or '[]')
    except Exception as e:  # noqa: BLE001
        return [Achado('gitleaks', 'OPS-06', 'gitleaks falhou', 'info', alvo.base_url, f'{type(e).__name__}: {e}',
                       'não foi possível rodar o gitleaks.', 'confira a instalação do gitleaks.')]
    achados = []
    for d in (dados or [])[:40]:
        onde = f"{d.get('File', '?')}:{d.get('StartLine', '?')} (commit {str(d.get('Commit', ''))[:8]})"
        achados.append(Achado('gitleaks', 'SEG-01', f"[gitleaks] {d.get('RuleID', 'segredo')}", 'critico', onde,
                              f"segredo no histórico do git: {d.get('Description', '')[:120]}",
                              'segredo commitado continua no histórico mesmo depois de apagado do código atual.',
                              'troque o segredo que vazou; remova do histórico com git filter-repo; force o push.'))
    if not achados:
        achados.append(Achado('gitleaks', 'SEG-01', 'gitleaks rodou sem achados', 'info', str(alvo.codigo),
                              'nenhum segredo no histórico.', 'bom sinal.', 'mantenha o gitleaks num hook de commit.'))
    return achados


# =====================================================================================================================
# osv-scanner — SCA (CVE nas dependências)
# =====================================================================================================================
def osv(alvo: Alvo) -> list[Achado]:
    if not alvo.codigo:
        return [_precisa_codigo('osv-scanner', alvo)]
    if not shutil.which('osv-scanner'):
        return [_falta('osv-scanner', 'veja github.com/google/osv-scanner', alvo, 'DEP-04')]
    try:
        proc = _rodar(['osv-scanner', '--format', 'json', '-r', str(alvo.codigo)])
        dados = json.loads(proc.stdout or '{}')
    except Exception as e:  # noqa: BLE001
        return [Achado('osv', 'OPS-06', 'osv-scanner falhou', 'info', alvo.base_url, f'{type(e).__name__}: {e}',
                       'não foi possível rodar o osv-scanner.', 'confira a instalação do osv-scanner.')]
    achados = []
    for res in dados.get('results', []):
        for pac in res.get('packages', []):
            nome = pac.get('package', {}).get('name', '?')
            versao = pac.get('package', {}).get('version', '?')
            for v in pac.get('vulnerabilities', [])[:3]:
                ident = v.get('id', '?')
                sev = 'alto'
                achados.append(Achado('osv', 'DEP-04', f'[osv] {nome} {versao}: {ident}', sev,
                                      str(alvo.codigo), (v.get('summary') or ident)[:200],
                                      'dependência com vulnerabilidade conhecida.',
                                      f'atualize {nome} para uma versão corrigida; veja {ident} no osv.dev.'))
    if not achados:
        achados.append(Achado('osv', 'DEP-04', 'osv-scanner rodou sem achados', 'info', str(alvo.codigo),
                              'nenhuma CVE conhecida nas dependências.', 'bom sinal.', 'rode a cada mudança de dependência.'))
    return achados[:50]


# =====================================================================================================================
# trivy — SCA, IaC e container
# =====================================================================================================================
def trivy(alvo: Alvo) -> list[Achado]:
    if not alvo.codigo:
        return [_precisa_codigo('trivy', alvo)]
    if not shutil.which('trivy'):
        return [_falta('trivy', 'veja aquasecurity.github.io/trivy', alvo, 'DEP-04')]
    try:
        proc = _rodar(['trivy', 'fs', '--scanners', 'vuln,misconfig,secret', '--format', 'json', '--quiet',
                       str(alvo.codigo)])
        dados = json.loads(proc.stdout or '{}')
    except Exception as e:  # noqa: BLE001
        return [Achado('trivy', 'OPS-06', 'trivy falhou', 'info', alvo.base_url, f'{type(e).__name__}: {e}',
                       'não foi possível rodar o trivy.', 'confira a instalação do trivy.')]
    achados = []
    for res in dados.get('Results', []):
        for v in (res.get('Vulnerabilities') or [])[:10]:
            sev = (v.get('Severity') or 'unknown').lower()
            achados.append(Achado('trivy', 'DEP-04', f"[trivy] {v.get('PkgName')} {v.get('VulnerabilityID')}",
                                  GRAV.get(sev, 'medio'), res.get('Target', str(alvo.codigo)),
                                  (v.get('Title') or v.get('VulnerabilityID') or '')[:200],
                                  'vulnerabilidade conhecida em dependência.', f"atualize {v.get('PkgName')}."))
        for m in (res.get('Misconfigurations') or [])[:10]:
            sev = (m.get('Severity') or 'unknown').lower()
            achados.append(Achado('trivy', 'OPS-04', f"[trivy] {m.get('ID')}: {m.get('Title', '')[:60]}",
                                  GRAV.get(sev, 'medio'), res.get('Target', str(alvo.codigo)),
                                  (m.get('Message') or '')[:200], 'erro de configuração de infra (IaC/container).',
                                  m.get('Resolution', 'veja a referência do trivy.')[:160]))
    if not achados:
        achados.append(Achado('trivy', 'DEP-04', 'trivy rodou sem achados', 'info', str(alvo.codigo),
                              'nada em dependências, IaC e segredos.', 'bom sinal.', 'rode no CI.'))
    return achados[:60]


# =====================================================================================================================
# testssl.sh — TLS a fundo
# =====================================================================================================================
def testssl(alvo: Alvo) -> list[Achado]:
    if urlparse(alvo.base_url).scheme != 'https':
        return []
    if not shutil.which('testssl.sh') and not shutil.which('testssl'):
        return [_falta('testssl.sh', 'veja github.com/drwetter/testssl.sh', alvo, 'DAD-09')]
    binario = shutil.which('testssl.sh') or shutil.which('testssl')
    host = urlparse(alvo.base_url).hostname
    try:
        proc = _rodar([binario, '--severity', 'HIGH', '--jsonfile', '-', '--quiet', host], timeout=600)
        linhas = [json.loads(l) for l in proc.stdout.splitlines() if l.strip().startswith('{')]
    except Exception as e:  # noqa: BLE001
        return [Achado('testssl', 'OPS-06', 'testssl.sh falhou', 'info', alvo.base_url, f'{type(e).__name__}: {e}',
                       'não foi possível rodar o testssl.sh.', 'confira a instalação.')]
    achados = []
    for f in linhas:
        sev = (f.get('severity') or 'info').lower()
        if sev in ('high', 'critical'):
            achados.append(Achado('testssl', 'DAD-09', f"[testssl] {f.get('id')}", GRAV.get(sev, 'medio'),
                                  alvo.base_url, (f.get('finding') or '')[:200], 'problema de TLS/SSL a fundo.',
                                  'ajuste cifras/protocolo no provedor; veja a referência do testssl.'))
    if not achados:
        achados.append(Achado('testssl', 'DAD-09', 'testssl.sh sem achados altos', 'info', alvo.base_url,
                              'nenhum problema de TLS de gravidade alta.', 'bom sinal.', 'TLS a fundo conferido.'))
    return achados
