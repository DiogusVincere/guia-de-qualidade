# -*- coding: utf-8 -*-
"""Ponte opcional para o nuclei: a varredura ampla, com milhares de testes mantidos pela comunidade.

Se o binário `nuclei` existir na máquina, roda contra o alvo e traz os achados para o mesmo relatório. Se não
existir, emite um aviso com o passo para instalar — o scanner segue com as sondas próprias. Em produção, exclui
modelos intrusivos, de fuzzing e de negação de serviço, e limita a taxa.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from nucleo import Achado, Alvo

GRAVIDADE_NUCLEI = {'critical': 'critico', 'high': 'alto', 'medium': 'medio', 'low': 'baixo',
                    'info': 'info', 'unknown': 'info'}


def disponivel() -> bool:
    return shutil.which('nuclei') is not None


def rodar_nuclei(alvo: Alvo) -> list[Achado]:
    if not disponivel():
        return [Achado('nuclei', 'DEP-04', 'nuclei não instalado (varredura ampla pulada)', 'info', alvo.base_url,
                       'o binário nuclei não foi encontrado.',
                       'o nuclei traz milhares de testes atualizados que as sondas próprias não cobrem.',
                       'instale (https://github.com/projectdiscovery/nuclei) e rode de novo; sem ele, o scanner usa '
                       'só as sondas próprias.')]

    comando = ['nuclei', '-u', alvo.base_url.rstrip('/'), '-jsonl', '-silent', '-nc', '-duc',
               '-severity', 'low,medium,high,critical']
    if alvo.ambiente == 'producao':
        comando += ['-exclude-tags', 'intrusive,dos,fuzz,bruteforce', '-rate-limit', '20']
    else:
        comando += ['-rate-limit', str(50 * alvo.intensidade)]

    try:
        proc = subprocess.run(comando, capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        return [Achado('nuclei', 'OPS-01', 'nuclei não terminou no tempo', 'info', alvo.base_url,
                       'a varredura passou de 30 min e foi interrompida.',
                       'pode ser alvo grande ou rede lenta.',
                       'rode o nuclei à parte com mais tempo, ou limite as tags.')]
    except Exception as e:  # noqa: BLE001
        return [Achado('nuclei', 'OPS-06', 'nuclei falhou ao rodar', 'info', alvo.base_url,
                       f'{type(e).__name__}: {e}', 'não foi possível executar o nuclei.',
                       'confira a instalação do nuclei.')]

    achados: list[Achado] = []
    for linha in proc.stdout.splitlines():
        linha = linha.strip()
        if not linha:
            continue
        try:
            d = json.loads(linha)
        except json.JSONDecodeError:
            continue
        info = d.get('info', {})
        grav = GRAVIDADE_NUCLEI.get(str(info.get('severity', 'info')).lower(), 'info')
        nome = info.get('name', d.get('template-id', 'achado do nuclei'))
        achados.append(Achado('nuclei', 'DEP-04', f'[nuclei] {nome}', grav,
                              d.get('matched-at', alvo.base_url),
                              f"modelo {d.get('template-id', '?')}; " + (info.get('description', '') or '')[:200],
                              'achado da varredura ampla do nuclei.',
                              '; '.join(info.get('reference', []) or []) or 'veja a referência do modelo do nuclei.'))
    if not achados:
        achados.append(Achado('nuclei', 'DEP-04', 'nuclei rodou sem achados', 'info', alvo.base_url,
                              f'{len(proc.stdout.splitlines())} linha(s) de saída, nenhum achado de gravidade.',
                              'a varredura ampla não encontrou nada nos modelos usados.',
                              'bom sinal; mantenha o nuclei atualizado (nuclei -update-templates).'))
    return achados
