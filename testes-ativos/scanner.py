# -*- coding: utf-8 -*-
"""Scanner de segurança do guia de qualidade: roda de verdade contra um site SEU e diz o que achou.

Uso:
    python testes-ativos/scanner.py --alvo https://seusite --autorizo "é meu / tenho autorização"
    python testes-ativos/scanner.py --alvo https://homolog.seusite --ambiente homologacao --escrever --intensidade 4
    python testes-ativos/scanner.py --alvo http://localhost:3000 --ambiente local --intensidade 5 --saida relatorio.md

As travas, que não se desligam por opção:
- sem --autorizo o scanner não roda. A frase é registrada no relatório.
- escrita (POST/PUT/PATCH/DELETE) NUNCA acontece em produção, mesmo com --escrever.
- o nível de carga é limitado em produção (teto 2), por mais alto que você peça; o limite aparece no relatório.
- não é ferramenta para mirar site de terceiro. Use só no que é seu ou que você tem permissão escrita para testar.

É teste não destrutivo: cargas de injeção são marcadores que DETECTAM a falha, nunca alteram nem apagam dado.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(os.path.abspath(__file__)).parent))

import relatorio as rel  # noqa: E402
import sondas  # noqa: E402
from configuracao import Config  # noqa: E402
from nucleo import Alvo, Bloqueado  # noqa: E402


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='Teste de segurança ativo e não destrutivo contra um site seu.')
    p.add_argument('--alvo', required=True, help='URL completa do site (http:// ou https://)')
    p.add_argument('--autorizo', required=True, metavar='FRASE',
                   help='declare que o alvo é seu ou que você tem autorização para testá-lo')
    p.add_argument('--ambiente', choices=['producao', 'homologacao', 'local'], default='producao',
                   help='producao (padrão) só leitura; homologacao e local liberam escrita e estresse')
    p.add_argument('--escrever', action='store_true',
                   help='permite requisições de escrita, varredura autenticada, lógica e login (ignorado em produção)')
    p.add_argument('--intensidade', type=int, default=2, help='nível de carga 1 a 5 (produção é limitada a 2)')
    p.add_argument('--codigo', type=Path, help='pasta do código-fonte local, para as ferramentas de SAST, segredo '
                                               'no git e SCA (semgrep, gitleaks, osv-scanner, trivy)')
    p.add_argument('--config', type=Path, help='JSON com a estrutura do site (login, rotas de admin, IDOR, pedido); '
                                               'sem segredo — ver exemplos/alvo.exemplo.json')
    p.add_argument('--usuario', help='usuário para a varredura autenticada (ou a variável SCANNER_USUARIO)')
    p.add_argument('--senha', help='senha para a varredura autenticada (ou a variável SCANNER_SENHA; preferível)')
    p.add_argument('--sondas', help='só estas sondas, separadas por vírgula (rastreio,tls,cabecalhos,segredos,'
                                    'exposicao,injecao,autenticacao,autenticado,logica,carga,login,nuclei)')
    p.add_argument('--pausa', type=float, default=0.0, help='segundos de pausa entre requisições (gentileza)')
    p.add_argument('--oast', action='store_true',
                   help='liga o colaborador fora-de-banda (interactsh) para achar SSRF cego; fala com um servidor '
                        'de terceiro (oast.pro etc.) — por isso é opcional')
    p.add_argument('--oast-servidor', action='append', metavar='HOST',
                   help='servidor interactsh próprio em vez dos públicos (pode repetir)')
    p.add_argument('--saida', type=Path, help='arquivo .md para gravar o relatório (além de resumir no terminal)')
    a = p.parse_args(argv)

    try:
        config = Config.de_arquivo(a.config).com_credenciais(a.usuario or '', a.senha or '')
    except (ValueError, OSError) as e:
        print(f'config inválida: {e}', file=sys.stderr)
        return 2

    try:
        alvo = Alvo(a.alvo, a.ambiente, a.intensidade, autorizado=True,
                    permitir_escrita=a.escrever, pausa=a.pausa, config=config)
        alvo.codigo = a.codigo
    except (Bloqueado, ValueError) as e:
        print(f'não dá para começar: {e}', file=sys.stderr)
        return 2

    if a.oast or a.oast_servidor:
        from oast import Colaborador
        alvo.oast = Colaborador(servidores=a.oast_servidor or None)
        print('fora-de-banda (OAST) ligado: fala com um servidor interactsh para achar SSRF cego.', file=sys.stderr)

    print(f'Testando {alvo.base_url} ({alvo.ambiente}). Autorização: "{a.autorizo}".', file=sys.stderr)
    if alvo.ambiente == 'producao':
        print('Produção: só leitura; escrita e estresse alto ficam para homologação.', file=sys.stderr)
    if alvo.escrita_pedida_em_producao:
        print('--escrever foi ignorado porque o ambiente é produção.', file=sys.stderr)
    if alvo.intensidade_limitada:
        print(f'nível {a.intensidade} limitado a {alvo.intensidade} em produção.', file=sys.stderr)

    apenas = [s.strip() for s in a.sondas.split(',')] if a.sondas else None
    achados = sondas.rodar_tudo(alvo, apenas)

    texto = rel.montar(alvo, achados, a.autorizo)
    if a.saida:
        a.saida.write_text(texto, 'utf-8')
        print(f'relatório em {a.saida}', file=sys.stderr)
    print(rel.resumo_terminal(alvo, achados))

    graves = [x for x in achados if x.gravidade in ('critico', 'alto')]
    return 1 if graves else 0


if __name__ == '__main__':
    sys.exit(main())
