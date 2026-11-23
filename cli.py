"""Interface de linha de comando (CLI) para gerenciar e consultar a blockchain didática.

Projeto Bônus — Introdução à Criptografia (Extensão Opcional — Seção 9)
Permite:
- Inicializar uma cadeia em arquivo JSON (`init`);
- Inserir um novo evento acadêmico fictício minerando um bloco (`inserir`);
- Consultar eventos por participante ou tipo (`consultar`);
- Exibir todos os blocos e raízes de Merkle (`listar`);
- Validar a integridade da cadeia armazenada (`validar`);
- Executar benchmark estatístico de dificuldade (`benchmark`).
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from blockchain import Blockchain, criar_registro
from extensoes import (
    calcular_raiz_merkle,
    carregar_cadeia_json,
    medir_media_tentativas,
    salvar_cadeia_json,
)

ARQUIVO_PADRAO = Path("cadeia_academica.json")


def construir_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos da interface de linha de comando."""
    parser = argparse.ArgumentParser(
        prog="python cli.py",
        description="CLI da Blockchain Didática — Registro de Eventos Acadêmicos Fictícios",
    )
    parser.add_argument(
        "--arquivo",
        type=Path,
        default=ARQUIVO_PADRAO,
        help="Caminho do arquivo JSON da cadeia (padrão: cadeia_academica.json)",
    )

    subparsers = parser.add_subparsers(dest="comando", required=True)

    # Subcomando: init
    p_init = subparsers.add_parser("init", help="Cria uma nova cadeia com o bloco gênese")
    p_init.add_argument(
        "--dificuldade",
        type=int,
        default=2,
        help="Dificuldade da prova de trabalho entre 1 e 6 (padrão: 2)",
    )

    # Subcomando: inserir
    p_ins = subparsers.add_parser("inserir", help="Minera e adiciona um bloco com novo evento")
    p_ins.add_argument("--tipo", required=True, help="Tipo do evento (ex.: certificado, disciplina)")
    p_ins.add_argument(
        "--participante",
        required=True,
        help="Pseudônimo fictício (ex.: aluno-017)",
    )
    p_ins.add_argument("--descricao", required=True, help="Descrição do evento acadêmico")

    # Subcomando: consultar
    p_con = subparsers.add_parser("consultar", help="Filtra eventos por participante ou tipo")
    p_con.add_argument("--participante", help="Filtrar por pseudônimo exato (ex.: aluno-017)")
    p_con.add_argument("--tipo", help="Filtrar por tipo de evento (ex.: certificado)")

    # Subcomando: listar
    subparsers.add_parser("listar", help="Lista todos os blocos, registros e raízes de Merkle")

    # Subcomando: validar
    subparsers.add_parser("validar", help="Verifica a integridade completa da cadeia no arquivo JSON")

    # Subcomando: benchmark
    p_bench = subparsers.add_parser(
        "benchmark",
        help="Mede o número médio de tentativas por dificuldade (1, 2 e 3)",
    )
    p_bench.add_argument(
        "--amostras",
        type=int,
        default=5,
        help="Quantidade de blocos minerados por dificuldade (padrão: 5)",
    )

    return parser


def executar_cli(argv: list[str] | None = None) -> int:
    """Executa o comando solicitado na CLI e devolve o código de saída (0 = sucesso)."""
    parser = construir_parser()
    args = parser.parse_args(argv)
    arquivo: Path = args.arquivo

    if args.comando == "init":
        cadeia = Blockchain(dificuldade=args.dificuldade)
        salvar_cadeia_json(cadeia, arquivo)
        print(
            f"[OK] Cadeia inicializada com dificuldade {cadeia.dificuldade} em '{arquivo}'. "
            f"Hash gênese: {cadeia.ultimo_bloco.hash}"
        )
        return 0

    if args.comando == "benchmark":
        stats = medir_media_tentativas((1, 2, 3), amostras_por_dificuldade=args.amostras)
        print(
            f"{'Dificuldade':<12} | {'Amostras':<8} | {'Média Empírica':<16} | "
            f"{'Teórico (16^d)':<15} | {'Tempo Médio (ms)'}"
        )
        print("-" * 78)
        for item in stats:
            print(
                f"{item['dificuldade']:<12} | {item['amostras']:<8} | "
                f"{item['media_tentativas_empirica']:<16} | "
                f"{item['esperanca_teorica_16_pow_d']:<15.1f} | {item['tempo_medio_ms']}"
            )
        return 0

    if not arquivo.exists():
        print(
            f"[ERRO] Arquivo '{arquivo}' não encontrado. Execute `python cli.py init` primeiro.",
            file=sys.stderr,
        )
        return 1

    if args.comando == "validar":
        cadeia = carregar_cadeia_json(arquivo, exigir_valida=False)
        valido, motivo = cadeia.diagnosticar()
        print(f"Arquivo   : {arquivo}")
        print(f"Válida?   : {valido}")
        print(f"Diagnóstico: {motivo}")
        return 0 if valido else 2

    cadeia = carregar_cadeia_json(arquivo, exigir_valida=True)

    if args.comando == "inserir":
        reg = criar_registro(args.tipo, args.participante, args.descricao)
        bloco = cadeia.adicionar_bloco([reg])
        salvar_cadeia_json(cadeia, arquivo)
        print(
            f"[OK] Bloco #{bloco.indice} minerado (nonce={bloco.nonce}, hash={bloco.hash[:20]}...) "
            f"e salvo em '{arquivo}'."
        )
        return 0

    if args.comando == "listar":
        print(f"=== Cadeia Acadêmica ({len(cadeia.blocos)} blocos, dificuldade={cadeia.dificuldade}) ===")
        for b in cadeia.blocos:
            raiz_merkle = calcular_raiz_merkle(b.registros)
            print(
                f"Bloco #{b.indice} | timestamp={b.timestamp} | nonce={b.nonce} | "
                f"hash={b.hash[:16]}... | merkle={raiz_merkle[:16]}..."
            )
            for r in b.registros:
                print(f"  - [{r['tipo']}] {r['participante']}: {r['descricao']}")
        return 0

    if args.comando == "consultar":
        encontrados = 0
        for b in cadeia.blocos:
            for r in b.registros:
                if args.participante and r["participante"] != args.participante:
                    continue
                if args.tipo and r["tipo"] != args.tipo:
                    continue
                encontrados += 1
                print(
                    f"[Bloco #{b.indice} | {b.hash[:12]}...] "
                    f"[{r['tipo']}] {r['participante']} -> {r['descricao']}"
                )
        print(f"Total de registros encontrados: {encontrados}")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(executar_cli())
