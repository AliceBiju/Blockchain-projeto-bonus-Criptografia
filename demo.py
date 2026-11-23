"""Demonstração completa da blockchain didática e do ataque controlado.

Projeto Bônus — Introdução à Criptografia
Este script executa as 5 situações obrigatórias da demonstração (Seções 4, 5 e 7):
1. Criação do bloco gênese + 3 blocos com eventos acadêmicos fictícios e validação da cadeia original;
2. Adulteração de um registro em um bloco antigo (Bloco 1) e detecção da falha pelo validador;
3. Remineração APENAS do bloco adulterado, demonstrando que a cadeia continua inválida devido à quebra do elo (hash_anterior do Bloco 2);
4. Reconstrução completa (atualização de hash_anterior e remineração de todos os elos posteriores), demonstrando que a cadeia local volta a ser válida e como uma âncora externa confiável detecta a fraude;
5. Comparação experimental entre diferentes níveis de dificuldade (1, 2 e 3), medindo nonces testados e tempo com time.perf_counter().
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

from blockchain import (
    Blockchain,
    criar_registro,
    serializar_canonico,
)


def exibir_resumo_cadeia(cadeia: Blockchain, titulo: str) -> None:
    """Imprime o estado detalhado de cada bloco da cadeia e o resultado da validação."""
    valido, motivo = cadeia.diagnosticar()
    status_str = "VÁLIDA (True)" if valido else "INVÁLIDA (False)"

    print("=" * 88)
    print(f" {titulo}")
    print("=" * 88)
    for bloco in cadeia.blocos:
        hash_recalc = bloco.calcular_hash()
        bate_hash = "OK" if bloco.hash == hash_recalc else "DIVERGENTE"
        print(
            f"  [Bloco {bloco.indice}] timestamp={bloco.timestamp} | "
            f"dificuldade={bloco.dificuldade} | nonce={bloco.nonce}"
        )
        print(f"    hash_anterior : {bloco.hash_anterior[:24]}...{bloco.hash_anterior[-8:]}")
        print(f"    hash_guardado : {bloco.hash[:24]}...{bloco.hash[-8:]} ({bate_hash})")
        for reg in bloco.registros:
            print(
                f"    registro      : [{reg['tipo']}] {reg['participante']} -> {reg['descricao']}"
            )
    print("-" * 88)
    print(f"  Resultado de cadeia.validar(): {status_str}")
    print(f"  Diagnóstico técnico          : {motivo}")
    print("=" * 88 + "\n")


def demonstrar_serializacao_e_avalanche() -> dict[str, Any]:
    """Demonstra a Etapa 2: determinismo da serialização canônica e efeito avalanche do SHA-256."""
    dict_ordem_a = {
        "tipo": "certificado",
        "participante": "aluno-017",
        "descricao": "Conclusao do curso de Introducao a Criptografia com carga de 60h",
    }
    dict_ordem_b = {
        "descricao": "Conclusao do curso de Introducao a Criptografia com carga de 60h",
        "tipo": "certificado",
        "participante": "aluno-017",
    }
    dict_alterado_1_char = {
        "tipo": "certificado",
        "participante": "aluno-017",
        "descricao": "Conclusao do curso de Introducao a Criptografia com carga de 61h",
    }

    json_a = serializar_canonico(dict_ordem_a)
    json_b = serializar_canonico(dict_ordem_b)
    json_alt = serializar_canonico(dict_alterado_1_char)

    hash_a = hashlib.sha256(json_a.encode("utf-8")).hexdigest()
    hash_b = hashlib.sha256(json_b.encode("utf-8")).hexdigest()
    hash_alt = hashlib.sha256(json_alt.encode("utf-8")).hexdigest()

    print("=" * 88)
    print(" ETAPA 2 — SERIALIZAÇÃO CANÔNICA E EFEITO AVALANCHE DO SHA-256")
    print("=" * 88)
    print(f"  JSON Ordem A == JSON Ordem B : {json_a == json_b}")
    print(f"  Texto Canônico               : {json_a}")
    print(f"  SHA-256 Original (60h)       : {hash_a}")
    print(f"  SHA-256 Alterado (61h)       : {hash_alt}")
    print(f"  Hashes diferentes?           : {hash_a != hash_alt}")
    print("=" * 88 + "\n")

    return {
        "serializacao_deterministica": json_a == json_b,
        "hash_original": hash_a,
        "hash_alterado": hash_alt,
    }


def comparar_dificuldades(dificuldades: tuple[int, ...] = (1, 2, 3)) -> list[dict[str, Any]]:
    """Compara o número de tentativas (nonce + 1) e o tempo de mineração para diferentes dificuldades."""
    resultados: list[dict[str, Any]] = []

    print("=" * 88)
    print(" SITUAÇÃO 5 — COMPARAÇÃO EXPERIMENTAL DE DIFICULDADE (PROVA DE TRABALHO)")
    print("=" * 88)
    print(
        f"  {'Dificuldade':<12} | {'Prefixo':<10} | {'Total de Tentativas':<20} | "
        f"{'Tempo (ms)':<14} | {'Hash do Último Bloco (início)'}"
    )
    print("-" * 88)

    for dif in dificuldades:
        inicio = time.perf_counter()
        cadeia = Blockchain(dificuldade=dif)
        cadeia.adicionar_bloco(
            [criar_registro("matricula", "aluno-017", "Ingresso no semestre letivo 2026.1")],
            timestamp=1700000100,
        )
        cadeia.adicionar_bloco(
            [criar_registro("disciplina", "aluno-017", "Aprovacao em Introducao a Criptografia")],
            timestamp=1700000200,
        )
        cadeia.adicionar_bloco(
            [criar_registro("certificado", "aluno-017", "Emissao de diploma digital verificavel")],
            timestamp=1700000300,
        )
        duracao_ms = (time.perf_counter() - inicio) * 1000.0

        tentativas_totais = sum(bloco.nonce + 1 for bloco in cadeia.blocos)
        prefixo = "0" * dif
        ultimo_hash = cadeia.ultimo_bloco.hash

        print(
            f"  {dif:<12} | {prefixo:<10} | {tentativas_totais:<20} | "
            f"{duracao_ms:<14.3f} | {ultimo_hash[:24]}..."
        )

        resultados.append(
            {
                "dificuldade": dif,
                "prefixo": prefixo,
                "tentativas_totais": tentativas_totais,
                "tempo_ms": duracao_ms,
                "ultimo_hash": ultimo_hash,
                "valida": cadeia.validar(),
            }
        )

    print("-" * 88)
    print(
        "  Observação teórica: cada zero hexadecimal adicional exige 4 bits adicionais iguais a zero,"
    )
    print(
        "  multiplicando o número médio esperado de tentativas por 16 (2^4 = 16)."
    )
    print("=" * 88 + "\n")
    return resultados


def executar_demonstracao_completa(
    dificuldade_demo: int = 2,
    silencioso: bool = False,
) -> dict[str, Any]:
    """Executa todas as 5 situações obrigatórias da demonstração e retorna os dados coletados."""
    if not silencioso:
        info_serializacao = demonstrar_serializacao_e_avalanche()
    else:
        dict_a = {"tipo": "certificado", "participante": "aluno-017", "descricao": "60h"}
        dict_b = {"descricao": "60h", "tipo": "certificado", "participante": "aluno-017"}
        dict_c = {"tipo": "certificado", "participante": "aluno-017", "descricao": "61h"}
        ja = serializar_canonico(dict_a)
        jb = serializar_canonico(dict_b)
        jc = serializar_canonico(dict_c)
        info_serializacao = {
            "serializacao_deterministica": ja == jb,
            "hash_original": hashlib.sha256(ja.encode("utf-8")).hexdigest(),
            "hash_alterado": hashlib.sha256(jc.encode("utf-8")).hexdigest(),
        }

    # -------------------------------------------------------------------------
    # SITUAÇÃO 1: Criar bloco gênese + 3 blocos e validar a cadeia original
    # -------------------------------------------------------------------------
    cadeia = Blockchain(dificuldade=dificuldade_demo)

    cadeia.adicionar_bloco(
        [
            criar_registro(
                tipo="conclusao_disciplina",
                participante="aluno-017",
                descricao="Aprovado em Introducao a Criptografia com conceito A",
            ),
            criar_registro(
                tipo="conclusao_disciplina",
                participante="aluno-042",
                descricao="Aprovado em Introducao a Criptografia com conceito B",
            ),
        ],
        timestamp=1710000100,
    )

    cadeia.adicionar_bloco(
        [
            criar_registro(
                tipo="emissao_certificado",
                participante="aluno-017",
                descricao="Certificado de Monitoria em Seguranca da Informacao (40h)",
            )
        ],
        timestamp=1710000200,
    )

    cadeia.adicionar_bloco(
        [
            criar_registro(
                tipo="ata_defesa",
                participante="aluno-089",
                descricao="Defesa de Trabalho de Conclusao de Curso aprovada sem ressalvas",
            )
        ],
        timestamp=1710000300,
    )

    if not silencioso:
        exibir_resumo_cadeia(
            cadeia,
            "SITUAÇÃO 1 — CADEIA ORIGINAL ÍNTEGRA (GÊNESE + 3 BLOCOS)",
        )
    valida_original = cadeia.validar()

    # Guardamos uma "âncora externa confiável" (hash do último bloco antes do ataque)
    ancora_externa_hash_bloco_3 = cadeia.ultimo_bloco.hash
    hash_original_bloco_1 = cadeia.blocos[1].hash

    # -------------------------------------------------------------------------
    # SITUAÇÃO 2: Adulterar um registro antigo (Bloco 1) sem reminerar
    # -------------------------------------------------------------------------
    cadeia.blocos[1].registros[1]["descricao"] = (
        "Aprovado em Introducao a Criptografia com conceito A+ (ADULTERADO)"
    )
    if not silencioso:
        exibir_resumo_cadeia(
            cadeia,
            "SITUAÇÃO 2 — ADULTERAÇÃO DIRETA DE REGISTRO NO BLOCO 1 (SEM REMINERAR)",
        )
    valida_apos_adulteracao = cadeia.validar()
    _, motivo_adulteracao = cadeia.diagnosticar()

    # -------------------------------------------------------------------------
    # SITUAÇÃO 3: Reminerar SOMENTE o bloco adulterado (Bloco 1)
    # -------------------------------------------------------------------------
    cadeia.blocos[1].minerar()
    if not silencioso:
        exibir_resumo_cadeia(
            cadeia,
            "SITUAÇÃO 3 — REMINERAÇÃO ISOLADA DO BLOCO 1 (FALHA NO ELO DO BLOCO 2)",
        )
    valida_apos_reminerar_um = cadeia.validar()
    _, motivo_reminerar_um = cadeia.diagnosticar()

    # -------------------------------------------------------------------------
    # SITUAÇÃO 4: Reconstruir e reminerar todos os blocos posteriores (Blocos 2 e 3)
    # -------------------------------------------------------------------------
    for indice in range(2, len(cadeia.blocos)):
        cadeia.blocos[indice].hash_anterior = cadeia.blocos[indice - 1].hash
        cadeia.blocos[indice].minerar()

    if not silencioso:
        exibir_resumo_cadeia(
            cadeia,
            "SITUAÇÃO 4 — RECONSTRUÇÃO TOTAL DOS ELOS AFETADOS (BLOCOS 1, 2 E 3 REMINERADOS)",
        )
    valida_apos_reconstrucao_total = cadeia.validar()
    novo_hash_bloco_3 = cadeia.ultimo_bloco.hash

    if not silencioso:
        print("=" * 88)
        print(" ANÁLISE CRÍTICA — POR QUE UMA LISTA LOCAL NÃO É UMA BLOCKCHAIN DISTRIBUÍDA SEGURA?")
        print("=" * 88)
        print(f"  Hash original do Bloco 1             : {hash_original_bloco_1}")
        print(f"  Novo hash do Bloco 1 (após fraude)   : {cadeia.blocos[1].hash}")
        print(f"  Âncora Externa Confiável (Bloco 3)   : {ancora_externa_hash_bloco_3}")
        print(f"  Novo Hash Local do Bloco 3 (refeito) : {novo_hash_bloco_3}")
        print(
            f"  Divergência detectada pela âncora?   : {ancora_externa_hash_bloco_3 != novo_hash_bloco_3}"
        )
        print("-" * 88)
        print("  Conclusão:")
        print("  1. O encadeamento por hash e a prova de trabalho (PoW) garantem EVIDÊNCIA DE ADULTERAÇÃO")
        print("     parcial, mas NÃO oferecem imutabilidade absoluta quando há um único controlador local.")
        print("  2. Com dificuldade baixa e controle exclusivo da memória/arquivo, o atacante consegue")
        print("     atualizar `hash_anterior` e reminerar todos os blocos subsequentes em milissegundos.")
        print("  3. Para impedir ou detectar essa reescrita total, são necessários:")
        print("     - Uma ÂNCORA EXTERNA CONFIÁVEL (hash publicado fora do controle do atacante); ou")
        print("     - Uma REDE DISTRIBUÍDA P2P com múltiplos nós independentes, assinaturas digitais")
        print("       para autenticar a autoria dos registros e uma regra de CONSENSO DISTRIBUÍDO.")
        print("=" * 88 + "\n")

        # -------------------------------------------------------------------------
        # SITUAÇÃO 5: Comparar dificuldades
        # -------------------------------------------------------------------------
        comparativo_dificuldades = comparar_dificuldades((1, 2, 3))
    else:
        comparativo_dificuldades = []

    return {
        "serializacao": info_serializacao,
        "valida_original": valida_original,
        "valida_apos_adulteracao": valida_apos_adulteracao,
        "motivo_adulteracao": motivo_adulteracao,
        "valida_apos_reminerar_um": valida_apos_reminerar_um,
        "motivo_reminerar_um": motivo_reminerar_um,
        "valida_apos_reconstrucao_total": valida_apos_reconstrucao_total,
        "ancora_externa": ancora_externa_hash_bloco_3,
        "hash_final_reconstruido": novo_hash_bloco_3,
        "comparativo_dificuldades": comparativo_dificuldades,
    }


if __name__ == "__main__":
    executar_demonstracao_completa(dificuldade_demo=2)
