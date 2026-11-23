"""Extensões opcionais da Seção 9 da blockchain didática.

Projeto Bônus — Introdução à Criptografia
Implementa as 6 extensões opcionais propostas na Seção 9 (pós-testes obrigatórios):
1. Árvore de Merkle (`calcular_raiz_merkle`, `gerar_prova_merkle`, `verificar_prova_merkle`);
2. Assinatura digital Ed25519 dos registros com identidade fictícia usando biblioteca
   criptográfica consolidada (`cryptography.hazmat.primitives.asymmetric.ed25519`),
   com fallback gracioso caso o pacote opcional não esteja instalado no ambiente;
3. Persistência e recarga completa da cadeia em arquivo JSON (`salvar_cadeia_json`, `carregar_cadeia_json`);
4. Simulação de dois nós (`NoSimulado`) e regra explícita de escolha de cadeia válida mais longa /
   maior trabalho acumulado (`resolver_conflito_cadeias`), deixando explícito por que isso ainda
   não constitui um consenso distribuído robusto;
5. Medição estatística do número médio de tentativas por dificuldade (`medir_media_tentativas`);
6. Interface de linha de comando (CLI) para inserir, listar, validar e consultar eventos (`cli.py`).

Aviso importante (Seção 9):
Mesmo com extensões, este sistema continua sendo uma simulação local didática e NÃO é
descentralizado, imutável ou seguro para produção sem modelo de ameaça, rede P2P real,
consenso resistente a Sybil/Byzantine, gestão de identidade (PKI) e proteção de chaves (HSM).
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import time
from typing import Any

from blockchain import (
    Bloco,
    Blockchain,
    criar_registro,
    serializar_canonico,
)


# =============================================================================
# 1. ÁRVORE DE MERKLE E PROVA DE INCLUSÃO PARA OS REGISTROS
# =============================================================================
def hash_folha_merkle(registro: dict[str, str]) -> str:
    """Calcula o hash SHA-256 de uma folha da árvore de Merkle com prefixo de domínio 0x00."""
    dados = b"\x00" + serializar_canonico(registro).encode("utf-8")
    return hashlib.sha256(dados).hexdigest()


def hash_no_interno_merkle(esquerda: str, direita: str) -> str:
    """Calcula o hash SHA-256 de um nó interno da árvore de Merkle com prefixo de domínio 0x01."""
    dados = b"\x01" + esquerda.encode("ascii") + b":" + direita.encode("ascii")
    return hashlib.sha256(dados).hexdigest()


def calcular_raiz_merkle(registros: list[dict[str, str]]) -> str:
    """Calcula a raiz de Merkle (Merkle Root) de uma lista não vazia de registros acadêmicos.

    Se um nível tiver quantidade ímpar de nós, o último nó é duplicado para formar par.
    Usa separação de domínio (0x00 para folhas, 0x01 para nós internos) para prevenir
    ataques de segunda pré-imagem em árvores de Merkle.
    """
    if not isinstance(registros, list) or len(registros) == 0:
        raise ValueError("A lista de registros para a árvore de Merkle não pode ser vazia.")

    nivel_atual = [hash_folha_merkle(reg) for reg in registros]

    while len(nivel_atual) > 1:
        if len(nivel_atual) % 2 == 1:
            nivel_atual.append(nivel_atual[-1])
        proximo_nivel: list[str] = []
        for i in range(0, len(nivel_atual), 2):
            proximo_nivel.append(hash_no_interno_merkle(nivel_atual[i], nivel_atual[i + 1]))
        nivel_atual = proximo_nivel

    return nivel_atual[0]


def gerar_prova_merkle(
    registros: list[dict[str, str]],
    indice_alvo: int,
) -> list[dict[str, str]]:
    """Gera a prova de inclusão de Merkle (lista de irmãos e direções) para `registros[indice_alvo]`."""
    if not isinstance(registros, list) or len(registros) == 0:
        raise ValueError("A lista de registros não pode ser vazia.")
    if not (0 <= indice_alvo < len(registros)):
        raise IndexError("Índice do registro fora do intervalo da lista.")

    nivel_atual = [hash_folha_merkle(reg) for reg in registros]
    prova: list[dict[str, str]] = []
    pos = indice_alvo

    while len(nivel_atual) > 1:
        if len(nivel_atual) % 2 == 1:
            nivel_atual.append(nivel_atual[-1])

        if pos % 2 == 0:
            irmao = nivel_atual[pos + 1]
            posicao_irmao = "direita"
        else:
            irmao = nivel_atual[pos - 1]
            posicao_irmao = "esquerda"

        prova.append({"hash": irmao, "posicao": posicao_irmao})

        proximo_nivel: list[str] = []
        for i in range(0, len(nivel_atual), 2):
            proximo_nivel.append(hash_no_interno_merkle(nivel_atual[i], nivel_atual[i + 1]))

        nivel_atual = proximo_nivel
        pos //= 2

    return prova


def verificar_prova_merkle(
    registro: dict[str, str],
    prova: list[dict[str, str]],
    raiz_esperada: str,
) -> bool:
    """Verifica se um registro pertence à árvore de Merkle com `raiz_esperada` usando sua prova."""
    acumulado = hash_folha_merkle(registro)
    for passo in prova:
        irmao = passo["hash"]
        posicao = passo["posicao"]
        if posicao == "direita":
            acumulado = hash_no_interno_merkle(acumulado, irmao)
        elif posicao == "esquerda":
            acumulado = hash_no_interno_merkle(irmao, acumulado)
        else:
            raise ValueError(f"Posição inválida na prova de Merkle: {posicao}")
    return acumulado == raiz_esperada


# =============================================================================
# 2. ASSINATURA DIGITAL Ed25519 DOS REGISTROS (BIBLIOTECA CONSOLIDADA)
# =============================================================================
@dataclass
class IdentidadeFicticiaEd25519:
    """Representa uma identidade acadêmica fictícia (ex.: 'secretaria-001') com par de chaves Ed25519."""

    identificador: str
    _chave_privada: Any
    chave_publica_hex: str

    @classmethod
    def gerar(cls, identificador: str) -> IdentidadeFicticiaEd25519:
        """Gera um novo par de chaves Ed25519 usando a biblioteca consolidada `cryptography`."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        if not isinstance(identificador, str) or not identificador.strip():
            raise ValueError("O identificador fictício não pode ser vazio.")

        priv = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return cls(
            identificador=identificador.strip(),
            _chave_privada=priv,
            chave_publica_hex=pub_bytes.hex(),
        )

    def assinar_registro(self, registro: dict[str, str]) -> dict[str, str]:
        """Assina canonicamente um registro acadêmico e devolve um pacote autenticado."""
        reg_limpo = criar_registro(
            registro["tipo"],
            registro["participante"],
            registro["descricao"],
        )
        mensagem_bytes = serializar_canonico(reg_limpo).encode("utf-8")
        assinatura_bytes = self._chave_privada.sign(mensagem_bytes)
        return {
            "registro": reg_limpo,  # type: ignore[dict-item]
            "emissor": self.identificador,
            "chave_publica_hex": self.chave_publica_hex,
            "assinatura_hex": assinatura_bytes.hex(),
        }


def verificar_assinatura_registro(
    pacote_assinado: dict[str, Any],
    chave_publica_esperada_hex: str | None = None,
) -> bool:
    """Verifica a assinatura Ed25519 de um registro acadêmico usando `cryptography`."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519

    try:
        registro = pacote_assinado["registro"]
        reg_limpo = criar_registro(
            registro["tipo"],
            registro["participante"],
            registro["descricao"],
        )
        pub_hex = chave_publica_esperada_hex or pacote_assinado["chave_publica_hex"]
        assinatura_hex = pacote_assinado["assinatura_hex"]

        chave_publica = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        mensagem_bytes = serializar_canonico(reg_limpo).encode("utf-8")
        chave_publica.verify(bytes.fromhex(assinatura_hex), mensagem_bytes)
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError):
        return False


# =============================================================================
# 3. PERSISTÊNCIA E RECARGA DA CADEIA EM JSON
# =============================================================================
def exportar_cadeia_dict(cadeia: Blockchain) -> dict[str, Any]:
    """Converte uma instância de Blockchain em um dicionário serializável em JSON."""
    return {
        "dificuldade": cadeia.dificuldade,
        "blocos": [
            {
                "indice": b.indice,
                "timestamp": b.timestamp,
                "registros": copy.deepcopy(b.registros),
                "hash_anterior": b.hash_anterior,
                "nonce": b.nonce,
                "dificuldade": b.dificuldade,
                "hash": b.hash,
            }
            for b in cadeia.blocos
        ],
    }


def salvar_cadeia_json(cadeia: Blockchain, caminho: str | Path) -> Path:
    """Salva toda a cadeia de blocos em um arquivo JSON formatado em UTF-8."""
    destino = Path(caminho)
    dados = exportar_cadeia_dict(cadeia)
    destino.write_text(
        json.dumps(dados, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    return destino


def carregar_cadeia_json(caminho: str | Path, exigir_valida: bool = True) -> Blockchain:
    """Recarrega uma cadeia de blocos a partir de um arquivo JSON e valida sua integridade."""
    origem = Path(caminho)
    dados = json.loads(origem.read_text(encoding="utf-8"))

    if not isinstance(dados, dict) or "dificuldade" not in dados or "blocos" not in dados:
        raise ValueError("Arquivo JSON não possui a estrutura esperada de Blockchain.")

    cadeia = Blockchain(dificuldade=dados["dificuldade"])
    blocos_reconstruidos: list[Bloco] = []
    for item in dados["blocos"]:
        bloco = Bloco(
            indice=item["indice"],
            timestamp=item["timestamp"],
            registros=item["registros"],
            hash_anterior=item["hash_anterior"],
            dificuldade=item["dificuldade"],
            nonce=item["nonce"],
            hash=item["hash"],
        )
        blocos_reconstruidos.append(bloco)

    cadeia.blocos = blocos_reconstruidos
    if exigir_valida and not cadeia.validar():
        _, motivo = cadeia.diagnosticar()
        raise ValueError(f"A cadeia carregada do JSON é inválida: {motivo}")
    return cadeia


# =============================================================================
# 4. SIMULAÇÃO DE DOIS NÓS E REGRA EXPLÍCITA DE ESCOLHA DE CADEIA
# =============================================================================
def calcular_trabalho_acumulado(cadeia: Blockchain) -> int:
    """Calcula uma estimativa didática do trabalho acumulado: soma de 16^(dificuldade) por bloco."""
    if not cadeia.validar():
        return 0
    return sum(16**bloco.dificuldade for bloco in cadeia.blocos)


@dataclass
class NoSimulado:
    """Representa um nó local simulado para demonstrar sincronização e resolução de conflitos."""

    nome: str
    cadeia: Blockchain

    def clonar_cadeia_de(self, outro_no: NoSimulado) -> None:
        """Copia profundamente os blocos de outro nó."""
        self.cadeia.dificuldade = outro_no.cadeia.dificuldade
        self.cadeia.blocos = copy.deepcopy(outro_no.cadeia.blocos)

    def sincronizar_com(self, candidato: Blockchain) -> tuple[bool, str]:
        """Adota a cadeia candidata somente se ela for íntegra e tiver maior trabalho acumulado
        (ou maior comprimento com mesma dificuldade).

        Nota didática: Esta regra ilustra a escolha da cadeia mais longa/pesada, mas NÃO constitui
        um consenso distribuído robusto porque ambos os objetos executam no mesmo processo local,
        sem rede P2P real, sem resistência a ataques Sybil/51% e sem identidade criptográfica.
        """
        if not candidato.validar():
            return False, "Cadeia candidata rejeitada: falhou na validação criptográfica."

        minha_valida = self.cadeia.validar()
        meu_trabalho = calcular_trabalho_acumulado(self.cadeia) if minha_valida else -1
        trabalho_candidato = calcular_trabalho_acumulado(candidato)

        if not minha_valida or trabalho_candidato > meu_trabalho:
            self.cadeia.dificuldade = candidato.dificuldade
            self.cadeia.blocos = copy.deepcopy(candidato.blocos)
            return (
                True,
                f"Nó '{self.nome}' adotou a nova cadeia (blocos={len(candidato.blocos)}, "
                f"trabalho={trabalho_candidato}).",
            )

        return (
            False,
            f"Nó '{self.nome}' manteve sua cadeia atual (trabalho atual {meu_trabalho} >= "
            f"candidato {trabalho_candidato}).",
        )


# =============================================================================
# 5. MEDIÇÃO DO NÚMERO MÉDIO DE TENTATIVAS POR DIFICULDADE
# =============================================================================
def medir_media_tentativas(
    dificuldades: tuple[int, ...] = (1, 2, 3),
    amostras_por_dificuldade: int = 8,
) -> list[dict[str, Any]]:
    """Mede empiricamente o número médio de tentativas e o tempo médio por dificuldade."""
    estatisticas: list[dict[str, Any]] = []

    for dif in dificuldades:
        if amostras_por_dificuldade < 1:
            raise ValueError("O número de amostras deve ser pelo menos 1.")

        total_tentativas = 0
        inicio = time.perf_counter()

        for i in range(amostras_por_dificuldade):
            bloco = Bloco(
                indice=i + 1,
                timestamp=1720000000 + i,
                registros=[
                    criar_registro(
                        "experimento",
                        f"aluno-{i:03d}",
                        f"Amostra estatistica {i} para dificuldade {dif}",
                    )
                ],
                hash_anterior=f"{i:064x}",
                dificuldade=dif,
            )
            bloco.minerar()
            total_tentativas += bloco.nonce + 1

        duracao_total_ms = (time.perf_counter() - inicio) * 1000.0
        media_empirica = total_tentativas / amostras_por_dificuldade
        esperanca_teorica = float(16**dif)

        estatisticas.append(
            {
                "dificuldade": dif,
                "amostras": amostras_por_dificuldade,
                "media_tentativas_empirica": round(media_empirica, 2),
                "esperanca_teorica_16_pow_d": esperanca_teorica,
                "tempo_medio_ms": round(duracao_total_ms / amostras_por_dificuldade, 3),
            }
        )

    return estatisticas
