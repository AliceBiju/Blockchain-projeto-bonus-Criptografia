"""Implementação de uma blockchain didática local para registro de eventos acadêmicos.

Projeto Bônus — Introdução à Criptografia
Este módulo utiliza exclusivamente a biblioteca padrão do Python 3.10+ e demonstra:
- Representação canônica e determinística de dados em JSON;
- Resumo criptográfico SHA-256 sobre bytes UTF-8;
- Estrutura de blocos encadeados pelo hash anterior e bloco gênese;
- Prova de trabalho (Proof of Work - PoW) simplificada por busca linear de nonce;
- Validação completa e imutável de integridade estrutural e criptográfica.

Aviso de segurança:
Este código tem finalidade estritamente educacional. Não implementa rede P2P,
consenso distribuído, criptomoeda, carteira ou proteção contra reescrita total
por um controlador local único sem âncora externa confiável.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
import hashlib
import json
import time
from typing import Any

# Constantes de protocolo didático
DIFICULDADE_MINIMA: int = 1
DIFICULDADE_MAXIMA: int = 6
HASH_ANTERIOR_GENESE: str = "0" * 64
CAMPOS_REGISTRO_OBRIGATORIOS: tuple[str, ...] = ("tipo", "participante", "descricao")

REGISTRO_GENESE: dict[str, str] = {
    "tipo": "genese",
    "participante": "sistema-000",
    "descricao": "Bloco genese da cadeia academica didatica",
}


def _validar_dificuldade(dificuldade: Any) -> int:
    """Valida se a dificuldade é um inteiro estrito entre 1 e 6 (rejeita booleanos)."""
    if isinstance(dificuldade, bool) or not isinstance(dificuldade, int):
        raise TypeError("A dificuldade deve ser um número inteiro entre 1 e 6.")
    if not (DIFICULDADE_MINIMA <= dificuldade <= DIFICULDADE_MAXIMA):
        raise ValueError(
            f"A dificuldade deve estar entre {DIFICULDADE_MINIMA} e {DIFICULDADE_MAXIMA}."
        )
    return dificuldade


def _validar_timestamp(timestamp: Any) -> int:
    """Valida se o timestamp é um número inteiro não negativo (rejeita booleanos)."""
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise TypeError("O timestamp deve ser um número inteiro (segundos Unix).")
    if timestamp < 0:
        raise ValueError("O timestamp não pode ser negativo.")
    return timestamp


def serializar_canonico(dados: Any) -> str:
    """Converte estruturas de dados Python em texto JSON determinístico (canônico).

    Regras aplicadas:
    - sort_keys=True: ordena chaves de dicionários lexicograficamente;
    - separators=(",", ":"): elimina espaços em branco opcionais;
    - ensure_ascii=False: preserva caracteres Unicode diretamente;
    - allow_nan=False: rejeita valores float especiais (NaN, Infinity, -Infinity).
    """
    return json.dumps(
        dados,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def criar_registro(tipo: str, participante: str, descricao: str) -> dict[str, str]:
    """Valida e normaliza os três campos textuais de um evento acadêmico fictício.

    Cada campo deve ser do tipo `str` e conter texto não vazio após remoção
    de espaços nas extremidades (`strip()`). Use apenas pseudônimos fictícios
    (ex.: 'aluno-017'), pois hashes públicos não anonimizam dados pessoais.
    """
    campos_entrada = {
        "tipo": tipo,
        "participante": participante,
        "descricao": descricao,
    }
    registro_normalizado: dict[str, str] = {}

    for nome_campo, valor in campos_entrada.items():
        if not isinstance(valor, str):
            raise TypeError(f"O campo '{nome_campo}' do registro deve ser uma string (str).")
        texto_limpo = valor.strip()
        if not texto_limpo:
            raise ValueError(f"O campo '{nome_campo}' do registro não pode ser vazio.")
        registro_normalizado[nome_campo] = texto_limpo

    return registro_normalizado


def _validar_lista_registros(registros: Any) -> list[dict[str, str]]:
    """Valida uma lista de registros garantindo cópia profunda e formato canônico."""
    if not isinstance(registros, list):
        raise TypeError("Os registros do bloco devem ser fornecidos em uma lista.")
    if len(registros) == 0:
        raise ValueError("A lista de registros de um bloco não pode ser vazia.")

    registros_validados: list[dict[str, str]] = []
    for item in registros:
        if not isinstance(item, dict):
            raise TypeError("Cada registro deve ser um dicionário com tipo, participante e descricao.")
        if set(item.keys()) != set(CAMPOS_REGISTRO_OBRIGATORIOS):
            raise ValueError(
                "Cada registro deve conter exatamente as chaves: 'tipo', 'participante' e 'descricao'."
            )
        registro_limpo = criar_registro(
            item["tipo"],
            item["participante"],
            item["descricao"],
        )
        registros_validados.append(registro_limpo)

    return registros_validados


@dataclass
class Bloco:
    """Representa um bloco da cadeia com metadados, registros acadêmicos e prova de trabalho."""

    indice: int
    timestamp: int
    registros: list[dict[str, str]]
    hash_anterior: str
    dificuldade: int = 1
    nonce: int = 0
    hash: str = field(default="")

    def __post_init__(self) -> None:
        """Valida tipos básicos, normaliza cópia profunda dos registros e inicializa o hash."""
        if isinstance(self.indice, bool) or not isinstance(self.indice, int):
            raise TypeError("O índice do bloco deve ser um número inteiro.")
        if self.indice < 0:
            raise ValueError("O índice do bloco não pode ser negativo.")

        _validar_timestamp(self.timestamp)
        _validar_dificuldade(self.dificuldade)

        if isinstance(self.nonce, bool) or not isinstance(self.nonce, int):
            raise TypeError("O nonce deve ser um número inteiro.")
        if self.nonce < 0:
            raise ValueError("O nonce não pode ser negativo.")

        if not isinstance(self.hash_anterior, str) or not self.hash_anterior:
            raise ValueError("O hash_anterior deve ser uma string hexadecimal não vazia.")

        if not isinstance(self.hash, str):
            raise TypeError("O campo hash deve ser uma string.")

        self.registros = _validar_lista_registros(copy.deepcopy(self.registros))

        if not self.hash:
            self.hash = self.calcular_hash()

    def conteudo_para_hash(self) -> dict[str, Any]:
        """Reúne os campos protegidos do bloco em um dicionário, sem incluir o próprio campo `hash`."""
        return {
            "indice": self.indice,
            "timestamp": self.timestamp,
            "registros": self.registros,
            "hash_anterior": self.hash_anterior,
            "nonce": self.nonce,
            "dificuldade": self.dificuldade,
        }

    def calcular_hash(self) -> str:
        """Serializa canonicamente o conteúdo do bloco, codifica em UTF-8 e calcula o SHA-256."""
        texto_canonico = serializar_canonico(self.conteudo_para_hash())
        dados_bytes = texto_canonico.encode("utf-8")
        return hashlib.sha256(dados_bytes).hexdigest()

    def minerar(self) -> str:
        """Incrementa o nonce a partir de 0 até encontrar um hash com o prefixo exigido pela PoW."""
        _validar_dificuldade(self.dificuldade)
        prefixo_alvo = "0" * self.dificuldade
        self.nonce = 0

        while True:
            candidato = self.calcular_hash()
            if candidato.startswith(prefixo_alvo):
                self.hash = candidato
                return candidato
            self.nonce += 1


class Blockchain:
    """Gerencia a cadeia local de blocos, desde a criação do bloco gênese até a validação completa."""

    def __init__(self, dificuldade: int = 1) -> None:
        """Inicializa a cadeia validando a dificuldade e minerando o bloco gênese."""
        _validar_dificuldade(dificuldade)
        self.dificuldade: int = dificuldade
        self.blocos: list[Bloco] = []

        bloco_genese = Bloco(
            indice=0,
            timestamp=0,
            registros=[copy.deepcopy(REGISTRO_GENESE)],
            hash_anterior=HASH_ANTERIOR_GENESE,
            dificuldade=self.dificuldade,
            nonce=0,
        )
        bloco_genese.minerar()
        self.blocos.append(bloco_genese)

    @property
    def cadeias(self) -> list[Bloco]:
        """Alias de leitura para a lista de blocos da cadeia."""
        return self.blocos

    @property
    def ultimo_bloco(self) -> Bloco:
        """Oferece acesso de leitura ao último bloco atualmente anexado à cadeia."""
        if not self.blocos:
            raise ValueError("A cadeia de blocos está vazia.")
        return self.blocos[-1]

    def adicionar_bloco(
        self,
        registros: list[dict[str, str]],
        timestamp: int | None = None,
    ) -> Bloco:
        """Valida as entradas, copia profundamente os registros, minera e anexa um novo bloco.

        Não permite adicionar um bloco caso a cadeia atual já esteja inválida.
        """
        if not self.validar():
            raise ValueError("Não é permitido adicionar um novo bloco a uma cadeia inválida.")

        registros_copiados = _validar_lista_registros(copy.deepcopy(registros))

        if timestamp is None:
            instante = int(time.time())
        else:
            instante = _validar_timestamp(timestamp)

        anterior = self.ultimo_bloco
        novo_bloco = Bloco(
            indice=anterior.indice + 1,
            timestamp=instante,
            registros=registros_copiados,
            hash_anterior=anterior.hash,
            dificuldade=self.dificuldade,
            nonce=0,
        )
        novo_bloco.minerar()
        self.blocos.append(novo_bloco)
        return novo_bloco

    def diagnosticar(self) -> tuple[bool, str]:
        """Verifica toda a cadeia sem modificá-la e retorna `(valido, motivo_detalhado)`.

        Útil para relatórios, depuração e demonstração exata de qual elo ou regra falhou.
        """
        try:
            if not isinstance(self.blocos, list) or len(self.blocos) == 0:
                return False, "A cadeia de blocos está vazia ou malformada."

            _validar_dificuldade(self.dificuldade)

            for posicao, bloco in enumerate(self.blocos):
                if not isinstance(bloco, Bloco):
                    return False, f"O elemento na posição {posicao} não é uma instância de Bloco."

                # 1. Conferência de índice sequencial
                if isinstance(bloco.indice, bool) or not isinstance(bloco.indice, int):
                    return False, f"Bloco {posicao}: índice com tipo inválido."
                if bloco.indice != posicao:
                    return (
                        False,
                        f"Bloco na posição {posicao} possui índice divergente ({bloco.indice}).",
                    )

                # 2. Conferência de timestamp e nonce
                if isinstance(bloco.timestamp, bool) or not isinstance(bloco.timestamp, int) or bloco.timestamp < 0:
                    return False, f"Bloco {posicao}: timestamp inválido ({bloco.timestamp})."
                if isinstance(bloco.nonce, bool) or not isinstance(bloco.nonce, int) or bloco.nonce < 0:
                    return False, f"Bloco {posicao}: nonce inválido ({bloco.nonce})."

                # 3. Conferência de dificuldade
                if isinstance(bloco.dificuldade, bool) or not isinstance(bloco.dificuldade, int):
                    return False, f"Bloco {posicao}: dificuldade com tipo inválido."
                if not (DIFICULDADE_MINIMA <= bloco.dificuldade <= DIFICULDADE_MAXIMA):
                    return (
                        False,
                        f"Bloco {posicao}: dificuldade {bloco.dificuldade} fora do intervalo [1, 6].",
                    )
                if bloco.dificuldade != self.dificuldade:
                    return (
                        False,
                        f"Bloco {posicao}: dificuldade ({bloco.dificuldade}) diverge da cadeia ({self.dificuldade}).",
                    )

                # 4. Conferência de estrutura e integridade dos registros
                if not isinstance(bloco.registros, list) or len(bloco.registros) == 0:
                    return False, f"Bloco {posicao}: lista de registros vazia ou inválida."

                for idx_reg, reg in enumerate(bloco.registros):
                    if not isinstance(reg, dict) or set(reg.keys()) != set(CAMPOS_REGISTRO_OBRIGATORIOS):
                        return (
                            False,
                            f"Bloco {posicao}, registro {idx_reg}: chaves inválidas.",
                        )
                    for campo in CAMPOS_REGISTRO_OBRIGATORIOS:
                        valor = reg[campo]
                        if not isinstance(valor, str) or not valor.strip() or valor != valor.strip():
                            return (
                                False,
                                f"Bloco {posicao}, registro {idx_reg}: campo '{campo}' vazio ou não normalizado.",
                            )

                # 5. Regras específicas do bloco gênese vs blocos subsequentes
                if posicao == 0:
                    if bloco.timestamp != 0:
                        return False, f"Bloco gênese deve ter timestamp 0 (encontrado: {bloco.timestamp})."
                    if bloco.hash_anterior != HASH_ANTERIOR_GENESE:
                        return False, "Bloco gênese não possui hash_anterior formado por 64 zeros."
                    if bloco.registros != [REGISTRO_GENESE]:
                        return False, "Bloco gênese possui registros diferentes do REGISTRO_GENESE padrão."
                else:
                    bloco_anterior = self.blocos[posicao - 1]
                    if bloco.hash_anterior != bloco_anterior.hash:
                        return (
                            False,
                            f"Bloco {posicao}: hash_anterior não corresponde ao hash do bloco {posicao - 1}.",
                        )

                # 6. Conferência da prova de trabalho e integridade do hash
                prefixo_exigido = "0" * bloco.dificuldade
                if not isinstance(bloco.hash, str) or len(bloco.hash) != 64:
                    return False, f"Bloco {posicao}: formato de hash inválido."

                hash_recalculado = bloco.calcular_hash()
                if bloco.hash != hash_recalculado:
                    return (
                        False,
                        f"Bloco {posicao}: hash armazenado diverge do hash recalculado (dados adulterados).",
                    )
                if not bloco.hash.startswith(prefixo_exigido):
                    return (
                        False,
                        f"Bloco {posicao}: hash não cumpre a dificuldade {bloco.dificuldade} (PoW inválida).",
                    )

            return True, "Cadeia íntegra: todos os blocos, hashes, elos e provas de trabalho são válidos."
        except (TypeError, ValueError) as erro:
            return False, f"Erro de validação estrutural: {erro}"

    def validar(self) -> bool:
        """Verifica toda a cadeia sem consertá-la e devolve True se íntegra ou False se inválida."""
        valido, _ = self.diagnosticar()
        return valido
