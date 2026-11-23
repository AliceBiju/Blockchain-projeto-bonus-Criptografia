"""Esqueleto inicial de referência (Etapa 0) com os TODOs mapeados no caderno.

Nota: Este arquivo é mantido na subpasta `codigo_inicial/` apenas para documentar
a Etapa 0 (hipóteses e relação entre falhas iniciais e TODOs). A implementação
completa e funcional encontra-se na raiz do repositório (`../blockchain.py`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

HASH_ANTERIOR_GENESE: str = "0" * 64
REGISTRO_GENESE: dict[str, str] = {
    "tipo": "genese",
    "participante": "sistema-000",
    "descricao": "Bloco genese da cadeia academica didatica",
}


def serializar_canonico(dados: Any) -> str:
    """TODO (Etapa 2): converter dados em JSON determinístico."""
    raise NotImplementedError("TODO: implementar serializar_canonico")


def criar_registro(tipo: str, participante: str, descricao: str) -> dict[str, str]:
    """TODO (Etapa 1): validar e normalizar os três campos textuais."""
    raise NotImplementedError("TODO: implementar criar_registro")


@dataclass
class Bloco:
    indice: int
    timestamp: int
    registros: list[dict[str, str]]
    hash_anterior: str
    dificuldade: int = 1
    nonce: int = 0
    hash: str = field(default="")

    def conteudo_para_hash(self) -> dict[str, Any]:
        """TODO (Etapa 3): reunir os campos protegidos, sem incluir o próprio hash."""
        raise NotImplementedError("TODO: implementar Bloco.conteudo_para_hash")

    def calcular_hash(self) -> str:
        """TODO (Etapa 2): serializar, codificar em UTF-8 e aplicar SHA-256."""
        raise NotImplementedError("TODO: implementar Bloco.calcular_hash")

    def minerar(self) -> str:
        """TODO (Etapa 4): variar o nonce e armazenar o hash que cumpre a dificuldade."""
        raise NotImplementedError("TODO: implementar Bloco.minerar")


class Blockchain:
    def __init__(self, dificuldade: int = 1) -> None:
        """TODO (Etapa 3): criar e minerar o bloco gênese."""
        raise NotImplementedError("TODO: implementar Blockchain.__init__")

    @property
    def ultimo_bloco(self) -> Bloco:
        """TODO (Etapa 3): oferecer acesso de leitura ao último bloco."""
        raise NotImplementedError("TODO: implementar Blockchain.ultimo_bloco")

    def adicionar_bloco(
        self,
        registros: list[dict[str, str]],
        timestamp: int | None = None,
    ) -> Bloco:
        """TODO (Etapa 5): validar, copiar, minerar e anexar um novo bloco."""
        raise NotImplementedError("TODO: implementar Blockchain.adicionar_bloco")

    def validar(self) -> bool:
        """TODO (Etapa 6): verificar toda a cadeia sem consertá-la."""
        raise NotImplementedError("TODO: implementar Blockchain.validar")
