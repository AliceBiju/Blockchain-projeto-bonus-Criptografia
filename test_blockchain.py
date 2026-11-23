"""Suíte completa de testes automatizados para a blockchain didática.

Projeto Bônus — Introdução à Criptografia
Cobre integralmente os 12 requisitos funcionais obrigatórios da Seção 5:
1. serialização canônica e hash determinístico;
2. hash diferente após alteração de dado relevante;
3. rejeição de registro com campo vazio ou tipo incorreto;
4. criação válida do bloco gênese;
5. mineração satisfazendo a dificuldade;
6. inclusão de pelo menos três blocos;
7. cadeia íntegra aceita pelo validador;
8. registro adulterado rejeitado;
9. hash anterior adulterado rejeitado;
10. nonce adulterado ou prova inválida rejeitada;
11. dificuldade fora do intervalo de 1 a 6 rejeitada;
12. entradas do chamador copiadas, sem mutação inesperada;
além de testes para o cenário de ataque controlado e reconstrução da Etapa 7.
"""

from __future__ import annotations

import math
import unittest

from blockchain import (
    HASH_ANTERIOR_GENESE,
    REGISTRO_GENESE,
    Bloco,
    Blockchain,
    criar_registro,
    serializar_canonico,
)
from demo import executar_demonstracao_completa


class TestBlockchainDidatica(unittest.TestCase):
    """Testes unitários e funcionais da especificação da blockchain didática."""

    # -------------------------------------------------------------------------
    # Requisito 1: Serialização canônica e hash determinístico
    # -------------------------------------------------------------------------
    def test_01_serializacao_canonica_e_hash_deterministico(self) -> None:
        """Dicionários equivalentes com chaves em ordens distintas devem gerar o mesmo JSON e hash."""
        d1 = {
            "tipo": "certificado",
            "participante": "aluno-017",
            "descricao": "Curso de Introducao a Criptografia — 60h",
        }
        d2 = {
            "descricao": "Curso de Introducao a Criptografia — 60h",
            "tipo": "certificado",
            "participante": "aluno-017",
        }
        s1 = serializar_canonico(d1)
        s2 = serializar_canonico(d2)

        self.assertEqual(s1, s2)
        self.assertNotIn(": ", s1)
        self.assertNotIn(", ", s1)
        self.assertIn("—", s1)  # ensure_ascii=False preserva Unicode

        b1 = Bloco(
            indice=1,
            timestamp=1700000000,
            registros=[d1],
            hash_anterior=HASH_ANTERIOR_GENESE,
            dificuldade=1,
            nonce=7,
        )
        b2 = Bloco(
            indice=1,
            timestamp=1700000000,
            registros=[d2],
            hash_anterior=HASH_ANTERIOR_GENESE,
            dificuldade=1,
            nonce=7,
        )
        self.assertEqual(b1.calcular_hash(), b2.calcular_hash())
        self.assertEqual(len(b1.calcular_hash()), 64)
        self.assertNotIn("hash", b1.conteudo_para_hash())

    def test_01b_serializacao_rejeita_nan_e_infinito(self) -> None:
        """A serialização canônica deve rejeitar valores especiais NaN e Infinito (allow_nan=False)."""
        for valor_invalido in (math.nan, math.inf, -math.inf):
            with self.subTest(valor=valor_invalido):
                with self.assertRaises(ValueError):
                    serializar_canonico({"valor": valor_invalido})

    # -------------------------------------------------------------------------
    # Requisito 2: Hash diferente após alteração de dado relevante
    # -------------------------------------------------------------------------
    def test_02_hash_muda_apos_alteracao_de_qualquer_campo_relevante(self) -> None:
        """Alterar um único caractere ou qualquer metadado do bloco deve alterar o SHA-256."""
        reg_base = criar_registro("disciplina", "aluno-017", "Nota final: 9.5")
        bloco_base = Bloco(
            indice=1,
            timestamp=1700000100,
            registros=[reg_base],
            hash_anterior="a" * 64,
            dificuldade=1,
            nonce=0,
        )
        hash_original = bloco_base.calcular_hash()

        variacoes = [
            ("indice", Bloco(2, 1700000100, [reg_base], "a" * 64, 1, 0)),
            ("timestamp", Bloco(1, 1700000101, [reg_base], "a" * 64, 1, 0)),
            (
                "registro_1_char",
                Bloco(
                    1,
                    1700000100,
                    [criar_registro("disciplina", "aluno-017", "Nota final: 9.6")],
                    "a" * 64,
                    1,
                    0,
                ),
            ),
            ("hash_anterior", Bloco(1, 1700000100, [reg_base], "b" * 64, 1, 0)),
            ("dificuldade", Bloco(1, 1700000100, [reg_base], "a" * 64, 2, 0)),
            ("nonce", Bloco(1, 1700000100, [reg_base], "a" * 64, 1, 1)),
        ]

        for nome_campo, bloco_modificado in variacoes:
            with self.subTest(campo=nome_campo):
                self.assertNotEqual(hash_original, bloco_modificado.calcular_hash())

    # -------------------------------------------------------------------------
    # Requisito 3: Rejeição de registro com campo vazio ou tipo incorreto
    # -------------------------------------------------------------------------
    def test_03_criar_registro_normaliza_e_rejeita_invalidos(self) -> None:
        """criar_registro deve remover espaços externos e rejeitar strings vazias ou tipos não-str."""
        reg = criar_registro("  certificado  ", " aluno-017 ", "  Conclusao com exito  ")
        self.assertEqual(
            reg,
            {
                "tipo": "certificado",
                "participante": "aluno-017",
                "descricao": "Conclusao com exito",
            },
        )

        # Campos vazios ou apenas espaços
        casos_vazios = [
            ("", "aluno-017", "Descricao valida"),
            ("   ", "aluno-017", "Descricao valida"),
            ("certificado", "", "Descricao valida"),
            ("certificado", "   \t\n ", "Descricao valida"),
            ("certificado", "aluno-017", ""),
            ("certificado", "aluno-017", "    "),
        ]
        for tipo, part, desc in casos_vazios:
            with self.subTest(tipo=tipo, participante=part, descricao=desc):
                with self.assertRaises(ValueError):
                    criar_registro(tipo, part, desc)

        # Tipos incorretos
        casos_tipo_incorreto = [
            (None, "aluno-017", "Descricao"),
            (123, "aluno-017", "Descricao"),
            ("certificado", 17, "Descricao"),
            ("certificado", ["aluno-017"], "Descricao"),
            ("certificado", "aluno-017", {"texto": "Descricao"}),
        ]
        for tipo, part, desc in casos_tipo_incorreto:
            with self.subTest(tipo=tipo, participante=part, descricao=desc):
                with self.assertRaises((TypeError, ValueError)):
                    criar_registro(tipo, part, desc)  # type: ignore[arg-type]

    # -------------------------------------------------------------------------
    # Requisito 4: Criação válida do bloco gênese
    # -------------------------------------------------------------------------
    def test_04_criacao_valida_do_bloco_genese(self) -> None:
        """O bloco gênese deve ter índice 0, timestamp 0, REGISTRO_GENESE, 64 zeros e hash minerado."""
        bc = Blockchain(dificuldade=1)
        self.assertEqual(len(bc.blocos), 1)
        genese = bc.blocos[0]

        self.assertEqual(genese.indice, 0)
        self.assertEqual(genese.timestamp, 0)
        self.assertEqual(genese.hash_anterior, "0" * 64)
        self.assertEqual(genese.registros, [REGISTRO_GENESE])
        self.assertEqual(genese.dificuldade, 1)
        self.assertTrue(genese.hash.startswith("0"))
        self.assertEqual(genese.hash, genese.calcular_hash())
        self.assertIs(bc.ultimo_bloco, genese)

    # -------------------------------------------------------------------------
    # Requisito 5: Mineração satisfazendo a dificuldade
    # -------------------------------------------------------------------------
    def test_05_mineracao_satisfaz_dificuldade(self) -> None:
        """Bloco.minerar deve ajustar o nonce até que o hash comece com '0' * dificuldade."""
        for dificuldade in (1, 2):
            with self.subTest(dificuldade=dificuldade):
                bloco = Bloco(
                    indice=1,
                    timestamp=1700000500,
                    registros=[criar_registro("exame", "aluno-019", "Aprovado no exame final")],
                    hash_anterior="0" * 64,
                    dificuldade=dificuldade,
                )
                hash_minerado = bloco.minerar()
                self.assertEqual(hash_minerado, bloco.hash)
                self.assertEqual(bloco.hash, bloco.calcular_hash())
                self.assertTrue(bloco.hash.startswith("0" * dificuldade))
                self.assertGreaterEqual(bloco.nonce, 0)

    # -------------------------------------------------------------------------
    # Requisito 6 e 7: Inclusão de pelo menos 3 blocos e cadeia íntegra aceita
    # -------------------------------------------------------------------------
    def test_06_e_07_inclusao_de_tres_blocos_e_validacao_integra(self) -> None:
        """Uma cadeia com gênese e três blocos adicionados deve ter elos corretos e ser válida."""
        bc = Blockchain(dificuldade=1)
        b1 = bc.adicionar_bloco(
            [criar_registro("matricula", "aluno-001", "Matricula em Criptografia")],
            timestamp=1700000100,
        )
        b2 = bc.adicionar_bloco(
            [criar_registro("projeto", "aluno-001", "Entrega do projeto bonus")],
            timestamp=1700000200,
        )
        b3 = bc.adicionar_bloco(
            [criar_registro("certificado", "aluno-001", "Conclusao com nota maxima")],
            timestamp=1700000300,
        )

        self.assertEqual(len(bc.blocos), 4)
        self.assertEqual([b.indice for b in bc.blocos], [0, 1, 2, 3])
        self.assertEqual(b1.hash_anterior, bc.blocos[0].hash)
        self.assertEqual(b2.hash_anterior, b1.hash)
        self.assertEqual(b3.hash_anterior, b2.hash)
        self.assertIs(bc.ultimo_bloco, b3)
        self.assertTrue(bc.validar())

    # -------------------------------------------------------------------------
    # Requisito 8: Registro adulterado rejeitado (sem reparo silencioso)
    # -------------------------------------------------------------------------
    def test_08_registro_adulterado_rejeitado_e_impede_novos_blocos(self) -> None:
        """Modificar qualquer registro após a mineração deve invalidar a cadeia sem consertá-la."""
        bc = Blockchain(dificuldade=1)
        bc.adicionar_bloco(
            [criar_registro("nota", "aluno-017", "Conceito B")],
            timestamp=1700000100,
        )
        bc.adicionar_bloco(
            [criar_registro("certificado", "aluno-017", "Certificado emitido")],
            timestamp=1700000200,
        )

        # Adulteração direta no bloco 1
        bc.blocos[1].registros[0]["descricao"] = "Conceito A+"
        self.assertFalse(bc.validar())
        # Verificar que validar() não reparou silenciosamente a cadeia
        self.assertEqual(bc.blocos[1].registros[0]["descricao"], "Conceito A+")
        self.assertFalse(bc.validar())

        # Não deve permitir incluir novo bloco em cadeia já inválida
        with self.assertRaises(ValueError):
            bc.adicionar_bloco(
                [criar_registro("historico", "aluno-017", "Tentativa em cadeia invalida")],
                timestamp=1700000300,
            )

    # -------------------------------------------------------------------------
    # Requisito 9: Hash anterior adulterado rejeitado
    # -------------------------------------------------------------------------
    def test_09_hash_anterior_adulterado_ou_elo_quebrado_rejeitado(self) -> None:
        """Quebrar o hash_anterior ou reminerar apenas um bloco intermediário deve invalidar a cadeia."""
        bc = Blockchain(dificuldade=1)
        bc.adicionar_bloco(
            [criar_registro("nota", "aluno-017", "Conceito B")],
            timestamp=1700000100,
        )
        bc.adicionar_bloco(
            [criar_registro("certificado", "aluno-017", "Certificado emitido")],
            timestamp=1700000200,
        )

        # Caso A: Adulterar registro do bloco 1 e reminerar SOMENTE o bloco 1
        bc.blocos[1].registros[0]["descricao"] = "Conceito A"
        bc.blocos[1].minerar()
        # O bloco 1 agora tem hash e PoW válidos isoladamente, mas o bloco 2 aponta para o hash antigo
        self.assertFalse(bc.validar())

        # Caso B: Corromper diretamente o hash_anterior do gênese
        bc_gen = Blockchain(dificuldade=1)
        bc_gen.blocos[0].hash_anterior = "f" * 64
        bc_gen.blocos[0].minerar()
        self.assertFalse(bc_gen.validar())

    # -------------------------------------------------------------------------
    # Requisito 10: Nonce adulterado ou prova de trabalho inválida rejeitada
    # -------------------------------------------------------------------------
    def test_10_nonce_adulterado_ou_pow_invalida_rejeitada(self) -> None:
        """Alterar o nonce ou forjar um hash sem o prefixo de zeros exigido deve ser rejeitado."""
        bc = Blockchain(dificuldade=2)
        bc.adicionar_bloco(
            [criar_registro("disciplina", "aluno-025", "Aprovado")],
            timestamp=1700000100,
        )
        self.assertTrue(bc.validar())

        # Subteste A: Alterar o nonce sem atualizar o hash
        nonce_original = bc.blocos[1].nonce
        bc.blocos[1].nonce = nonce_original + 1
        self.assertFalse(bc.validar())

        # Subteste B: Encontrar um nonce cujo hash NÃO comece com "00", mas atualizar bloco.hash
        nonce_sem_pow = 0
        while True:
            bc.blocos[1].nonce = nonce_sem_pow
            candidato = bc.blocos[1].calcular_hash()
            if not candidato.startswith("00"):
                bc.blocos[1].hash = candidato
                break
            nonce_sem_pow += 1

        # Embora bloco.hash == bloco.calcular_hash(), a PoW não satisfaz dificuldade=2
        self.assertEqual(bc.blocos[1].hash, bc.blocos[1].calcular_hash())
        self.assertFalse(bc.validar())

    # -------------------------------------------------------------------------
    # Requisito 11: Dificuldade fora do intervalo de 1 a 6 rejeitada
    # -------------------------------------------------------------------------
    def test_11_dificuldade_fora_do_intervalo_rejeitada(self) -> None:
        """Dificuldades menores que 1, maiores que 6 ou não inteiras devem ser rejeitadas."""
        for dif_invalida in (0, -1, 7, 10, 1.5, "2", None, True, False):
            with self.subTest(dificuldade=dif_invalida):
                with self.assertRaises((ValueError, TypeError)):
                    Blockchain(dificuldade=dif_invalida)  # type: ignore[arg-type]

                with self.assertRaises((ValueError, TypeError)):
                    Bloco(
                        indice=0,
                        timestamp=0,
                        registros=[REGISTRO_GENESE],
                        hash_anterior=HASH_ANTERIOR_GENESE,
                        dificuldade=dif_invalida,  # type: ignore[arg-type]
                    )

        # Adulteração de dificuldade diretamente em um bloco de uma cadeia existente
        bc = Blockchain(dificuldade=1)
        bc.adicionar_bloco([criar_registro("evento", "aluno-001", "Teste")], timestamp=100)
        bc.blocos[1].dificuldade = 2
        bc.blocos[1].minerar()
        self.assertFalse(bc.validar())

    # -------------------------------------------------------------------------
    # Requisito 12: Entradas do chamador copiadas, sem mutação inesperada
    # -------------------------------------------------------------------------
    def test_12_copia_profunda_protege_contra_mutacao_externa(self) -> None:
        """Modificar a lista ou o dicionário externo após adicionar_bloco não pode afetar o bloco."""
        registro_externo = criar_registro("matricula", "aluno-099", "Registro original integro")
        lista_externa = [registro_externo]

        bc = Blockchain(dificuldade=1)
        bloco = bc.adicionar_bloco(lista_externa, timestamp=1700000900)
        hash_antes = bloco.hash

        # Tentar mutar o dicionário e a lista do chamador após a inclusão do bloco
        registro_externo["descricao"] = "Tentativa de mutacao silenciosa via referencia"
        lista_externa.append(criar_registro("extra", "aluno-099", "Registro intruso"))

        self.assertEqual(len(bloco.registros), 1)
        self.assertEqual(bloco.registros[0]["descricao"], "Registro original integro")
        self.assertEqual(bloco.calcular_hash(), hash_antes)
        self.assertTrue(bc.validar())

    # -------------------------------------------------------------------------
    # Teste Extra: Ataque controlado e fluxo completo do demo.py
    # -------------------------------------------------------------------------
    def test_13_fluxo_completo_ataque_controlado_e_reconstrucao(self) -> None:
        """Verifica se o roteiro completo de ataque controlado da Etapa 7 funciona conforme esperado."""
        resultado = executar_demonstracao_completa(dificuldade_demo=1, silencioso=True)

        self.assertTrue(resultado["serializacao"]["serializacao_deterministica"])
        self.assertNotEqual(
            resultado["serializacao"]["hash_original"],
            resultado["serializacao"]["hash_alterado"],
        )
        self.assertTrue(resultado["valida_original"])
        self.assertFalse(resultado["valida_apos_adulteracao"])
        self.assertFalse(resultado["valida_apos_reminerar_um"])
        self.assertTrue(resultado["valida_apos_reconstrucao_total"])
        self.assertNotEqual(
            resultado["ancora_externa"],
            resultado["hash_final_reconstruido"],
        )


class TestExtensoesOpcionais(unittest.TestCase):
    """Testes automatizados para as 6 extensões opcionais da Seção 9."""

    def test_14_arvore_de_merkle_e_prova_de_inclusao(self) -> None:
        """A prova de inclusão de Merkle deve validar registros presentes e rejeitar adulterados."""
        from extensoes import (
            calcular_raiz_merkle,
            gerar_prova_merkle,
            verificar_prova_merkle,
        )

        registros = [
            criar_registro("matricula", "aluno-001", "Ingresso 2026"),
            criar_registro("disciplina", "aluno-002", "Criptografia A"),
            criar_registro("certificado", "aluno-003", "Monitoria 40h"),
            criar_registro("defesa", "aluno-004", "TCC Aprovado"),
            criar_registro("premio", "aluno-005", "Destaque Academico"),
        ]
        raiz = calcular_raiz_merkle(registros)
        self.assertEqual(len(raiz), 64)

        for idx, reg in enumerate(registros):
            with self.subTest(indice=idx):
                prova = gerar_prova_merkle(registros, idx)
                self.assertTrue(verificar_prova_merkle(reg, prova, raiz))
                reg_falso = criar_registro(reg["tipo"], reg["participante"], "Texto Adulterado")
                self.assertFalse(verificar_prova_merkle(reg_falso, prova, raiz))

    def test_15_assinatura_ed25519_dos_registros(self) -> None:
        """Assinaturas Ed25519 devem autenticar o registro e falhar se o dado ou a chave mudarem."""
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("Pacote 'cryptography' não instalado neste ambiente Python.")

        from extensoes import IdentidadeFicticiaEd25519, verificar_assinatura_registro

        secretaria = IdentidadeFicticiaEd25519.gerar("secretaria-academica-01")
        outro_emissor = IdentidadeFicticiaEd25519.gerar("secretaria-intrusa-99")

        reg = criar_registro("diploma", "aluno-017", "Bacharelado concluido")
        pacote = secretaria.assinar_registro(reg)

        self.assertTrue(verificar_assinatura_registro(pacote))
        self.assertTrue(
            verificar_assinatura_registro(pacote, secretaria.chave_publica_hex)
        )
        # Rejeitar quando verificado contra outra chave pública
        self.assertFalse(
            verificar_assinatura_registro(pacote, outro_emissor.chave_publica_hex)
        )
        # Rejeitar quando o conteúdo do registro assinado é adulterado
        pacote["registro"]["descricao"] = "Doutorado concluido (forjado)"
        self.assertFalse(verificar_assinatura_registro(pacote))

    def test_16_persistencia_e_recarga_json(self) -> None:
        """Salvar e recarregar a cadeia em JSON deve preservar todos os blocos e detectar corrupção."""
        import tempfile
        from pathlib import Path
        from extensoes import carregar_cadeia_json, salvar_cadeia_json

        bc = Blockchain(dificuldade=1)
        bc.adicionar_bloco(
            [criar_registro("certificado", "aluno-017", "Persistido em JSON")],
            timestamp=1700000123,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            caminho = Path(tmpdir) / "cadeia_teste.json"
            salvar_cadeia_json(bc, caminho)
            recarregada = carregar_cadeia_json(caminho)

            self.assertTrue(recarregada.validar())
            self.assertEqual(len(recarregada.blocos), 2)
            self.assertEqual(recarregada.ultimo_bloco.hash, bc.ultimo_bloco.hash)

    def test_17_simulacao_dois_nos_e_escolha_de_cadeia(self) -> None:
        """Um nó simulado deve adotar uma cadeia íntegra com maior trabalho acumulado e rejeitar inválida."""
        from extensoes import NoSimulado

        no_a = NoSimulado("no-secretaria", Blockchain(dificuldade=1))
        no_b = NoSimulado("no-auditoria", Blockchain(dificuldade=1))
        no_b.clonar_cadeia_de(no_a)

        # Nó A minera 2 blocos novos
        no_a.cadeia.adicionar_bloco(
            [criar_registro("nota", "aluno-017", "Bloco 1 no A")],
            timestamp=1700000100,
        )
        no_a.cadeia.adicionar_bloco(
            [criar_registro("nota", "aluno-017", "Bloco 2 no A")],
            timestamp=1700000200,
        )

        adotou, _ = no_b.sincronizar_com(no_a.cadeia)
        self.assertTrue(adotou)
        self.assertEqual(len(no_b.cadeia.blocos), 3)

        # Se a cadeia candidata estiver adulterada, o nó deve rejeitá-la
        no_a.cadeia.blocos[1].registros[0]["descricao"] = "Fraude sem PoW"
        adotou_invalida, _ = no_b.sincronizar_com(no_a.cadeia)
        self.assertFalse(adotou_invalida)
        self.assertTrue(no_b.cadeia.validar())

    def test_18_medicao_estatistica_e_cli(self) -> None:
        """A medição de tentativas e os comandos da CLI devem funcionar de ponta a ponta."""
        import tempfile
        from pathlib import Path
        from cli import executar_cli
        from extensoes import medir_media_tentativas

        stats = medir_media_tentativas((1, 2), amostras_por_dificuldade=2)
        self.assertEqual(len(stats), 2)
        self.assertEqual(stats[0]["dificuldade"], 1)
        self.assertGreaterEqual(stats[0]["media_tentativas_empirica"], 1.0)

        with tempfile.TemporaryDirectory() as tmpdir:
            arq = str(Path(tmpdir) / "cli_chain.json")
            self.assertEqual(executar_cli(["--arquivo", arq, "init", "--dificuldade", "1"]), 0)
            self.assertEqual(
                executar_cli(
                    [
                        "--arquivo",
                        arq,
                        "inserir",
                        "--tipo",
                        "certificado",
                        "--participante",
                        "aluno-017",
                        "--descricao",
                        "Emitido via CLI",
                    ]
                ),
                0,
            )
            self.assertEqual(executar_cli(["--arquivo", arq, "validar"]), 0)
            self.assertEqual(
                executar_cli(["--arquivo", arq, "consultar", "--participante", "aluno-017"]),
                0,
            )
            self.assertEqual(executar_cli(["--arquivo", arq, "listar"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
