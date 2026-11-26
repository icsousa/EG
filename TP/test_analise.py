"""Testes da análise estática (Parte II, tarefa 2). Correr com: pytest -q

testes_analise/: um programa por achado, com '# expect: CÓDIGO' em cada linha
onde a análise tem de o assinalar (e em nenhuma outra)."""
import re
from math import inf
from pathlib import Path

import pytest

from analise import (DefinicoesQueChegam, Intervalos, ValidacaoDeAlvos, VALIDADO,
                     NAO_VALIDADO, analisar_playbook, resolver)
from cfg import construir_cfg

CASOS = sorted(Path("testes_analise").glob("*.snt"))
EXEMPLOS = sorted(Path("exemplos").glob("*.snt"))
AVISOS = sorted(Path("testes").glob("W*.snt"))
EXPECT = re.compile(r"expect:\s*([A-Z]\d+)")


def achados(f):
    r = analisar_playbook(f.read_text(encoding="utf-8"))
    return sorted((a.codigo, a.linha) for a in r.achados)


def no_da_linha(g, linha, tipo=None):
    return next(n for n, d in g.nodes(data=True)
                for i in d["instrs"] if i.linha == linha and (tipo is None or i.tipo == tipo))


@pytest.mark.parametrize("f", CASOS, ids=lambda p: p.stem)
def test_casos(f):
    esperado = sorted((m.group(1), n) for n, l in enumerate(f.read_text().splitlines(), 1)
                      for m in EXPECT.finditer(l))
    assert achados(f) == esperado


def test_exemplos():
    # o caso 01 bloqueia s.src_ip, mas a condição só testa a porta
    assert {f.stem: achados(f) for f in EXEMPLOS} == {
        "01_port_scan": [("V01", 12)], "02_brute_force_ssh": [],
        "03_syn_flood": [], "04_arp_spoofing": []}


@pytest.mark.parametrize("f", EXEMPLOS + AVISOS + CASOS, ids=lambda p: p.stem)
def test_termina_e_tudo_alcancavel_tem_estado(f):
    g = construir_cfg(f.read_text(encoding="utf-8"))
    for analise in (DefinicoesQueChegam(), Intervalos(), ValidacaoDeAlvos()):
        entrada, _ = resolver(g, analise)
        assert entrada[g.graph["despacho"]] is not None


# --- definições que chegam / DFG

def test_dfg_estado_persistente():
    r = analisar_playbook(Path("exemplos/04_arp_spoofing.snt").read_text())
    g, dfg = r.g, r.dfg
    soma, reset, teste = no_da_linha(g, 24), no_da_linha(g, 34), no_da_linha(g, 32)
    # o "if (incidentes > 0)" do every lê o valor escrito no on (execução anterior)
    origens = {(u, d["origem"]) for u, _, d in dfg.in_edges(teste, data=True)}
    assert (soma, "anterior") in origens and (reset, "anterior") in origens
    # incidentes = incidentes + 1 lê o seu próprio valor da execução anterior
    assert any(u == soma and d["origem"] == "anterior" for u, _, d in dfg.in_edges(soma, data=True))


def test_dfg_shadowing_nao_mistura_variaveis():
    r = analisar_playbook(Path("testes/W03_shadowing.snt").read_text())
    g, dfg = r.g, r.dfg
    interior, exterior = no_da_linha(r.g, 11), no_da_linha(r.g, 8)
    assert {u for u, _, d in dfg.in_edges(no_da_linha(g, 12), data=True)
            if d["var"].startswith("limite")} == {interior}
    assert {u for u, _, d in dfg.in_edges(no_da_linha(g, 14), data=True)
            if d["var"].startswith("limite")} == {exterior}


# --- intervalos

def test_intervalos_contador_com_limiares():
    texto = Path("testes_analise/I02_nivel_impossivel.snt").read_text()
    g = construir_cfg(texto)
    entrada, _ = resolver(g, Intervalos())
    assert entrada[g.graph["despacho"]]["nivel"] == (0, 3)


def test_intervalos_ciclo_alarga():
    g = construir_cfg(Path("exemplos/03_syn_flood.snt").read_text())
    entrada, _ = resolver(g, Intervalos())
    assert entrada[no_da_linha(g, 21)]["mitigados"] == (0, inf)


def test_intervalos_refina_ramos():
    g = construir_cfg(Path("exemplos/04_arp_spoofing.snt").read_text())
    entrada, _ = resolver(g, Intervalos())
    assert entrada[no_da_linha(g, 33)]["incidentes"] == (1, inf)   # dentro de if (incidentes > 0)


# --- validação de alvos

def test_validacao_por_ramo():
    g = construir_cfg(Path("exemplos/02_brute_force_ssh.snt").read_text())
    entrada, _ = resolver(g, ValidacaoDeAlvos())
    assert entrada[no_da_linha(g, 14)]["a.src_ip"] == VALIDADO
    assert ValidacaoDeAlvos.nivel(entrada[no_da_linha(g, 13)], "a.src_ip") == NAO_VALIDADO


def test_validacao_alias_novo_em_cada_alerta():
    # o que foi validado num alerta não vale para o alerta seguinte
    g = construir_cfg(Path("exemplos/02_brute_force_ssh.snt").read_text())
    entrada, _ = resolver(g, ValidacaoDeAlvos())
    assert "a.src_ip" not in entrada[g.graph["despacho"]]


def test_comparar_dois_campos_nao_valida():
    texto = """alert a { x: ip; y: ip; }
playbook p {
  on a as e {
    if (e.x == e.y) {
      block_ip(e.x, 1h);
    }
  }
}"""
    assert [(a.codigo, a.linha) for a in analisar_playbook(texto).achados] == [("V01", 5)]
