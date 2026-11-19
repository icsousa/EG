"""Testes do CFG (Parte II, tarefa 1). Correr com: pytest -q"""
from collections import Counter
from pathlib import Path

import networkx as nx
import pytest

from cfg import blocos_basicos, construir_cfg, sem_servico, para_dot

EXEMPLOS = sorted(Path("exemplos").glob("*.snt"))
AVISOS = sorted(Path("testes").glob("W*.snt"))          # válidos, só com avisos


def cfg_de(f):
    return construir_cfg(f.read_text(encoding="utf-8"))


def com_alerta(corpo, estado=""):
    return f"alert a {{ x: int; }}\nplaybook p {{\n{estado}\non a as e {{\n{corpo}\n}}\n}}"


def rotulos(g, n):
    return sorted(r for _, _, r in g.out_edges(n, data="rotulo"))


# --- propriedades gerais, em todos os playbooks válidos

@pytest.mark.parametrize("f", EXEMPLOS + AVISOS, ids=lambda p: p.stem)
@pytest.mark.parametrize("nivel", ["instrucoes", "blocos"])
def test_estrutura(f, nivel):
    g = cfg_de(f)
    if nivel == "blocos":
        g = blocos_basicos(g)
    inicio, despacho = g.graph["inicio"], g.graph["despacho"]
    # tudo é alcançável a partir da ativação
    assert nx.descendants(g, inicio) | {inicio} == set(g.nodes)
    # cada handler: entrada → saída sem passar pelo despacho, e a saída volta ao despacho
    intra = sem_servico(g)
    for entrada, saida in g.graph["handlers"].values():
        assert saida in nx.descendants(intra, entrada)
        assert list(g.successors(saida)) == [despacho]
    # decisões e ciclos têm exatamente dois sucessores, com os rótulos certos
    for n, tipo in g.nodes(data="tipo"):
        if tipo == "cond":
            assert rotulos(g, n) == ["falso", "verdadeiro"]
        if tipo == "ciclo":
            assert rotulos(g, n) == ["iterar", "sair"]
    para_dot(g)                                         # o desenho não falha


@pytest.mark.parametrize("f", EXEMPLOS + AVISOS, ids=lambda p: p.stem)
def test_blocos_basicos_preservam_instrucoes(f):
    g = cfg_de(f)
    bb = blocos_basicos(g)
    linhas = lambda h: Counter((i.linha, i.texto) for _, d in h.nodes(data=True) for i in d["instrs"])
    assert linhas(g) == linhas(bb)
    for _, d in bb.nodes(data=True):                    # num bloco, as instruções estão por ordem
        ls = [i.linha for i in d["instrs"]]
        assert ls == sorted(ls)
    assert bb.number_of_nodes() <= g.number_of_nodes()


# --- casos concretos

def test_if_else_port_scan():
    g = blocos_basicos(cfg_de(Path("exemplos/01_port_scan.snt")))
    (cond,) = [n for n, t in g.nodes(data="tipo") if t == "cond"]
    ramos = {r: v for _, v, r in g.out_edges(cond, data="rotulo")}
    textos = lambda n: [i.texto for i in g.nodes[n]["instrs"]]
    assert textos(ramos["verdadeiro"])[0].startswith("block_ip")
    assert textos(ramos["falso"])[0].startswith("log")
    # os dois ramos juntam-se no fim do handler
    assert set(g.successors(ramos["verdadeiro"])) == set(g.successors(ramos["falso"]))


def test_for_cria_ciclo_dentro_do_handler():
    g = sem_servico(cfg_de(Path("exemplos/03_syn_flood.snt")))
    ciclos = list(nx.simple_cycles(g))
    assert ciclos and all(any(g.nodes[n]["tipo"] == "ciclo" for n in c) for c in ciclos)


def test_sem_for_nao_ha_ciclos_dentro_dos_handlers():
    g = sem_servico(cfg_de(Path("exemplos/01_port_scan.snt")))
    assert nx.is_directed_acyclic_graph(g)


def test_despacho_tem_um_evento_por_handler():
    g = cfg_de(Path("exemplos/04_arp_spoofing.snt"))
    eventos = rotulos(g, g.graph["despacho"])
    assert eventos == ["every 1h", "on arp_spoof"]


def test_if_vazio_tem_duas_arestas_paralelas():
    g = construir_cfg(com_alerta("if (e.x > 1) { } log(\"ok\");"))
    (cond,) = [n for n, t in g.nodes(data="tipo") if t == "cond"]
    destinos = [v for _, v in g.out_edges(cond)]
    assert len(destinos) == 2 and len(set(destinos)) == 1


def test_defs_e_uses():
    g = cfg_de(Path("exemplos/02_brute_force_ssh.snt"))
    instrs = {i.linha: i for _, d in g.nodes(data=True) for i in d["instrs"]}
    assert instrs[11].defs == {"a"}                                   # alias do alerta
    assert instrs[12].defs == {"tentativas"} and instrs[12].uses == {"a"}
    assert instrs[13].uses == {"tentativas", "limite", "a", "rede_interna"}


def test_playbook_invalido_nao_tem_cfg():
    with pytest.raises(ValueError):
        construir_cfg(Path("testes/E101_nao_declarada.snt").read_text(encoding="utf-8"))
