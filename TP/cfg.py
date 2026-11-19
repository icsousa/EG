"""
Sentinela: grafo de fluxo de controlo (CFG).  Parte II, tarefa 1.

Constrói o CFG de um playbook *válido* a partir da árvore sintática do Lark
(a mesma que a gramática de atributos validou) e desenha-o com o Graphviz.

Modelo (explicado em IR.md):

  inicio ──► declarações do estado ──► despacho ──on X──► entrada ─► … ─► saída ─┐
                                          ▲  └──every T──► entrada ─► … ─► saída ─┤
                                          └──────────────────────────────────────┘

  - o playbook é um serviço: corre as declarações do estado uma vez (ativação) e
    depois fica no nó "despacho" à espera de eventos;
  - cada handler (`on`, `every`) é um sub-grafo com uma entrada e uma saída;
    a saída volta ao despacho (arestas "de serviço", a tracejado);
  - `if` é um nó de decisão com arestas "verdadeiro"/"falso";
  - `for` é um nó de ciclo com arestas "iterar"/"sair" e uma aresta de volta
    do fim do corpo;
  - as instruções simples (declarações, atribuições, ações) são agrupadas em
    blocos básicos.

Cada instrução guarda o texto, a linha, as variáveis que define (defs) e as
que lê (uses), para as análises das tarefas seguintes.

Uso:
  python cfg.py exemplos/*.snt                  escreve cfg/<nome>.dot e .svg
  python cfg.py --instrucoes exemplos/01.snt    uma instrução por nó (sem blocos básicos)
  python cfg.py --texto exemplos/01.snt         lista os blocos no terminal
  python cfg.py -o pasta exemplos/01.snt        pasta de saída (por omissão: cfg/)
"""
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx
from lark import Token, Tree

from sentinela import analisar, parse

# Ações marcadas como destrutivas na biblioteca (sentinela.ag, P30).
DESTRUTIVAS = {"block_ip", "quarantine"}


@dataclass
class Instrucao:
    """Uma instrução do playbook, como aparece num nó do CFG."""
    tipo: str                 # var | secret | atrib | acao | if | for | entrada
    texto: str
    linha: int
    defs: set[str] = field(default_factory=set)
    uses: set[str] = field(default_factory=set)
    acao: str | None = None   # nome da ação ou função chamada (tipo "acao")

    @property
    def destrutiva(self):
        return self.acao in DESTRUTIVAS


# ---------------------------------------------------------------------------
#  Navegação na árvore do LarkAG
#  O LarkAG numera as alternativas de cada não-terminal: stmt_0 é a 1.ª
#  alternativa de stmt (vardecl), stmt_4 é o for, etc. (ordem de sentinela.ag)
# ---------------------------------------------------------------------------

def _regra(arvore):
    nome, _, alt = str(arvore.data).rpartition("_")
    return nome, int(alt)


def _filhos(arvore):
    return [c for c in arvore.children if isinstance(c, Tree)]


def _tokens(arvore):
    return [c for c in arvore.children if isinstance(c, Token)]


def _lista(arvore, nome):
    """Achata uma lista recursiva à esquerda (stmts, statedecls, handlers)."""
    itens = []
    while True:
        filhos = _filhos(arvore)
        if filhos and _regra(filhos[0])[0] == nome:
            itens.append(filhos[-1])
            arvore = filhos[0]
        else:
            itens.extend(filhos)          # caso base: vazio ou um só elemento
            return itens[::-1]


def _usos(arvore):
    """Variáveis lidas numa expressão: os NAME de `primary → NAME` (P47).
    Em `a.src_ip` lê-se a variável `a`; o nome do campo não conta."""
    return {str(_tokens(t)[0]) for t in arvore.iter_subtrees()
            if _regra(t) == ("primary", 0)}


# ---------------------------------------------------------------------------
#  Construção do CFG (uma instrução por nó)
# ---------------------------------------------------------------------------

class ConstrutorCFG:
    """Percorre a árvore e constrói o CFG ao nível das instruções.

    Cada método recebe as arestas `pendentes` (origem, rótulo) que ainda não
    têm destino e devolve as que ficam pendentes depois da construção, à
    espera da instrução seguinte. Assim não são precisos nós de junção."""

    def __init__(self, texto):
        self.texto = texto
        self.g = nx.MultiDiGraph()
        self.contador = 0
        self.handler = None               # handler a que pertencem os nós novos

    # -- utilitários
    def _fonte(self, arvore):
        trecho = self.texto[arvore.meta.start_pos:arvore.meta.end_pos]
        return re.sub(r"\s+", " ", trecho).strip()

    def _no(self, tipo, instrucao=None, rotulo=""):
        nid = f"n{self.contador}"
        self.contador += 1
        self.g.add_node(nid, tipo=tipo, rotulo=rotulo, handler=self.handler,
                        instrs=[instrucao] if instrucao else [])
        return nid

    def _ligar(self, pendentes, destino):
        for origem, rotulo in pendentes:
            self.g.add_edge(origem, destino, rotulo=rotulo, servico=False)

    def _simples(self, instrucao, pendentes):
        n = self._no("instr", instrucao)
        self._ligar(pendentes, n)
        return [(n, "")]

    # -- programa
    def programa(self, arvore):
        playbook = _filhos(arvore)[1]                       # P1: start → alerts playbook
        nome = str(_tokens(playbook)[0])
        statedecls, handlers = _filhos(playbook)

        inicio = self._no("inicio", rotulo=f"ativação de {nome}")
        pendentes = [(inicio, "")]
        for decl in _lista(statedecls, "statedecls"):
            pendentes = self._simples(self.declaracao(decl), pendentes)

        despacho = self._no("despacho", rotulo="aguardar evento")
        self._ligar(pendentes, despacho)
        self.g.graph.update(playbook=nome, inicio=inicio, despacho=despacho, handlers={})

        for h in _lista(handlers, "handlers"):
            self.handler_(h, despacho)
        self.handler = None
        return self.g

    def handler_(self, arvore, despacho):
        _, alt = _regra(arvore)
        if alt == 0:                                        # P15: on X as a { … }
            alerta, alias, bloco = _filhos(arvore)
            alerta, alias = str(_tokens(alerta)[0]), str(_tokens(alias)[0])
            evento = f"on {alerta}"
            instr = Instrucao("entrada", f"on {alerta} as {alias}",
                              arvore.meta.line, defs={alias})
        else:                                               # P16: every T { … }
            duracao, bloco = str(_tokens(arvore)[0]), _filhos(arvore)[0]
            evento = f"every {duracao}"
            instr = Instrucao("entrada", evento, arvore.meta.line)

        self.handler = evento
        entrada = self._no("entrada", instr, rotulo=instr.texto)
        self.g.add_edge(despacho, entrada, rotulo=evento, servico=True)
        pendentes = self.bloco(bloco, [(entrada, "")])
        saida = self._no("saida", rotulo="fim")
        self._ligar(pendentes, saida)
        self.g.add_edge(saida, despacho, rotulo="", servico=True)
        self.g.graph["handlers"][evento] = (entrada, saida)

    # -- instruções
    def bloco(self, arvore, pendentes):                     # P18: block → { stmts }
        for stmt in _lista(_filhos(arvore)[0], "stmts"):
            pendentes = self.instrucao(stmt, pendentes)
        return pendentes

    def declaracao(self, arvore):                           # P21/P22: var / secret
        nome = str(_tokens(arvore)[0])
        expr = _filhos(arvore)[1]
        tipo = "var" if _regra(arvore)[1] == 0 else "secret"
        return Instrucao(tipo, self._fonte(arvore), arvore.meta.line,
                         defs={nome}, uses=_usos(expr))

    def instrucao(self, arvore, pendentes):
        _, alt = _regra(arvore)
        linha = arvore.meta.line

        if alt == 0:                                        # P23: declaração local
            return self._simples(self.declaracao(_filhos(arvore)[0]), pendentes)

        if alt == 1:                                        # P24: x = expr;
            nome = str(_tokens(arvore)[0])
            expr = _filhos(arvore)[0]
            return self._simples(Instrucao("atrib", self._fonte(arvore), linha,
                                           defs={nome}, uses=_usos(expr)), pendentes)

        if alt in (2, 3):                                   # P25/P26: if / if-else
            expr, *blocos = _filhos(arvore)
            cond = self._no("cond", Instrucao("if", f"if ({self._fonte(expr)})", linha,
                                              uses=_usos(expr)))
            self._ligar(pendentes, cond)
            saidas = self.bloco(blocos[0], [(cond, "verdadeiro")])
            if len(blocos) == 2:
                saidas += self.bloco(blocos[1], [(cond, "falso")])
            else:
                saidas.append((cond, "falso"))
            return saidas

        if alt == 4:                                        # P27: for x in lista { … }
            var = str(_tokens(arvore)[0])
            expr, bloco = _filhos(arvore)
            ciclo = self._no("ciclo", Instrucao("for", f"for {var} in {self._fonte(expr)}",
                                                linha, defs={var}, uses=_usos(expr)))
            self._ligar(pendentes, ciclo)
            fim_corpo = self.bloco(bloco, [(ciclo, "iterar")])
            self._ligar(fim_corpo, ciclo)                   # aresta de volta
            return [(ciclo, "sair")]

        # P28/P29: chamada de uma ação
        callee = _filhos(arvore)[0]
        args = _filhos(arvore)[1] if alt == 5 else None
        return self._simples(Instrucao("acao", self._fonte(arvore), linha,
                                       uses=_usos(args) if args else set(),
                                       acao=str(_tokens(callee)[0])), pendentes)


def construir_cfg(texto):
    """CFG ao nível das instruções. Só para playbooks válidos (sem erros)."""
    resultado = analisar(texto)
    if not resultado.ativo:
        raise ValueError(f"playbook inválido, sem CFG: {resultado.erro}")
    return ConstrutorCFG(texto).programa(parse(texto))


# ---------------------------------------------------------------------------
#  Blocos básicos
# ---------------------------------------------------------------------------

def blocos_basicos(g):
    """Agrupa as cadeias máximas de instruções simples em blocos básicos.

    Um nó "instr" é o líder de um bloco se não tiver exatamente um
    predecessor, se esse predecessor não for "instr" ou se tiver mais do
    que um sucessor. Os outros nós (decisões, ciclos, entradas, …) ficam
    sozinhos."""
    def lider(n):
        if g.nodes[n]["tipo"] != "instr":
            return True
        preds = list(g.predecessors(n))
        return (g.in_degree(n) != 1 or g.nodes[preds[0]]["tipo"] != "instr"
                or g.out_degree(preds[0]) != 1)

    bloco_de, cadeias = {}, {}
    for n in g.nodes:
        if not lider(n):
            continue
        cadeia = [n]
        while g.nodes[n]["tipo"] == "instr":
            (s,) = g.successors(n)                          # uma instrução simples tem 1 sucessor
            if lider(s):
                break
            cadeia.append(s)
            n = s
        cadeias[cadeia[0]] = cadeia
        for m in cadeia:
            bloco_de[m] = cadeia[0]

    # nomes B0, B1, … por ordem de visita em profundidade (cada handler fica
    # com números seguidos; num if, o ramo verdadeiro vem antes do falso)
    ordem, pilha = {}, [g.graph["inicio"]]
    while pilha:
        b = bloco_de[pilha.pop()]
        if b in ordem:
            continue
        ordem[b] = f"B{len(ordem)}"
        pilha.extend(reversed([v for _, v in g.out_edges(cadeias[b][-1])]))
    for b in cadeias:                                       # nós inalcançáveis, se houver
        ordem.setdefault(b, f"B{len(ordem)}")

    bb = nx.MultiDiGraph()
    bb.graph.update(g.graph)
    for b, cadeia in cadeias.items():
        dados = dict(g.nodes[b])
        dados["instrs"] = [i for m in cadeia for i in g.nodes[m]["instrs"]]
        bb.add_node(ordem[b], **dados)
    for b, cadeia in cadeias.items():
        for _, destino, dados in g.out_edges(cadeia[-1], data=True):
            bb.add_edge(ordem[b], ordem[bloco_de[destino]], **dados)

    bb.graph["inicio"] = ordem[bloco_de[g.graph["inicio"]]]
    bb.graph["despacho"] = ordem[bloco_de[g.graph["despacho"]]]
    bb.graph["handlers"] = {h: (ordem[bloco_de[e]], ordem[bloco_de[s]])
                            for h, (e, s) in g.graph["handlers"].items()}
    return bb


def sem_servico(g):
    """Vista do CFG sem as arestas de serviço (despacho → handler → despacho):
    o que fica é o fluxo de controlo *dentro* de cada execução de um handler."""
    vista = g.copy()
    vista.remove_edges_from([(u, v, k) for u, v, k, s in g.edges(keys=True, data="servico") if s])
    return vista


# ---------------------------------------------------------------------------
#  Saída: Graphviz (DOT) e texto
# ---------------------------------------------------------------------------

def _esc(texto):
    return texto.replace("\\", "\\\\").replace('"', '\\"')


def _rotulo_no(nid, d):
    if d["tipo"] in ("inicio", "despacho", "saida"):
        return f'"{_esc(d["rotulo"])}"'
    linhas = [f"{nid}"] + [f"L{i.linha}: {i.texto}" for i in d["instrs"]]
    return '"' + "".join(_esc(l) + "\\l" for l in linhas) + '"'


ESTILO = {
    "inicio":   'shape=oval, style="filled,bold", fillcolor="#dbeafe"',
    "despacho": 'shape=oval, style="filled,bold", fillcolor="#fef3c7"',
    "entrada":  'shape=box, style="rounded,filled,bold", fillcolor="#e0e7ff"',
    "saida":    'shape=oval, style=filled, fillcolor="#f3f4f6"',
    "instr":    'shape=box',
    "cond":     'shape=diamond, style=filled, fillcolor="#fef9c3"',
    "ciclo":    'shape=hexagon, style=filled, fillcolor="#dcfce7"',
}


def para_dot(g):
    linhas = [f'digraph "{_esc(g.graph["playbook"])}" {{',
              '  rankdir=TB; nodesep=0.4;',
              '  node [fontname="Helvetica", fontsize=10];',
              '  edge [fontname="Helvetica", fontsize=9];']

    def no(nid, d):
        cor = ', color="#dc2626", fontcolor="#dc2626"' if any(
            i.destrutiva for i in d["instrs"]) else ""
        return f'"{nid}" [label={_rotulo_no(nid, d)}, {ESTILO[d["tipo"]]}{cor}];'

    for nid, d in g.nodes(data=True):
        if d["handler"] is None:
            linhas.append("  " + no(nid, d))
    for k, h in enumerate(g.graph["handlers"]):
        linhas += [f"  subgraph cluster_{k} {{",
                   f'    label="{_esc(h)}"; style="rounded,dashed"; color="#9ca3af";']
        linhas += ["    " + no(nid, d) for nid, d in g.nodes(data=True) if d["handler"] == h]
        linhas.append("  }")

    for u, v, d in g.edges(data=True):
        attrs = [f'label="{_esc(d["rotulo"])}"'] if d["rotulo"] else []
        if d["servico"]:
            attrs.append('style=dashed, color="#6b7280"')
            if g.nodes[u]["tipo"] == "saida":               # o regresso ao despacho não
                attrs.append("constraint=false")            # deve puxar o despacho para baixo
        elif d["rotulo"] in ("verdadeiro", "iterar"):
            attrs.append('color="#15803d"')
        elif d["rotulo"] in ("falso", "sair"):
            attrs.append('color="#b91c1c"')
        linhas.append(f'  "{u}" -> "{v}" [{", ".join(attrs)}];')
    linhas.append("}")
    return "\n".join(linhas) + "\n"


def para_texto(g):
    saida = []
    for nid, d in g.nodes(data=True):
        sucs = ", ".join(f"{v}" + (f" ({r})" if r else "")
                         for _, v, r in g.out_edges(nid, data="rotulo"))
        cabecalho = d["rotulo"] if d["tipo"] in ("inicio", "despacho", "saida") else d["tipo"]
        saida.append(f"{nid} [{cabecalho}]  → {sucs or '∅'}")
        for i in d["instrs"]:
            saida.append(f"    L{i.linha}: {i.texto}"
                         f"   defs={sorted(i.defs) or '∅'} uses={sorted(i.uses) or '∅'}")
    return "\n".join(saida)


def main(argumentos):
    instrucoes = "--instrucoes" in argumentos
    texto_apenas = "--texto" in argumentos
    pasta = Path("cfg")
    if "-o" in argumentos:
        i = argumentos.index("-o")
        pasta = Path(argumentos[i + 1])
        argumentos = argumentos[:i] + argumentos[i + 2:]
    ficheiros = [a for a in argumentos if not a.startswith("--")]

    for ficheiro in ficheiros:
        try:
            g = construir_cfg(Path(ficheiro).read_text(encoding="utf-8"))
        except ValueError as e:
            print(f"✘ {ficheiro}: {e}")
            continue
        if not instrucoes:
            g = blocos_basicos(g)
        if texto_apenas:
            print(f"── {ficheiro}\n{para_texto(g)}\n")
            continue
        pasta.mkdir(parents=True, exist_ok=True)
        destino = pasta / (Path(ficheiro).stem + ("_instrucoes" if instrucoes else ""))
        destino.with_suffix(".dot").write_text(para_dot(g), encoding="utf-8")
        gerados = [destino.with_suffix(".dot")]
        if shutil.which("dot"):
            subprocess.run(["dot", "-Tsvg", str(destino.with_suffix(".dot")),
                            "-o", str(destino.with_suffix(".svg"))], check=True)
            gerados.append(destino.with_suffix(".svg"))
        print(f"✔ {ficheiro}: {g.number_of_nodes()} nós, {g.number_of_edges()} arestas"
              f" → {', '.join(map(str, gerados))}")


if __name__ == "__main__":
    main(sys.argv[1:])
