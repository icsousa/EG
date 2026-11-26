"""
Sentinela: análise estática sobre o CFG.  Parte II, tarefa 2.

Um motor de análise de fluxo de dados (ponto fixo com lista de trabalho,
junção e alargamento) percorre o CFG da tarefa 1 (cfg.py) e aceita um
*domínio* que diz o que se calcula. Como no notebook 8, o domínio está
separado do percurso do grafo e do cálculo do ponto fixo. Há três domínios
(explicados em ANALISE.md):

  1. Definições que chegam (reaching definitions) → grafo de dependências de
     dados (DFG) e atribuições mortas ............................... D01
  2. Intervalos (interpretação abstrata) → condições que são sempre
     verdadeiras ou sempre falsas e código que nunca corre ........ I01, I02
  3. Validação dos alvos das ações destrutivas: um IP que vem do alerta
     (controlado por quem ataca) só deve ir para block_ip/quarantine
     depois de ser comparado com uma referência de confiança ........... V01

As análises correm sobre o CFG *com* as arestas de serviço: o estado do
playbook persiste entre execuções e o que um handler escreve chega aos
outros handlers (e a si próprio) através do despacho.

Uso:
  python analise.py exemplos/*.snt               achados das três análises
  python analise.py --detalhe exemplos/04.snt    e o estado abstrato em cada instrução
  python analise.py --dfg exemplos/*.snt         escreve dfg/<nome>.dot e .svg
"""
import re
import shutil
import subprocess
import sys
from collections import Counter, deque
from dataclasses import dataclass
from math import inf
from pathlib import Path

import networkx as nx
from lark import Token, Tree

from cfg import DESTRUTIVAS, _esc, construir_cfg, sem_servico


# ---------------------------------------------------------------------------
#  Expressões: da árvore do LarkAG para tuplos simples
# ---------------------------------------------------------------------------

def _filhos(t):
    return [c for c in t.children if isinstance(c, Tree)]


def _tok(t):
    return [c for c in t.children if isinstance(c, Token)]


_SEGUNDOS = {"s": 1, "m": 60, "h": 3600}


def ast(t):
    """Converte uma expressão (P33–P55) em tuplos:
    ('or'|'and', a, b) ('not', a) ('rel', op, a, b) ('+'|'-', a, b)
    ('campo', base, nome) ('var', nome) ('chamada', nome, [args]) ('lista', [itens])
    ('int'|'dur', n) ('bool', v) ('str'|'ip'|'cidr', texto)."""
    nome, _, alt = str(t.data).rpartition("_")
    alt = int(alt)
    f = _filhos(t)
    if (nome, alt) in {("expr", 1), ("andexpr", 1), ("notexpr", 1), ("relexpr", 2),
                       ("addexpr", 2), ("accessexpr", 1), ("primary", 3)}:
        return ast(f[0])                                    # produções unitárias e ( )
    if nome == "expr":
        return ("or", ast(f[0]), ast(f[1]))
    if nome == "andexpr":
        return ("and", ast(f[0]), ast(f[1]))
    if nome == "notexpr":
        return ("not", ast(f[0]))
    if nome == "relexpr":
        op = str(_tok(t)[0]) if alt == 0 else "in"
        return ("rel", op, ast(f[0]), ast(f[1]))
    if nome == "addexpr":
        return ("+" if alt == 0 else "-", ast(f[0]), ast(f[1]))
    if nome == "accessexpr":
        return ("campo", ast(f[0]), str(_tok(t)[0]))
    if nome == "primary":
        if alt == 0:
            return ("var", str(_tok(t)[0]))
        if alt in (1, 2):
            args = _lista_args(f[1]) if alt == 1 else []
            return ("chamada", str(_tok(f[0])[0]), [ast(a) for a in args])
        if alt in (4, 5):
            return ("lista", [ast(i) for i in _lista_args(f[0])] if alt == 4 else [])
        v = str(_tok(t)[0])
        if alt == 6:
            return ("int", int(v))
        if alt == 10:
            return ("dur", int(v[:-1]) * _SEGUNDOS[v[-1]])
        if alt == 11:
            return ("bool", v == "true")
        return ({7: "str", 8: "ip", 9: "cidr"}[alt], v)
    raise ValueError(f"expressão desconhecida: {t.data}")


def _lista_args(t):
    """Achata args/items (recursivos à esquerda)."""
    itens = []
    while len(_filhos(t)) == 2:
        itens.append(_filhos(t)[1])
        t = _filhos(t)[0]
    itens.append(_filhos(t)[0])
    return itens[::-1]


def _chave(e, nomes):
    """Nome único de uma variável, ou 'alias.campo' para o campo de um alerta."""
    if e[0] == "var":
        return nomes.get(e[1], e[1])
    if e[0] == "campo" and e[1][0] == "var":
        return f"{nomes.get(e[1][1], e[1][1])}.{e[2]}"
    return None


# ---------------------------------------------------------------------------
#  Motor de fluxo de dados
# ---------------------------------------------------------------------------

class Analise:
    """Um domínio abstrato. Um estado `None` é o ⊥: o ponto é inalcançável."""
    nome = ""

    def inicial(self, g):
        raise NotImplementedError

    def juntar(self, a, b):
        raise NotImplementedError

    def alargar(self, antigo, novo):          # ∇: por omissão, a junção basta
        return self.juntar(antigo, novo)       # (domínios de altura finita)

    def transferir(self, n, instr, estado):
        return estado

    def refinar(self, instr, valor, estado):  # aresta verdadeiro/falso de um if
        return estado

    def restringir(self, estado, variaveis):  # fim de um handler: as locais morrem
        raise NotImplementedError

    # -- aresta u → v: o que chega a v vindo de u
    def aresta(self, g, u, dados, estado):
        if estado is None:
            return None
        tipo = g.nodes[u]["tipo"]
        if tipo == "cond":
            return self.refinar(g.nodes[u]["instrs"][0], dados["rotulo"] == "verdadeiro", estado)
        if tipo == "saida" and dados["servico"]:
            return self.restringir(estado, g.graph["estado"])
        return estado


def _junta(analise, a, b):
    if a is None:
        return b
    if b is None:
        return a
    return analise.juntar(a, b)


def resolver(g, analise, estreitar=2):
    """Ponto fixo, para a frente, sobre o CFG de instruções.
    Devolve (entrada, saida): o estado abstrato antes e depois de cada nó.
    Nos nós onde os ciclos fecham (for e despacho) usa-se o alargamento ∇
    a partir da 3.ª visita, para garantir que termina; no fim, `estreitar`
    passagens sem ∇ recuperam alguma da precisão perdida."""
    entrada = {n: None for n in g}
    saida = {n: None for n in g}
    entrada[g.graph["inicio"]] = analise.inicial(g)
    visitas = Counter()
    trabalho = deque(nx.dfs_preorder_nodes(g, g.graph["inicio"]))
    pendente = set(trabalho)
    while trabalho:
        n = trabalho.popleft()
        pendente.discard(n)
        estado = entrada[n]
        for i in g.nodes[n]["instrs"]:
            if estado is not None:
                estado = analise.transferir(n, i, estado)
        saida[n] = estado
        for s in set(g.successors(n)):
            novo = None
            for p, _, dados in g.in_edges(s, data=True):
                novo = _junta(analise, novo, analise.aresta(g, p, dados, saida[p]))
            if s == g.graph["inicio"]:
                novo = _junta(analise, novo, analise.inicial(g))
            visitas[s] += 1
            if g.nodes[s]["tipo"] in ("ciclo", "despacho") and visitas[s] > 2 \
                    and entrada[s] is not None and novo is not None:
                novo = analise.alargar(entrada[s], novo)
            if novo != entrada[s]:
                entrada[s] = novo
                if s not in pendente:
                    trabalho.append(s)
                    pendente.add(s)

    # Estreitamento: o alargamento pode ter subido de mais; voltar a aplicar
    # as equações sem ∇ a partir do ponto fixo só dá resultados mais precisos
    # e continua correto (cada passagem é uma aproximação por cima).
    ordem = list(nx.dfs_preorder_nodes(g, g.graph["inicio"]))
    for _ in range(estreitar):
        for n in ordem:
            if n != g.graph["inicio"]:
                novo = None
                for p, _, dados in g.in_edges(n, data=True):
                    novo = _junta(analise, novo, analise.aresta(g, p, dados, saida[p]))
                entrada[n] = novo
            estado = entrada[n]
            for i in g.nodes[n]["instrs"]:
                if estado is not None:
                    estado = analise.transferir(n, i, estado)
            saida[n] = estado
    return entrada, saida


@dataclass
class Achado:
    codigo: str
    linha: int
    mensagem: str

    def __str__(self):
        return f"linha {self.linha}: {self.codigo}: {self.mensagem}"


# ---------------------------------------------------------------------------
#  1. Definições que chegam → DFG e atribuições mortas (D01)
# ---------------------------------------------------------------------------

class DefinicoesQueChegam(Analise):
    """Estado: conjunto de pares (variável, nó que a definiu). Junção: ∪."""
    nome = "definições que chegam"

    def inicial(self, g):
        return frozenset()

    def juntar(self, a, b):
        return a | b

    def transferir(self, n, instr, estado):
        if not instr.defs:
            return estado
        return frozenset({(v, d) for v, d in estado if v not in instr.defs}
                         | {(v, n) for v in instr.defs})

    def restringir(self, estado, variaveis):
        return frozenset((v, d) for v, d in estado if v in variaveis)


def construir_dfg(g, entrada=None):
    """Grafo de dependências de dados: uma aresta d → u, rotulada com a
    variável v, quando a definição de v em d chega a uma instrução u que lê v.
    `origem` diz de onde vem o valor: "ativacao" (declaração do estado),
    "execucao" (a mesma execução do handler) ou "anterior" (só chega através
    do despacho: é escrito numa execução e lido numa execução seguinte)."""
    if entrada is None:
        entrada, _ = resolver(g, DefinicoesQueChegam())
    intra = sem_servico(g)
    dfg = nx.MultiDiGraph()
    dfg.graph.update(g.graph)
    for n, dados in g.nodes(data=True):
        if dados["instrs"]:
            dfg.add_node(n, **dados)
    for u, dados in g.nodes(data=True):
        for i in dados["instrs"]:
            for v, d in sorted(entrada[u] or ()):
                if v in i.uses:
                    if g.nodes[d]["handler"] is None:
                        origem = "ativacao"
                    elif any(nx.has_path(intra, s, u) for s in intra.successors(d)):
                        origem = "execucao"
                    else:
                        origem = "anterior"
                    dfg.add_edge(d, u, var=v, origem=origem)
    return dfg


def atribuicoes_mortas(g, dfg):
    usadas = {v for _, d in g.nodes(data=True) for i in d["instrs"] for v in i.uses}
    achados = []
    for n, dados in g.nodes(data=True):
        for i in dados["instrs"]:
            if i.tipo not in ("var", "atrib"):
                continue
            (v,) = i.defs
            if i.tipo == "var" and v not in usadas:
                continue                          # nunca é lida: é o aviso W02 da GA
            if not any(dv == v for _, _, dv in dfg.out_edges(n, data="var")):
                nome = v.split("@")[0]
                achados.append(Achado("D01", i.linha,
                    f"o valor dado a '{nome}' nunca é lido: é sempre substituído "
                    f"antes de ser usado"))
    return achados


# ---------------------------------------------------------------------------
#  2. Intervalos (interpretação abstrata) → condições constantes (I01, I02)
#  Valores: (lo, hi) para int e duration (em segundos), frozenset de bool,
#  None = desconhecido (⊤ de qualquer tipo).
# ---------------------------------------------------------------------------

TF = frozenset({True, False})


def _jv(x, y):
    if isinstance(x, tuple) and isinstance(y, tuple):
        return (min(x[0], y[0]), max(x[1], y[1]))
    if isinstance(x, frozenset) and isinstance(y, frozenset):
        return x | y
    return None


def _inter(x, lo, hi):
    lo, hi = max(x[0], lo), min(x[1], hi)
    return None if lo > hi else (lo, hi)


_NEG = {"<": ">=", ">=": "<", ">": "<=", "<=": ">", "==": "!=", "!=": "=="}
_TROCA = {"<": ">", ">": "<", "<=": ">=", ">=": "<=", "==": "==", "!=": "!="}


def _constantes(g):
    """Limiares do alargamento: as constantes do programa (e c ± 1)."""
    cs = set()
    for _, d in g.nodes(data=True):
        for i in d["instrs"]:
            for t in [i.expr, *i.args]:
                if t is not None:
                    for tok in t.scan_values(lambda v: isinstance(v, Token)):
                        if tok.type in ("INT", "DURATION"):
                            c = int(tok[:-1]) * _SEGUNDOS[tok[-1]] if tok.type == "DURATION" \
                                else int(tok)
                            cs |= {c - 1, c, c + 1}
    return sorted(cs)


class Intervalos(Analise):
    """Alargamento com limiares (como no Astrée): em vez de saltar logo para
    ±∞, um limite que cresce passa para a constante do programa seguinte.
    Um contador `if (n < 3) { n = n + 1; }` fica em [0, 3] e não em [0, +∞]."""
    nome = "intervalos"

    def __init__(self):
        self.limiares = []

    def inicial(self, g):
        self.limiares = _constantes(g)
        return {}

    def juntar(self, a, b):
        return {k: _jv(a.get(k), b.get(k)) for k in a.keys() | b.keys()}

    def alargar(self, antigo, novo):
        r = {}
        for k in antigo.keys() | novo.keys():
            x, y = antigo.get(k), novo.get(k)
            if isinstance(x, tuple) and isinstance(y, tuple):
                lo = x[0] if y[0] >= x[0] else max([c for c in self.limiares if c <= y[0]],
                                                    default=-inf)
                hi = x[1] if y[1] <= x[1] else min([c for c in self.limiares if c >= y[1]],
                                                   default=inf)
                r[k] = (lo, hi)
            else:
                r[k] = _jv(x, y)
        return r

    def restringir(self, estado, variaveis):
        return {k: v for k, v in estado.items() if k in variaveis}

    # -- valor abstrato de uma expressão
    def valor(self, e, st, nomes):
        t = e[0]
        if t in ("int", "dur"):
            return (e[1], e[1])
        if t == "bool":
            return frozenset({e[1]})
        if t == "var":
            return st.get(nomes.get(e[1], e[1]))
        if t == "chamada" and e[1] in ("count", "len"):
            return (0, inf)
        if t in ("+", "-"):
            a, b = self.valor(e[1], st, nomes), self.valor(e[2], st, nomes)
            if isinstance(a, tuple) and isinstance(b, tuple):
                return (a[0] + b[0], a[1] + b[1]) if t == "+" else (a[0] - b[1], a[1] - b[0])
            return None
        if t == "not":
            a = self._bool(e[1], st, nomes)
            return frozenset(not x for x in a)
        if t in ("and", "or"):
            a, b = self._bool(e[1], st, nomes), self._bool(e[2], st, nomes)
            if t == "and":
                return frozenset(({True} if True in a and True in b else set())
                                 | ({False} if False in a or False in b else set()))
            return frozenset(({True} if True in a or True in b else set())
                             | ({False} if False in a and False in b else set()))
        if t == "rel" and e[1] != "in":
            a, b = self.valor(e[2], st, nomes), self.valor(e[3], st, nomes)
            if isinstance(a, tuple) and isinstance(b, tuple):
                return frozenset(r for r in (True, False)
                                 if self._possivel(e[1] if r else _NEG[e[1]], a, b))
            if isinstance(a, frozenset) and isinstance(b, frozenset) and e[1] in ("==", "!="):
                iguais = {x == y for x in a for y in b}
                return frozenset(iguais if e[1] == "==" else {not x for x in iguais})
            return TF
        if t == "rel":
            return TF
        return None

    def _bool(self, e, st, nomes):
        v = self.valor(e, st, nomes)
        return v if isinstance(v, frozenset) else TF

    @staticmethod
    def _possivel(op, a, b):
        """Há x ∈ a e y ∈ b com x op y?"""
        return {"<": a[0] < b[1], "<=": a[0] <= b[1], ">": a[1] > b[0], ">=": a[1] >= b[0],
                "==": max(a[0], b[0]) <= min(a[1], b[1]),
                "!=": not (a[0] == a[1] == b[0] == b[1])}[op]

    # -- transferência e refinamento
    def transferir(self, n, instr, estado):
        if instr.tipo in ("var", "atrib", "secret"):
            (v,) = instr.defs
            return {**estado, v: self.valor(ast(instr.expr), estado, instr.nomes)}
        if instr.defs:                                    # alias do alerta, variável do for
            return {**estado, **{v: None for v in instr.defs}}
        return estado

    def refinar(self, instr, valor, estado):
        return self._refina(ast(instr.expr), valor, estado, instr.nomes)

    def _refina(self, e, quer, st, nomes):
        """Estado restrito aos casos em que `e` vale `quer` (None se nenhum)."""
        if st is None:
            return None
        t = e[0]
        if t == "not":
            return self._refina(e[1], not quer, st, nomes)
        if t in ("and", "or"):
            curto = (t == "and") != quer                  # basta o 1.º operando decidir?
            so_a = self._refina(e[1], quer, st, nomes)    # (curto-circuito)
            a_depois_b = self._refina(e[2], quer, self._refina(e[1], t == "and", st, nomes), nomes)
            return _junta(self, so_a, a_depois_b) if curto else \
                self._refina(e[2], quer, so_a, nomes)
        if t == "var":
            k = nomes.get(e[1], e[1])
            atual = st.get(k)
            atual = atual if isinstance(atual, frozenset) else TF
            if quer not in atual:
                return None
            return {**st, k: frozenset({quer})}
        if t == "rel" and e[1] != "in":
            op = e[1] if quer else _NEG[e[1]]
            st = self._restringe(e[2], op, e[3], st, nomes)
            if st is not None:
                st = self._restringe(e[3], _TROCA[op], e[2], st, nomes)
            if st is None:
                return None
        if quer not in self._bool(e, st, nomes):
            return None
        return st

    def _restringe(self, esq, op, dir, st, nomes):
        """Restringe a variável `esq` para que `esq op dir` seja possível."""
        if esq[0] != "var":
            return st
        k = nomes.get(esq[1], esq[1])
        x, y = st.get(k), self.valor(dir, st, nomes)
        if not isinstance(y, tuple) or (x is not None and not isinstance(x, tuple)):
            return st
        x = x or (-inf, inf)
        lo, hi = {"<": (-inf, y[1] - 1), "<=": (-inf, y[1]), ">": (y[0] + 1, inf),
                  ">=": (y[0], inf), "==": y, "!=": (-inf, inf)}[op]
        novo = _inter(x, lo, hi)
        if op == "!=" and novo and y[0] == y[1]:          # só tira um extremo
            if novo[0] == y[0]:
                novo = _inter(novo, y[0] + 1, inf)
            elif novo and novo[1] == y[0]:
                novo = _inter(novo, -inf, y[0] - 1)
        return None if novo is None else {**st, k: novo}


def condicoes_constantes(g, entrada, analise):
    achados = []
    intra = sem_servico(g)
    for n, dados in g.nodes(data=True):
        if dados["tipo"] != "cond" or entrada[n] is None:
            continue
        i = dados["instrs"][0]
        if not i.uses:
            continue                              # condição literal: é o aviso W05 da GA
        v = analise._bool(ast(i.expr), entrada[n], i.nomes)
        if len(v) != 1:
            continue
        (sempre,) = v
        morto = "falso" if sempre else "verdadeiro"
        linhas = sorted({ins.linha for _, s, r in g.out_edges(n, data="rotulo") if r == morto
                         for m in {s} | nx.descendants(intra, s) if entrada[m] is None
                         for ins in g.nodes[m]["instrs"]})
        onde = f"; nunca correm as linhas {', '.join(map(str, linhas))}" if linhas else ""
        achados.append(Achado("I01" if sempre else "I02", i.linha,
            f"'{i.texto}' é sempre {'verdadeira' if sempre else 'falsa'} "
            f"em todas as execuções{onde}"))
    return achados


# ---------------------------------------------------------------------------
#  3. Validação dos alvos das ações destrutivas (V01)
#  Níveis: CONFIAVEL ⊑ VALIDADO ⊑ NAO_VALIDADO. A junção é o máximo:
#  um valor só está validado se o estiver em *todos* os caminhos.
# ---------------------------------------------------------------------------

CONFIAVEL, VALIDADO, NAO_VALIDADO = 0, 1, 2
NIVEIS = {CONFIAVEL: "confiável", VALIDADO: "validado", NAO_VALIDADO: "não validado"}


class ValidacaoDeAlvos(Analise):
    """Os campos de um alerta são escritos por quem ataca (um IP de origem pode
    ser falsificado). Um valor é *validado* depois de ser comparado (`in`, `==`,
    `!=`) com uma referência confiável, isto é, que não vem de nenhum alerta."""
    nome = "validação de alvos"

    @staticmethod
    def nivel(st, k):
        return st.get(k, NAO_VALIDADO if "." in k else CONFIAVEL)

    def inicial(self, g):
        return {}

    def juntar(self, a, b):
        return {k: max(self.nivel(a, k), self.nivel(b, k)) for k in a.keys() | b.keys()}

    def restringir(self, estado, variaveis):
        return {k: v for k, v in estado.items() if k in variaveis}

    def valor(self, e, st, nomes):
        k = _chave(e, nomes)
        if k is not None:
            return self.nivel(st, k)
        t = e[0]
        if t == "chamada":
            return CONFIAVEL if e[1] in ("count", "len") else \
                max((self.valor(a, st, nomes) for a in e[2]), default=CONFIAVEL)
        if t == "lista":
            return max((self.valor(a, st, nomes) for a in e[1]), default=CONFIAVEL)
        filhos = [x for x in e[1:] if isinstance(x, tuple)]
        return max((self.valor(x, st, nomes) for x in filhos), default=CONFIAVEL)

    def transferir(self, n, instr, estado):
        if instr.tipo in ("var", "atrib", "secret", "for"):
            (v,) = instr.defs                     # no for, o elemento vale o que vale a lista
            return {**estado, v: self.valor(ast(instr.expr), estado, instr.nomes)}
        if instr.tipo == "entrada" and instr.defs:
            (a,) = instr.defs                     # um alerta novo: os campos não estão validados
            return {k: v for k, v in estado.items() if not k.startswith(a + ".")}
        return estado

    def validados(self, e, quer, st, nomes):
        """Chaves que, sabendo que `e` vale `quer`, foram de certeza comparadas
        com uma referência confiável."""
        t = e[0]
        if t == "not":
            return self.validados(e[1], not quer, st, nomes)
        if t in ("and", "or"):
            a_sim = self.validados(e[1], t == "and", st, nomes)
            a_nao = self.validados(e[1], t != "and", st, nomes)
            b = self.validados(e[2], quer, st, nomes)
            if (t == "and") == quer:              # os dois operandos foram avaliados
                return a_sim | b
            return a_nao & (a_sim | b)            # ou decidiu o 1.º, ou ambos
        if t == "rel" and e[1] in ("in", "==", "!="):
            r = set()
            for x, ref in ((e[2], e[3]), (e[3], e[2])) if e[1] != "in" else ((e[2], e[3]),):
                k = _chave(x, nomes)
                if k and self.valor(ref, st, nomes) == CONFIAVEL and _chave(ref, nomes) != k:
                    r.add(k)
            return r
        return set()

    def refinar(self, instr, valor, estado):
        ks = self.validados(ast(instr.expr), valor, estado, instr.nomes)
        return {**estado, **{k: min(self.nivel(estado, k), VALIDADO) for k in ks}}


def alvos_nao_validados(g, entrada, analise):
    achados = []
    for n, dados in g.nodes(data=True):
        for i in dados["instrs"]:
            if i.tipo != "acao" or i.acao not in DESTRUTIVAS or entrada[n] is None:
                continue
            alvo = ast(i.args[0])
            if analise.valor(alvo, entrada[n], i.nomes) == NAO_VALIDADO:
                texto = re.sub(r"\s+", " ", _texto_arg(i))
                achados.append(Achado("V01", i.linha,
                    f"o alvo de {i.acao} ({texto}) vem do alerta e, em pelo menos um "
                    f"caminho, não é comparado com nenhuma lista ou rede de confiança"))
    return achados


def _texto_arg(i):
    dentro = i.texto[i.texto.index("(") + 1:i.texto.rindex(")")]
    profundidade, fim = 0, len(dentro)
    for k, c in enumerate(dentro):                # o 1.º argumento, até à vírgula de topo
        profundidade += c in "([" and 1 or c in ")]" and -1 or 0
        if c == "," and profundidade == 0:
            fim = k
            break
    return dentro[:fim].strip()


# ---------------------------------------------------------------------------
#  Tudo junto
# ---------------------------------------------------------------------------

@dataclass
class Relatorio:
    g: nx.MultiDiGraph
    dfg: nx.MultiDiGraph
    intervalos: dict
    validacao: dict
    achados: list


def analisar_playbook(texto):
    g = construir_cfg(texto)
    rd, _ = resolver(g, DefinicoesQueChegam())
    dfg = construir_dfg(g, rd)
    ia = Intervalos()
    iv, _ = resolver(g, ia)
    va = ValidacaoDeAlvos()
    vv, _ = resolver(g, va)
    achados = atribuicoes_mortas(g, dfg) + condicoes_constantes(g, iv, ia) \
        + alvos_nao_validados(g, vv, va)
    achados.sort(key=lambda a: (a.linha, a.codigo))
    return Relatorio(g, dfg, iv, vv, achados)


def _fmt_intervalo(v):
    if isinstance(v, tuple):
        f = lambda x: "-∞" if x == -inf else "+∞" if x == inf else str(int(x))
        return f"[{f(v[0])}, {f(v[1])}]"
    if isinstance(v, frozenset):
        return "{" + ", ".join(sorted(str(b).lower() for b in v)) + "}"
    return "⊤"


def detalhe(r):
    linhas = ["  (estado abstrato antes de cada instrução: intervalos | alvos)"]
    for n, dados in r.g.nodes(data=True):
        if dados["tipo"] == "despacho":
            st = r.intervalos[n] or {}
            linhas.append("  despacho (invariante do estado entre execuções): " + ", ".join(
                f"{k} ∈ {_fmt_intervalo(v)}" for k, v in sorted(st.items())
                if v is not None))
        for i in dados["instrs"]:
            st, sv = r.intervalos[n], r.validacao[n]
            if st is None:
                linhas.append(f"  L{i.linha:<3} {i.texto:<50} inalcançável")
                continue
            ints = ", ".join(f"{k}∈{_fmt_intervalo(v)}" for k, v in sorted(st.items())
                             if k in i.uses and v is not None)
            alvos = ", ".join(f"{k.split('@')[0]}:{NIVEIS[v]}" for k, v in sorted(sv.items())
                              if v != CONFIAVEL and re.search(
                                  r"\b" + re.escape(k.split("@")[0]) + r"\b", i.texto))
            linhas.append(f"  L{i.linha:<3} {i.texto:<50} {ints}"
                          + (f"  | {alvos}" if alvos else ""))
    return "\n".join(linhas)


# ---------------------------------------------------------------------------
#  DFG em Graphviz
# ---------------------------------------------------------------------------

def dfg_para_dot(r):
    dfg = r.dfg
    mortos = {a.linha for a in r.achados if a.codigo == "D01"}
    linhas = [f'digraph "dfg_{_esc(dfg.graph["playbook"])}" {{',
              '  rankdir=TB; nodesep=0.3;',
              '  node [fontname="Helvetica", fontsize=10, shape=box, style=rounded];',
              '  edge [fontname="Helvetica", fontsize=9];']

    def no(n, d):
        i = d["instrs"][0]
        cor = ', color="#dc2626", fontcolor="#dc2626"' if i.linha in mortos else ""
        return f'"{n}" [label="L{i.linha}: {_esc(i.texto)}"{cor}];'

    activos = {n for e in dfg.edges for n in e[:2]}
    grupos = {}
    for n, d in dfg.nodes(data=True):
        if n in activos:
            grupos.setdefault(d["handler"], []).append(no(n, d))
    linhas += ["  " + x for x in grupos.pop(None, [])]
    for k, (h, nos) in enumerate(grupos.items()):
        linhas += [f"  subgraph cluster_{k} {{",
                   f'    label="{_esc(h)}"; style="rounded,dashed"; color="#9ca3af";']
        linhas += ["    " + x for x in nos]
        linhas.append("  }")
    for u, v, d in dfg.edges(data=True):
        estilo = {"execucao": "",
                  "ativacao": ', style=dotted, color="#6b7280", fontcolor="#6b7280"',
                  "anterior": ', style=dashed, color="#2563eb", fontcolor="#2563eb", '
                              'constraint=false'}[d["origem"]]
        linhas.append(f'  "{u}" -> "{v}" [label="{_esc(d["var"].split("@")[0])}"{estilo}];')
    linhas.append("}")
    return "\n".join(linhas) + "\n"


def main(argumentos):
    ver_detalhe = "--detalhe" in argumentos
    escrever_dfg = "--dfg" in argumentos
    pasta = Path("dfg")
    ficheiros = [a for a in argumentos if not a.startswith("--")]
    total = 0
    for ficheiro in ficheiros:
        try:
            r = analisar_playbook(Path(ficheiro).read_text(encoding="utf-8"))
        except ValueError as e:
            print(f"✘ {ficheiro}: {e}")
            continue
        total += len(r.achados)
        print(f"{'✔' if not r.achados else '!'} {ficheiro}: {len(r.achados)} achado(s)")
        for a in r.achados:
            print(f"    {a}")
        if ver_detalhe:
            print(detalhe(r))
        if escrever_dfg:
            pasta.mkdir(exist_ok=True)
            destino = pasta / (Path(ficheiro).stem + ".dot")
            destino.write_text(dfg_para_dot(r), encoding="utf-8")
            if shutil.which("dot"):
                subprocess.run(["dot", "-Tsvg", str(destino), "-o",
                                str(destino.with_suffix(".svg"))], check=True)
            print(f"    DFG → {destino}")
    return total


if __name__ == "__main__":
    main(sys.argv[1:])
