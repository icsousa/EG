"""
Sentinela — métricas de qualidade da gramática (tarefa 4 do guião).

Calcula as métricas do NB07 (Language and Grammar Quality):
  - GIC: tamanho, dependências, tamanho do parser LALR, forma (recursão, notação)
         e métricas lexicográficas;
  - GA:  nº de atributos (herdados/sintetizados), regras de cálculo, condições de
         contexto, complexidade dos atributos e grafo de dependências.

As métricas da GIC são calculadas para as duas formas da gramática:
  - EBNF: sentinela.lark (a que o parser usa);
  - BNF:  a GIC do exemplo LarkAG (sentinela_ag.py), igual às produções de GRAMATICA.md.

Uso: python metricas.py
"""
import re
from collections import Counter, defaultdict
from pathlib import Path

from lark import Lark
from lark_ag import Lark_AG
from sentinela_ag import GRAMMAR as AG_GRAMMAR


# ------------------------------------------------------------------ GIC
def metricas_gic(nome, texto_gramatica):
    parser = Lark(texto_gramatica, parser="lalr")
    rules = parser.rules
    por_simbolo = Counter(r.origin.name for r in rules)
    nts = set(por_simbolo)
    comp = [len(r.expansion) for r in rules]

    arestas = {(r.origin.name, s.name) for r in rules for s in r.expansion if not s.is_term}
    grau_in = Counter(b for _, b in arestas)
    grau_out = Counter(a for a, _ in arestas)

    # recursão direta, à esquerda / à direita
    rec_esq = {r.origin.name for r in rules if r.expansion and not r.expansion[0].is_term
               and r.expansion[0].name == r.origin.name}
    rec_dir = {r.origin.name for r in rules if r.expansion and not r.expansion[-1].is_term
               and r.expansion[-1].name == r.origin.name}
    rec_direta = {r.origin.name for r in rules
                  if any(not s.is_term and s.name == r.origin.name for s in r.expansion)}

    # recursão indireta: símbolos num ciclo de comprimento >= 2 do grafo de dependências
    sucessores = defaultdict(set)
    for a, b in arestas:
        if a != b:
            sucessores[a].add(b)

    def alcanca(origem):
        vistos, pilha = set(), [origem]
        while pilha:
            for nxt in sucessores[pilha.pop()]:
                if nxt not in vistos:
                    vistos.add(nxt)
                    pilha.append(nxt)
        return vistos

    rec_indireta = {n for n in nts if n in alcanca(n)}

    tabela = parser.parser.parser._parse_table
    estados = len(tabela.states)
    entradas = sum(len(acoes) for acoes in tabela.states.values())

    fixos = [t.name for t in parser.terminals if t.pattern.type == "str"]
    flexiveis = [t.name for t in parser.terminals if t.pattern.type == "re"]

    return {
        "Gramática": nome,
        "Terminais": len(parser.terminals),
        "  fixos (palavras reservadas, pontuação)": len(fixos),
        "  flexíveis (NAME, INT, IP, ...)": len(flexiveis),
        "Não-terminais": len(nts),
        "Produções": len(rules),
        "Produções unitárias (A → B)": sum(len(r.expansion) == 1 and not r.expansion[0].is_term for r in rules),
        "Comprimento médio do lado direito": round(sum(comp) / len(comp), 2),
        "Comprimento máximo do lado direito": max(comp),
        "Média de produções por não-terminal": round(sum(por_simbolo.values()) / len(nts), 2),
        "Máximo de produções por não-terminal": max(por_simbolo.values()),
        "Grau de entrada médio (dependências)": round(sum(grau_in[n] for n in nts) / len(nts), 2),
        "Grau de saída médio (dependências)": round(sum(grau_out[n] for n in nts) / len(nts), 2),
        "Símbolos com recursão direta": len(rec_direta),
        "  à esquerda": len(rec_esq),
        "  à direita": len(rec_dir),
        "Símbolos com recursão indireta": len(rec_indireta),
        "Estados LALR": estados,
        "Entradas da tabela action/goto": entradas,
    }


# ------------------------------------------------------------------ GA
def metricas_ga():
    ag = Lark_AG(AG_GRAMMAR)
    gen = ag.generator
    atributos = [(simb, a) for simb, attrs in gen.__attributes__.items() for a in attrs.values()]
    regras = [r for alts in gen.__semantics__.values() for alt in alts for r in alt["semantics"]]
    ers = [r for r in regras if r["type"] == "er"]
    ccs = [r for r in regras if r["type"] == "cc"]

    atomicos = {"str", "bool", "int"}
    tipos = Counter("atómico" if a["type"] in atomicos else "estruturado" for _, a in atributos)

    # grafo de dependências entre atributos (símbolo.atributo, sem índices de ocorrência)
    simbolos = set(gen.__attributes__)
    ref = re.compile(r"\b(%s)(?:\[\d+\])?\.([a-z]\w*)" % "|".join(sorted(simbolos, key=len, reverse=True)))
    arestas = set()
    for r in ers:
        esquerda, direita = r["code"].split("=", 1)
        destino = ref.search(esquerda)
        if not destino:
            continue
        alvo = f"{destino.group(1)}.{destino.group(2)}"
        for m in ref.finditer(direita):
            arestas.add((f"{m.group(1)}.{m.group(2)}", alvo))
    nos = {f"{s}.{a['name']}" for s, a in atributos}
    grau_in = Counter(b for _, b in arestas)
    grau_out = Counter(a for a, _ in arestas)

    ops_simples = sum(r["code"].count("\n") == 0 for r in ers)
    # regra de cópia: o lado direito é só um atributo (ex.: block.env = stmt.env)
    copia = re.compile(r"^\s*\w+(?:\[\d+\])?\.\w+\s*$")
    copias = sum(bool(copia.match(r["code"].split("=", 1)[1])) for r in ers)

    return {
        "Atributos (por símbolo)": len(atributos),
        "  herdados": sum(a["inheritance"] == "IA" for _, a in atributos),
        "  sintetizados": sum(a["inheritance"] == "SA" for _, a in atributos),
        "  de tipo atómico (str, bool)": tipos["atómico"],
        "  de tipo estruturado (dict, set, list, tuple)": tipos["estruturado"],
        "Regras de cálculo (ER)": len(ers),
        "  numa só linha": ops_simples,
        "  regras de cópia (X.a = Y.a)": copias,
        "Condições de contexto (CC)": len(ccs),
        "Códigos de erro distintos": len({c["message"].split(":")[0] for c in ccs}),
        "Arestas no grafo de dependências": len(arestas),
        "Grau de entrada médio": round(sum(grau_in[n] for n in nos) / len(nos), 2),
        "Grau de saída médio": round(sum(grau_out[n] for n in nos) / len(nos), 2),
    }


def lexicografia():
    texto = Path("sentinela.lark").read_text(encoding="utf-8")
    palavras = sorted(set(re.findall(r'"([a-z]+)"', texto)))
    return {
        "Palavras reservadas": " ".join(palavras),
        "Comentários": "de linha (#); sem comentários de bloco nem meta-informação",
    }


def tabela(titulo, *colunas):
    print(f"\n## {titulo}\n")
    chaves = list(colunas[0])
    if len(colunas) == 1:
        print("| Métrica | Valor |\n|---|---|")
        for k in chaves:
            print(f"| {k.strip()} | {colunas[0][k]} |")
    else:
        print("| Métrica | " + " | ".join(str(c[chaves[0]]) for c in colunas) + " |")
        print("|---" * (len(colunas) + 1) + "|")
        for k in chaves[1:]:
            print(f"| {k} | " + " | ".join(str(c[k]) for c in colunas) + " |")


if __name__ == "__main__":
    ebnf = metricas_gic("EBNF (sentinela.lark)", Path("sentinela.lark").read_text(encoding="utf-8"))
    bnf = metricas_gic("BNF (GRAMATICA.md / LarkAG)", Lark_AG(AG_GRAMMAR).getCFG())
    tabela("Métricas da GIC", ebnf, bnf)
    tabela("Métricas lexicográficas", lexicografia())
    tabela("Métricas da GA (exemplo LarkAG)", metricas_ga())
