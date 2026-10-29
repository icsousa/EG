"""
Sentinela — métricas de qualidade da gramática (tarefa 4 do guião, NB07).

  - GIC: tamanho, dependências, tamanho do parser LALR, forma (recursão) e léxico;
  - GA:  atributos (herdados/sintetizados, atómicos/estruturados), regras de cálculo,
         condições de contexto e grafo de dependências entre atributos.

Tudo é calculado a partir de sentinela.ag, a única definição da linguagem.
Uso: python metricas.py
"""
import re
from collections import Counter, defaultdict

from lark import Lark
from sentinela import AG


def metricas_gic():
    parser = Lark(AG.getCFG(), parser="lalr")
    rules = parser.rules
    por_simbolo = Counter(r.origin.name for r in rules)
    nts = set(por_simbolo)
    comp = [len(r.expansion) for r in rules]
    arestas = {(r.origin.name, s.name) for r in rules for s in r.expansion if not s.is_term}
    grau_in = Counter(b for _, b in arestas)
    grau_out = Counter(a for a, _ in arestas)

    def primeiro_e(r, nome): return r.expansion and not r.expansion[0].is_term and r.expansion[0].name == nome
    def ultimo_e(r, nome): return r.expansion and not r.expansion[-1].is_term and r.expansion[-1].name == nome
    rec_esq = {r.origin.name for r in rules if primeiro_e(r, r.origin.name)}
    rec_dir = {r.origin.name for r in rules if ultimo_e(r, r.origin.name)}
    rec_direta = {r.origin.name for r in rules if any(not s.is_term and s.name == r.origin.name for s in r.expansion)}

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

    tabela = parser.parser.parser._parse_table
    return {
        "Terminais": len(parser.terminals),
        "  fixos (palavras reservadas, pontuação)": sum(t.pattern.type == "str" for t in parser.terminals),
        "  flexíveis (NAME, INT, IP, ...)": sum(t.pattern.type == "re" for t in parser.terminals),
        "Não-terminais": len(nts),
        "Produções": len(rules),
        "Produções unitárias (A → B)": sum(len(r.expansion) == 1 and not r.expansion[0].is_term for r in rules),
        "Comprimento médio do lado direito": round(sum(comp) / len(comp), 2),
        "Comprimento máximo do lado direito": max(comp),
        "Média de produções por não-terminal": round(sum(por_simbolo.values()) / len(nts), 2),
        "Máximo de produções por não-terminal": max(por_simbolo.values()),
        "Grau de entrada / saída médio": round(sum(grau_in[n] for n in nts) / len(nts), 2),
        "Símbolos com recursão direta": len(rec_direta),
        "  à esquerda": len(rec_esq),
        "  à direita": len(rec_dir),
        "Símbolos com recursão indireta": len({n for n in nts if n in alcanca(n)}),
        "Estados LALR": len(tabela.states),
        "Entradas da tabela action/goto": sum(len(a) for a in tabela.states.values()),
    }


def metricas_lexicograficas():
    parser = Lark(AG.getCFG(), parser="lalr")
    palavras = sorted(t.pattern.value for t in parser.terminals
                      if t.pattern.type == "str" and t.pattern.value.isalpha())
    return {
        "Palavras reservadas": f"{len(palavras)}: " + " ".join(palavras),
        "Comentários": "de linha (#); sem comentários de bloco nem meta-informação",
    }


def metricas_ga():
    gen = AG.generator
    atributos = [(s, a) for s, attrs in gen.__attributes__.items() for a in attrs.values()]
    regras = [r for alts in gen.__semantics__.values() for alt in alts for r in alt["semantics"]]
    ers = [r for r in regras if r["type"] == "er"]
    ccs = [r for r in regras if r["type"] == "cc"]

    atomico = lambda t: t in ("str", "bool", "int")
    simbolos = set(gen.__attributes__)
    ref = re.compile(r"\b(%s)(?:\[\d+\])?\.([a-z]\w*)" % "|".join(sorted(simbolos, key=len, reverse=True)))
    arestas = set()
    for r in ers:
        esquerda, direita = r["code"].split("=", 1)
        destino = ref.search(esquerda)
        if destino:
            alvo = f"{destino.group(1)}.{destino.group(2)}"
            arestas |= {(f"{m.group(1)}.{m.group(2)}", alvo) for m in ref.finditer(direita)}
    nos = {f"{s}.{a['name']}" for s, a in atributos}
    grau = Counter(b for _, b in arestas)

    copia = re.compile(r"^\s*\w+(?:\[\d+\])?\.\w+\s*$")
    copias = sum(bool(copia.match(r["code"].split("=", 1)[1])) for r in ers)
    return {
        "Atributos (contados por símbolo)": len(atributos),
        "  herdados": sum(a["inheritance"] == "IA" for _, a in atributos),
        "  sintetizados": sum(a["inheritance"] == "SA" for _, a in atributos),
        "  de tipo atómico (str, bool, int)": sum(atomico(a["type"]) for _, a in atributos),
        "  de tipo estruturado (dict, set, list, tuple)": sum(not atomico(a["type"]) for _, a in atributos),
        "Nomes de atributos distintos": len({a["name"] for _, a in atributos}),
        "Regras de cálculo (ER)": len(ers),
        "  regras de cópia (X.a = Y.a)": copias,
        "  restantes": len(ers) - copias,
        "Condições de contexto (CC)": len(ccs),
        "Códigos de erro distintos": len({c["message"].split(":")[0].strip('"') for c in ccs}),
        "Arestas no grafo de dependências": len(arestas),
        "Grau de entrada / saída médio": round(sum(grau[n] for n in nos) / len(nos), 2),
    }


def tabela(titulo, dados):
    print(f"\n## {titulo}\n\n| Métrica | Valor |\n|---|---|")
    for k, v in dados.items():
        print(f"| {k.strip()} | {v} |")


if __name__ == "__main__":
    tabela("Métricas da GIC", metricas_gic())
    tabela("Métricas lexicográficas", metricas_lexicograficas())
    tabela("Métricas da gramática de atributos", metricas_ga())
