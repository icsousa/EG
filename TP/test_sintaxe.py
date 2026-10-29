"""Testes da sintaxe: a GIC (gerada a partir de sentinela.ag) é LALR(1),
não é ambígua e aceita / rejeita os programas certos. Correr com: pytest -q"""
from pathlib import Path
import pytest
from lark import Lark, UnexpectedInput
from sentinela import AG, PARSER, parse

PROGRAMAS = sorted(Path("exemplos").glob("*.snt")) + sorted(Path("testes").glob("*.snt"))


def test_gramatica_lalr_sem_conflitos():
    # O Lark recusa construir a tabela se houver conflitos. Uma gramática LALR(1)
    # é sempre não ambígua: cada programa tem uma única árvore de derivação.
    Lark(AG.getCFG(), parser="lalr")


@pytest.mark.parametrize("f", PROGRAMAS, ids=lambda p: p.name)
def test_aceita_programas(f):
    parse(f.read_text(encoding="utf-8"))


@pytest.mark.parametrize("codigo", [
    'playbook p { on x as a { if (a > ) { } } }',        # expressão incompleta
    'playbook p { var x int = 1; on y as b { } }',       # falta ':'
    'playbook p { var x: int = 1; }',                    # playbook sem handlers
    'playbook p { on x as a { log("ok") } }',            # falta ';'
    'playbook p { on x as a { if (a < b < c) { } } }',   # comparações não associam
])
def test_rejeita_programas_mal_formados(codigo):
    with pytest.raises(UnexpectedInput):
        parse(codigo)


@pytest.mark.parametrize("texto,tipo", [
    ("10.0.0.0/8", "CIDR"), ("10.0.0.5", "IP"), ("24h", "DURATION"),
    ("5432", "INT"), ("index", "NAME"), ("true", "BOOL"), ("<=", "RELOP"),
])
def test_lexico(texto, tipo):
    assert [t.type for t in PARSER.lex(texto)] == [tipo]
