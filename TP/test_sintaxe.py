"""Testes sintáticos. Correr com: pytest -v"""
from pathlib import Path
import pytest
from lark import Lark, UnexpectedInput
from parser import parse, GRAMATICA

EXEMPLOS = sorted(Path("exemplos").glob("*.snt")) + sorted(Path("erros").glob("*.snt"))

def test_gramatica_lalr_sem_conflitos():
    Lark(GRAMATICA.read_text(encoding="utf-8"), parser="lalr")   # falha se houver conflitos

@pytest.mark.parametrize("f", EXEMPLOS, ids=lambda p: p.name)
def test_aceita_programas_validos(f):
    parse(f.read_text(encoding="utf-8"))

@pytest.mark.parametrize("codigo", [
    'playbook p { on x as a { if (a > ) { } } }',          # expressão incompleta
    'playbook p { var x int = 1; on y as b { } }',         # falta ':'
    'playbook p { var x: int = 1; }',                      # playbook sem handlers
    'playbook p { on x as a { log("ok") } }',              # falta ';'
])
def test_rejeita_programas_invalidos(codigo):
    with pytest.raises(UnexpectedInput):
        parse(codigo)

@pytest.mark.parametrize("texto,tipo", [
    ("10.0.0.0/8", "CIDR"), ("10.0.0.5", "IP"), ("24h", "DURATION"),
    ("5432", "INT"), ("index", "NAME"),
])
def test_lexico(texto, tipo):
    tokens = list(Lark(GRAMATICA.read_text(encoding="utf-8"), parser="lalr").lex(texto))
    assert [t.type for t in tokens] == [tipo]
