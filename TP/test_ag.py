"""Testes da gramática de atributos em LarkAG: cada programa viola UMA regra
e o LarkAG tem de parar com o código certo (ContextConditionError)."""
from pathlib import Path
import pytest
from lark_ag import Lark_AG, ContextConditionError
from sentinela_ag import GRAMMAR

AG = Lark_AG(GRAMMAR)

def prog(corpo, decls="", alertas="alert scan { src: ip; port: int; }"):
    return f"{alertas} playbook p {{ {decls} on scan as s {{ {corpo} }} }}"

CASOS = {
    "E101": prog('log(str(total));'),
    "E102": prog('', decls='var a: int = 1; var a: int = 2;'),
    "E103": prog('log("x");', alertas="alert scan { src: ip; } alert scan { port: int; }"),
    "E104": prog('log("x");', alertas="alert scan { src: ip; src: int; }"),
    "E201": "alert scan { src: ip; } playbook p { on ddos as d { log(\"x\"); } }",
    "E203": prog('log(str(n.valor));', decls='var n: int = 1;'),
    "E204": prog('log(str(s.porta));'),
    "E301": prog('', decls='var r: ip = 10.0.0.0/8;'),
    "E302": prog('log("porta " + s.port);'),
    "E303": prog('log("a" - "b");'),
    "E304": prog('if (s.src > 10.0.0.1) { log("x"); }'),
    "E305": prog('if (s.port == "22") { log("x"); }'),
    "E306": prog('if (s.port in 10.0.0.0/8) { log("x"); }'),
    "E307": prog('if (s.port and true) { log("x"); }'),
    "E308": prog('if (s.port) { log("x"); }'),
    "E309": prog('for x in s.port { log("x"); }'),
    "E310": prog('', decls='var l: list<int> = [1, "2"];'),
    "E401": prog('ban_ip(s.src);'),
    "E402": prog('block_ip(s.src);'),
    "E403": prog('block_ip(s.port, 1h);'),
    "E405": prog('var r: int = log("x");'),
    "E501": prog('t = "y";', decls='secret t: string = "x";'),
    "E502": prog('for x in [1, 2] { x = 3; }'),
    "E601": prog('log("t=" + t);', decls='secret t: string = "x";'),
    "E602": prog('', decls='secret t: string = "x"; var c: string = t;'),
}

@pytest.mark.parametrize("codigo", sorted(CASOS))
def test_ag_detecta(codigo):
    with pytest.raises(ContextConditionError) as erro:
        AG.process(CASOS[codigo])
    assert str(erro.value).startswith(codigo)

@pytest.mark.parametrize("f", sorted(Path("exemplos").glob("*.snt")), ids=lambda p: p.name)
def test_ag_aceita_exemplos(f):
    AG.process(f.read_text(encoding="utf-8"))

def test_ag_credencial_do_notify_e_permitida():
    AG.process(prog('notify("scan", t);', decls='secret t: string = "x";'))
