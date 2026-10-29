"""Testes da semântica (gramática de atributos em LarkAG).

testes/: um programa por código de erro ou aviso, com '# expect: CÓDIGO' na
linha onde o problema tem de ser assinalado. Um erro pára a avaliação e o
playbook não é ativado; um aviso não impede a ativação.
Correr com: pytest -q"""
import re
from pathlib import Path
import pytest
from sentinela import analisar

TESTES = sorted(Path("testes").glob("*.snt"))
EXEMPLOS = sorted(Path("exemplos").glob("*.snt"))
EXPECT = re.compile(r"expect:\s*([EW]\d+)")


def esperado(texto):
    marcas = [(m.group(1), n) for n, linha in enumerate(texto.splitlines(), 1)
              for m in EXPECT.finditer(linha)]
    assert len(marcas) == 1, "cada teste assinala exatamente um problema"
    return marcas[0]


@pytest.mark.parametrize("f", TESTES, ids=lambda p: p.stem)
def test_codigo_e_linha(f):
    texto = f.read_text(encoding="utf-8")
    codigo, linha = esperado(texto)
    r = analisar(texto)
    if codigo.startswith("E"):
        assert not r.ativo
        assert (r.erro.codigo, r.erro.linha) == (codigo, linha)
    else:
        assert r.ativo
        assert [(a.codigo, a.linha) for a in r.avisos] == [(codigo, linha)]


@pytest.mark.parametrize("f", EXEMPLOS, ids=lambda p: p.stem)
def test_exemplos_ativos_sem_avisos(f):
    r = analisar(f.read_text(encoding="utf-8"))
    assert r.ativo and r.avisos == []


def test_todos_os_codigos_tem_teste():
    codigos = {esperado(f.read_text(encoding="utf-8"))[0] for f in TESTES}
    erros = {f"E{n}" for n in [101, 102, 103, 104, 105, 201, 202, 203, 204,
                               *range(301, 311), *range(401, 406), 501, 502,
                               601, 602, 603, 701, 702, 703]}
    avisos = {f"W0{n}" for n in range(1, 7)}
    assert codigos == erros | avisos


# ---- casos que têm de ser ACEITES (para garantir que as regras não são demasiado rígidas)
H = "alert scan { src: ip; port: int; }\n"

@pytest.mark.parametrize("corpo,estado", [
    ('notify("scan de " + str(s.src), token);', 'secret token: string = "x";'),   # credencial
    ('log("x" + "");', ''),                              # W06 só para "" escrito diretamente
    ('if (s.src in 10.0.0.0/8) { log("interno"); }', ''),
    ('if (s.port in [22, 80]) { log("ok"); }', ''),
    ('if (1h + 30m > 1h) { log("ok"); }', ''),
    ('total = total + 1;', 'var total: int = 0;'),      # estado persistente
])
def test_aceita(corpo, estado):
    r = analisar(f"{H}playbook p {{ {estado} on scan as s {{ {corpo} }} }}")
    assert r.ativo and r.avisos == [], (r.erro, r.avisos)


def test_aviso_w06_no_notify():
    r = analisar(f'{H}playbook p {{ on scan as s {{ notify(""); }} }}')
    assert [a.codigo for a in r.avisos] == ["W06"]


def test_erro_de_sintaxe():
    r = analisar("playbook p { on scan as s { log(\"x\") } }")
    assert not r.ativo and r.erro.codigo == "SINTAXE"
