"""Testes semânticos: cada ficheiro anota com '# expect: CÓDIGO' as linhas onde
o verificador TEM de reportar esse erro/aviso. Nada a mais, nada a menos."""
import re
from pathlib import Path
import pytest
from verificador import check

FICHEIROS = sorted(Path("tests_semantica").glob("*.snt")) + sorted(Path("erros").glob("*.snt"))
EXEMPLOS = sorted(Path("exemplos").glob("*.snt"))
EXPECT = re.compile(r"expect:\s*([EW]\d+)")

def esperados(texto):
    return sorted((n, m.group(1)) for n, linha in enumerate(texto.splitlines(), 1)
                  for m in EXPECT.finditer(linha))

@pytest.mark.parametrize("f", FICHEIROS, ids=lambda p: p.name)
def test_erros_esperados(f):
    texto = f.read_text(encoding="utf-8")
    obtidos = sorted((d.linha, d.codigo) for d in check(texto))
    assert obtidos == esperados(texto)

@pytest.mark.parametrize("f", EXEMPLOS, ids=lambda p: p.name)
def test_exemplos_sem_erros(f):
    assert check(f.read_text(encoding="utf-8")) == []
