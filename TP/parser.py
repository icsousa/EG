"""Sentinela — parser (Lark LALR). Uso: python parser.py exemplos/01_port_scan.snt"""
import sys
from pathlib import Path
from lark import Lark, UnexpectedInput

GRAMATICA = Path(__file__).with_name("sentinela.lark")
PARSER = Lark(GRAMATICA.read_text(encoding="utf-8"), parser="lalr", propagate_positions=True)

def parse(texto: str):
    return PARSER.parse(texto)

if __name__ == "__main__":
    for ficheiro in sys.argv[1:]:
        try:
            arvore = parse(Path(ficheiro).read_text(encoding="utf-8"))
            print(f"✔ {ficheiro}")
            print(arvore.pretty())
        except UnexpectedInput as e:
            print(f"✘ {ficheiro}: erro de sintaxe na linha {e.line}, coluna {e.column}")
            print(e.get_context(Path(ficheiro).read_text(encoding="utf-8")))
