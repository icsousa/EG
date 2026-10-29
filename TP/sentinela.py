"""
Sentinela — processador da linguagem.

Lê a gramática de atributos (sentinela.ag), gera com o LarkAG o avaliador de
atributos e aplica-o a um playbook:

  1. análise léxica e sintática (parser LALR(1) gerado a partir da GIC do sentinela.ag);
  2. avaliação dos atributos e das condições de contexto (LarkAG);
  3. resultado: o primeiro erro (com a linha), ou os avisos.

Uso:
  python sentinela.py exemplos/*.snt          verificar playbooks
  python sentinela.py --arvore ficheiro.snt   mostrar também a árvore sintática
"""
import sys
from dataclasses import dataclass, field
from pathlib import Path

from lark import Lark, Tree, UnexpectedInput
from lark_ag import Lark_AG, ContextConditionError

GRAMATICA = Path(__file__).with_name("sentinela.ag")

AG = Lark_AG(GRAMATICA.read_text(encoding="utf-8"))
PARSER = Lark(AG.getCFG(), parser="lalr", propagate_positions=True)


@dataclass
class Diagnostico:
    codigo: str
    linha: int
    mensagem: str

    def __str__(self):
        nivel = "aviso" if self.codigo.startswith("W") else "erro"
        return f"linha {self.linha}: {nivel} {self.codigo}: {self.mensagem}"


@dataclass
class Resultado:
    erro: Diagnostico | None = None              # erro sintático ou semântico (o primeiro)
    avisos: list[Diagnostico] = field(default_factory=list)

    @property
    def ativo(self):
        """Um playbook só é ativado se não tiver erros."""
        return self.erro is None


def parse(texto: str) -> Tree:
    return PARSER.parse(texto)


def _linha(pilha):
    """Linha do nó mais interior (com posição) que estava a ser avaliado."""
    for no in reversed(pilha):
        if isinstance(no, Tree) and not no.meta.empty:
            return no.meta.line
    return 0


def analisar(texto: str) -> Resultado:
    try:
        arvore = parse(texto)
    except UnexpectedInput as e:
        return Resultado(erro=Diagnostico("SINTAXE", e.line, "programa mal formado"))

    avaliador = AG.getInterpreter()
    visitar = avaliador.visit
    pilha = []

    def visitar_com_pilha(no):          # guarda o caminho até ao nó em avaliação,
        pilha.append(no)                # para saber a linha de um erro
        resultado = visitar(no)
        pilha.pop()
        return resultado

    avaliador.visit = visitar_com_pilha
    try:
        visitar_com_pilha(arvore)
    except ContextConditionError as e:
        codigo, _, mensagem = str(e).partition(": ")
        return Resultado(erro=Diagnostico(codigo, _linha(pilha), mensagem))

    return Resultado(avisos=[Diagnostico(c, l, m) for c, l, m in arvore.warnings])


def main(argumentos):
    mostrar_arvore = "--arvore" in argumentos
    ficheiros = [a for a in argumentos if a != "--arvore"]
    for ficheiro in ficheiros:
        texto = Path(ficheiro).read_text(encoding="utf-8")
        r = analisar(texto)
        estado = "✔ ativo" if r.ativo else "✘ rejeitado"
        print(f"{estado}  {ficheiro}")
        if r.erro:
            print(f"    {r.erro}")
        for aviso in r.avisos:
            print(f"    {aviso}")
        if mostrar_arvore and r.erro is None:
            print(parse(texto).pretty())


if __name__ == "__main__":
    main(sys.argv[1:])
