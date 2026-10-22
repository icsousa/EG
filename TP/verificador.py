"""
Sentinela — verificador semântico (avaliação da gramática de atributos).

Atributos herdados  -> passados como argumentos:  env (scopes), em_condicao, em_handler
Atributos sintetizados -> valores de retorno:      (tipo, secreto) das expressões, lista de erros

Uso: python verificador.py exemplos/*.snt
"""
import sys
from dataclasses import dataclass, field
from pathlib import Path
from lark import Tree, Token
from parser import parse

# ---------------------------------------------------------------- tipos
# Tipos: 'int' 'bool' 'string' 'ip' 'cidr' 'duration', ('list', T), ('alert', nome)
# None = tipo desconhecido (⊥): resulta de um erro já reportado e é compatível com tudo,
#        para não gerar erros em cascata.

def nome_tipo(t):
    if t is None:
        return "?"
    if isinstance(t, tuple):
        return f"list<{nome_tipo(t[1])}>" if t[0] == "list" else f"alerta {t[1]}"
    return t

def compativel(esperado, obtido):
    return esperado is None or obtido is None or esperado == obtido

def eh_lista(t):
    return isinstance(t, tuple) and t[0] == "list"

# ---------------------------------------------------------------- biblioteca predefinida
# nome: (parâmetros, tipo devolvido, destrutiva). Cada parâmetro é um conjunto de tipos aceites;
# 'any' aceita qualquer tipo, 'list' aceita qualquer lista. Parâmetros com '?' são opcionais.
BIBLIOTECA = {
    "block_ip":   ([{"ip", "cidr"}, {"duration"}], None, True),
    "unblock_ip": ([{"ip", "cidr"}], None, False),
    "quarantine": ([{"ip"}], None, True),
    "rate_limit": ([{"ip"}, {"int"}], None, False),
    "log":        ([{"string"}], None, False),
    "notify":     ([{"string"}, {"string", "?"}], None, False),   # 2.º = credencial (opcional)
    "count":      ([{"ip"}, {"duration"}], "int", False),
    "len":        ([{"list"}], "int", False),
    "str":        ([{"any"}], "string", False),
}

# ---------------------------------------------------------------- símbolos e erros
@dataclass
class Simbolo:
    tipo: object
    tipo_simbolo: str          # 'var' | 'secret' | 'loop' | 'alias'
    linha: int
    usado: bool = False

@dataclass(order=True)
class Diagnostico:
    linha: int
    codigo: str
    mensagem: str = field(compare=False)

    def __str__(self):
        nivel = "aviso" if self.codigo.startswith("W") else "erro"
        return f"linha {self.linha}: {nivel} {self.codigo}: {self.mensagem}"


class Ambiente:
    """Pilha de scopes (atributo herdado env)."""

    def __init__(self, verificador):
        self.scopes = []
        self.v = verificador

    def abrir(self):
        self.scopes.append({})

    def fechar(self):
        for nome, s in self.scopes.pop().items():
            if not s.usado and s.tipo_simbolo in ("var", "secret"):
                self.v.diag("W02", s.linha, f"'{nome}' é declarada mas nunca é usada")

    def declarar(self, nome, simbolo):
        if nome in self.scopes[-1]:
            self.v.diag("E102", simbolo.linha, f"'{nome}' já foi declarada neste scope (linha {self.scopes[-1][nome].linha})")
            return
        if any(nome in s for s in self.scopes[:-1]):
            self.v.diag("W03", simbolo.linha, f"'{nome}' esconde uma declaração de um scope exterior")
        self.scopes[-1][nome] = simbolo

    def procurar(self, nome):
        for s in reversed(self.scopes):
            if nome in s:
                return s[nome]
        return None


class Verificador:
    def __init__(self):
        self.erros = []
        self.alertas = {}            # nome -> {campo: tipo}
        self.env = Ambiente(self)

    def diag(self, codigo, linha, mensagem):
        self.erros.append(Diagnostico(linha, codigo, mensagem))

    # ------------------------------------------------------------ programa
    def verificar(self, arvore):
        *alertas, playbook = arvore.children
        for a in alertas:                                   # passagem 1: recolher alertas
            self.alert_decl(a)
        self.playbook(playbook)                             # passagem 2: playbook
        unicos = {(d.linha, d.codigo, d.mensagem): d for d in self.erros}
        return sorted(unicos.values())

    def alert_decl(self, t):
        nome, *campos = t.children
        if nome in self.alertas:
            self.diag("E103", nome.line, f"o alerta '{nome}' já foi declarado")
            return
        tabela = {}
        for c in campos:
            cnome, ctipo = c.children
            if cnome in tabela:
                self.diag("E104", cnome.line, f"campo '{cnome}' repetido no alerta '{nome}'")
            tabela[str(cnome)] = self.tipo(ctipo)
        self.alertas[str(nome)] = tabela

    def tipo(self, t):
        if t.data == "basic_type":
            return str(t.children[0])
        return ("list", self.tipo(t.children[0]))

    def playbook(self, t):
        _, *itens = t.children
        self.env.abrir()                                    # scope do playbook (estado persistente)
        tratados = set()
        for item in itens:
            if item.data == "var_decl":
                self.var_decl(item, em_condicao=False, nivel_playbook=True)
            elif item.data == "on_handler":
                alerta, alias, bloco = item.children
                if str(alerta) not in self.alertas:
                    self.diag("E201", alerta.line, f"não existe nenhum alerta '{alerta}' declarado")
                elif str(alerta) in tratados:
                    self.diag("E202", alerta.line, f"já existe um handler para o alerta '{alerta}'")
                tratados.add(str(alerta))
                tipo_alias = ("alert", str(alerta)) if str(alerta) in self.alertas else None
                self.env.abrir()
                self.env.declarar(str(alias), Simbolo(tipo_alias, "alias", alias.line))
                self.bloco(bloco, em_condicao=False, novo_scope=False)
                self.env.fechar()
            else:                                           # every_handler
                duracao, bloco = item.children
                self.literal_duracao(duracao)
                self.bloco(bloco, em_condicao=False)
        for nome in self.alertas:
            if nome not in tratados:
                self.diag("W04", t.meta.line, f"o alerta '{nome}' está declarado mas não tem handler")
        self.env.fechar()

    # ------------------------------------------------------------ instruções
    def bloco(self, t, em_condicao, novo_scope=True):
        if novo_scope:
            self.env.abrir()
        for s in t.children:
            self.instrucao(s, em_condicao)
        if novo_scope:
            self.env.fechar()

    def instrucao(self, s, em_condicao):
        getattr(self, s.data)(s, em_condicao=em_condicao)

    def var_decl(self, t, em_condicao, nivel_playbook=False):
        kind, nome, ttipo, expr = t.children
        kind = str(kind.children[0])                        # 'var' | 'secret'
        declarado = self.tipo(ttipo)
        obtido, secreto = self.expr(expr)
        if kind == "secret" and not nivel_playbook:
            self.diag("E105", nome.line, f"o segredo '{nome}' só pode ser declarado ao nível do playbook")
        if not compativel(declarado, obtido):
            self.diag("E301", nome.line, f"'{nome}' é {nome_tipo(declarado)} mas o valor é {nome_tipo(obtido)}")
        if secreto and kind == "var":
            self.diag("E602", nome.line, f"um segredo não pode ser guardado na variável normal '{nome}'")
        self.env.declarar(str(nome), Simbolo(declarado, kind, nome.line))

    def assign(self, t, em_condicao):
        nome, expr = t.children
        obtido, secreto = self.expr(expr)
        s = self.env.procurar(str(nome))
        if s is None:
            self.diag("E101", nome.line, f"'{nome}' não foi declarada")
            return
        if s.tipo_simbolo == "secret":
            self.diag("E501", nome.line, f"não é possível alterar o segredo '{nome}'")
        elif s.tipo_simbolo in ("loop", "alias"):
            self.diag("E502", nome.line, f"'{nome}' é só de leitura (variável do for ou alias do alerta)")
        elif not compativel(s.tipo, obtido):
            self.diag("E301", nome.line, f"'{nome}' é {nome_tipo(s.tipo)} mas o valor é {nome_tipo(obtido)}")
        if secreto and s.tipo_simbolo == "var":
            self.diag("E602", nome.line, f"um segredo não pode ser guardado na variável normal '{nome}'")

    def if_stmt(self, t, em_condicao):
        cond, entao, senao = t.children
        tipo, secreto = self.expr(cond)
        linha = cond.meta.line if isinstance(cond, Tree) else cond.line
        if not compativel("bool", tipo):
            self.diag("E308", linha, f"a condição do if tem de ser bool, mas é {nome_tipo(tipo)}")
        if secreto:
            self.diag("E603", linha, "um segredo não pode ser usado numa condição (fuga implícita)")
        if isinstance(cond, Tree) and cond.data == "bool_lit":
            self.diag("W05", linha, f"a condição é sempre {cond.children[0]}")
        self.bloco(entao, em_condicao=True)
        if senao is not None:
            self.bloco(senao, em_condicao=True)

    def for_stmt(self, t, em_condicao):
        var, expr, corpo = t.children
        tipo, secreto = self.expr(expr)
        elem = None
        if eh_lista(tipo):
            elem = tipo[1]
        elif tipo is not None:
            self.diag("E309", var.line, f"o for tem de percorrer uma lista, mas recebeu {nome_tipo(tipo)}")
        if secreto:
            self.diag("E603", var.line, "um segredo não pode controlar um ciclo (fuga implícita)")
        self.env.abrir()
        self.env.declarar(str(var), Simbolo(elem, "loop", var.line))
        self.bloco(corpo, em_condicao, novo_scope=False)
        self.env.fechar()

    def action(self, t, em_condicao):
        nome, *args = t.children
        args = [a for a in args if a is not None]
        if str(nome) in BIBLIOTECA and BIBLIOTECA[str(nome)][1] is not None:
            self.diag("E404", nome.line, f"'{nome}' devolve um valor e não pode ser usada como instrução")
        self.chamada(nome, args, como_instrucao=True)
        if str(nome) in BIBLIOTECA and BIBLIOTECA[str(nome)][2] and not em_condicao:
            self.diag("W01", nome.line, f"a ação destrutiva '{nome}' é executada sem nenhuma condição")

    # ------------------------------------------------------------ chamadas
    def chamada(self, nome, args, como_instrucao):
        """Verifica a chamada; devolve (tipo devolvido, secreto)."""
        tipos = [self.expr(a) for a in args]
        secreto = any(s for _, s in tipos)
        if str(nome) not in BIBLIOTECA:
            self.diag("E401", nome.line, f"'{nome}' não é uma ação nem uma função conhecida")
            return None, secreto
        params, ret, _ = BIBLIOTECA[str(nome)]
        obrigatorios = [p for p in params if "?" not in p]
        if not (len(obrigatorios) <= len(args) <= len(params)):
            esperado = str(len(params)) if len(obrigatorios) == len(params) else f"{len(obrigatorios)} a {len(params)}"
            self.diag("E402", nome.line, f"'{nome}' recebe {esperado} argumento(s), mas recebeu {len(args)}")
        for i, ((tipo, sec), param) in enumerate(zip(tipos, params)):
            aceita = (tipo is None or "any" in param or tipo in param or ("list" in param and eh_lista(tipo)))
            if not aceita:
                esperado = " ou ".join(sorted(p for p in param if p != "?"))
                self.diag("E403", nome.line, f"o {i + 1}.º argumento de '{nome}' devia ser {esperado}, mas é {nome_tipo(tipo)}")
            credencial = str(nome) == "notify" and i == 1
            if sec and como_instrucao and not credencial:
                self.diag("E601", nome.line, f"um segredo não pode ser passado a '{nome}' (só como credencial do notify)")
        return ret, secreto

    # ------------------------------------------------------------ expressões
    def expr(self, e):
        """Atributos sintetizados de uma expressão: (tipo, secreto)."""
        return getattr(self, "e_" + e.data)(e)

    def e_int_lit(self, e):  return "int", False
    def e_str_lit(self, e):  return "string", False
    def e_bool_lit(self, e): return "bool", False

    def e_ip_lit(self, e):
        tok = e.children[0]
        if any(int(o) > 255 for o in str(tok).split(".")):
            self.diag("E701", tok.line, f"'{tok}' não é um endereço IPv4 válido")
        return "ip", False

    def e_cidr_lit(self, e):
        tok = e.children[0]
        endereco, prefixo = str(tok).split("/")
        if any(int(o) > 255 for o in endereco.split(".")):
            self.diag("E701", tok.line, f"'{endereco}' não é um endereço IPv4 válido")
        if int(prefixo) > 32:
            self.diag("E702", tok.line, f"o prefixo /{prefixo} é inválido (máximo /32)")
        return "cidr", False

    def e_dur_lit(self, e):
        self.literal_duracao(e.children[0])
        return "duration", False

    def literal_duracao(self, tok):
        if int(str(tok)[:-1]) == 0:
            self.diag("E703", tok.line, f"a duração '{tok}' tem de ser maior que zero")

    def e_var(self, e):
        nome = e.children[0]
        s = self.env.procurar(str(nome))
        if s is None:
            self.diag("E101", nome.line, f"'{nome}' não foi declarada")
            return None, False
        s.usado = True
        return s.tipo, s.tipo_simbolo == "secret"

    def e_field_access(self, e):
        alvo, campo = e.children
        tipo, secreto = self.expr(alvo)
        if tipo is None:
            return None, secreto
        if not (isinstance(tipo, tuple) and tipo[0] == "alert"):
            self.diag("E203", campo.line, f"não é possível aceder a '.{campo}' num valor do tipo {nome_tipo(tipo)}")
            return None, secreto
        campos = self.alertas[tipo[1]]
        if str(campo) not in campos:
            self.diag("E204", campo.line, f"o alerta '{tipo[1]}' não tem o campo '{campo}' (campos: {', '.join(campos)})")
            return None, secreto
        return campos[str(campo)], secreto

    def e_call(self, e):
        nome, *args = e.children
        args = [a for a in args if a is not None]
        if str(nome) in BIBLIOTECA and BIBLIOTECA[str(nome)][1] is None:
            self.diag("E405", nome.line, f"'{nome}' é uma ação e não devolve valor")
            self.chamada(nome, args, como_instrucao=False)
            return None, False
        return self.chamada(nome, args, como_instrucao=False)

    def e_list_lit(self, e):
        itens = [i for i in e.children if i is not None]
        linha = e.meta.line
        if not itens:
            self.diag("E310", linha, "a lista vazia não tem tipo; use pelo menos um elemento")
            return None, False
        tipos = [self.expr(i) for i in itens]
        conhecidos = {t for t, _ in tipos if t is not None}
        if len(conhecidos) > 1:
            self.diag("E310", linha, f"lista com elementos de tipos diferentes: {', '.join(sorted(map(nome_tipo, conhecidos)))}")
            return None, any(s for _, s in tipos)
        return ("list", conhecidos.pop() if conhecidos else None), any(s for _, s in tipos)

    def e_not_(self, e):
        tipo, sec = self.expr(e.children[0])
        if not compativel("bool", tipo):
            self.diag("E307", e.meta.line, f"'not' precisa de um bool, mas recebeu {nome_tipo(tipo)}")
        return "bool", sec

    def _logico(self, e, op):
        (ta, sa), (tb, sb) = self.expr(e.children[0]), self.expr(e.children[1])
        for t in (ta, tb):
            if not compativel("bool", t):
                self.diag("E307", e.meta.line, f"'{op}' precisa de operandos bool, mas recebeu {nome_tipo(t)}")
        return "bool", sa or sb

    def e_and_(self, e): return self._logico(e, "and")
    def e_or_(self, e):  return self._logico(e, "or")

    def e_arith(self, e):
        a, op, b = e.children
        (ta, sa), (tb, sb) = self.expr(a), self.expr(b)
        op = str(op.children[0])
        permitidos = {"+": {"int", "string", "duration"}, "-": {"int", "duration"}}[op]
        if ta is None or tb is None:
            return None, sa or sb
        if ta != tb or ta not in permitidos:
            codigo = "E302" if op == "+" else "E303"
            dica = " (use str() para converter)" if op == "+" and "string" in (ta, tb) else ""
            self.diag(codigo, e.meta.line, f"'{op}' não se aplica a {nome_tipo(ta)} e {nome_tipo(tb)}{dica}")
            return None, sa or sb
        return ta, sa or sb

    def e_cmp(self, e):
        a, op, b = e.children
        (ta, sa), (tb, sb) = self.expr(a), self.expr(b)
        op = str(op.children[0])
        sec = sa or sb
        if ta is None or tb is None:
            return "bool", sec
        if op in ("<", ">", "<=", ">="):
            if ta != tb or ta not in ("int", "duration"):
                self.diag("E304", e.meta.line, f"'{op}' só compara int ou duration do mesmo tipo, não {nome_tipo(ta)} e {nome_tipo(tb)}")
        elif op in ("==", "!="):
            if ta != tb or eh_lista(ta) or isinstance(ta, tuple):
                self.diag("E305", e.meta.line, f"'{op}' não pode comparar {nome_tipo(ta)} com {nome_tipo(tb)}")
        else:  # in
            ok = (eh_lista(tb) and compativel(tb[1], ta)) or (ta == "ip" and tb == "cidr")
            if not ok:
                self.diag("E306", e.meta.line, f"'in' não se aplica a {nome_tipo(ta)} e {nome_tipo(tb)} (use T in list<T> ou ip in cidr)")
        return "bool", sec


def check(texto):
    return Verificador().verificar(parse(texto))


if __name__ == "__main__":
    for ficheiro in sys.argv[1:]:
        diags = check(Path(ficheiro).read_text(encoding="utf-8"))
        print(f"{'✔' if not diags else '✘'} {ficheiro}: {len(diags)} diagnóstico(s)")
        for d in diags:
            print("   ", d)
