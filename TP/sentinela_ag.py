"""
Sentinela — Gramática de Atributos em LarkAG (formato usado nas aulas, EX04).

Especifica formalmente um SUBCONJUNTO das propriedades semânticas (o guião não exige todas):
  scopes (E101, E102), alertas (E103, E104, E201, E203, E204),
  tipos (E301 a E309), chamadas (E401 a E403), mutabilidade (E501, E502)
  e segredos (E601, E602).

Nota: os nomes dos atributos não podem coincidir com nomes de não-terminais
(por isso 'atab' e 'campos' em vez de 'alerts' e 'fields').

O LarkAG pára no PRIMEIRO erro (ContextConditionError). O verificador completo, que
reporta todos os erros e os avisos, está em verificador.py.

Instalar:  pip install "git+https://github.com/nmacedo/LarkAG.git@ag-soundness-fixes"
Uso:       python sentinela_ag.py exemplos/*.snt tests_semantica/*.snt

Convenções:
  - tipos são strings: "int", "bool", "string", "ip", "cidr", "duration", "list<T>", "A:nome" (alerta)
  - env: dict nome -> (tipo, espécie), espécie em {"var", "secret", "loop", "alias"}
  - loc: conjunto dos nomes declarados no scope atual (para E102)
  - sec: True se a expressão depende de um segredo
  - os nomes dos não-terminais não têm "_" (o LarkAG usa "_" para numerar alternativas)
"""

GRAMMAR = r"""
SA(start)    { atab : dict }
SA(alerts)   { tab : dict }
SA(alert)    { name : str, campos : dict }
SA(fields)   { tab : dict }
SA(field)    { name : str, ty : str }
SA(tipo)     { ty : str }
IA(playbook) { atab : dict }
IA(pdecls)   { env : dict, atab : dict }
SA(pdecls)   { envout : dict }
IA(handlers) { env : dict, atab : dict }
IA(handler)  { env : dict, atab : dict }
IA(block)    { env : dict, atab : dict }
IA(stmts)    { env : dict, loc : set, atab : dict }
SA(stmts)    { envout : dict, locout : set }
IA(stmt)     { env : dict, loc : set, atab : dict }
SA(stmt)     { envout : dict, locout : set }
IA(vdecl)    { env : dict, loc : set, atab : dict }
SA(vdecl)    { envout : dict, locout : set }
SA(fname)    { name : str, sig : tuple }
SA(ident)    { v : str }
IA(args)     { env : dict, atab : dict }
SA(args)     { tys : list, secs : list }
IA(expr)     { env : dict, atab : dict }
SA(expr)     { ty : str, sec : bool }
IA(conj)     { env : dict, atab : dict }
SA(conj)     { ty : str, sec : bool }
IA(neg)      { env : dict, atab : dict }
SA(neg)      { ty : str, sec : bool }
IA(rel)      { env : dict, atab : dict }
SA(rel)      { ty : str, sec : bool }
IA(soma)     { env : dict, atab : dict }
SA(soma)     { ty : str, sec : bool }
IA(post)     { env : dict, atab : dict }
SA(post)     { ty : str, sec : bool }
IA(prim)     { env : dict, atab : dict }
SA(prim)     { ty : str, sec : bool }
IA(items)    { env : dict, atab : dict }
SA(items)    { tys : list, sec : bool }

// ===================== Programa e alertas =====================
start : alerts playbook
ER {
  playbook.atab = alerts.tab;
  start.atab = alerts.tab;
}

alerts : alerts alert
ER {
  alerts[1].tab = alerts[2].tab | { alert.name : alert.campos };
}
CC {
  alert.name not in alerts[2].tab -> "E103: alerta declarado duas vezes";
}
|
ER {
  alerts.tab = {};
}

alert : "alert" NAME "{" fields "}"
ER {
  alert.name = str(NAME);
  alert.campos = fields.tab;
}

fields : fields field
ER {
  fields[1].tab = fields[2].tab | { field.name : field.ty };
}
CC {
  field.name not in fields[2].tab -> "E104: campo repetido no alerta";
}
|
ER {
  fields.tab = {};
}

field : NAME ":" tipo ";"
ER {
  field.name = str(NAME);
  field.ty = tipo.ty;
}

tipo : "int"      ER { tipo.ty = "int"; }
     | "bool"     ER { tipo.ty = "bool"; }
     | "string"   ER { tipo.ty = "string"; }
     | "ip"       ER { tipo.ty = "ip"; }
     | "cidr"     ER { tipo.ty = "cidr"; }
     | "duration" ER { tipo.ty = "duration"; }
     | "list" "<" tipo ">"
       ER { tipo[1].ty = "list<" + tipo[2].ty + ">"; }

// ===================== Playbook (estado persistente) =====================
playbook : "playbook" NAME "{" pdecls handlers "}"
ER {
  pdecls.env = {};
  pdecls.atab = playbook.atab;
  handlers.env = pdecls.envout;
  handlers.atab = playbook.atab;
}

pdecls : pdecls vdecl
ER {
  pdecls[2].env = pdecls[1].env;
  pdecls[2].atab = pdecls[1].atab;
  vdecl.env = pdecls[2].envout;
  vdecl.loc = set(pdecls[2].envout);
  vdecl.atab = pdecls[1].atab;
  pdecls[1].envout = vdecl.envout;
}
|
ER {
  pdecls.envout = pdecls.env;
}

handlers : handlers handler
ER {
  handlers[2].env = handlers[1].env;
  handlers[2].atab = handlers[1].atab;
  handler.env = handlers[1].env;
  handler.atab = handlers[1].atab;
}
| handler
ER {
  handler.env = handlers.env;
  handler.atab = handlers.atab;
}

handler : "on" ident "as" ident block
ER {
  block.env = handler.env | { ident[2].v : ("A:" + ident[1].v, "alias") };
  block.atab = handler.atab;
}
CC {
  ident[1].v in handler.atab -> "E201: handler para um alerta nao declarado";
}
| "every" DURATION block
ER {
  block.env = handler.env;
  block.atab = handler.atab;
}

// Um terminal não pode ser indexado (NAME[2]); por isso, quando há dois nomes, usa-se ident
ident : NAME
ER {
  ident.v = str(NAME);
}

// ===================== Blocos e instruções =====================
block : "{" stmts "}"
ER {
  stmts.env = block.env;
  stmts.loc = set();
  stmts.atab = block.atab;
}

stmts : stmts stmt
ER {
  stmts[2].env = stmts[1].env;
  stmts[2].loc = stmts[1].loc;
  stmts[2].atab = stmts[1].atab;
  stmt.env = stmts[2].envout;
  stmt.loc = stmts[2].locout;
  stmt.atab = stmts[1].atab;
  stmts[1].envout = stmt.envout;
  stmts[1].locout = stmt.locout;
}
|
ER {
  stmts.envout = stmts.env;
  stmts.locout = stmts.loc;
}

vdecl : "var" NAME ":" tipo "=" expr ";"
ER {
  expr.env = vdecl.env;
  expr.atab = vdecl.atab;
  vdecl.envout = vdecl.env | { str(NAME) : (tipo.ty, "var") };
  vdecl.locout = vdecl.loc | { str(NAME) };
}
CC {
  str(NAME) not in vdecl.loc -> "E102: variavel ja declarada neste scope";
  expr.ty == tipo.ty -> "E301: o valor nao tem o tipo declarado";
  not expr.sec -> "E602: um segredo nao pode ser guardado numa variavel normal";
}
| "secret" NAME ":" tipo "=" expr ";"
ER {
  expr.env = vdecl.env;
  expr.atab = vdecl.atab;
  vdecl.envout = vdecl.env | { str(NAME) : (tipo.ty, "secret") };
  vdecl.locout = vdecl.loc | { str(NAME) };
}
CC {
  str(NAME) not in vdecl.loc -> "E102: variavel ja declarada neste scope";
  expr.ty == tipo.ty -> "E301: o valor nao tem o tipo declarado";
}

stmt : vdecl
ER {
  vdecl.env = stmt.env;
  vdecl.loc = stmt.loc;
  vdecl.atab = stmt.atab;
  stmt.envout = vdecl.envout;
  stmt.locout = vdecl.locout;
}
| NAME "=" expr ";"
ER {
  expr.env = stmt.env;
  expr.atab = stmt.atab;
  stmt.envout = stmt.env;
  stmt.locout = stmt.loc;
}
CC {
  str(NAME) in stmt.env -> "E101: variavel nao declarada";
  stmt.env[str(NAME)][1] != "secret" -> "E501: nao e possivel alterar um segredo";
  stmt.env[str(NAME)][1] not in ("loop", "alias") -> "E502: variavel so de leitura";
  stmt.env[str(NAME)][0] == expr.ty -> "E301: o valor nao tem o tipo da variavel";
  not expr.sec -> "E602: um segredo nao pode ser guardado numa variavel normal";
}
| "if" "(" expr ")" block
ER {
  expr.env = stmt.env;
  expr.atab = stmt.atab;
  block.env = stmt.env;
  block.atab = stmt.atab;
  stmt.envout = stmt.env;
  stmt.locout = stmt.loc;
}
CC {
  expr.ty == "bool" -> "E308: a condicao do if tem de ser bool";
}
| "if" "(" expr ")" block "else" block
ER {
  expr.env = stmt.env;
  expr.atab = stmt.atab;
  block[1].env = stmt.env;
  block[1].atab = stmt.atab;
  block[2].env = stmt.env;
  block[2].atab = stmt.atab;
  stmt.envout = stmt.env;
  stmt.locout = stmt.loc;
}
CC {
  expr.ty == "bool" -> "E308: a condicao do if tem de ser bool";
}
| "for" NAME "in" expr block
ER {
  expr.env = stmt.env;
  expr.atab = stmt.atab;
  block.env = stmt.env | { str(NAME) : (expr.ty[5:-1], "loop") };
  block.atab = stmt.atab;
  stmt.envout = stmt.env;
  stmt.locout = stmt.loc;
}
CC {
  expr.ty.startswith("list<") -> "E309: o for tem de percorrer uma lista";
}
| fname "(" args ")" ";"
ER {
  args.env = stmt.env;
  args.atab = stmt.atab;
  stmt.envout = stmt.env;
  stmt.locout = stmt.loc;
}
CC {
  fname.sig is not None -> "E401: acao desconhecida";
  fname.sig[1] <= len(args.tys) <= len(fname.sig[0]) -> "E402: numero de argumentos errado";
  all(t in ps or "*" in ps or ("L" in ps and t.startswith("list<")) for t, ps in zip(args.tys, fname.sig[0])) -> "E403: argumento com tipo errado";
  not any(s for i, s in enumerate(args.secs) if not (fname.name == "notify" and i == 1)) -> "E601: um segredo so pode ir para a credencial do notify";
}

fname : NAME
ER {
  fname.name = str(NAME);
  fname.sig = {
    "block_ip":   ([{"ip", "cidr"}, {"duration"}], 2, None),
    "unblock_ip": ([{"ip", "cidr"}], 1, None),
    "quarantine": ([{"ip"}], 1, None),
    "rate_limit": ([{"ip"}, {"int"}], 2, None),
    "log":        ([{"string"}], 1, None),
    "notify":     ([{"string"}, {"string"}], 1, None),
    "count":      ([{"ip"}, {"duration"}], 2, "int"),
    "len":        ([{"L"}], 1, "int"),
    "str":        ([{"*"}], 1, "string")
  }.get(str(NAME));
}

args : args "," expr
ER {
  args[2].env = args[1].env;
  args[2].atab = args[1].atab;
  expr.env = args[1].env;
  expr.atab = args[1].atab;
  args[1].tys = args[2].tys + [expr.ty];
  args[1].secs = args[2].secs + [expr.sec];
}
| expr
ER {
  expr.env = args.env;
  expr.atab = args.atab;
  args.tys = [expr.ty];
  args.secs = [expr.sec];
}

// ===================== Expressões =====================
// Cada nível: herda env e alerts; sintetiza ty (tipo) e sec (depende de um segredo?)

expr : expr "or" conj
ER {
  expr[2].env = expr[1].env;
  expr[2].atab = expr[1].atab;
  conj.env = expr[1].env;
  conj.atab = expr[1].atab;
  expr[1].ty = "bool";
  expr[1].sec = expr[2].sec or conj.sec;
}
CC {
  expr[2].ty == "bool" and conj.ty == "bool" -> "E307: 'or' precisa de operandos bool";
}
| conj
ER {
  conj.env = expr.env;
  conj.atab = expr.atab;
  expr.ty = conj.ty;
  expr.sec = conj.sec;
}

conj : conj "and" neg
ER {
  conj[2].env = conj[1].env;
  conj[2].atab = conj[1].atab;
  neg.env = conj[1].env;
  neg.atab = conj[1].atab;
  conj[1].ty = "bool";
  conj[1].sec = conj[2].sec or neg.sec;
}
CC {
  conj[2].ty == "bool" and neg.ty == "bool" -> "E307: 'and' precisa de operandos bool";
}
| neg
ER {
  neg.env = conj.env;
  neg.atab = conj.atab;
  conj.ty = neg.ty;
  conj.sec = neg.sec;
}

neg : "not" neg
ER {
  neg[2].env = neg[1].env;
  neg[2].atab = neg[1].atab;
  neg[1].ty = "bool";
  neg[1].sec = neg[2].sec;
}
CC {
  neg[2].ty == "bool" -> "E307: 'not' precisa de um bool";
}
| rel
ER {
  rel.env = neg.env;
  rel.atab = neg.atab;
  neg.ty = rel.ty;
  neg.sec = rel.sec;
}

rel : soma RELOP soma
ER {
  soma[1].env = rel.env;
  soma[1].atab = rel.atab;
  soma[2].env = rel.env;
  soma[2].atab = rel.atab;
  rel.ty = "bool";
  rel.sec = soma[1].sec or soma[2].sec;
}
CC {
  str(RELOP) in ("==", "!=") or (soma[1].ty == soma[2].ty and soma[1].ty in ("int", "duration")) -> "E304: comparacao de ordem invalida";
  str(RELOP) not in ("==", "!=") or (soma[1].ty == soma[2].ty and not soma[1].ty.startswith("A:")) -> "E305: igualdade entre tipos diferentes";
}
| soma "in" soma
ER {
  soma[1].env = rel.env;
  soma[1].atab = rel.atab;
  soma[2].env = rel.env;
  soma[2].atab = rel.atab;
  rel.ty = "bool";
  rel.sec = soma[1].sec or soma[2].sec;
}
CC {
  soma[2].ty == "list<" + soma[1].ty + ">" or (soma[1].ty == "ip" and soma[2].ty == "cidr") -> "E306: 'in' com tipos invalidos";
}
| soma
ER {
  soma.env = rel.env;
  soma.atab = rel.atab;
  rel.ty = soma.ty;
  rel.sec = soma.sec;
}

soma : soma "+" post
ER {
  soma[2].env = soma[1].env;
  soma[2].atab = soma[1].atab;
  post.env = soma[1].env;
  post.atab = soma[1].atab;
  soma[1].ty = post.ty;
  soma[1].sec = soma[2].sec or post.sec;
}
CC {
  soma[2].ty == post.ty and post.ty in ("int", "string", "duration") -> "E302: '+' com tipos invalidos";
}
| soma "-" post
ER {
  soma[2].env = soma[1].env;
  soma[2].atab = soma[1].atab;
  post.env = soma[1].env;
  post.atab = soma[1].atab;
  soma[1].ty = post.ty;
  soma[1].sec = soma[2].sec or post.sec;
}
CC {
  soma[2].ty == post.ty and post.ty in ("int", "duration") -> "E303: '-' com tipos invalidos";
}
| post
ER {
  post.env = soma.env;
  post.atab = soma.atab;
  soma.ty = post.ty;
  soma.sec = post.sec;
}

post : post "." NAME
ER {
  post[2].env = post[1].env;
  post[2].atab = post[1].atab;
  post[1].ty = post[1].atab.get(post[2].ty[2:], {}).get(str(NAME), "?");
  post[1].sec = post[2].sec;
}
CC {
  post[2].ty.startswith("A:") -> "E203: so se acede a campos de um alerta";
  str(NAME) in post[1].atab[post[2].ty[2:]] -> "E204: campo inexistente no alerta";
}
| prim
ER {
  prim.env = post.env;
  prim.atab = post.atab;
  post.ty = prim.ty;
  post.sec = prim.sec;
}

prim : NAME
ER {
  prim.ty = prim.env.get(str(NAME), ("?", "var"))[0];
  prim.sec = prim.env.get(str(NAME), ("?", "var"))[1] == "secret";
}
CC {
  str(NAME) in prim.env -> "E101: variavel nao declarada";
}
| fname "(" args ")"
ER {
  args.env = prim.env;
  args.atab = prim.atab;
  prim.ty = fname.sig[2] if fname.sig else "?";
  prim.sec = any(args.secs);
}
CC {
  fname.sig is not None -> "E401: funcao desconhecida";
  fname.sig[2] is not None -> "E405: esta acao nao devolve valor";
  fname.sig[1] <= len(args.tys) <= len(fname.sig[0]) -> "E402: numero de argumentos errado";
  all(t in ps or "*" in ps or ("L" in ps and t.startswith("list<")) for t, ps in zip(args.tys, fname.sig[0])) -> "E403: argumento com tipo errado";
}
| "(" expr ")"
ER {
  expr.env = prim.env;
  expr.atab = prim.atab;
  prim.ty = expr.ty;
  prim.sec = expr.sec;
}
| "[" items "]"
ER {
  items.env = prim.env;
  items.atab = prim.atab;
  prim.ty = "list<" + items.tys[0] + ">";
  prim.sec = items.sec;
}
CC {
  len(set(items.tys)) == 1 -> "E310: lista com elementos de tipos diferentes";
}
| INT      ER { prim.ty = "int";      prim.sec = False; }
| STRING   ER { prim.ty = "string";   prim.sec = False; }
| CIDR     ER { prim.ty = "cidr";     prim.sec = False; }
| IP       ER { prim.ty = "ip";       prim.sec = False; }
| DURATION ER { prim.ty = "duration"; prim.sec = False; }
| BOOL     ER { prim.ty = "bool";     prim.sec = False; }

items : items "," expr
ER {
  items[2].env = items[1].env;
  items[2].atab = items[1].atab;
  expr.env = items[1].env;
  expr.atab = items[1].atab;
  items[1].tys = items[2].tys + [expr.ty];
  items[1].sec = items[2].sec or expr.sec;
}
| expr
ER {
  expr.env = items.env;
  expr.atab = items.atab;
  items.tys = [expr.ty];
  items.sec = expr.sec;
}

// ===================== Terminais =====================
RELOP    : "==" | "!=" | "<=" | ">=" | "<" | ">"
BOOL.2   : "true" | "false"
CIDR.5   : /\d{1,3}(\.\d{1,3}){3}\/\d{1,2}/
IP.4     : /\d{1,3}(\.\d{1,3}){3}/
DURATION.3 : /\d+(s|m|h)\b/
INT      : /\d+/
STRING   : /"[^"]*"/
NAME     : /[a-zA-Z_][a-zA-Z0-9_]*/
COMMENT  : /\#[^\n]*/

%import common.WS
%ignore WS
%ignore COMMENT
"""

if __name__ == "__main__":
    import sys
    from pathlib import Path
    from lark_ag import Lark_AG, ContextConditionError

    parser = Lark_AG(GRAMMAR)
    for ficheiro in sys.argv[1:]:
        try:
            parser.process(Path(ficheiro).read_text(encoding="utf-8"))
            print(f"✔ {ficheiro}")
        except ContextConditionError as e:
            print(f"✘ {ficheiro}: {e}")
