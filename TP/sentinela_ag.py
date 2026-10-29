"""
Sentinela — exemplo em LarkAG de uma PARTE da gramática de atributos (formato das aulas, EX04).

A gramática de atributos COMPLETA está especificada em GRAMATICA.md; este ficheiro torna
executável um subconjunto das suas condições de contexto (o guião não exige todas):
  scopes (E101, E102), alertas (E103, E104, E201, E203, E204),
  tipos (E301 a E310), chamadas (E401 a E403, E405), mutabilidade (E501, E502)
  e segredos (E601, E602).

O LarkAG para no PRIMEIRO erro (ContextConditionError). O verificador completo, que
reporta todos os erros e os avisos, está em verificador.py.

Instalar:  pip install "git+https://github.com/nmacedo/LarkAG.git@ag-soundness-fixes"
Uso:       python sentinela_ag.py exemplos/*.snt

Nomes: os mesmos de sentinela.lark e de GRAMATICA.md (inglês, minúsculas, sem "_",
porque o LarkAG usa "_" para numerar alternativas). Um atributo não pode ter o nome de
um não-terminal: por isso "alerttab" e "fieldtab" em vez de "alerts" e "fields".

Atributos:
  alerttab  (herdado)     tabela dos alertas: nome -> {campo: tipo}
  env       (herdado)     variáveis visíveis: nome -> (tipo, espécie), espécie em
                          {"var", "secret", "loop", "alias"}
  scope     (herdado)     nomes já declarados no scope atual (E102)
  envout, scopeout (sint.) env e scope depois de uma declaração
  type      (sintetizado) tipo da expressão: "int", "bool", "string", "ip", "cidr",
                          "duration", "list<T>", "A:nome" (alias de um alerta)
  secret    (sintetizado) a expressão depende de um segredo?
  types, secrets (sint.)  listas com o tipo / segredo de cada argumento
  signature (sintetizado) assinatura de uma ação ou função da biblioteca
"""

GRAMMAR = r"""
SA(start)        { alerttab : dict }
SA(alerts)       { table : dict }
SA(alert)        { name : str, fieldtab : dict }
SA(fields)       { table : dict }
SA(field)        { name : str, type : str }
SA(datatype)     { type : str }
IA(playbook)     { alerttab : dict }
IA(statedecls)   { env : dict, alerttab : dict }
SA(statedecls)   { envout : dict }
IA(handlers)     { env : dict, alerttab : dict }
IA(handler)      { env : dict, alerttab : dict }
IA(block)        { env : dict, scope : set, alerttab : dict }
IA(stmts)        { env : dict, scope : set, alerttab : dict }
SA(stmts)        { envout : dict, scopeout : set }
IA(stmt)         { env : dict, scope : set, alerttab : dict }
SA(stmt)         { envout : dict, scopeout : set }
IA(vardecl)      { env : dict, scope : set, alerttab : dict }
SA(vardecl)      { envout : dict, scopeout : set }
SA(callee)       { name : str, signature : tuple }
SA(ident)        { name : str }
IA(args)         { env : dict, alerttab : dict }
SA(args)         { types : list, secrets : list }
IA(expr)         { env : dict, alerttab : dict }
SA(expr)         { type : str, secret : bool }
IA(andexpr)      { env : dict, alerttab : dict }
SA(andexpr)      { type : str, secret : bool }
IA(notexpr)      { env : dict, alerttab : dict }
SA(notexpr)      { type : str, secret : bool }
IA(relexpr)      { env : dict, alerttab : dict }
SA(relexpr)      { type : str, secret : bool }
IA(addexpr)      { env : dict, alerttab : dict }
SA(addexpr)      { type : str, secret : bool }
IA(accessexpr)   { env : dict, alerttab : dict }
SA(accessexpr)   { type : str, secret : bool }
IA(primary)      { env : dict, alerttab : dict }
SA(primary)      { type : str, secret : bool }
IA(items)        { env : dict, alerttab : dict }
SA(items)        { types : list, secret : bool }

// ===================== Programa e alertas =====================
start : alerts playbook
ER {
  playbook.alerttab = alerts.table;
  start.alerttab = alerts.table;
}

alerts : alerts alert
ER {
  alerts[1].table = alerts[2].table | { alert.name : alert.fieldtab };
}
CC {
  alert.name not in alerts[2].table -> "E103: alerta declarado duas vezes";
}
|
ER {
  alerts.table = {};
}

alert : "alert" NAME "{" fields "}"
ER {
  alert.name = str(NAME);
  alert.fieldtab = fields.table;
}

fields : fields field
ER {
  fields[1].table = fields[2].table | { field.name : field.type };
}
CC {
  field.name not in fields[2].table -> "E104: campo repetido no alerta";
}
|
ER {
  fields.table = {};
}

field : NAME ":" datatype ";"
ER {
  field.name = str(NAME);
  field.type = datatype.type;
}

datatype : "int"      ER { datatype.type = "int"; }
         | "bool"     ER { datatype.type = "bool"; }
         | "string"   ER { datatype.type = "string"; }
         | "ip"       ER { datatype.type = "ip"; }
         | "cidr"     ER { datatype.type = "cidr"; }
         | "duration" ER { datatype.type = "duration"; }
         | "list" "<" datatype ">"
       ER { datatype[1].type = "list<" + datatype[2].type + ">"; }

// ===================== Playbook (estado persistente) =====================
playbook : "playbook" NAME "{" statedecls handlers "}"
ER {
  statedecls.env = {};
  statedecls.alerttab = playbook.alerttab;
  handlers.env = statedecls.envout;
  handlers.alerttab = playbook.alerttab;
}

statedecls : statedecls vardecl
ER {
  statedecls[2].env = statedecls[1].env;
  statedecls[2].alerttab = statedecls[1].alerttab;
  vardecl.env = statedecls[2].envout;
  vardecl.scope = set(statedecls[2].envout);
  vardecl.alerttab = statedecls[1].alerttab;
  statedecls[1].envout = vardecl.envout;
}
|
ER {
  statedecls.envout = statedecls.env;
}

handlers : handlers handler
ER {
  handlers[2].env = handlers[1].env;
  handlers[2].alerttab = handlers[1].alerttab;
  handler.env = handlers[1].env;
  handler.alerttab = handlers[1].alerttab;
}
| handler
ER {
  handler.env = handlers.env;
  handler.alerttab = handlers.alerttab;
}

handler : "on" ident "as" ident block
ER {
  block.env = handler.env | { ident[2].name : ("A:" + ident[1].name, "alias") };
  block.scope = { ident[2].name };
  block.alerttab = handler.alerttab;
}
CC {
  ident[1].name in handler.alerttab -> "E201: handler para um alerta nao declarado";
}
| "every" DURATION block
ER {
  block.env = handler.env;
  block.scope = set();
  block.alerttab = handler.alerttab;
}

// Um terminal não pode ser indexado (NAME[2]); por isso, quando há dois nomes, usa-se ident
ident : NAME
ER {
  ident.name = str(NAME);
}

// ===================== Blocos e instruções =====================
block : "{" stmts "}"
ER {
  stmts.env = block.env;
  stmts.scope = block.scope;
  stmts.alerttab = block.alerttab;
}

stmts : stmts stmt
ER {
  stmts[2].env = stmts[1].env;
  stmts[2].scope = stmts[1].scope;
  stmts[2].alerttab = stmts[1].alerttab;
  stmt.env = stmts[2].envout;
  stmt.scope = stmts[2].scopeout;
  stmt.alerttab = stmts[1].alerttab;
  stmts[1].envout = stmt.envout;
  stmts[1].scopeout = stmt.scopeout;
}
|
ER {
  stmts.envout = stmts.env;
  stmts.scopeout = stmts.scope;
}

vardecl : "var" NAME ":" datatype "=" expr ";"
ER {
  expr.env = vardecl.env;
  expr.alerttab = vardecl.alerttab;
  vardecl.envout = vardecl.env | { str(NAME) : (datatype.type, "var") };
  vardecl.scopeout = vardecl.scope | { str(NAME) };
}
CC {
  str(NAME) not in vardecl.scope -> "E102: variavel ja declarada neste scope";
  expr.type == datatype.type -> "E301: o valor nao tem o datatype declarado";
  not expr.secret -> "E602: um segredo nao pode ser guardado numa variavel normal";
}
| "secret" NAME ":" datatype "=" expr ";"
ER {
  expr.env = vardecl.env;
  expr.alerttab = vardecl.alerttab;
  vardecl.envout = vardecl.env | { str(NAME) : (datatype.type, "secret") };
  vardecl.scopeout = vardecl.scope | { str(NAME) };
}
CC {
  str(NAME) not in vardecl.scope -> "E102: variavel ja declarada neste scope";
  expr.type == datatype.type -> "E301: o valor nao tem o datatype declarado";
}

stmt : vardecl
ER {
  vardecl.env = stmt.env;
  vardecl.scope = stmt.scope;
  vardecl.alerttab = stmt.alerttab;
  stmt.envout = vardecl.envout;
  stmt.scopeout = vardecl.scopeout;
}
| NAME "=" expr ";"
ER {
  expr.env = stmt.env;
  expr.alerttab = stmt.alerttab;
  stmt.envout = stmt.env;
  stmt.scopeout = stmt.scope;
}
CC {
  str(NAME) in stmt.env -> "E101: variavel nao declarada";
  stmt.env[str(NAME)][1] != "secret" -> "E501: nao e possivel alterar um segredo";
  stmt.env[str(NAME)][1] not in ("loop", "alias") -> "E502: variavel so de leitura";
  stmt.env[str(NAME)][0] == expr.type -> "E301: o valor nao tem o datatype da variavel";
  not expr.secret -> "E602: um segredo nao pode ser guardado numa variavel normal";
}
| "if" "(" expr ")" block
ER {
  expr.env = stmt.env;
  expr.alerttab = stmt.alerttab;
  block.env = stmt.env;
  block.scope = set();
  block.alerttab = stmt.alerttab;
  stmt.envout = stmt.env;
  stmt.scopeout = stmt.scope;
}
CC {
  expr.type == "bool" -> "E308: a condicao do if tem de ser bool";
}
| "if" "(" expr ")" block "else" block
ER {
  expr.env = stmt.env;
  expr.alerttab = stmt.alerttab;
  block[1].env = stmt.env;
  block[1].scope = set();
  block[1].alerttab = stmt.alerttab;
  block[2].env = stmt.env;
  block[2].scope = set();
  block[2].alerttab = stmt.alerttab;
  stmt.envout = stmt.env;
  stmt.scopeout = stmt.scope;
}
CC {
  expr.type == "bool" -> "E308: a condicao do if tem de ser bool";
}
| "for" NAME "in" expr block
ER {
  expr.env = stmt.env;
  expr.alerttab = stmt.alerttab;
  block.env = stmt.env | { str(NAME) : (expr.type[5:-1], "loop") };
  block.scope = { str(NAME) };
  block.alerttab = stmt.alerttab;
  stmt.envout = stmt.env;
  stmt.scopeout = stmt.scope;
}
CC {
  expr.type.startswith("list<") -> "E309: o for tem de percorrer uma lista";
}
| callee "(" args ")" ";"
ER {
  args.env = stmt.env;
  args.alerttab = stmt.alerttab;
  stmt.envout = stmt.env;
  stmt.scopeout = stmt.scope;
}
CC {
  callee.signature is not None -> "E401: acao desconhecida";
  callee.signature[1] <= len(args.types) <= len(callee.signature[0]) -> "E402: numero de argumentos errado";
  all(t in ps or "*" in ps or ("L" in ps and t.startswith("list<")) for t, ps in zip(args.types, callee.signature[0])) -> "E403: argumento com datatype errado";
  not any(s for i, s in enumerate(args.secrets) if not (callee.name == "notify" and i == 1)) -> "E601: um segredo so pode ir para a credencial do notify";
}
| callee "(" ")" ";"
ER {
  stmt.envout = stmt.env;
  stmt.scopeout = stmt.scope;
}
CC {
  callee.signature is not None -> "E401: acao desconhecida";
  callee.signature[1] == 0 -> "E402: numero de argumentos errado";
}

callee : NAME
ER {
  callee.name = str(NAME);
  callee.signature = {
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
  args[2].alerttab = args[1].alerttab;
  expr.env = args[1].env;
  expr.alerttab = args[1].alerttab;
  args[1].types = args[2].types + [expr.type];
  args[1].secrets = args[2].secrets + [expr.secret];
}
| expr
ER {
  expr.env = args.env;
  expr.alerttab = args.alerttab;
  args.types = [expr.type];
  args.secrets = [expr.secret];
}

// ===================== Expressões =====================
// Cada nível: herda env e alerts; sintetiza ty (datatype) e sec (depende de um segredo?)

expr : expr "or" andexpr
ER {
  expr[2].env = expr[1].env;
  expr[2].alerttab = expr[1].alerttab;
  andexpr.env = expr[1].env;
  andexpr.alerttab = expr[1].alerttab;
  expr[1].type = "bool";
  expr[1].secret = expr[2].secret or andexpr.secret;
}
CC {
  expr[2].type == "bool" and andexpr.type == "bool" -> "E307: 'or' precisa de operandos bool";
}
| andexpr
ER {
  andexpr.env = expr.env;
  andexpr.alerttab = expr.alerttab;
  expr.type = andexpr.type;
  expr.secret = andexpr.secret;
}

andexpr : andexpr "and" notexpr
ER {
  andexpr[2].env = andexpr[1].env;
  andexpr[2].alerttab = andexpr[1].alerttab;
  notexpr.env = andexpr[1].env;
  notexpr.alerttab = andexpr[1].alerttab;
  andexpr[1].type = "bool";
  andexpr[1].secret = andexpr[2].secret or notexpr.secret;
}
CC {
  andexpr[2].type == "bool" and notexpr.type == "bool" -> "E307: 'and' precisa de operandos bool";
}
| notexpr
ER {
  notexpr.env = andexpr.env;
  notexpr.alerttab = andexpr.alerttab;
  andexpr.type = notexpr.type;
  andexpr.secret = notexpr.secret;
}

notexpr : "not" notexpr
ER {
  notexpr[2].env = notexpr[1].env;
  notexpr[2].alerttab = notexpr[1].alerttab;
  notexpr[1].type = "bool";
  notexpr[1].secret = notexpr[2].secret;
}
CC {
  notexpr[2].type == "bool" -> "E307: 'not' precisa de um bool";
}
| relexpr
ER {
  relexpr.env = notexpr.env;
  relexpr.alerttab = notexpr.alerttab;
  notexpr.type = relexpr.type;
  notexpr.secret = relexpr.secret;
}

relexpr : addexpr RELOP addexpr
ER {
  addexpr[1].env = relexpr.env;
  addexpr[1].alerttab = relexpr.alerttab;
  addexpr[2].env = relexpr.env;
  addexpr[2].alerttab = relexpr.alerttab;
  relexpr.type = "bool";
  relexpr.secret = addexpr[1].secret or addexpr[2].secret;
}
CC {
  str(RELOP) in ("==", "!=") or (addexpr[1].type == addexpr[2].type and addexpr[1].type in ("int", "duration")) -> "E304: comparacao de ordem invalida";
  str(RELOP) not in ("==", "!=") or (addexpr[1].type == addexpr[2].type and not addexpr[1].type.startswith("A:") and not addexpr[1].type.startswith("list<")) -> "E305: igualdade entre tipos diferentes";
}
| addexpr "in" addexpr
ER {
  addexpr[1].env = relexpr.env;
  addexpr[1].alerttab = relexpr.alerttab;
  addexpr[2].env = relexpr.env;
  addexpr[2].alerttab = relexpr.alerttab;
  relexpr.type = "bool";
  relexpr.secret = addexpr[1].secret or addexpr[2].secret;
}
CC {
  addexpr[2].type == "list<" + addexpr[1].type + ">" or (addexpr[1].type == "ip" and addexpr[2].type == "cidr") -> "E306: 'in' com tipos invalidos";
}
| addexpr
ER {
  addexpr.env = relexpr.env;
  addexpr.alerttab = relexpr.alerttab;
  relexpr.type = addexpr.type;
  relexpr.secret = addexpr.secret;
}

addexpr : addexpr "+" accessexpr
ER {
  addexpr[2].env = addexpr[1].env;
  addexpr[2].alerttab = addexpr[1].alerttab;
  accessexpr.env = addexpr[1].env;
  accessexpr.alerttab = addexpr[1].alerttab;
  addexpr[1].type = accessexpr.type;
  addexpr[1].secret = addexpr[2].secret or accessexpr.secret;
}
CC {
  addexpr[2].type == accessexpr.type and accessexpr.type in ("int", "string", "duration") -> "E302: '+' com tipos invalidos";
}
| addexpr "-" accessexpr
ER {
  addexpr[2].env = addexpr[1].env;
  addexpr[2].alerttab = addexpr[1].alerttab;
  accessexpr.env = addexpr[1].env;
  accessexpr.alerttab = addexpr[1].alerttab;
  addexpr[1].type = accessexpr.type;
  addexpr[1].secret = addexpr[2].secret or accessexpr.secret;
}
CC {
  addexpr[2].type == accessexpr.type and accessexpr.type in ("int", "duration") -> "E303: '-' com tipos invalidos";
}
| accessexpr
ER {
  accessexpr.env = addexpr.env;
  accessexpr.alerttab = addexpr.alerttab;
  addexpr.type = accessexpr.type;
  addexpr.secret = accessexpr.secret;
}

accessexpr : accessexpr "." NAME
ER {
  accessexpr[2].env = accessexpr[1].env;
  accessexpr[2].alerttab = accessexpr[1].alerttab;
  accessexpr[1].type = accessexpr[1].alerttab.get(accessexpr[2].type[2:], {}).get(str(NAME), "?");
  accessexpr[1].secret = accessexpr[2].secret;
}
CC {
  accessexpr[2].type.startswith("A:") -> "E203: so se acede a campos de um alerta";
  str(NAME) in accessexpr[1].alerttab[accessexpr[2].type[2:]] -> "E204: campo inexistente no alerta";
}
| primary
ER {
  primary.env = accessexpr.env;
  primary.alerttab = accessexpr.alerttab;
  accessexpr.type = primary.type;
  accessexpr.secret = primary.secret;
}

primary : NAME
ER {
  primary.type = primary.env.get(str(NAME), ("?", "var"))[0];
  primary.secret = primary.env.get(str(NAME), ("?", "var"))[1] == "secret";
}
CC {
  str(NAME) in primary.env -> "E101: variavel nao declarada";
}
| callee "(" args ")"
ER {
  args.env = primary.env;
  args.alerttab = primary.alerttab;
  primary.type = callee.signature[2] if callee.signature else "?";
  primary.secret = any(args.secrets);
}
CC {
  callee.signature is not None -> "E401: funcao desconhecida";
  callee.signature[2] is not None -> "E405: esta acao nao devolve valor";
  callee.signature[1] <= len(args.types) <= len(callee.signature[0]) -> "E402: numero de argumentos errado";
  all(t in ps or "*" in ps or ("L" in ps and t.startswith("list<")) for t, ps in zip(args.types, callee.signature[0])) -> "E403: argumento com datatype errado";
}
| callee "(" ")"
ER {
  primary.type = callee.signature[2] if callee.signature else "?";
  primary.secret = False;
}
CC {
  callee.signature is not None -> "E401: funcao desconhecida";
  callee.signature[2] is not None -> "E405: esta acao nao devolve valor";
  callee.signature[1] == 0 -> "E402: numero de argumentos errado";
}
| "(" expr ")"
ER {
  expr.env = primary.env;
  expr.alerttab = primary.alerttab;
  primary.type = expr.type;
  primary.secret = expr.secret;
}
| "[" items "]"
ER {
  items.env = primary.env;
  items.alerttab = primary.alerttab;
  primary.type = "list<" + items.types[0] + ">";
  primary.secret = items.secret;
}
CC {
  len(set(items.types)) == 1 -> "E310: lista com elementos de tipos diferentes";
}
| "[" "]"
ER {
  primary.type = "?";
  primary.secret = False;
}
CC {
  False -> "E310: a lista vazia nao tem datatype";
}
| INT      ER { primary.type = "int";      primary.secret = False; }
| STRING   ER { primary.type = "string";   primary.secret = False; }
| CIDR     ER { primary.type = "cidr";     primary.secret = False; }
| IP       ER { primary.type = "ip";       primary.secret = False; }
| DURATION ER { primary.type = "duration"; primary.secret = False; }
| BOOL     ER { primary.type = "bool";     primary.secret = False; }

items : items "," expr
ER {
  items[2].env = items[1].env;
  items[2].alerttab = items[1].alerttab;
  expr.env = items[1].env;
  expr.alerttab = items[1].alerttab;
  items[1].types = items[2].types + [expr.type];
  items[1].secret = items[2].secret or expr.secret;
}
| expr
ER {
  expr.env = items.env;
  expr.alerttab = items.alerttab;
  items.types = [expr.type];
  items.secret = expr.secret;
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
