# Sentinela: uma linguagem para playbooks de resposta a incidentes de segurança e de rede

**Engenharia Gramatical 2026/27 · Projeto, Parte I: Language and Grammar Engineering**
Mestrado em Engenharia Informática, Universidade do Minho

| Grupo | |
|---|---|
| Ivo Sousa | PG63976|
| Miguel Páscoa | PG64007|
| Ricardo Eusébio | PG64022 |

Este README é o relatório deste checkpoint e segue as quatro tarefas do guião. Os detalhes completos estão nos documentos indicados:

| Tarefa do guião | Secção | Documento completo |
|---|---|---|
| 1. Desenho da linguagem | [§1](#1-desenho-da-linguagem) | `exemplos/`, `CATALOGO_ERROS.md` |
| 2. Especificação léxica e sintática | [§2](#2-especificação-léxica-e-sintática) | `GRAMATICA.md` (§1–2), `sentinela.lark` |
| 3. Especificação semântica | [§3](#3-especificação-semântica) | `GRAMATICA.md` (§3–6), `sentinela_ag.py`, `CATALOGO_ERROS.md` |
| 4. Qualidade da linguagem e da gramática | [§4](#4-qualidade-da-linguagem-e-da-gramática) | `QUALIDADE.md`, `metricas.py` |

---

## 1. Desenho da linguagem

### 1.1 Domínio e problema

As equipas de segurança (SOC) e de redes automatizam a resposta a ataques com **playbooks**: programas que, quando chega um alerta (um *port scan*, uma tentativa de força bruta, um *flood*), executam ações como bloquear um IP, limitar tráfego ou isolar uma máquina.

Nas plataformas atuais, os playbooks são escritos em YAML ou montados com blocos visuais, que **não verificam nada antes da execução**: um campo mal escrito, um segredo enviado por email ou um bloqueio sem condição só se descobrem durante um incidente real.

A **Sentinela** é uma linguagem de domínio específico para escrever playbooks **legíveis e verificáveis antes de serem ativados**.

| | |
|---|---|
| **Utilizadores** | analistas de segurança e engenheiros de redes e de operações |
| **Conceitos** | *alerta* (evento com campos tipados), *playbook* (conjunto de reações com estado), *handler* (reação a um alerta ou à passagem do tempo), *ação* (operação sobre a rede), *segredo* (credencial que não pode ser exposta) |
| **Como as construções servem o domínio** | tipos de rede (`ip`, `cidr`, `duration`) evitam confundir um IP com uma rede; `secret` torna a confidencialidade verificável; os esquemas `alert` documentam e validam os dados recebidos; ações destrutivas sem condição são assinaladas |

### 1.2 Modelo de execução

Um playbook é um **serviço sempre ativo**. Antes de ser ativado, passa pelo verificador semântico: **com erros não é ativado**; com avisos é ativado e os avisos ficam registados.

- `on X as a { … }` corre sempre que chega um alerta do tipo `X`;
- `every 1h { … }` corre periodicamente, haja ou não alertas;
- as variáveis do playbook são **estado persistente**: mantêm o valor entre execuções;
- as variáveis de um handler são criadas de novo em cada execução;
- os handlers correm um de cada vez, pela ordem dos eventos.

### 1.3 Exemplo

```
alert ssh_failed_login {
  src_ip: ip;
  user: string;
}

playbook brute_force_ssh {
  var limite: int = 5;
  var rede_interna: cidr = 10.0.0.0/8;

  on ssh_failed_login as a {
    var tentativas: int = count(a.src_ip, 10m);
    if (tentativas > limite and not (a.src_ip in rede_interna)) {
      block_ip(a.src_ip, 24h);
      notify("Brute force contra " + a.user + " vindo de " + str(a.src_ip));
    }
  }
}
```

### 1.4 Construções e requisitos mínimos do guião

| Requisito do guião | Na Sentinela |
|---|---|
| Variáveis e declarações | `var nome: tipo = valor;` e `secret nome: tipo = valor;` |
| Scopes com disciplina definida | **estáticos**: playbook ⊃ handler ⊃ bloco (`if`, `for`); declarar antes de usar; sem redeclarações no mesmo scope; *shadowing* num scope interior permitido com aviso; a variável do `for` e o alias do alerta são só de leitura e só existem no seu bloco |
| Expressões e manipulação de estado | `or and not`, `== != < > <= >= in`, `+ -`, acesso a campos (`a.src_ip`), atribuição `x = expr;` e estado persistente |
| Construções compostas e aninhadas | handlers com blocos `if`/`else` e `for` aninhados |
| Ramificação e repetição | `if (…) { … } else { … }` e `for x in lista { … }`; a repetição no tempo é dada pelos handlers `every` |
| Propriedades que a sintaxe não determina | 32 erros e 5 avisos semânticos (§3) |

**Tipos:** `int`, `bool`, `string`, `ip`, `cidr`, `duration`, `list<T>`.
**Ações:** `block_ip`, `unblock_ip`, `quarantine`, `rate_limit`, `log`, `notify`. **Funções:** `count`, `len`, `str`.

### 1.5 Casos práticos

| Nível | Ficheiro | Ataque real | O que exercita |
|---|---|---|---|
| Fácil | `exemplos/01_port_scan.snt` | `nmap -sS` | `if/else`, `in` sobre listas, `block_ip` |
| Fácil | `exemplos/02_brute_force_ssh.snt` | `hydra` | `count`, `and`/`not`, `ip in cidr` |
| Intermédio | `exemplos/03_syn_flood.snt` | `hping3 -S --flood` | `for` com `if` aninhado, contador, *whitelist* |
| Difícil | `exemplos/04_arp_spoofing.snt` | `arpspoof` | `secret`, estado persistente, handler `every`, várias ações |

---

## 2. Especificação léxica e sintática

### 2.1 Léxico

| Token | Definição | Exemplo |
|---|---|---|
| Palavras reservadas | `alert and as bool cidr duration else every false for if in int ip list not on or playbook secret string true var` | `playbook` |
| `NAME` | `[a-zA-Z_][a-zA-Z0-9_]*` | `src_ip` |
| `INT` | `\d+` | `5432` |
| `STRING` | `"[^"]*"` | `"Scan bloqueado"` |
| `IP` | `\d{1,3}(\.\d{1,3}){3}` | `10.0.0.5` |
| `CIDR` | `\d{1,3}(\.\d{1,3}){3}/\d{1,2}` | `10.0.0.0/8` |
| `DURATION` | `\d+(s\|m\|h)` | `24h` |
| `BOOL` | `true \| false` | |
| Comentários | `#` até ao fim da linha | |

Os literais de rede têm **prioridades** no lexer (`CIDR` > `IP` > `DURATION` > `INT`), para `10.0.0.0/8` ser um só token. A validade dos valores (octetos ≤ 255, prefixo ≤ 32, duração > 0) é verificada na **semântica**.

### 2.2 Gramática

`sentinela.lark` tem a gramática em EBNF, usada pelo parser Lark. `GRAMATICA.md` (§2) tem a mesma gramática em **BNF pura, com 55 produções numeradas (P1–P55)**, que é a forma usada pela gramática de atributos. Os nomes são os mesmos nos dois ficheiros.

<details>
<summary>Ver <code>sentinela.lark</code></summary>

```lark
start: alert* playbook

alert: "alert" NAME "{" field* "}"
field: NAME ":" datatype ";"

?datatype: basictype
         | "list" "<" datatype ">"         -> listtype
!basictype: "int" | "bool" | "string" | "ip" | "cidr" | "duration"

playbook: "playbook" NAME "{" vardecl* handler+ "}"

?handler: "on" NAME "as" NAME block        -> onhandler
        | "every" DURATION block           -> everyhandler

block: "{" stmt* "}"

?stmt: vardecl | assign | ifstmt | forstmt | action

vardecl: declkind NAME ":" datatype "=" expr ";"
!declkind: "var" | "secret"
assign: NAME "=" expr ";"
ifstmt: "if" "(" expr ")" block ["else" block]
forstmt: "for" NAME "in" expr block
action: NAME "(" [expr ("," expr)*] ")" ";"

?expr: expr "or" andexpr                   -> orop
     | andexpr
?andexpr: andexpr "and" notexpr            -> andop
        | notexpr
?notexpr: "not" notexpr                    -> notop
        | relexpr
?relexpr: addexpr relop addexpr            -> comparison
        | addexpr
?addexpr: addexpr addop accessexpr         -> arith
        | accessexpr
?accessexpr: accessexpr "." NAME           -> fieldaccess
           | primary
?primary: NAME                             -> var
        | NAME "(" [expr ("," expr)*] ")"  -> call
        | "(" expr ")"
        | "[" [expr ("," expr)*] "]"       -> listlit
        | INT -> intlit | STRING -> strlit | CIDR -> cidrlit
        | IP -> iplit | DURATION -> durlit | BOOL -> boollit

!relop: "==" | "!=" | "<" | ">" | "<=" | ">=" | "in"
!addop: "+" | "-"
```
</details>

| Propriedade | Como se garante |
|---|---|
| **Sem ambiguidade** | o Lark constrói o parser **LALR(1) sem conflitos**; o Earley com `ambiguity="explicit"` não encontra ambiguidade nos 23 programas de teste |
| **Precedência** | por estratificação: `or` < `and` < `not` < comparações / `in` < `+ -` < `.` |
| **Associatividade** | à esquerda (recursão à esquerda); comparações não associativas |
| **Sem *dangling else*** | os blocos levam sempre `{ }` |

---

## 3. Especificação semântica

A semântica é especificada por uma **gramática de atributos**: a gramática da §2 anotada com atributos e, em cada produção, com regras de cálculo (ER) e condições de contexto (CC). Um programa é **válido** se todas as condições de contexto forem verdadeiras.

### 3.1 Declaração dos atributos

Para cada símbolo, os atributos que tem, se são herdados (↓) ou sintetizados (↑) e o seu domínio:

```
A(start)      = { (warnings,  ↑, [Warning]) }

A(alerts)     = { (table,     ↑, AlertTab) }
A(alert)      = { (name,      ↑, Nome),     (fieldtab, ↑, FieldTab) }
A(fields)     = { (table,     ↑, FieldTab) }
A(field)      = { (name,      ↑, Nome),     (type,     ↑, Tipo) }
A(datatype)   = { (type,      ↑, Tipo) }

A(playbook)   = { (alerttab,  ↓, AlertTab),
                  (handled,   ↑, ℘(Nome)),  (warnings, ↑, [Warning]) }
A(statedecls) = { (env,       ↓, Env),      (alerttab, ↓, AlertTab),
                  (envout,    ↑, Env),      (declared, ↑, ℘(Nome)),
                  (used,      ↑, ℘(Nome)),  (warnings, ↑, [Warning]) }
A(handlers)   = { (env,       ↓, Env),      (alerttab, ↓, AlertTab),
                  (handled,   ↑, ℘(Nome)),  (used,     ↑, ℘(Nome)),
                  (warnings,  ↑, [Warning]) }
A(handler)    = { (env,       ↓, Env),      (alerttab, ↓, AlertTab),
                  (target,    ↑, Nome ∪ {⊥}), (used,   ↑, ℘(Nome)),
                  (warnings,  ↑, [Warning]) }
A(ident)      = { (name,      ↑, Nome) }

A(block)      = { (env,       ↓, Env),      (scope,    ↓, Scope),
                  (alerttab,  ↓, AlertTab), (guarded,  ↓, 𝔹),
                  (used,      ↑, ℘(Nome)),  (warnings, ↑, [Warning]) }
A(stmts)      = A(stmt) =
                { (env,       ↓, Env),      (scope,    ↓, Scope),
                  (alerttab,  ↓, AlertTab), (guarded,  ↓, 𝔹),
                  (envout,    ↑, Env),      (scopeout, ↑, Scope),
                  (declared,  ↑, ℘(Nome)),  (used,     ↑, ℘(Nome)),
                  (warnings,  ↑, [Warning]) }
A(vardecl)    = { (env,       ↓, Env),      (scope,    ↓, Scope),
                  (alerttab,  ↓, AlertTab), (level,    ↓, Level),
                  (envout,    ↑, Env),      (scopeout, ↑, Scope),
                  (declared,  ↑, ℘(Nome)),  (used,     ↑, ℘(Nome)),
                  (warnings,  ↑, [Warning]) }

A(callee)     = { (name,      ↑, Nome),     (signature, ↑, Sig ∪ {⊥}) }
A(args)       = A(items) =
                { (env,       ↓, Env),      (alerttab, ↓, AlertTab),
                  (types,     ↑, [Tipo]),   (secrets,  ↑, [𝔹]),
                  (used,      ↑, ℘(Nome)) }

A(X)          = { (env,       ↓, Env),      (alerttab, ↓, AlertTab),
                  (type,      ↑, Tipo),     (secret,   ↑, 𝔹),
                  (const,     ↑, 𝔹 ∪ {⊥}),  (used,     ↑, ℘(Nome)) }
                para X ∈ {expr, andexpr, notexpr, relexpr, addexpr, accessexpr, primary}
```

Domínios: `Tipo = {int, bool, string, ip, cidr, duration} ∪ {list<T>} ∪ {A:n} ∪ {⊥}`, `Espécie = {var, secret, loop, alias}`, `Env = Nome ⇀ Tipo × Espécie`, `Scope = ℘(Nome)`, `AlertTab = Nome ⇀ (Nome ⇀ Tipo)`, `Level = {playbook, block}`. Definições completas em `GRAMATICA.md` (§3.1).

### 3.2 O que as declarações dizem sobre a semântica

Só com as declarações, sem olhar para nenhuma regra de cálculo, já se leem as regras da linguagem:

| Declaração | Regra da linguagem |
|---|---|
| `env` ↓ em todas as instruções e expressões; `envout` ↑ nas sequências de declarações | **scopes estáticos** e **declarar antes de usar**: o ambiente desce na árvore e cresce da esquerda para a direita |
| `scope` ↓, com um `scope` próprio por bloco | **não se redeclara no mesmo bloco**; um bloco interior pode reutilizar um nome |
| `Env` guarda a `Espécie` além do tipo | segredos, variáveis do `for` e aliases de alertas têm **regras próprias** |
| `type` ↑ nas expressões, sem tipo herdado | **tipagem de baixo para cima**; os tipos das variáveis vêm sempre de uma declaração explícita |
| `Tipo` inclui `ip`, `cidr`, `duration` e `A:n` | os conceitos de **rede e de alerta são tipos** verificados |
| `secret` ↑ nas expressões | **fluxo de informação**: o que usa um segredo fica secreto, e é seguido até onde é usado |
| `alerttab` ↓ desde `start` | os alertas são **globais** |
| `level` ↓ em `vardecl` | os segredos só existem ao nível do playbook |
| `guarded` ↓ nas instruções | uma ação destrutiva fora de um `if` é **assinalada** |
| `handled` ↑ nos handlers | **no máximo um handler por alerta** |
| `warnings` é um atributo, os erros são CC | **dois níveis**: erros impedem a ativação, avisos não |

### 3.3 Gramática anotada (exemplos)

`GRAMATICA.md` (§4) tem as regras de **todas** as 55 produções. Quatro exemplos:

| Produção | Regras de cálculo (ER) | Condições de contexto (CC) |
|---|---|---|
| P19 `stmts₀ → stmts₁ stmt` | `stmt.env = stmts₁.envout`<br>`stmt.scope = stmts₁.scopeout`<br>`stmts₀.envout = stmt.envout` | |
| P21 `vardecl → "var" NAME ":" datatype "=" expr ";"` | `vardecl.envout = vardecl.env ⊕ {NAME ↦ (datatype.type, var)}`<br>`vardecl.scopeout = vardecl.scope ∪ {NAME}` | `NAME ∉ vardecl.scope` → **E102**<br>`compat(datatype.type, expr.type)` → **E301**<br>`¬ expr.secret` → **E602** |
| P42 `addexpr₀ → addexpr₁ "+" accessexpr` | `addexpr₀.type = accessexpr.type`<br>`addexpr₀.secret = addexpr₁.secret ∨ accessexpr.secret` | `addexpr₁.type = accessexpr.type ∈ {int, string, duration}` → **E302** |
| P47 `primary → NAME` | `(primary.type, k) = primary.env(NAME)`<br>`primary.secret = (k = secret)` | `NAME ∈ dom(primary.env)` → **E101** |

A gramática é **L-atribuída**: os atributos herdados dependem só do pai e dos irmãos à esquerda (por exemplo, P19), por isso uma travessia da esquerda para a direita avalia tudo.

### 3.4 Propriedades verificadas

| Família | Códigos | Exemplos sintaticamente corretos mas inválidos |
|---|---|---|
| Declarações e scopes | E101–E105 | variável não declarada; redeclarada no mesmo scope; segredo fora do playbook |
| Alertas e handlers | E201–E204 | handler de um alerta inexistente; campo inexistente (`s.dest_prt`) |
| Tipos | E301–E310 | `var r: ip = 10.0.0.0/8;` · `"porta " + 22` · `if (s.dest_port)` · `[22, "80"]` · `[]` |
| Chamadas | E401–E405 | ação inexistente; `log();` · `block_ip(s.src_ip);` (argumentos em falta) |
| Mutabilidade | E501–E502 | alterar um segredo ou a variável do `for` |
| Segredos | E601–E603 | `log("token=" + token);` · guardar um segredo numa `var` · segredo numa condição |
| Literais de rede | E701–E703 | `300.1.1.1` · `10.0.0.0/40` · `block_ip(x, 0h)` |
| **Avisos** | W01–W05 | ação destrutiva fora de um `if`; variável não usada; *shadowing*; alerta sem handler; condição constante |

Catálogo completo, com a regra de cada código: `CATALOGO_ERROS.md`.

### 3.5 Implementação

| | `GRAMATICA.md` | `sentinela_ag.py` (LarkAG) | `verificador.py` |
|---|---|---|---|
| Papel | especificação completa | **exemplo executável de uma parte**, no formato das aulas | implementação completa |
| Cobertura | 32 erros + 5 avisos | 25 erros (42 CC) | 32 erros + 5 avisos |
| Comportamento | — | para no primeiro erro | reporta todos, com a linha |

O exemplo LarkAG declara os atributos com os mesmos nomes e domínios da §3.1:

```
IA(vardecl)    { env : dict[str, tuple[str, str]], scope : set[str], alerttab : dict[str, dict[str, str]] }
SA(vardecl)    { envout : dict[str, tuple[str, str]], scopeout : set[str] }

vardecl : "var" NAME ":" datatype "=" expr ";"
ER {
  expr.env = vardecl.env;
  expr.alerttab = vardecl.alerttab;
  vardecl.envout = vardecl.env | { str(NAME) : (datatype.type, "var") };
  vardecl.scopeout = vardecl.scope | { str(NAME) };
}
CC {
  str(NAME) not in vardecl.scope -> "E102: variavel ja declarada neste scope";
  expr.type == datatype.type -> "E301: o valor nao tem o tipo declarado";
  not expr.secret -> "E602: um segredo nao pode ser guardado numa variavel normal";
}
```

O verificador reporta todos os problemas de um programa sintaticamente correto:

```
$ python verificador.py erros/erros_semanticos.snt
✘ erros/erros_semanticos.snt: 10 diagnóstico(s)
    linha 9: erro E301: 'rede' é ip mas o valor é cidr
    linha 9: aviso W02: 'rede' é declarada mas nunca é usada
    linha 11: erro E102: 'limite' já foi declarada neste scope (linha 10)
    linha 14: erro E204: o alerta 'port_scan' não tem o campo 'dest_prt' (campos: src_ip, dest_port)
    linha 15: erro E402: 'block_ip' recebe 2 argumento(s), mas recebeu 1
    linha 17: aviso W01: a ação destrutiva 'block_ip' é executada sem nenhuma condição
    linha 18: erro E601: um segredo não pode ser passado a 'log' (só como credencial do notify)
    linha 19: erro E302: '+' não se aplica a string e int (use str() para converter)
    linha 20: erro E101: 'contador' não foi declarada
    linha 23: erro E201: não existe nenhum alerta 'ddos' declarado
```

---

## 4. Qualidade da linguagem e da gramática

Avaliação completa, segundo o NB07, em `QUALIDADE.md`. As métricas são calculadas por `python metricas.py`.

| Fator da linguagem | Avaliação |
|---|---|
| Expressividade | **alta** para o domínio: tipos, literais e ações de rede são primitivos da linguagem |
| Unicidade | **alta**: uma só forma de cada construção |
| Consistência | **alta**: `nome: tipo` em todas as declarações, `;` nas instruções simples, `{ }` nos blocos; nomes da gramática iguais nos três ficheiros |
| Fiabilidade | **alta, e é o objetivo da linguagem**: tipos estáticos, campos validados, fluxo de segredos, ações destrutivas assinaladas |
| Documentação | média: só comentários de linha; os esquemas `alert` documentam os dados de forma verificável |
| Extensibilidade, modularidade | baixas, **por opção**, para manter a linguagem pequena |

| Métrica da GIC (BNF) | Valor | | Métrica da GA (LarkAG) | Valor |
|---|---|---|---|---|
| Não-terminais | 25 | | Atributos (herdados / sintetizados) | 73 (37 / 36) |
| Terminais | 46 | | Regras de cálculo | 221 |
| Produções | 65 | | das quais regras de cópia | 151 (68 %) |
| Produções unitárias | 10 | | Condições de contexto | 42 |
| Estados LALR | 132 | | Arestas no grafo de dependências | 132 |

- **Tamanho controlado:** a proposta inicial tinha 110 produções; a versão atual tem 81 (EBNF), **menos 26 %**.
- **Recursão** consistentemente à esquerda; a única à direita é o prefixo `not`.
- **A GA parece grande, mas a lógica é pequena:** 68 % das regras são cópias do ambiente de pai para filho, obrigatórias no LarkAG. A verificação real está em 70 regras e 42 condições.
- **Limite:** as métricas descrevem a estrutura, não a facilidade de uso. Uma comparação empírica com YAML fica como trabalho futuro.

---

## 5. Repositório e execução

| Ficheiro / pasta | O que é |
|---|---|
| `sentinela.lark` | gramática (Lark, LALR(1)) |
| `GRAMATICA.md` | especificação completa: léxico, BNF (P1–P55) e gramática de atributos |
| `CATALOGO_ERROS.md` | modelo de execução, regras de tipos e catálogo de todos os erros e avisos |
| `QUALIDADE.md` | avaliação de qualidade (tarefa 4) |
| `parser.py` | parser: mostra a árvore sintática |
| `verificador.py` | verificador semântico completo |
| `sentinela_ag.py` | exemplo da gramática de atributos em LarkAG |
| `metricas.py` | métricas de qualidade da GIC e da GA |
| `exemplos/` | os 4 casos práticos (sem erros) |
| `erros/` | programa de demonstração com um erro de cada família |
| `tests_semantica/` | um ficheiro por família de erros, com `# expect: CÓDIGO` na linha do erro |
| `test_*.py` | 73 testes automáticos (sintaxe, semântica e LarkAG) |

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python parser.py exemplos/01_port_scan.snt           # árvore sintática
python verificador.py exemplos/*.snt erros/*.snt     # todos os erros e avisos
python sentinela_ag.py exemplos/*.snt                # exemplo da GA em LarkAG
python metricas.py                                   # métricas de qualidade
pytest -q                                            # 73 testes
```

## 6. Ligação à Parte II

A árvore anotada pela gramática de atributos (tipos, scopes, segredos) é a base da Parte II: **representar** cada handler como um grafo de fluxo de controlo, **analisar** código inalcançável e ações destrutivas alcançáveis sem condição, **visualizar** os playbooks e **transformar** playbooks em regras `nftables`.
