# Sentinela: uma linguagem para playbooks de resposta a incidentes de segurança e de rede

**Engenharia Gramatical 2026/27 · Projeto, Parte I: Language and Grammar Engineering**
*Mestrado em Engenharia Informática, Universidade do Minho*

| Grupo 7 | |
|---|---|
| Ivo Sousa | PG63976 |
| Miguel Páscoa | PG64007 |
| Ricardo Eusébio | PG64022 |

A linguagem está definida em [`sentinela.ag`](sentinela.ag): a gramática, os atributos, as regras de cálculo e as condições de contexto, em **LarkAG**.

<a id="indice"></a>
## Índice

| | Capítulo | Documentos de detalhe |
|:-:|---|---|
| **1** | **[Desenho da linguagem](#desenho)**<br>[Domínio e problema](#dominio) · [Modelo de execução](#execucao) · [Exemplo](#exemplo) · [Construções e requisitos](#construcoes) · [Casos práticos](#casos) | [`exemplos/`](exemplos/) · [`CATALOGO_ERROS.md`](CATALOGO_ERROS.md) |
| **2** | **[Especificação léxica e sintática](#sintaxe)**<br>[Léxico](#lexico) · [Gramática (BNF)](#gramatica) | [`GRAMATICA.md`](GRAMATICA.md) · [`sentinela.ag`](sentinela.ag) |
| **3** | **[Especificação semântica](#semantica)**<br>[Declaração dos atributos](#atributos) · [O que as declarações dizem](#leitura) · [Gramática anotada](#anotada) · [Propriedades verificadas](#propriedades) · [Implementação em LarkAG](#larkag) | [`GRAMATICA.md`](GRAMATICA.md) · [`CATALOGO_ERROS.md`](CATALOGO_ERROS.md) |
| **4** | **[Qualidade da linguagem e da gramática](#qualidade)** | [`QUALIDADE.md`](QUALIDADE.md) · [`metricas.py`](metricas.py) |
| **5** | **[Repositório e execução](#repositorio)** | [`sentinela.py`](sentinela.py) · [`testes/`](testes/) |

---

<a id="desenho"></a>
## 1. Desenho da linguagem

<a id="dominio"></a>
### 1.1 Domínio e problema

As equipas de segurança (SOC) e de redes automatizam a resposta a ataques com **playbooks**: programas que, quando chega um alerta (um *port scan*, uma tentativa de força bruta, um *flood*), executam ações como bloquear um IP, limitar tráfego ou isolar uma máquina.

Nas plataformas atuais, os playbooks são escritos em YAML ou montados com blocos visuais, que **não verificam nada antes da execução**: um campo mal escrito, um segredo enviado por email ou um bloqueio sem condição só se descobrem durante um incidente real.

A **Sentinela** é uma linguagem de domínio específico para escrever playbooks **legíveis e verificáveis antes de serem ativados**.

- **Utilizadores**: analistas de segurança e engenheiros de redes e de operações 
- **Conceitos**: *alerta* (evento com campos tipados), *playbook* (conjunto de reações com estado), *handler* (reação a um alerta ou à passagem do tempo), *ação* (operação sobre a rede), *segredo* (credencial que não pode ser exposta) 
- **Como as construções servem o domínio**: tipos de rede (`ip`, `cidr`, `duration`) evitam confundir um IP com uma rede; `secret` torna a confidencialidade verificável; os esquemas `alert` documentam e validam os dados recebidos; ações destrutivas sem condição são assinaladas 

<a id="execucao"></a>
### 1.2 Modelo de execução

Um playbook é um **serviço sempre ativo**. Antes de ser ativado, passa pela gramática de atributos: **com um erro não é ativado**; com avisos é ativado e os avisos ficam registados.

- `on X as a { … }` corre sempre que chega um alerta do tipo `X`;
- `every 1h { … }` corre periodicamente, haja ou não alertas;
- as variáveis do playbook são **estado persistente**: mantêm o valor entre execuções;
- as variáveis de um handler são criadas de novo em cada execução;
- os handlers correm um de cada vez, pela ordem dos eventos.

<a id="exemplo"></a>
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

<a id="construcoes"></a>
### 1.4 Construções e requisitos mínimos do guião

| Requisito do guião | Na Sentinela |
|---|---|
| Variáveis e declarações | `var nome: tipo = valor;` e `secret nome: tipo = valor;` |
| Scopes com disciplina definida | **estáticos**: playbook ⊃ handler ⊃ bloco (`if`, `for`); declarar antes de usar; sem redeclarações no mesmo scope; *shadowing* num scope interior permitido com aviso; a variável do `for` e o alias do alerta são só de leitura e só existem no seu bloco |
| Expressões e manipulação de estado | `or and not`, `== != < > <= >= in`, `+ -`, acesso a campos (`a.src_ip`), atribuição `x = expr;` e estado persistente |
| Construções compostas e aninhadas | handlers com blocos `if`/`else` e `for` aninhados |
| Ramificação e repetição | `if (…) { … } else { … }` e `for x in lista { … }`; a repetição no tempo é dada pelos handlers `every` |
| Propriedades que a sintaxe não determina | 32 erros e 6 avisos semânticos ([§3](#semantica)) |

**Tipos:** `int`, `bool`, `string`, `ip`, `cidr`, `duration`, `list<T>`.
**Ações:** `block_ip`, `unblock_ip`, `quarantine`, `rate_limit`, `log`, `notify`. 
**Funções:** `count`, `len`, `str`.

<a id="casos"></a>
### 1.5 Casos práticos

| Ficheiro | Ataque real | O que exercita |
|---|---|---|
| [`01_port_scan.snt`](exemplos/01_port_scan.snt) | `nmap -sS` | `if/else`, `in` sobre listas, `block_ip` |
| [`02_brute_force_ssh.snt`](exemplos/02_brute_force_ssh.snt) | `hydra` | `count`, `and`/`not`, `ip in cidr` |
| [`03_syn_flood.snt`](exemplos/03_syn_flood.snt) | `hping3 -S --flood` | `for` com `if` aninhado, contador, *whitelist* |
| [`04_arp_spoofing.snt`](exemplos/04_arp_spoofing.snt) | `arpspoof` | `secret`, estado persistente, handler `every`, várias ações |

[↑ Voltar ao índice](#indice)

---

<a id="sintaxe"></a>
## 2. Especificação léxica e sintática

<a id="lexico"></a>
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
| `RELOP` | `== != < > <= >=` | |
| Comentários | `#` até ao fim da linha | |

Os literais de rede têm **prioridades** no lexer (`CIDR` > `IP` > `DURATION` > `INT`), para `10.0.0.0/8` ser um só token. A validade dos valores (octetos ≤ 255, prefixo ≤ 32, duração > 0) é verificada na **semântica**.

<a id="gramatica"></a>
### 2.2 Gramática (BNF)

As produções são as de [`sentinela.ag`](sentinela.ag), com a mesma numeração. As listas usam **recursão à esquerda** (como `decls → decls decl` nas aulas), que é a forma que permite passar o ambiente de uma declaração para a seguinte.

```
P1   start      → alerts playbook
P2   alerts     → alerts alert
P3   alerts     → ε
P4   alert      → "alert" NAME "{" fields "}"
P5   fields     → fields field
P6   fields     → ε
P7   field      → NAME ":" datatype ";"
P8   datatype   → "int" | "bool" | "string" | "ip" | "cidr" | "duration"
P9   datatype   → "list" "<" datatype ">"

P10  playbook   → "playbook" NAME "{" statedecls handlers "}"
P11  statedecls → statedecls vardecl
P12  statedecls → ε
P13  handlers   → handlers handler
P14  handlers   → handler
P15  handler    → "on" ident "as" ident block
P16  handler    → "every" DURATION block
P17  ident      → NAME

P18  block      → "{" stmts "}"
P19  stmts      → stmts stmt
P20  stmts      → ε
P21  vardecl    → "var" NAME ":" datatype "=" expr ";"
P22  vardecl    → "secret" NAME ":" datatype "=" expr ";"
P23  stmt       → vardecl
P24  stmt       → NAME "=" expr ";"
P25  stmt       → "if" "(" expr ")" block
P26  stmt       → "if" "(" expr ")" block "else" block
P27  stmt       → "for" NAME "in" expr block
P28  stmt       → callee "(" args ")" ";"
P29  stmt       → callee "(" ")" ";"
P30  callee     → NAME
P31  args       → args "," expr
P32  args       → expr

P33  expr       → expr "or" andexpr
P34  expr       → andexpr
P35  andexpr    → andexpr "and" notexpr
P36  andexpr    → notexpr
P37  notexpr    → "not" notexpr
P38  notexpr    → relexpr
P39  relexpr    → addexpr RELOP addexpr              RELOP ∈ { == != < > <= >= }
P40  relexpr    → addexpr "in" addexpr
P41  relexpr    → addexpr
P42  addexpr    → addexpr "+" accessexpr
P43  addexpr    → addexpr "-" accessexpr
P44  addexpr    → accessexpr
P45  accessexpr → accessexpr "." NAME
P46  accessexpr → primary
P47  primary    → NAME
P48  primary    → callee "(" args ")"
P49  primary    → callee "(" ")"
P50  primary    → "(" expr ")"
P51  primary    → "[" items "]"
P52  primary    → "[" "]"
P53  primary    → INT | STRING | IP | CIDR | DURATION | BOOL
P54  items      → items "," expr
P55  items      → expr
```

| Propriedade | Como se garante |
|---|---|
| **Sem ambiguidade** | o Lark constrói o parser **LALR(1) sem conflitos**; uma gramática LALR(1) é sempre não ambígua |
| **Precedência** | por estratificação: `or` < `and` < `not` < comparações / `in` < `+ -` < `.` |
| **Associatividade** | à esquerda (recursão à esquerda); comparações não associativas |
| **Sem *dangling else*** | os blocos levam sempre `{ }` |

[↑ Voltar ao índice](#indice)

---

<a id="semantica"></a>
## 3. Especificação semântica

A semântica é especificada por uma **gramática de atributos**: a gramática da [§2](#gramatica) anotada com atributos e, em cada produção, com regras de cálculo (ER) e condições de contexto (CC). Um programa é **válido** se todas as condições de contexto forem verdadeiras. Toda a gramática de atributos está implementada em **LarkAG**, em [`sentinela.ag`](sentinela.ag).

<a id="atributos"></a>
### 3.1 Declaração dos atributos

Para cada símbolo, os atributos que tem, se são herdados (↓) ou sintetizados (↑) e o seu domínio:

```
A(start)      = { (warnings,  ↑, [Warning]) }

A(alerts)     = { (table,     ↑, AlertTab), (lines,    ↑, Nome ⇀ ℕ) }
A(alert)      = { (seen,      ↓, ℘(Nome)),
                  (name,      ↑, Nome),     (fieldtab, ↑, FieldTab),  (line, ↑, ℕ) }
A(fields)     = { (table,     ↑, FieldTab) }
A(field)      = { (seen,      ↓, ℘(Nome)),
                  (name,      ↑, Nome),     (type,     ↑, Tipo) }
A(datatype)   = { (type,      ↑, Tipo) }

A(playbook)   = { (alerttab,  ↓, AlertTab),
                  (handled,   ↑, ℘(Nome)),  (warnings, ↑, [Warning]) }
A(statedecls) = { (env,       ↓, Env),      (alerttab, ↓, AlertTab),
                  (envout,    ↑, Env),      (declared, ↑, Nome ⇀ ℕ),
                  (used,      ↑, ℘(Nome)),  (warnings, ↑, [Warning]) }
A(handlers)   = { (env,       ↓, Env),      (alerttab, ↓, AlertTab),
                  (handled,   ↑, ℘(Nome)),  (used,     ↑, ℘(Nome)),
                  (warnings,  ↑, [Warning]) }
A(handler)    = { (env,       ↓, Env),      (alerttab, ↓, AlertTab),
                  (seen,      ↓, ℘(Nome)),
                  (target,    ↑, Nome),     (used,     ↑, ℘(Nome)),
                  (warnings,  ↑, [Warning]) }
A(ident)      = { (name,      ↑, Nome),     (line,     ↑, ℕ) }

A(block)      = { (env,       ↓, Env),      (scope,    ↓, Scope),
                  (alerttab,  ↓, AlertTab), (guarded,  ↓, 𝔹),
                  (used,      ↑, ℘(Nome)),  (warnings, ↑, [Warning]) }
A(stmts)      = A(stmt) =
                { (env,       ↓, Env),      (scope,    ↓, Scope),
                  (alerttab,  ↓, AlertTab), (guarded,  ↓, 𝔹),
                  (envout,    ↑, Env),      (scopeout, ↑, Scope),
                  (declared,  ↑, Nome ⇀ ℕ), (used,     ↑, ℘(Nome)),
                  (warnings,  ↑, [Warning]) }
A(vardecl)    = { (env,       ↓, Env),      (scope,    ↓, Scope),
                  (alerttab,  ↓, AlertTab), (level,    ↓, Level),
                  (envout,    ↑, Env),      (scopeout, ↑, Scope),
                  (declared,  ↑, Nome ⇀ ℕ), (used,     ↑, ℘(Nome)),
                  (warnings,  ↑, [Warning]) }

A(callee)     = { (name,      ↑, Nome),     (signature, ↑, Sig ∪ {⊥}), (line, ↑, ℕ) }
A(args)       = { (env,       ↓, Env),      (alerttab, ↓, AlertTab),
                  (types,     ↑, [Tipo]),   (secrets,  ↑, [𝔹]),
                  (consts,    ↑, [Const]),  (used,     ↑, ℘(Nome)) }
A(items)      = { (env,       ↓, Env),      (alerttab, ↓, AlertTab),
                  (types,     ↑, [Tipo]),   (secret,   ↑, 𝔹),
                  (used,      ↑, ℘(Nome)) }

A(X)          = { (env,       ↓, Env),      (alerttab, ↓, AlertTab),
                  (type,      ↑, Tipo),     (secret,   ↑, 𝔹),
                  (const,     ↑, Const),    (used,     ↑, ℘(Nome)) }
                para X ∈ {expr, andexpr, notexpr, relexpr, addexpr, accessexpr, primary}
```

Domínios: `Tipo = {int, bool, string, ip, cidr, duration} ∪ {list<T>} ∪ {A:n}`, `Espécie = {var, secret, loop, alias}`, `Env = Nome ⇀ Tipo × Espécie`, `Scope = ℘(Nome)`, `AlertTab = Nome ⇀ (Nome ⇀ Tipo)`, `Level = {top, inner}`, `Warning = (código, linha, mensagem)`. Definições completas em [`GRAMATICA.md`](GRAMATICA.md) (§3.1).

<a id="leitura"></a>
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
| `seen` ↓ em `alert`, `field` e `handler` | cada alerta, cada campo e cada `on` é **único** |
| `alerttab` ↓ desde `start` | os alertas são **globais** |
| `level` ↓ em `vardecl` | os segredos só existem no estado do playbook |
| `guarded` ↓ nas instruções | uma ação destrutiva fora de um `if` é **assinalada** |
| `declared` e `used` ↑ | variáveis declaradas e nunca lidas são **assinaladas** |
| `const` ↑ nas expressões | constantes como `if (true)` ou `log("")` são **assinaladas** |
| `warnings` é um atributo, os erros são CC | **dois níveis**: erros impedem a ativação, avisos não |

<a id="anotada"></a>
### 3.3 Gramática Anotada (exemplos)

[`GRAMATICA.md`](GRAMATICA.md) (§4) tem as regras de **todas** as produções. Quatro exemplos:

| Produção | Regras de cálculo (ER) | Condições de contexto (CC) |
|---|---|---|
| P19 `stmts₀ → stmts₁ stmt` | `stmt.env = stmts₁.envout`<br>`stmt.scope = stmts₁.scopeout`<br>`stmts₀.envout = stmt.envout` | |
| P21 `vardecl → "var" NAME ":" datatype "=" expr ";"` | `vardecl.envout = vardecl.env ⊕ {NAME ↦ (datatype.type, var)}`<br>`vardecl.scopeout = vardecl.scope ∪ {NAME}` | `NAME ∉ vardecl.scope` → **E102**<br>`expr.type = datatype.type` → **E301**<br>`¬ expr.secret` → **E602** |
| P42 `addexpr₀ → addexpr₁ "+" accessexpr` | `addexpr₀.type = accessexpr.type`<br>`addexpr₀.secret = addexpr₁.secret ∨ accessexpr.secret` | `addexpr₁.type = accessexpr.type ∈ {int, string, duration}` → **E302** |
| P47 `primary → NAME` | `(primary.type, k) = primary.env(NAME)`<br>`primary.secret = (k = secret)`<br>`primary.used = {NAME}` | `NAME ∈ dom(primary.env)` → **E101** |

A gramática é **L-atribuída**: os atributos herdados dependem só do pai e dos irmãos à esquerda (por exemplo, P19), por isso uma travessia da esquerda para a direita avalia tudo.

<a id="propriedades"></a>
### 3.4 Propriedades Verificadas

| Família | Códigos | Exemplos sintaticamente corretos mas inválidos |
|---|---|---|
| Declarações e scopes | E101–E105 | variável não declarada; redeclarada no mesmo scope; alerta ou campo repetido; segredo fora do estado do playbook |
| Alertas e handlers | E201–E204 | `on` de um alerta inexistente; dois `on` para o mesmo alerta; campo inexistente (`s.dest_prt`) |
| Tipos | E301–E310 | `var r: ip = 10.0.0.0/8;` · `"porta " + 22` · `if (s.dest_port)` · `[22, "80"]` · `[]` |
| Chamadas | E401–E405 | ação inexistente; `log();` · `block_ip(s.src_ip);` (argumentos em falta) |
| Mutabilidade | E501–E502 | alterar um segredo ou a variável do `for` |
| Segredos | E601–E603 | `log("token=" + token);` · guardar um segredo numa `var` · segredo numa condição |
| Literais de rede | E701–E703 | `300.1.1.1` · `10.0.0.0/40` · `block_ip(x, 0h)` |
| **Avisos** | W01–W06 | ação destrutiva fora de um `if`; variável não usada; *shadowing*; alerta sem `on`; condição constante; `log("")` |

Catálogo completo, com a regra de cada código: [`CATALOGO_ERROS.md`](CATALOGO_ERROS.md).

<a id="larkag"></a>
### 3.5 Implementação em LarkAG

[`sentinela.ag`](sentinela.ag) declara os atributos e anota cada produção no formato das aulas. Por exemplo, a declaração de variáveis (P21):

```
IA(vardecl) { env : dict[str, tuple[str, str]], scope : set[str], alerttab : dict[str, dict[str, str]], level : str }
SA(vardecl) { envout : dict[str, tuple[str, str]], scopeout : set[str], declared : dict[str, int], used : set[str], warnings : list[tuple[str, int, str]] }

vardecl : "var" NAME ":" datatype "=" expr ";"
ER {
  expr.env = vardecl.env;
  expr.alerttab = vardecl.alerttab;
  vardecl.envout = vardecl.env | { str(NAME) : (datatype.type, "var") };
  vardecl.scopeout = vardecl.scope | { str(NAME) };
  ...
}
CC {
  str(NAME) not in vardecl.scope -> "E102: nome já declarado neste scope";
  expr.type == datatype.type -> "E301: o valor não tem o tipo declarado";
  not expr.secret -> "E602: um segredo não pode ser guardado numa variável normal";
}
```

[`sentinela.py`](sentinela.py) gera o parser LALR(1) e o avaliador de atributos a partir de `sentinela.ag`. O **primeiro** erro pára a avaliação (como num compilador) e é reportado com a linha; os avisos são o atributo `warnings` da raiz:

```
$ python sentinela.py testes/E204_campo_inexistente.snt testes/E601_segredo_no_log.snt testes/W06_mensagem_vazia.snt exemplos/04_arp_spoofing.snt
✘ rejeitado  testes/E204_campo_inexistente.snt
    linha 9: erro E204: o alerta não tem esse campo
✘ rejeitado  testes/E601_segredo_no_log.snt
    linha 10: erro E601: um segredo só pode ser passado como credencial do notify
✔ ativo  testes/W06_mensagem_vazia.snt
    linha 9: aviso W06: 'log' com uma mensagem vazia
✔ ativo  exemplos/04_arp_spoofing.snt
```

[↑ Voltar ao índice](#indice)

---

<a id="qualidade"></a>
## 4. Qualidade da Linguagem e da Gramática

Avaliação completa, segundo o NB07, em [`QUALIDADE.md`](QUALIDADE.md). As métricas são calculadas por [`metricas.py`](metricas.py).

| Fator da linguagem | Avaliação |
|---|---|
| Expressividade | **alta** para o domínio: tipos, literais e ações de rede são primitivos da linguagem |
| Unicidade | **alta**: uma só forma de cada construção |
| Consistência | **alta**: `nome: tipo` em todas as declarações, `;` nas instruções simples, `{ }` nos blocos; uma só convenção de nomes na gramática |
| Fiabilidade | **alta, e é o objetivo da linguagem**: tipos estáticos, campos validados, fluxo de segredos, ações destrutivas assinaladas |
| Documentação | média: só comentários de linha; os esquemas `alert` documentam os dados de forma verificável |
| Extensibilidade, modularidade | baixas, **por opção**, para manter a linguagem pequena |

| Métrica da GIC | Valor | 
|---|---|
| Não-terminais | 25 | 
| Terminais | 46 | 
| Produções | 65 | 
| Produções unitárias | 10 | 
| Estados LALR | 132 | 

| Métrica da GA | Valor |
|---|---|
| Atributos (herdados / sintetizados) | 123 (44 / 79) |
| Regras de cálculo | 354 |
| das quais regras de cópia | 190 (54 %) |
| Condições de contexto | 54 |
| Códigos de erro | 32 |

- **Tamanho controlado:** a proposta inicial tinha 45 não-terminais e 110 produções; a versão atual tem 25 e 65, numa só gramática.
- **Recursão** consistentemente à esquerda; a única à direita é o prefixo `not`.
- **A GA parece grande, mas a lógica é pequena:** 54 % das regras são cópias que passam o contexto de pai para filho, obrigatórias no LarkAG. A verificação real está em 164 regras e 54 condições.
- **Limite:** as métricas descrevem a estrutura, não a facilidade de uso. Uma comparação empírica com YAML fica como trabalho futuro.

[↑ Voltar ao índice](#indice)

---

<a id="repositorio"></a>
## 5. Repositório e Execução

| Ficheiro / pasta | O que é |
|---|---|
| [`sentinela.ag`](sentinela.ag) | **a linguagem**: gramática, atributos, regras de cálculo e condições de contexto (LarkAG) |
| [`sentinela.py`](sentinela.py) | processador: gera o parser e o avaliador a partir de `sentinela.ag` e verifica playbooks |
| [`GRAMATICA.md`](GRAMATICA.md) | especificação em notação matemática: léxico, BNF (P1–P55) e gramática de atributos |
| [`CATALOGO_ERROS.md`](CATALOGO_ERROS.md) | modelo de execução, regras de tipos e catálogo de todos os erros e avisos |
| [`QUALIDADE.md`](QUALIDADE.md) | avaliação de qualidade (tarefa 4) |
| [`metricas.py`](metricas.py) | métricas de qualidade da GIC e da GA |
| [`exemplos/`](exemplos/) | os 4 casos práticos (ativos, sem avisos) |
| [`testes/`](testes/) | um programa por código de erro ou aviso, com `# expect: CÓDIGO` na linha do problema |
| `test_*.py` | testes automáticos (`pytest`) |

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python sentinela.py exemplos/*.snt               # verificar os casos práticos
python sentinela.py testes/*.snt                 # ver cada erro e aviso
python sentinela.py --arvore exemplos/01_port_scan.snt   # com a árvore sintática
python metricas.py                               # métricas de qualidade
pytest -q                                        # testes automáticos
```

[↑ Voltar ao índice](#indice)
