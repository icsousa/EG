# Sentinela: modelo de execução e catálogo de erros semânticos

Versão 1.3 · GA completa em `GRAMATICA.md` · Verificador completo em `verificador.py` (todos os códigos) · Exemplo em LarkAG em `sentinela_ag.py` (25 erros) · Testes em `test_semantica.py` e `test_ag.py`

---

## 1. Modelo de execução: o playbook está sempre ativo

Um playbook **não é um script que corre uma vez**. É um **serviço contínuo** (*daemon*) que fica ativo enquanto o sistema está a monitorizar a rede.

| Conceito | Regra |
|---|---|
| **Ativação** | antes de ser ativado, o playbook passa pelo verificador. **Com erros (`E…`), não é ativado.** Com avisos (`W…`), é ativado, e os avisos ficam registados. |
| **Handler de alerta** `on X as a { … }` | corre **sempre que chega** um alerta do tipo `X` |
| **Handler periódico** `every 1h { … }` | corre **de X em X tempo**, haja ou não alertas (relatórios, limpeza, verificações) |
| **Estado persistente** | as variáveis declaradas ao nível do playbook **mantêm o valor entre execuções** (ex.: `incidentes` acumula ao longo do dia) |
| **Estado local** | as variáveis declaradas dentro de um handler são **criadas de novo em cada execução** |
| **Concorrência** | os handlers executam **um de cada vez**, pela ordem de chegada dos eventos. Não há condições de corrida sobre o estado persistente. |

Exemplo (caso difícil, `exemplos/04_arp_spoofing.snt`): o handler `on arp_spoof` incrementa `incidentes` em cada ataque, e o handler `every 1h` envia um resumo e repõe o contador a zero.

O verificador **não para no primeiro erro**: reporta todos. Quando uma expressão tem um erro, o seu tipo passa a "desconhecido" (⊥), que é compatível com tudo, para evitar erros em cascata.

---

## 2. Regras de tipos dos operadores

| Operador | Operandos válidos | Resultado | Exemplo válido | Exemplo inválido → erro |
|---|---|---|---|---|
| `+` | `int + int` · `string + string` · `duration + duration` | o mesmo tipo | `"porta " + str(p)` · `1h + 30m` | `"porta " + 22` → **E302** |
| `-` | `int - int` · `duration - duration` | o mesmo tipo | `limite - 1` | `"a" - "b"` → **E303** |
| `< > <= >=` | `int` com `int` · `duration` com `duration` | `bool` | `s.dest_port > 1024` | `s.src_ip > 10.0.0.1` → **E304** |
| `== !=` | dois valores do **mesmo** tipo (não listas nem alertas) | `bool` | `x.claimed_ip == x.gateway_ip` | `s.dest_port == "22"` → **E305** |
| `in` | `T in list<T>` · `ip in cidr` | `bool` | `a.src_ip in 10.0.0.0/8` | `s.dest_port in rede` → **E306** |
| `and or` | `bool` com `bool` | `bool` | `crit and x in lan` | `s.dest_port and true` → **E307** |
| `not` | `bool` | `bool` | `not (a in lan)` | `not s.src_ip` → **E307** |
| `.campo` | só sobre o alias de um alerta | tipo do campo | `s.src_ip` | `limite.valor` → **E203** |

Não há conversões automáticas: para juntar números ou IPs a texto usa-se `str(...)`.

---

## 3. Biblioteca predefinida (assinaturas)

| Nome | Parâmetros | Devolve | Destrutiva |
|---|---|---|---|
| `block_ip` | `ip` ou `cidr`, `duration` | — | **sim** |
| `quarantine` | `ip` | — | **sim** |
| `unblock_ip` | `ip` ou `cidr` | — | não |
| `rate_limit` | `ip`, `int` | — | não |
| `log` | `string` | — | não |
| `notify` | `string` [, `string` = credencial] | — | não |
| `count` | `ip`, `duration` | `int` | não |
| `len` | `list<T>` | `int` | não |
| `str` | qualquer | `string` | não |

---

## 4. Catálogo de erros e avisos

### Família 1: Declarações e scopes

| Código | Regra | Exemplo inválido |
|---|---|---|
| **E101** | Um identificador tem de estar declarado e visível. A variável do `for` e o alias do alerta só existem no seu bloco. | `log(str(total));` sem `var total` · usar `porta` depois do `for porta in …` |
| **E102** | Não se pode declarar duas vezes o mesmo nome no mesmo scope. | `var limite: int = 5;` seguido de `var limite: int = 10;` |
| **E103** | Dois alertas com o mesmo nome. | dois `alert a1 { … }` |
| **E104** | Campo repetido dentro de um alerta. | `alert a { x: int; x: ip; }` |
| **E105** | Segredos só podem ser declarados ao nível do playbook. | `secret k: string = "…";` dentro de um handler |

### Família 2: Alertas e handlers

| Código | Regra | Exemplo inválido |
|---|---|---|
| **E201** | Um handler tem de tratar um alerta declarado. | `on ddos as d { … }` sem `alert ddos` |
| **E202** | No máximo um handler por tipo de alerta. | dois `on port_scan as …` |
| **E203** | O `.` só se aplica ao alias de um alerta. | `limite.valor` |
| **E204** | O campo tem de existir no esquema do alerta. | `s.dest_prt` (o campo é `dest_port`) |

### Família 3: Tipos

| Código | Regra | Exemplo inválido |
|---|---|---|
| **E301** | O valor tem de ter o tipo declarado (declaração e atribuição). | `var rede: ip = 10.0.0.0/8;` (é `cidr`) · `n = "dez";` com `n: int` |
| **E302** | `+` só entre `int`, `string` ou `duration` iguais. | `"porta " + 22` · `5 + true` |
| **E303** | `-` só entre `int` ou `duration` iguais. | `"a" - "b"` · `10.0.0.1 - 1` |
| **E304** | `< > <= >=` só entre `int` ou `duration` iguais. | `s.src_ip > 10.0.0.1` · `nome < "z"` |
| **E305** | `== !=` só entre valores do mesmo tipo. | `s.dest_port == "22"` |
| **E306** | `in` só em `T in list<T>` ou `ip in cidr`. | `s.src_ip in portas` · `s.dest_port in rede` |
| **E307** | `and`, `or` e `not` só com `bool`. | `s.dest_port and true` · `not s.src_ip` |
| **E308** | A condição do `if` tem de ser `bool`. | `if (s.dest_port) { … }` |
| **E309** | O `for` só percorre listas. | `for p in s.dest_port { … }` |
| **E310** | As listas literais não podem ser vazias e todos os elementos têm o mesmo tipo. | `[22, "80"]` · `[]` |

### Família 4: Chamadas de ações e funções

| Código | Regra | Exemplo inválido |
|---|---|---|
| **E401** | A ação ou função tem de existir na biblioteca. | `ban_ip(s.src_ip);` |
| **E402** | Número de argumentos certo. | `block_ip(s.src_ip);` (falta a duração) |
| **E403** | Tipo de cada argumento certo. | `block_ip(s.dest_port, 1h);` · `rate_limit(s.src_ip, "100");` |
| **E404** | Uma função que devolve valor não pode ser usada sozinha como instrução (o resultado perdia-se). | `count(s.src_ip, 10m);` |
| **E405** | Uma ação (sem valor) não pode ser usada dentro de uma expressão. | `var r: int = log("x");` |

### Família 5: Mutabilidade

| Código | Regra | Exemplo inválido |
|---|---|---|
| **E501** | Um segredo não pode ser alterado. | `token = "outro";` |
| **E502** | A variável do `for` e o alias do alerta são só de leitura. | `porta = 80;` dentro do `for porta …` · `s = s;` |

### Família 6: Segredos (análise de fluxo de informação)

Uma expressão é **secreta** se usar um segredo, mesmo indiretamente: `"x" + token`, `str(token)` e `token == "abc"` são todas secretas.

| Código | Regra | Exemplo inválido |
|---|---|---|
| **E601** | Um valor secreto não pode ser passado a nenhuma ação, **exceto** como 2.º argumento (credencial) do `notify`. | `log("token=" + token);` · `notify("chave " + str(token));` |
| **E602** | Um valor secreto não pode ser guardado numa variável normal (`var`). Evita "lavar" o segredo por uma variável. | `var copia: string = token;` |
| **E603** | Um valor secreto não pode controlar um `if` ou um `for` (fuga **implícita**: o comportamento revelaria o segredo). | `if (token == "abc") { … }` |

Válido: `notify("scan de " + str(s.src_ip), token);`, porque o segredo vai só para o parâmetro de credencial.

### Família 7: Literais de rede

O lexer aceita qualquer `n.n.n.n`; o significado é verificado aqui.

| Código | Regra | Exemplo inválido |
|---|---|---|
| **E701** | Cada octeto de um IP está entre 0 e 255. | `300.1.1.1` |
| **E702** | O prefixo de um CIDR está entre /0 e /32. | `10.0.0.0/40` |
| **E703** | Durações têm de ser maiores que zero (em ações e no `every`). | `block_ip(x, 0h);` · `every 0m { … }` |

### Avisos (não impedem a ativação)

| Código | Regra | Exemplo |
|---|---|---|
| **W01** | Ação destrutiva (`block_ip`, `quarantine`) fora de qualquer `if`/`else`. | `block_ip(s.src_ip, 1h);` diretamente no handler |
| **W02** | Variável declarada e nunca usada. | `var esquecida: int = 0;` |
| **W03** | Declaração que esconde uma variável de um scope exterior (*shadowing*). | `var limite` dentro de um `for`, já existindo `limite` no playbook |
| **W04** | Alerta declarado sem nenhum handler. | `alert sem_handler { … }` sem `on sem_handler` |
| **W05** | Condição constante. | `if (true) { … }` |

**Total: 32 erros + 5 avisos = 37 verificações**, todas com teste automático.

---

## 5. Atributos da gramática de atributos usados por cada família

| Atributo | Tipo | Usado em |
|---|---|---|
| `env` (pilha de scopes: nome → tipo, tipo de símbolo, usado?) | herdado | famílias 1, 3, 5, 6 · W02, W03 |
| `alertas` (tabela de esquemas) | herdado (sintetizado na 1.ª passagem) | famílias 2, 3 · W04 |
| `em_condicao` | herdado | W01 |
| `tipo` | sintetizado | famílias 3, 4 |
| `secreto` | sintetizado | família 6 |
| `erros` | sintetizado | todas |

---

## 6. Cobertura do exemplo em LarkAG

`sentinela_ag.py` especifica em LarkAG (SA/IA, ER, CC) os erros E101–E104, E201, E203, E204, E301–E310,
E401–E403, E405, E501, E502, E601 e E602. Os restantes (E105, E202, E404, E603, E701–E703 e os avisos
W01–W05) estão especificados em `GRAMATICA.md` e implementados no verificador Python. As regras são as mesmas; a diferença é que o
LarkAG para no primeiro erro, enquanto o verificador reporta todos.

## 7. O que **não** se consegue apanhar antes da execução

É importante dizer isto no relatório: são limites de qualquer análise estática.

| Situação | Porque é que só se sabe em execução |
|---|---|
| O alerta real (JSON do Suricata) chega sem um campo declarado | depende dos dados que chegam, não do programa |
| A firewall falha ao aplicar o `block_ip` | depende do estado da rede |
| `count(...)` devolve um valor inesperado | depende do histórico de alertas |
| Um playbook bloqueia um IP legítimo | é um erro de lógica do analista, não da linguagem |

---

## 8. Como correr

```bash
pip install lark pytest
python verificador.py exemplos/*.snt erros/*.snt     # ver os diagnósticos
python sentinela_ag.py exemplos/*.snt                # gramática de atributos (LarkAG)
pytest -v                                            # 73 testes: sintaxe + semântica + GA
```
