# Sentinela: avaliação da qualidade da linguagem e da gramática

Tarefa 4 do guião · Segue os fatores e as métricas do NB07 (*Language and Grammar Quality*) · Métricas calculadas por `python metricas.py` a partir de `sentinela.ag`

---

## 1. Qualidade da linguagem (fatores internos)

| Fator | Avaliação na Sentinela | Evidência |
|---|---|---|
| **Expressividade** | Alta para o domínio. Os conceitos de segurança são primitivos da linguagem: tipos `ip`, `cidr` e `duration`, literais `10.0.0.0/8` e `24h`, ações `block_ip` e `quarantine`, e `ip in cidr`. Um playbook escreve-se ao nível do problema ("se o IP não é interno, bloqueia 24 h"), não de comandos de firewall. | `exemplos/02_brute_force_ssh.snt` tem 18 linhas; a mesma lógica em YAML de SOAR não tem tipos nem verificação. |
| **Documentação** | Média. Só há comentários de linha (`#`), sem comentários de bloco nem documentação estruturada. Para playbooks curtos é suficiente, e os esquemas `alert` funcionam como documentação **verificável** dos dados que chegam. | Léxico em `GRAMATICA.md` (secção 1). |
| **Unicidade** | Alta. Há **uma** forma de fazer cada coisa: um só ciclo (`for`), um só condicional (`if/else`), uma só forma de declarar (`var`/`secret nome: tipo = valor;`). Não há `while`, `else if` especial, operadores compostos (`+=`) nem conversões implícitas. | GIC: `stmt` tem só 7 alternativas (P23 a P29). |
| **Consistência** | Alta. Todas as declarações seguem `nome: tipo`; todas as instruções simples acabam em `;` e as compostas usam `{ }`; as palavras reservadas são palavras inglesas em minúsculas. Os nomes da gramática e dos atributos seguem uma só convenção (inglês, como as palavras reservadas). | Na v1.3 unificámos os nomes (antes havia `soma`, `prim`, `atab` misturados com `expr`, `stmt`, `env`); na v2.0 a linguagem passou a estar definida num só ficheiro. |
| **Extensibilidade** | Baixa, por opção. O utilizador não define ações, tipos nem macros: as ações vêm de uma biblioteca fixa (`SIG`). Acrescentar uma ação nova só exige uma linha na tabela de assinaturas, sem mudar a gramática. | Ações definidas pelo utilizador estavam na v0 e foram retiradas para controlar o tamanho. |
| **Escalabilidade** | Média. Um playbook trata vários alertas e tem estado partilhado, mas não há módulos: muitos playbooks implicam repetir esquemas de alerta. | Ver modularidade. |
| **Fiabilidade** | **Alta: é o objetivo principal da linguagem.** Sistema de tipos estático, verificação dos campos dos alertas, análise de fluxo de segredos e avisos para ações destrutivas sem condição. Um playbook com erros nunca é ativado. | 32 erros + 6 avisos (`CATALOGO_ERROS.md`), cada um com um programa de teste. |
| **Modularidade** | Baixa. Não há `import` nem funções do utilizador. É a principal limitação para usar a linguagem em grande escala e o primeiro candidato a uma extensão futura. | Fora do âmbito (decisão para manter o projeto pequeno). |

**Resumo.** A Sentinela troca extensibilidade e modularidade por **fiabilidade, unicidade e consistência**. É a troca certa para o domínio: um playbook mal escrito pode bloquear tráfego legítimo, por isso deve ser simples, previsível e verificado antes de correr.

---

## 2. Qualidade da gramática independente de contexto

### 2.1 Métricas

Contagens do Lark sobre a GIC de `sentinela.ag`. As 55 produções numeradas de `GRAMATICA.md` dão 65 porque P8 e P53 têm 6 alternativas cada.

| Métrica | Valor |
|---|---|
| Terminais | 46 |
| fixos (palavras reservadas, pontuação) / flexíveis (`NAME`, `INT`, `IP`, ...) | 36 / 10 |
| Não-terminais | 25 |
| Produções | 65 |
| Produções unitárias (A → B) | 10 |
| Comprimento médio / máximo do lado direito | 2.38 / 7 |
| Média / máximo de produções por não-terminal | 2.6 / 12 |
| Grau de entrada / saída médio (dependências) | 1.84 |
| Símbolos com recursão direta (à esquerda / à direita) | 13 (11 / 1) |
| Símbolos com recursão indireta | 12 |
| Estados LALR | 132 |
| Entradas da tabela action/goto | 849 |
| Palavras reservadas | 21 (mais `true` e `false`) |

**Evolução do tamanho.** A proposta inicial (v0) tinha 45 não-terminais e 110 produções. A v1 tinha duas gramáticas (uma EBNF para o parser e uma BNF para a GA). A v2.0 tem **uma só**, com 25 não-terminais e 65 produções. Tiraram-se as ações do utilizador, o `retry ... until`, a interpolação `${...}`, o `else if` em cadeia, os operadores `*` e `/`, e os tipos `port` e `host`. É a resposta à preocupação de a gramática ser "demasiado extensa".

### 2.2 Interpretação

| Característica (NB07) | Na gramática da Sentinela |
|---|---|
| **Identificadores claros** | Os não-terminais têm o nome do conceito (`playbook`, `handler`, `vardecl`, `relexpr`). Os terminais flexíveis têm o nome do tipo de valor (`IP`, `CIDR`, `DURATION`). `callee` e `ident` existem porque o LarkAG não deixa indexar terminais. |
| **Produções unitárias** | Das 10, 6 são a "escada" de precedência das expressões (`expr → andexpr → notexpr → relexpr → addexpr → accessexpr → primary`). Custam passos de derivação, mas tornam a precedência **explícita na gramática**. As outras 4 (`stmt → vardecl`, `handlers → handler`, `args → expr`, `items → expr`) dão nome a um conceito ou são o caso base de uma lista. |
| **Comprimento das produções** | Média abaixo de 2,4 símbolos. A maior (7 símbolos) é a declaração `var NAME : datatype = expr ;`, que se lê como uma frase. |
| **Notação** | BNF pura, como pede o LarkAG. É menos compacta do que EBNF, mas torna cada passo de derivação explícito, e é a forma necessária para passar o ambiente de uma declaração para a seguinte. |
| **Recursão** | **Consistentemente à esquerda** nas listas e nos operadores binários: dá associatividade à esquerda e é a forma natural para LALR. A única recursão à direita é `not`, que é prefixo. A recursão indireta (`expr → … → primary → ( expr )`, `block → stmts → stmt → block`) vem do aninhamento, que o guião exige. |
| **Determinismo** | LALR(1) **sem conflitos**, logo não ambígua. Não há *dangling else*, porque os blocos levam sempre `{ }`. |
| **Eficiência de reconhecimento** | 132 estados LALR e 849 entradas na tabela: um parser pequeno. O reconhecimento é linear no tamanho do programa. |
| **Modularidade da gramática** | Uma só gramática, sem sub-gramáticas importadas. Com este tamanho, dividir só acrescentaria dependências. |

---

## 3. Qualidade da gramática de atributos

### 3.1 Métricas

| Métrica | Valor |
|---|---|
| Atributos (contados por símbolo) | 123 |
| herdados / sintetizados | 44 / 79 |
| de tipo atómico (`str`, `bool`, `int`) / estruturado (`dict`, `set`, `list`, `tuple`) | 36 / 87 |
| Nomes de atributos distintos | 25 |
| Regras de cálculo (ER) | 354 |
| das quais regras de **cópia** (`X.a = Y.a`) | **190 (54 %)** |
| Condições de contexto (CC) | 54 |
| Códigos de erro distintos | 32 (todos) |
| Arestas no grafo de dependências entre atributos | 223 |
| Grau de entrada / saída médio | 1.81 |

### 3.2 Interpretação

| Característica (NB07) | Na GA da Sentinela |
|---|---|
| **Identificadores de atributos claros** | 25 nomes, todos do conceito, em inglês: `env`, `scope`, `type`, `secret`, `signature`, `alerttab`, `warnings`. Cada nome tem **o mesmo significado** em todos os símbolos onde aparece (por exemplo, `type` é sempre "tipo do valor"). |
| **Número de atributos e de regras** | Elevado (123 e 354), mas **enganador**: 54 % das regras são cópias que só passam o contexto (`env`, `alerttab`, `scope`) de pai para filho, ou sobem um valor numa produção unitária. O LarkAG obriga a escrevê-las uma a uma; em notação de papel (`GRAMATICA.md`, secção 4) ficam implícitas. A lógica real está em 164 regras e 54 condições. |
| **Complexidade dos atributos** | 87 estruturados: o ambiente (`dict`), o scope e os nomes usados (`set`), as listas de argumentos e de avisos. São inevitáveis para modelar scopes, tipos e avisos. Cada domínio está definido em `GRAMATICA.md` (secção 3.1). |
| **Complexidade das regras** | Quase todas as regras ocupam uma linha. A maior é a tabela de assinaturas da biblioteca (`callee.signature`). |
| **Esquema de avaliação** | **L-atribuído**: uma só travessia, da esquerda para a direita, avalia tudo (`GRAMATICA.md`, secção 5). O grafo de dependências tem grau médio 1,8. |
| **Esquema de restrições** | Cada condição de contexto verifica **uma** propriedade, com um código e uma mensagem próprios. A primeira que falha pára a avaliação, como num compilador; a linha do erro é a do nó em avaliação. Os avisos são um atributo à parte, para não impedirem a ativação. |
| **Estilo e especificidade** | Declarativo (relações entre atributos, não uma sequência de passos) e específico do domínio (tipos de rede, segredos, ações destrutivas). |

---

## 4. Decisões tomadas por causa desta análise

| Problema detetado | Decisão |
|---|---|
| Duas definições da mesma linguagem (EBNF para o parser, BNF para a GA, mais um verificador em Python) que tinham de ser mantidas em paralelo | **v2.0**: uma só definição, `sentinela.ag`; o parser e o avaliador são gerados a partir dela |
| Nomes inconsistentes: português e inglês misturados e abreviaturas nos atributos | **v1.3**: convenção única, em inglês, como as palavras reservadas |
| Gramática "demasiado extensa" na proposta inicial | De 110 para 65 produções; funcionalidades secundárias retiradas (secção 2.1) |
| Formas alternativas para a mesma coisa (`else if`, `retry`/`for`) | Uma só forma por construção (unicidade) |

## 5. Limites desta avaliação

As métricas descrevem a **estrutura** da gramática, mas não dizem se a linguagem é fácil de usar para um analista de segurança. Para isso seria preciso uma avaliação empírica: por exemplo, pedir a colegas que escrevam o mesmo playbook em Sentinela e em YAML e comparar o tempo e o número de erros. Fica como trabalho futuro.
