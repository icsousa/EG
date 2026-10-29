# Sentinela: avaliação da qualidade da linguagem e da gramática

Tarefa 4 do guião · Segue os fatores e as métricas do NB07 (*Language and Grammar Quality*) · Métricas calculadas por `python metricas.py`

---

## 1. Qualidade da linguagem (fatores internos)

| Fator | Avaliação na Sentinela | Evidência |
|---|---|---|
| **Expressividade** | Alta para o domínio. Os conceitos de segurança são primitivos da linguagem: tipos `ip`, `cidr` e `duration`, literais `10.0.0.0/8` e `24h`, ações `block_ip` e `quarantine`, e `ip in cidr`. Um playbook escreve-se ao nível do problema ("se o IP não é interno, bloqueia 24 h"), não de comandos de firewall. | `exemplos/02_brute_force_ssh.snt` tem 18 linhas; a mesma lógica em YAML de SOAR não tem tipos nem verificação. |
| **Documentação** | Média. Só há comentários de linha (`#`), sem comentários de bloco nem documentação estruturada. Para playbooks curtos é suficiente, e os esquemas `alert` funcionam como documentação **verificável** dos dados que chegam. | Métricas lexicográficas (secção 3.3). |
| **Unicidade** | Alta. Há **uma** forma de fazer cada coisa: um só ciclo (`for`), um só condicional (`if/else`), uma só forma de declarar (`var`/`secret nome: tipo = valor;`). Não há `while`, `else if` especial, operadores compostos (`+=`) nem conversões implícitas. | GIC: `stmt` tem só 7 alternativas (P23 a P29). |
| **Consistência** | Alta. Todas as declarações seguem `nome: tipo`; todas as instruções simples acabam em `;` e as compostas usam `{ }`; as palavras reservadas são palavras inglesas em minúsculas. Os nomes da gramática seguem a mesma convenção nos 3 ficheiros. | Na v1.3 unificámos os nomes dos não-terminais e dos atributos (antes havia `soma`, `prim`, `atab` misturados com `expr`, `stmt`, `env`). |
| **Extensibilidade** | Baixa, por opção. O utilizador não define ações, tipos nem macros: as ações vêm de uma biblioteca fixa (`SIG`). Acrescentar uma ação nova só exige uma linha na tabela de assinaturas, sem mudar a gramática. | Ações definidas pelo utilizador estavam na v0 e foram retiradas para controlar o tamanho. |
| **Escalabilidade** | Média. Um playbook trata vários alertas e tem estado partilhado, mas não há módulos: muitos playbooks implicam repetir esquemas de alerta. | Ver modularidade. |
| **Fiabilidade** | **Alta: é o objetivo principal da linguagem.** Sistema de tipos estático, verificação dos campos dos alertas, análise de fluxo de segredos e avisos para ações destrutivas sem condição. Um playbook com erros nunca é ativado. | 32 erros + 5 avisos (`CATALOGO_ERROS.md`), todos testados. |
| **Modularidade** | Baixa. Não há `import` nem funções do utilizador. É a principal limitação para usar a linguagem em grande escala e o primeiro candidato a uma extensão futura. | Fora do âmbito (decisão para manter o projeto pequeno). |

**Resumo.** A Sentinela troca extensibilidade e modularidade por **fiabilidade, unicidade e consistência**. É a troca certa para o domínio: um playbook mal escrito pode bloquear tráfego legítimo, por isso deve ser simples, previsível e verificado antes de correr.

---

## 2. Qualidade da gramática independente de contexto

### 2.1 Métricas

Calculadas para as duas formas da mesma gramática: a **EBNF** que o parser usa (`sentinela.lark`) e a **BNF** em que a GA está escrita (`GRAMATICA.md` / LarkAG). As contagens são as internas do Lark: as 55 produções numeradas de `GRAMATICA.md` dão 65 porque P8 e P53 têm 6 alternativas cada; na EBNF, o Lark acrescenta regras auxiliares para cada `*`, `+` e `[...]`.

| Métrica | EBNF (`sentinela.lark`) | BNF (`GRAMATICA.md`) |
|---|---|---|
| Terminais | 49 | 46 |
| fixos (palavras reservadas, pontuação) | 40 | 36 |
| flexíveis (`NAME`, `INT`, `IP`, ...) | 9 | 10 |
| Não-terminais | 30 | 25 |
| Produções | 81 | 65 |
| Produções unitárias (A → B) | 18 | 10 |
| Comprimento médio do lado direito | 2.27 | 2.38 |
| Comprimento máximo do lado direito | 7 | 7 |
| Média de produções por não-terminal | 2.7 | 2.6 |
| Máximo de produções por não-terminal | 14 | 12 |
| Grau de entrada / saída médio | 1.73 | 1.84 |
| Símbolos com recursão direta | 12 | 13 |
| à esquerda / à direita | 10 / 1 | 11 / 1 |
| Símbolos com recursão indireta | 13 | 12 |
| Estados LALR | 148 | 132 |
| Entradas da tabela action/goto | 1040 | 849 |

**Evolução do tamanho.** A proposta inicial (v0) tinha 45 não-terminais, 59 terminais e 110 produções. A versão atual tem 30, 49 e 81 (EBNF): **menos 26 % de produções**. Tiraram-se as ações do utilizador, o `retry ... until`, a interpolação `${...}`, o `else if` em cadeia, os operadores `*` e `/`, e os tipos `port` e `host`. É a resposta à preocupação de a gramática ser "demasiado extensa".

### 2.2 Interpretação

| Característica (NB07) | Na gramática da Sentinela |
|---|---|
| **Identificadores claros** | Os não-terminais têm o nome do conceito (`playbook`, `handler`, `vardecl`, `relexpr`). Os terminais flexíveis têm o nome do tipo de valor (`IP`, `CIDR`, `DURATION`). `callee` e `ident` só existem na BNF, para a GA poder referir cada nome. |
| **Produções unitárias** | Das 10 da BNF, 6 são a "escada" de precedência das expressões (`expr → andexpr → notexpr → relexpr → addexpr → accessexpr → primary`). Custam passos de derivação, mas tornam a precedência **explícita na gramática**, sem regras de prioridade externas. As outras 4 (`stmt → vardecl`, `handlers → handler`, `args → expr`, `items → expr`) dão nome a um conceito ou são o caso base de uma lista. |
| **Comprimento das produções** | Média abaixo de 2,4 símbolos. A maior (7 símbolos) é a declaração `var NAME : datatype = expr ;`, que se lê como uma frase. |
| **Notação** | EBNF no ficheiro do parser (mais compacta) e BNF pura na especificação da GA (derivações explícitas, necessárias para passar o `env`). A mistura é **deliberada e documentada** (`GRAMATICA.md`, secção 2.2), não acidental. |
| **Recursão** | **Consistentemente à esquerda** nas listas e nos operadores binários: dá associatividade à esquerda e é a forma natural para LALR. A única recursão à direita é `not`, que é prefixo. A recursão indireta (`expr → … → primary → ( expr )`, `block → stmts → stmt → block`) vem do aninhamento, que o guião exige. |
| **Determinismo** | LALR(1) **sem conflitos**, e sem ambiguidade nos 23 programas do corpus (verificado com Earley). Não há *dangling else*, porque os blocos levam sempre `{ }`. |
| **Eficiência de reconhecimento** | 132 a 148 estados LALR e cerca de mil entradas na tabela: um parser pequeno. O reconhecimento é linear no tamanho do programa. |
| **Modularidade da gramática** | Uma só gramática, sem sub-gramáticas importadas. Com este tamanho, dividir só acrescentaria dependências. |

---

## 3. Qualidade da gramática de atributos

### 3.1 Métricas (exemplo LarkAG)

| Métrica | Valor |
|---|---|
| Atributos (contados por símbolo) | 73 |
| herdados / sintetizados | 37 / 36 |
| de tipo atómico (`str`, `bool`) / estruturado (`dict`, `set`, `list`, `tuple`) | 21 / 52 |
| Regras de cálculo (ER) | 221 |
| das quais regras de **cópia** (`X.a = Y.a`) | **151 (68 %)** |
| Condições de contexto (CC) | 42 |
| Códigos de erro distintos | 25 |
| Arestas no grafo de dependências entre atributos | 132 |
| Grau de entrada / saída médio | 1.81 / 1.81 |

### 3.2 Interpretação

| Característica (NB07) | Na GA da Sentinela |
|---|---|
| **Identificadores de atributos claros** | Nomes do conceito, em inglês: `env`, `scope`, `type`, `secret`, `signature`, `alerttab`. Na v1.3 substituímos abreviaturas (`ty`, `sec`, `loc`, `atab`) por nomes completos. |
| **Número de atributos e de regras** | Elevado (73 e 221), mas **enganador**: 68 % das regras são cópias que só passam `env` e `alerttab` de pai para filho. O LarkAG obriga a escrevê-las uma a uma; em notação de papel (`GRAMATICA.md`) ficam implícitas ("passam sem alteração"). A complexidade **semântica** real está em 70 regras e 42 condições. |
| **Complexidade dos atributos** | 52 atributos estruturados: o ambiente (`dict`), o scope (`set`) e as listas de tipos dos argumentos. São inevitáveis para modelar scopes e tipos. Cada um tem um só significado, documentado em `GRAMATICA.md` (secção 3.2). |
| **Complexidade das regras** | 220 das 221 regras ocupam uma linha. A única maior é a tabela de assinaturas (`callee.signature`). |
| **Esquema de avaliação** | **L-atribuído**: uma só travessia, da esquerda para a direita, avalia tudo (`GRAMATICA.md`, secção 5). O grafo de dependências tem grau médio 1,8: cada atributo depende, em média, de menos de 2 outros. |
| **Esquema de restrições** | Cada condição de contexto verifica **uma** propriedade e tem um código e uma mensagem próprios (E101 a E703), o que torna os erros fáceis de explicar ao utilizador. |
| **Estilo e especificidade** | Declarativo (relações entre atributos, não uma sequência de passos) e específico do domínio (tipos de rede, segredos, ações destrutivas). |

---

## 4. Decisões tomadas por causa desta análise

| Problema detetado | Decisão (v1.3) |
|---|---|
| Nomes inconsistentes: português e inglês misturados (`soma`, `prim`, `tipo` ao lado de `expr`, `stmt`) e abreviaturas nos atributos | Convenção única nos 3 ficheiros: inglês, como as palavras reservadas, minúsculas e sem `_` |
| Gramática "demasiado extensa" na proposta inicial | De 110 para 81 produções (EBNF); funcionalidades secundárias retiradas (secção 2.1) |
| Formas alternativas para a mesma coisa (`else if`, `retry`/`for`) | Uma só forma por construção (unicidade) |
| Notação mista sem explicação | EBNF no parser e BNF na GA, com tabela de correspondência |

## 5. Limites desta avaliação

As métricas descrevem a **estrutura** da gramática, mas não dizem se a linguagem é fácil de usar para um analista de segurança. Para isso seria preciso uma avaliação empírica: por exemplo, pedir a colegas que escrevam o mesmo playbook em Sentinela e em YAML e comparar o tempo e o número de erros. Fica como trabalho futuro.
