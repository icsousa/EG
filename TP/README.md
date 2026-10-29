# Sentinela: playbooks de resposta a incidentes de segurança e de rede

Projeto de Engenharia Gramatical 2026/27 (Parte I). A Sentinela é uma DSL para escrever *playbooks*:
programas **sempre ativos** que reagem a alertas de rede (port scan, brute force SSH, SYN flood,
ARP spoofing) com ações como `block_ip`, `rate_limit` ou `quarantine`, e que são **verificados
antes de serem ativados**.

## Estrutura

| Ficheiro / pasta | O que é |
|---|---|
| `GRAMATICA.md` | **especificação completa**: léxico, GIC em BNF (P1–P55) e gramática de atributos completa (atributos, ER, CC) |
| `QUALIDADE.md` | avaliação da qualidade da linguagem e da gramática (tarefa 4), segundo o NB07 |
| `metricas.py` | calcula as métricas da GIC e da GA usadas em `QUALIDADE.md` |
| `sentinela.lark` | gramática da linguagem em Lark (LALR(1) sem conflitos), com os mesmos nomes da GA |
| `parser.py` | parser: `python parser.py exemplos/01_port_scan.snt` mostra a árvore |
| `sentinela_ag.py` | **exemplo em LarkAG** de uma parte da GA (formato das aulas): scopes, tipos, alertas, chamadas, mutabilidade, segredos |
| `verificador.py` | verificador completo: reporta **todos** os erros (32) e avisos (5), não só o primeiro |
| `CATALOGO_ERROS.md` | modelo de execução, regras de tipos e catálogo de todos os erros e avisos |
| `exemplos/` | os 4 casos práticos (2 fáceis, 1 intermédio, 1 difícil): todos sem erros |
| `erros/` | programa de demonstração com um erro de cada família |
| `tests_semantica/` | um ficheiro por família de erros, com `# expect: CÓDIGO` na linha do erro |
| `test_*.py` | testes automáticos (`pytest`) |

## Como correr

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python parser.py exemplos/01_port_scan.snt              # árvore sintática
python verificador.py exemplos/*.snt erros/*.snt        # todos os erros e avisos
python sentinela_ag.py exemplos/*.snt                   # exemplo da GA em LarkAG
python metricas.py                                      # métricas de qualidade
pytest -v                                               # 73 testes
```

## Especificação e implementações da gramática de atributos

| | `GRAMATICA.md` | `sentinela_ag.py` (LarkAG) | `verificador.py` (Python) |
|---|---|---|---|
| Papel | **especificação** completa da GA | **exemplo executável** de uma parte, como nas aulas (SA/IA, ER, CC) | implementação completa, para o utilizador |
| Erros | todos (32) + avisos (5) | 25 erros; para no **primeiro** (`ContextConditionError`) | todos os erros e avisos, com linha |

O guião não exige que a GA cubra todas as propriedades. A GA completa está especificada em `GRAMATICA.md`;
o exemplo em LarkAG mostra os atributos herdados (`env`, `scope`, `alerttab`) e sintetizados (`type`, `secret`,
`envout`, `types`) e as suas dependências; o verificador Python implementa tudo (incluindo avisos e literais de rede).

## Casos práticos

| Nível | Ficheiro | Ataque real |
|---|---|---|
| Fácil | `exemplos/01_port_scan.snt` | `nmap -sS` |
| Fácil | `exemplos/02_brute_force_ssh.snt` | `hydra` |
| Intermédio | `exemplos/03_syn_flood.snt` | `hping3 -S --flood` |
| Difícil | `exemplos/04_arp_spoofing.snt` | `arpspoof` (estado persistente + handler `every`) |
