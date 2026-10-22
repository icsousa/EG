# Sentinela: playbooks de resposta a incidentes de segurança e de rede

Projeto de Engenharia Gramatical 2026/27 (Parte I). A Sentinela é uma DSL para escrever *playbooks*:
programas **sempre ativos** que reagem a alertas de rede (port scan, brute force SSH, SYN flood,
ARP spoofing) com ações como `block_ip`, `rate_limit` ou `quarantine`, e que são **verificados
antes de serem ativados**.

## Estrutura

| Ficheiro / pasta | O que é |
|---|---|
| `sentinela.lark` | gramática da linguagem (Lark, LALR(1) sem conflitos) |
| `parser.py` | parser: `python parser.py exemplos/01_port_scan.snt` mostra a árvore |
| `sentinela_ag.py` | **gramática de atributos em LarkAG** (formato das aulas): scopes, tipos, alertas, chamadas, segredos |
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
python sentinela_ag.py exemplos/*.snt                   # gramática de atributos (LarkAG)
pytest -v                                               # 68 testes
```

## Duas implementações da semântica: porquê?

| | `sentinela_ag.py` (LarkAG) | `verificador.py` (Python) |
|---|---|---|
| Papel | **especificação formal** da GA, como nas aulas (SA/IA, ER, CC) | ferramenta para o utilizador |
| Erros | pára no **primeiro** erro (`ContextConditionError`) | reporta **todos** os erros e avisos, com linha |
| Cobertura | 25 erros (scopes, alertas, tipos, chamadas, mutabilidade, segredos) | 32 erros + 5 avisos |

O guião não exige que a GA cubra todas as propriedades. A versão LarkAG mostra os atributos
herdados (`env`, `loc`, `atab`) e sintetizados (`ty`, `sec`, `envout`, `tys`) e as suas dependências;
o verificador Python cobre o resto (avisos, literais de rede, condições com segredos).

## Casos práticos

| Nível | Ficheiro | Ataque real |
|---|---|---|
| Fácil | `exemplos/01_port_scan.snt` | `nmap -sS` |
| Fácil | `exemplos/02_brute_force_ssh.snt` | `hydra` |
| Intermédio | `exemplos/03_syn_flood.snt` | `hping3 -S --flood` |
| Difícil | `exemplos/04_arp_spoofing.snt` | `arpspoof` (estado persistente + handler `every`) |
