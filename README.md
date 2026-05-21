# vicarius-reports

Índice dos scripts do projeto para coleta/enriquecimento de CVEs Ubuntu via Vicarius + OVAL.

## Visão geral do fluxo

1. `get_endpoint_so.py` gera o mapeamento endpoint -> SO/versão.
2. `get_oval_ubuntu.py` baixa os feeds OVAL das releases detectadas.
3. `get_active_cve.py` gera relatório final (`jsonl`, `xlsx`, `csv`) e dashboard.
4. `get_ubuntu_oval_status.py` é utilitário técnico (normalmente chamado internamente pelo passo 3).

## Índice dos scripts

| Script                        | Função principal                                                  | Entradas                                                        | Saídas                                                                                                                    |
| ----------------------------- | ------------------------------------------------------------------- | --------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `get_endpoint_so.py`        | Consulta endpoints no Vicarius e resolve SO/versão                 | `.env` (`VICARIUS_BASE_URL`, `VICARIUS_API_KEY`)          | `reports/endpoint_so.jsonl`                                                                                              |
| `get_oval_ubuntu.py`        | Baixa e descompacta OVAL Ubuntu por release                         | `reports/endpoint_so.jsonl`                                   | `reports/oval/*.xml` e `reports/oval/*.bz2`                                                                            |
| `get_active_cve.py`         | Coleta CVEs ativas, enriquece status Ubuntu e gera relatório final | `.env`, `reports/endpoint_so.jsonl`, `reports/oval/*.xml` | `reports/active_cve.jsonl`, `reports/active_cve.xlsx`, `reports/active_cve.csv`, `reports/ubuntu_oval_cache.jsonl` |
| `get_ubuntu_oval_status.py` | Resolve status de CVE em OVAL/API Ubuntu (uso técnico)             | `--ubuntu`, `--cve`, `--pkg`                              | JSON em stdout                                                                                                             |

## Execução

```shell
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env-sample .env

# Altere no nano para a sua API e URL
nano .env

# Execute os scripts nessa ordem
python3 get_endpoint_so.py
python3 get_oval_ubuntu.py
python3 get_active_cve.py --force-update
```

## Estrutura esperada de artefatos

```text
reports/
├── endpoint_so.jsonl
├── active_cve.jsonl
├── active_cve.xlsx
├── active_cve.csv
├── ubuntu_oval_cache.jsonl
└── oval/
    ├── com.ubuntu.<codename>.usn.oval.xml
    └── com.ubuntu.<codename>.cve.oval.xml
```

## Documentação detalhada

- `get_active_cve.py`: veja [`get_active_cve.md`](./get_active_cve.md)
