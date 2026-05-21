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

## Pré-requisitos

Para executar os scripts nesta estação (Linux), certifique-se de ter:

- **Sistema Operacional:** Linux (ambiente de terminal Bash/Zsh).
- **Python 3:** Instalado no sistema.
- **Módulo venv:** Necessário para o isolamento das bibliotecas (em distros Debian/Ubuntu, instalável via `sudo apt install python3-venv`).
- **Acesso à rede:** Para o download dos feeds OVAL Ubuntu e comunicação com a API do Vicarius.
- **Credenciais do Vicarius:** URL Base e chave de API para o arquivo de configuração `.env`.

## Execução

```shell
git clone https://github.com/loonar-morpheus-sysint/vicarius-reports.git
cd vicarius-reports

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env-sample .env

# Edite o arquivo .env com sua API e URL (opcionalmente com $EDITOR)
${EDITOR:-vi} .env

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
