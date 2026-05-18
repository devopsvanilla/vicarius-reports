# `get_active_cve.py` — referência técnica rápida

## Propósito

`get_active_cve.py` consulta vulnerabilidades ativas na API Vicarius, enriquece os dados com contexto de SO/pacote e status Ubuntu (OVAL/API), e gera artefatos para análise operacional.

## Dependências de entrada

### Obrigatórios

- `.env` (mesmo diretório do script) com:
  - `VICARIUS_BASE_URL`
  - `VICARIUS_API_KEY`
- `reports/endpoint_so.jsonl` (gerado por `get_endpoint_so.py`)
- feeds OVAL locais em `reports/oval/` (gerados por `get_oval_ubuntu.py`)

### Fontes externas consultadas (indiretas e diretas)

- Vicarius API (`/vicarius-external-data-api/aggregation/searchGroup`)
- Canonical OVAL (`security-metadata.canonical.com`) via arquivos locais em `reports/oval/*.xml`
- Ubuntu Security API (`https://ubuntu.com/security/cves/{CVE}.json`) como fallback

### Dependências Python

- `requests`
- `urllib3`
- `openpyxl`
- biblioteca local: `get_ubuntu_oval_status.py` (`check_cve`)

## Saídas geradas

- `reports/active_cve.jsonl` (payload agregado por vulnerabilidade)
- `reports/active_cve.xlsx`
  - aba `Vulnerabilidades Ativas`
  - abas de dashboard Ubuntu (gráficos e tabelas auxiliares)
- `reports/active_cve.csv` (export da aba principal)
- `reports/ubuntu_oval_cache.jsonl` (cache incremental das consultas OVAL/API)

## Leiaute dos artefatos

### `reports/endpoint_so.jsonl`

```json
{"endpoint":"srv-01","os":"Ubuntu","version":"24.04.4"}
```

### `reports/ubuntu_oval_cache.jsonl`

```json
{"key":"24.04.4|CVE-2024-0001|openssl|3.0.2","status":"Vulnerable"}
```

### `reports/active_cve.xlsx` e `reports/active_cve.csv`

Colunas (ordem fixa):

1. Ativo
2. SO
3. Versão do SO
4. Fornecedor do pacote
5. Pacote
6. Versão do Pacote
7. Descrição da Vulnerabilidade
8. CVE
9. Nível da Vulnerabilidade
10. Data da Criação
11. Data da Atualização
12. Status OVAL Ubuntu
13. KEV

## Estratégia de coleta

- `size` máximo por request: `500`
- paginação por SEEK:
  - mantém `from=0`
  - ordena por `aggregationId`
  - avança com `q=vulnerabilityId<ULTIMO_ID`
- retry para 429 e 5xx com backoff exponencial
- prioriza header de espera de rate limit:
  1. `X-Rate-Limit-Retry-After-Seconds`
  2. `Retry-After`

## Parâmetros

| Script | Parâmetro | Default | Tipo |
|---|---|---|---|
| `get_active_cve.py` | `--force-update` | `false` | flag |
| `get_endpoint_so.py` | `--env` | `.env` | path |
| `get_endpoint_so.py` | `--output` | `reports/endpoint_so.jsonl` | path |
| `get_oval_ubuntu.py` | `--input` | `reports/endpoint_so.jsonl` | path |
| `get_oval_ubuntu.py` | `--output-dir` | `reports/oval` | path |
| `get_ubuntu_oval_status.py` | `--ubuntu` | — | str |
| `get_ubuntu_oval_status.py` | `--cve` | — | str |
| `get_ubuntu_oval_status.py` | `--pkg` | — | repeat `nome:versão` |

## Uso

```shell
python3 get_active_cve.py
```

Para forçar regeneração sem reutilizar arquivos locais:

```shell
python3 get_active_cve.py --force-update
```

Exemplo de validação pontual do resolvedor OVAL/API:

```shell
python3 get_ubuntu_oval_status.py --ubuntu 24.04 --cve CVE-2024-0001 --pkg openssl:3.0.2
```

## Variáveis de ajuste (opcionais)

- `VRX_VULN_REQUEST_DELAY_SEC` (default `0`)

## Fluxo recomendado antes da execução

1. `python3 get_endpoint_so.py`
2. `python3 get_oval_ubuntu.py`
3. `python3 get_active_cve.py`

## Troubleshooting rápido

- **Erro de credencial ausente**: valide `.env` no mesmo diretório do script.
- **Status OVAL em branco/inconsistente**: atualize feeds com `get_oval_ubuntu.py`.
- **Muitas CVEs/tempo de execução alto**: esperado; processo inclui enriquecimento por pacote e cache progressivo.
