#!/usr/bin/env python3
"""
Gera endpoint_so.jsonl com campos: endpoint, os, version.

Regras aplicadas:
- Usa APENAS a correlação organizationEndpointPublisherOperatingSystems para os/version.
- Lê VICARIUS_BASE_URL e VICARIUS_API_KEY de .env no mesmo diretório do script por padrão.
- Respeita limites da API Vicarius (size<=500, até 60 req/min, from até 10k).
- Para volume >10k usa SEEK pagination.
- Retry para 429/5xx com backoff e headers de retry.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Generator

import requests
import urllib3

urllib3.disable_warnings()

MAX_SIZE = 500
MAX_FROM = 10_000

REQUEST_DELAY = float(os.environ.get("VRX_REQUEST_DELAY", "1.05"))
MAX_RETRIES = int(os.environ.get("VRX_MAX_RETRIES", "6"))
BACKOFF_BASE = float(os.environ.get("VRX_BACKOFF_BASE", "2"))
PROGRESS_INTERVAL = int(os.environ.get("VRX_PROGRESS_INTERVAL", "500"))

ENDPOINT_SEARCH_PATH = "/vicarius-external-data-api/endpoint/search"
ORG_ENDPOINT_OS_PATH = "/vicarius-external-data-api/organizationEndpointPublisherOperatingSystems/search"


def load_env(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.exists():
        return data

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"').strip("'")

    return data


def _retry_after_seconds(resp: requests.Response, fallback: float) -> float:
    for key in ("X-Rate-Limit-Retry-After-Seconds", "Retry-After"):
        raw = resp.headers.get(key)
        if raw:
            try:
                return max(float(raw), 1.0)
            except ValueError:
                pass
    return max(fallback, 1.0)


def query_api(
    session: requests.Session,
    base_url: str,
    headers: dict[str, str],
    endpoint_path: str,
    params: dict[str, Any],
    timeout: int = 60,
) -> tuple[int, dict[str, Any]]:
    """Executa GET com retry para 429/5xx e backoff exponencial."""
    url = f"{base_url}{endpoint_path}"
    backoff = BACKOFF_BASE

    for attempt in range(1, MAX_RETRIES + 1):
        time.sleep(REQUEST_DELAY)
        try:
            resp = session.get(
                url,
                headers=headers,
                params=params,
                timeout=timeout,
                verify=False,
            )
        except requests.RequestException as exc:
            if attempt >= MAX_RETRIES:
                print(f"[ERRO] Falha de rede persistente em {endpoint_path}: {exc}")
                return 0, {}
            print(
                f"[AVISO] Falha de rede em {endpoint_path} "
                f"(tentativa {attempt}/{MAX_RETRIES}). Aguardando {backoff:.1f}s..."
            )
            time.sleep(backoff)
            backoff *= 2
            continue

        if resp.status_code == 429:
            wait_s = _retry_after_seconds(resp, backoff)
            print(
                f"[429] Rate limit em {endpoint_path}. "
                f"Aguardando {wait_s:.1f}s (tentativa {attempt}/{MAX_RETRIES})..."
            )
            time.sleep(wait_s)
            backoff = max(backoff * 2, wait_s)
            continue

        if resp.status_code >= 500:
            if attempt >= MAX_RETRIES:
                print(f"[ERRO] HTTP {resp.status_code} persistente em {endpoint_path}.")
                return resp.status_code, {}
            print(
                f"[AVISO] HTTP {resp.status_code} em {endpoint_path} "
                f"(tentativa {attempt}/{MAX_RETRIES}). Aguardando {backoff:.1f}s..."
            )
            time.sleep(backoff)
            backoff *= 2
            continue

        if resp.status_code != 200:
            snippet = (resp.text or "")[:300]
            print(f"[ERRO] HTTP {resp.status_code} em {endpoint_path}: {snippet}")
            return resp.status_code, {}

        try:
            return resp.status_code, resp.json()
        except ValueError:
            print(f"[ERRO] Resposta inválida (não JSON) em {endpoint_path}.")
            return resp.status_code, {}

    return 0, {}


def get_total_count(
    session: requests.Session,
    base_url: str,
    headers: dict[str, str],
    endpoint_path: str,
) -> int:
    status, payload = query_api(
        session,
        base_url,
        headers,
        endpoint_path,
        {"from": 0, "size": 1},
        timeout=30,
    )
    if status != 200:
        return 0
    try:
        return int(payload.get("serverResponseCount", 0))
    except (TypeError, ValueError):
        return 0


def parse_server_response_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    items = payload.get("serverResponseObject", []) if isinstance(payload, dict) else []
    return items if isinstance(items, list) else []


def print_stage_progress(prefix: str, current: int, total: int) -> None:
    if total <= 0:
        print(f"\r{prefix}: {current}", end="", flush=True)
        return
    pct = (current / total) * 100
    print(f"\r{prefix}: {current}/{total} ({pct:5.1f}%)", end="", flush=True)


def fetch_all_with_from(
    session: requests.Session,
    base_url: str,
    headers: dict[str, str],
    endpoint_path: str,
    include_fields: str,
    total: int,
) -> Generator[dict[str, Any], None, None]:
    fr0m = 0
    page_num = 0

    while fr0m < total:
        size = min(MAX_SIZE, total - fr0m)
        page_num += 1
        status, payload = query_api(
            session,
            base_url,
            headers,
            endpoint_path,
            {
                "from": fr0m,
                "size": size,
                "includeFields": include_fields,
            },
        )
        if status != 200:
            break

        page = parse_server_response_items(payload)
        if not page:
            break

        yield from page
        fr0m += len(page)
        print_stage_progress(f"[PROGRESS] {endpoint_path} (from, página {page_num})", fr0m, total)

    print()


def fetch_all_with_seek(
    session: requests.Session,
    base_url: str,
    headers: dict[str, str],
    endpoint_path: str,
    include_fields: str,
    total: int,
) -> Generator[dict[str, Any], None, None]:
    """
    SEEK pagination para >10k:
    - from=0
    - size=500
    - sort=-endpointId
    - q=endpointId<ultimo_id
    """
    last_id: int | None = None
    seen_ids: set[str] = set()
    page_num = 0
    yielded_count = 0

    while True:
        page_num += 1
        params: dict[str, Any] = {
            "from": 0,
            "size": MAX_SIZE,
            "sort": "-endpointId",
            "includeFields": include_fields,
        }
        if last_id is not None:
            params["q"] = f"endpointId<{last_id}"

        status, payload = query_api(session, base_url, headers, endpoint_path, params)
        if status != 200:
            break

        page = parse_server_response_items(payload)
        if not page:
            break

        for row in page:
            key = str(row.get("endpointId") or "")
            if key and key in seen_ids:
                continue
            if key:
                seen_ids.add(key)
            yield row
            yielded_count += 1

        print_stage_progress(
            f"[PROGRESS] {endpoint_path} (seek, página {page_num})",
            yielded_count,
            total,
        )

        try:
            last_id = int(page[-1].get("endpointId"))
        except (TypeError, ValueError):
            break

        if len(page) < MAX_SIZE:
            break

    print()


def fetch_all(
    session: requests.Session,
    base_url: str,
    headers: dict[str, str],
    endpoint_path: str,
    include_fields: str,
) -> Generator[dict[str, Any], None, None]:
    total = get_total_count(session, base_url, headers, endpoint_path)
    if total <= 0:
        return

    strategy = "seek" if total > MAX_FROM else "from"
    print(f"[INFO] {endpoint_path}: total={total}, estratégia={strategy}")

    if total > MAX_FROM:
        yield from fetch_all_with_seek(session, base_url, headers, endpoint_path, include_fields, total)
    else:
        yield from fetch_all_with_from(session, base_url, headers, endpoint_path, include_fields, total)


def build_endpoint_lookup(
    session: requests.Session,
    base_url: str,
    headers: dict[str, str],
) -> dict[str, str]:
    endpoint_rows = fetch_all(
        session,
        base_url,
        headers,
        ENDPOINT_SEARCH_PATH,
        include_fields="endpointId,endpointName",
    )

    lookup: dict[str, str] = {}
    for row in endpoint_rows:
        endpoint_id = str(row.get("endpointId") or "").strip()
        endpoint_name = str(row.get("endpointName") or "").strip()
        if endpoint_id:
            lookup[endpoint_id] = endpoint_name

    print(f"[INFO] Endpoints mapeados: {len(lookup)}")
    return lookup


def collect_endpoint_so_records(
    session: requests.Session,
    base_url: str,
    headers: dict[str, str],
    endpoint_lookup: dict[str, str],
    output_path: Path,
) -> int:
    correlation_rows = fetch_all(
        session,
        base_url,
        headers,
        ORG_ENDPOINT_OS_PATH,
        include_fields=(
            "endpointId,publisherId,operatingSystemId,"
            "organizationEndpointPublisherOperatingSystemsOperatingSystem.operatingSystemName,"
            "organizationEndpointPublisherOperatingSystemsVersion.versionName"
        ),
    )

    seen: set[tuple[str, str, str]] = set()
    details_interval = PROGRESS_INTERVAL if PROGRESS_INTERVAL > 0 else 500
    count = 0

    with output_path.open("w", encoding="utf-8") as f:
        for idx, row in enumerate(correlation_rows, start=1):
            endpoint_id = str(row.get("endpointId") or "").strip()
            publisher_id = str(row.get("publisherId") or "N/A")
            operating_system_id = str(row.get("operatingSystemId") or "N/A")
            version_obj = (
                row.get("organizationEndpointPublisherOperatingSystemsVersion")
                or row.get("version")
                or {}
            )
            os_obj = (
                row.get("organizationEndpointPublisherOperatingSystemsOperatingSystem")
                or row.get("operatingSystem")
                or {}
            )

            os_name = str(os_obj.get("operatingSystemName") or "").strip()
            version = str(version_obj.get("versionName") or "").strip()

            if idx == 1 or idx % details_interval == 0:
                print(
                    f"\n[PROGRESS] Processando correlações: {idx}"
                    f"\n- publisherId={publisher_id}, "
                    f"operatingSystemId={operating_system_id}, "
                    f"OS={os_name or 'N/A'}, "
                    f"version={version or 'N/A'}"
                )

            # os/version devem vir apenas da correlação; se estiver vazio, ignora.
            if not os_name or not version:
                continue

            endpoint_name = endpoint_lookup.get(endpoint_id) or endpoint_id
            dedup_key = (endpoint_name, os_name, version)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            record = {
                "endpoint": endpoint_name,
                "os": os_name,
                "version": version,
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    print(f"[INFO] Registros endpoint/os/version salvos: {count}")
    return count


def main() -> int:
    script_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description="Gera endpoint_so.json com endpoint, os e version (somente via correlação)."
    )
    parser.add_argument(
        "--env",
        default=".env",
        help="Arquivo .env (default: .env ao lado do script)",
    )
    parser.add_argument(
        "--output",
        default="reports/endpoint_so.jsonl",
        help="Arquivo JSONL de saída (default: reports/endpoint_so.jsonl)",
    )
    args = parser.parse_args()

    env_path = Path(args.env)
    if not env_path.is_absolute():
        env_path = script_dir / env_path

    env_data = load_env(env_path)
    base_url = (env_data.get("VICARIUS_BASE_URL") or "").strip().rstrip("/")
    api_key = (env_data.get("VICARIUS_API_KEY") or "").strip()

    if not base_url or not api_key:
        print(
            "❌ ERRO: VICARIUS_BASE_URL e/ou VICARIUS_API_KEY ausentes. "
            "Preencha o .env no mesmo diretório do script."
        )
        return 1

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = script_dir / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    headers = {
        "Accept": "application/json",
        "Vicarius-Token": api_key,
    }

    print(f"[INFO] Base URL: {base_url}")
    print("[INFO] Coletando endpoints...")
    endpoint_lookup = build_endpoint_lookup(session, base_url, headers)

    print("[INFO] Coletando correlações de SO e salvando...")
    collect_endpoint_so_records(session, base_url, headers, endpoint_lookup, output_path)

    print(f"✅ Arquivo JSONL gerado: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
