#!/usr/bin/env python3
"""
Baixa e descomprime arquivos OVAL USN do Ubuntu com base nas versões
encontradas em um JSONL (default: reports/endpoint_so.jsonl).

Regras:
- considera apenas registros cujo campo "os" contém "ubuntu" (case-insensitive)
- extrai apenas major.minor da versão (ex.: 24.04.4 -> 24.04)
- converte versão para codename via mapa fixo
- faz download de:
  https://security-metadata.canonical.com/oval/com.ubuntu.<CODENAME>.usn.oval.xml.bz2
- salva em ./reports/oval/ e descomprime para .xml
"""

from __future__ import annotations

import argparse
import bz2
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


VERSION_TO_CODENAME: dict[str, str] = {
	"4.10": "warty",
	"5.04": "hoary",
	"5.10": "breezy",
	"6.06": "dapper",
	"6.10": "edgy",
	"7.04": "feisty",
	"7.10": "gutsy",
	"8.04": "hardy",
	"8.10": "intrepid",
	"9.04": "jaunty",
	"9.10": "karmic",
	"10.04": "lucid",
	"10.10": "maverick",
	"11.04": "natty",
	"11.10": "oneiric",
	"12.04": "precise",
	"12.10": "quantal",
	"13.04": "raring",
	"13.10": "saucy",
	"14.04": "trusty",
	"14.10": "utopic",
	"15.04": "vivid",
	"15.10": "wily",
	"16.04": "xenial",
	"16.10": "yakkety",
	"17.04": "zesty",
	"17.10": "artful",
	"18.04": "bionic",
	"18.10": "cosmic",
	"19.04": "disco",
	"19.10": "eoan",
	"20.04": "focal",
	"20.10": "groovy",
	"21.04": "hirsute",
	"21.10": "impish",
	"22.04": "jammy",
	"22.10": "kinetic",
	"23.04": "lunar",
	"23.10": "mantic",
	"24.04": "noble",
	"24.10": "oracular",
	"25.04": "plucky",
	"25.10": "questing",
	"26.04": "resolute",
}

OVAL_URL_TEMPLATE = "https://security-metadata.canonical.com/oval/com.ubuntu.{codename}.usn.oval.xml.bz2"


def normalize_major_minor(version_value: Any) -> str | None:
	text = str(version_value or "").strip()
	match = re.search(r"(\d+)\.(\d+)", text)
	if not match:
		return None
	major = int(match.group(1))
	minor = int(match.group(2))
	return f"{major}.{minor:02d}"


def extract_ubuntu_versions(data: list[dict[str, Any]]) -> list[str]:
	versions: set[str] = set()
	for row in data:
		os_name = str(row.get("os") or "")
		if "ubuntu" not in os_name.lower():
			continue
		normalized = normalize_major_minor(row.get("version"))
		if normalized:
			versions.add(normalized)

	return sorted(versions, key=lambda v: tuple(int(x) for x in v.split(".")))


def download_and_decompress(url: str, dest_bz2: Path, dest_xml: Path) -> None:
	with urlopen(url, timeout=120) as response, dest_bz2.open("wb") as f_out:
		shutil.copyfileobj(response, f_out)

	with bz2.open(dest_bz2, "rb") as f_in, dest_xml.open("wb") as f_out:
		shutil.copyfileobj(f_in, f_out)


def main() -> int:
	parser = argparse.ArgumentParser(
		description="Baixa e descomprime OVAL USN Ubuntu baseado em endpoint_so.jsonl"
	)
	parser.add_argument(
		"--input",
		default="reports/endpoint_so.jsonl",
		help="JSONL de entrada com campos os/version (default: reports/endpoint_so.jsonl)",
	)
	parser.add_argument(
		"--output-dir",
		default="reports/oval",
		help="Diretório de saída para .bz2 e .xml (default: reports/oval)",
	)
	args = parser.parse_args()

	script_dir = Path(__file__).resolve().parent
	input_path = Path(args.input)
	if not input_path.is_absolute():
		input_path = script_dir / input_path

	output_dir = Path(args.output_dir)
	if not output_dir.is_absolute():
		output_dir = script_dir / output_dir
	output_dir.mkdir(parents=True, exist_ok=True)

	if not input_path.exists():
		print(f"❌ Arquivo JSON não encontrado: {input_path}")
		return 1

	try:
		payload = []
		for line in input_path.read_text(encoding="utf-8").splitlines():
			line = line.strip()
			if line:
				payload.append(json.loads(line))
	except json.JSONDecodeError as exc:
		print(f"❌ JSON inválido em {input_path}: {exc}")
		return 1

	if not isinstance(payload, list):
		print(f"❌ Estrutura inesperada em {input_path}: esperado array ou linhas JSON.")
		return 1

	versions = extract_ubuntu_versions(payload)
	if not versions:
		print("⚠️ Nenhuma versão Ubuntu encontrada no JSON informado.")
		return 0

	print(f"[INFO] Versões Ubuntu detectadas: {', '.join(versions)}")

	unknown_versions: list[str] = []
	codenames: list[str] = []
	for version in versions:
		codename = VERSION_TO_CODENAME.get(version)
		if not codename:
			unknown_versions.append(version)
			continue
		codenames.append(codename)

	if unknown_versions:
		print(
			"[AVISO] Versões sem mapeamento para codename (ignoradas): "
			+ ", ".join(unknown_versions)
		)

	if not codenames:
		print("⚠️ Nenhuma versão com codename mapeado. Nada para baixar.")
		return 0

	downloaded = 0
	for codename in sorted(set(codenames)):
		for feed_type in ["usn", "cve"]:
			url = f"https://security-metadata.canonical.com/oval/com.ubuntu.{codename}.{feed_type}.oval.xml.bz2"
			bz2_name = f"com.ubuntu.{codename}.{feed_type}.oval.xml.bz2"
			xml_name = f"com.ubuntu.{codename}.{feed_type}.oval.xml"
			dest_bz2 = output_dir / bz2_name
			dest_xml = output_dir / xml_name

			print(f"[DOWNLOAD] {url}")
			try:
				download_and_decompress(url, dest_bz2, dest_xml)
				downloaded += 1
				print(f"[OK] Arquivos salvos: {dest_bz2} e {dest_xml}")
			except HTTPError as exc:
				print(f"[ERRO] HTTP {exc.code} ao baixar {url}")
			except URLError as exc:
				print(f"[ERRO] Falha de rede ao baixar {url}: {exc}")
			except OSError as exc:
				print(f"[ERRO] Falha ao salvar/descomprimir {url}: {exc}")

	print(f"✅ Concluído. Releases baixadas/descomprimidas: {downloaded}")
	return 0


if __name__ == "__main__":
	sys.exit(main())
