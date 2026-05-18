import os
import sys
import json
import argparse
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET

# --- consulta API Ubuntu Security para CVEs ausentes da OVAL tree ---
def query_ubuntu_security_api(cve, codename, package):
    url = f"https://ubuntu.com/security/cves/{cve}.json"
    try:
        print(f"[*] Consultando API Ubuntu Security: {url} (release={codename}, pkg={package})", file=sys.stderr)
        req = urllib.request.Request(url, headers={"User-Agent": "vRx-OVAL-Checker/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as e:
        print(f"[!] Falha ao consultar API Ubuntu: {e}", file=sys.stderr)
        return None

    pkg_lower = package.lower().strip()
    # Variantes comuns de nome de pacote no Ubuntu (xz -> xz-utils, openssl -> openssl, etc.)
    candidates = {
        pkg_lower,
        f"{pkg_lower}-utils",
        f"{pkg_lower}-bin",
        f"{pkg_lower}-common",
        pkg_lower.replace("_", "-"),
    }

    def _match(name):
        n = (name or "").lower()
        if not n:
            return False
        if n in candidates or pkg_lower in n or n in pkg_lower:
            return True
        return False

    matches = []
    for pkg in data.get("packages", []):
        if not _match(pkg.get("name", "")):
            continue
        for st in pkg.get("statuses", []):
            if st.get("release_codename") != codename:
                continue
            matches.append((pkg.get("name"), st.get("status")))

    if not matches:
        return None
    # Preferir nome exato > nome com candidato > primeiro match
    for name, status in matches:
        if (name or "").lower() == pkg_lower:
            return status
    return matches[0][1]


# Mapeia status da API Ubuntu Security para o vocabulario interno
UBUNTU_API_STATUS_MAP = {
    "released":       ("fixed",        "high"),
    "released-esm":   ("fixed",        "high"),
    "not-affected":   ("not_affected", "high"),
    "DNE":            ("unknown",      "low"),    # Ubuntu nao empacota; pacote 3rd-party precisa avaliacao manual
    "deferred":       ("vulnerable",   "high"),  # Vulneravel, fix deferred
    "needed":         ("vulnerable",   "high"),  # Vulneravel, fix pendente
    "needs-triage":   ("unknown",      "low"),   # Ubuntu ainda nao avaliou -> Needs evaluation
    "pending":        ("vulnerable",   "high"),
    "active":         ("vulnerable",   "high"),
    "ignored":        ("unknown",      "low"),    # geralmente EOL; nao garante seguranca da versao instalada
}

# --- mapa fixo ---
UBUNTU_MAP = {
    "18.04": "bionic",
    "20.04": "focal",
    "22.04": "jammy",
    "24.04": "noble",
    "26.04": "resolute"
}

SCRIPT_DIR = os.path.dirname(__file__)
REPORTS_DIR = os.path.join(SCRIPT_DIR, 'reports')
OVAL_DIR = os.path.join(REPORTS_DIR, 'oval')

# --- normaliza versão ---
def normalize_ubuntu(v):
    if v in UBUNTU_MAP.values():
        return v
    base = ".".join(v.split(".")[:2])
    return UBUNTU_MAP.get(base)

# --- compara versão ---
def debian_compare(v1, op, v2):
    def _deb_str_cmp(s1, s2):
        i = j = 0
        while i < len(s1) or j < len(s2):
            nd1, nd2 = "", ""
            while i < len(s1) and not s1[i].isdigit():
                nd1 += s1[i]; i += 1
            while j < len(s2) and not s2[j].isdigit():
                nd2 += s2[j]; j += 1
            
            for c1, c2 in zip(nd1 + "\0", nd2 + "\0"):
                if c1 == c2: continue
                if c1 == "\0": return 1 if c2 == '~' else -1
                if c2 == "\0": return -1 if c1 == '~' else 1
                if c1 == '~': return -1
                if c2 == '~': return 1
                return 1 if c1 > c2 else -1

            d1, d2 = "", ""
            while i < len(s1) and s1[i].isdigit():
                d1 += s1[i]; i += 1
            while j < len(s2) and s2[j].isdigit():
                d2 += s2[j]; j += 1
                
            n1 = int(d1) if d1 else 0
            n2 = int(d2) if d2 else 0
            if n1 != n2:
                return 1 if n1 > n2 else -1
                
        return 0

    def parse_ver(v):
        epoch = 0
        if ':' in v:
            e, v = v.split(':', 1)
            epoch = int(e)
        rev = ""
        if '-' in v:
            v, rev = v.rsplit('-', 1)
        return epoch, v, rev
        
    e1, u1, r1 = parse_ver(v1)
    e2, u2, r2 = parse_ver(v2)
    
    cmp = 0
    if e1 != e2:
        cmp = 1 if e1 > e2 else -1
    else:
        cmp = _deb_str_cmp(u1, u2)
        if cmp == 0:
            cmp = _deb_str_cmp(r1, r2)
            
    if op in ("lt", "less than"): return cmp < 0
    if op in ("le", "less than or equal"): return cmp <= 0
    if op in ("gt", "greater than"): return cmp > 0
    if op in ("ge", "greater than or equal"): return cmp >= 0
    if op in ("eq", "equals"): return cmp == 0
    return False

def compare_versions(installed, op, target):
    # Conforme solicitado: ignora a revisão/patch do Ubuntu (tudo após o hífen)
    if '-' in installed:
        installed = installed.split('-')[0]
    if '-' in target:
        target = target.split('-')[0]
        
    # Remove Epoch (tudo antes do ':') para que 9.1.0016 seja igual a 2:9.1.0016
    if ':' in installed:
        installed = installed.split(':')[-1]
    if ':' in target:
        target = target.split(':')[-1]
        
    return debian_compare(installed, op, target)

# --- busca CVE no OVAL ---
def find_cve_in_oval(oval_file, cve):
    tree = ET.parse(oval_file)
    root = tree.getroot()

    ns = {
        'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
        'linux': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux'
    }

    rules = []

    for definition in root.findall(".//oval:definition", ns):
        metadata = definition.find("oval:metadata", ns)
        if metadata is None:
            continue

        found_cve = False
        for c in metadata.findall(".//oval:cve", ns):
            if c.text and cve in c.text:
                found_cve = True
                break
        
        if not found_cve:
            title = metadata.find("oval:title", ns)
            if title is not None and cve in title.text:
                found_cve = True

        if not found_cve:
            continue

        # encontrou CVE
        criteria = definition.find(".//oval:criteria", ns)
        if criteria is None:
            continue

        for criterion in criteria.findall(".//oval:criterion", ns):
            test_ref = criterion.attrib.get("test_ref")
            if not test_ref:
                continue

            test = root.find(f".//linux:dpkginfo_test[@id='{test_ref}']", ns)
            if test is None:
                continue

            state_elem = test.find("linux:state", ns)
            if state_elem is None:
                continue
            state_ref = state_elem.attrib.get("state_ref")

            state = root.find(f".//linux:dpkginfo_state[@id='{state_ref}']", ns) if state_ref else None
            if state is None:
                continue

            evr = state.find("linux:evr", ns)
            if evr is None:
                ver_el = state.find("linux:version", ns)
                if ver_el is None:
                    continue
                version_str = ver_el.text
                operation_str = ver_el.attrib.get("operation")
            else:
                version_str = evr.text
                operation_str = evr.attrib.get("operation")

            obj_elem = test.find("linux:object", ns)
            if obj_elem is None:
                continue
            obj_ref = obj_elem.attrib.get("object_ref")
            
            obj = root.find(f".//linux:dpkginfo_object[@id='{obj_ref}']", ns) if obj_ref else None
            if obj is None:
                continue

            name_el = obj.find("linux:name", ns)
            pkgs = []
            if name_el is not None:
                var_ref = name_el.attrib.get("var_ref")
                if var_ref:
                    var = root.find(f".//oval:constant_variable[@id='{var_ref}']", ns)
                    if var is not None:
                        for val in var.findall("oval:value", ns):
                            if val.text: pkgs.append(val.text)
                elif name_el.text:
                    pkgs.append(name_el.text)
            
            for pkg in pkgs:
                rules.append({
                    "package": pkg,
                    "operation": operation_str,
                    "version": version_str
                })

    return rules


# --- função principal ---
def check_cve(ubuntu_version, cve, installed_packages):
    import sys
    print(f"[*] Iniciando análise para {cve} no Ubuntu {ubuntu_version}...", file=sys.stderr)

    # normaliza os pacotes instalados para minúsculo
    installed_packages_lower = {k.lower(): v for k, v in installed_packages.items()}

    codename = normalize_ubuntu(ubuntu_version)
    if not codename:
        print("[!] Versão do Ubuntu não suportada.", file=sys.stderr)
        return {"error": "Ubuntu version não suportada"}

    usn_path = os.path.join(OVAL_DIR, f"com.ubuntu.{codename}.usn.oval.xml")
    cve_path = os.path.join(OVAL_DIR, f"com.ubuntu.{codename}.cve.oval.xml")

    print(f"[*] Buscando arquivos OVAL: {usn_path} e {cve_path}", file=sys.stderr)
    if not os.path.exists(usn_path) and not os.path.exists(cve_path):
        print("[!] Nenhum arquivo OVAL encontrado localmente.", file=sys.stderr)
        return {"error": f"Arquivos OVAL não encontrados para: {codename}"}

    rules = []
    if os.path.exists(usn_path):
        print(f"[*] Consultando feed USN ({usn_path})...", file=sys.stderr)
        rules = find_cve_in_oval(usn_path, cve)
        
    if not rules and os.path.exists(cve_path):
        print(f"[*] CVE não encontrada no USN. Consultando feed CVE tracker ({cve_path})...", file=sys.stderr)
        rules = find_cve_in_oval(cve_path, cve)

    if not rules:
        print("[*] CVE não consta nas bases OVAL. Tentando fallback via API Ubuntu Security...", file=sys.stderr)
        api_results = []
        api_status_overall = None
        api_confidence = "medium"
        for pkg_name in installed_packages.keys():
            api_status = query_ubuntu_security_api(cve, codename, pkg_name)
            if not api_status:
                continue
            mapped, conf = UBUNTU_API_STATUS_MAP.get(api_status, ("unknown", "low"))
            api_results.append({
                "package": pkg_name,
                "ubuntu_api_status": api_status,
                "status": mapped,
                "confidence": conf,
                "source": "ubuntu_api"
            })
            # Prioridade: vulnerable > unknown > fixed/not_affected
            if mapped == "vulnerable":
                api_status_overall = "vulnerable"
                api_confidence = conf
            elif mapped == "unknown" and api_status_overall != "vulnerable":
                api_status_overall = "unknown"
                api_confidence = conf
            elif api_status_overall is None:
                api_status_overall = mapped
                api_confidence = conf

        if api_status_overall:
            sub_status_reason = {
                "needs-triage": "Ubuntu ainda nao avaliou esta CVE para a release (needs-triage)",
                "DNE":          "Ubuntu nao empacota este software na release; versao instalada e 3rd-party e requer avaliacao manual",
                "ignored":      "Ubuntu marcou como ignored (ex.: EOL); nao garante seguranca da versao instalada",
                "deferred":     "Ubuntu marca a CVE como vulneravel, fix deferred",
                "needed":       "Ubuntu marca a CVE como vulneravel, fix needed",
                "pending":      "Ubuntu marca a CVE como vulneravel, fix pending",
                "active":       "Ubuntu marca a CVE como vulneravel, fix active",
                "released":     "Ubuntu reporta correcao disponivel para esta release",
                "released-esm": "Ubuntu reporta correcao disponivel via ESM para esta release",
                "not-affected": "Ubuntu reporta release nao afetada por esta CVE",
            }
            # Pega o sub_status do primeiro detalhe que casa com o status agregado
            chosen_sub = None
            for d in api_results:
                if d.get("status") == api_status_overall:
                    chosen_sub = d.get("ubuntu_api_status")
                    break
            reason = sub_status_reason.get(chosen_sub, "Resposta da API Ubuntu Security")
            return {
                "cve_id": cve,
                "status": api_status_overall,
                "confidence": api_confidence,
                "source": "ubuntu_api",
                "reason": reason,
                "details": api_results
            }

        print("[*] API Ubuntu sem dados conclusivos. Marcando como Needs evaluation (pacote presente no endpoint).", file=sys.stderr)
        return {
            "cve_id": cve,
            "status": "unknown",
            "confidence": "low",
            "source": "heuristic",
            "reason": "CVE ausente da OVAL e da API Ubuntu Security; pacote esta instalado e requer avaliacao manual"
        }

    print(f"[*] Extração finalizada, validando {len(rules)} regra(s)...", file=sys.stderr)

    confidence = "high"
    source = "oval"

    results = []
    
    # Avaliação OVAL
    for rule in rules:
        pkg = rule["package"].lower()

        if pkg not in installed_packages_lower:
            continue

        installed_version = installed_packages_lower[pkg]

        vulnerable = compare_versions(
            installed_version,
            rule["operation"],
            rule["version"]
        )

        results.append({
            "package": pkg,
            "installed_version": installed_version,
            "rule": f"{rule['operation']} {rule['version']}",
            "status": "vulnerable" if vulnerable else "fixed",
            "confidence": confidence,
            "source": source
        })

    if not results:
        return {
            "cve_id": cve,
            "status": "not_affected", 
            "confidence": "medium",
            "source": "heuristic",
            "reason": "Pacote não encontrado ou estruturalmente não afetado (ausente na OVAL tree de pacotes vulneráveis)"
        }

    status = "vulnerable" if any(r["status"] == "vulnerable" for r in results) else "fixed"

    return {
        "cve_id": cve,
        "status": status,
        "confidence": confidence,
        "source": source,
        "details": results
    }


# --- EXEMPLO DE USO ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verifica status de CVE no OVAL do Ubuntu")
    parser.add_argument("--ubuntu", required=True, help="Versão do Ubuntu (ex: 22.04)")
    parser.add_argument("--cve", required=True, help="CVE para buscar (ex: CVE-2016-4956)")
    parser.add_argument("--pkg", required=True, action="append", help="Pacote e versão instalada no formato nome:versão (ex: NTP:4.2.8). Pode ser usado múltiplas vezes para diferentes pacotes.")
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    
    installed_packages = {}
    for p in args.pkg:
        if ":" in p:
            name, ver = p.split(":", 1)
            installed_packages[name] = ver
        else:
            print(f"Formato inválido para pacote ignorado: {p}", file=sys.stderr)

    result = check_cve(args.ubuntu, args.cve, installed_packages)
    import json
    print(json.dumps(result, indent=2))