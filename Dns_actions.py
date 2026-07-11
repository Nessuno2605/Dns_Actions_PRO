import subprocess
import dns.resolver
import ipaddress
import shutil
import requests

# ===== COLORI =====
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[37m"
RESET = "\033[0m"

banner = """
# ============================
# ===Dns_Actions By F.D=====
# ============================
"""

# BANNER
def center_banner(text):
    columns = shutil.get_terminal_size().columns
    lines = text.split("\n")
    centered = ""
    for line in lines:
        if line.strip() == "":
            centered += "\n"
        else:
            centered += line.center(columns) + "\n"
    return centered

# DIG QUERY
def dig_query(domain, record, dns_server):
    cmd = ["dig", domain, record, f"@{dns_server}"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

# SPF
def analyze_spf(domain):
    return dig_query(domain, "TXT", "8.8.8.8")

def extract_spf(output):
    for line in output.splitlines():
        if "v=spf1" in line:
            return line.strip()
    return "SPF non trovato"

# DMARC
def analyze_dmarc(domain):
    return dig_query("_dmarc." + domain, "TXT", "8.8.8.8")

def extract_dmarc(output):
    for line in output.splitlines():
        if "v=DMARC1" in line:
            return line.strip()
    return "DMARC non trovato"

# MX
def analyze_mx(domain):
    return dig_query(domain, "MX", "8.8.8.8")

def extract_mx(output):
    mx_records = []
    answer_section = False

    for line in output.splitlines():
        if "ANSWER SECTION" in line:
            answer_section = True
            continue
        if answer_section and "MX" in line and "IN" in line:
            mx_records.append(line.strip())
        if answer_section and line.strip() == "":
            break

    return mx_records if mx_records else ["MX non trovato"]

# NS
def analyze_ns(domain):
    return dig_query(domain, "NS", "8.8.8.8")

def extract_ns(output):
    ns_records = []
    answer_section = False

    for line in output.splitlines():
        if "ANSWER SECTION" in line:
            answer_section = True
            continue
        if answer_section and "NS" in line and "IN" in line:
            ns_records.append(line.strip())
        if answer_section and line.strip() == "":
            break

    return ns_records if ns_records else ["NS non trovato"]

# A RECORD
def analyze_a(domain):
    return dig_query(domain, "A", "8.8.8.8")

def extract_ip(output):
    ips = []

    for line in output.splitlines():
        # Normalizza TAB → spazio
        line = line.replace("\t", " ")

        # Prende SOLO le righe della ANSWER SECTION
        if " IN A " in line:
            parts = line.split()
            ip = parts[-1]
            if ip.count(".") == 3:
                ips.append(ip)

    # Se ci sono più IP, prendi il primo (o tutti)
    if ips:
        return ips[0]

    return "IP non trovato"


# SCORING SYSTEM
def score_spf(spf):
    if spf == "SPF non trovato":
        return 0
    if "~all" in spf:
        return 70
    if "-all" in spf:
        return 100
    return 40

def score_dmarc(dmarc):
    if dmarc == "DMARC non trovato":
        return 0
    if "p=reject" in dmarc:
        return 100
    if "p=quarantine" in dmarc:
        return 70
    if "p=none" in dmarc:
        return 30
    return 40

def score_mx(mx):
    if mx == ["MX non trovato"]:
        return 0
    return 100

def score_ns(ns):
    if ns == ["NS non trovato"]:
        return 0
    return 100

def score_ip(ip):
    if ip == "IP non trovato":
        return 0
    # Cloud / estero detection base
    if ip.startswith(("34.", "35.", "52.", "54.", "142.", "172.", "192.")):
        return 100
    return 70

def final_strength(total):
    if total >= 90:
        return f"{GREEN}ECCELLENTE{RESET}"
    if total >= 70:
        return f"{CYAN}BUONO{RESET}"
    if total >= 50:
        return f"{YELLOW}MEDIO{RESET}"
    if total >= 30:
        return f"{RED}DEBOLE{RESET}"
    return f"{RED}CRITICO{RESET}"

#DKIM Scanner
def check_dkim(domain):
    selectors = [
        "default", "selector1", "selector2",
        "google", "mail", "s1", "s2"
    ]

    results = []

    for sel in selectors:
        query = f"{sel}._domainkey.{domain}"
        dig = subprocess.run(["dig", "TXT", query], capture_output=True, text=True)
        out = dig.stdout

        if "v=DKIM1" in out:
            # Estrai la chiave
            for line in out.splitlines():
                if "p=" in line:
                    key = line.split("p=")[1].replace('"', '').strip()
                    bits = len(key) * 6  # stima bit
                    results.append(f"{sel}: valido – chiave ~{bits} bit")
                    break

    if results:
        return "\n".join(results)
    else:
        return "DKIM non trovato – rischio spoofing elevato"

#DNSSec
def check_dnssec(domain):
    dig = subprocess.run(["dig", "+dnssec", domain], capture_output=True, text=True)
    out = dig.stdout

    if "RRSIG" in out or "DNSKEY" in out or "DS" in out:
        return "DNSSEC: attivo – protezione anti-spoofing"
    else:
        return "DNSSEC: NON attivo – rischio spoofing DNS"

#MTA‑STS + TLS‑RPT
def check_mta_sts(domain):
    sts = subprocess.run(["dig", "TXT", f"_mta-sts.{domain}"], capture_output=True, text=True).stdout
    tls = subprocess.run(["dig", "TXT", f"_smtp._tls.{domain}"], capture_output=True, text=True).stdout

    result = ""

    if "v=STSv1" in sts:
        result += "MTA-STS: configurato\n"
    else:
        result += "MTA-STS: assente\n"

    if "v=TLSRPTv1" in tls:
        result += "TLS-RPT: configurato\n"
    else:
        result += "TLS-RPT: assente\n"

    return result

#Geolocalizzazione
def check_geoip(ip):
    try:
        data = requests.get(f"https://ipinfo.io/{ip}/json").json()
        return f"{ip} → {data.get('country')} – {data.get('org')} – {data.get('city')}"
    except:
        return "Geo-IP non disponibile"
#AAAA IPv6
def check_ipv6(domain):
    dig = subprocess.run(["dig", "AAAA", domain], capture_output=True, text=True).stdout
    ips = []

    for line in dig.splitlines():
        if " IN AAAA " in line:
            ips.append(line.split()[-1])

    if ips:
        return "\n".join(ips)
    else:
        return "IPv6 non presente"

#CNAME
def check_cname(domain):
    dig = subprocess.run(["dig", "CNAME", domain], capture_output=True, text=True).stdout

    for line in dig.splitlines():
        if " CNAME " in line:
            return line.split()[-1]

    return "Nessun CNAME rilevato"

#BIMI
def check_bimi(domain):
    dig = subprocess.run(["dig", "TXT", f"default._bimi.{domain}"], capture_output=True, text=True).stdout

    if "v=BIMI1" in dig:
        return "BIMI: configurato"
    else:
        return "BIMI: assente"

#mode
def hacker_mode(results):
    out = ""
    for key, val in results.items():
        if "NON" in val or "assente" in val:
            out += f"[-] {key}\n"
        else:
            out += f"[+] {key}\n"
    return out


# ESECUZIONE PROGRAMMA

print(center_banner(banner))
dominio = input("Inserisci il dominio: ")

print("\n================ SPF ================")
spf_raw = analyze_spf(dominio)
spf = extract_spf(spf_raw)
print(spf)

print("\n================ DMARC ===============")
dmarc_raw = analyze_dmarc(dominio)
dmarc = extract_dmarc(dmarc_raw)
print(dmarc)

print("\n================ MX ==================")
mx_raw = analyze_mx(dominio)
mx_clean = extract_mx(mx_raw)
for mx in mx_clean:
    parts = mx.split()
    if len(parts) >= 6:
        priority = parts[-2]
        server = parts[-1]
        print(f"- {server} (priority {priority})")

print("\n================ NS ==================")
ns_raw = analyze_ns(dominio)
ns_clean = extract_ns(ns_raw)
for ns in ns_clean:
    parts = ns.split()
    print(f"- {parts[-1]}")

print("\n================ A ===================")
a_raw = analyze_a(dominio)
ip = extract_ip(a_raw)
print(f"- {ip}")

#OUTPUT FINALE
spf_score = score_spf(spf)
dmarc_score = score_dmarc(dmarc)
mx_score = score_mx(mx_clean)
ns_score = score_ns(ns_clean)
ip_score = score_ip(ip)

total_score = int((spf_score + dmarc_score + mx_score + ns_score + ip_score) / 5)
strength = final_strength(total_score)

print("\n================ AUDIT ===================")

print(f"SPF: {spf_score}/100")
print(f"DMARC: {dmarc_score}/100")
print(f"MX: {mx_score}/100")
print(f"NS: {ns_score}/100")
print(f"A: {ip_score}/100")

print(f"\nPunteggio totale: {CYAN}{total_score}/100{RESET}")
print(f"Livello di forza: {strength}")

if total_score < 50:
    print(f"{RED}Dominio vulnerabile a spoofing e impersonation.{RESET}")
elif total_score < 80:
    print(f"{YELLOW}Dominio parzialmente protetto. Miglioramenti consigliati.{RESET}")
else:
    print(f"{GREEN}Dominio ben protetto contro spoofing e phishing.{RESET}")

print("\n------------------------------------------------------------")
print("                 SEZIONE PRO — ANALISI AVANZATA")
print("------------------------------------------------------------\n")

print("=============== DKIM ================")
dkim = check_dkim(dominio)
print(dkim)

print("\n=============== DNSSEC ================")
dnssec = check_dnssec(dominio)
print(dnssec)

print("\n=============== MTA-STS ================")
mta = check_mta_sts(dominio)
print(mta)

print("\n=============== GEO-IP ================")
geo = check_geoip(ip)
print(geo)

print("\n=============== AAAA IPv6 ================")
ipv6 = check_ipv6(dominio)
print(ipv6)

print("\n=============== CNAME ================")
cname = check_cname(dominio)
print(cname)

print("\n=============== BIMI ================")
bimi = check_bimi(dominio)
print(bimi)

print("\n=============== DIFESE ATTIVE ================")
results = {
    "DKIM": dkim,
    "DNSSEC": dnssec,
    "MTA-STS": mta,
    "Geo-IP": geo,
    "IPv6": ipv6,
    "CNAME": cname,
    "BIMI": bimi
}
print(hacker_mode(results))
