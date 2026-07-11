🛡️ Dns_Actions_PRO — Domain Security & Anti‑Phishing Analyzer
Dns_Actions_PRO è uno strumento di analisi DNS progettato per verificare la protezione di un dominio contro attacchi di phishing, spoofing e impersonation.
Il tool esegue controlli sia base che avanzati (PRO), analizzando i record DNS più importanti per la sicurezza delle email e dell’infrastruttura del dominio.

🔍 Funzionalità Base
SPF — verifica la policy anti‑spoofing

DMARC — controlla la policy e i report

MX — analizza i mail server configurati

NS — verifica i nameserver autoritativi

A Record — identifica l’IP del dominio

Audit — genera un punteggio di sicurezza da 0 a 100

🔥 Funzionalità PRO (Analisi Avanzata)
DKIM Scanner — rileva selettori e chiavi DKIM

DNSSEC Check — verifica la protezione crittografica del DNS

MTA‑STS — controlla la policy SMTP sicura

TLS‑RPT — verifica i report TLS del dominio

Geo‑IP — identifica posizione, ASN e provider dell’IP

IPv6 (AAAA) — verifica la presenza del record IPv6

CNAME Lookup — rileva eventuali alias del dominio

BIMI — verifica la presenza del logo certificato nelle email

Modalità Hacker — riepilogo rapido stile penetration testing

🎯 Obiettivo del progetto
Dns_Actions_PRO nasce per offrire un modo semplice e veloce per valutare la sicurezza di un dominio contro:

phishing

spoofing

email impersonation

attacchi DNS

configurazioni errate dei record

È pensato per:

tecnici IT

help desk

sistemisti

esperti di cybersecurity

pentester

studenti

🧩 Tecnologie utilizzate
Python

DIG

dnspython

ipinfo API

ANSI terminal colors

📦 Installazione
Clona il repository:

Codice
git clone https://github.com/Nessuno2605/Dns_Actions_PRO.git
Entra nella cartella:

Codice
cd Dns_Actions_PRO
Esegui il programma:

Codice
python Dns_actions.py
🛠️ Roadmap
[ ] Aggiungere analisi CAA

[ ] Aggiungere analisi SOA

[ ] Aggiungere analisi PTR

[ ] Aggiungere analisi certificato SSL

[ ] Aggiungere takeover DNS detection

[ ] Aggiungere export report

[ ] Versione GUI

👤 Autore
Francesco D.  
Cybersecurity & Ethical Hacking

📄 Licenza
MIT License
