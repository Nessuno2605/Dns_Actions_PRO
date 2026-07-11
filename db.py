# ============================
# DATABASE UNICO
# ============================

# PROVIDER DNS / EMAIL / CLOUD
provider_db = {
    "google_workspace": [
        "google.com",
        "_spf.google.com",
        "aspmx.l.google.com",
        "gmail-smtp-in.l.google.com"
    ],

    "microsoft_365": [
        "outlook.com",
        "protection.outlook.com",
        "office365.com",
        "mail.protection.outlook.com"
    ],

    "cloudflare": [
        "cloudflare.com",
        "cdn.cloudflare.net"
    ],

    "cisco": [
        "messagelabs.com",
        "cisco.com"
    ],

    "aruba": [
        "aruba.it",
        "arubabusiness.it"
    ],

    "register": [
        "register.it"
    ],

    "sophos": [
        "sophos.com",
        "protection.sophos.com"
    ],

    "zoho": [
        "zoho.com",
        "zoho.eu"
    ],

    "google_cloud": [
        "googleusercontent.com",
        "gcp.gvt2.com"
    ],

    "aws": [
        "amazonaws.com",
        "awsdns"
    ],

    "azure_cloud": [
        "azure.com",
        "microsoftazure.de",
        "cloudapp.net"
    ],

    "ovh": [
        "ovh.net",
        "ovhcloud.com"
    ],

    "hetzner": [
        "hetzner.com",
        "your-server.de"
    ]
}


# ============================
# IP RANGE ITALIANI
# ============================

italy_ip_ranges = [
    "5.90.0.0/16",     # TIM
    "37.160.0.0/12",   # Vodafone
    "79.0.0.0/11",     # Fastweb
    "151.0.0.0/16",    # WindTre
    "93.34.0.0/15",    # Telecom Italia
    "2.32.0.0/13"      # Telecom Italia
]


# ============================
# IP RANGE CLOUD PROVIDER
# ============================

cloud_ip_ranges = {
    "aws": [
        "3.0.0.0/8",
        "13.0.0.0/8",
        "52.0.0.0/8"
    ],

    "google_cloud": [
        "8.8.8.0/24",
        "8.34.0.0/15",
        "8.35.0.0/16"
    ],

    "azure": [
        "40.64.0.0/10",
        "52.96.0.0/12"
    ],

    "ovh": [
        "51.38.0.0/16",
        "54.36.0.0/15"
    ],

    "hetzner": [
        "88.198.0.0/16",
        "144.76.0.0/16"
    ]
}


# ============================
# DKIM SELECTOR COMUNI
# ============================

dkim_selectors = [
    "default",
    "selector1",
    "selector2",
    "google",
    "smtp",
    "mail",
    "dkim"
]


# ============================
# RECORD DA CONTROLLARE
# ============================

records_to_check = [
    "SPF",
    "DKIM",
    "DMARC",
    "MX",
    "NS",
    "A"
]
