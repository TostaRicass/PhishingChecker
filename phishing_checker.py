import imaplib
import email
import re
import time
import requests
from config import (
    IMAP_SERVER,
    IMAP_PORT,
    EMAIL_ACCOUNT,
    EMAIL_PASSWORD,
    VIRUSTOTAL_API_KEY,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
)

def check_virustotal_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            # Si detección de malware > 0 consideramos malicioso
            return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0
    except Exception as e:
        print(f"[VT IP] Error: {e}")
    return False

def check_virustotal_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0
    except Exception as e:
        print(f"[VT Domain] Error: {e}")
    return False

def check_threatfox(domain):
    url = f"https://threatfox-api.abuse.ch/api/v1/"
    payload = {
        "query": "get_ioc_details",
        "ioc": domain,
        "ioc_type": "domain"
    }
    try:
        r = requests.post(url, data=payload, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return data.get("query_status") == "ok"
    except Exception as e:
        print(f"[ThreatFox] Error: {e}")
    return False

def alert_telegram(message):
    url = f"https://api.telegram.org/tu_token_de_telegram/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        response = requests.post(url, data=payload, timeout=10)
        print(f"[Telegram] Status: {response.status_code}")
        if response.status_code != 200:
            print(f"[Telegram] Error: {response.text}")
    except Exception as e:
        print(f"[Telegram] Exception: {e}")

def extract_domain(email_address):
    # Extrae dominio de un correo electrónico
    match = re.search(r"@([^\s>]+)", email_address)
    return match.group(1) if match else ""

def main():
    while True:
        print("[*] Conectando al correo...")
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
            mail.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
            mail.select("inbox")

            status, messages = mail.search(None, 'UNSEEN')
            if status != "OK":
                print("[!] Error buscando mensajes")
                mail.logout()
                time.sleep(300)
                continue

            for num in messages[0].split():
                print(f"[+] Procesando email ID: {num.decode()}")
                status, data = mail.fetch(num, '(RFC822)')
                if status != "OK":
                    print(f"[!] No se pudo leer email {num.decode()}")
                    continue

                msg = email.message_from_bytes(data[0][1])
                sender = msg.get("From", "")
                sender_email_match = re.search(r"<(.+?)>", sender)
                sender_email = sender_email_match.group(1) if sender_email_match else sender

                domain = extract_domain(sender_email)

                # Extraer IP del email (simplificado, desde Received headers)
                ip_match = None
                for header in msg.get_all("Received", []):
                    ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", header)
                    if ip_match:
                        break
                sender_ip = ip_match.group(0) if ip_match else ""

                vt_domain = check_virustotal_domain(domain) if domain else False
                threatfox_domain = check_threatfox(domain) if domain else False
                ip_malicious = check_virustotal_ip(sender_ip) if sender_ip else False

                if vt_domain or threatfox_domain or ip_malicious:
                    message = f"""
🚨 *Phishing detectado*:
👤 Remitente: `{sender_email}`
🌐 Dominio: `{domain}`

*Detalles:*
{"🔴 VirusTotal (dominio)" if vt_domain else ""}
{"🔴 ThreatFox" if threatfox_domain else ""}
{"🔴 VirusTotal (IP)" if ip_malicious else ""}
"""
                    alert_telegram(message.strip())
                else:
                    print("[✓] Correo legítimo")

            mail.logout()

        except Exception as e:
            print(f"[!] Error general: {e}")

        print("[*] Esperando 5 minutos para la próxima revisión...")
        time.sleep(300)

if __name__ == "__main__":
    main()

