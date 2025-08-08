# 🛡️ PhishingChecker – Email Phishing Detection Bot

**PhishingChecker** es una herramienta de **ciberseguridad defensiva** que detecta automáticamente intentos de **phishing** en correos electrónicos, integrando análisis en múltiples fuentes y enviando alertas en tiempo real vía **Telegram**.

---

## 🚀 Características
- 📥 **Conexión IMAP** a Gmail para la lectura automática de correos.
- 🧠 **Análisis asistido por IA** para identificar correos sospechosos.
- 🔍 **Verificación de reputación**:
  - IP del remitente → **VirusTotal**
  - Dominio del remitente → **VirusTotal** + **ThreatFox**
- ⚡ **Notificaciones instantáneas** en Telegram.
- 🐳 **Ejecución en Docker** para máxima portabilidad.

---

## 📦 Tecnologías
- Python 3.11
- Docker & Docker Compose
- IMAPClient
- Requests
- VirusTotal API
- ThreatFox API
- Telegram Bot API

---

## 📋 Requisitos previos
1. Tener instalado:
   - [Docker](https://docs.docker.com/get-docker/)
   - [Docker Compose](https://docs.docker.com/compose/install/)
2. Una cuenta de **Gmail** con [IMAP activado](https://support.google.com/mail/answer/7126229?hl=es) y [contraseña de aplicación](https://support.google.com/accounts/answer/185833?hl=es).
3. Clave de API de:
   - [VirusTotal](https://www.virustotal.com/gui/join-us)
   - [ThreatFox](https://threatfox.abuse.ch/)
4. Bot de Telegram y tu **CHAT_ID**.  
   - Crear bot: [BotFather](https://core.telegram.org/bots#6-botfather)
   - Obtener CHAT_ID: iniciar chat con [@userinfobot](https://t.me/userinfobot)

---

## ⚙️ Configuración
Edita el archivo `config.py` con tus credenciales:

```python
IMAP_SERVER = "imap.gmail.com"
EMAIL_ACCOUNT = "tuemail@gmail.com"
EMAIL_PASSWORD = "tu_contraseña_de_aplicacion"

VT_API_KEY = "tu_api_key_de_virustotal"
THREATFOX_API_KEY = "tu_api_key_de_threatfox"

TELEGRAM_BOT_TOKEN = "tu_token_de_telegram"
TELEGRAM_CHAT_ID = "tu_chat_id"
```

Edita el archivo `phishing_checker.py` con tu token de telegram en la línea 58:

```python
def alert_telegram(message):
    url = f"https://api.telegram.org/tu_token_de_telegram/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
```

---

▶️ Instalación y ejecución

# 1. Clonar repositorio
git clone https://github.com/TostaRicass/phishingchecker.git
cd phishingchecker

# 2. Levantar el contenedor
docker compose up -d --build

---

📜 Ejemplo de alerta en Telegram

🚨 Phishing detectado:
👤 Remitente: phishing@malicioso.com
🌐 Dominio: malicioso.com

Detalles:
🔴 VirusTotal (dominio)
🔴 ThreatFox
