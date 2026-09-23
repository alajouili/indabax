import os
import re
import imaplib
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.header import decode_header


ENV_FILE = Path(__file__).with_name(".env")


def load_env():
    """Charge dashboard/backend/.env sans dépendance externe."""
    if not ENV_FILE.exists():
        raise FileNotFoundError(
            f"Fichier .env introuvable : {ENV_FILE}"
        )

    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)

        os.environ.setdefault(
            key.strip(),
            value.strip().strip('"').strip("'")
        )


def decode_mime_header(value):
    if not value:
        return ""

    result = []

    for part, encoding in decode_header(value):
        if isinstance(part, bytes):
            result.append(
                part.decode(encoding or "utf-8", errors="replace")
            )
        else:
            result.append(part)

    return "".join(result)


def clean_html(html):
    """Nettoyage simple si le mail ne contient que du HTML."""
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_body(message):
    text_plain = []
    text_html = []

    if message.is_multipart():
        for part in message.walk():

            if part.get_content_disposition() == "attachment":
                continue

            content_type = part.get_content_type()

            if content_type not in ("text/plain", "text/html"):
                continue

            try:
                content = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True)

                if payload is None:
                    continue

                charset = part.get_content_charset() or "utf-8"
                content = payload.decode(
                    charset,
                    errors="replace"
                )

            if content_type == "text/plain":
                text_plain.append(content)
            else:
                text_html.append(content)

    else:
        try:
            content = message.get_content()
        except Exception:
            payload = message.get_payload(decode=True)

            if payload is None:
                content = ""
            else:
                charset = message.get_content_charset() or "utf-8"
                content = payload.decode(
                    charset,
                    errors="replace"
                )

        if message.get_content_type() == "text/html":
            text_html.append(content)
        else:
            text_plain.append(content)

    if text_plain:
        return "\n".join(text_plain).strip()

    if text_html:
        return clean_html("\n".join(text_html))

    return ""


def fetch_latest_email():
    load_env()

    gmail_address = os.getenv("GMAIL_ADDRESS")
    app_password = os.getenv("GMAIL_APP_PASSWORD")
    host = os.getenv("GMAIL_IMAP_HOST", "imap.gmail.com")
    port = int(os.getenv("GMAIL_IMAP_PORT", "993"))

    if not gmail_address:
        raise ValueError("GMAIL_ADDRESS manque dans .env")

    if not app_password:
        raise ValueError("GMAIL_APP_PASSWORD manque dans .env")

    mail = imaplib.IMAP4_SSL(host, port)

    try:
        mail.login(gmail_address, app_password)

        status, _ = mail.select("INBOX", readonly=True)

        if status != "OK":
            raise RuntimeError("Impossible d'ouvrir INBOX")

        status, data = mail.search(None, "ALL")

        if status != "OK":
            raise RuntimeError("Impossible de rechercher les emails")

        email_ids = data[0].split()

        if not email_ids:
            return None

        latest_id = email_ids[-1]

        status, message_data = mail.fetch(
            latest_id,
            "(RFC822)"
        )

        if status != "OK":
            raise RuntimeError("Impossible de récupérer le dernier email")

        raw_email = message_data[0][1]

        message = BytesParser(
            policy=policy.default
        ).parsebytes(raw_email)

        return {
            "message_id": str(latest_id.decode()),
            "from": decode_mime_header(message.get("From")),
            "to": decode_mime_header(message.get("To")),
            "subject": decode_mime_header(message.get("Subject")),
            "date": str(message.get("Date", "")),
            "body": extract_body(message),
        }

    finally:
        try:
            mail.logout()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        email_data = fetch_latest_email()

        if email_data is None:
            print("Aucun email trouvé.")
        else:
            print("\n=== DERNIER EMAIL ===")
            print("From   :", email_data["from"])
            print("To     :", email_data["to"])
            print("Subject:", email_data["subject"])
            print("Date   :", email_data["date"])

            print("\n--- BODY ---")
            print(email_data["body"])

    except Exception as exc:
        print("\nERREUR Gmail:")
        print(type(exc).__name__, "-", exc)