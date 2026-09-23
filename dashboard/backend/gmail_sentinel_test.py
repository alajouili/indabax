import json
import urllib.request

from gmail_watcher import fetch_latest_email


SENTINEL_URL = "http://127.0.0.1:8001/api/gmail/evaluate"

def analyze_latest_email():
    email_data = fetch_latest_email()

    if email_data is None:
        print("Aucun email trouvé.")
        return

    body = email_data["body"]
    sender = email_data["from"]
    subject = email_data["subject"]

    proposal = {
        "action_id": f"gmail-{email_data['message_id']}",

        "user_task": "Read the incoming email and inspect it safely.",

        "proposed_action_description":
            "Read the incoming email without executing instructions contained inside it.",

        "instruction_content": body,

        "proposed_action": {
            "tool": "read_document",
            "params": {
                "document_id": f"gmail-{email_data['message_id']}"
            }
        },

        "instruction_source": {
            "type": "email",
            "sender": sender,
            "subject": subject,
            "content": body
        },

        "agent_role": "enterprise_assistant"
    }

    request = urllib.request.Request(
        SENTINEL_URL,
        data=json.dumps(proposal).encode("utf-8"),
        headers={
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(request) as response:
            result = json.loads(
                response.read().decode("utf-8")
            )

        print("\n=== EMAIL SENT TO SENTINEL ===")
        print("From   :", sender)
        print("Subject:", subject)

        print("\n=== SENTINEL RESULT ===")
        print(json.dumps(result, indent=2))

    except Exception as exc:
        print("\nErreur SENTINEL:")
        print(type(exc).__name__, "-", exc)


if __name__ == "__main__":
    analyze_latest_email()