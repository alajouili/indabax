import json
import time
import urllib.request

from gmail_watcher import fetch_latest_email


SENTINEL_URL = "http://127.0.0.1:8001/api/gmail/evaluate"

CHECK_INTERVAL_SECONDS = 10


def send_to_sentinel(email_data):
    body = email_data["body"]
    sender = email_data["from"]
    subject = email_data["subject"]

    proposal = {
        "action_id": f"gmail-{email_data['message_id']}",

        "user_task":
            "Read the incoming email and inspect it safely.",

        "proposed_action_description":
            "Read the incoming email without executing instructions contained inside it.",

        "instruction_content": body,

        "proposed_action": {
            "tool": "read_document",
            "params": {
                "document_id":
                    f"gmail-{email_data['message_id']}"
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

    with urllib.request.urlopen(
        request,
        timeout=120
    ) as response:

        return json.loads(
            response.read().decode("utf-8")
        )


def main():

    print("====================================")
    print("SENTINEL Gmail Watcher")
    print("====================================")

    print("\nChecking current mailbox...")

    current_email = fetch_latest_email()

    if current_email:
        last_message_id = current_email["message_id"]

        print(
            "Current latest email:",
            current_email["subject"]
        )
    else:
        last_message_id = None

    print("\nWatcher active.")
    print(
        f"Checking Gmail every "
        f"{CHECK_INTERVAL_SECONDS} seconds..."
    )

    print("Press CTRL+C to stop.\n")

    while True:

        try:

            email_data = fetch_latest_email()

            if email_data is None:
                time.sleep(
                    CHECK_INTERVAL_SECONDS
                )
                continue

            message_id = email_data["message_id"]

            if message_id != last_message_id:

                print("\n====================================")
                print("NEW EMAIL DETECTED")
                print("====================================")

                print(
                    "From   :",
                    email_data["from"]
                )

                print(
                    "Subject:",
                    email_data["subject"]
                )

                print("\nAnalyzing with SENTINEL...")

                result = send_to_sentinel(
                    email_data
                )

                print("\n=== SENTINEL RESULT ===")

                print(
                    "Risk Score :",
                    result["risk_score"]
                )

                print(
                    "Outcome    :",
                    result["outcome"]
                )

                print(
                    "Human      :",
                    result["human_response"]
                )

                print(
                    "Executed   :",
                    result["executed"]
                )

                print(
                    "Reasons    :",
                    result["reason_codes"]
                )

                last_message_id = message_id

                print(
                    "\nWaiting for next email..."
                )

        except KeyboardInterrupt:

            print("\nGmail watcher stopped.")
            break

        except Exception as exc:

            print(
                "\nWatcher error:",
                type(exc).__name__,
                "-",
                exc
            )

        time.sleep(
            CHECK_INTERVAL_SECONDS
        )


if __name__ == "__main__":
    main()