import sys
import os
import hmac
import hashlib
import requests

from time import time


def slash_command(request):
    """HTTP Cloud Function.
    Args:
        request (flask.Request): The request object.
        <http://flask.pocoo.org/docs/1.0/api/#flask.Request>
    Returns:
        The response text, or any set of values that can be turned into a
        Response object using `make_response`
        <http://flask.pocoo.org/docs/1.0/api/#flask.Flask.make_response>.
    """
    if not _verify_signature(request):
        return ("Request signature invalid.", 401)

    slash_command = request.form.get("command")
    if slash_command == os.environ.get("SLACK_SLASH_COMMAND"):
        trigger_dialog(request)
        return "Launching dialog"

    return "Unhandled Slack request received", 403


def _verify_signature(request):
    """Verify that the request is coming from Slack"""
    signature = request.headers.get("X-Slack-Signature")
    req_timestamp = request.headers.get("X-Slack-Request-Timestamp")
    req_body = request.get_data().decode("utf-8")
    slack_signing_secret = bytes(os.environ.get("SLACK_SIGNING_SECRET"), "utf-8")

    if not slack_signing_secret:
        print("Missing ENV SLACK_SIGNING_SECRET, verification of request failed.")
        return False
    if not signature:
        print("Missing X-Slack-Signature header, verification of request failed.")
        return False
    if not req_timestamp:
        print(
            "Missing X-Slack-Request-Timestamp header, verification of request failed."
        )
        return False
    if abs(time() - int(req_timestamp)) > 60 * 5:
        print(
            "X-Slack-Request-Timestamp differs too much in time, verification failed."
        )
        return False

    req_string = f"v0:{req_timestamp}:{req_body}".encode("utf-8")
    request_hash = (
        "v0=" + hmac.new(slack_signing_secret, req_string, hashlib.sha256).hexdigest()
    )

    return hmac.compare_digest(request_hash, signature)


def trigger_dialog(request):
    response_url = "https://slack.com/api/dialog.open"
    trigger_id = request.form["trigger_id"]

    payload = {
        "trigger_id": trigger_id,
        "dialog": {
            "callback_id": "YOUR_POSSIBLE_CALLBACK",
            "title": "Example dialog",
            "submit_label": "Request",
            "notify_on_cancel": False,
            "state": "YOUR_POSSIBLE_STATE",
            "elements": [
                {
                    "type": "select",
                    "label": "My dropdown menu",
                    "name": "project_type",
                    "options": [
                        {"label": "Option1", "value": "Value1"},
                        {"label": "Option2", "value": "Value2"},
                    ],
                },
                {"type": "text", "label": "A text entry", "name": "my_text_entry_1"},
                {
                    "type": "text",
                    "label": "A second text entry",
                    "name": "whatever_you_want",
                },
            ],
        },
    }

    bearer_token = os.environ.get("SLACK_OAUTH_TOKEN")
    authorization_header_value = f"Bearer {bearer_token}"
    headers = {"Authorization": authorization_header_value}
    r = requests.post(response_url, json=payload, headers=headers)
    print(f"Dialog trigger status_code from slack: {r.status_code}")
    print(f"Dialog trigger response body from slack: {r.text}")
