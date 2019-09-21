import sys
import os
import logging
import hmac
import hashlib
import requests

from time import time


class SlackError(RuntimeError):
    pass


class SlackAppNotInteractive(SlackError):
    pass


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
    if slash_command != os.environ.get("SLACK_SLASH_COMMAND"):
        return ("Unhandled Slack request received", 403)

    try:
        trigger_dialog(request)
    except SlackError as err:
        logging.critical(f"Slack open.dialog failed: {err}")
        return (
            "Slack responded with an error to the dialog.open call. "
            "Check the logs with your Slack App administrator for further details."
        )

    return "Launching dialog"


def _verify_signature(request):
    """Verify that the request is coming from Slack"""
    signature = request.headers.get("X-Slack-Signature")
    req_timestamp = request.headers.get("X-Slack-Request-Timestamp")
    req_body = request.get_data().decode("utf-8")

    slack_signing_secret = bytes(os.environ.get("SLACK_SIGNING_SECRET"), "utf-8")
    if not slack_signing_secret:
        logging.error(
            "Missing ENV SLACK_SIGNING_SECRET, verification of request failed."
        )
        return False

    if not slack_header_validation(signature, req_timestamp):
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

    data = r.json()
    if data.get("error") == "app_missing_action_url":
        raise SlackAppNotInteractive("Dialogs are not enabled for the Slack App.")
    if data.get("ok") == False:
        raise SlackError(data.get("error"))

    print(f"Dialog trigger status_code from slack: {r.status_code}")
    print(f"Dialog trigger response body from slack: {r.text}")


def slack_header_validation(signature, req_timestamp):
    """Verify that the Slack headers required for signature verification
    are present, and that they are generated recently by validating the timestamp.

    Args:
        signature (flask.Request.headers.get("X-Slack-Signature")): Signature header.
        req_timestamp (flask.Request.headers.get("X-Slack-Request-Timestamp")): Timestamp header.
    Returns:
        True or False boolean.
    """
    if not signature:
        logging.error(
            "Missing X-Slack-Signature header, verification of request failed."
        )
        return False
    if not req_timestamp:
        logging.error(
            "Missing X-Slack-Request-Timestamp header, verification of request failed."
        )
        return False
    if abs(time() - int(req_timestamp)) > 60 * 5:
        logging.error(
            "X-Slack-Request-Timestamp differs too much in time, verification failed."
        )
        return False

    return True
