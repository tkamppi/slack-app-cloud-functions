import sys
import os
import hmac
import hashlib
import json

from time import time
from google.cloud import pubsub_v1


def dialog_submission(request):
    """HTTP Cloud Function.
    Args:
        request (flask.Request): The request object.
        <http://flask.pocoo.org/docs/1.0/api/#flask.Request>
    Returns:
        The response text, or any set of values that can be turned into a
        Response object using `make_response`
        <http://flask.pocoo.org/docs/1.0/api/#flask.Flask.make_response>.
    """
    if not __verify_signature(request):
        return ("Request signature invalid.", 401)

    payload = request.form.get("payload")
    try:
        json_payload = json.loads(payload)
    except json.JSONDecodeError: 
        return ("Unable to deserialize JSON from Slack payload", 400)
    if json_payload.get("type") == "dialog_submission":
        pubsub_push(json_payload)
        return ""

    return "Unhandled Slack request received", 403


def __verify_signature(request):
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


def pubsub_push(data):
    """
    Takes the data sent in, and pushes it into a Pub/Sub topic.
    :param data: object serializable to JSON using json.dumps(data).
    """
    topic_name = os.environ.get("PUBSUB_TOPIC_NAME")
    json_str = json.dumps(data)
    pubsub_bytestring = str(json_str).encode("utf-8")  # Pub/Sub requires bytestring

    publisher = pubsub_v1.PublisherClient()
    publisher.publish(topic_name, pubsub_bytestring, caller="Slack")
