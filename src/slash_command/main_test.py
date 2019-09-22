import json
import flask
import pytest
import responses
from unittest import mock

import main


@pytest.fixture(scope="module")
def app():
    return flask.Flask(__name__)


def get_example_headers(header):
    TIMESTAMP = "1531420618"
    SIGNATURE = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503"

    if header == "X-Slack-Signature":
        return SIGNATURE
    elif header == "X-Slack-Request-Timestamp":
        return TIMESTAMP


@pytest.mark.parametrize(
    "slack_signing_secret, timestamp, expected_outcome",
    [
        ("8f742231b10e8888abcd99yyyzzz85a5", 1531420618, True),
        ("WRONG_SECRET_THIS_SHOULD_FAIL", 1531420618, False),
        ("8f742231b10e8888abcd99yyyzzz85a5", 1531420000, False),
    ],
)
@mock.patch("flask.request")
@mock.patch("main.time")
def test__verify_signature(
    time_mock,
    request_mock,
    slack_signing_secret,
    timestamp,
    expected_outcome,
    app,
    monkeypatch,
):
    """This test is parametrized to run three tests.
    1. All input and validation should be correct.
    2. The Slack SIGNING_SECRET is set incorrect and verification should fail.
    3. The timestamp differs too much and the verification should fail. 

    We are using a Slack provided example hash to match their calculation against
    our function. Example hash and values are from:
    https://api.slack.com/docs/verifying-requests-from-slack
    The headers for timestamp and signature are in the function get_example_headers.
    """
    BODY = b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c"

    monkeypatch.setenv("SLACK_SIGNING_SECRET", slack_signing_secret)
    request_mock.headers.get.side_effect = get_example_headers
    request_mock.get_data.return_value = BODY
    time_mock.return_value = timestamp
    with app.test_request_context():
        res = main._verify_signature(flask.request)
    assert res == expected_outcome


def test_request_unauthenticated(app, monkeypatch):
    """Test that the Flask Response will be HTTP status 401,
    and that  the response indicates it was because the signature 
    could not be verified.
    """
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "secret")
    with app.test_request_context(method="POST"):
        res = main.slash_command(flask.request)
        response = flask.make_response(res)
    assert response.status_code == 401
    assert response.get_data(as_text=True) == "Request signature invalid."


@pytest.mark.parametrize(
    "slash_command, expected_status_code",
    [
        ("/wrong-slash-command", 403),
        ("/correct-slash-command", 200),
    ],
)
@mock.patch("main._verify_signature")
@mock.patch("main.trigger_dialog")
def test_request_with_slack_command(trigger_dialog_mock, 
verify_signature_mock, 
slash_command, 
expected_status_code, 
app, 
monkeypatch
):
    """Test that the slash command allowed is set by the env SLACK_SLASH_COMMAND,
    any other slash command should generate a HTTP 403 Forbidden response.
    We mock out any Slakc authentication validation and actual work performed by  
    functions verify_signature & trigger_dialog.
    """
    monkeypatch.setenv("SLACK_SLASH_COMMAND", "/correct-slash-command")
    verify_signature_mock.return_value = True
    trigger_dialog_mock.return_value = None
    with app.test_request_context(
        data=f"command={slash_command}", 
        content_type="application/x-www-form-urlencoded",
    ) as request:
        res = main.slash_command(request.request)
        response = flask.make_response(res)

    assert response.status_code == expected_status_code


@responses.activate
def test_dialog_trigger_request_towards_slack_dialog_api(app, monkeypatch):
    """Test that the dialog trigger sends a request to Slack containing:
    1. The oauth token from environment variable SLACK_OAUTH_TOKEN is used
    2. trigger_id from request object is in the json structure of the HTTP body
    3. Request is sent to Slack API endpoint https://slack.com/api/dialog.open
    4. Request is sent using content-type application/json.
    """
    OAUTH_TOKEN = "my_oauth_token"
    SLACK_DIALOG_API = "https://slack.com/api/dialog.open"
    TRIGGER_ID = "13345224609.738474920.8088930838d88f008e0"
    
    responses.add(responses.POST, SLACK_DIALOG_API, json={"ok": True}, status=200)

    monkeypatch.setenv("SLACK_OAUTH_TOKEN", OAUTH_TOKEN)
    with app.test_request_context(
        method="POST",
        data=f"token=gIkuvaNzQIHg97ATvDxqgjtO&trigger_id={TRIGGER_ID}",
        content_type="application/x-www-form-urlencoded",
    ) as request:
        main.trigger_dialog(request.request)

    assert responses.calls[0].request.headers["Authorization"] == f"Bearer {OAUTH_TOKEN}"
    assert json.loads(responses.calls[0].request.body)["trigger_id"] == TRIGGER_ID
    assert responses.calls[0].request.url == SLACK_DIALOG_API
    assert responses.calls[0].request.headers["Content-Type"] == "application/json"
