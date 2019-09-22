import flask
import pytest
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
