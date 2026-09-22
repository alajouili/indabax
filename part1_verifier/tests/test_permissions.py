from sentinel_verifier.config import load_rules
from sentinel_verifier.permissions import check_permissions


def test_disallowed_tool():
    r = check_permissions("security_assistant", {"tool":"delete_file"}, {}, None, load_rules().permissions)
    assert r.permission_ok is False
    assert "TOOL_NOT_ALLOWED" in r.flags


def test_missing_prerequisite():
    r = check_permissions("enterprise_assistant", {"tool":"upload_file"}, {}, None, load_rules().permissions)
    assert r.permission_ok is False
    assert "MISSING_PREREQUISITE" in r.flags


def test_unknown_role_is_unknown():
    r = check_permissions("unknown", {"tool":"read_document"}, {}, None, load_rules().permissions)
    assert r.permission_ok is None
