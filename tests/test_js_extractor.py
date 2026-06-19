from apimapper.extractors.js_extractor import extract_endpoints_from_js, extract_secrets_from_js


SAMPLE_JS = '''
function fetchUsers() {
  return fetch("/api/v1/users/{id}/profile").then(r => r.json());
}
axios.get("/api/v2/admin/settings");
const config = {
  firebaseApiKey: "AIza00000000000000000000000000000000000",
  awsKey: "AKIAFFFFFFFFFFFFFFFF",
  apiKey: "sk_test_FAKEKEY1234567890abcdef",
  stripeLive: "sk_live_FAKEKEYabcdefghijklmnopqrst",
  jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummysignaturepart"
};
fetch("https://internal-api.example.com/debug/dump");
const logo = "/assets/logo.png";
'''


def test_extracts_relative_paths():
    endpoints = extract_endpoints_from_js(SAMPLE_JS, "test.js")
    paths = {e.path for e in endpoints}
    assert "/api/v1/users/{id}/profile" in paths
    assert "/api/v2/admin/settings" in paths


def test_extracts_full_url_and_splits_host():
    endpoints = extract_endpoints_from_js(SAMPLE_JS, "test.js")
    matches = [e for e in endpoints if e.base_host == "https://internal-api.example.com"]
    assert len(matches) == 1
    assert matches[0].path == "/debug/dump"
    assert matches[0].full_url == "https://internal-api.example.com/debug/dump"


def test_filters_static_assets():
    endpoints = extract_endpoints_from_js(SAMPLE_JS, "test.js")
    paths = {e.path for e in endpoints}
    assert not any(p.endswith(".png") for p in paths)


def test_detects_aws_key():
    secrets = extract_secrets_from_js(SAMPLE_JS, "test.js")
    types = {s.secret_type for s in secrets}
    assert "aws_access_key_id" in types


def test_detects_firebase_key():
    secrets = extract_secrets_from_js(SAMPLE_JS, "test.js")
    types = {s.secret_type for s in secrets}
    assert "firebase_api_key" in types


def test_detects_stripe_live_vs_test_severity():
    secrets = extract_secrets_from_js(SAMPLE_JS, "test.js")
    live = [s for s in secrets if s.secret_type == "stripe_live_key"]
    test = [s for s in secrets if s.secret_type == "stripe_test_key"]
    assert live and live[0].severity.value == "critical"
    assert test and test[0].severity.value == "low"


def test_detects_jwt():
    secrets = extract_secrets_from_js(SAMPLE_JS, "test.js")
    types = {s.secret_type for s in secrets}
    assert "generic_bearer_jwt" in types


def test_secret_values_are_redacted_not_raw():
    secrets = extract_secrets_from_js(SAMPLE_JS, "test.js")
    for s in secrets:
        assert "*" in s.value_redacted, f"{s.secret_type} value was not redacted"


def test_generic_pattern_captures_value_not_variable_name():
    secrets = extract_secrets_from_js(SAMPLE_JS, "test.js")
    generic = [s for s in secrets if s.secret_type == "generic_api_key_assignment"]
    assert generic
    for s in generic:
        # the redacted value should start with the secret's actual prefix
        # (AIza / sk_test_), never with the variable name like "apiKey"
        assert not s.value_redacted.lower().startswith("apik")
