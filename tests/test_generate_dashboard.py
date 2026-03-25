import pytest
from generate_dashboard import to_json_encoded, slugify

def test_slugify():
    assert slugify("Hello World") == "hello-world"
    assert slugify("Image:v1.0") == "image-v1-0"
    assert slugify("  Extra  Spaces  ") == "extra-spaces"
    assert slugify("Special!@#$%^&*()Chars") == "special-chars"
    assert slugify(None) == ""

def test_to_json_encoded_basic():
    data = {"name": "test", "version": "1.0"}
    encoded = to_json_encoded(data)
    assert "%22name%22: %22test%22" in encoded
    assert "%22version%22: %221.0%22" in encoded

def test_to_json_encoded_xss_payload():
    # Test that potentially malicious characters are handled by json.dumps
    data = {"description": "<script>alert('xss')</script>"}
    encoded = to_json_encoded(data)
    # The output of to_json_encoded is meant to be used inside an HTML attribute
    # so we're primarily checking that it's a valid JSON-like string with encoded quotes
    assert "%22<script>alert(%27xss%27)</script>%22" in encoded

def test_to_json_encoded_quotes():
    data = {"msg": "It's a \"test\""}
    encoded = to_json_encoded(data)
    # The current implementation: json.dumps encodes " as \", then we replace " with %22 and ' with %27
    # So "msg" -> %22msg%22
    # "It's a \"test\" -> %22It%27s a \\%22test\\%22%22
    assert "%22msg%22" in encoded
    assert "It%27s a" in encoded
    assert "\\%22test\\%22" in encoded
