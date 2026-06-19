from pathlib import Path

from apimapper.probes.wordlist_probe import load_wordlist, DEFAULT_WORDLIST


def test_default_wordlist_exists():
    assert DEFAULT_WORDLIST.exists()


def test_default_wordlist_loads_nonempty():
    words = load_wordlist()
    assert len(words) > 10
    assert all(isinstance(w, str) and w for w in words)


def test_wordlist_strips_blank_lines_and_comments(tmp_path):
    p = tmp_path / "custom.txt"
    p.write_text("api/v1\n\n# a comment\napi/v2\n   \napi/v3\n")
    words = load_wordlist(p)
    assert words == ["api/v1", "api/v2", "api/v3"]


def test_missing_wordlist_raises():
    import pytest
    with pytest.raises(FileNotFoundError):
        load_wordlist("/nonexistent/path/wordlist.txt")
