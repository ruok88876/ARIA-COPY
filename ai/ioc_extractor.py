"""Deterministic Indicator of Compromise (IOC) extractor."""
import ipaddress
import re
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

from backend.app.schemas.ioc import IOC, IOCType
from backend.app.schemas.session import Command
from backend.app.core.logging import get_logger

logger = get_logger("ai.ioc_extractor")

# Strict regex patterns for IOC extraction
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
URL_REGEX = re.compile(r"https?://[^\s\'\"<>\[\]\(\)]+", re.IGNORECASE)
DOMAIN_REGEX = re.compile(
    r"(?<![/a-zA-Z0-9_\-\.])(?!(?:https?://))[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.(?:com|org|net|io|ru|cn|cc|xyz|info|biz|top|pw|me|online|site|tech|vip)\b",
    re.IGNORECASE,
)
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
FILE_PATH_REGEX = re.compile(
    r"(?:/[a-zA-Z0-9_\-\.]+){2,}|(?:/tmp/[a-zA-Z0-9_\-\.]+)|(?:/etc/[a-zA-Z0-9_\-\./]+)|(?:/var/[a-zA-Z0-9_\-\./]+)"
)

# Ignored false positive values
IGNORED_DOMAINS = {
    "localhost",
    "localdomain",
    "github.com",
    "pypi.org",
    "python.org",
}
IGNORED_PATHS = {
    "/dev/null",
    "/bin/sh",
    "/bin/bash",
    "/dev/tcp",
    "/dev/udp",
}

# Explicit internal networks (RFC 1918, loopback, link-local)
INTERNAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
)


def is_private_ip(ip_str: str) -> bool:
    """Check if IPv4 address is RFC 1918 private, loopback, or link-local."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in INTERNAL_NETWORKS)
    except ValueError:
        return False


MARKDOWN_LINK_REGEX = re.compile(r"^\[.*?\]\((https?://[^\s\)]+)\)$", re.IGNORECASE)


def clean_url(raw_url: str) -> str:
    """Trim trailing punctuation, markdown brackets/syntax, and shell artifacts from URL string."""
    cleaned = raw_url.strip()
    md_match = MARKDOWN_LINK_REGEX.match(cleaned)
    if md_match:
        cleaned = md_match.group(1).strip()
    return cleaned.rstrip(").,;:'\"<>\\[]").lstrip("[<(\"'")


class IOCExtractor:
    """Extracts observable indicators (IPv4, domains, URLs, hashes, file paths) from telemetry."""

    def extract_from_text(
        self,
        text: str,
        session_id: str,
        timestamp: str,
        source: str = "command",
    ) -> List[IOC]:
        """Extract all observable IOCs from a raw text string (e.g. shell command)."""
        if not text:
            return []

        extracted: List[IOC] = []
        seen_keys: Set[Tuple[str, IOCType]] = set()

        def add_ioc(ioc_type: IOCType, val: str, is_int: bool = False, meta: Dict = None):
            cleaned = val.strip()
            if not cleaned:
                return
            key = (cleaned.lower(), ioc_type)
            if key not in seen_keys:
                seen_keys.add(key)
                extracted.append(
                    IOC(
                        type=ioc_type,
                        value=cleaned,
                        session_id=session_id,
                        source=source,
                        timestamp=timestamp,
                        is_internal=is_int,
                        metadata=meta or {},
                    )
                )

        # 1. URLs
        clean_text_for_paths = text
        for match in URL_REGEX.findall(text):
            url_str = clean_url(match)
            # Remove URL from text used for standalone file paths and domains to avoid false fragment matches
            clean_text_for_paths = clean_text_for_paths.replace(match, " ")
            try:
                parsed = urlparse(url_str)
                hostname = parsed.hostname
                add_ioc(IOCType.URL, url_str, is_int=False, meta={"scheme": parsed.scheme})

                if hostname:
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
                        is_priv = is_private_ip(hostname)
                        add_ioc(IOCType.IPV4, hostname, is_int=is_priv, meta={"source_context": "url_host"})
                    elif hostname.lower() not in IGNORED_DOMAINS and "." in hostname:
                        add_ioc(IOCType.DOMAIN, hostname.lower(), is_int=False, meta={"source_context": "url_domain"})
            except Exception:
                pass

        # 2. Standalone IPv4 addresses
        for ip in IPV4_REGEX.findall(text):
            parts = [int(p) for p in ip.split(".")]
            if all(0 <= p <= 255 for p in parts):
                is_priv = is_private_ip(ip)
                if ip not in {"0.0.0.0", "255.255.255.255"}:
                    add_ioc(IOCType.IPV4, ip, is_int=is_priv)

        # 3. Standalone Domains (scan outside URLs)
        for domain in DOMAIN_REGEX.findall(clean_text_for_paths):
            dom_lower = domain.lower()
            if dom_lower not in IGNORED_DOMAINS and not re.match(r"^\d+\.\d+\.\d+\.\d+$", dom_lower):
                add_ioc(IOCType.DOMAIN, dom_lower)

        # 4. SHA-256 Hashes
        for sha256_match in SHA256_REGEX.findall(text):
            add_ioc(IOCType.SHA256, sha256_match.lower())

        # 5. SHA-1 Hashes (exclude if matched as substring of SHA-256)
        for sha1_match in SHA1_REGEX.findall(text):
            if not any(sha1_match.lower() in i.value.lower() for i in extracted if i.type == IOCType.SHA256):
                add_ioc(IOCType.SHA1, sha1_match.lower())

        # 6. MD5 Hashes (exclude if substring of SHA-256 or SHA-1)
        for md5_match in MD5_REGEX.findall(text):
            if not any(
                md5_match.lower() in i.value.lower()
                for i in extracted
                if i.type in (IOCType.SHA256, IOCType.SHA1)
            ):
                add_ioc(IOCType.MD5, md5_match.lower())

        # 7. File Paths (scan outside URLs)
        for path_match in FILE_PATH_REGEX.findall(clean_text_for_paths):
            clean_path = path_match.strip(";,\"'")
            if clean_path not in IGNORED_PATHS and len(clean_path) > 3:
                add_ioc(IOCType.FILE_PATH, clean_path)

        return extracted

    def extract_from_commands(self, commands: List[Command]) -> List[IOC]:
        """Extract IOCs from a list of session Command objects."""
        all_iocs: List[IOC] = []
        seen: Set[Tuple[str, IOCType]] = set()

        for cmd in commands:
            cmd_iocs = self.extract_from_text(
                text=cmd.command,
                session_id=cmd.session_id,
                timestamp=cmd.timestamp,
                source="command",
            )
            for ioc in cmd_iocs:
                key = (ioc.value.lower(), ioc.type)
                if key not in seen:
                    seen.add(key)
                    all_iocs.append(ioc)
        return all_iocs

    def extract_from_downloads(
        self,
        downloads: List[Dict],
        session_id: str,
    ) -> List[IOC]:
        """Extract IOCs from Cowrie file download events (URLs, hashes, destination files)."""
        download_iocs: List[IOC] = []

        for dl in downloads:
            ts = dl.get("timestamp", "")
            # URL
            url = dl.get("url")
            if url:
                download_iocs.extend(
                    self.extract_from_text(url, session_id=session_id, timestamp=ts, source="file_download")
                )
            # Hash (typically SHA-256 in Cowrie)
            shasum = dl.get("shasum")
            if shasum:
                sha_len = len(shasum.strip())
                if sha_len == 64:
                    download_iocs.append(
                        IOC(
                            type=IOCType.SHA256,
                            value=shasum.strip().lower(),
                            session_id=session_id,
                            source="file_download",
                            timestamp=ts,
                        )
                    )
                elif sha_len == 40:
                    download_iocs.append(
                        IOC(
                            type=IOCType.SHA1,
                            value=shasum.strip().lower(),
                            session_id=session_id,
                            source="file_download",
                            timestamp=ts,
                        )
                    )
                elif sha_len == 32:
                    download_iocs.append(
                        IOC(
                            type=IOCType.MD5,
                            value=shasum.strip().lower(),
                            session_id=session_id,
                            source="file_download",
                            timestamp=ts,
                        )
                    )
            # Destination path
            destfile = dl.get("destfile")
            if destfile and destfile.startswith("/"):
                download_iocs.append(
                    IOC(
                        type=IOCType.FILE_PATH,
                        value=destfile.strip(),
                        session_id=session_id,
                        source="file_download",
                        timestamp=ts,
                    )
                )

        return download_iocs
