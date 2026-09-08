"""Deterministic rule-based Intent Classifier aligned with MITRE ATT&CK."""
import re
from typing import List, NamedTuple, Optional
from backend.app.schemas.intent import Intent, IntentTactic
from backend.app.schemas.session import Command
from backend.app.core.logging import get_logger

logger = get_logger("ai.intent_classifier")


class IntentRule(NamedTuple):
    rule_id: str
    pattern: re.Pattern
    tactic: IntentTactic
    confidence: float
    mitre_id: str
    mitre_technique: str


# Deterministic rules mapped to MITRE ATT&CK Enterprise Matrix
RULES: List[IntentRule] = [
    # 1. Reconnaissance / Discovery
    IntentRule(
        rule_id="recon_sys_info_uname",
        pattern=re.compile(r"\buname(\s+-[a-zA-Z]+)?\b"),
        tactic=IntentTactic.RECONNAISSANCE,
        confidence=0.90,
        mitre_id="T1082",
        mitre_technique="System Information Discovery",
    ),
    IntentRule(
        rule_id="recon_user_discovery",
        pattern=re.compile(r"\b(whoami|id)\b"),
        tactic=IntentTactic.RECONNAISSANCE,
        confidence=0.90,
        mitre_id="T1033",
        mitre_technique="System Owner/User Discovery",
    ),
    IntentRule(
        rule_id="recon_host_info",
        pattern=re.compile(r"\b(hostname|uptime|lscpu|nproc)\b"),
        tactic=IntentTactic.RECONNAISSANCE,
        confidence=0.85,
        mitre_id="T1082",
        mitre_technique="System Information Discovery",
    ),
    IntentRule(
        rule_id="recon_os_release",
        pattern=re.compile(r"cat\s+/etc/(issue|os-release|redhat-release|debian_version)"),
        tactic=IntentTactic.RECONNAISSANCE,
        confidence=0.90,
        mitre_id="T1082",
        mitre_technique="System Information Discovery",
    ),
    IntentRule(
        rule_id="recon_net_config",
        pattern=re.compile(r"\b(ifconfig|ip\s+(addr|a|route|r)|route\s+-n)\b"),
        tactic=IntentTactic.RECONNAISSANCE,
        confidence=0.90,
        mitre_id="T1016",
        mitre_technique="System Network Configuration Discovery",
    ),
    IntentRule(
        rule_id="recon_net_connections",
        pattern=re.compile(r"\b(netstat|ss|lsof\s+-i|arp\s+-a)\b"),
        tactic=IntentTactic.RECONNAISSANCE,
        confidence=0.85,
        mitre_id="T1049",
        mitre_technique="System Network Connections Discovery",
    ),
    IntentRule(
        rule_id="recon_process_discovery",
        pattern=re.compile(r"\b(ps\s+(aux|-ef)|top\s+-b|pstree)\b"),
        tactic=IntentTactic.RECONNAISSANCE,
        confidence=0.85,
        mitre_id="T1057",
        mitre_technique="Process Discovery",
    ),

    # 2. Credential Access
    IntentRule(
        rule_id="cred_dump_shadow",
        pattern=re.compile(r"(cat|head|tail|more|less)\s+/etc/shadow"),
        tactic=IntentTactic.CREDENTIAL_ACCESS,
        confidence=0.95,
        mitre_id="T1003.008",
        mitre_technique="OS Credential Dumping: /etc/passwd and /etc/shadow",
    ),
    IntentRule(
        rule_id="cred_dump_passwd",
        pattern=re.compile(r"(cat|head|tail|more|less)\s+/etc/passwd"),
        tactic=IntentTactic.CREDENTIAL_ACCESS,
        confidence=0.85,
        mitre_id="T1087.001",
        mitre_technique="Account Discovery: Local Accounts",
    ),
    IntentRule(
        rule_id="cred_search_files",
        pattern=re.compile(r"grep\s+(-[a-zA-Z]+\s+)?[\"']?(password|passwd|secret)[\"']?"),
        tactic=IntentTactic.CREDENTIAL_ACCESS,
        confidence=0.80,
        mitre_id="T1552.001",
        mitre_technique="Credentials in Files",
    ),
    IntentRule(
        rule_id="cred_cracking_tools",
        pattern=re.compile(r"\b(unshadow|john|hashcat|hydra|medusa)\b"),
        tactic=IntentTactic.CREDENTIAL_ACCESS,
        confidence=0.90,
        mitre_id="T1110",
        mitre_technique="Brute Force",
    ),

    # 3. Privilege Escalation
    IntentRule(
        rule_id="priv_esc_sudo_su",
        pattern=re.compile(r"\b(sudo\s+|su\s+(-|\w+)|pkexec|doas)\b"),
        tactic=IntentTactic.PRIVILEGE_ESCALATION,
        confidence=0.90,
        mitre_id="T1548.003",
        mitre_technique="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    ),
    IntentRule(
        rule_id="priv_esc_setuid",
        pattern=re.compile(r"chmod\s+(\+[sS]|[0-7]?[42][0-7]{3})"),
        tactic=IntentTactic.PRIVILEGE_ESCALATION,
        confidence=0.90,
        mitre_id="T1548.001",
        mitre_technique="Abuse Elevation Control Mechanism: Setuid and Setgid",
    ),
    IntentRule(
        rule_id="priv_esc_useradd",
        pattern=re.compile(r"\b(useradd|usermod|groupadd)\b"),
        tactic=IntentTactic.PRIVILEGE_ESCALATION,
        confidence=0.85,
        mitre_id="T1136.001",
        mitre_technique="Create Account: Local Account",
    ),

    # 4. Persistence
    IntentRule(
        rule_id="persist_crontab",
        pattern=re.compile(r"(\bcrontab\b|/var/spool/cron|/etc/cron\.)"),
        tactic=IntentTactic.PERSISTENCE,
        confidence=0.95,
        mitre_id="T1053.003",
        mitre_technique="Scheduled Task/Job: Cron",
    ),
    IntentRule(
        rule_id="persist_systemd",
        pattern=re.compile(r"systemctl\s+(enable|start)\s+"),
        tactic=IntentTactic.PERSISTENCE,
        confidence=0.85,
        mitre_id="T1543.002",
        mitre_technique="Create or Modify System Process: Systemd Service",
    ),
    IntentRule(
        rule_id="persist_ssh_authorized_keys",
        pattern=re.compile(r"(\.ssh/authorized_keys|echo\s+.*>>\s+.*authorized_keys)"),
        tactic=IntentTactic.PERSISTENCE,
        confidence=0.95,
        mitre_id="T1098.004",
        mitre_technique="Account Manipulation: SSH Authorized Keys",
    ),

    # 5. Execution
    IntentRule(
        rule_id="exec_ingress_tool_transfer",
        pattern=re.compile(r"\b(wget|curl)\s+"),
        tactic=IntentTactic.EXECUTION,
        confidence=0.85,
        mitre_id="T1105",
        mitre_technique="Ingress Tool Transfer",
    ),
    IntentRule(
        rule_id="exec_pipe_to_shell",
        pattern=re.compile(r"(wget|curl)\s+.*(\||\&\&)\s*(sh|bash)"),
        tactic=IntentTactic.EXECUTION,
        confidence=0.95,
        mitre_id="T1059.004",
        mitre_technique="Command and Scripting Interpreter: Unix Shell",
    ),
    IntentRule(
        rule_id="exec_chmod_and_run",
        pattern=re.compile(r"chmod\s+\+x\s+.*(\&\&|;)\s*(\./|/tmp/)"),
        tactic=IntentTactic.EXECUTION,
        confidence=0.95,
        mitre_id="T1059.004",
        mitre_technique="Command and Scripting Interpreter: Unix Shell",
    ),
    IntentRule(
        rule_id="exec_chmod_permissions",
        pattern=re.compile(r"\bchmod\s+(\+x|[0-7]{3,4})\s+"),
        tactic=IntentTactic.DEFENSE_EVASION,
        confidence=0.85,
        mitre_id="T1222.002",
        mitre_technique="File and Directory Permissions Modification: Linux and Mac",
    ),
    IntentRule(
        rule_id="exec_shell_wrapper",
        pattern=re.compile(r"\b(bash|sh|zsh)\s+-c\b"),
        tactic=IntentTactic.EXECUTION,
        confidence=0.85,
        mitre_id="T1059.004",
        mitre_technique="Command and Scripting Interpreter: Unix Shell",
    ),
    IntentRule(
        rule_id="exec_script_interpreter",
        pattern=re.compile(r"\b(python[0-9]?|perl|php|ruby)\s+(-e|-c)\b"),
        tactic=IntentTactic.EXECUTION,
        confidence=0.90,
        mitre_id="T1059",
        mitre_technique="Command and Scripting Interpreter",
    ),

    # 6. Defense Evasion
    IntentRule(
        rule_id="evasion_clear_history",
        pattern=re.compile(r"(history\s+-c|rm\s+(-[rf]+\s+)?.*bash_history|unset\s+HISTFILE)"),
        tactic=IntentTactic.DEFENSE_EVASION,
        confidence=0.95,
        mitre_id="T1070.003",
        mitre_technique="Indicator Removal on Host: Clear Command History",
    ),
    IntentRule(
        rule_id="evasion_flush_firewall",
        pattern=re.compile(r"iptables\s+(-F|-X)"),
        tactic=IntentTactic.DEFENSE_EVASION,
        confidence=0.95,
        mitre_id="T1562.004",
        mitre_technique="Impair Defenses: Disable or Modify System Firewall",
    ),

    # 7. Lateral Movement
    IntentRule(
        rule_id="lateral_ssh",
        pattern=re.compile(r"\bssh\s+(-i\s+\S+\s+)?\S+@\S+"),
        tactic=IntentTactic.LATERAL_MOVEMENT,
        confidence=0.90,
        mitre_id="T1021.004",
        mitre_technique="Remote Services: SSH",
    ),
    IntentRule(
        rule_id="lateral_transfer",
        pattern=re.compile(r"\b(scp|rsync)\s+.*@"),
        tactic=IntentTactic.LATERAL_MOVEMENT,
        confidence=0.85,
        mitre_id="T1570",
        mitre_technique="Lateral Tool Transfer",
    ),

    # 8. Data Exfiltration
    IntentRule(
        rule_id="exfil_post_request",
        pattern=re.compile(r"curl\s+.*(-X\s*POST|-d|--data|-F)\s+"),
        tactic=IntentTactic.DATA_EXFILTRATION,
        confidence=0.85,
        mitre_id="T1048.003",
        mitre_technique="Exfiltration Over Alternative Protocol",
    ),
    IntentRule(
        rule_id="exfil_netcat_pipe",
        pattern=re.compile(r"nc\s+.*<\s+/"),
        tactic=IntentTactic.DATA_EXFILTRATION,
        confidence=0.85,
        mitre_id="T1048",
        mitre_technique="Exfiltration Over Alternative Protocol",
    ),

    # 9. Destruction / Tampering
    IntentRule(
        rule_id="destruct_root_deletion",
        pattern=re.compile(r"rm\s+(-[rf]+\s+)?(/|/\*|/bin|/sbin|/boot)"),
        tactic=IntentTactic.DESTRUCTION_TAMPERING,
        confidence=0.95,
        mitre_id="T1485",
        mitre_technique="Data Destruction",
    ),
    IntentRule(
        rule_id="destruct_reboot",
        pattern=re.compile(r"\b(shutdown|reboot|poweroff|init\s+0)\b"),
        tactic=IntentTactic.DESTRUCTION_TAMPERING,
        confidence=0.90,
        mitre_id="T1529",
        mitre_technique="System Shutdown/Reboot",
    ),
]


class IntentClassifier:
    """Classifies commands into attack intent tactics with MITRE ATT&CK technique IDs."""

    def classify_command(
        self,
        command: str,
        session_id: str,
        timestamp: Optional[str] = None,
    ) -> List[Intent]:
        """Classify a single command string against all deterministic rules."""
        if not command:
            return []

        intents: List[Intent] = []
        clean_cmd = command.strip()

        for rule in RULES:
            if rule.pattern.search(clean_cmd):
                intents.append(
                    Intent(
                        intent=rule.tactic,
                        confidence=rule.confidence,
                        matched_command=clean_cmd,
                        rule=rule.rule_id,
                        session_id=session_id,
                        mitre_technique=rule.mitre_technique,
                        mitre_id=rule.mitre_id,
                        timestamp=timestamp,
                    )
                )

        intents.sort(key=lambda x: x.confidence, reverse=True)
        return intents

    def classify_session_commands(self, commands: List[Command]) -> List[Intent]:
        """Classify all commands within a session, deduplicating matching rules per session."""
        session_intents: List[Intent] = []
        seen_rule_commands = set()

        for cmd in commands:
            matched = self.classify_command(
                command=cmd.command,
                session_id=cmd.session_id,
                timestamp=cmd.timestamp,
            )
            for intent in matched:
                key = (intent.rule, intent.matched_command)
                if key not in seen_rule_commands:
                    seen_rule_commands.add(key)
                    session_intents.append(intent)

        return session_intents
