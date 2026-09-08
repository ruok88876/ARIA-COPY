"""Tests for database repositories in standalone/in-memory mode."""
import pytest
from database.repositories import (
    SessionRepository,
    LogRepository,
    IOCRepository,
    IntentRepository,
    SDNRepository,
)
from backend.app.schemas import (
    Session,
    CowrieEvent,
    IOC,
    IOCType,
    Intent,
    IntentTactic,
    SDNEvent,
)


@pytest.mark.asyncio
async def test_session_repository_crud():
    repo = SessionRepository()
    session = Session(
        session_id="test_repo_s1",
        attacker_ip="192.0.2.1",
        start_time="2026-09-06T00:00:00Z",
    )
    await repo.upsert(session)

    fetched = await repo.get_by_id("test_repo_s1")
    assert fetched is not None
    assert fetched.session_id == "test_repo_s1"
    assert fetched.attacker_ip == "192.0.2.1"

    listed = await repo.list_sessions(attacker_ip="192.0.2.1")
    assert len(listed) == 1

    count = await repo.count()
    assert count == 1

    deleted = await repo.delete("test_repo_s1")
    assert deleted is True
    assert await repo.get_by_id("test_repo_s1") is None


@pytest.mark.asyncio
async def test_ioc_repository():
    repo = IOCRepository()
    ioc = IOC(
        type=IOCType.IPV4,
        value="198.51.100.99",
        session_id="s1",
        timestamp="2026-09-06T00:00:00Z",
    )
    await repo.upsert(ioc)

    found = await repo.get_by_value("198.51.100.99")
    assert found is not None
    assert found.value == "198.51.100.99"

    # Upsert again with new session ID
    ioc2 = IOC(
        type=IOCType.IPV4,
        value="198.51.100.99",
        session_id="s2",
        timestamp="2026-09-06T00:01:00Z",
    )
    await repo.upsert(ioc2)
    assert await repo.count() == 1
    updated = await repo.get_by_value("198.51.100.99")
    assert "s2" in updated.metadata.get("sessions", [])


@pytest.mark.asyncio
async def test_ioc_mongodb_upsert_no_path_conflict():
    from unittest.mock import AsyncMock, MagicMock

    mock_db = MagicMock()
    mock_collection = MagicMock()
    mock_collection.update_one = AsyncMock()
    mock_db.iocs = mock_collection

    repo = IOCRepository(db=mock_db)
    ioc = IOC(
        type=IOCType.IPV4,
        value="198.51.100.55",
        session_id="s_aria_001",
        source="command",
        timestamp="2026-09-06T00:10:28Z",
        is_internal=False,
        metadata={"source_context": "url_host"},
    )

    result = await repo.upsert(ioc)
    assert mock_collection.update_one.called
    filter_arg, update_arg = mock_collection.update_one.call_args[0][:2]

    # Verify unique identity filter
    assert filter_arg == {"value": "198.51.100.55", "type": "ipv4"}

    # Verify $set does NOT set the entire 'metadata' dictionary
    assert "$set" in update_arg
    assert "metadata" not in update_arg["$set"], "Path conflict: 'metadata' cannot be in $set"
    assert update_arg["$set"]["metadata.source_context"] == "url_host"
    assert update_arg["$set"]["value"] == "198.51.100.55"
    assert update_arg["$set"]["type"] == "ipv4"

    # Verify $addToSet updates 'metadata.sessions'
    assert "$addToSet" in update_arg
    assert "metadata.sessions" in update_arg["$addToSet"]

    # Verify sessions tracking in returned IOC
    assert "s_aria_001" in result.metadata.get("sessions", [])


@pytest.mark.asyncio
async def test_sdn_repository():
    repo = SDNRepository()
    event = SDNEvent(
        attacker_ip="10.0.0.1",
        destination_ip="10.0.0.10",
        source_port=55555,
        destination_port=22,
        protocol="TCP",
        timestamp="2026-09-06T00:00:00Z",
        ssh_detected=True,
        redirected=True,
    )
    await repo.insert(event)

    events = await repo.list_events(attacker_ip="10.0.0.1")
    assert len(events) == 1
    assert events[0].redirected is True

    summary = await repo.get_status_summary()
    assert summary["redirected_count"] == 1
    assert summary["ssh_detected_count"] == 1
    assert summary["unique_attackers"] == 1


@pytest.mark.asyncio
async def test_log_repository():
    repo = LogRepository()
    event = CowrieEvent(
        eventid="cowrie.command.input",
        timestamp="2026-09-06T00:00:00Z",
        session="s_log_test",
        input="id",
    )
    await repo.insert(event)
    assert await repo.count() == 1

    logs = await repo.list_logs(session_id="s_log_test")
    assert len(logs) == 1
    assert logs[0].input == "id"


@pytest.mark.asyncio
async def test_intent_repository():
    repo = IntentRepository()
    intent = Intent(
        intent=IntentTactic.RECONNAISSANCE,
        confidence=0.9,
        matched_command="whoami",
        rule="recon_user_discovery",
        session_id="s_intent_test",
    )
    await repo.insert(intent)
    assert await repo.count() == 1

    intents = await repo.list_by_session("s_intent_test")
    assert len(intents) == 1
    assert intents[0].rule == "recon_user_discovery"
