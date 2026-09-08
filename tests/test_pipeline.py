"""Tests for end-to-end AttackAnalysisPipeline."""
import pytest
from honeypot.pipeline import AttackAnalysisPipeline


@pytest.mark.asyncio
async def test_attack_analysis_pipeline_batch():
    pipeline = AttackAnalysisPipeline()
    result = await pipeline.process_file("tests/fixtures/sample_cowrie.json")

    assert result.events_processed >= 14
    assert result.malformed_lines >= 1
    assert result.sessions_updated == 2
    assert result.iocs_extracted > 0
    assert result.intents_classified > 0

    # Validate repositories contain persisted documents
    assert await pipeline.session_repo.count() == 2
    assert await pipeline.log_repo.count() == result.events_processed
    assert await pipeline.ioc_repo.count() > 0
    assert await pipeline.intent_repo.count() > 0

    # Validate session data
    s1 = await pipeline.session_repo.get_by_id("s_aria_001")
    assert s1 is not None
    assert s1.attacker_ip == "203.0.113.15"
    assert s1.is_closed is True
    assert len(s1.commands) == 7
    assert len(s1.iocs) > 0
    assert len(s1.intents) > 0


@pytest.mark.asyncio
async def test_attack_analysis_pipeline_missing_file():
    pipeline = AttackAnalysisPipeline()
    result = await pipeline.process_file("tests/fixtures/non_existent.json")
    assert result.events_processed == 0
    assert result.sessions_updated == 0
