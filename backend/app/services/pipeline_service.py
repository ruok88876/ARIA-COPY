"""Service layer coordinating repositories and the Attack Analysis Pipeline."""
from typing import Optional
from database.connection import get_database
from database.repositories.session_repo import SessionRepository
from database.repositories.log_repo import LogRepository
from database.repositories.ioc_repo import IOCRepository
from database.repositories.intent_repo import IntentRepository
from database.repositories.sdn_repo import SDNRepository
from honeypot.pipeline import AttackAnalysisPipeline
from backend.app.core.logging import get_logger

logger = get_logger("backend.services.pipeline_service")

# Global singleton repository instances
_session_repo: Optional[SessionRepository] = None
_log_repo: Optional[LogRepository] = None
_ioc_repo: Optional[IOCRepository] = None
_intent_repo: Optional[IntentRepository] = None
_sdn_repo: Optional[SDNRepository] = None
_pipeline: Optional[AttackAnalysisPipeline] = None


async def get_session_repository() -> SessionRepository:
    """Get or create singleton SessionRepository."""
    global _session_repo
    if _session_repo is None:
        db = await get_database()
        _session_repo = SessionRepository(db)
    return _session_repo


async def get_log_repository() -> LogRepository:
    """Get or create singleton LogRepository."""
    global _log_repo
    if _log_repo is None:
        db = await get_database()
        _log_repo = LogRepository(db)
    return _log_repo


async def get_ioc_repository() -> IOCRepository:
    """Get or create singleton IOCRepository."""
    global _ioc_repo
    if _ioc_repo is None:
        db = await get_database()
        _ioc_repo = IOCRepository(db)
    return _ioc_repo


async def get_intent_repository() -> IntentRepository:
    """Get or create singleton IntentRepository."""
    global _intent_repo
    if _intent_repo is None:
        db = await get_database()
        _intent_repo = IntentRepository(db)
    return _intent_repo


async def get_sdn_repository() -> SDNRepository:
    """Get or create singleton SDNRepository."""
    global _sdn_repo
    if _sdn_repo is None:
        db = await get_database()
        _sdn_repo = SDNRepository(db)
    return _sdn_repo


async def get_pipeline() -> AttackAnalysisPipeline:
    """Get or create singleton AttackAnalysisPipeline."""
    global _pipeline
    if _pipeline is None:
        s_repo = await get_session_repository()
        l_repo = await get_log_repository()
        i_repo = await get_ioc_repository()
        t_repo = await get_intent_repository()
        _pipeline = AttackAnalysisPipeline(
            session_repo=s_repo,
            log_repo=l_repo,
            ioc_repo=i_repo,
            intent_repo=t_repo,
        )
    return _pipeline
