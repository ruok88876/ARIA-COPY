"""End-to-End Cowrie Ingestion, Analysis, and Intelligence Pipeline."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.schemas.log import CowrieEvent
from backend.app.schemas.session import Session
from backend.app.schemas.ioc import IOC
from backend.app.schemas.intent import Intent
from honeypot.parser import CowrieParser
from honeypot.session_builder import SessionBuilder
from ai.ioc_extractor import IOCExtractor
from ai.intent_classifier import IntentClassifier
from database.repositories.session_repo import SessionRepository
from database.repositories.log_repo import LogRepository
from database.repositories.ioc_repo import IOCRepository
from database.repositories.intent_repo import IntentRepository
from backend.app.core.logging import get_logger

logger = get_logger("honeypot.pipeline")


class PipelineResult(BaseModel):
    """Execution summary of the intelligence pipeline processing run."""

    events_processed: int = 0
    sessions_updated: int = 0
    iocs_extracted: int = 0
    intents_classified: int = 0
    malformed_lines: int = 0
    sessions: List[Session] = Field(default_factory=list)
    new_iocs: List[IOC] = Field(default_factory=list)
    new_intents: List[Intent] = Field(default_factory=list)


class AttackAnalysisPipeline:
    """Orchestrates Cowrie Log -> Parser -> Session -> Commands -> IOC -> Intent -> DB."""

    def __init__(
        self,
        session_repo: Optional[SessionRepository] = None,
        log_repo: Optional[LogRepository] = None,
        ioc_repo: Optional[IOCRepository] = None,
        intent_repo: Optional[IntentRepository] = None,
    ):
        self.parser = CowrieParser()
        self.session_builder = SessionBuilder()
        self.ioc_extractor = IOCExtractor()
        self.intent_classifier = IntentClassifier()

        self.session_repo = session_repo or SessionRepository()
        self.log_repo = log_repo or LogRepository()
        self.ioc_repo = ioc_repo or IOCRepository()
        self.intent_repo = intent_repo or IntentRepository()

    async def process_event(self, event: CowrieEvent) -> PipelineResult:
        """Process a single incoming Cowrie event and update its session, IOCs, and intents."""
        result = PipelineResult(events_processed=1)

        # 1. Persist raw event
        await self.log_repo.insert(event)

        # 2. Update session state
        session = self.session_builder.process_event(event)

        # 3. If event is a command or file download, run IOC and Intent extraction
        new_iocs: List[IOC] = []
        new_intents: List[Intent] = []

        if event.eventid == "cowrie.command.input" and event.input:
            cmd_iocs = self.ioc_extractor.extract_from_text(
                text=event.input,
                session_id=session.session_id,
                timestamp=event.timestamp,
                source="command",
            )
            new_iocs.extend(cmd_iocs)

            cmd_intents = self.intent_classifier.classify_command(
                command=event.input,
                session_id=session.session_id,
                timestamp=event.timestamp,
            )
            new_intents.extend(cmd_intents)

        elif event.eventid == "cowrie.session.file_download":
            dl_iocs = self.ioc_extractor.extract_from_downloads(
                session.downloaded_files,
                session_id=session.session_id,
            )
            new_iocs.extend(dl_iocs)

        # 4. Attach extracted IOCs and intents to Session
        if new_iocs:
            session.iocs.extend(new_iocs)
            await self.ioc_repo.upsert_many(new_iocs)
            result.iocs_extracted = len(new_iocs)
            result.new_iocs = new_iocs

        if new_intents:
            session.intents.extend(new_intents)
            await self.intent_repo.insert_many(new_intents)
            result.intents_classified = len(new_intents)
            result.new_intents = new_intents

        # 5. Persist updated Session
        await self.session_repo.upsert(session)
        result.sessions_updated = 1
        result.sessions = [session]

        return result

    async def process_file(self, file_path: str) -> PipelineResult:
        """Execute end-to-end batch processing of a Cowrie log file."""
        events = self.parser.parse_file(file_path)
        result = PipelineResult(
            events_processed=len(events),
            malformed_lines=self.parser.malformed_lines_count,
        )

        if not events:
            return result

        # 1. Bulk insert events
        await self.log_repo.insert_many(events)

        # 2. Build aggregated sessions
        sessions = self.session_builder.build_from_events(events)

        all_iocs: List[IOC] = []
        all_intents: List[Intent] = []

        # 3. For each session, extract IOCs and classify intents
        for session in sessions:
            # Extract IOCs from commands
            cmd_iocs = self.ioc_extractor.extract_from_commands(session.commands)
            # Extract IOCs from downloads
            dl_iocs = self.ioc_extractor.extract_from_downloads(
                session.downloaded_files,
                session_id=session.session_id,
            )
            combined_iocs = cmd_iocs + dl_iocs

            # Classify intents from commands
            session_intents = self.intent_classifier.classify_session_commands(session.commands)

            session.iocs = combined_iocs
            session.intents = session_intents

            all_iocs.extend(combined_iocs)
            all_intents.extend(session_intents)

            # Persist session
            await self.session_repo.upsert(session)

        # 4. Persist IOCs and Intents
        if all_iocs:
            await self.ioc_repo.upsert_many(all_iocs)
        if all_intents:
            await self.intent_repo.insert_many(all_intents)

        result.sessions_updated = len(sessions)
        result.iocs_extracted = len(all_iocs)
        result.intents_classified = len(all_intents)
        result.sessions = sessions
        result.new_iocs = all_iocs
        result.new_intents = all_intents

        logger.info(
            "Pipeline completed: %d events -> %d sessions -> %d IOCs -> %d intents",
            result.events_processed,
            result.sessions_updated,
            result.iocs_extracted,
            result.intents_classified,
        )
        return result
