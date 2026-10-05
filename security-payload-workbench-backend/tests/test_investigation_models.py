import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError

from database import Base, create_database
from models import (
    AuthSession,
    Investigation,
    InvestigationEvent,
    InvestigationEvidence,
    InvestigationFinding,
    InvestigationIOC,
    User,
)


@pytest.fixture
def database():
    db = create_database("sqlite:///:memory:")

    @event.listens_for(db.engine, "connect")
    def enable_sqlite_foreign_keys(connection, _record):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(db.engine)
    yield db
    db.dispose()


def add_user(session, email="analyst@example.org"):
    user = User(email=email, password_hash="test-hash", display_name="Analyst")
    session.add(user)
    session.flush()
    return user


def add_investigation(session, owner, title="Incident 1"):
    investigation = Investigation(owner=owner, title=title)
    session.add(investigation)
    session.flush()
    return investigation


def test_investigation_requires_existing_owner(database):
    with pytest.raises(IntegrityError):
        with database.sessions.begin() as session:
            session.add(Investigation(title="No owner"))

    with pytest.raises(IntegrityError):
        with database.sessions.begin() as session:
            session.add(Investigation(owner_id=98765, title="Missing owner"))


def test_children_belong_to_investigation_and_evidence_finding_must_match(database):
    with database.sessions.begin() as session:
        user = add_user(session)
        investigation = add_investigation(session, user)
        finding = InvestigationFinding(investigation=investigation, title="Suspicious host", severity="high")
        ioc = InvestigationIOC(investigation=investigation, ioc_type="domain", value="evil.example", normalized_value="evil.example", confidence=80)
        event = InvestigationEvent(investigation=investigation, event_type="created", message="Investigation opened")
        evidence = InvestigationEvidence(investigation=investigation, finding=finding, evidence_type="log_snippet", title="DNS log", content="Query observed")
        general_evidence = InvestigationEvidence(investigation=investigation, evidence_type="note", title="Analyst note", content="Review pending")
        session.add_all([finding, ioc, event, evidence, general_evidence])
        session.flush()
        assert ioc.investigation_id == investigation.id
        assert finding.investigation_id == investigation.id
        assert evidence.finding_id == finding.id
        assert general_evidence.finding_id is None
        assert finding.investigation.owner_id == user.id

    with pytest.raises(IntegrityError):
        with database.sessions.begin() as session:
            owner = add_user(session, "other@example.org")
            first = add_investigation(session, owner, "First")
            second = add_investigation(session, owner, "Second")
            finding = InvestigationFinding(investigation=first, title="First finding")
            session.add(finding)
            session.flush()
            session.add(InvestigationEvidence(
                investigation=second, finding_id=finding.id, evidence_type="note", title="Cross-link", content="Invalid",
            ))


@pytest.mark.parametrize(
    "record",
    [
        lambda investigation: Investigation(owner=investigation.owner, title="Invalid", status="pending"),
        lambda investigation: InvestigationFinding(investigation=investigation, title="Invalid", severity="urgent"),
        lambda investigation: InvestigationFinding(investigation=investigation, title="Invalid", status="new"),
        lambda investigation: InvestigationIOC(investigation=investigation, ioc_type="ip", value="192.0.2.1", confidence=101),
    ],
)
def test_database_checks_reject_invalid_controlled_values(database, record):
    with pytest.raises(IntegrityError):
        with database.sessions.begin() as session:
            user = add_user(session)
            investigation = add_investigation(session, user)
            session.add(record(investigation))


def test_deleting_user_cascades_through_investigation_children(database):
    with database.sessions.begin() as session:
        user = add_user(session)
        investigation = add_investigation(session, user)
        finding = InvestigationFinding(investigation=investigation, title="Finding")
        session.add_all([
            finding,
            InvestigationIOC(investigation=investigation, ioc_type="hash", value="a" * 64),
            InvestigationEvent(investigation=investigation, event_type="created", message="Created"),
        ])
        session.flush()
        session.add(InvestigationEvidence(investigation=investigation, finding=finding, evidence_type="note", title="Evidence", content="Detail"))
        user_id = user.id

    with database.sessions.begin() as session:
        session.delete(session.get(User, user_id))

    with database.sessions() as session:
        for model in (Investigation, InvestigationIOC, InvestigationFinding, InvestigationEvidence, InvestigationEvent, AuthSession):
            assert session.scalar(select(model)) is None
