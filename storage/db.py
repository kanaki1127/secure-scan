import uuid
from datetime import datetime
from sqlalchemy import create_engine, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(primary_key=True)
    target_path: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    status: Mapped[str] = mapped_column(default="pending")
    total_findings: Mapped[int] = mapped_column(default=0)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    rule_id: Mapped[str]
    file_path: Mapped[str]
    line: Mapped[int]
    severity: Mapped[str]
    cwe: Mapped[str | None]
    message: Mapped[str]
    remediation: Mapped[str | None]


def init_db(db_url: str = "sqlite:///secure_scan.db"):
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def create_scan(session, target_path: str) -> Scan:
    scan = Scan(id=str(uuid.uuid4()), target_path=target_path, status="running")
    session.add(scan)
    session.commit()
    return scan


def save_findings(session, scan_id: str, sarif: dict) -> int:
    results = sarif.get("runs", [{}])[0].get("results", [])
    count = 0
    for r in results:
        try:
            loc = r["locations"][0]["physicalLocation"]
            file_path = loc["artifactLocation"]["uri"]
            line = loc["region"]["startLine"]
        except (KeyError, IndexError):
            continue
        props = r.get("properties", {})
        level = r.get("level")
        severity = props.get("severity") or {"error": "high", "warning": "medium", "note": "low"}.get(level, "low")
        f = Finding(
            scan_id=scan_id,
            rule_id=r.get("ruleId", ""),
            file_path=file_path,
            line=line,
            severity=severity,
            cwe=props.get("cwe"),
            message=r.get("message", {}).get("text", ""),
            remediation=props.get("remediation"),
        )
        session.add(f)
        count += 1

    scan = session.query(Scan).filter_by(id=scan_id).first()
    if scan:
        scan.status = "done"
        scan.total_findings = count
    session.commit()
    return count


def list_scans(session) -> list[Scan]:
    return session.query(Scan).order_by(Scan.created_at.desc()).all()


def get_findings(session, scan_id: str) -> list[Finding]:
    return session.query(Finding).filter_by(scan_id=scan_id).all()