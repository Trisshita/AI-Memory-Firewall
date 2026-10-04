"""
Seed demo data for AI Memory Firewall local testing.
Creates default tenant, admin user, standard user, agent session,
default security policies, custom firewall rules, and genesis audit block.
"""

import uuid
from sqlalchemy import create_engine
from config.settings import settings
from config.database import Base, SyncSessionLocal
from src.models import (
    AgentSession,
    FirewallRule,
    RuleAction,
    RuleType,
    Tenant,
    User,
    UserRole,
)
from src.models.audit import AuditLogEntry
from src.security import hash_password, hash_audit_log
from src.services.policy_service import seed_default_policies

def seed():
    # Ensure tables exist
    engine = create_engine(settings.sync_database_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)

    db = SyncSessionLocal()
    try:
        # 1. Tenant
        tenant_id = uuid.UUID("e8869819-cc43-4aae-8789-5f7c1228be4a")
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant:
            tenant = Tenant(
                id=tenant_id,
                name="FinHealth Enterprise Corp",
                slug="finhealth-corp",
                api_key_hash="seed_api_key_hash_123",
                is_active=True,
            )
            db.add(tenant)
            db.flush()
            print("Created Tenant: FinHealth Enterprise Corp")

        # 2. Admin User
        admin = db.query(User).filter(User.email == "admin@firewall.com").first()
        if not admin:
            admin = User(
                id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
                email="admin@firewall.com",
                hashed_password=hash_password("AdminSecure123!"),
                role=UserRole.ADMIN.value,
                tenant_id=tenant_id,
                is_active=True,
            )
            db.add(admin)
            print("Created Admin User: admin@firewall.com")

        # 3. Standard User
        user = db.query(User).filter(User.email == "doctor@acme.com").first()
        if not user:
            user = User(
                id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
                email="doctor@acme.com",
                hashed_password=hash_password("SecurePass123!"),
                role=UserRole.USER.value,
                tenant_id=tenant_id,
                is_active=True,
            )
            db.add(user)
            print("Created User: doctor@acme.com")

        # 4. Agent Session
        session_id = uuid.UUID("b0331cd9-e5e8-4d88-badf-5e23eb49934f")
        agent_sess = db.query(AgentSession).filter(AgentSession.id == session_id).first()
        if not agent_sess:
            agent_sess = AgentSession(
                id=session_id,
                tenant_id=tenant_id,
                agent_name="AdvisorBot",
                session_token="sess_advisor_bot_demo",
                status="ACTIVE",
            )
            db.add(agent_sess)
            print("Created Agent Session: AdvisorBot")

        # 5. Firewall Rules
        ask_rule = db.query(FirewallRule).filter(FirewallRule.name == "Confirm Wire Transfer Data").first()
        if not ask_rule:
            ask_rule = FirewallRule(
                tenant_id=tenant_id,
                name="Confirm Wire Transfer Data",
                rule_type=RuleType.KEYWORD_FILTER,
                pattern_payload="wire transfer,account balance,routing number",
                action=RuleAction.ASK_USER,
                severity="MEDIUM",
                priority_order=1,
                is_active=True,
                description="Prompts human confirmation whenever financial transfer terms are detected",
            )
            db.add(ask_rule)
            print("Created FirewallRule: Confirm Wire Transfer Data (ASK_USER)")

        block_rule = db.query(FirewallRule).filter(FirewallRule.name == "Block Confidential Code").first()
        if not block_rule:
            block_rule = FirewallRule(
                tenant_id=tenant_id,
                name="Block Confidential Code",
                rule_type=RuleType.REGEX_PATTERN,
                pattern_payload=r"CONFIDENTIAL_PROJ_[A-Z0-9]+",
                action=RuleAction.BLOCK,
                severity="HIGH",
                priority_order=2,
                is_active=True,
                description="Blocks proprietary internal project codenames",
            )
            db.add(block_rule)
            print("Created FirewallRule: Block Confidential Code (BLOCK)")

        # 6. Default Policies
        seed_default_policies(db)
        print("Seeded default security policies")

        # 7. Genesis block in audit ledger
        genesis = db.query(AuditLogEntry).filter(AuditLogEntry.sequence_number == 1).first()
        if not genesis:
            from datetime import datetime, timezone
            from src.engine.audit_logger import compute_entry_hash, GENESIS_HASH
            now = datetime.now(timezone.utc)
            now_iso = now.isoformat()
            genesis_payload = {"info": "AI Memory Firewall SHA-256 Ledger Initialized"}
            genesis_hash = compute_entry_hash(
                sequence_number=1,
                tenant_id=str(tenant_id),
                event_type="SYSTEM",
                severity="LOW",
                actor="system",
                action="ledger.genesis",
                resource="chain:genesis",
                payload=genesis_payload,
                created_at_iso=now_iso,
                previous_hash=GENESIS_HASH,
            )
            genesis_entry = AuditLogEntry(
                sequence_number=1,
                tenant_id=tenant_id,
                event_type="SYSTEM",
                severity="LOW",
                actor="system",
                action="ledger.genesis",
                resource="chain:genesis",
                payload=genesis_payload,
                previous_hash=GENESIS_HASH,
                entry_hash=genesis_hash,
                created_at=now,
            )
            db.add(genesis_entry)
            print("Created Genesis block #1 in SHA-256 ledger")

        db.commit()
        print("Database seeding completed successfully!")
    finally:
        db.close()

if __name__ == "__main__":
    seed()
