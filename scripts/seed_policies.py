#!/usr/bin/env python
"""
AI Memory Firewall - Database Policy Seed Script
=================================================
Seeds standard system default security policies into the database.

Usage:
    python scripts/seed_policies.py
"""

import sys
import os

# Ensure project root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config.database import SyncSessionLocal, init_db, sync_engine
from src.services.policy_service import seed_default_policies


def main() -> None:
    print("Initializing database tables if not created...")
    from config.database import Base
    Base.metadata.create_all(bind=sync_engine)

    db = SyncSessionLocal()

    try:
        print("Seeding default security policies...")
        seeded = seed_default_policies(db)
        print(f"Successfully seeded/verified {len(seeded)} default security policies:")
        for pol in seeded:
            print(f"  - [{pol.action.value}] {pol.name} (Role: '{pol.target_role}', Priority: {pol.priority_order})")
    except Exception as e:
        print(f"Error seeding security policies: {e}")
        db.rollback()
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
