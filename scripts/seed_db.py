#!/usr/bin/env python3
"""
Database Seeding Script

Creates initial database schema and seeds with default data:
- Default admin user
- Sample data for development/testing

Usage:
    python scripts/seed_db.py                    # Interactive mode
    python scripts/seed_db.py --admin-only       # Only create admin user
    python scripts/seed_db.py --force            # Drop and recreate database
    python scripts/seed_db.py --reset            # Alias for --force
"""
import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import argparse
from getpass import getpass
from services.duckdb_service import DuckDBService
from services.auth_service import AuthService
from schemas.user import UserCreate


def init_database(db_service: DuckDBService, force: bool = False):
    """Initialize database schema"""
    if force:
        db_path = Path(db_service.db_path)
        if db_path.exists():
            print(f"🗑️  Dropping existing database: {db_path}")
            db_service.close()
            db_path.unlink()
            try:
                Path(f"{db_path}.wal").unlink()
            except FileNotFoundError:
                pass
            # Reconnect
            db_service.conn = None

    print("📊 Initializing database schema...")
    db_service.init_db()
    print("✅ Database schema created successfully")


def create_admin_user(auth_service: AuthService, email: str = None, password: str = None,
                     full_name: str = None, interactive: bool = True):
    """Create default admin user"""
    print("\n👤 Creating admin user...")

    # Check if admin already exists
    if email:
        existing = auth_service.get_user_by_email(email)
        if existing:
            print(f"⚠️  Admin user '{email}' already exists. Skipping.")
            return existing

    # Interactive mode
    if interactive and not all([email, password, full_name]):
        print("\n📝 Enter admin user details:")
        email = email or input("Email [admin@example.com]: ").strip() or "admin@example.com"
        full_name = full_name or input("Full Name [FluxEngine Admin]: ").strip() or "FluxEngine Admin"

        if not password:
            password = getpass("Password (min 8 chars): ")
            password_confirm = getpass("Confirm Password: ")

            if password != password_confirm:
                print("❌ Passwords don't match!")
                sys.exit(1)

            if len(password) < 8:
                print("❌ Password must be at least 8 characters!")
                sys.exit(1)
    else:
        # Non-interactive defaults
        email = email or "admin@example.com"
        password = password or "admin123"  # Default for development only!
        full_name = full_name or "FluxEngine Admin"

    # Create admin user
    try:
        user_data = UserCreate(
            email=email,
            password=password,
            full_name=full_name,
            role="admin"
        )

        user = auth_service.create_user(user_data)
        print(f"✅ Admin user created successfully!")
        print(f"   Email: {user.email}")
        print(f"   Name: {user.full_name}")
        print(f"   Role: {user.role}")
        print(f"   ID: {user.id}")

        return user

    except ValueError as e:
        print(f"⚠️  {e}")
        return None
    except Exception as e:
        print(f"❌ Error creating admin user: {e}")
        sys.exit(1)


def create_sample_data(auth_service: AuthService, db_service: DuckDBService):
    """Create sample editor users and test data"""
    print("\n📦 Creating sample data...")

    sample_users = [
        {
            "email": "editor@example.com",
            "password": "editor123",
            "full_name": "Sample Editor",
            "role": "editor"
        },
        {
            "email": "test@example.com",
            "password": "test1234",
            "full_name": "Test User",
            "role": "editor"
        }
    ]

    created_count = 0
    for user_data in sample_users:
        try:
            existing = auth_service.get_user_by_email(user_data["email"])
            if existing:
                print(f"  ⏭️  User '{user_data['email']}' already exists")
                continue

            user = auth_service.create_user(UserCreate(**user_data))
            print(f"  ✅ Created user: {user.email} ({user.role})")
            created_count += 1

        except Exception as e:
            print(f"  ⚠️  Failed to create {user_data['email']}: {e}")

    if created_count > 0:
        print(f"✅ Created {created_count} sample user(s)")
    else:
        print("⏭️  All sample users already exist")


def main():
    """Main seeding function"""
    parser = argparse.ArgumentParser(
        description="Seed FluxEngine database with initial data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/seed_db.py                    # Interactive mode
  python scripts/seed_db.py --admin-only       # Only create admin user
  python scripts/seed_db.py --force            # Drop and recreate database
  python scripts/seed_db.py --non-interactive  # Use defaults, no prompts
        """
    )

    parser.add_argument(
        "--force", "--reset",
        action="store_true",
        help="Drop existing database and recreate from scratch"
    )

    parser.add_argument(
        "--admin-only",
        action="store_true",
        help="Only create admin user, skip sample data"
    )

    parser.add_argument(
        "--non-interactive", "-y",
        action="store_true",
        help="Non-interactive mode, use default values"
    )

    parser.add_argument(
        "--admin-email",
        default="admin@example.com",
        help="Admin user email (default: admin@example.com)"
    )

    parser.add_argument(
        "--admin-password",
        default=None,
        help="Admin user password (default: prompt or 'admin123' in non-interactive)"
    )

    parser.add_argument(
        "--admin-name",
        default="FluxEngine Admin",
        help="Admin user full name (default: FluxEngine Admin)"
    )

    args = parser.parse_args()

    # Warning for force mode
    if args.force:
        if not args.non_interactive:
            response = input("\n⚠️  WARNING: This will DELETE all existing data! Continue? [y/N]: ")
            if response.lower() != 'y':
                print("❌ Aborted")
                sys.exit(0)

    print("=" * 60)
    print("🚀 FluxEngine Database Seeding")
    print("=" * 60)

    # Initialize services
    db_service = DuckDBService()
    auth_service = AuthService()

    try:
        # Initialize database
        init_database(db_service, force=args.force)

        # Create admin user
        create_admin_user(
            auth_service,
            email=args.admin_email,
            password=args.admin_password,
            full_name=args.admin_name,
            interactive=not args.non_interactive
        )

        # Create sample data (unless admin-only mode)
        if not args.admin_only:
            create_sample_data(auth_service, db_service)

        print("\n" + "=" * 60)
        print("✅ Database seeding completed successfully!")
        print("=" * 60)

        print("\n📋 Quick Start:")
        print(f"  Email: {args.admin_email}")
        if args.non_interactive and not args.admin_password:
            print("  Password: admin123")
        print("  Role: admin")
        print("\n🌐 Start the server:")
        print("  python main.py")
        print("\n🔐 Login endpoint:")
        print("  POST http://localhost:8000/api/auth/login")
        print()

    except KeyboardInterrupt:
        print("\n\n❌ Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error during seeding: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        db_service.close()


if __name__ == "__main__":
    main()
