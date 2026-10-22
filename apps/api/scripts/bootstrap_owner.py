"""Create the first organization and owner when self-registration is disabled (the production default).

    docker compose -f docker-compose.prod.yml run --rm -e OWNER_PASSWORD='...' api \
        python -m scripts.bootstrap_owner --email you@company.com --org "Company MSP"

The password is read from OWNER_PASSWORD (not a command-line argument, which would end up in shell history
and process listings). Further users are added by an owner from Settings -> Team.
"""
import argparse
import os
import re
import sys

from sqlalchemy import select

from app.db import SessionLocal
from app.deps import bind_org
from app.models import Membership, Organization, User
from app.security import hash_password
from app.services import audit


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--email", required=True)
    ap.add_argument("--org", required=True, help="Organization name")
    ap.add_argument("--name", default="", help="Display name")
    args = ap.parse_args()

    password = os.environ.get("OWNER_PASSWORD", "")
    if len(password) < 12:
        print("Set OWNER_PASSWORD to a password of at least 12 characters.", file=sys.stderr)
        return 2
    email = args.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        print("That does not look like an email address.", file=sys.stderr)
        return 2

    with SessionLocal() as db:
        if db.scalar(select(User.id).where(User.email == email)):
            print("A user with that email already exists.", file=sys.stderr)
            return 1
        slug = re.sub(r"[^a-z0-9]+", "-", args.org.lower()).strip("-")[:60] or "org"
        if db.scalar(select(Organization.id).where(Organization.slug == slug)):
            print("An organization with that name already exists.", file=sys.stderr)
            return 1
        user = User(email=email, password_hash=hash_password(password), display_name=args.name)
        org = Organization(name=args.org.strip(), slug=slug)
        db.add_all([user, org])
        db.flush()
        db.add(Membership(user_id=user.id, organization_id=org.id, role="owner"))
        bind_org(db, org.id)
        audit.record(db, org.id, "auth.bootstrap_owner", actor=user, object_type="user", object_id=user.id)
        db.commit()
    print(f"Created organization '{args.org}' with owner {email}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
