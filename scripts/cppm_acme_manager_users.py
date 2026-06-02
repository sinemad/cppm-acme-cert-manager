#!/usr/bin/env python3
"""
cppm_acme_manager_users.py – CLI user management for the CPPM ACME cert manager web UI.

Manages the admin accounts that control access to the web-based status and
configuration interface.  Credentials are stored as bcrypt hashes in
/data/certs/admin.htpasswd on the persistent volume and survive container
rebuilds.

Usage (run inside the container via docker exec):
    docker exec -it cppm-acme-cert-manager cppm-users add <username>
    docker exec -it cppm-acme-cert-manager cppm-users passwd <username>
    docker exec -it cppm-acme-cert-manager cppm-users delete <username>
    docker exec -it cppm-acme-cert-manager cppm-users list

Examples:
    # Create the first admin account
    docker exec -it cppm-acme-cert-manager cppm-users add admin

    # Add a second admin
    docker exec -it cppm-acme-cert-manager cppm-users add alice

    # Change a user's password
    docker exec -it cppm-acme-cert-manager cppm-users passwd admin

    # Remove a user
    docker exec -it cppm-acme-cert-manager cppm-users delete alice

    # List all users
    docker exec -it cppm-acme-cert-manager cppm-users list

Notes:
    - Usernames: letters, digits, hyphens, underscores (1–64 characters)
    - Passwords: minimum 8 characters
    - Deleting the last user re-enables the first-time setup wizard in the web UI
"""

import getpass
import sys

sys.path.insert(0, "/opt/cppm")

try:
    from auth_utils import (
        HAS_BCRYPT, HTPASSWD_FILE,
        delete_user, load_users, needs_setup, save_user, verify_password,
    )
except ImportError as exc:
    sys.exit(
        f"ERROR: Cannot import auth_utils: {exc}\n"
        "This script must be run inside the container:\n"
        "  docker exec -it cppm-acme-cert-manager cppm-users <cmd>"
    )


# ── Password prompt ───────────────────────────────────────────────────────────

def _prompt_password(username: str, confirm: bool = True) -> str:
    """Prompt for a password with optional confirmation. Loops until valid."""
    while True:
        try:
            pw = getpass.getpass(f"  Password for '{username}': ")
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if len(pw) < 8:
            print("  Password must be at least 8 characters. Try again.")
            continue
        if confirm:
            try:
                pw2 = getpass.getpass("  Confirm password: ")
            except (EOFError, KeyboardInterrupt):
                print()
                sys.exit(0)
            if pw != pw2:
                print("  Passwords do not match. Try again.")
                continue
        return pw


# ── Subcommands ───────────────────────────────────────────────────────────────

def cmd_add(username: str) -> int:
    users = load_users()
    if username in users:
        print(f"User '{username}' already exists.")
        print(f"  To change the password: cppm-users passwd {username}")
        return 1
    try:
        pw = _prompt_password(username)
        save_user(username, pw)
        print(f"User '{username}' created.")
        if needs_setup():
            print("  Note: This is the first admin user. The web UI setup wizard is now complete.")
        return 0
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}")
        return 1


def cmd_passwd(username: str) -> int:
    users = load_users()
    if username not in users:
        print(f"User '{username}' not found.")
        print("  Run 'list' to see all users.")
        return 1
    try:
        pw = _prompt_password(username)
        save_user(username, pw)
        print(f"Password updated for '{username}'.")
        return 0
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}")
        return 1


def cmd_delete(username: str) -> int:
    users = load_users()
    if username not in users:
        print(f"User '{username}' not found.")
        return 1
    try:
        confirm = input(f"Delete user '{username}'? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return 0
    if confirm != "y":
        print("Cancelled.")
        return 0
    if delete_user(username):
        print(f"User '{username}' deleted.")
        remaining = load_users()
        if not remaining:
            print(
                "WARNING: No admin users remain.\n"
                "  The web UI will show the first-time setup wizard until a new user is created.\n"
                f"  Create one with: cppm-users add <username>"
            )
        else:
            print(f"  {len(remaining)} user(s) remaining.")
        return 0
    return 1


def cmd_list() -> int:
    users = load_users()
    if not users:
        print("No admin users configured.")
        print(
            f"  Credential file: {HTPASSWD_FILE}\n"
            f"  Create the first user: cppm_acme_manager_users.py add <username>\n"
            f"  Or use the web UI setup wizard at http://<host>:${{STATUS_PORT:-8080}}/setup\n"
            f"  CLI: cppm-users add <username>"
        )
        return 0
    print(f"Admin users ({len(users)}) — stored in {HTPASSWD_FILE}:")
    for name in sorted(users):
        print(f"  {name}")
    return 0


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    if not HAS_BCRYPT:
        print(
            "ERROR: py3-bcrypt is not installed.\n"
            "  Rebuild the Docker image: docker compose build --no-cache"
        )
        return 1

    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1

    cmd, *rest = args

    if cmd == "list":
        return cmd_list()

    if cmd in ("add", "passwd", "delete"):
        if not rest:
            print(f"Usage: cppm-users {cmd} <username>")
            return 1
        return {"add": cmd_add, "passwd": cmd_passwd, "delete": cmd_delete}[cmd](rest[0])

    print(f"Unknown command: '{cmd}'")
    print("Available commands: add, passwd, delete, list")
    return 1


if __name__ == "__main__":
    sys.exit(main())
