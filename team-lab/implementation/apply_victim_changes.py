#!/usr/bin/env python3
"""Apply reviewed source files only; never migrate a DB, start services or make requests."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

PACKAGE = Path(__file__).resolve().parent
MAP = {
    'common-overlay': ['app/bootstrap.php', 'app/auth/session.php', '.gitignore', '.env.example'],
    'photo-overlay': ['app/customer-photos.php', 'app/customer-form.php', 'public/customer/action.php',
                      'public/customer/photo.php', 'public/customer/tickets.php', 'public/customer/board.php',
                      'database/migrations/017_customer_ticket_files.sql', 'tests/customer_photos_domain.php'],
    'mfa-overlay': ['app/auth/mfa.php', 'public/login.php', 'public/mfa.php', 'tests/mfa_domain.php',
                    'config/mfa.env.example', 'config/mfa-secrets.example.json'],
}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    target = args.target.resolve()
    if not (target / 'app/bootstrap.php').is_file() or not (target / 'public/login.php').is_file():
        raise SystemExit('Target is not the expected Victim project')
    expected = {}
    for group in MAP:
        expected.update(json.loads((PACKAGE / group / 'base-sha256.json').read_text()))
    operations = []
    for group, relatives in MAP.items():
        for relative in relatives:
            source = PACKAGE / group / relative
            destination = target / relative
            if not destination.resolve().is_relative_to(target) or destination.is_symlink():
                raise SystemExit('Unexpected target path: ' + relative)
            if not source.is_file():
                raise SystemExit('Missing package source: ' + relative)
            if destination.exists() and sha(destination) == sha(source):
                continue  # Already applied byte-for-byte.
            if relative in expected:
                if not destination.is_file() or sha(destination) != expected[relative]:
                    raise SystemExit('Changed original; review before applying: ' + relative)
            elif destination.exists():
                raise SystemExit('New file already exists with other contents: ' + relative)
            operations.append((source, destination, relative))
    backup = PACKAGE.parent / 'evidence' / 'mentor-20261031' / 'before-victim'
    if args.apply:
        for source, destination, relative in operations:
            if destination.is_file():
                saved = backup / relative
                saved.parent.mkdir(parents=True, exist_ok=True)
                if not saved.exists():
                    shutil.copy2(destination, saved)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
    print(json.dumps({'status': 'applied' if args.apply else 'checked_only',
                      'file_count': len(operations), 'files': [r for _, _, r in operations],
                      'database_migrated': False, 'services_changed': False,
                      'http_requests': 0}, ensure_ascii=False))

if __name__ == '__main__':
    main()
